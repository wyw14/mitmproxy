import asyncio
import contextlib
import inspect
import logging
import pprint
import sys
import traceback
import types
from collections.abc import Callable
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import hooks
from mitmproxy.utils import asyncio_utils

logger = logging.getLogger(__name__)


def _get_name(itm):
    return getattr(itm, "name", itm.__class__.__name__.lower())


def cut_traceback(tb, func_name):
    """
    Cut off a traceback at the function with the given name.
    The func_name's frame is excluded.

    Args:
        tb: traceback object, as returned by sys.exc_info()[2]
        func_name: function name

    Returns:
        Reduced traceback.
    """
    tb_orig = tb
    for _, _, fname, _ in traceback.extract_tb(tb):
        tb = tb.tb_next
        if fname == func_name:
            break
    return tb or tb_orig


@contextlib.contextmanager
def safecall():
    try:
        yield
    except (exceptions.AddonHalt, exceptions.OptionsError):
        raise
    except Exception:
        etype, value, tb = sys.exc_info()
        tb = cut_traceback(tb, "invoke_addon_sync")
        tb = cut_traceback(tb, "invoke_addon")
        assert etype
        assert value
        logger.error(
            f"Addon error: {value}",
            exc_info=(etype, value, tb),
        )


class Loader:
    """
    A loader object is passed to the load() event when addons start up.
    """

    def __init__(self, master):
        self.master = master

    def add_option(
        self,
        name: str,
        typespec: type,
        default: Any,
        help: str,
        choices: Sequence[str] | None = None,
    ) -> None:
        """
        Add an option to mitmproxy.

        Help should be a single paragraph with no linebreaks - it will be
        reflowed by tools. Information on the data type should be omitted -
        it will be generated and added by tools as needed.
        """
        assert not isinstance(choices, str)
        if name in self.master.options:
            existing = self.master.options._options[name]
            same_signature = (
                existing.name == name
                and existing.typespec == typespec
                and existing.default == default
                and existing.help == help
                and existing.choices == choices
            )
            if same_signature:
                return
            else:
                logger.warning("Over-riding existing option %s" % name)
        self.master.options.add_option(name, typespec, default, help, choices)

    def add_command(self, path: str, func: Callable) -> None:
        """Add a command to mitmproxy.

        Unless you are generating commands programatically,
        this API should be avoided. Decorate your function with `@mitmproxy.command.command` instead.
        """
        self.master.commands.add(path, func)


def traverse(chain):
    """
    Recursively traverse an addon chain.
    """
    for a in chain:
        yield a
        if hasattr(a, "addons"):
            yield from traverse(a.addons)


@dataclass
class LoadHook(hooks.Hook):
    """
    Called when an addon is first loaded. This event receives a Loader
    object, which contains methods for adding options and commands. This
    method is where the addon configures itself.
    """

    loader: Loader


@dataclass(frozen=True)
class IsolationInfo:
    """
    A snapshot of an addon's fault isolation state, as returned by
    `AddonIsolation.status()`.
    """

    name: str
    isolated: bool
    reason: str | None
    failures: int
    last_hook: str | None
    last_error: str | None


@dataclass
class _IsolationState:
    """Mutable fault isolation state for a single addon instance."""

    addon: object
    isolated: bool = False
    reason: str | None = None
    failures: int = 0
    last_hook: str | None = None
    last_error: BaseException | None = None
    #: Tasks currently executing a (timed-out-capable) hook for this addon.
    pending: set[asyncio.Task] = field(default_factory=set)


class _HookTimeout(Exception):
    def __init__(self, hook_name: str, timeout: float):
        super().__init__(f"Hook {hook_name!r} did not complete within {timeout:g}s")
        self.hook_name = hook_name
        self.timeout = timeout


class AddonIsolation:
    """
    Optional fault isolation for (script-loaded) addons.

    Addons are registered via `guard()` (typically the script loader registers
    each loaded script addon). When the ``addon_isolation`` option is enabled,
    hook execution for guarded addons is supervised:

    * Awaitable hooks that do not complete within ``addon_isolation_timeout``
      seconds are cancelled, count as a failure and isolate the addon immediately.
    * Every other hook failure increments the consecutive failure counter; once
      ``addon_isolation_max_failures`` consecutive failures are reached, the
      addon is isolated.
    * A successful hook resets the consecutive failure counter.
    * Isolated addons no longer receive traffic hooks, but their ``done``
      cleanup hook is still delivered so they can shut down properly.
    * Isolation state is per addon instance: a reloaded script gets a fresh
      state, and an isolated addon can be re-enabled manually via `recover()`.

    When the option is disabled (the default), hook invocation is passed
    through unchanged.
    """

    #: Hooks that must still be delivered to isolated addons.
    CLEANUP_HOOKS = frozenset({hooks.DoneHook.name})

    def __init__(self, manager: "AddonManager"):
        self.manager = manager
        self._states: dict[object, _IsolationState] = {}

    # -- configuration -------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return bool(getattr(self.manager.master.options, "addon_isolation", False))

    @property
    def timeout(self) -> float:
        return float(
            getattr(self.manager.master.options, "addon_isolation_timeout", 10.0)
        )

    @property
    def max_failures(self) -> int:
        return int(
            getattr(self.manager.master.options, "addon_isolation_max_failures", 3)
        )

    # -- (un)registration ----------------------------------------------------

    def guard(self, addon: object) -> None:
        """
        Register *addon* and all of its sub-addons for fault isolation.
        A fresh, non-isolated state is created for each addon instance.
        """
        for a in traverse([addon]):
            self._states.setdefault(a, _IsolationState(addon=a))

    def unguard(self, addon: object) -> None:
        """
        Drop isolation state for *addon* and all of its sub-addons. Any task
        still executing a hook for them is cancelled so that a removed addon
        is never called back and no tasks are left behind.
        """
        for a in traverse([addon]):
            state = self._states.pop(a, None)
            if state is not None:
                for task in state.pending:
                    task.cancel()
                state.pending.clear()

    def clear(self) -> None:
        """Remove all isolation state and cancel all pending hook tasks."""
        for state in self._states.values():
            for task in state.pending:
                task.cancel()
            state.pending.clear()
        self._states.clear()

    # -- queries --------------------------------------------------------------

    def is_guarded(self, addon: object) -> bool:
        return addon in self._states

    def is_isolated(self, addon: object) -> bool:
        state = self._states.get(addon)
        return state is not None and state.isolated

    def should_skip(self, addon: object, event: hooks.Hook) -> bool:
        """
        Return True if a guarded addon is currently isolated and therefore
        should not receive *event*. Cleanup hooks (``done``) always pass.
        """
        if not self.enabled or event.name in self.CLEANUP_HOOKS:
            return False
        state = self._states.get(addon)
        return state is not None and state.isolated

    def status(self, addon: object) -> IsolationInfo | None:
        """Return isolation information for *addon*, or None if not guarded."""
        state = self._states.get(addon)
        if state is None:
            return None
        last_error = (
            f"{type(state.last_error).__name__}: {state.last_error}"
            if state.last_error is not None
            else None
        )
        return IsolationInfo(
            name=_get_name(addon),
            isolated=state.isolated,
            reason=state.reason,
            failures=state.failures,
            last_hook=state.last_hook,
            last_error=last_error,
        )

    def isolated_addons(self) -> list[object]:
        """Return all currently isolated addon instances."""
        return [a for a, state in self._states.items() if state.isolated]

    def recover(self, addon: object | str | None) -> bool:
        """
        Manually take an addon out of isolation and reset its failure counter.
        Accepts either an addon instance or its name. Returns True if the
        addon was guarded and has been recovered.
        """
        if isinstance(addon, str):
            addon = self.manager.get(addon)
        if addon is None:
            return False
        state = self._states.get(addon)
        if state is None:
            return False
        state.isolated = False
        state.reason = None
        state.failures = 0
        state.last_hook = None
        state.last_error = None
        return True

    # -- hook invocation ------------------------------------------------------

    async def invoke(self, addon: object, event: hooks.Hook, func: Callable) -> None:
        """
        Invoke a single hook callable, applying fault isolation when enabled.
        Exceptions from supervised hooks are logged and counted instead of
        propagating, so that other addons keep processing traffic in order.
        ``AddonHalt`` and ``OptionsError`` always propagate.
        """
        state = self._states.get(addon)
        cleanup = event.name in self.CLEANUP_HOOKS

        if state is None or not self.enabled:
            # Not guarded or isolation switched off: pass through unchanged.
            res = func(*event.args())
            if res is not None and inspect.isawaitable(res):
                await res
            return

        if state.isolated and not cleanup:
            logger.debug(
                f"Skipping {event.name!r} hook for isolated addon {_get_name(addon)}."
            )
            return

        if cleanup:
            # Cleanup hooks (done) are always delivered, even to isolated
            # addons, and they are never supervised or counted.
            res = func(*event.args())
            if res is not None and inspect.isawaitable(res):
                await res
            return

        try:
            res = func(*event.args())
            if res is not None and inspect.isawaitable(res):
                await self._await_with_timeout(addon, state, event, res)
        except (exceptions.AddonHalt, exceptions.OptionsError):
            raise
        except _HookTimeout as e:
            state.failures += 1
            state.last_hook = event.name
            state.last_error = e
            logger.error(f"Addon error: {e} (addon {_get_name(addon)})")
            self._isolate(addon, state, reason="timeout")
            return
        except Exception as e:
            state.failures += 1
            state.last_hook = event.name
            state.last_error = e
            self._log_error(e)
            if self.max_failures > 0 and state.failures >= self.max_failures:
                self._isolate(addon, state, reason="failures")
            return

        # The hook completed successfully: reset the consecutive failure count.
        state.failures = 0
        state.last_hook = None
        state.last_error = None

    async def _await_with_timeout(
        self,
        addon: object,
        state: _IsolationState,
        event: hooks.Hook,
        awaitable: Any,
    ) -> None:
        timeout = self.timeout
        if timeout <= 0:
            # A non-positive timeout disables the timeout supervision.
            await awaitable
            return
        task = asyncio.ensure_future(awaitable)
        if isinstance(task, asyncio.Task):
            asyncio_utils.set_task_debug_info(
                task,
                name=f"isolated {event.name} hook of {_get_name(addon)}",
            )
        state.pending.add(task)
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout)
        except asyncio.TimeoutError:
            # Cancel the runaway hook and wait for its cancellation to take
            # effect so that no coroutine/task outlives the timeout and the
            # addon is never called back afterwards.
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            raise _HookTimeout(event.name, timeout) from None
        except BaseException:
            # The calling task itself was cancelled (e.g. shutdown): make sure
            # the hook task does not outlive us.
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
            raise
        finally:
            state.pending.discard(task)

    # -- internals ------------------------------------------------------------

    def _isolate(self, addon: object, state: _IsolationState, *, reason: str) -> None:
        if state.isolated:
            return
        state.isolated = True
        state.reason = reason
        logger.error(
            f"Isolating addon {_get_name(addon)} due to {reason} "
            f"after {state.failures} consecutive failure(s). The addon will "
            f"no longer receive traffic hooks; use the addon.recover command "
            f"to re-enable it."
        )

    @staticmethod
    def _log_error(exc: BaseException) -> None:
        etype, value, tb = type(exc), exc, exc.__traceback__
        tb = cut_traceback(tb, "invoke_addon_sync")
        tb = cut_traceback(tb, "invoke_addon")
        tb = cut_traceback(tb, "_await_with_timeout")
        tb = cut_traceback(tb, "invoke")
        assert value is not None
        logger.error(
            f"Addon error: {value}",
            exc_info=(etype, value, tb),
        )


class AddonManager:
    def __init__(self, master):
        self.lookup = {}
        self.chain = []
        self.master = master
        self.isolation = AddonIsolation(self)
        master.options.changed.connect(self._configure_all)

    def _configure_all(self, updated):
        self.trigger(hooks.ConfigureHook(updated))

    def clear(self):
        """
        Remove all addons.
        """
        for a in self.chain:
            self.invoke_addon_sync(a, hooks.DoneHook())
        self.lookup = {}
        self.chain = []
        self.isolation.clear()

    def get(self, name):
        """
        Retrieve an addon by name. Addon names are equal to the .name
        attribute on the instance, or the lower case class name if that
        does not exist.
        """
        return self.lookup.get(name, None)

    def register(self, addon):
        """
        Register an addon, call its load event, and then register all its
        sub-addons. This should be used by addons that dynamically manage
        addons.

        If the calling addon is already running, it should follow with
        running and configure events. Must be called within a current
        context.
        """
        api_changes = {
            # mitmproxy 6 -> mitmproxy 7
            "clientconnect": f"The clientconnect event has been removed, use client_connected instead",
            "clientdisconnect": f"The clientdisconnect event has been removed, use client_disconnected instead",
            "serverconnect": "The serverconnect event has been removed, use server_connect and server_connected instead",
            "serverdisconnect": f"The serverdisconnect event has been removed, use server_disconnected instead",
            # mitmproxy 8 -> mitmproxy 9
            "add_log": "The add_log event has been deprecated, use Python's builtin logging module instead",
        }
        for a in traverse([addon]):
            for old, msg in api_changes.items():
                if hasattr(a, old):
                    logger.warning(
                        f"{msg}. For more details, see https://docs.mitmproxy.org/dev/addons-api-changelog/."
                    )
            name = _get_name(a)
            if name in self.lookup:
                raise exceptions.AddonManagerError(
                    "An addon called '%s' already exists." % name
                )
        loader = Loader(self.master)
        self.invoke_addon_sync(addon, LoadHook(loader))
        for a in traverse([addon]):
            name = _get_name(a)
            self.lookup[name] = a
        for a in traverse([addon]):
            self.master.commands.collect_commands(a)
        self.master.options.process_deferred()
        return addon

    def add(self, *addons):
        """
        Add addons to the end of the chain, and run their load event.
        If any addon has sub-addons, they are registered.
        """
        for i in addons:
            self.chain.append(self.register(i))

    def remove(self, addon):
        """
        Remove an addon and all its sub-addons.

        If the addon is not in the chain - that is, if it's managed by a
        parent addon - it's the parent's responsibility to remove it from
        its own addons attribute.
        """
        for a in traverse([addon]):
            n = _get_name(a)
            if n not in self.lookup:
                raise exceptions.AddonManagerError("No such addon: %s" % n)
            self.chain = [i for i in self.chain if i is not a]
            del self.lookup[_get_name(a)]
        self.invoke_addon_sync(addon, hooks.DoneHook())
        # Drop isolation state (and cancel any lingering hook tasks) only after
        # the addon has received its done cleanup event.
        self.isolation.unguard(addon)

    def __len__(self):
        return len(self.chain)

    def __str__(self):
        return pprint.pformat([str(i) for i in self.chain])

    def __contains__(self, item):
        name = _get_name(item)
        return name in self.lookup

    async def handle_lifecycle(self, event: hooks.Hook):
        """
        Handle a lifecycle event.
        """
        message = event.args()[0]

        await self.trigger_event(event)

        if isinstance(message, flow.Flow):
            await self.trigger_event(hooks.UpdateHook([message]))

    def _iter_hooks(self, addon, event: hooks.Hook):
        """
        Enumerate all hook callables belonging to the given addon
        """
        assert isinstance(event, hooks.Hook)
        for a in traverse([addon]):
            func = getattr(a, event.name, None)
            if func:
                if callable(func):
                    yield a, func
                elif isinstance(func, types.ModuleType):
                    # we gracefully exclude module imports with the same name as hooks.
                    # For example, a user may have "from mitmproxy import log" in an addon,
                    # which has the same name as the "log" hook. In this particular case,
                    # we end up in an error loop because we "log" this error.
                    pass
                else:
                    raise exceptions.AddonManagerError(
                        f"Addon handler {event.name} ({a}) not callable"
                    )

    async def invoke_addon(self, addon, event: hooks.Hook):
        """
        Asynchronously invoke an event on an addon and all its children.
        """
        for addon, func in self._iter_hooks(addon, event):
            await self.isolation.invoke(addon, event, func)

    def invoke_addon_sync(self, addon, event: hooks.Hook):
        """
        Invoke an event on an addon and all its children.
        """
        for addon, func in self._iter_hooks(addon, event):
            if self.isolation.should_skip(addon, event):
                # Isolated addon: skip traffic hooks, cleanup hooks still pass.
                continue
            if inspect.iscoroutinefunction(func):
                raise exceptions.AddonManagerError(
                    f"Async handler {event.name} ({addon}) cannot be called from sync context"
                )
            func(*event.args())

    async def trigger_event(self, event: hooks.Hook):
        """
        Asynchronously trigger an event across all addons.
        """
        for i in self.chain:
            try:
                with safecall():
                    await self.invoke_addon(i, event)
            except exceptions.AddonHalt:
                return

    def trigger(self, event: hooks.Hook):
        """
        Trigger an event across all addons.

        This API is discouraged and may be deprecated in the future.
        Use `trigger_event()` instead, which provides the same functionality but supports async hooks.
        """
        for i in self.chain:
            try:
                with safecall():
                    self.invoke_addon_sync(i, event)
            except exceptions.AddonHalt:
                return
