"""Tests for optional script-addon fault isolation."""

import asyncio

import pytest

from mitmproxy import exceptions
from mitmproxy.addons import script
from mitmproxy.proxy.layers.http import HttpRequestHook
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def traffic_event():
    return HttpRequestHook(tflow.tflow())


class TrafficAddon:
    def __init__(self, name="addon", addons=None):
        self.name = name
        self.addons = addons or []
        self.requests = 0
        self.configure_count = 0
        self.done_count = 0

    def request(self, flow):
        self.requests += 1

    def configure(self, updated):
        self.configure_count += 1

    def done(self):
        self.done_count += 1


class SyncFail(TrafficAddon):
    def request(self, flow):
        self.requests += 1
        raise ValueError(f"{self.name} sync boom")


class AsyncFail(TrafficAddon):
    async def request(self, flow):
        self.requests += 1
        await asyncio.sleep(0)
        raise RuntimeError(f"{self.name} async boom")


class Flaky(TrafficAddon):
    def __init__(self, name="flaky"):
        super().__init__(name)
        self.fail = True

    def request(self, flow):
        self.requests += 1
        if self.fail:
            raise ValueError("flaky boom")


class SlowAsync(TrafficAddon):
    def __init__(self, name="slow", delay=30.0):
        super().__init__(name)
        self.delay = delay
        self.started = asyncio.Event()
        self.finished = asyncio.Event()

    async def request(self, flow):
        self.requests += 1
        self.started.set()
        await asyncio.sleep(self.delay)
        self.finished.set()


class AsyncDone(SyncFail):
    def __init__(self, name="asyncdone"):
        super().__init__(name)
        self.done_ran = asyncio.Event()

    async def done(self):
        self.done_count += 1
        self.done_ran.set()


class Halt(TrafficAddon):
    def request(self, flow):
        self.requests += 1
        raise exceptions.AddonHalt


def isolated_task_names():
    return [t.get_name() for t in asyncio.all_tasks() if "isolated" in t.get_name()]


def enable(tctx, **kwargs):
    tctx.options.update(addon_isolation=True, **kwargs)


# -- default behaviour ---------------------------------------------------------


async def test_disabled_by_default(caplog):
    with taddons.context(script.ScriptLoader(), loadcore=False) as tctx:
        bad = SyncFail("bad")
        good = TrafficAddon("good")
        tctx.master.addons.add(bad, good)
        tctx.master.addons.isolation.guard(bad)

        await tctx.master.addons.trigger_event(traffic_event())

        # Errors are still logged (legacy safecall behaviour)...
        assert "Addon error" in caplog.text
        # ...but the addon is not isolated and keeps being invoked.
        assert not tctx.master.addons.isolation.is_isolated(bad)
        assert bad.requests == 1
        assert good.requests == 1

        # The option exists and defaults to off.
        assert tctx.options.addon_isolation is False
        assert tctx.options.addon_isolation_timeout == 10.0
        assert tctx.options.addon_isolation_max_failures == 3


async def test_disabled_after_isolation_runs_legacy(caplog):
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        bad = SyncFail("bad")
        tctx.master.addons.add(bad)
        tctx.master.addons.isolation.guard(bad)

        tctx.options.update(addon_isolation=True, addon_isolation_max_failures=1)
        await tctx.master.addons.trigger_event(traffic_event())
        assert tctx.master.addons.isolation.is_isolated(bad)
        caplog.clear()

        # Switching the feature off restores the legacy behaviour: the addon
        # is invoked again even though it used to be isolated.
        tctx.options.update(addon_isolation=False)
        await tctx.master.addons.trigger_event(traffic_event())
        assert bad.requests == 2
        assert "Addon error" in caplog.text


# -- sync / async exceptions ----------------------------------------------------


async def test_sync_exception_isolates(caplog):
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = SyncFail("bad")
        good = TrafficAddon("good")
        tctx.master.addons.add(bad, good)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=2)

        await tctx.master.addons.trigger_event(traffic_event())
        assert not iso.is_isolated(bad)
        assert iso.status(bad).failures == 1

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)

        info = iso.status(bad)
        assert info.isolated
        assert info.reason == "failures"
        assert info.failures == 2
        assert info.last_hook == "request"
        assert "ValueError" in info.last_error
        assert "Isolating addon bad" in caplog.text

        # The isolated addon is skipped...
        await tctx.master.addons.trigger_event(traffic_event())
        assert bad.requests == 2
        # ...while the other addon keeps processing traffic in order.
        assert good.requests == 3


async def test_async_exception_isolates():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = AsyncFail("asyncbad")
        good = TrafficAddon("good")
        tctx.master.addons.add(bad, good)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=1)

        await tctx.master.addons.trigger_event(traffic_event())

        assert iso.is_isolated(bad)
        assert iso.status(bad).reason == "failures"
        assert "RuntimeError" in iso.status(bad).last_error
        assert bad.requests == 1

        await tctx.master.addons.trigger_event(traffic_event())
        assert bad.requests == 1
        assert good.requests == 2


async def test_success_resets_failure_count():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        flaky = Flaky()
        tctx.master.addons.add(flaky)
        iso.guard(flaky)
        enable(tctx, addon_isolation_max_failures=2)

        async def trigger():
            await tctx.master.addons.trigger_event(traffic_event())

        await trigger()  # failure 1
        assert iso.status(flaky).failures == 1
        flaky.fail = False
        await trigger()  # success -> counter reset
        assert iso.status(flaky).failures == 0
        assert not iso.is_isolated(flaky)
        flaky.fail = True
        await trigger()  # failure 1 again
        assert not iso.is_isolated(flaky)
        assert iso.status(flaky).failures == 1
        await trigger()  # failure 2 -> isolate
        assert iso.is_isolated(flaky)


async def test_addonhalt_still_propagates():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        halt = Halt("halt")
        end = TrafficAddon("end")
        tctx.master.addons.add(halt, end)
        iso.guard(halt)
        enable(tctx)

        await tctx.master.addons.trigger_event(traffic_event())
        assert halt.requests == 1
        assert end.requests == 0
        assert not iso.is_isolated(halt)


# -- timeout --------------------------------------------------------------------


async def test_timeout_isolates_and_cancels_coroutine():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        slow = SlowAsync(delay=30.0)
        good = TrafficAddon("good")
        tctx.master.addons.add(slow, good)
        iso.guard(slow)
        enable(tctx, addon_isolation_timeout=0.1)

        loop = asyncio.get_running_loop()
        start = loop.time()
        await tctx.master.addons.trigger_event(traffic_event())
        elapsed = loop.time() - start

        # The hanging hook must not block traffic processing.
        assert elapsed < 10
        assert iso.is_isolated(slow)
        info = iso.status(slow)
        assert info.reason == "timeout"
        assert info.failures == 1
        assert "did not complete" in info.last_error
        assert slow.started.is_set()

        # The runaway coroutine is cancelled: wait long enough for it to
        # notice, then make sure it never completed.
        await asyncio.sleep(0.3)
        assert not slow.finished.is_set()

        # No timeout-produced tasks are left behind...
        assert isolated_task_names() == []
        # ...the isolated addon is skipped on subsequent traffic...
        await tctx.master.addons.trigger_event(traffic_event())
        assert slow.requests == 1
        # ...and other addons are still called promptly.
        assert good.requests == 2


async def test_hook_completing_in_time_is_not_isolated():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation

        class Quick(SlowAsync):
            pass

        quick = Quick(name="quick", delay=0.01)
        tctx.master.addons.add(quick)
        iso.guard(quick)
        enable(tctx, addon_isolation_timeout=5.0)

        await tctx.master.addons.trigger_event(traffic_event())
        assert not iso.is_isolated(quick)
        assert iso.status(quick).failures == 0
        assert quick.finished.is_set()


async def test_caller_cancellation_does_not_leak_task():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        slow = SlowAsync(delay=30.0)
        tctx.master.addons.add(slow)
        iso.guard(slow)
        enable(tctx, addon_isolation_timeout=10.0)

        event = traffic_event()
        task = asyncio.ensure_future(tctx.master.addons.trigger_event(event))
        await asyncio.sleep(0.1)
        assert slow.started.is_set()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.1)
        assert isolated_task_names() == []


# -- nested addons ---------------------------------------------------------------


async def test_nested_addon_isolation():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = SyncFail("badchild")
        good = TrafficAddon("goodchild")
        parent = TrafficAddon("parent", addons=[bad, good])
        tctx.master.addons.add(parent)
        iso.guard(parent)
        enable(tctx, addon_isolation_max_failures=1)

        assert iso.is_guarded(parent)
        assert iso.is_guarded(bad)
        assert iso.is_guarded(good)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)
        assert not iso.is_isolated(parent)
        assert not iso.is_isolated(good)

        await tctx.master.addons.trigger_event(traffic_event())
        assert bad.requests == 1  # skipped now
        assert parent.requests == 2
        assert good.requests == 2

        # Removing the parent delivers done to the isolated child as well.
        tctx.master.addons.remove(parent)
        assert bad.done_count == 1
        assert good.done_count == 1
        assert parent.done_count == 1

        # State is dropped for the whole subtree.
        assert iso.status(bad) is None
        assert iso.status(good) is None
        assert iso.status(parent) is None


async def test_isolated_addon_skipped_in_sync_path():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = SyncFail("bad")
        tctx.master.addons.add(bad)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=1)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)
        before = bad.configure_count
        # Options changes trigger the sync configure hook.
        tctx.options.update(addon_isolation_timeout=1.0)
        assert bad.configure_count == before


async def test_unguard_cancels_pending_tasks():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        addon = TrafficAddon("leak")
        tctx.master.addons.add(addon)
        iso.guard(addon)

        state = iso._states[addon]
        task = asyncio.get_running_loop().create_task(asyncio.sleep(3600))
        state.pending.add(task)

        iso.unguard(addon)
        await asyncio.sleep(0)  # let the scheduled cancellation take effect
        assert task.cancelled()
        assert not iso.is_guarded(addon)


# -- runtime unload / cleanup ----------------------------------------------------


async def test_done_hook_still_runs_for_isolated_addon():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = TrafficAddon("bad")
        tctx.master.addons.add(bad)
        iso.guard(bad)
        state = iso._states[bad]
        state.isolated = True
        state.reason = "failures"

        tctx.master.addons.remove(bad)
        assert bad.done_count == 1
        assert iso.status(bad) is None


async def test_async_done_hook_runs_on_shutdown():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = AsyncDone()
        good = TrafficAddon("good")
        tctx.master.addons.add(bad, good)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=1)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)
        requests_after_isolation = bad.requests
        done_before = bad.done_count

        # Simulate mitmproxy shutdown.
        await tctx.master.done()

        # The isolated addon received its cleanup hook...
        assert bad.done_count == done_before + 1
        assert bad.done_ran.is_set()
        # ...but no traffic hooks during/after shutdown...
        assert bad.requests == requests_after_isolation
        # ...and no tasks are left behind.
        assert isolated_task_names() == []


async def test_watcher_task_cancelled_on_remove(tmp_path):
    script_file = tmp_path / "watched.py"
    script_file.write_text("\n")
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        tctx.options.update(scripts=[str(script_file)])
        await asyncio.sleep(0.3)  # let the watcher perform its initial load
        assert tctx.master.addons.get(str(script_file)) is not None

        tctx.options.update(scripts=[])
        await asyncio.sleep(0.1)
        watchers = [t for t in asyncio.all_tasks() if "script watcher" in t.get_name()]
        assert not watchers


# -- manual recovery ---------------------------------------------------------------


async def test_manual_recovery():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = SyncFail("bad")
        tctx.master.addons.add(bad)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=1)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)

        assert iso.recover(bad)
        info = iso.status(bad)
        assert not info.isolated
        assert info.failures == 0
        assert info.reason is None
        assert info.last_error is None

        # The addon receives traffic again (and immediately re-isolates
        # because it still fails).
        await tctx.master.addons.trigger_event(traffic_event())
        assert bad.requests == 2
        assert iso.is_isolated(bad)

        # Recovery by name also works.
        assert iso.recover("bad")
        assert not iso.is_isolated(bad)

        # Unknown addons are reported as not found.
        assert not iso.recover("does-not-exist")
        assert not iso.recover(TrafficAddon("unguarded"))


async def test_recover_command():
    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        iso = tctx.master.addons.isolation
        bad = SyncFail("bad")
        tctx.master.addons.add(bad)
        iso.guard(bad)
        enable(tctx, addon_isolation_max_failures=1)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(bad)
        assert sl.addon_isolation_options() == ["bad"]

        tctx.command(sl.addon_recover, "bad")
        assert not iso.is_isolated(bad)

        with pytest.raises(exceptions.CommandError):
            tctx.command(sl.addon_recover, "nobody")


# -- script integration ------------------------------------------------------------


BAD_SCRIPT = """
def request(flow):
    raise ValueError("bad script boom")


def done():
    import logging
    logging.info("bad script done")
"""

GOOD_SCRIPT = """
def request(flow):
    flow.request.headers["x-good-script"] = "1"
"""

NESTED_BAD_SCRIPT = """
class Child:
    name = "iso_script_child"

    def __init__(self):
        self.calls = 0
        self.dones = 0

    def request(self, flow):
        self.calls += 1
        raise RuntimeError("child boom")

    def done(self):
        self.dones += 1


addons = [Child()]
"""


async def test_script_isolated_and_reload_resets_state(tmp_path, caplog):
    caplog.set_level("INFO")
    script_path = tmp_path / "isobad.py"
    script_path.write_text(BAD_SCRIPT)

    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        tctx.options.update(
            scripts=[str(script_path)],
            addon_isolation=True,
            addon_isolation_max_failures=1,
        )
        await asyncio.sleep(0.3)  # let the watcher load the script

        old_ns = tctx.master.addons.get(str(script_path))
        assert old_ns is not None

        await tctx.master.addons.trigger_event(traffic_event())
        iso = tctx.master.addons.isolation
        assert iso.is_isolated(old_ns)
        assert "bad script boom" in iso.status(old_ns).last_error

        # A healthy sibling addon is unaffected.
        good = TrafficAddon("good")
        tctx.master.addons.add(good)
        await tctx.master.addons.trigger_event(traffic_event())
        assert good.requests == 1

        # Rewrite and reload: the new script instance must not inherit the
        # isolation state of the old instance, and the old instance gets its
        # done cleanup and is discarded.
        script_path.write_text(GOOD_SCRIPT)
        sc = sl.addons[0]
        sc.loadscript()

        assert iso.status(old_ns) is None
        new_ns = sc.ns
        assert new_ns is not old_ns
        assert not iso.is_isolated(new_ns)

        flow = tflow.tflow()
        await tctx.master.addons.trigger_event(HttpRequestHook(flow))
        assert flow.request.headers["x-good-script"] == "1"
        assert "bad script done" in caplog.text

        tctx.master.addons.remove(sc)
        await asyncio.sleep(0.1)
        assert isolated_task_names() == []


async def test_nested_script_addon_isolation(tmp_path):
    script_path = tmp_path / "isonested.py"
    script_path.write_text(NESTED_BAD_SCRIPT)

    sl = script.ScriptLoader()
    with taddons.context(sl, loadcore=False) as tctx:
        tctx.options.update(
            scripts=[str(script_path)],
            addon_isolation=True,
            addon_isolation_max_failures=1,
        )
        await asyncio.sleep(0.3)

        child = tctx.master.addons.get("iso_script_child")
        assert child is not None
        iso = tctx.master.addons.isolation
        assert iso.is_guarded(child)

        await tctx.master.addons.trigger_event(traffic_event())
        assert iso.is_isolated(child)
        calls = child.calls

        await tctx.master.addons.trigger_event(traffic_event())
        assert child.calls == calls  # skipped

        # Unloading the script still delivers done to the isolated child.
        tctx.options.update(scripts=[])
        await asyncio.sleep(0.2)
        assert child.dones == 1
        assert iso.status(child) is None
