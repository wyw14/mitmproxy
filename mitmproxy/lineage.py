"""
Optional flow lineage metadata.

When the ``flow_lineage`` option is enabled, flows carry a small lineage
record in ``flow.metadata`` that describes how a flow instance relates to the
originally captured flow:

- ``root_id``:   stable id of the original flow at the root of the lineage tree
- ``parent_id``: id of the flow this instance was derived from (``None`` for roots)
- ``attempt``:   client-replay attempt counter, unique within a root lineage
- ``origin``:    how this instance came to be (``original``, ``copy``, ``replay`` or ``import``)

The feature is disabled by default, in which case no lineage data is created
and the serialization, copy, replay and import behaviour remains unchanged.
"""

from __future__ import annotations

import uuid
from typing import Any
from typing import TYPE_CHECKING

from mitmproxy import ctx

if TYPE_CHECKING:
    from mitmproxy.flow import Flow

METADATA_KEY = "lineage"
HAR_FIELD = "_mitmproxy_lineage"

ORIGIN_ORIGINAL = "original"
ORIGIN_COPY = "copy"
ORIGIN_REPLAY = "replay"
ORIGIN_IMPORT = "import"
_ORIGINS = {ORIGIN_ORIGINAL, ORIGIN_COPY, ORIGIN_REPLAY, ORIGIN_IMPORT}


def enabled() -> bool:
    """``True`` if flow lineage tracking is currently enabled."""
    return bool(getattr(getattr(ctx, "options", None), "flow_lineage", False))


def get(f: Flow) -> dict[str, Any] | None:
    """Return the flow's lineage record, or ``None`` if it has no valid lineage."""
    lin = f.metadata.get(METADATA_KEY)
    if isinstance(lin, dict) and isinstance(lin.get("root_id"), str) and lin["root_id"]:
        return lin
    return None


def _new_id() -> str:
    return str(uuid.uuid4())


def _root(root_id: str, origin: str) -> dict[str, Any]:
    return {
        "root_id": root_id,
        "parent_id": None,
        "attempt": 0,
        "origin": origin,
    }


def ensure_root(f: Flow, origin: str = ORIGIN_ORIGINAL) -> dict[str, Any] | None:
    """
    Assign a root lineage record to the flow if lineage tracking is enabled
    and it has no valid lineage yet. Returns the (existing or new) record.
    """
    if not enabled():
        return None
    lin = get(f)
    if lin is None:
        lin = _root(f.id, origin)
        f.metadata[METADATA_KEY] = lin
    return lin


def on_copy(src: Flow, dst: Flow) -> None:
    """
    Called after ``dst`` has been copied from ``src``.

    With lineage tracking enabled, the copy becomes a child of the source in
    the same root lineage. When disabled, any lineage data is stripped from
    the copy so that copies never inherit stale relationships.
    """
    if enabled():
        parent = ensure_root(src)
        assert parent is not None
        dst.metadata[METADATA_KEY] = {
            "root_id": parent["root_id"],
            "parent_id": src.id,
            "attempt": parent["attempt"],
            "origin": ORIGIN_COPY,
        }
    else:
        dst.metadata.pop(METADATA_KEY, None)


def next_replay_attempt(src: Flow, counters: dict[str, int]) -> int:
    """
    Return the next unique client-replay attempt number for ``src``'s root
    lineage. ``counters`` stores the highest attempt number per root id so
    that concurrent replays still get distinct attempt numbers.
    """
    parent = ensure_root(src)
    assert parent is not None
    root = parent["root_id"]
    attempt = counters.get(root, parent["attempt"]) + 1
    counters[root] = attempt
    return attempt


def derive_replay(src: Flow, dst: Flow, attempt: int) -> dict[str, Any]:
    """
    Turn ``dst`` (a fresh copy of ``src``) into a client-replay attempt of
    ``src``'s root lineage: the root relationship is preserved, the source
    becomes the parent and the attempt number distinguishes this attempt.
    """
    parent = ensure_root(src)
    assert parent is not None
    lin = {
        "root_id": parent["root_id"],
        "parent_id": src.id,
        "attempt": attempt,
        "origin": ORIGIN_REPLAY,
    }
    dst.metadata[METADATA_KEY] = lin
    return lin


def _coerce(raw: Any) -> dict[str, Any] | None:
    """Validate lineage data read from an external source (flow file or HAR)."""
    if not isinstance(raw, dict):
        return None
    root_id = raw.get("root_id")
    if not isinstance(root_id, str) or not root_id:
        return None

    parent_id = raw.get("parent_id")
    if parent_id is not None and not (isinstance(parent_id, str) and parent_id):
        parent_id = None

    attempt = raw.get("attempt", 0)
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        try:
            attempt = int(attempt)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            attempt = 0
    attempt = max(0, attempt)

    origin = raw.get("origin")
    if origin not in _ORIGINS:
        origin = ORIGIN_IMPORT

    exported_id = raw.get("id")
    if exported_id is not None and not (isinstance(exported_id, str) and exported_id):
        exported_id = None

    return {
        "id": exported_id,
        "root_id": root_id,
        "parent_id": parent_id,
        "attempt": attempt,
        "origin": origin,
    }


def on_import(
    f: Flow,
    namespace: uuid.UUID,
    *,
    har_entry: dict[str, Any] | None = None,
) -> Flow:
    """
    Re-establish lineage identity for a flow read from an external source
    (a ``.mitm`` flow file or a HAR file).

    Every imported flow instance gets a fresh, isolated id that is derived
    deterministically from a per-import random namespace. This keeps
    relationships intact within one import while guaranteeing that repeated
    imports of the same content never reuse an existing flow's id. Flows
    without usable lineage data start a new, isolated root lineage tagged
    ``import`` so they remain traceable.
    """
    if not enabled():
        return f

    raw: Any = None
    if har_entry is not None:
        raw = har_entry.get(HAR_FIELD)
    else:
        raw = f.metadata.get(METADATA_KEY)
    coerced = _coerce(raw)

    old_id = coerced["id"] if (coerced and coerced["id"]) else f.id

    def remap(existing_id: str) -> str:
        return str(uuid.uuid5(namespace, existing_id))

    f.id = remap(old_id)

    if coerced is None:
        f.metadata[METADATA_KEY] = _root(f.id, ORIGIN_IMPORT)
    else:
        f.metadata[METADATA_KEY] = {
            "root_id": remap(coerced["root_id"]),
            "parent_id": remap(coerced["parent_id"]) if coerced["parent_id"] else None,
            "attempt": coerced["attempt"],
            "origin": coerced["origin"],
        }
    return f


__all__ = [
    "METADATA_KEY",
    "HAR_FIELD",
    "ORIGIN_ORIGINAL",
    "ORIGIN_COPY",
    "ORIGIN_REPLAY",
    "ORIGIN_IMPORT",
    "enabled",
    "get",
    "ensure_root",
    "on_copy",
    "next_replay_attempt",
    "derive_replay",
    "on_import",
]
