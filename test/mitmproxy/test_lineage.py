from __future__ import annotations

import json
import uuid
from io import BytesIO

from mitmproxy import flow as flow_mod
from mitmproxy import io
from mitmproxy import lineage
from mitmproxy.addons.clientplayback import ClientPlayback
from mitmproxy.addons.clientplayback import ReplayHandler
from mitmproxy.addons.lineage import Lineage
from mitmproxy.addons.savehar import SaveHar
from mitmproxy.addons.view import View
from mitmproxy.test import taddons
from mitmproxy.test import tflow


def _lin(f: flow_mod.Flow) -> dict:
    lin = lineage.get(f)
    assert lin is not None
    return lin


def _is_uuid4(s: str) -> bool:
    return uuid.UUID(s).version == 4


def _is_uuid5(s: str) -> bool:
    return uuid.UUID(s).version == 5


class TestDisabledByDefault:
    def test_no_lineage_for_new_flows(self):
        f = tflow.tflow(resp=True, live=False)
        assert lineage.get(f) is None
        assert lineage.METADATA_KEY not in f.metadata

    def test_copy_has_no_lineage(self):
        f = tflow.tflow(resp=True, live=False)
        c = f.copy()
        assert lineage.get(c) is None
        assert lineage.METADATA_KEY not in c.metadata
        # default behaviour unchanged: copy gets a fresh id
        assert c.id != f.id

    def test_copy_strips_stale_lineage(self):
        # A flow that carries lineage data (e.g. read from a file that was
        # written with lineage enabled) must not propagate it when tracking
        # is disabled.
        f = tflow.tflow(resp=True, live=False)
        f.metadata[lineage.METADATA_KEY] = {
            "root_id": "root-from-elsewhere",
            "parent_id": None,
            "attempt": 0,
            "origin": lineage.ORIGIN_ORIGINAL,
        }
        c = f.copy()
        assert lineage.get(c) is None
        assert lineage.METADATA_KEY not in c.metadata

    def test_import_is_unchanged(self):
        f = tflow.tflow(resp=True, live=False)
        original_id = f.id
        buf = BytesIO()
        io.FlowWriter(buf).add(f)
        buf.seek(0)
        with taddons.context(Lineage()):
            (loaded,) = list(io.FlowReader(buf).stream())
        # lineage disabled: id is preserved, no import lineage
        assert loaded.id == original_id
        assert lineage.get(loaded) is None


class TestRootAndCopy:
    def test_ensure_root(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            assert lineage.ensure_root(f) is not None
            lin = _lin(f)
            assert lin["root_id"] == f.id
            assert lin["parent_id"] is None
            assert lin["attempt"] == 0
            assert lin["origin"] == lineage.ORIGIN_ORIGINAL
            # idempotent
            assert lineage.ensure_root(f) is lin

    def test_ensure_root_disabled(self):
        with taddons.context(Lineage()):
            f = tflow.tflow(resp=True, live=False)
            assert lineage.ensure_root(f) is None
            assert lineage.get(f) is None

    def test_copy_creates_child(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            root = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(root)

            child = root.copy()
            rlin = _lin(root)
            clin = _lin(child)
            assert child.id != root.id
            assert clin["root_id"] == rlin["root_id"] == root.id
            assert clin["parent_id"] == root.id
            assert clin["origin"] == lineage.ORIGIN_COPY
            assert clin["attempt"] == 0

            grandchild = child.copy()
            glin = _lin(grandchild)
            assert glin["root_id"] == root.id
            assert glin["parent_id"] == child.id
            assert glin["origin"] == lineage.ORIGIN_COPY

    def test_copy_of_untracked_flow_gets_rooted(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)  # never went through a hook
            c = f.copy()
            assert lineage.get(f) is not None
            assert _lin(c)["root_id"] == f.id
            assert _lin(c)["parent_id"] == f.id

    def test_view_assigns_roots(self):
        lin_addon = Lineage()
        v = View()
        with taddons.context(lin_addon, v) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            v.add([f])
            assert lineage.get(f) is not None
            # manually created flows are originals
            v.create("GET", "https://example.com/")
            created = v[-1]
            assert _lin(created)["origin"] == lineage.ORIGIN_ORIGINAL

    async def test_addon_hooks_assign_roots(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            assert lineage.get(f) is None
            await tctx.cycle(lin_addon, f)
            assert _lin(f)["origin"] == lineage.ORIGIN_ORIGINAL
            assert _lin(f)["root_id"] == f.id


class TestClientReplay:
    def _drain(self, cp: ClientPlayback) -> list:
        out = []
        while True:
            try:
                out.append(cp.queue.get_nowait())
            except Exception:
                break
        return out

    def test_replay_creates_attempt(self):
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)

            f = tflow.tflow(resp=True, live=False)
            v = View()
            v.add([f])
            original_response = f.response
            cp.start_replay([f])

            (attempt,) = self._drain(cp)
            assert attempt is not f
            alin = _lin(attempt)
            assert alin["origin"] == lineage.ORIGIN_REPLAY
            assert alin["root_id"] == f.id
            assert alin["parent_id"] == f.id
            assert alin["attempt"] == 1
            assert attempt.is_replay == "request"
            assert attempt.response is None

            # the source flow is never mutated
            assert lineage.get(f)["origin"] == lineage.ORIGIN_ORIGINAL
            assert f.is_replay is None
            assert f.response is original_response
            assert not f.modified()

    def test_concurrent_replays_get_distinct_attempts(self):
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(f)

            # queue the same source twice in one call
            cp.start_replay([f, f])
            attempts = self._drain(cp)
            assert {a.id for a in attempts} == {a.id for a in attempts}
            assert len({a.id for a in attempts}) == 2
            assert sorted(_lin(a)["attempt"] for a in attempts) == [1, 2]
            for a in attempts:
                assert _lin(a)["root_id"] == f.id
                assert _lin(a)["parent_id"] == f.id

            # a later replay continues the per-root counter
            cp.start_replay([f])
            (third,) = self._drain(cp)
            assert _lin(third)["attempt"] == 3

    def test_replay_preserves_root_across_copies(self):
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            root = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(root)
            copy = root.copy()

            cp.start_replay([copy])
            (attempt,) = self._drain(cp)
            alin = _lin(attempt)
            assert alin["root_id"] == root.id
            assert alin["parent_id"] == copy.id
            assert alin["attempt"] == 1

            cp.start_replay([attempt])
            (second,) = self._drain(cp)
            slin = _lin(second)
            assert slin["root_id"] == root.id
            assert slin["parent_id"] == attempt.id
            assert slin["attempt"] == 2

    def test_cancelled_replay_leaves_no_relation(self):
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(f)

            cp.start_replay([f])
            assert cp.count() == 1
            cp.stop_replay()
            assert cp.count() == 0

            # source is untouched: no backup, no mutation, still a plain root
            assert f.is_replay is None
            assert not f.modified()
            assert _lin(f) == {
                "root_id": f.id,
                "parent_id": None,
                "attempt": 0,
                "origin": lineage.ORIGIN_ORIGINAL,
            }

    async def test_failed_replay_leaves_source_untouched(
        self, monkeypatch, caplog_async
    ):
        async def raise_err(*_, **__):
            raise ValueError("boom")

        monkeypatch.setattr(ReplayHandler, "replay", raise_err)
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(live=False)
            f.request.content = b"data"
            f.request.host, f.request.port = "127.0.0.1", 1
            lineage.ensure_root(f)

            cp.running()
            cp.start_replay([f])
            await caplog_async.await_log("Client replay has crashed!")
            assert cp.count() == 0
            await cp.done()

            # source is untouched and does not reference any failed attempt
            assert f.is_replay is None
            assert f.response is None
            assert not f.modified()
            assert _lin(f)["parent_id"] is None
            assert _lin(f)["attempt"] == 0

    def test_disabled_replay_mutates_in_place(self):
        cp = ClientPlayback()
        with taddons.context(cp):
            f = tflow.tflow(resp=True, live=False)
            original_id = f.id
            cp.start_replay([f])
            (queued,) = self._drain(cp)
            # legacy behaviour: the source flow itself is replayed in place
            assert queued is f
            assert queued.id == original_id
            assert lineage.get(queued) is None


class TestMitmImport:
    def test_lineage_roundtrip_preserved_and_isolated(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)

            root = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(root)
            child = root.copy()
            root_file_id, child_file_id = root.id, child.id

            buf = BytesIO()
            w = io.FlowWriter(buf)
            w.add(root)
            w.add(child)
            data = buf.getvalue()

            def read():
                return list(io.FlowReader(BytesIO(data)).stream())

            first = read()
            assert [f.id for f in first] != [root_file_id, child_file_id]
            r, c = first
            assert _is_uuid5(r.id) and _is_uuid5(c.id)
            # relationships are consistent within the import
            assert _lin(r)["root_id"] == r.id
            assert _lin(r)["parent_id"] is None
            assert _lin(c)["root_id"] == r.id
            assert _lin(c)["parent_id"] == r.id
            # origin data is preserved
            assert _lin(r)["origin"] == lineage.ORIGIN_ORIGINAL
            assert _lin(c)["origin"] == lineage.ORIGIN_COPY

            # importing the same content again yields entirely fresh ids
            second = read()
            assert [f.id for f in second] != [f.id for f in first]
            r2, c2 = second
            assert _lin(c2)["root_id"] == r2.id
            assert _lin(c2)["parent_id"] == r2.id
            # nothing from the second import collides with the first
            second_ids = {f.id for f in second} | {
                _lin(f)["root_id"] for f in second
            }
            first_ids = {f.id for f in first} | {_lin(f)["root_id"] for f in first}
            assert second_ids.isdisjoint(first_ids)

    def test_old_file_gets_isolated_import_root(self):
        # write a flow without lineage (old/current format, feature off)
        f = tflow.tflow(resp=True, live=False)
        old_id = f.id
        buf = BytesIO()
        io.FlowWriter(buf).add(f)
        data = buf.getvalue()

        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            (loaded,) = list(io.FlowReader(BytesIO(data)).stream())
            lin = _lin(loaded)
            assert lin["origin"] == lineage.ORIGIN_IMPORT
            assert lin["parent_id"] is None
            assert lin["attempt"] == 0
            assert lin["root_id"] == loaded.id
            assert loaded.id != old_id
            assert _is_uuid5(loaded.id)

            # repeated import of the same old file stays isolated
            (again,) = list(io.FlowReader(BytesIO(data)).stream())
            assert again.id != loaded.id

    def test_malformed_lineage_is_replaced(self):
        f = tflow.tflow(resp=True, live=False)
        f.metadata[lineage.METADATA_KEY] = {"root_id": 12345}
        buf = BytesIO()
        io.FlowWriter(buf).add(f)
        data = buf.getvalue()

        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            (loaded,) = list(io.FlowReader(BytesIO(data)).stream())
            lin = _lin(loaded)
            assert lin["origin"] == lineage.ORIGIN_IMPORT
            assert lin["root_id"] == loaded.id
            assert lin["parent_id"] is None

    def test_dangling_references_are_isolated(self):
        f = tflow.tflow(resp=True, live=False)
        f.metadata[lineage.METADATA_KEY] = {
            "root_id": "root-from-another-file",
            "parent_id": "parent-from-another-file",
            "attempt": 3,
            "origin": lineage.ORIGIN_REPLAY,
        }
        buf = BytesIO()
        io.FlowWriter(buf).add(f)
        data = buf.getvalue()

        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            (loaded,) = list(io.FlowReader(BytesIO(data)).stream())
            lin = _lin(loaded)
            # remapped to fresh, traceable (uuid5) values that cannot collide
            assert lin["root_id"] != "root-from-another-file"
            assert lin["parent_id"] != "parent-from-another-file"
            assert lin["root_id"] != lin["parent_id"]
            assert _is_uuid5(lin["root_id"])
            assert _is_uuid5(lin["parent_id"])
            assert lin["attempt"] == 3
            assert lin["origin"] == lineage.ORIGIN_REPLAY

    def test_replay_imported_flow_extends_imported_root(self):
        cp = ClientPlayback()
        lin_addon = Lineage()
        with taddons.context(lin_addon, cp) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)

            f = tflow.tflow(resp=True, live=False)
            buf = BytesIO()
            io.FlowWriter(buf).add(f)
            buf.seek(0)
            (imported,) = list(io.FlowReader(buf).stream())
            imported_root = _lin(imported)["root_id"]

            cp.start_replay([imported])
            (attempt,) = [
                cp.queue.get_nowait() for _ in range(cp.queue.qsize())
            ]
            alin = _lin(attempt)
            assert alin["root_id"] == imported_root
            assert alin["parent_id"] == imported.id
            assert alin["attempt"] == 1


class TestHarExchange:
    def _har_bytes(self, flows) -> bytes:
        har = SaveHar().make_har(flows)
        return json.dumps(har).encode()

    def test_har_roundtrip(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            root = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(root)
            child = root.copy()

            data = self._har_bytes([root, child])
            har = json.loads(data)
            entries = har["log"]["entries"]
            assert all(lineage.HAR_FIELD in e for e in entries)

            flows = list(io.FlowReader(BytesIO(data)).stream())
            assert len(flows) == 2
            r, c = flows
            assert _lin(r)["root_id"] == r.id
            assert _lin(c)["root_id"] == r.id
            assert _lin(c)["parent_id"] == r.id
            assert _lin(r)["origin"] == lineage.ORIGIN_ORIGINAL
            assert _lin(c)["origin"] == lineage.ORIGIN_COPY

            # duplicate import stays isolated
            again = list(io.FlowReader(BytesIO(data)).stream())
            assert {f.id for f in again}.isdisjoint({f.id for f in flows})

    def test_har_without_lineage_gets_import_roots(self):
        # HAR produced with lineage disabled contains no lineage field.
        root = tflow.tflow(resp=True, live=False)
        data = self._har_bytes([root])
        assert lineage.HAR_FIELD not in json.loads(data)["log"]["entries"][0]

        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            flows = list(io.FlowReader(BytesIO(data)).stream())
            (loaded,) = flows
            assert _lin(loaded)["origin"] == lineage.ORIGIN_IMPORT
            assert _lin(loaded)["root_id"] == loaded.id
            assert _is_uuid5(loaded.id)

    def test_har_duplicate_entries_stay_isolated_across_imports(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            root = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(root)
            data = self._har_bytes([root])
            har = json.loads(data)
            # same entry twice in one HAR (merged/duplicated content)
            har["log"]["entries"] = har["log"]["entries"] * 2
            data = json.dumps(har).encode()

            flows = list(io.FlowReader(BytesIO(data)).stream())
            assert len(flows) == 2
            # duplicated entries are the same exported flow and group together
            assert flows[0].id == flows[1].id
            assert _lin(flows[0])["root_id"] == _lin(flows[1])["root_id"]

            # re-importing the same duplicated file stays isolated
            again = list(io.FlowReader(BytesIO(data)).stream())
            assert {f.id for f in again}.isdisjoint({f.id for f in flows})

    def test_har_distinct_entries_get_distinct_ids(self):
        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            a = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(a)
            b = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(b)
            data = self._har_bytes([a, b])
            flows = list(io.FlowReader(BytesIO(data)).stream())
            assert len(flows) == 2
            assert flows[0].id != flows[1].id
            assert _lin(flows[0])["root_id"] != _lin(flows[1])["root_id"]


class TestWebJson:
    def test_flow_to_json_includes_lineage(self):
        from mitmproxy.tools.web.app import flow_to_json

        lin_addon = Lineage()
        with taddons.context(lin_addon) as tctx:
            tctx.configure(lin_addon, flow_lineage=True)
            f = tflow.tflow(resp=True, live=False)
            lineage.ensure_root(f)
            j = flow_to_json(f)
            assert j["lineage"] == {
                "root_id": f.id,
                "parent_id": None,
                "attempt": 0,
                "origin": "original",
            }

    def test_flow_to_json_omits_lineage_when_disabled(self):
        from mitmproxy.tools.web.app import flow_to_json

        with taddons.context(Lineage()):
            f = tflow.tflow(resp=True, live=False)
            j = flow_to_json(f)
            assert "lineage" not in j
