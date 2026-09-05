from __future__ import annotations

from mitmproxy import flow
from mitmproxy import lineage


class Lineage:
    """
    Assigns root lineage metadata to live flows when the ``flow_lineage``
    option is enabled.
    """

    def load(self, loader):
        loader.add_option(
            "flow_lineage",
            bool,
            False,
            """
            Track optional flow lineage metadata: Original flows get a stable
            root id, duplicates are linked to their parent flow, client
            replays keep the root id and get a per-attempt number, and
            imported flows (flow files and HAR files) get isolated identities.
            Disabled by default for full backward compatibility.
            """,
        )

    def requestheaders(self, f: flow.Flow):
        lineage.ensure_root(f)

    def response(self, f: flow.Flow):
        lineage.ensure_root(f)

    def error(self, f: flow.Flow):
        lineage.ensure_root(f)

    def tcp_start(self, f: flow.Flow):
        lineage.ensure_root(f)

    def tcp_error(self, f: flow.Flow):
        lineage.ensure_root(f)

    def udp_start(self, f: flow.Flow):
        lineage.ensure_root(f)

    def udp_error(self, f: flow.Flow):
        lineage.ensure_root(f)

    def dns_request(self, f: flow.Flow):
        lineage.ensure_root(f)

    def dns_error(self, f: flow.Flow):
        lineage.ensure_root(f)
