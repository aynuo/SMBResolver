"""Plugin 02: hostname via NetBIOS, falling back to reverse DNS."""
import socket
from typing import Any, Dict

from smbscan.plugins.base import Plugin
from smbscan.protocols.netbios import node_status_query


class HostnamePlugin(Plugin):
    name = "hostname"
    description = "NBNS node status query (UDP 137) with gethostbyaddr fallback"
    requires_auth = False

    def run(self, host: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        timeout = ctx.get("timeout", 3.0)
        status = node_status_query(host, timeout)
        if status and status.hostname:
            return {"hostname": status.hostname, "hostname_source": "netbios",
                    "mac": status.mac, "workgroup": status.workgroup}
        out: Dict[str, Any] = {"hostname": None, "hostname_source": None,
                               "mac": status.mac if status else None,
                               "workgroup": status.workgroup if status else None}
        try:
            out["hostname"] = socket.gethostbyaddr(host)[0]
            out["hostname_source"] = "dns"
        except OSError:
            pass
        return out
