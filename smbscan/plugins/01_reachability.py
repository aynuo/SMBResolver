"""Plugin 01: TCP reachability (445, then 139)."""
from typing import Any, Dict

from smbscan.plugins.base import Plugin
from smbscan.protocols.smb import NBSS_PORT, SMB_PORT, probe_port


class ReachabilityPlugin(Plugin):
    name = "reachability"
    description = "Checks TCP 445 then 139; aborts the host if neither is open"
    requires_auth = False

    def run(self, host: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        timeout = ctx.get("timeout", 3.0)
        for port in (SMB_PORT, NBSS_PORT):
            if probe_port(host, port, timeout):
                return {"up": True, "smb_port": port}
        return {"up": False, "smb_port": None, "abort": True}
