"""Plugin 04: SMB signing status."""
from typing import Any, Dict

from smbscan.plugins.base import Plugin


def _label(enabled: bool, required: bool) -> str:
    return "required" if required else ("enabled" if enabled else "disabled")


class SmbSigningPlugin(Plugin):
    name = "smb_signing"
    description = "Reads SecurityMode flags from the negotiate response"
    requires_auth = False

    def run(self, host: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        smb2 = ctx.get("smb2")
        if smb2:
            mode = smb2["security_mode"]
            return {"signing": _label(bool(mode & 1), bool(mode & 2))}
        smb1 = ctx.get("smb1")
        if smb1:
            return {"signing": _label(smb1["signing_enabled"], smb1["signing_required"])}
        return {"signing": "unknown"}
