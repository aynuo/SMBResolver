"""Plugin 03: SMB version detection."""
from typing import Any, Dict

from smbscan.plugins.base import Plugin
from smbscan.protocols.smb import SMBError, smb1_negotiate, smb2_negotiate


class SmbVersionPlugin(Plugin):
    name = "smb_version"
    description = "Negotiates SMB1 and SMB2/3 to find supported/selected dialects"
    requires_auth = False

    def run(self, host: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        timeout = ctx.get("timeout", 3.0)
        port = ctx.get("smb_port") or 445
        out: Dict[str, Any] = {"smb_version": None, "smb1_enabled": None}
        try:
            r2 = smb2_negotiate(host, port, timeout)
            out["smb_version"] = r2.version
            out["smb2"] = {"dialect": r2.dialect_revision, "security_mode": r2.security_mode,
                           "capabilities": r2.capabilities}
        except (SMBError, OSError) as exc:
            out["smb2_error"] = str(exc) or type(exc).__name__
        try:
            r1 = smb1_negotiate(host, port, timeout)
            out["smb1_enabled"] = r1.supported
            if r1.supported:
                out["smb1"] = {"dialect": r1.dialect, "signing_enabled": r1.signing_enabled,
                               "signing_required": r1.signing_required}
                if out["smb_version"] is None:
                    out["smb_version"] = "SMBv1"
        except (SMBError, OSError) as exc:
            out["smb1_error"] = str(exc) or type(exc).__name__
            if "smb2" in out:
                out["smb1_enabled"] = False
        if out["smb_version"] is None:
            out["smb_version"] = "unknown"
        return out
