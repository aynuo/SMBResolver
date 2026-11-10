"""NetBIOS Name Service (UDP/137) node status query (NBSTAT)."""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

NBNS_PORT = 137
NBSTAT_TYPE = 0x0021
CLASS_IN = 0x0001
WILDCARD_NAME = "CK" + "A" * 30  # first-level encoding of '*' + 15 NULs


class NetBIOSError(Exception):
    """Raised on malformed NBNS responses."""


@dataclass
class NetBIOSName:
    """One 18-byte node-status record."""
    name: str
    suffix: int
    flags: int

    @property
    def is_group(self) -> bool:
        return bool(self.flags & 0x8000)


@dataclass
class NodeStatus:
    """Parsed node status response."""
    names: List[NetBIOSName] = field(default_factory=list)
    mac: Optional[str] = None

    @property
    def hostname(self) -> Optional[str]:
        """Unique workstation (<00>) or file server (<20>) name."""
        for wanted in (0x00, 0x20):
            for n in self.names:
                if n.suffix == wanted and not n.is_group and n.name:
                    return n.name
        return None

    @property
    def workgroup(self) -> Optional[str]:
        for n in self.names:
            if n.suffix == 0x00 and n.is_group and n.name:
                return n.name
        return None


def build_node_status_query(txid: int) -> bytes:
    """Build an NBSTAT query packet for the wildcard name."""
    header = struct.pack(">HHHHHH", txid, 0x0010, 1, 0, 0, 0)
    question = b"\x20" + WILDCARD_NAME.encode("ascii") + b"\x00"
    question += struct.pack(">HH", NBSTAT_TYPE, CLASS_IN)
    return header + question


def _skip_name(data: bytes, pos: int) -> int:
    """Return the offset after a (possibly compressed) DNS-style name."""
    while True:
        if pos >= len(data):
            raise NetBIOSError("truncated name")
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        pos += 1 + length


def parse_node_status(data: bytes, txid: Optional[int] = None) -> NodeStatus:
    """Parse an NBSTAT response; raises NetBIOSError if malformed."""
    if len(data) < 12:
        raise NetBIOSError("response too short")
    rid, flags, _qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if txid is not None and rid != txid:
        raise NetBIOSError("transaction id mismatch")
    if not flags & 0x8000 or flags & 0x000F or an < 1:
        raise NetBIOSError("not a successful response")
    try:
        pos = _skip_name(data, 12)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
    except struct.error:
        raise NetBIOSError("truncated answer header") from None
    if rtype != NBSTAT_TYPE:
        raise NetBIOSError("unexpected record type")
    pos += 10
    rdata = data[pos:pos + rdlen]
    if not rdata:
        raise NetBIOSError("empty rdata")
    count = rdata[0]
    if len(rdata) < 1 + count * 18:
        raise NetBIOSError("truncated name table")
    status = NodeStatus()
    for i in range(count):
        rec = rdata[1 + i * 18: 1 + (i + 1) * 18]
        name = rec[:15].decode("ascii", errors="replace").rstrip(" \x00")
        suffix = rec[15]
        (nflags,) = struct.unpack(">H", rec[16:18])
        status.names.append(NetBIOSName(name, suffix, nflags))
    mac_off = 1 + count * 18
    if len(rdata) >= mac_off + 6:
        mac = rdata[mac_off:mac_off + 6]
        if any(mac):
            status.mac = ":".join(f"{b:02X}" for b in mac)
    return status


def node_status_query(host: str, timeout: float = 3.0, retries: int = 2) -> Optional[NodeStatus]:
    """Send an NBSTAT query; return NodeStatus or None when no valid reply.

    Network errors and malformed packets are swallowed (None is returned).
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for _ in range(max(1, retries)):
        txid = struct.unpack(">H", os.urandom(2))[0]
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(build_node_status_query(txid), (host, NBNS_PORT))
                while True:
                    data, addr = sock.recvfrom(4096)
                    if addr[0] != host:
                        continue
                    try:
                        return parse_node_status(data, txid)
                    except NetBIOSError:
                        continue
        except socket.timeout:
            continue
        except OSError:
            return None
    return None
