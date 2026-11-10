"""Minimal SMB1 / SMB2 / SMB3 negotiate implementation over raw sockets."""
from __future__ import annotations

import os
import socket
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

SMB_PORT = 445
NBSS_PORT = 139
MAX_PACKET = 1 << 20

DIALECT_NAMES = {
    0x0202: "SMBv2.0.2",
    0x0210: "SMBv2.1",
    0x0300: "SMBv3.0",
    0x0302: "SMBv3.0.2",
    0x0311: "SMBv3.1.1",
    0x02FF: "SMBv2 (wildcard)",
}
SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
SMB1_DIALECTS = ("PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12")


class SMBError(Exception):
    """Raised on protocol-level failures (bad framing, bad status...)."""


@dataclass
class Smb1Result:
    """Outcome of an SMB1 negotiate."""
    supported: bool
    dialect: Optional[str] = None
    signing_enabled: bool = False
    signing_required: bool = False
    note: str = ""


@dataclass
class Smb2Result:
    """Outcome of an SMB2/3 negotiate."""
    dialect_revision: int
    security_mode: int
    capabilities: int

    @property
    def version(self) -> str:
        return DIALECT_NAMES.get(self.dialect_revision, f"SMB 0x{self.dialect_revision:04x}")

    @property
    def signing_enabled(self) -> bool:
        return bool(self.security_mode & 0x01)

    @property
    def signing_required(self) -> bool:
        return bool(self.security_mode & 0x02)


# ---------------------------------------------------------------- framing

def nbss_frame(payload: bytes) -> bytes:
    """Prefix payload with the 4-byte NetBIOS Session Service header."""
    return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SMBError("connection closed by peer")
        buf += chunk
    return bytes(buf)


def recv_packet(sock: socket.socket) -> bytes:
    """Receive one NBSS-framed message and return its payload."""
    hdr = _recv_exact(sock, 4)
    length = int.from_bytes(hdr[1:4], "big")
    if length > MAX_PACKET:
        raise SMBError("oversized packet")
    return _recv_exact(sock, length) if length else b""


def _l1_encode(name: str, suffix: int) -> bytes:
    raw = name.upper().ljust(15)[:15].encode("ascii", "replace") + bytes([suffix])
    out = bytearray()
    for b in raw:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return b"\x20" + bytes(out) + b"\x00"


def _session_request(sock: socket.socket) -> None:
    """RFC 1002 session request (port 139)."""
    body = _l1_encode("*SMBSERVER", 0x20) + _l1_encode("SMBSCAN", 0x00)
    sock.sendall(b"\x81\x00" + struct.pack(">H", len(body)) + body)
    hdr = _recv_exact(sock, 4)
    if hdr[0] != 0x82:
        raise SMBError(f"NetBIOS session request refused (0x{hdr[0]:02x})")


def probe_port(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@contextmanager
def smb_connection(host: str, port: int, timeout: float) -> Iterator[socket.socket]:
    """Open a TCP connection (with session request on 139); always closed."""
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if port == NBSS_PORT:
            _session_request(sock)
        yield sock
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------- SMB1

def build_smb1_negotiate() -> bytes:
    """Build an SMB1 Negotiate Protocol Request (NBSS framed)."""
    header = (b"\xffSMB" + b"\x72" + struct.pack("<I", 0) + b"\x18"
              + struct.pack("<HH", 0xC853, 0) + b"\x00" * 8
              + struct.pack("<HHHHH", 0, 0, 0xFEFF, 0, 0))
    dialects = b"".join(b"\x02" + d.encode("ascii") + b"\x00" for d in SMB1_DIALECTS)
    body = b"\x00" + struct.pack("<H", len(dialects)) + dialects
    return nbss_frame(header + body)


def smb1_negotiate(host: str, port: int, timeout: float) -> Smb1Result:
    """Probe SMBv1 support. Network errors propagate as OSError."""
    with smb_connection(host, port, timeout) as sock:
        sock.sendall(build_smb1_negotiate())
        data = recv_packet(sock)
    if data[:4] == b"\xfeSMB":
        return Smb1Result(False, note="server answered with SMB2")
    if data[:4] != b"\xffSMB" or len(data) < 36:
        return Smb1Result(False, note="malformed SMB1 response")
    status = struct.unpack("<I", data[5:9])[0]
    if status != 0:
        return Smb1Result(False, note=f"status 0x{status:08x}")
    (idx,) = struct.unpack("<H", data[33:35])
    if idx >= len(SMB1_DIALECTS):
        return Smb1Result(False, note="no common dialect")
    secmode = data[35]
    return Smb1Result(True, SMB1_DIALECTS[idx], bool(secmode & 0x04), bool(secmode & 0x08))


# ------------------------------------------------------------------- SMB2

def build_smb2_negotiate() -> bytes:
    """Build an SMB2 Negotiate request offering 2.0.2 - 3.1.1 (NBSS framed)."""
    header = (b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
              + b"\x00" * 16)
    n = len(SMB2_DIALECTS)
    ctx_offset = (64 + 36 + 2 * n + 7) & ~7
    fixed = struct.pack("<HHHHI", 36, n, 0x0001, 0, 0x7F) + os.urandom(16)
    fixed += struct.pack("<IHH", ctx_offset, 2, 0)
    dialects = b"".join(struct.pack("<H", d) for d in SMB2_DIALECTS)
    pad = b"\x00" * (ctx_offset - (64 + 36 + len(dialects)))
    salt = os.urandom(32)
    preauth = struct.pack("<HH", 1, 32) + struct.pack("<H", 1) + salt  # SHA-512
    c1 = struct.pack("<HHI", 1, len(preauth), 0) + preauth
    c1 += b"\x00" * (-len(c1) % 8)
    enc = struct.pack("<HH", 1, 0x0002)  # AES-128-GCM
    c2 = struct.pack("<HHI", 2, len(enc), 0) + enc
    return nbss_frame(header + fixed + dialects + pad + c1 + c2)


def smb2_negotiate(host: str, port: int, timeout: float) -> Smb2Result:
    """Perform an SMB2/3 negotiate.

    Raises:
        SMBError: non-SMB2 reply or error status.
        OSError: network failure (including socket.timeout).
    """
    with smb_connection(host, port, timeout) as sock:
        sock.sendall(build_smb2_negotiate())
        data = recv_packet(sock)
    if data[:4] != b"\xfeSMB":
        raise SMBError("not an SMB2 response")
    if len(data) < 92:
        raise SMBError("truncated SMB2 negotiate response")
    (status,) = struct.unpack("<I", data[8:12])
    if status != 0:
        raise SMBError(f"SMB2 negotiate failed, status 0x{status:08x}")
    secmode, dialect = struct.unpack("<HH", data[66:70])
    (caps,) = struct.unpack("<I", data[88:92])
    return Smb2Result(dialect, secmode, caps)
