"""Target parsing: single IPs, ranges, CIDRs and host files."""
from __future__ import annotations

import ipaddress
from typing import Iterable, List

MAX_TARGETS = 1 << 20  # safety cap (about one million hosts)


def _check_cap(count: int) -> None:
    if count > MAX_TARGETS:
        raise ValueError(f"Too many targets ({count}); the limit is {MAX_TARGETS}")


def parse_target(spec: str) -> List[str]:
    """Expand one target spec into a list of IPv4/IPv6 address strings.

    Supported forms: ``10.0.0.1``, ``10.0.0.1-10.0.0.50``, ``10.0.0.1-50``
    (last-octet shorthand) and ``10.0.0.0/24``.

    Raises:
        ValueError: if the spec is malformed.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Empty target specification")
    try:
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            _check_cap(net.num_addresses)
            if net.version == 4 and net.prefixlen < 31:
                return [str(h) for h in net.hosts()]
            return [str(h) for h in net]
        if "-" in spec:
            left, right = (p.strip() for p in spec.split("-", 1))
            start = ipaddress.ip_address(left)
            if right.isdigit() and start.version == 4:
                prefix = left.rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{prefix}.{right}")
            else:
                end = ipaddress.ip_address(right)
            if start.version != end.version:
                raise ValueError("mixed IP versions in range")
            if int(end) < int(start):
                raise ValueError("range end is lower than range start")
            _check_cap(int(end) - int(start) + 1)
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        return [str(ipaddress.ip_address(spec))]
    except ValueError as exc:
        raise ValueError(f"Invalid target '{spec}': {exc}") from None


def parse_targets(specs: Iterable[str]) -> List[str]:
    """Parse several specs (each may be comma-separated); de-duplicate, keep order."""
    seen: dict = {}
    for spec in specs:
        for part in spec.split(","):
            if part.strip():
                for ip in parse_target(part):
                    seen.setdefault(ip, None)
        _check_cap(len(seen))
    return list(seen)


def parse_file(path: str) -> List[str]:
    """Read targets from a file (one per line, ``#`` comments allowed)."""
    specs: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    parse_targets([line])
                except ValueError as exc:
                    raise ValueError(f"{path}:{lineno}: {exc}") from None
                specs.append(line)
    except OSError as exc:
        raise ValueError(f"Cannot read target file '{path}': {exc.strerror or exc}") from None
    return parse_targets(specs)
