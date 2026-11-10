"""Command line interface, scan orchestration, progress bar and output."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Sequence

from smbscan import __version__
from smbscan.ip_parser import parse_file, parse_targets
from smbscan.plugins import discover_plugins
from smbscan.plugins.base import Plugin

log = logging.getLogger("smbscan")

COLUMNS = [("ip", "IP"), ("status", "Status"), ("hostname", "Hostname"), ("mac", "MAC"),
           ("smb_version", "SMB Version"), ("smb1_enabled", "SMBv1"),
           ("signing", "Signing"), ("error", "Error")]


class ProgressBar:
    """Thread-safe pure-Python progress bar written to stderr."""

    def __init__(self, total: int, width: int = 30, stream=None) -> None:
        self.total, self.width = total, width
        self.stream = stream or sys.stderr
        self.done = 0
        self._lock = threading.Lock()
        self.enabled = hasattr(self.stream, "isatty") and self.stream.isatty()

    def update(self, n: int = 1) -> None:
        with self._lock:
            self.done += n
            if not self.enabled:
                return
            frac = self.done / self.total if self.total else 1.0
            filled = int(self.width * frac)
            bar = "#" * filled + "-" * (self.width - filled)
            self.stream.write(f"\r[{bar}] {frac * 100:5.1f}% ({self.done}/{self.total})")
            self.stream.flush()

    def close(self) -> None:
        if self.enabled:
            self.stream.write("\n")
            self.stream.flush()


def scan_host(host: str, plugins: Sequence[Plugin], timeout: float) -> Dict[str, Any]:
    """Run all plugins sequentially on one host; never raises."""
    ctx: Dict[str, Any] = {"ip": host, "host": host, "timeout": timeout, "errors": []}
    for plugin in plugins:
        try:
            result = plugin.run(host, ctx)
        except Exception as exc:  # a plugin must never kill the scan
            log.debug("%s: plugin %s failed: %r", host, plugin.name, exc)
            ctx["errors"].append(f"{plugin.name}: {exc or type(exc).__name__}")
            continue
        ctx.update(result or {})
        log.debug("%s: plugin %s -> %s", host, plugin.name, result)
        if ctx.get("abort"):
            break
    ctx["status"] = "up" if ctx.get("up") else "down"
    ctx["error"] = "; ".join(ctx["errors"])
    for key in ("host", "timeout", "abort"):
        ctx.pop(key, None)
    return ctx


def run_scan(targets: List[str], plugins: Sequence[Plugin], threads: int,
             timeout: float) -> List[Dict[str, Any]]:
    """Scan all targets concurrently, returning results sorted by IP."""
    bar = ProgressBar(len(targets))
    results: List[Dict[str, Any]] = []
    pool = ThreadPoolExecutor(max_workers=max(1, threads))
    futures: List[Future] = []
    try:
        futures = [pool.submit(scan_host, t, plugins, timeout) for t in targets]
        for fut in as_completed(futures):
            results.append(fut.result())
            bar.update()
    except KeyboardInterrupt:
        for f in futures:
            f.cancel()
        print("\nInterrupted; showing partial results.", file=sys.stderr)
    finally:
        pool.shutdown(wait=True)
        bar.close()
    results.sort(key=lambda r: int(ipaddress.ip_address(r["ip"])))
    return results


def _cell(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def render_table(results: List[Dict[str, Any]]) -> str:
    """Render results as an aligned ASCII table."""
    rows = [[_cell(r.get(k)) for k, _ in COLUMNS] for r in results]
    heads = [h for _, h in COLUMNS]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(heads)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells: List[str]) -> str:
        return "| " + " | ".join(c.ljust(w) for c, w in zip(cells, widths)) + " |"

    return "\n".join([sep, line(heads), sep, *(line(r) for r in rows), sep])


def save_output(path: str, results: List[Dict[str, Any]]) -> None:
    """Save results as JSON or CSV depending on the file extension."""
    ext = path.lower().rsplit(".", 1)[-1]
    if ext == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, default=str)
    elif ext == "csv":
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=[k for k, _ in COLUMNS], extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
    else:
        raise ValueError("Output file must end in .json or .csv")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="smbscan", description="SMB / NetBIOS network scanner")
    p.add_argument("--targets", help="IP, range (a-b) or CIDR; comma separated allowed")
    p.add_argument("--file", "-f", help="file with one target per line")
    p.add_argument("--threads", "-t", type=int, default=20, help="worker threads (default 20)")
    p.add_argument("--timeout", type=float, default=3.0, help="socket timeout in seconds (default 3)")
    p.add_argument("--output", "-o", help="save results to .json or .csv")
    p.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point; returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s", stream=sys.stderr)
    if not args.targets and not args.file:
        parser.error("provide --targets and/or --file")
    if args.threads < 1 or args.timeout <= 0:
        parser.error("--threads must be >= 1 and --timeout > 0")
    if args.output and args.output.lower().rsplit(".", 1)[-1] not in ("json", "csv"):
        parser.error("--output must end in .json or .csv")
    try:
        targets: List[str] = []
        if args.targets:
            targets += parse_targets([args.targets])
        if args.file:
            targets += parse_file(args.file)
        targets = list(dict.fromkeys(targets))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        print("Error: no targets to scan", file=sys.stderr)
        return 2
    plugins = discover_plugins()
    log.debug("plugins: %s", [p.name for p in plugins])
    print(f"Scanning {len(targets)} host(s) with {min(args.threads, len(targets))} thread(s)...",
          file=sys.stderr)
    results = run_scan(targets, plugins, args.threads, args.timeout)
    print(render_table(results))
    up = sum(1 for r in results if r.get("up"))
    print(f"\n{up} of {len(results)} host(s) up.")
    if args.output:
        try:
            save_output(args.output, results)
            print(f"Results saved to {args.output}")
        except OSError as exc:
            print(f"Error: cannot write output: {exc}", file=sys.stderr)
            return 1
    return 0
