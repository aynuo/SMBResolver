#!/usr/bin/env python3
"""SMBResolver - SMB network scanner, hostname resolver."""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from smbresolver.core.target_parser import parse_targets
from smbresolver.core.scanner import scan_hosts
from smbresolver.core.registry import PluginRegistry
from smbresolver.output import print_results_table, export_json, export_csv


def build_parser():
    parser = argparse.ArgumentParser(
        prog="SMBResolver",
        description="Scan SMB hosts, resolve hostnames, detect versions and signing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python run.py --targets 192.168.1.0/24
  python run.py --targets 192.168.1.10-192.168.1.50 --threads 30
  python run.py --file targets.txt --plugins hostname,smb_version
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--targets", "-t", type=str, help="IPs, ranges (10.0.0.1-10), or CIDR (/24)")
    group.add_argument("--file", "-f", type=str, help="File with one target per line")

    parser.add_argument("--plugins", type=str, default=None,
                        help="Comma-separated plugin names (default: all enabled)")
    parser.add_argument("--threads", "-n", type=int, default=20, help="Concurrent threads (default: 20)")
    parser.add_argument("--timeout", "-w", type=int, default=5, help="Per-host timeout seconds (default: 5)")
    parser.add_argument("--output", "-o", type=str, default=None, help="Export results to file (json or csv)")

    return parser


async def run_scan(args):
    registry = PluginRegistry()
    registry.discover()

    if args.targets:
        targets = parse_targets(args.targets)
    else:
        with open(args.file, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        targets = []
        for line in lines:
            targets.extend(parse_targets(line))

    print(f"Scanning {len(targets)} target(s) with {args.threads} threads...")
    print("-" * 60)

    plugin_names = None
    if args.plugins:
        plugin_names = [p.strip() for p in args.plugins.split(",")]

    ctx = {}

    results = await scan_hosts(
        targets=targets,
        registry=registry,
        threads=args.threads,
        timeout=args.timeout,
        ctx=ctx,
        plugin_names=plugin_names,
    )

    print("-" * 60)
    print_results_table(results)

    if args.output:
        ext = Path(args.output).suffix.lower()
        if ext == ".json":
            export_json(results, args.output)
        elif ext == ".csv":
            export_csv(results, args.output)
        else:
            export_json(results, args.output)
        print(f"\nResults exported to {args.output}")

    return results


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()