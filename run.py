#!/usr/bin/env python3
"""Entry point: ``python run.py --targets 192.168.1.0/24``."""
import sys

from smbscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
