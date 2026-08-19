#!/usr/bin/env python3
"""Startpunkt des Clients."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sshca.client.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
