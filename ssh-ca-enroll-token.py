#!/usr/bin/env python3
"""Startpunkt des Token-Werkzeugs — eigenes Programm, eigene Berechtigung."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sshca.server.token_tool import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
