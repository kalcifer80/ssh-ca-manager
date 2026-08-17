#!/usr/bin/env python3
"""Startpunkt des SSH-CA Managers.

    ./ssh-ca-manager.py <befehl> …          Kommandozeilenmodus (Standard)
    ./ssh-ca-manager.py --gui               grafische Oberfläche
    ./ssh-ca-manager.py --base /pfad …      anderes Datenverzeichnis

Ohne Befehl wird die Hilfe mit allen Befehlen angezeigt.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sshca.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
