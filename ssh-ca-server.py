#!/usr/bin/env python3
"""Startpunkt des Signierdienstes.

Wird von der systemd-Unit als 'ssh-ca-server run --config …' aufgerufen;
'ssh-ca-server install' richtet genau diese Unit ein.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sshca.server.service import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
