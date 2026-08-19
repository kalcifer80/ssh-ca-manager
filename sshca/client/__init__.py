"""Client des Signierdienstes.

    api.py   lokaler Zustand (~/.ssh-ca-client) und HTTPS-Aufrufe
    cli.py   Kommandozeile ssh-ca-client

Der private Schlüssel entsteht hier und bleibt hier. Zum Server geht nur die
``.pub``-Zeile; zurück kommt die ``…-cert.pub``.
"""

from __future__ import annotations

__all__ = ["api", "cli"]
