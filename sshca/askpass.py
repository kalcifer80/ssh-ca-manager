#!/usr/bin/env python3
"""Askpass-Helfer fuer ssh-keygen.

ssh-keygen liest Passphrasen grundsaetzlich vom Terminal, nicht von stdin.
Eine GUI hat kein Terminal, deshalb wird ueber SSH_ASKPASS ein Hilfsprogramm
untergeschoben; SSH_ASKPASS_REQUIRE=force erzwingt dessen Verwendung auch dann,
wenn ein Terminal vorhanden waere.

Die Passphrase wird nicht ueber die Kommandozeile (waere in der Prozessliste
sichtbar) und nicht ueber die Umgebung (waere in /proc/<pid>/environ lesbar)
uebergeben, sondern ueber eine Pipe, deren Lese-Ende der Kindprozess erbt. Die
Nummer des Deskriptors steht in SSHCA_PASS_FD. Pro Aufruf wird genau eine Zeile
gelesen, sodass mehrfach abgefragte Passphrasen (Eingabe + Bestaetigung) einfach
mehrfach in die Pipe geschrieben werden.

Der Helfer wird als eigenstaendiges Skript aufgerufen und importiert deshalb
bewusst nichts aus dem Paket.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    fd_raw = os.environ.get("SSHCA_PASS_FD")
    if not fd_raw:
        # Ohne Deskriptor gibt es nichts zu liefern. Eine leere Antwort ist
        # besser als ein Haenger, denn ssh-keygen bricht dann sauber ab.
        sys.stdout.write("\n")
        return 0

    fd = int(fd_raw)
    chunks: list[bytes] = []
    while True:
        # Byteweise lesen: mehrere Aufrufe teilen sich dieselbe Pipe, ein
        # gepufferter Read wuerde die Passphrase des naechsten Aufrufs
        # mitverschlucken.
        byte = os.read(fd, 1)
        if not byte or byte == b"\n":
            break
        chunks.append(byte)

    sys.stdout.write(b"".join(chunks).decode("utf-8", "surrogateescape"))
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
