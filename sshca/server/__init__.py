"""Signierdienst: HTTPS-API über der bestehenden Kernschicht.

    config.py      Konfiguration (/etc/ssh-ca-server/server.conf)
    registry.py    Enrollment-Tokens und registrierte Clients (Dateibaum)
    api.py         Fachlogik und Rechtevergabe — ohne HTTP
    http.py        Routen, Signaturprüfung, TLS
    install.py     systemd-Unit und Verzeichnisse
    service.py     Kommandozeile ssh-ca-server
    token_tool.py  Kommandozeile ssh-ca-enroll-token

Der Dienst fügt der Kernschicht nichts hinzu: er ruft dieselben Funktionen
auf wie GUI, TUI und CLI. Insbesondere signiert er über
``import_and_sign_pubkey`` — die Funktion für eingereichte Public Keys, bei
der auf der CA nie ein privater Schlüssel entsteht.
"""

from __future__ import annotations

__all__ = ["api", "config", "http", "install", "registry", "service", "token_tool"]
