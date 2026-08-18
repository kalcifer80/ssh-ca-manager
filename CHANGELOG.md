# Changelog

Alle nennenswerten Änderungen; Versionierung nach SemVer, Version steht in
`sshca/config.py` (`APP_VERSION`).

## 0.3.2 — 2026-08-18

* Neu: extern erzeugte Public Keys signieren — der Benutzer reicht nur die
  `.pub`-Datei ein und erhält die `…-cert.pub` zurück (GUI: Menü
  Zertifikate → „Externen Schlüssel signieren"; CLI: `sign-key`;
  TUI: Taste `s`). Unterstützt ed25519, RSA, ECDSA, sk-*.
* Wiedereinreichung rotiert den bisherigen Stand nach `archive/`
  (Re-Zertifizierung); Kollision mit lokal verwalteten Schlüsseln und
  versehentlich eingereichte private Schlüssel werden abgewiesen.
* CLI-Zertifikatssuche findet auch Nicht-ed25519-Dateinamen.

## 0.3.1 — 2026-08-16/17

* Fix: Oberfläche „fror ein" bei Widerrufen/Löschen — verlorene
  Worker-Callbacks durch zu früh freigegebene Signal-Sender; behoben über
  Registry + Brücken-QObject (Details: docs/ENTWICKLUNG.md, Invariante 2).
* Neu: Export gültiger Zertifikate als tar.gz (alle oder ausgewähltes).
* Neu: Löschen abgelaufener/widerrufener Zertifikate und von
  Widerrufsablagen (KRL-Eintrag bleibt bestehen).
* Neu: Schriftgröße 80–180 % (Menü Ansicht, Strg+Plus/Minus/0),
  Einstellung persistent; Zeilen und Spalten skalieren mit.
* Stabiler Referenzstand, Tag v0.3.1.

## 0.3.0 — 2026-08-16

* Neu: interaktives TUI-Menü als Standard auf einem Terminal (Banner,
  gruppierte Menüpunkte, geführte Abfragen mit Vorgaben, Zusammenfassung
  vor dem Erstellen); in Pipes weiterhin Hilfe + Exitcode 2.
* GUI-Neugestaltung: dunkles Graphit/Bernstein-Theme (Fusion + QSS),
  Seitenleiste mit Zählern, Statuspillen, Seitenköpfe mit Aktionsknöpfen.

## 0.2.0 — 2026-08-16

* Neu: Subcommand-CLI mit vollem Funktionsumfang; CLI ist der
  Standard-Einstieg, GUI über `--gui` (Qt lädt erst dann).
* Sammelübernahme aller Einträge aus `principals.conf` im Dialog.

## 0.1.0 — 2026-08-16

* Erste Fassung: PySide6-GUI über neuer, ein-/ausgabefreier Kernschicht.
  CA anlegen/importieren, Zertifikate erstellen/anzeigen/erneuern/
  widerrufen (KRL + Auslagerung), Sichern/Wiederherstellen, Log,
  Deployment-Anleitung.
* Askpass-Pipe-Mechanik für Passphrasen; Signieren über den ssh-agent;
  Extensions/Critical Options als Formular; Vorlagen (`templates.json`);
  SQLite-Index als Listen-Cache.
* Datenlayout vollständig kompatibel zum Ursprungsskript `ssh-ca-tool.sh`.
