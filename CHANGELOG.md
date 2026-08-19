# Changelog

Alle nennenswerten Änderungen; Versionierung nach SemVer, Version steht in
`sshca/config.py` (`APP_VERSION`).

## 0.4.0 — 2026-08-19

* **Neu: Signierdienst und Client.** Ein Client erzeugt seinen ed25519-Key
  selbst, lässt nur den öffentlichen Teil über HTTPS signieren und bekommt
  die `…-cert.pub` zurück. Der private Schlüssel entsteht auf der CA zu
  keinem Zeitpunkt — intern läuft das über `import_and_sign_pubkey`,
  dieselbe Funktion wie die Externsignatur seit 0.3.2.
* Drei neue Programme neben `ssh-ca-manager.py`: `ssh-ca-server.py`
  (Dienst), `ssh-ca-client.py` (Client) und `ssh-ca-enroll-token.py`
  (Tokens). GUI, TUI, CLI, Datenlayout und Logformat sind unverändert.
* **Transport:** HTTPS mit einem Zertifikat aus der bestehenden X.509-PKI,
  optional zusätzlich mutual TLS. Es gibt keinen Klartextmodus.
* **Herkunft:** Jede Anfrage nach dem Enrollment trägt eine SSHSIG-Signatur
  (`ssh-keygen -Y sign`/`-Y verify`) des beim Enrollment hinterlegten
  Client-Schlüssels. Signiert werden Methode, Pfad, Client-ID, Zeitstempel,
  Nonce und der SHA-256 des Rumpfes gemeinsam; Nonce-Cache und ein Fenster
  von ±300 s wehren Wiedereinspielungen ab. Bewusst keine zweite PKI für
  die Client-Authentisierung.
* **Enrollment:** `ssh-ca-enroll-token create` gibt ein Token aus — eigenes
  Programm, damit es sich getrennt berechtigen lässt. Gespeichert wird nur
  der SHA-256; der Klartext erscheint genau einmal. Ein Token bindet
  Benutzer, optional Host, erlaubte Prinzipale und Vorlagen, eine
  Laufzeitobergrenze und die Zahl der Verwendungen.
* **Rechtevergabe:** Der Benutzername eines Zertifikats stammt immer aus dem
  Token, nie aus der Anfrage. Prinzipale und Vorlagen sind auf das
  Freigegebene begrenzt. Eine ausdrücklich zu lange Gültigkeit wird
  abgewiesen; stammt die Dauer aus der Vorlage, wird sie auf die Obergrenze
  gekürzt — der Client hat sie sich dann nicht ausgesucht.
* **Prinzipalauswahl auf dem Client:** Der Server liefert die Liste, der
  Client zeigt sie nummeriert; `a` bzw. `--all-principals` übernimmt alle,
  `-p` wählt einzeln.
* **Vorlagen auf der Serverseite:** `ssh-ca-server template add|list|remove`
  schreibt in dieselbe `templates.json`, die auch die Oberflächen lesen; der
  Client wählt mit `-t`.
* **Installation:** `ssh-ca-server install` legt Dienstbenutzer,
  Verzeichnisse, Konfigurationsvorlage und eine gehärtete systemd-Unit an —
  Trockenlauf ist die Vorgabe, `--apply` führt aus. Optional eine
  `ssh-ca-agent.service`, damit der CA-Schlüssel im Agent liegen kann statt
  als Passphrase auf der Platte.
* `Ssh.run()` kennt wieder `stdin_file`; `ssh-keygen -Y verify` liest die zu
  prüfende Nachricht ausschließlich von stdin.
* Neue Suite `tests/test_server.py` (93 Prüfungen) mit echten Schlüsseln,
  echten SSHSIG-Signaturen und einem echten TLS-Server auf 127.0.0.1.
* Damit ist der unter 0.3.x als „verworfen" geführte Client-Server-Weg
  wieder aufgenommen — in der dort festgehaltenen Form: Schlüsselerzeugung
  auf dem Client, Transport-TLS aus der bestehenden PKI, Client-Auth über
  SSH-Signaturen.

## 0.3.4 — 2026-08-19

* **Fix: Widerruf sperrte nur die Seriennummer, nicht den Schlüssel.** In die
  KRL ging bisher ausschließlich die `…-cert.pub`, woraus `ssh-keygen` einen
  Eintrag über die Seriennummer macht — gültig für genau dieses eine
  Zertifikat. Der zugehörige Public Key blieb aus Sicht der Zielsysteme
  unbelastet und hätte jederzeit ein neues, gültiges Zertifikat bekommen
  können. Widerruf und Sperrung nehmen jetzt Zertifikat **und** Public Key
  auf; beide Einträge gehen in einem Aufruf an die bestehende KRL (`-u`).
* `revoke()`/`krl_add()` kennen dafür `revoke_key` (Vorgabe: `True`).
  `revoke_key=False` beschränkt den Eintrag auf die Seriennummer — nur
  sinnvoll, wenn derselbe Public Key später erneut zertifiziert werden soll,
  etwa bei einem FIDO-Token.
* `revoked.info` hält im neuen Feld `krl=` fest, was eingetragen wurde.

## 0.3.3 — 2026-08-19

* Prinzipale werden geprüft: Komma, Leer- und Steuerzeichen sind nicht mehr
  zulässig. `ssh-keygen` trennt die Liste am Komma — ein Prinzipal
  `dennis,root` wurde vorher stillschweigend zu zweien.
* Benutzer- und Hostnamen werden zentral in `Paths` geprüft (`..`, `.`,
  leer, `/`, `\`, Leer- und Steuerzeichen). Vorher konnte `user=".."` ein
  Verzeichnis neben dem Datenverzeichnis anlegen. `CaError` liegt dafür
  jetzt in `config.py` und wird von `ca.py` weiter exportiert.
* `restore` weist Ausbrüche zuverlässig ab: der Präfixvergleich enthält den
  Pfadtrenner (ein Nachbarverzeichnis `…/.ssh-ca-fremd` kam vorher durch),
  Symlink- und Hardlinkziele werden geprüft, und `extractall` läuft mit
  `filter="tar"` als zweitem Riegel (`data` scheidet aus: es setzt
  Verzeichnisse auf 0755).
* Widerrufsprüfung als Sammelaufruf (`revoked_paths`): der Index prüft alle
  Zertifikate mit einem `ssh-keygen -Q` statt mit einem je Zertifikat. Bricht
  der Sammelaufruf an einer unlesbaren Datei ab, werden die unbeantworteten
  einzeln nachgefragt.

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
