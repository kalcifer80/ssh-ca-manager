# SSH-CA Manager — Entwicklungsdokumentation

Stand: Version 0.3.2

Dieses Dokument enthält alles, was für die Weiterführung des Projekts ohne
weiteres Vorwissen nötig ist: Architektur, Modulverantwortungen, die
**unantastbaren Invarianten** (mit Begründung), Teststrategie, Konventionen
und Release-Prozess.

## Inhalt

1. [Projektziel und eiserne Regeln](#projektziel-und-eiserne-regeln)
2. [Architektur](#architektur)
3. [Module im Einzelnen](#module-im-einzelnen)
4. [Unantastbare Invarianten](#unantastbare-invarianten)
5. [Teststrategie](#teststrategie)
6. [Konventionen](#konventionen)
7. [Release-Prozess](#release-prozess)
8. [Historie und verworfene Wege](#historie-und-verworfene-wege)
9. [Roadmap](#roadmap)

## Projektziel und eiserne Regeln

Der SSH-CA Manager verwaltet eine SSH Certificate Authority — das, was XCA
für X.509 ist, für OpenSSH-Zertifikate. Entstanden aus dem Bash-Skript
`ssh-ca-tool.sh`; dessen Datenlayout ist der Vertrag.

Regeln, die bei jeder Änderung gelten:

1. **Datenlayout-Kompatibilität.** Verzeichnisse, Dateinamen und Logformat
   unter `~/.ssh-ca` bleiben mit dem Bash-Skript austauschbar. Neue Dateien
   (wie `templates.json`, `index.sqlite`) sind erlaubt, Änderungen an
   bestehenden Namen/Strukturen nicht.
2. **Kernschicht ohne Ein-/Ausgabe.** `ca.py`, `model.py`, `keygen.py`,
   `templates.py`, `store.py` kennen weder `input()` noch `print()` noch Qt.
   Sie nehmen Werte, liefern Werte, werfen `CaError` mit anzeigbarem Text.
   GUI, CLI und TUI sind dünne Schichten darüber — jede neue Funktion
   entsteht zuerst im Kern und bekommt dann bis zu drei Oberflächen.
3. **Keine Funktions- oder Optikänderung ohne ausdrücklichen Auftrag.**
   Insbesondere: Farben/Layout der GUI (theme.py) und die Abfrage-
   Reihenfolgen der TUI sind Schnittstellen — die TUI-Tests brechen bei
   jeder Umsortierung absichtlich.
4. **Keine neuen Laufzeitabhängigkeiten.** Standardbibliothek + PySide6
   (nur GUI) + OpenSSH-Binaries. CLI/TUI müssen ohne PySide6 laufen
   (Qt-Import erst hinter `--gui`).
5. **Sicherheitsentscheidungen sind dokumentiert und bleiben:** Passphrasen
   nie in `argv`/Umgebung; Dateirechte 0600/0700; destruktive Aktionen mit
   Bestätigung; KRL kennt keine Rücknahme.

## Architektur

```
             ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
Oberflächen  │ gui/ (PySide6)│  │ tui.py (Menü) │  │ cli.py (Args) │
             └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
                     └────────────┬─────┴──────────────────┘
                                  ▼
             ┌────────────────────────────────────────────┐
Kernschicht  │ ca.py  ← CertificateAuthority, CertRequest │
             │ model.py (CertInfo, Status, Parser)        │
             │ templates.py · store.py (SQLite-Cache)     │
             └───────────────────┬────────────────────────┘
                                 ▼
             ┌────────────────────────────────────────────┐
Systemzugriff│ keygen.py (Ssh.run) ── askpass.py (Helfer) │
             │            └── ssh-keygen / ssh-add        │
             └────────────────────────────────────────────┘
```

Datenfluss am Beispiel „Neues Zertifikat" (GUI): Dialog sammelt Eingaben →
`CertRequest` → `run_task(ca.create_certificate, request)` im Threadpool →
Kern erzeugt Schlüssel (`Ssh.run` mit Askpass-Pipe) und signiert → Ergebnis
`CertInfo` kommt per Signal in den GUI-Thread zurück → `refresh()` gleicht
den SQLite-Index mit dem Dateibaum ab.

## Module im Einzelnen

| Modul | Verantwortung / Wichtiges |
|---|---|
| `ssh-ca-manager.py` | Startpunkt; delegiert an `sshca.cli.main` (CLI ist Standard, `--gui` startet Qt). |
| `sshca/config.py` | `Paths` (alle Pfade aus einer Basis), Konstanten (`KEY_TYPE`, `KDF_ROUNDS`, `APP_VERSION`), `DEPLOYMENT_HELP`. Layout-Definition = Kompatibilitätsvertrag. |
| `sshca/keygen.py` | `Ssh.run()` — einziger Weg zu `ssh-keygen`/`ssh-add`. Passphrasen-Mechanik (siehe Invarianten), Timeouts, `SshKeygenError`, `stdin_file` für `-Y verify`. |
| `sshca/askpass.py` | Eigenständiges Askpass-Programm; liest die Passphrase byteweise von einem geerbten Deskriptor (`SSHCA_PASS_FD`). Importiert bewusst nichts aus dem Paket. |
| `sshca/model.py` | `CertInfo` (+ abgeleitete Pfade, `status()`), `Status`-Enum mit Farben, Parser für `ssh-keygen -L`, `parse_validity_spec`, `RevokedEntry`. Reines Datenmodell. |
| `sshca/ca.py` | Die Fachlogik: CA anlegen/importieren, `create_certificate`, `sign`, `import_and_sign_pubkey` (extern), `renew_certificate`, `revoke` (KRL → dann Auslagerung), `delete_*`, `export_certificates`, `backup`/`restore`, Log, Seriennummern. |
| `sshca/templates.py` | Vorlagen (`templates.json`), `KNOWN_EXTENSIONS` / `KNOWN_CRITICAL_OPTIONS` — die eine Quelle für Rechte-Listen aller Oberflächen. |
| `sshca/store.py` | `CertIndex` (SQLite) + `refresh_index`: Cache über dem Dateibaum, invalidiert über mtime+Größe; Widerrufsstatus kommt immer frisch aus der KRL. |
| `sshca/cli.py` | argparse-Subcommands; Test-Hooks `_getpass`/`_input` (Modulvariablen!); `run_cli` startet ohne Befehl auf einem TTY die TUI. |
| `sshca/tui.py` | Interaktives Menü: Rendering (`_panel`, `_rule`, Farben), geführte Abläufe (`_flow_*`), Menütabellen. Nutzt die CLI-Hooks für alle Eingaben. |
| `sshca/gui/theme.py` | Farbpalette, `build_qss(scale)` (skalierende Schriftgrößen), `apply_theme`, `set_scale`/`load_scale` (QSettings), `StatusPillDelegate`. |
| `sshca/gui/models.py` | `CertTableModel`/`RevokedTableModel` (+ Spaltendefinition mit Basisbreiten), `CertFilterProxy` (Freitext + „Abgelaufene ausblenden", Sortier-Rolle). |
| `sshca/gui/dialogs.py` | Alle Dialoge. `CertDialog` deckt Erstellen, Erneuern (`fixed=`) und Externsignatur (`external=True`) ab. |
| `sshca/gui/main_window.py` | Fenster: Seitenleiste, Seiten, Aktionen/Menüs, `refresh()`, Zoom, alle Handler (Muster: `_busy` → `run_task` → Callbacks → `on_done` reaktiviert). |
| `sshca/gui/workers.py` | `run_task`: Threadpool + Brücken-QObject. **Vor Änderungen die Invariante lesen.** |

Tests: `tests/test_core.py`, `test_cli.py`, `test_tui.py`, `test_gui.py` —
siehe [Teststrategie](#teststrategie).

## Unantastbare Invarianten

Diese Konstruktionen sehen nach Kandidaten für „Vereinfachung" aus. Sie
sind es nicht — jede hat einen erlebten Fehler oder eine Sicherheitsfrage
hinter sich.

### 1. Passphrasen über Askpass-Pipe (`keygen.py` + `askpass.py`)

`ssh-keygen` liest Passphrasen vom Terminal, nicht von stdin. Ohne Terminal
(GUI!) erzwingt `SSH_ASKPASS_REQUIRE=force` den Askpass-Helfer. Die
Passphrase geht über eine **Pipe, deren Lese-Ende vererbt wird**
(`pass_fds`), nicht über `-N`/argv (Prozessliste!) und nicht über die
Umgebung (`/proc/<pid>/environ`). Der Helfer liest **byteweise** bis zum
Zeilenende, weil mehrere Askpass-Aufrufe (Passphrase + Bestätigung)
dieselbe Pipe teilen — ein gepufferter Read würde die zweite Antwort
verschlucken. Ohne Passphrasen wird `SSH_ASKPASS_REQUIRE=never` gesetzt,
damit nichts jemals interaktiv hängen bleibt. `stdin` ist immer
`DEVNULL` bzw. eine explizite Datei.

Portabilitätsgrenze: `pass_fds` und das `#!/bin/sh`-Shim sind POSIX — der
dokumentierte Windows-Blocker.

### 2. Worker-Lebensdauer (`gui/workers.py`)

Der Fehler dahinter: Callbacks wurden direkt mit den Task-Signalen
verbunden, der Aufrufer verwarf den Task — nach `run()` löschte der
Threadpool das Runnable, damit fiel die letzte Referenz auf den
Signal-Sender, und **queued Signale starben unzugestellt** (Stresstest:
39/40 verloren). Sichtbares Symptom: Fenster blieb nach `_busy()` für immer
deaktiviert („eingefroren").

Deshalb: `setAutoDelete(False)`; die Registry `_ACTIVE` hält Task und
`_Bridge` bis zur Zustellung von `done`; die Callbacks hängen an
**Slots eines QObjects im GUI-Thread** (garantiert Queued-Zustellung im
richtigen Thread, egal ob Lambda oder Methode); Handler mit `_busy` geben
zusätzlich `on_done=… setEnabled(True)` mit, damit selbst eine Ausnahme im
Erfolgs-Callback die Oberfläche nicht sperrt. Der Regressionstest in
`test_gui.py` fährt 15 Zyklen unter erzwungenem GC — er bricht, wenn hier
„aufgeräumt" wird.

### 3. Widerrufsreihenfolge (`ca.py::revoke`)

Erst KRL aktualisieren, **dann** Material verschieben. Schlägt die KRL
fehl, ist auf der Platte nichts passiert. Eine KRL kennt keine Rücknahme —
deshalb löscht „Ablage löschen" nur Material, nie den KRL-Eintrag, und
jede Oberfläche sagt das dem Benutzer.

### 4. Aufräumen bei Fehlschlag (`ca.py::create_certificate`)

Scheitert das Signieren (z. B. falsche CA-Passphrase), wird der bereits
erzeugte Schlüssel wieder gelöscht — es bleibt nie unsigniertes Material
liegen. Analog prüft `import_and_sign_pubkey` den eingereichten Key
(`ssh-keygen -l`) **bevor** rotiert wird.

### 5. Fusion + ein Stylesheet (`gui/theme.py`)

Der Qt-Stil „Fusion" ist die einzige Basis, auf der das QSS überall
identisch rendert (Plattformstile ignorieren Teile davon). Alle Farben sind
Konstanten am Dateianfang; Schriftgrößen existieren **nur** in
`build_qss(scale)` — die Zoom-Funktion ersetzt das komplette Stylesheet.
Keine `setStyleSheet`-Einzelwerte in Widgets; abweichende Darstellung läuft
über `setObjectName` (`primary`, `danger`, `hintError`, `noteMuted`, …).

### 6. Index ist nur Cache (`store.py`)

`index.sqlite` beschleunigt die Liste; Wahrheit ist der Dateibaum.
Invalidierung über mtime+Größe der Zertifikatsdatei; der Widerrufsstatus
wird bewusst **immer** frisch gegen die KRL geprüft (er hängt nicht an der
Datei). Jede Funktion muss korrekt bleiben, wenn der Index gelöscht wird.

### 7. Test-Hooks statt Terminal (`cli._getpass`, `cli._input`)

CLI **und** TUI beziehen jede Eingabe über diese zwei Modulvariablen; die
Tests hängen Queues ein. Neue Eingabestellen müssen zwingend über diese
Hooks laufen (`cli._input(...)` zur Aufrufzeit auflösen, nicht beim Import
binden), sonst hängen die Tests an einem echten Terminal.

### 8. Externsignatur reißt keine Paare auseinander (`import_and_sign_pubkey`)

Existiert für user/host ein **lokal verwalteter** Schlüssel (privater Teil
vorhanden), bricht die Externsignatur ab. Nur rein extern signierte Stände
(pub + cert ohne privaten Teil) werden bei Wiedereinreichung nach
`archive/` rotiert.

## Teststrategie

Vier Suiten, zusammen 187 Prüfungen, alle ohne Bildschirm und ohne echtes
Terminal lauffähig; benötigt wird nur `ssh-keygen` im `PATH` (und für die
GUI-Suite PySide6):

```sh
python3 tests/test_core.py                           # 58 — Kernschicht
python3 tests/test_cli.py                            # 37 — Subcommands
python3 tests/test_tui.py                            # 34 — Menü, gescriptet
QT_QPA_PLATFORM=offscreen python3 tests/test_gui.py  # 58 — GUI headless
```

Prinzipien:

* Kein Test-Framework — jede Suite ist ein Skript mit `check(label, bool)`,
  bricht beim ersten Fehler und arbeitet in einem Temp-Verzeichnis
  (fasst `~/.ssh-ca` nie an).
* **Echte Kryptografie:** Es wird nie gemockt — jede Suite erzeugt echte
  Schlüssel und Zertifikate über `ssh-keygen`. Abgelaufene Zertifikate
  entstehen über absolute `-V`-Zeiten in der Vergangenheit
  (`20200101120000:20210101120000`).
* CLI/TUI-Tests speisen Eingaben und Passphrasen über die Hooks als Queues
  ein; **leergelaufene oder übrige Queues sind Testfehler** — dadurch fällt
  jede Änderung an Abfrage-Reihenfolgen sofort auf. Das ist Absicht.
* GUI-Tests bauen echte Fenster/Dialoge offscreen, prüfen Modelle, Filter,
  Zoom (Stylesheet-Inhalt!) und enthalten den Worker-Regressionstest.
* Neue Funktion ⇒ Kern-Test für Erfolg **und** Fehlerpfade, plus je ein
  Test pro angebotener Oberfläche.

Screenshots zur Sichtprüfung entstehen headless (`widget.grab().save(…)`)
— bei Optikarbeiten immer rendern und ansehen, nicht raten.

## Konventionen

* Sprache: Oberflächen, Meldungen, Doku und Kommentare Deutsch; Docstrings
  ASCII-tolerant (bewusst „ue"/„ss" in einigen Kerndateien). Bezeichner
  Englisch.
* Stil: PEP 8, 4 Leerzeichen, Zeilen ≤ 88; `from __future__ import
  annotations` in jedem Modul; sprechende Fehlertexte in `CaError` — die
  Oberflächen zeigen sie unverändert an.
* GUI-Muster für lange Operationen: `self._busy(text)` →
  `run_task(kernfunktion, …, on_success=…, on_error=self._fail,
  on_done=lambda: self.setEnabled(True))`. Kernaufrufe nie direkt im
  GUI-Thread, wenn `ssh-keygen` beteiligt ist.
* Versionsnummer ausschließlich in `sshca/config.py` (`APP_VERSION`).
* Git: `main` trägt nur getestete Stände; Experimente auf Branches;
  annotierte Tags `vX.Y.Z`; Commit-Botschaften Deutsch mit Stichpunkten.

## Release-Prozess

1. Alle vier Suiten grün (siehe oben), bei GUI-Änderungen zusätzlich
   Screenshots sichten.
2. `APP_VERSION` in `sshca/config.py` anheben, `CHANGELOG.md` ergänzen.
3. Commit auf `main`, annotiertes Tag `vX.Y.Z`.
4. Archiv erzeugen: `git bundle create ssh-ca-manager-vX.Y.Z.bundle --all`
   plus ZIP inkl. `.git`; SHA-256-Summen daneben.
5. Bundle/ZIP extern ablegen (Homelab-Git per `git push origin main
   vX.Y.Z`, NAS-Kopie).

## Historie und verworfene Wege

* **0.1.0** GUI-Grundgerüst (PySide6) über neuer Kernschicht;
  Askpass-Mechanik; SQLite-Index; Vorlagen.
* **0.2.0** Subcommand-CLI, CLI als Standard-Einstieg.
* **0.3.0** Interaktives TUI-Menü; dunkles Theme (Fusion + QSS),
  Seitenleiste, Statuspillen.
* **0.3.1** Fix der verlorenen Worker-Callbacks (GUI „fror ein");
  Export gültiger Zertifikate; Löschen ungültiger; Zoom 80–180 %.
* **0.3.2** Extern erzeugte Public Keys signieren (GUI/CLI/TUI).
* **Verworfen: Client-Server** (0.4.0-dev, nicht in der Historie von
  `main`). HTTPS-Signierdienst mit Token-Enrollment, `ssh-keygen -Y`-
  signierten Requests, Policies, systemd-Härtung — funktionsfähig
  (29 Tests), aber für den Ein-Admin-Homelab-Betrieb zu viel
  Betriebsaufwand. Bewusste Entscheidung: lokal ausstellen, Schlüssel
  manuell verteilen; für Fremdschlüssel gibt es seit 0.3.2 die
  Externsignatur. Bei Wiederaufnahme: Schlüsselerzeugung gehört auf den
  Client, Transport-TLS aus der bestehenden SSL-CA, Client-Auth über
  SSH-Signaturen — nicht über eine zweite X.509-PKI.

## Roadmap

Offene, bewusst zurückgestellte Punkte:

* Host-Zertifikate (`ssh-keygen -h` samt `HostCertificate`-Anleitung).
* CA-Schlüssel auf PKCS#11-Token (`ssh-keygen -D`); die Signaturschicht
  unterscheidet bereits Datei/Agent, ein dritter Weg passt dort an.
* Vorlagen-Editor in der GUI (derzeit `templates.json` von Hand).
* Erinnerung an bald ablaufende Zertifikate.
* KRL-Verteilung an Zielsysteme aus der Anwendung heraus (derzeit
  Anleitung + manuell/Ansible).
