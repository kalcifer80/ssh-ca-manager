# SSH-CA Manager

Grafische Verwaltung einer SSH Certificate Authority — das, was XCA für X.509
ist, für OpenSSH-Zertifikate. Eigenständige Desktop-Anwendung, alles lokal, kein
Dienst und keine Datenbank im Hintergrund.

Der Datenbestand ist derselbe wie beim Bash-Skript `ssh-ca-tool.sh`: gleiche
Verzeichnisse, gleiches Namensschema, gleiches Logformat. Skript und GUI lassen
sich parallel benutzen.

## Installation

```sh
# Arch
sudo pacman -S pyside6 openssh

# Debian/Ubuntu
sudo apt install python3-pyside6.qtwidgets openssh-client

# oder unabhängig von der Distribution
python3 -m venv ~/.venvs/sshca
~/.venvs/sshca/bin/pip install PySide6
```

Starten — Standard ist die Kommandozeile, die Oberfläche kommt mit `--gui`:

```sh
./ssh-ca-manager.py                      # interaktives Menü (auf einem Terminal)
./ssh-ca-manager.py <befehl> …           # Subcommands für Skripte
./ssh-ca-manager.py --gui                # grafische Oberfläche
./ssh-ca-manager.py --base /pfad/zur/ca  # anderes Datenverzeichnis
SSH_CA_HOME=/pfad/zur/ca ./ssh-ca-manager.py
```

Ohne Befehl startet auf einem Terminal das interaktive Menü — Banner,
gruppierte Menüpunkte, geführte Abfragen mit Vorgaben in eckigen Klammern,
Auswahllisten für Zertifikate und Vorlagen, Zusammenfassung vor jedem
Erstellen und Bestätigungsfragen vor allem Endgültigen. Das Farbschema
entspricht der GUI (Bernstein auf dunklem Grund). In Pipes und Skripten
(kein Terminal) erscheint stattdessen wie gehabt die Hilfe.

Für die reine CLI wird PySide6 nicht benötigt — Qt lädt erst mit `--gui`.

## CLI

Gleicher Funktionsumfang wie die Oberfläche, gleiche Kernschicht, gleicher
Datenbestand:

```
status                       CA-Status und Bestand
init / import KEYFILE        CA anlegen / importieren
pubkey [--out DATEI]         CA-Public-Key ausgeben oder speichern
list [--all] [--filter T]    Zertifikate auflisten
create USER HOST [Optionen]  Zertifikat erstellen
show USER HOST [--raw]       Details (mit -L-Rohausgabe)
renew USER HOST              erneuern (Key wird neu erzeugt)
revoke USER HOST [--lock]    widerrufen bzw. sperren (KRL + Auslagerung)
delete USER HOST             ungültiges Material löschen
revoked / purge USER HOST TS Widerrufsablagen auflisten / löschen
export [USER HOST] [-o F]    gültige Zertifikate als tar.gz
backup / restore ARCHIV      Komplettsicherung
templates / deploy / log     Vorlagen, Zielsystem-Anleitung, Log
```

`create` und `renew` kennen dieselben Stellschrauben wie der Dialog:
`-t VORLAGE`, `-p PRINZIPAL` (mehrfach), `--conf-principals`, `-V +9h`,
`--ext permit-pty` (mehrfach, oder `--ext none`), `--force-command`,
`--source-address`, `--verify-required`, `--no-key-pass`. Liegt der
CA-Schlüssel im ssh-agent, wird ohne Rückfrage darüber signiert
(`--no-agent` erzwingt die Passphrase). Destruktive Befehle fragen nach;
`--yes` übernimmt die Antwort für Skripte.

Beispiele:

```sh
./ssh-ca-manager.py create dennis jump -t Arbeitstag --conf-principals
./ssh-ca-manager.py revoke ansible web01 --reason "Host neu aufgesetzt" --yes
./ssh-ca-manager.py export -o /tmp/gueltige.tar.gz
```

## Aufbau

```
sshca/
    cli.py         Subcommand-CLI und Einstiegspunkt
    tui.py         interaktives Menü (Standard auf einem Terminal)
    config.py      Pfade und Konstanten
    keygen.py      Aufrufe von ssh-keygen, Passphrasen-Handling
    askpass.py     Askpass-Helfer (wird von ssh-keygen gestartet)
    model.py       CertInfo, Status, Parser für ssh-keygen -L
    ca.py          Kernlogik: anlegen, signieren, erneuern, widerrufen, sichern
    store.py       SQLite-Index über den Dateibaum
    templates.py   Vorlagen (Gültigkeit, Prinzipale, Extensions)
    gui/
        theme.py         Farbpalette, Stylesheet, Status-Pillen-Delegate
        main_window.py   Fenster, Seitenleiste, Seiten, Aktionen
        models.py        Tabellenmodelle und Filter
        dialogs.py       Dialoge
        workers.py       Hintergrundausführung
```

## Erscheinungsbild

Dunkles Graphit mit Bernstein-Akzent, als Basis der Qt-Stil „Fusion" — der
lässt sich, anders als die Plattformstile, vollständig per Stylesheet
gestalten und sieht damit unter Plasma, GNOME und Windows identisch aus.
Navigation über eine Seitenleiste mit Zählern, der Zertifikatsstatus als
farbige Pille (eigener Delegate in `theme.py`). Die Schriftgröße lässt sich
über das Menü „Ansicht" oder mit Strg+Plus / Strg+Minus / Strg+0 zwischen
80 % und 180 % verstellen; Zeilenhöhen und Spaltenbreiten wachsen mit, die
Einstellung bleibt über Neustarts erhalten. Alle Farben liegen als
Konstanten am Anfang von `theme.py`; wer ein helles Thema will, tauscht dort
die Werte.

Die Kernschicht ist frei von Ein- und Ausgabe: sie nimmt Werte entgegen und gibt
Ergebnisse zurück. Deshalb ist sie ohne Qt testbar — CLI und GUI sind zwei
dünne Schichten über derselben Logik, ein Ansible-Modul könnte die dritte sein.

### Passphrasen ohne Terminal

`ssh-keygen` liest Passphrasen grundsätzlich vom Terminal. Eine GUI hat keins,
also wird über `SSH_ASKPASS` ein Helfer untergeschoben und mit
`SSH_ASKPASS_REQUIRE=force` dessen Verwendung erzwungen. Die Passphrase kommt
über eine Pipe, deren Lese-Ende der Kindprozess erbt — nicht über `argv` (wäre
in der Prozessliste sichtbar) und nicht über die Umgebung (wäre in
`/proc/<pid>/environ` lesbar).

Besser noch: den CA-Schlüssel in den `ssh-agent` laden. Die Anwendung erkennt
das am Fingerprint und signiert dann mit `ssh-keygen -Us ca_key.pub`. Es wird
keine Passphrase abgefragt, sie verlässt den Agent nie. Derselbe Weg trägt einen
CA-Schlüssel auf Smartcard oder Token.

### Index

Wahrheit ist der Dateibaum. `index.sqlite` ist nur ein Cache, damit die Liste
nicht bei jedem Öffnen n-mal `ssh-keygen -L` aufrufen muss; ein Eintrag wird neu
gelesen, sobald sich mtime oder Größe der Datei ändern. „Aktualisieren" baut den
Index neu auf, Löschen der Datei ist gefahrlos.

## Was die Oberfläche gegenüber dem Skript hinzufügt

* **Extensions und Critical Options** als Formular: `permit-pty`,
  `permit-agent-forwarding`, `permit-port-forwarding`, `force-command`,
  `source-address`, `verify-required`. Das Skript setzte pauschal `-O clear`.
* **Vorlagen** im Stil von XCA — Gültigkeit, Prinzipalmuster (`{user}`,
  `{host}`), Extensions unter einem Namen. Liegen als `templates.json` vor.
* **Filter und Sortierung** über alle Zertifikate, Restlaufzeit aktualisiert
  sich im laufenden Betrieb.
* **Signieren über den ssh-agent**, siehe oben.

## Tests

```sh
python3 tests/test_core.py                           # Kernschicht, braucht ssh-keygen
python3 tests/test_cli.py                            # Subcommand-CLI
python3 tests/test_tui.py                            # interaktives Menü, gescriptet
QT_QPA_PLATFORM=offscreen python3 tests/test_gui.py  # Oberfläche, ohne Bildschirm
```

Beide Tests arbeiten in einem temporären Verzeichnis und fassen `~/.ssh-ca`
nicht an.

## Offene Punkte

* Host-Zertifikate (`ssh-keygen -h`) — bislang nur Benutzerzertifikate.
* CA-Schlüssel auf PKCS#11-Token (`ssh-keygen -D`).
* Verteilung von CA-Public-Key und KRL auf die Zielsysteme, statt nur die
  Anleitung dafür anzuzeigen.
* Vorlagen-Editor in der Oberfläche; derzeit wird `templates.json` bearbeitet.
* Erinnerung an bald ablaufende Zertifikate.
