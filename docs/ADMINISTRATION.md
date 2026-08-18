# SSH-CA Manager — Administrationshandbuch

Stand: Version 0.3.2

Dieses Handbuch beschreibt Installation, Datenhaltung, Sicherheitsmodell,
die Einrichtung der Zielsysteme und die Wartung. Die Bedienung beschreibt
[BENUTZERHANDBUCH.md](BENUTZERHANDBUCH.md), die Weiterentwicklung
[ENTWICKLUNG.md](ENTWICKLUNG.md).

## Inhalt

1. [Installation](#installation)
2. [Datenverzeichnis](#datenverzeichnis)
3. [Kompatibilität zum Bash-Skript](#kompatibilität-zum-bash-skript)
4. [Konfigurationsdateien](#konfigurationsdateien)
5. [Sicherheitsmodell](#sicherheitsmodell)
6. [Zielsysteme einrichten](#zielsysteme-einrichten)
7. [KRL-Verteilung nach Widerruf](#krl-verteilung-nach-widerruf)
8. [Sicherung und Wiederherstellung](#sicherung-und-wiederherstellung)
9. [Wartung](#wartung)
10. [Fehlerbehebung](#fehlerbehebung)
11. [Grenzen und Hinweise](#grenzen-und-hinweise)

## Installation

Voraussetzungen: Python ≥ 3.11, OpenSSH ≥ 8.4 (`ssh-keygen` mit
`SSH_ASKPASS_REQUIRE`), für die GUI PySide6 ≥ 6.5. CLI und TUI laufen ohne
PySide6 — Qt wird erst bei `--gui` geladen.

```sh
# Arch Linux
sudo pacman -S python openssh pyside6

# Debian / Ubuntu
sudo apt install python3 openssh-client python3-pyside6.qtwidgets

# distributionsunabhängig (GUI aus pip)
python3 -m venv ~/.venvs/sshca && ~/.venvs/sshca/bin/pip install PySide6
```

Projekt ablegen (z. B. `/opt/ssh-ca-manager` oder im Home), Startskripte
sind `ssh-ca-manager.py` (ausführbar). Optional `ssh-ca-manager.desktop`
nach `~/.local/share/applications/` und im `Exec=`-Feld den vollen Pfad
eintragen. Es gibt keinen Installationsschritt und keine Registrierung im
System — Löschen des Verzeichnisses entfernt die Anwendung (die Daten
liegen getrennt, siehe unten).

Unter KDE Plasma ist zu erwarten, dass die GUI **nicht** dem Breeze-Thema
folgt: sie bringt bewusst ein eigenes, überall identisches Erscheinungsbild
mit (Qt-Stil „Fusion" + eigenes Stylesheet).

## Datenverzeichnis

Vorgabe `~/.ssh-ca`, änderbar per `--base` oder `SSH_CA_HOME`. Die
Anwendung legt fehlende Teile selbst an.

```
~/.ssh-ca/
├── ca/
│   ├── ca_key               privater CA-Schlüssel        (0600)
│   ├── ca_key.pub           öffentlicher CA-Schlüssel    (0644)
│   ├── revoked_keys.krl     Widerrufsliste               (0600)
│   └── serial.counter       Zählerteil der Seriennummern (0600)
├── <user>/<host>/           ein Ordner je Benutzer@Host  (0700)
│   ├── <host>_<user>_<typ>          privater Schlüssel (0600; fehlt bei
│   │                                extern signierten Schlüsseln)
│   ├── <host>_<user>_<typ>.pub      Public Key (0644)
│   ├── <host>_<user>_<typ>-cert.pub Zertifikat (0644)
│   └── archive/             genau die letzte abgelöste Version (0700)
├── revoked/<user>/<host>/<zeitstempel>/
│   └── … + revoked.info     ausgelagertes Material, Schlüssel auf 0400
├── backups/                 Ziel der Komplettsicherungen
├── principals.conf          vordefinierte Prinzipale (0600)
├── templates.json           Vorlagen der Anwendung (0600)
├── index.sqlite             Cache der GUI-Liste — jederzeit löschbar
└── ssh-ca.log               Protokoll (0600)
```

`<typ>` ist `ed25519` für lokal erzeugte Schlüssel; bei extern
eingereichten richtet er sich nach dem Schlüsseltyp (`rsa`, `ecdsa`,
`ed25519_sk`, `ecdsa_sk`).

**Wahrheit ist immer der Dateibaum.** `index.sqlite` ist nur ein Cache für
die GUI-Liste (Neuaufbau über „Aktualisieren" oder Löschen der Datei);
Seriennummern bestehen aus Zufallsanteil plus Zähler aus `serial.counter`.

## Kompatibilität zum Bash-Skript

Layout, Namensschema und Logformat entsprechen `ssh-ca-tool.sh` — Skript
und Anwendung können denselben Bestand parallel benutzen. Eine Migration
ist nicht nötig: Anwendung auf `~/.ssh-ca` starten, fertig. Zwei
Unterschiede im Verhalten:

* Das Skript setzte beim Signieren pauschal `-O clear` (keine Extensions);
  die Anwendung setzt Extensions explizit — Zertifikate der Anwendung
  tragen also z. B. `permit-pty`, die des Skripts nicht.
* `templates.json` und `index.sqlite` kennt nur die Anwendung; das Skript
  ignoriert sie.

## Konfigurationsdateien

### principals.conf

Eine Zeile pro vordefiniertem Prinzipal; Leerzeilen und `#`-Kommentare
werden ignoriert. Die Einträge erscheinen als Vorschläge im Dialog, über
„Alle übernehmen" / `--conf-principals` / Taste `a` im TUI-Editor.

```
# Gruppen
admins
devops
# Hostklassen
ubuntu-hosts
rocky-hosts
```

### templates.json

Liste von Vorlagen; wird beim ersten Start mit vier Beispielen angelegt.
In Prinzipal-Mustern stehen `{user}` und `{host}` für die Eingaben des
jeweiligen Zertifikats. Bearbeitung derzeit direkt in der Datei (JSON);
die Anwendung liest sie bei jedem Dialogaufruf neu.

```json
[
  {
    "name": "Arbeitstag (9 Stunden)",
    "validity": "+9h",
    "principal_patterns": ["{user}", "{user}@{host}"],
    "extensions": ["permit-pty", "permit-agent-forwarding"],
    "critical_options": {},
    "description": "Ein Zertifikat, das den Arbeitstag überdauert."
  }
]
```

Bei defektem JSON fällt die Anwendung stillschweigend auf die
Standardvorlagen zurück — nach Handänderungen einmal `templates` (CLI)
oder den Dialog öffnen und prüfen.

### GUI-Einstellungen

Die Schriftskala der GUI liegt in `~/.config/ssh-ca-manager/ui.conf`
(QSettings) — unabhängig vom Datenverzeichnis.

## Sicherheitsmodell

**Passphrasen-Übergabe an ssh-keygen.** `ssh-keygen` liest Passphrasen vom
Terminal; GUI und Dienste haben keins. Die Anwendung schiebt deshalb über
`SSH_ASKPASS` (+ `SSH_ASKPASS_REQUIRE=force`) einen eigenen Helfer unter
(`sshca/askpass.py`); die Passphrase läuft durch eine Pipe, deren Lese-Ende
der Kindprozess erbt. Sie erscheint **nie** in der Prozessliste (`argv`)
und nie in `/proc/<pid>/environ`.

**ssh-agent (empfohlen für den Alltag).** Liegt der private CA-Schlüssel im
Agent (`ssh-add ~/.ssh-ca/ca/ca_key`), erkennt die Anwendung das am
Fingerprint und signiert mit `ssh-keygen -Us` — es wird keine Passphrase
mehr abgefragt und sie verlässt den Agent nie. Derselbe Mechanismus trüge
später einen CA-Schlüssel auf Smartcard/Token (PKCS#11), das ist aber noch
nicht angebunden.

**Empfehlungen.**

* CA-Passphrase lang und einmalig; der CA-Schlüssel gehört nur auf die
  CA-Maschine (plus Offline-Sicherung).
* Kurze Gültigkeiten als Standard — Widerruf wird dann zur Ausnahme.
* Restriktive Extensions: nur geben, was gebraucht wird; `source-address`
  für alles, was das interne Netz nicht verlassen soll.
* Das Datenverzeichnis liegt komplett unter 0600/0700; darauf verlassen
  sich Sicherung und Export. Nicht „großzügiger" machen.
* Widerruf ist erst wirksam, wenn die KRL auf den Zielsystemen liegt —
  siehe unten.

## Zielsysteme einrichten

Einmalig pro Zielsystem den CA-Public-Key hinterlegen (vollständige,
kopierfertige Fassung: Befehl `deploy` bzw. Knopf „Deployment-Anleitung").

Linux (Ubuntu, Rocky u. a.):

```sh
sudo install -o root -g root -m 644 ca_key.pub /etc/ssh/ca_key.pub
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" \
    | sudo tee /etc/ssh/sshd_config.d/10-ssh-ca.conf
sudo systemctl reload sshd
```

OpenBSD:

```sh
doas install -o root -g wheel -m 644 ca_key.pub /etc/ssh/ca_key.pub
doas sh -c 'echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config'
doas rcctl reload sshd
```

Feiner steuern lässt sich das serverseitig mit `AuthorizedPrincipalsFile`
(welche Prinzipale welcher Systembenutzer akzeptiert); ohne diese Datei
akzeptiert sshd ein Zertifikat, wenn der Anmeldename unter den Prinzipalen
ist.

## KRL-Verteilung nach Widerruf

In die KRL gehen zwei Einträge je Vorgang: die **Seriennummer** des
Zertifikats und der **Public Key** selbst. Der zweite ist der wichtigere —
ein Eintrag über die Seriennummer gilt nur für genau dieses Zertifikat,
während der Schlüsseleintrag jedes Zertifikat sperrt, das je für diesen
Schlüssel ausgestellt wurde oder noch würde. Was eingetragen wurde, steht in
`revoked.info` unter `krl=`.

Folge davon: ein einmal widerrufener Public Key ist endgültig verbrannt. Bei
einem eingereichten FIDO-Token-Schlüssel, der sich nicht austauschen lässt,
ist das unerwünscht — dafür gibt es `revoke(..., revoke_key=False)` in der
Kernschicht, das nur die Seriennummer sperrt.

Nach **jedem** Widerruf muss `ca/revoked_keys.krl` neu auf alle
Zielsysteme:

```sh
scp ~/.ssh-ca/ca/revoked_keys.krl host:/tmp/
ssh host 'sudo install -o root -g root -m 644 /tmp/revoked_keys.krl \
    /etc/ssh/revoked_keys.krl'
# einmalig: RevokedKeys /etc/ssh/revoked_keys.krl in die sshd-Konfiguration
```

Das ist bewusst ein manueller Schritt (Holprinzip). Bei mehr als einer
Handvoll Hosts bietet sich ein kleines Verteilskript oder Ansible an; bei
konsequent kurzen Gültigkeiten ist die KRL selten nötig, weil abgelaufene
Zertifikate ohnehin wertlos sind.

## Sicherung und Wiederherstellung

* **Komplettsicherung:** `backup` (CLI/TUI) bzw. Datei → Sichern (GUI)
  schreibt ein `tar.gz` des gesamten Datenverzeichnisses (ohne `backups/`
  selbst), Rechte 0600. Enthält den **privaten CA-Schlüssel** — wie ein
  Schlüssel behandeln.
* **Wiederherstellung:** `restore ARCHIV` entpackt in das Datenverzeichnis;
  gleichnamige Dateien werden überschrieben, Pfade außerhalb der Basis
  weist die Anwendung zurück.
* **Umzug auf eine neue Maschine:** Sicherung erstellen → auf der neuen
  Maschine `restore` → fertig. Alternativ das Verzeichnis kopieren; die
  Rechte (0700/0600) müssen erhalten bleiben.
* **Export vs. Sicherung:** „Exportieren" ist die Weitergabe *gültiger*
  Zertifikate an Benutzer; „Sichern" ist das Backup der CA. Nicht
  verwechseln — der Export enthält private Benutzerschlüssel, aber nie den
  CA-Schlüssel.

## Wartung

* **Log:** `ssh-ca.log` im Datenverzeichnis, gemeinsames Format mit dem
  Bash-Skript; Ansicht über `log` bzw. Hilfe → Log. Wächst unbegrenzt —
  bei Bedarf rotieren (die Anwendung hängt nur an).
* **Aufräumen:** Abgelaufene Zertifikate über „Löschen", alte
  Widerrufsablagen über „Ablage löschen" (der KRL-Eintrag bleibt).
* **Index:** `index.sqlite` darf jederzeit gelöscht werden; „Aktualisieren"
  baut ihn neu.
* **Updates der Anwendung:** Projektverzeichnis ersetzen (oder `git pull`),
  danach die Testsuiten laufen lassen (siehe ENTWICKLUNG.md). Der
  Datenbestand ist von der Anwendungsversion unabhängig.

## Fehlerbehebung

| Symptom | Ursache / Abhilfe |
|---|---|
| GUI startet nicht: `No module named 'PySide6'` | PySide6 installieren (`pacman -S pyside6` / venv). CLI und TUI laufen auch ohne. |
| `ssh-keygen wurde nicht gefunden` | openssh(-client) installieren. |
| „falsche CA-Passphrase" trotz korrekter Eingabe | OpenSSH < 8.4 kennt `SSH_ASKPASS_REQUIRE` nicht — OpenSSH aktualisieren. |
| Signieren fragt nichts und schlägt fehl | CA-Key liegt im Agent, aber der Agent gehört einer anderen Sitzung (`SSH_AUTH_SOCK` prüfen) — oder `--no-agent` verwenden. |
| Zielsystem lehnt Zertifikat ab | `TrustedUserCAKeys` fehlt/falsch; Prinzipal ≠ Anmeldename; Zertifikat abgelaufen (`show`/Details prüfen); Uhren der Systeme vergleichen. |
| „certificate not trusted" nach CA-Neuanlage | Auf den Zielsystemen liegt noch der alte CA-Public-Key. |
| Zeile in der GUI ohne privaten Schlüssel | Normal bei extern signierten Schlüsseln — der private Teil liegt beim Benutzer. |
| Fenster wirkt eingefroren | In ≥ 0.3.1 behoben (Callback-Lebensdauer im Worker). Bei älterem Stand: aktualisieren. |
| GUI folgt nicht dem Systemthema | Beabsichtigt (eigenes Theme auf Fusion-Basis). |

## Grenzen und Hinweise

* **Ein Administrator-Modell:** keine Benutzerverwaltung, keine Rollen —
  wer das Datenverzeichnis lesen kann, kontrolliert die CA. Mehrbenutzer-
  oder Netzbetrieb ist bewusst nicht Teil der Anwendung (ein Client-Server-
  Prototyp wurde erprobt und verworfen, siehe ENTWICKLUNG.md).
* **Host-Zertifikate** (`ssh-keygen -h`) sind noch nicht umgesetzt — die
  Anwendung stellt Benutzerzertifikate aus.
* **Windows** läuft nicht ohne Anpassung: die Passphrasen-Übergabe nutzt
  Datei­deskriptor-Vererbung und ein Shell-Shim (beides POSIX). Der
  restliche Code ist portabel; Details in ENTWICKLUNG.md.
* **Gleichzeitige Schreibzugriffe** (zwei Instanzen, die zeitgleich
  ausstellen) sind nicht verriegelt — im Ein-Admin-Betrieb irrelevant,
  aber nicht darauf bauen.
