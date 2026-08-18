# SSH-CA Manager — Benutzerhandbuch

Stand: Version 0.3.2

Dieses Handbuch richtet sich an alle, die mit dem SSH-CA Manager Zertifikate
ausstellen, erneuern, widerrufen und verteilen. Die Einrichtung des Systems
selbst (Installation, Zielsysteme, Sicherung) beschreibt
[ADMINISTRATION.md](ADMINISTRATION.md).

## Inhalt

1. [Begriffe](#begriffe)
2. [Die drei Oberflächen](#die-drei-oberflächen)
3. [Grafische Oberfläche (GUI)](#grafische-oberfläche-gui)
4. [Interaktives Menü (TUI)](#interaktives-menü-tui)
5. [Kommandozeile (CLI)](#kommandozeile-cli)
6. [Typische Abläufe](#typische-abläufe)
7. [Anmeldung am Zielsystem](#anmeldung-am-zielsystem)

## Begriffe

| Begriff | Bedeutung |
|---|---|
| **CA** | Certificate Authority — das Schlüsselpaar, dem alle Zielsysteme vertrauen. Wer den privaten CA-Schlüssel besitzt, kann sich überall anmelden. |
| **Zertifikat** | Ein von der CA signierter Public Key mit Gültigkeitszeitraum, Prinzipalen und Rechten. Datei `…-cert.pub` neben dem Schlüssel. |
| **Prinzipal** | Name, unter dem das Zertifikat eine Anmeldung erlaubt — in der Regel der Benutzername auf dem Zielsystem. Ein Zertifikat kann mehrere Prinzipale tragen. |
| **Gültigkeit** | Zeitraum, z. B. `+1h` (eine Stunde ab jetzt), `+9h`, `+1w`. Kurze Gültigkeiten sind der Normalfall — abgelaufene Zertifikate sind automatisch wertlos. |
| **Extension** | Recht im Zertifikat: `permit-pty` (Terminal), `permit-agent-forwarding`, `permit-port-forwarding` usw. Ohne Extensions ist nur die nackte Anmeldung möglich. |
| **Critical Option** | Erzwungene Einschränkung: `source-address` (nur aus diesen Netzen), `force-command` (nur dieses Kommando), `verify-required` (FIDO-PIN). |
| **KRL** | Key Revocation List — Widerrufsliste. Wird auf die Zielsysteme verteilt; dort gelistete Zertifikate sind ungültig, egal ob abgelaufen oder nicht. |
| **Vorlage** | Benanntes Bündel aus Gültigkeit, Prinzipal-Mustern und Extensions (`templates.json`), wie Vorlagen in XCA. |

## Die drei Oberflächen

Alle drei arbeiten auf demselben Datenbestand (`~/.ssh-ca`) und derselben
Logik — sie sind jederzeit mischbar:

| Aufruf | Oberfläche | Wofür |
|---|---|---|
| `./ssh-ca-manager.py --gui` | Grafisch (Qt) | Überblick, Alltag, Maus |
| `./ssh-ca-manager.py` | Interaktives Menü im Terminal | Alltag per SSH auf der CA-Maschine |
| `./ssh-ca-manager.py <befehl>` | Subcommands | Skripte, Automatisierung, Einzelaktionen |

Ein anderes Datenverzeichnis wählt man überall mit `--base /pfad` oder der
Umgebungsvariable `SSH_CA_HOME`.

## Grafische Oberfläche (GUI)

Start: `./ssh-ca-manager.py --gui`

### Aufbau

Links die **Seitenleiste** mit drei Bereichen und Zählern, unten der Pfad des
Datenverzeichnisses. Rechts pro Bereich eine Seite mit Kopfzeile und
Aktionsknöpfen. Die Statuszeile am unteren Rand meldet Ergebnisse.

* **Zertifikate** — Tabelle aller aktiven Zertifikate. Statusspalte als
  farbige Pille: grün = gültig, gelb = läuft bald ab (weniger als ein Viertel
  der Laufzeit übrig), rot = abgelaufen/widerrufen, blau = noch nicht gültig,
  violett = ausgelagert. Der Tooltip jeder Zeile zeigt Datei, Fingerprint,
  Extensions und warnt, wenn der private Schlüssel fehlt.
  Darüber ein Freitextfilter (Benutzer, Host, Prinzipal, Seriennummer, Key
  ID) und „Abgelaufene ausblenden". Sortierung per Klick auf die
  Spaltenköpfe; Doppelklick öffnet die Details.
* **Widerrufen** — alle widerrufenen/gesperrten Vorgänge mit Zeitpunkt,
  Urheber und Grund.
* **CA** — Fingerprint, Pfade, KRL-Status, Public Key zum
  Kopieren/Speichern, Deployment-Anleitung. Hinweis „im ssh-agent geladen"
  erscheint, wenn der CA-Schlüssel im Agent liegt.

### Aktionen (Seite Zertifikate)

* **Neues Zertifikat** — Dialog mit drei Reitern:
  * *Allgemein:* Vorlage, Benutzer, Zielhost, Gültigkeit (mit Vorschau
    „gültig bis …"), Prinzipale. Prinzipale lassen sich einzeln ergänzen
    (Eingabefeld schlägt die Einträge aus `principals.conf` vor) oder mit
    „Alle aus principals.conf übernehmen" gesammelt hinzufügen; die
    Reihenfolge der Datei bleibt erhalten, Dubletten werden übersprungen.
  * *Extensions:* Rechte als Checkboxen, Critical Options als Felder.
  * *Schlüssel & Signatur:* Passphrase des neuen Schlüssels (mindestens
    8 Zeichen; „ohne Passphrase" nur für Automatisierung). Liegt der
    CA-Schlüssel im ssh-agent, ist „über den Agent signieren" vorausgewählt
    und keine CA-Passphrase nötig.

  Nach dem Erstellen öffnet sich automatisch das Detailfenster.
* **Details** — Übersicht aller Felder, Rohausgabe von `ssh-keygen -L`,
  Reiter „Verwendung" mit fertigen `ssh`-/`ssh-add`-Zeilen, Knopf
  „Zertifikat kopieren".
* **Erneuern** — erzeugt Schlüssel *und* Zertifikat neu; das bisherige
  Material wandert nach `archive/` (dort liegt immer genau die letzte
  Version). Benutzer/Host sind im Dialog fixiert.
* **Externen Schlüssel signieren** (Menü Zertifikate) — für Benutzer, die
  ihr Schlüsselpaar selbst erzeugt haben: Public Key einfügen oder als
  Datei laden, Rest wie beim Erstellen. Es entsteht kein privater Schlüssel
  auf der CA; zurück an den Benutzer geht nur die `…-cert.pub`. Erneutes
  Einreichen desselben Benutzers/Hosts rotiert den alten Stand nach
  `archive/` (Re-Zertifizierung).
* **Widerrufen** — nimmt das Zertifikat in die KRL auf und lagert das
  Material nach `revoked/` aus. Art „widerrufen" (gilt nicht mehr) oder
  „gesperrt" (Material kompromittiert), Grund als Freitext. **Endgültig** —
  eine KRL kennt keine Rücknahme. Danach die KRL neu auf die Zielsysteme
  verteilen (Hinweisfenster nennt den Pfad).
* **Löschen** — entfernt das Material eines *abgelaufenen oder widerrufenen*
  Zertifikats endgültig (inklusive `archive/`). Gültiges Material lässt sich
  nicht löschen — dafür gibt es Widerruf.
* **Exportieren** — packt gültige Zertifikate samt Schlüsseln als `tar.gz`
  (Struktur `<user>/<host>/…`, Datei mit Rechten 0600). Bei ausgewählter
  Zeile fragt die Anwendung: nur dieses oder alle gültigen.

Seite Widerrufen: **Ablage löschen** entfernt das ausgelagerte Material
eines Vorgangs; der KRL-Eintrag bleibt bestehen — das Zertifikat bleibt auf
den Zielsystemen ungültig.

### Schriftgröße

Menü **Ansicht** oder `Strg` + `+` / `-` / `0`: 80–180 % in 10-%-Schritten.
Zeilenhöhen und Spaltenbreiten wachsen mit; die Einstellung bleibt über
Neustarts erhalten.

## Interaktives Menü (TUI)

Start: `./ssh-ca-manager.py` (ohne Befehl, auf einem Terminal).

Oben Banner und eine Statuszeile (CA-Fingerprint, Agent-Status, farbige
Zähler). Darunter die Gruppen:

```
── Zertifikate ──   1 Auflisten   2 Neues Zertifikat   3 Details
                    4 Erneuern    5 Widerrufen/Sperren 6 Ungültiges löschen
                    7 Exportieren s Externen Schlüssel signieren
── Widerrufen ──    8 Vorgänge auflisten   9 Ablage löschen
── CA ──            c Status   p Public Key   d Deployment   t Vorlagen
── Wartung ──       b Sichern  r Wiederherstellen  l Log        q Beenden
```

Ohne CA erscheint stattdessen ein Einrichtungsmenü (`i` anlegen,
`m` importieren).

Bedienung der geführten Abfragen:

* Vorgaben stehen in eckigen Klammern — **Enter übernimmt** sie.
* Auswahllisten sind nummeriert; `0` geht zurück.
* Der Prinzipale-Editor versteht `+name` (hinzufügen), `-name` (entfernen),
  `a` (alle aus `principals.conf`), Enter (weiter).
* Vor jedem Erstellen erscheint eine Zusammenfassung zur Bestätigung; alles
  Endgültige (Widerruf, Löschen) fragt ausdrücklich nach.

In Pipes und Skripten (kein Terminal) startet das Menü nicht — dort
erscheint die Hilfe der Subcommands.

## Kommandozeile (CLI)

`./ssh-ca-manager.py <befehl> --help` zeigt zu jedem Befehl alle Optionen.

| Befehl | Zweck |
|---|---|
| `status` | CA-Status und Bestandszahlen |
| `init` / `import KEYFILE` | CA anlegen / bestehende importieren |
| `pubkey [--out DATEI]` | CA-Public-Key ausgeben oder speichern |
| `list [--all] [--filter TEXT]` | Zertifikate auflisten |
| `create USER HOST …` | Zertifikat erstellen |
| `sign-key PUB USER HOST …` | extern erzeugten Public Key signieren |
| `show USER HOST [--raw]` | Details, mit `-L`-Rohausgabe |
| `renew USER HOST …` | erneuern (Schlüssel wird neu erzeugt) |
| `revoke USER HOST [--lock] [--reason T]` | widerrufen bzw. sperren |
| `delete USER HOST` | ungültiges Material löschen |
| `revoked` / `purge USER HOST [TS]` | Widerrufsablagen auflisten / löschen |
| `export [USER HOST] [-o DATEI]` | gültige Zertifikate als tar.gz |
| `backup [-o DATEI]` / `restore ARCHIV` | Komplettsicherung |
| `templates` / `deploy` / `log [-n N]` | Vorlagen, Zielsystem-Anleitung, Log |

Optionen von `create`, `renew` und `sign-key` (Auszug):

```
-t VORLAGE            Vorlage anwenden (Namenspräfix genügt)
-p NAME               Prinzipal (mehrfach; ersetzt die Vorgabe)
--conf-principals     alle Einträge aus principals.conf ergänzen
-V +9h                Gültigkeit (Vorgabe +1h)
--ext permit-pty      Extension (mehrfach; --ext none = keine)
--force-command CMD   Critical Option
--source-address NETZ Critical Option
--no-key-pass         Schlüssel ohne Passphrase (nur create/renew)
--no-agent            Passphrase abfragen statt ssh-agent
--yes                 Bestätigungsfragen übernehmen (Skripte)
```

Verhalten: Liegt der CA-Schlüssel im ssh-agent, wird ohne Rückfrage darüber
signiert (Meldung erscheint). Farben nur auf einem Terminal. Exitcodes:
`0` Erfolg, `1` Fehler, `2` Aufruf ohne Befehl, `130` Abbruch mit Strg-C.

Beispiele:

```sh
./ssh-ca-manager.py create dennis jump -t Arbeitstag --conf-principals
./ssh-ca-manager.py sign-key eingereicht.pub max jump -p max -V +1h
./ssh-ca-manager.py revoke ansible web01 --reason "Host neu aufgesetzt" --yes
./ssh-ca-manager.py export -o /tmp/gueltige.tar.gz
```

## Typische Abläufe

**Erstes Zertifikat ausstellen:** CA anlegen (einmalig) → Zertifikat
erstellen (Vorlage wählen, Prinzipale prüfen) → auf den Arbeitsrechner
bringen (Export-tar.gz oder `scp` von Schlüssel + `…-cert.pub` +
`….pub`) → anmelden.

**Ein Benutzer bringt seinen eigenen Schlüssel mit:** Benutzer erzeugt
lokal `ssh-keygen -t ed25519` und schickt **nur die `.pub`-Datei** →
„Externen Schlüssel signieren" → die zurückgegebene `…-cert.pub` legt der
Benutzer neben seinen privaten Schlüssel. Sein privater Schlüssel berührt
die CA nie.

**Zertifikat läuft ab:** „Erneuern" (erzeugt neuen Schlüssel) oder beim
externen Schlüssel: dieselbe `.pub` erneut einreichen.

**Mitarbeiter/Host scheidet aus:** Widerrufen (mit Grund) → KRL auf alle
Zielsysteme verteilen → nach angemessener Zeit „Ablage löschen".

**Schlüssel kompromittiert:** Widerrufen mit Art „gesperrt" → KRL sofort
verteilen.

## Anmeldung am Zielsystem

Schlüssel und Zertifikat liegen nebeneinander; OpenSSH findet das
Zertifikat am Namen `<schlüssel>-cert.pub` automatisch:

```sh
ssh -i ~/.ssh/jump_dennis_ed25519 dennis@jump      # direkt
ssh-add ~/.ssh/jump_dennis_ed25519                 # oder in den Agent laden
```

Dauerhaft in `~/.ssh/config`:

```
Host jump
    IdentityFile ~/.ssh/jump_dennis_ed25519
    User dennis
```

Meldet das Zielsystem „certificate not trusted" oder fragt nach einem
Passwort, ist dort die CA nicht (korrekt) hinterlegt — siehe
Deployment-Anleitung (`deploy` bzw. Knopf auf der CA-Seite) und
[ADMINISTRATION.md](ADMINISTRATION.md).
