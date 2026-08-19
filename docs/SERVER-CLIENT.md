# SSH-CA Manager — Signierdienst und Client

Stand: Version 0.4.0

Dieses Dokument beschreibt den optionalen Client-Server-Betrieb: einen
HTTPS-Signierdienst auf der CA-Maschine und den Client, der sich dort
registriert und Zertifikate bezieht. Der lokale Betrieb (GUI, Menü, CLI)
bleibt davon vollständig unberührt und ist weiterhin der Normalfall für
eine Einzelmaschine — siehe [BENUTZERHANDBUCH.md](BENUTZERHANDBUCH.md) und
[ADMINISTRATION.md](ADMINISTRATION.md).

## Inhalt

1. [Wofür das gut ist](#wofür-das-gut-ist)
2. [Sicherheitsmodell](#sicherheitsmodell)
3. [Installation des Dienstes](#installation-des-dienstes)
4. [Konfiguration](#konfiguration)
5. [CA-Schlüssel für den Dienst](#ca-schlüssel-für-den-dienst)
6. [Vorlagen und Prinzipale festlegen](#vorlagen-und-prinzipale-festlegen)
7. [Enrollment-Tokens](#enrollment-tokens)
8. [Der Client](#der-client)
9. [Betrieb](#betrieb)
10. [API-Referenz](#api-referenz)
11. [Fehlerbehebung](#fehlerbehebung)
12. [Grenzen](#grenzen)

## Wofür das gut ist

Ohne Dienst entstehen Schlüssel auf der CA-Maschine und werden von Hand
verteilt; für fremde Schlüssel gibt es seit 0.3.2 die Externsignatur mit
Datei hin, Datei zurück. Der Dienst automatisiert genau diesen Weg:

* Der **private Schlüssel entsteht auf dem Client** und verlässt ihn nie.
  Über die Leitung geht nur die `.pub`-Zeile, zurück kommt die
  `…-cert.pub`.
* Ein Client kann sich **selbst bedienen**, innerhalb dessen, was der
  Administrator beim Enrollment festgelegt hat.
* Der Bestand bleibt derselbe. Ein per Dienst ausgestelltes Zertifikat
  erscheint in `ssh-ca-manager list` wie jedes andere und lässt sich dort
  ansehen, widerrufen und löschen.

Wenn nur ein Mensch an einer Maschine arbeitet, ist der Dienst
Mehraufwand ohne Gegenwert — das war der Grund, warum diese Fassung in
0.3.x zurückgestellt wurde. Sinnvoll wird sie, sobald mehrere Maschinen
regelmäßig kurzlebige Zertifikate brauchen.

## Sicherheitsmodell

Zwei getrennte Ebenen, die verschiedene Fragen beantworten:

| Ebene | Mittel | Beantwortet |
|---|---|---|
| Transport | HTTPS, Serverzertifikat aus der bestehenden X.509-PKI | Rede ich mit dem richtigen Server, und hört jemand mit? |
| Herkunft | SSHSIG über jede Anfrage (`ssh-keygen -Y sign` / `-Y verify`) | Ist dieser Client der, als der er sich beim Enrollment registriert hat? |

Die Trennung ist Absicht. Eine zweite X.509-PKI nur für die
Client-Authentisierung hätte eine zweite Zertifikatsverwaltung mit
eigenem Widerruf und eigenem Ablauf bedeutet — für ein Werkzeug, das
SSH-Schlüssel verwaltet, ist der SSH-Schlüssel das naheliegendere Mittel.
Wer zusätzlich Clientzertifikate aus seiner PKI verlangen will, setzt
`tls_client_ca` und bekommt mutual TLS obendrauf.

Signiert wird nicht der Rumpf allein, sondern:

```
<METHODE>\n<Pfad>\n<Client-ID>\n<Zeitstempel>\n<Nonce>\n<SHA256 des Rumpfes>\n
```

Damit lässt sich ein abgefangener Signaturblock weder auf einen anderen
Endpunkt noch auf einen anderen Inhalt noch auf einen anderen Client
setzen. Gegen Wiedereinspielung stehen ein Zeitfenster von ±300 Sekunden
und ein Nonce-Cache im Speicher des Dienstes.

Was der Dienst **nicht** entscheidet, entscheidet der Administrator beim
Ausstellen des Tokens:

* Der **Benutzername** kommt aus dem Token, nie aus der Anfrage. Ein
  Client kann sich kein Zertifikat für einen anderen Benutzer ausstellen
  lassen.
* **Prinzipale** und **Vorlagen** sind auf das begrenzt, was das Token
  freigibt.
* Die **Gültigkeit** wird auf das Minimum aus Serverobergrenze und
  Token-Obergrenze gekürzt. Fordert ein Client ausdrücklich mehr an, wird
  die Anfrage abgewiesen statt still etwas anderes auszustellen.

## Installation des Dienstes

```sh
sudo ./ssh-ca-server.py install                 # Trockenlauf: zeigt nur an
sudo ./ssh-ca-server.py install --apply         # führt aus
```

Ohne `--apply` wird nichts geändert — die Ausgabe listet jeden Schritt.
Angelegt werden:

* Systembenutzer `ssh-ca` (ohne Login-Shell)
* `/var/lib/ssh-ca/.ssh-ca` als CA-Datenverzeichnis und
  `/var/lib/ssh-ca-server` für Tokens und Registrierungen
* `/etc/ssh-ca-server/server.conf` aus der Vorlage
* `/etc/systemd/system/ssh-ca-server.service`, gehärtet
  (`ProtectSystem=strict`, `NoNewPrivileges`, leeres
  `CapabilityBoundingSet`, `SystemCallFilter=@system-service`,
  `ReadWritePaths` nur auf Zustands- und CA-Verzeichnis)
* optional `ssh-ca-agent.service` (siehe unten)

Optionen: `--user`, `--state-dir`, `--ca-base`, `--port`,
`--no-agent-unit`.

Danach fehlen die Schritte, die niemand raten kann — sie stehen am Ende
der Ausgabe: Serverzertifikat eintragen, CA anlegen, Signierweg
einrichten, prüfen, starten.

## Konfiguration

`/etc/ssh-ca-server/server.conf`, eine INI-Datei ohne Geheimnisse:

```ini
[server]
listen = 0.0.0.0
port = 8443

tls_cert = /etc/ssl/certs/ssh-ca-server.pem     # Serverzert. + Zwischenzert.
tls_key  = /etc/ssl/private/ssh-ca-server.key   # nur für den Dienst lesbar
tls_client_ca =                                 # gesetzt = mutual TLS

ca_base   = /var/lib/ssh-ca/.ssh-ca
state_dir = /var/lib/ssh-ca-server

signing = agent                                 # agent | passphrase-file | none
ca_passphrase_file =

max_validity = +9h
```

`ssh-ca-server check` prüft alles, was sich ohne Netzbetrieb prüfen lässt,
und sammelt die Befunde, statt beim ersten abzubrechen:

```sh
sudo -u ssh-ca ssh-ca-server check
```

Der Dienst startet nicht, wenn eine Datei fehlt, der TLS-Key für andere
lesbar ist, keine CA vorhanden ist oder `signing = agent` gilt, der
CA-Schlüssel aber nicht im Agent liegt.

## CA-Schlüssel für den Dienst

Der Dienst muss signieren können. Drei Wege, in dieser Reihenfolge
empfehlenswert:

**1. ssh-agent (`signing = agent`).** Die Passphrase verlässt den Agent
nie und liegt nirgends auf der Platte. Preis: nach jedem Neustart muss
der Schlüssel einmal von Hand geladen werden.

```sh
sudo systemctl enable --now ssh-ca-agent.service
sudo -u ssh-ca env SSH_AUTH_SOCK=/run/ssh-ca/agent.sock \
  ssh-add /var/lib/ssh-ca/.ssh-ca/ca/ca_key
```

**2. Passphrasendatei (`signing = passphrase-file`).** Vollautomatisch
über Neustarts hinweg; dafür liegt die Passphrase im Dateisystem. Der
Dienst weigert sich zu starten, wenn die Datei für andere zugänglich ist.

```sh
printf '%s' 'Passphrase' | sudo tee /etc/ssh-ca-server/ca.pass >/dev/null
sudo chown ssh-ca:ssh-ca /etc/ssh-ca-server/ca.pass
sudo chmod 600 /etc/ssh-ca-server/ca.pass
```

**3. Ohne Passphrase (`signing = none`).** Nur für abgeschottete
Testaufbauten.

Der CA-Schlüssel auf einer Smartcard ist noch nicht angebunden — siehe
[Grenzen](#grenzen).

## Vorlagen und Prinzipale festlegen

Beides liegt im CA-Datenverzeichnis und wird von den lokalen Oberflächen
und vom Dienst gemeinsam benutzt.

**Prinzipale** stehen in `principals.conf`, eine Zeile je Eintrag. Der
Dienst bietet einem Client die Einträge aus dieser Datei plus seinen
Benutzernamen und `<user>@<host>` an — es sei denn, das Token schreibt
eine engere Liste vor; dann gilt ausschließlich diese.

**Vorlagen** liegen in `templates.json`. Neu ist, dass sie sich ohne
Texteditor anlegen lassen:

```sh
sudo -u ssh-ca ssh-ca-server template list
sudo -u ssh-ca ssh-ca-server template add "Jumphost kurz" \
  -V +2h -p '{user}' -p admins \
  --ext permit-pty --ext permit-agent-forwarding \
  --description "Nur Jumphost, zwei Stunden."
sudo -u ssh-ca ssh-ca-server template remove "Jumphost kurz"
```

In den Prinzipalmustern stehen `{user}` und `{host}` wie gewohnt für die
Werte des jeweiligen Zertifikats.

## Enrollment-Tokens

Das Token ist die erste Kontaktaufnahme. Es ersetzt für einen Moment die
gesamte Authentisierung und gehört deshalb über einen Kanal zum Client,
der nicht derselbe ist wie der spätere Zugang.

```sh
sudo ssh-ca-enroll-token create \
  --user dennis --host jump \
  --principals dennis,admins,devops \
  --templates "Jumphost kurz,Arbeitstag (9 Stunden)" \
  --max-validity +4h \
  --valid 24h --uses 1 \
  --comment "Neuer Jumphost"

sudo ssh-ca-enroll-token list
sudo ssh-ca-enroll-token revoke <ID>
sudo ssh-ca-enroll-token purge          # verbrauchte und abgelaufene weg
```

Das Geheimnis erscheint **genau einmal**, bei der Ausgabe. Auf der Platte
liegt nur sein SHA-256; ein verlorenes Token lässt sich nicht
nachschlagen, nur zurückziehen und neu ausstellen.

Weggelassene Angaben bedeuten: `--host` leer — der Client nennt seinen
Hostnamen selbst; `--principals` leer — alles aus `principals.conf`;
`--templates` leer — alle Vorlagen; `--max-validity` leer — die
Servervorgabe.

Dass die Tokenausgabe ein eigenes Programm ist, ist Absicht: sie ist der
einzige Vorgang, der ein Geheimnis erzeugt. Getrennt aufrufbar heißt
getrennt berechtigbar (eine `sudo`-Regel nur auf dieses Programm) und
getrennt sichtbar im Audit.

## Der Client

```sh
ssh-ca-client enroll --server https://ca.example:8443 \
  --token 253813b2.… --ca-bundle /etc/ssl/certs/pki-root.pem
ssh-ca-client request
ssh -i ~/.ssh-ca-client/keys/jump_dennis_ed25519 dennis@zielhost
```

Beim Enrollment erzeugt der Client seinen Identitätsschlüssel, holt sich
den CA-Public-Key und merkt sich Server, Client-ID und CA-Bundle in
`~/.ssh-ca-client/client.json`. Ohne `--token` wird danach gefragt, damit
das Geheimnis nicht in der Shell-Historie landet.

`request` fragt am Terminal nach Vorlage und Prinzipalen; die Listen
kommen vom Server:

```
  Vom Server freigegebene Prinzipale:
    1  dennis
    2  admins
    3  devops
  Auswahl (Nummern mit Komma · a = alle · 0 = abbrechen):
```

Für Skripte gibt es dieselben Entscheidungen als Schalter:

```
-t VORLAGE           Vorlage des Servers (Präfix genügt)
-p NAME              Prinzipal (mehrfach); muss freigegeben sein
--all-principals     alle freigegebenen übernehmen
-V +2h               Gültigkeit ausdrücklich (sonst: Vorlage, gekürzt)
--no-key-pass        Schlüssel ohne Passphrase
--yes                nicht nachfragen
```

Weitere Befehle: `renew` (Schlüssel neu erzeugen und signieren lassen —
der bisherige Stand wandert clientseitig nach `keys/archive/`), `status`
(mit `--remote` auch der Bestand beim Server), `principals`, `templates`
und `ca` (holt CA-Public-Key und Widerrufsliste, um eigene Zielsysteme
einzurichten).

Datenverzeichnis des Clients:

```
~/.ssh-ca-client/
├── client.json           Server, Client-ID, CA-Bundle (0600)
├── client_ed25519        Identitätsschlüssel für die API (0600, ohne Passphrase)
├── client_ed25519.pub
├── ca_key.pub            öffentlicher CA-Schlüssel
├── revoked_keys.krl      nach 'ssh-ca-client ca'
└── keys/<host>_<user>_ed25519[.pub|-cert.pub]
```

Identitätsschlüssel und Zertifikatsschlüssel sind absichtlich
verschieden. Der Identitätsschlüssel beweist nur „ich bin dieser
registrierte Client" und hat deshalb keine Passphrase — sonst wäre kein
unbeaufsichtigter Bezug möglich. Die Zertifikatsschlüssel dürfen und
sollen eine haben; sie sind es, mit denen man sich anmeldet.

Änderbar über `--base` oder `SSH_CA_CLIENT_HOME`.

## Betrieb

```sh
systemctl status ssh-ca-server
journalctl -u ssh-ca-server -f            # jede Anfrage mit Adresse und Status

ssh-ca-server clients                     # wer ist registriert
ssh-ca-server client show dennis@jump
ssh-ca-server client disable dennis@jump  # sperren, Registrierung bleibt
ssh-ca-server client enable  dennis@jump
ssh-ca-server client remove  dennis@jump  # Registrierung löschen
```

Ausgestellte Zertifikate erscheinen im normalen Bestand und werden dort
verwaltet — Widerruf, Sperrung, Export und Löschen laufen wie immer über
`ssh-ca-manager` bzw. die Oberflächen. Der Dienst kennt keinen Widerruf;
das bleibt bewusst beim Administrator an der CA.

Ein Client, dessen Maschine neu aufgesetzt wurde, meldet sich mit einem
**neuen Token** erneut an; das ersetzt den hinterlegten Schlüssel. Ohne
Token geht das nicht.

## API-Referenz

Alle Pfade unter `/v1`, JSON hin wie zurück, Fehler als
`{"error": "…"}`.

| Methode | Pfad | Signatur nötig | Zweck |
|---|---|---|---|
| GET | `/v1/info` | nein | Version, CA-Fingerprint, CA-Public-Key |
| POST | `/v1/enroll` | nein (Token) | Registrierung |
| GET | `/v1/principals` | ja | freigegebene Prinzipale |
| GET | `/v1/templates` | ja | freigegebene Vorlagen, Obergrenze |
| GET | `/v1/ca` | ja | CA-Public-Key und KRL |
| GET | `/v1/certificates` | ja | eigener Bestand |
| POST | `/v1/sign` | ja | Public Key signieren |

Signierte Anfragen tragen vier Kopfzeilen: `X-SSHCA-Client`,
`X-SSHCA-Timestamp` (ISO-8601 mit Zeitzone), `X-SSHCA-Nonce` und
`X-SSHCA-Signature` (Base64 der SSHSIG im Namensraum
`ssh-ca-manager-api`).

## Fehlerbehebung

| Meldung | Ursache |
|---|---|
| „Das Serverzertifikat wurde nicht akzeptiert" | `--ca-bundle` passt nicht zur PKI, oder der Name im Zertifikat ist nicht der, unter dem der Server angesprochen wird |
| „Zeitstempel liegt außerhalb des zulässigen Fensters" | Uhr des Clients weicht um mehr als 300 s ab |
| „Diese Anfrage wurde bereits gestellt" | Wiedereinspielung — oder ein Client, der eine Anfrage wörtlich wiederholt |
| „Unbekannter Client" | noch kein Enrollment, oder die Registrierung wurde entfernt |
| „Token ist unbekannt, abgelaufen oder verbraucht" | eine Meldung für alle drei Fälle; ob eine ID existiert, verrät der Dienst nicht |
| „signing = agent, aber der CA-Schlüssel liegt nicht im ssh-agent" | `ssh-add` nach dem Neustart vergessen, oder `SSH_AUTH_SOCK` in der Unit stimmt nicht |
| „Für … existiert ein lokal verwalteter Schlüssel" | für diesen user/host liegt auf der CA ein Schlüsselpaar aus dem lokalen Betrieb; erst widerrufen oder löschen |

Für den ersten Test einer frisch aufgesetzten Instanz gibt es
`--insecure` — es schaltet die TLS-Prüfung ab und sagt das deutlich. Im
Betrieb hat es nichts zu suchen.

## Grenzen

* **Kein Widerruf über die API.** Bewusst: wer widerrufen darf, sitzt an
  der CA.
* **Host-Zertifikate** kennt auch der Dienst nicht — er stellt
  ausschließlich Benutzerzertifikate aus.
* **CA-Schlüssel auf PKCS#11-Token** ist nicht angebunden; die
  Signaturschicht unterscheidet bislang Datei und Agent.
* **Der Nonce-Cache liegt im Speicher.** Ein Neustart öffnet das
  Wiedereinspielungsfenster für wenige Minuten. Die Abwägung ist bewusst:
  eine wiederholte Anfrage kostet ein Zertifikat, kein Recht.
* **POSIX.** `fcntl.flock` für die Sperre und die Askpass-Mechanik der
  Kernschicht binden den Dienst an Unix.
