"""Kommandozeilenmodus.

Gleicher Funktionsumfang wie die Oberflaeche, gleiche Kernschicht, gleicher
Datenbestand. Passphrasen werden interaktiv abgefragt (getpass) und wie in der
GUI ueber den Askpass-Mechanismus an ssh-keygen uebergeben — nie ueber argv
oder die Umgebung. Liegt der CA-Schluessel im ssh-agent, wird ohne Rueckfrage
darueber signiert (abschaltbar mit --no-agent).

Die Hooks _getpass und _input sind absichtlich Modulvariablen: Tests haengen
sich dort ein, ohne ein Terminal zu brauchen.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime
from pathlib import Path

from .ca import CaError, CertificateAuthority, CertRequest
from .config import APP_NAME, APP_VERSION, DEPLOYMENT_HELP, Paths
from .keygen import SshKeygenError
from .model import CertInfo, Status
from .templates import KNOWN_CRITICAL_OPTIONS, KNOWN_EXTENSIONS, TemplateStore

# Test-Hooks
_getpass = getpass.getpass
_input = input

_STATUS_ANSI = {
    Status.VALID: "32",
    Status.EXPIRING: "33",
    Status.EXPIRED: "31",
    Status.FUTURE: "34",
    Status.REVOKED: "31",
    Status.STORED: "35",
    Status.UNKNOWN: "90",
}


def _color(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def _status_text(cert: CertInfo) -> str:
    return _color(_STATUS_ANSI[cert.status()], cert.status_text())


def _trunc(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _err(message: str) -> int:
    print(f"Fehler: {message}", file=sys.stderr)
    return 1


def _confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    answer = _input(f"{question} [j/N] ").strip().lower()
    return answer in ("j", "ja", "y", "yes")


def _ask_new_passphrase(prompt: str, min_length: int = 8) -> str:
    for _ in range(3):
        first = _getpass(f"{prompt}: ")
        if len(first) < min_length:
            print(f"Die Passphrase sollte mindestens {min_length} Zeichen haben.")
            continue
        second = _getpass("Wiederholen: ")
        if first != second:
            print("Die Eingaben stimmen nicht überein.")
            continue
        return first
    raise CaError("Keine gültige Passphrase eingegeben.")


def _resolve_signing(ca: CertificateAuthority, args) -> tuple[bool, str]:
    """Agent oder Passphrase? Liefert (use_agent, ca_passphrase)."""
    use_agent = ca.ca_in_agent() and not getattr(args, "no_agent", False)
    if use_agent:
        print("Signatur über den ssh-agent (CA-Schlüssel ist geladen).")
        return True, ""
    return False, _getpass("CA-Passphrase: ")


def _find_cert(ca: CertificateAuthority, user: str, host: str) -> CertInfo:
    cert_path = Path(str(ca.paths.key_path(user, host)) + "-cert.pub")
    if not cert_path.is_file():
        # Extern signierte Schlüssel tragen ihren Typ im Namen (rsa, ecdsa …).
        candidates = sorted(
            ca.paths.host_dir(user, host).glob(f"{host}_{user}_*-cert.pub")
        )
        if candidates:
            cert_path = candidates[0]
        else:
            raise CaError(
                f"Kein Zertifikat für {user}@{host} unter {cert_path.parent}"
            )
    return ca.load_certificate(cert_path)


def _build_request(ca: CertificateAuthority, args, ask_key_pass: bool = True) -> CertRequest:
    """Baut aus Vorlage und Schaltern ein CertRequest — wie der GUI-Dialog."""
    store = TemplateStore(ca.paths.templates_file)
    template = None
    if args.template:
        for candidate in store.load():
            if candidate.name.lower().startswith(args.template.lower()):
                template = candidate
                break
        if template is None:
            raise CaError(
                f"Vorlage '{args.template}' nicht gefunden. "
                "Verfügbare Vorlagen: ssh-ca-manager templates"
            )

    # Prinzipale: -p ersetzt die Vorgabe; --conf-principals ergänzt.
    if args.principal:
        principals = list(dict.fromkeys(args.principal))
    elif template is not None:
        principals = template.principals_for(args.user, args.host)
    else:
        principals = [args.user, f"{args.user}@{args.host}"]
    if getattr(args, "conf_principals", False):
        for value in ca.paths.read_principals_conf():
            if value not in principals:
                principals.append(value)

    if args.validity:
        validity = args.validity
    elif template is not None:
        validity = template.validity
    else:
        validity = "+1h"

    if args.ext is not None:
        extensions = [] if args.ext == ["none"] else list(dict.fromkeys(args.ext))
    elif template is not None:
        extensions = list(template.extensions)
    else:
        extensions = ["permit-pty"]

    critical: dict[str, str] = dict(template.critical_options) if template else {}
    if args.force_command:
        critical["force-command"] = args.force_command
    if args.source_address:
        critical["source-address"] = args.source_address
    if getattr(args, "verify_required", False):
        critical["verify-required"] = ""

    if ask_key_pass and not args.no_key_pass:
        key_pass = _ask_new_passphrase(
            f"Passphrase für den neuen Schlüssel {args.host}_{args.user}"
        )
    else:
        key_pass = ""

    use_agent, ca_pass = _resolve_signing(ca, args)
    return CertRequest(
        user=args.user,
        host=args.host,
        principals=principals,
        validity=validity,
        extensions=extensions,
        critical_options=critical,
        key_passphrase=key_pass,
        ca_passphrase=ca_pass,
        use_agent=use_agent,
        key_id=getattr(args, "key_id", "") or "",
    )


def _print_cert_summary(cert: CertInfo) -> None:
    print(f"  Status:        {_status_text(cert)}")
    print(f"  Key ID:        {cert.key_id}")
    print(f"  Seriennummer:  {cert.serial}")
    print(f"  Gültigkeit:    {cert.validity_text}")
    print(f"  Prinzipale:    {cert.principals_csv}")
    if cert.extensions:
        print(f"  Extensions:    {', '.join(sorted(cert.extensions))}")
    if cert.critical_options:
        joined = ", ".join(
            f"{k}={v}" if v else k for k, v in cert.critical_options.items()
        )
        print(f"  Critical:      {joined}")
    print(f"  Zertifikat:    {cert.cert_path}")


# ---------------------------------------------------------------- Befehle
def cmd_status(ca: CertificateAuthority, args) -> int:
    if not ca.exists():
        print("Keine CA vorhanden. Anlegen mit: ssh-ca-manager init")
        return 1
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    revoked = list(ca.iter_revoked_entries())
    agent = " · im ssh-agent geladen" if ca.ca_in_agent() else ""
    print(f"CA:            {ca.ca_fingerprint()}{agent}")
    print(f"Schlüssel:     {ca.paths.ca_key}")
    krl_state = "vorhanden" if ca.paths.krl.is_file() else "noch nicht angelegt"
    print(f"KRL:           {ca.paths.krl} ({krl_state})")
    print(f"Zertifikate:   {len(certs)} aktiv, {len(revoked)} widerrufen/ausgelagert")
    print(f"Datenbasis:    {ca.paths.base}")
    return 0


def cmd_init(ca: CertificateAuthority, args) -> int:
    if ca.exists():
        return _err("Es existiert bereits eine CA an dieser Stelle.")
    passphrase = _ask_new_passphrase("Passphrase für den neuen CA-Schlüssel")
    ca.init_ca(passphrase, args.comment)
    print(f"CA erstellt: {ca.ca_fingerprint()}")
    print(f"Public Key:  {ca.paths.ca_pub}")
    return 0


def cmd_import(ca: CertificateAuthority, args) -> int:
    passphrase = _getpass(
        "Passphrase des Schlüssels (leer lassen, falls eine .pub-Datei daneben liegt): "
    )
    ca.import_ca(Path(args.keyfile), passphrase)
    print(f"CA importiert: {ca.ca_fingerprint()}")
    return 0


def cmd_pubkey(ca: CertificateAuthority, args) -> int:
    ca.require()
    if args.out:
        Path(args.out).write_text(ca.ca_public_key() + "\n", encoding="utf-8")
        print(f"Gespeichert: {args.out}")
    else:
        print(ca.ca_public_key())
    return 0


def cmd_list(ca: CertificateAuthority, args) -> int:
    ca.require()
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    if args.filter:
        needle = args.filter.lower()
        certs = [
            c for c in certs
            if needle in " ".join(
                [c.user, c.host, c.key_id, c.serial, c.principals_csv]
            ).lower()
        ]
    if not args.all:
        certs = [
            c for c in certs
            if c.status() not in (Status.EXPIRED, Status.REVOKED)
        ]
    if not certs:
        print("Keine passenden Zertifikate. (--all zeigt auch abgelaufene)")
        return 0
    print(f"{'BENUTZER':<12} {'HOST':<18} {'GÜLTIG BIS':<17} "
          f"{'PRINZIPALE':<28} STATUS")
    for cert in sorted(certs, key=lambda c: (c.user, c.host)):
        until = (
            "unbegrenzt" if cert.forever
            else f"{cert.valid_to:%Y-%m-%d %H:%M}" if cert.valid_to else "-"
        )
        print(
            f"{_trunc(cert.user, 12):<12} {_trunc(cert.host, 18):<18} "
            f"{until:<17} {_trunc(cert.principals_csv, 28):<28} "
            f"{_status_text(cert)}"
        )
    return 0


def cmd_create(ca: CertificateAuthority, args) -> int:
    ca.require()
    # Vor jeder Passphrasen-Abfrage pruefen — niemand soll erst tippen
    # und dann "existiert schon" lesen.
    existing = ca.paths.key_path(args.user, args.host)
    if existing.exists():
        return _err(
            f"Es gibt bereits einen Schlüssel unter {existing}. "
            "Für eine neue Gültigkeit: ssh-ca-manager renew "
            f"{args.user} {args.host}"
        )
    request = _build_request(ca, args)
    cert = ca.create_certificate(request)
    print(f"Zertifikat erstellt: {cert.user}@{cert.host}")
    _print_cert_summary(cert)
    principal = cert.principals[0] if cert.principals else cert.user
    print("\nAnmeldung:")
    print(f"  ssh -i {cert.key_path} {principal}@{cert.host}")
    return 0


def cmd_sign_key(ca: CertificateAuthority, args) -> int:
    """Signiert einen extern erzeugten Public Key."""
    ca.require()
    pubfile = Path(args.pubfile).expanduser()
    if not pubfile.is_file():
        return _err(f"Datei nicht gefunden: {pubfile}")
    request = _build_request(ca, args, ask_key_pass=False)
    cert = ca.import_and_sign_pubkey(pubfile, request)
    print(f"Externer Schlüssel signiert: {cert.user}@{cert.host}")
    _print_cert_summary(cert)
    print("\nZurück an den Benutzer geht nur die Zertifikatsdatei:")
    print(f"  {cert.cert_path.name}")
    print("Er legt sie neben seinen privaten Schlüssel "
          "(<key> und <key>-cert.pub).")
    return 0


def cmd_show(ca: CertificateAuthority, args) -> int:
    cert = _find_cert(ca, args.user, args.host)
    _print_cert_summary(cert)
    print(f"  Fingerprint:   {cert.pubkey_fp}")
    print(f"  Signierende CA: {cert.ca_fp}")
    key_state = str(cert.key_path) if cert.has_private_key else "fehlt"
    print(f"  Privater Key:  {key_state}")
    if args.raw and cert.raw:
        print("\n--- ssh-keygen -L " + "-" * 44)
        print(cert.raw.rstrip())
    return 0


def cmd_renew(ca: CertificateAuthority, args) -> int:
    cert = _find_cert(ca, args.user, args.host)
    if not _confirm(
        f"Schlüssel und Zertifikat für {args.user}@{args.host} neu erzeugen? "
        "Das bisherige Material wandert nach archive/ und ersetzt den dortigen Stand.",
        args.yes,
    ):
        print("Abgebrochen.")
        return 1
    request = _build_request(ca, args)
    new_cert = ca.renew_certificate(cert, request)
    print(f"Zertifikat erneuert: {new_cert.user}@{new_cert.host}")
    _print_cert_summary(new_cert)
    return 0


def cmd_revoke(ca: CertificateAuthority, args) -> int:
    cert = _find_cert(ca, args.user, args.host)
    action = "gesperrt" if args.lock else "widerrufen"
    if not _confirm(
        f"Zertifikat für {args.user}@{args.host} {action[:-1]}en? "
        "Der Vorgang ist endgültig — die KRL kennt keine Rücknahme.",
        args.yes,
    ):
        print("Abgebrochen.")
        return 1
    use_agent, ca_pass = _resolve_signing(ca, args)
    store = ca.revoke(cert, args.reason or "", action, ca_pass, use_agent)
    print(f"{action}: {args.user}@{args.host}")
    print(f"Material ausgelagert nach: {store}")
    print(
        "\nDamit der Widerruf auf den Zielsystemen greift, dort die KRL "
        f"neu hinterlegen:\n  {ca.paths.krl}"
    )
    return 0


def cmd_delete(ca: CertificateAuthority, args) -> int:
    cert = _find_cert(ca, args.user, args.host)
    if not _confirm(
        f"Schlüssel, Public Key und Zertifikat für {args.user}@{args.host} "
        f"({cert.status_text()}) endgültig löschen — einschließlich archive/?",
        args.yes,
    ):
        print("Abgebrochen.")
        return 1
    ca.delete_certificate(cert)
    print(f"Gelöscht: {args.user}@{args.host}")
    return 0


def cmd_revoked(ca: CertificateAuthority, args) -> int:
    entries = list(ca.iter_revoked_entries())
    if not entries:
        print("Keine widerrufenen oder ausgelagerten Vorgänge.")
        return 0
    print(f"{'ART':<12} {'BENUTZER':<12} {'HOST':<18} {'ZEITPUNKT':<20} "
          f"{'ABLAGE':<16} GRUND")
    for entry in entries:
        print(
            f"{entry.action:<12} {_trunc(entry.user, 12):<12} "
            f"{_trunc(entry.host, 18):<18} {entry.revoked_at:<20} "
            f"{entry.directory.name:<16} {entry.reason}"
        )
    return 0


def cmd_purge(ca: CertificateAuthority, args) -> int:
    entries = [
        e for e in ca.iter_revoked_entries()
        if e.user == args.user and e.host == args.host
        and (not args.timestamp or e.directory.name == args.timestamp)
    ]
    if not entries:
        return _err(
            f"Keine Widerrufsablage für {args.user}@{args.host} gefunden. "
            "Übersicht: ssh-ca-manager revoked"
        )
    if len(entries) > 1 and not args.timestamp:
        print("Mehrere Ablagen gefunden — bitte den Zeitstempel angeben:")
        for entry in entries:
            print(f"  {entry.directory.name}  ({entry.action}, {entry.reason})")
        return 1
    entry = entries[0]
    if not _confirm(
        f"Ausgelagertes Material für {entry.user}@{entry.host} "
        f"({entry.directory.name}) endgültig löschen? "
        "Der KRL-Eintrag bleibt bestehen.",
        args.yes,
    ):
        print("Abgebrochen.")
        return 1
    ca.delete_revoked_entry(entry)
    print(f"Ablage gelöscht: {entry.directory}")
    return 0


def cmd_export(ca: CertificateAuthority, args) -> int:
    ca.require()
    if args.user and args.host:
        certs = [_find_cert(ca, args.user, args.host)]
    else:
        certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    destination = Path(args.output or f"ssh-ca-export-{stamp}.tar.gz")
    path, count = ca.export_certificates(certs, destination)
    print(f"{count} Zertifikat(e) exportiert: {path}")
    return 0


def cmd_backup(ca: CertificateAuthority, args) -> int:
    destination = ca.backup(Path(args.output) if args.output else None)
    print(f"Sicherung geschrieben: {destination}")
    return 0


def cmd_restore(ca: CertificateAuthority, args) -> int:
    if not _confirm(
        "Vorhandene Dateien mit gleichem Namen werden überschrieben. Fortfahren?",
        args.yes,
    ):
        print("Abgebrochen.")
        return 1
    ca.restore(Path(args.archive))
    print("Sicherung eingespielt.")
    return 0


def cmd_templates(ca: CertificateAuthority, args) -> int:
    for template in TemplateStore(ca.paths.templates_file).load():
        print(f"{template.name}")
        print(f"    Gültigkeit:  {template.validity}")
        print(f"    Prinzipale:  {', '.join(template.principal_patterns)}")
        exts = ", ".join(template.extensions) or "(keine)"
        print(f"    Extensions:  {exts}")
        if template.critical_options:
            joined = ", ".join(
                f"{k}={v}" if v else k
                for k, v in template.critical_options.items()
            )
            print(f"    Critical:    {joined}")
        if template.description:
            print(f"    {template.description}")
    return 0


def cmd_deploy(ca: CertificateAuthority, args) -> int:
    print(DEPLOYMENT_HELP.format(
        ca_pub=ca.paths.ca_pub, krl=ca.paths.krl, base=ca.paths.base
    ))
    return 0


def cmd_log(ca: CertificateAuthority, args) -> int:
    text = ca.read_log(args.lines)
    print(text if text else "Es gibt noch keine Logeinträge.")
    return 0


# ---------------------------------------------------------------- Parser
def _add_cert_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-t", "--template", metavar="NAME",
                        help="Vorlage anwenden (Präfix genügt)")
    parser.add_argument("-p", "--principal", action="append", metavar="NAME",
                        help="Prinzipal (mehrfach möglich; ersetzt die Vorgabe)")
    parser.add_argument("--conf-principals", action="store_true",
                        help="alle Einträge aus principals.conf übernehmen")
    parser.add_argument("-V", "--validity", metavar="SPEC",
                        help="Gültigkeit, z. B. +1h, +9h, +52w (Vorgabe: +1h)")
    parser.add_argument("--ext", action="append", metavar="EXT",
                        choices=[*KNOWN_EXTENSIONS, "none"],
                        help=f"Extension ({', '.join(KNOWN_EXTENSIONS)} oder none)")
    parser.add_argument("--force-command", metavar="CMD",
                        help=KNOWN_CRITICAL_OPTIONS["force-command"])
    parser.add_argument("--source-address", metavar="NETZE",
                        help=KNOWN_CRITICAL_OPTIONS["source-address"])
    parser.add_argument("--verify-required", action="store_true",
                        help=KNOWN_CRITICAL_OPTIONS["verify-required"])
    parser.add_argument("--key-id", metavar="ID", help="Key ID (Vorgabe: automatisch)")
    parser.add_argument("--no-key-pass", action="store_true",
                        help="Schlüssel ohne Passphrase erzeugen (Automatisierung)")
    parser.add_argument("--no-agent", action="store_true",
                        help="nicht über den ssh-agent signieren, Passphrase abfragen")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-ca-manager",
        description=f"{APP_NAME} {APP_VERSION} — SSH Certificate Authority "
                    "verwalten (CLI; grafische Oberfläche mit --gui)",
    )
    parser.add_argument("--base", type=Path, default=None,
                        help="Datenverzeichnis (Vorgabe: ~/.ssh-ca bzw. $SSH_CA_HOME)")
    parser.add_argument("--gui", action="store_true",
                        help="grafische Oberfläche starten")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")

    sub = parser.add_subparsers(dest="command", metavar="BEFEHL")

    sub.add_parser("status", help="CA-Status und Bestand anzeigen")

    p = sub.add_parser("init", help="neue CA anlegen")
    p.add_argument("--comment", default="ssh-ca", help="Kommentar im CA-Key")

    p = sub.add_parser("import", help="bestehende CA importieren")
    p.add_argument("keyfile", help="privater CA-Schlüssel")

    p = sub.add_parser("pubkey", help="CA-Public-Key ausgeben")
    p.add_argument("--out", metavar="DATEI", help="in Datei schreiben statt ausgeben")

    p = sub.add_parser("list", help="Zertifikate auflisten")
    p.add_argument("--all", action="store_true",
                   help="auch abgelaufene und widerrufene zeigen")
    p.add_argument("--filter", metavar="TEXT",
                   help="nach Benutzer, Host, Prinzipal oder Seriennummer filtern")

    p = sub.add_parser("create", help="neues Zertifikat erstellen")
    p.add_argument("user")
    p.add_argument("host")
    _add_cert_options(p)

    p = sub.add_parser("sign-key",
                       help="extern erzeugten Public Key signieren")
    p.add_argument("pubfile", help="eingereichte .pub-Datei des Benutzers")
    p.add_argument("user")
    p.add_argument("host")
    _add_cert_options(p)

    p = sub.add_parser("show", help="Details eines Zertifikats")
    p.add_argument("user")
    p.add_argument("host")
    p.add_argument("--raw", action="store_true", help="Rohausgabe von ssh-keygen -L")

    p = sub.add_parser("renew", help="Zertifikat erneuern (Key wird neu erzeugt)")
    p.add_argument("user")
    p.add_argument("host")
    p.add_argument("--yes", action="store_true", help="nicht nachfragen")
    _add_cert_options(p)

    p = sub.add_parser("revoke", help="Zertifikat widerrufen (KRL + Auslagerung)")
    p.add_argument("user")
    p.add_argument("host")
    p.add_argument("--reason", metavar="TEXT", help="Grund des Widerrufs")
    p.add_argument("--lock", action="store_true",
                   help="als 'gesperrt' kennzeichnen (Material kompromittiert)")
    p.add_argument("--yes", action="store_true", help="nicht nachfragen")
    p.add_argument("--no-agent", action="store_true",
                   help="nicht über den ssh-agent signieren, Passphrase abfragen")

    p = sub.add_parser("delete", help="ungültiges Zertifikat endgültig löschen")
    p.add_argument("user")
    p.add_argument("host")
    p.add_argument("--yes", action="store_true", help="nicht nachfragen")

    sub.add_parser("revoked", help="widerrufene/ausgelagerte Vorgänge auflisten")

    p = sub.add_parser("purge", help="Widerrufsablage endgültig löschen")
    p.add_argument("user")
    p.add_argument("host")
    p.add_argument("timestamp", nargs="?",
                   help="Zeitstempel der Ablage (bei mehreren nötig)")
    p.add_argument("--yes", action="store_true", help="nicht nachfragen")

    p = sub.add_parser("export", help="gültige Zertifikate als tar.gz exportieren")
    p.add_argument("user", nargs="?", help="nur dieses Zertifikat …")
    p.add_argument("host", nargs="?", help="… statt aller gültigen")
    p.add_argument("-o", "--output", metavar="DATEI",
                   help="Zieldatei (Vorgabe: ssh-ca-export-<Zeit>.tar.gz)")

    p = sub.add_parser("backup", help="komplette Sicherung als tar.gz")
    p.add_argument("-o", "--output", metavar="DATEI")

    p = sub.add_parser("restore", help="Sicherung einspielen")
    p.add_argument("archive")
    p.add_argument("--yes", action="store_true", help="nicht nachfragen")

    sub.add_parser("templates", help="Vorlagen anzeigen")
    sub.add_parser("deploy", help="Anleitung für die Zielsysteme ausgeben")

    p = sub.add_parser("log", help="Logeinträge anzeigen")
    p.add_argument("-n", "--lines", type=int, default=50, metavar="N",
                   help="Anzahl Zeilen (Vorgabe: 50)")

    return parser


_HANDLERS = {
    "status": cmd_status,
    "init": cmd_init,
    "import": cmd_import,
    "pubkey": cmd_pubkey,
    "list": cmd_list,
    "create": cmd_create,
    "sign-key": cmd_sign_key,
    "show": cmd_show,
    "renew": cmd_renew,
    "revoke": cmd_revoke,
    "delete": cmd_delete,
    "revoked": cmd_revoked,
    "purge": cmd_purge,
    "export": cmd_export,
    "backup": cmd_backup,
    "restore": cmd_restore,
    "templates": cmd_templates,
    "deploy": cmd_deploy,
    "log": cmd_log,
}


def run_cli(args, parser: argparse.ArgumentParser) -> int:
    if not args.command:
        # Auf einem Terminal startet das interaktive Menü; in Pipes und
        # Skripten gibt es wie gehabt die Hilfe (Exitcode 2).
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .tui import run_menu

            return run_menu(args.base)
        parser.print_help()
        return 2
    ca = CertificateAuthority(Paths(args.base))
    if args.command == "export" and bool(args.user) != bool(args.host):
        return _err("export braucht Benutzer UND Host — oder keins von beiden.")
    try:
        return _HANDLERS[args.command](ca, args)
    except (CaError, SshKeygenError) as exc:
        return _err(str(exc))
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        try:
            from .gui import run
        except ImportError as exc:
            print(f"PySide6 fehlt: {exc}", file=sys.stderr)
            print("Installation: sudo pacman -S pyside6  (oder: pip install PySide6)",
                  file=sys.stderr)
            return 1
        return run(args.base)
    return run_cli(args, parser)
