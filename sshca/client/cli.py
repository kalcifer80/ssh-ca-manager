"""Kommandozeile des Clients: ``ssh-ca-client``.

Darstellung und Abfragestil sind die des interaktiven Menues — dieselben
Hilfsfunktionen aus :mod:`sshca.tui`, damit der Client nicht wie ein fremdes
Programm aussieht. Eingaben laufen wie ueberall im Projekt ueber die Hooks
``cli._input`` und ``cli._getpass``; damit sind die Ablaeufe ohne Terminal
testbar.

Der Ablauf in drei Schritten:

    ssh-ca-client enroll --server … --token …   einmalig, mit dem Token
    ssh-ca-client request                        Schlüssel erzeugen, signieren
    ssh -i ~/.ssh-ca-client/keys/…               anmelden
"""

from __future__ import annotations

import argparse
import socket
import sys
from datetime import datetime
from pathlib import Path

from .. import cli as base_cli
from ..config import APP_NAME, APP_VERSION, CaError, validate_name
from ..keygen import Ssh, SshKeygenError
from ..protocol import DEFAULT_PORT, cap_validity
from ..tui import (
    ACCENT,
    BANNER,
    MUTED,
    _ask_yesno,
    _c,
    _ok,
    _pad,
    _panel,
    _pick,
    _rule,
    _warn,
)
from .api import ClientPaths, ClientState, Connection, generate_identity, generate_key


def _err(message: str) -> int:
    print(f"Fehler: {message}", file=sys.stderr)
    return 1


def _require_enrolled(paths: ClientPaths) -> ClientState:
    state = paths.load_state()
    if not state.client_id or not state.server:
        raise CaError(
            "Dieser Client ist noch nicht registriert. Zuerst:\n"
            "  ssh-ca-client enroll --server https://<CA-Host>:"
            f"{DEFAULT_PORT} --token <ID>.<Geheimnis>"
        )
    if not paths.identity.is_file():
        raise CaError(
            f"Der Identitätsschlüssel fehlt ({paths.identity}). Der Client "
            "muss sich mit einem neuen Token erneut registrieren."
        )
    return state


def _connect(state: ClientState, args, ssh: Ssh) -> Connection:
    return Connection(
        state.server,
        ca_bundle=getattr(args, "ca_bundle", None) or state.ca_bundle or None,
        ssh=ssh,
        insecure=getattr(args, "insecure", False),
    )


# ------------------------------------------------------------------ Auswahl
def _choose_principals(available: list[str], args) -> list[str]:
    """Prinzipale aus der Serverliste waehlen.

    Drei Wege, in dieser Reihenfolge: ``-p`` auf der Kommandozeile,
    ``--all-principals``, sonst die Auswahl am Terminal. Ohne Terminal und
    ohne Angabe wird abgebrochen statt geraten — was hier stillschweigend
    passiert, steht spaeter in einem Zertifikat.
    """
    if args.principal:
        unknown = [p for p in args.principal if p not in available]
        if unknown:
            raise CaError(
                "Der Server gibt diese Prinzipale nicht frei: "
                + ", ".join(unknown)
                + "\nVerfügbar: " + ", ".join(available)
            )
        return list(dict.fromkeys(args.principal))
    if args.all_principals:
        return list(available)
    if not sys.stdin.isatty():
        raise CaError(
            "Ohne Terminal müssen die Prinzipale angegeben werden: "
            "-p NAME (mehrfach) oder --all-principals."
        )

    print(_c(MUTED, "  Vom Server freigegebene Prinzipale:"))
    for number, name in enumerate(available, 1):
        print(f"  {_c(ACCENT, f'{number:>3}')}  {name}")
    while True:
        raw = base_cli._input(
            _c(ACCENT, "  Auswahl (Nummern mit Komma · a = alle · 0 = abbrechen): ")
        ).strip().lower()
        if raw in ("0", "q"):
            raise CaError("Abgebrochen.")
        if raw == "a":
            return list(available)
        chosen: list[str] = []
        parts = [p.strip() for p in raw.replace(" ", ",").split(",") if p.strip()]
        if not parts:
            _warn("Bitte mindestens einen Prinzipal wählen.")
            continue
        for part in parts:
            if not part.isdigit() or not 1 <= int(part) <= len(available):
                chosen = []
                break
            value = available[int(part) - 1]
            if value not in chosen:
                chosen.append(value)
        if chosen:
            return chosen
        _warn("Eingabe nicht verstanden.")


def _choose_template(templates: list[dict], args) -> dict:
    if args.template:
        for entry in templates:
            if entry["name"].lower().startswith(args.template.lower()):
                return entry
        raise CaError(
            f"Der Server kennt keine freigegebene Vorlage '{args.template}'. "
            "Verfügbar: " + ", ".join(t["name"] for t in templates)
        )
    if not templates:
        raise CaError("Der Server hat für diesen Client keine Vorlage freigegeben.")
    if len(templates) == 1 or not sys.stdin.isatty():
        return templates[0]
    entries = [
        f"{_pad(t['name'], 26)} {_pad(t['validity'], 6)} "
        + _c(MUTED, ", ".join(t["extensions"]) or "(keine Extensions)")
        for t in templates
    ]
    index = _pick("Vorlage wählen:", entries)
    if index is None:
        raise CaError("Abgebrochen.")
    return templates[index]


def _ask_key_passphrase(args) -> str:
    if args.no_key_pass:
        return ""
    if not sys.stdin.isatty():
        raise CaError(
            "Ohne Terminal bitte --no-key-pass angeben, wenn der Schlüssel "
            "ohne Passphrase erzeugt werden soll."
        )
    while True:
        first = base_cli._getpass(
            "  Passphrase für den neuen Schlüssel (leer = ohne): "
        )
        if not first:
            if _ask_yesno("Wirklich ohne Passphrase (nur für Automatisierung)?",
                          default=False):
                return ""
            continue
        if len(first) < 8:
            _warn("Die Passphrase sollte mindestens 8 Zeichen haben.")
            continue
        if base_cli._getpass("  Wiederholen: ") != first:
            _warn("Die Eingaben stimmen nicht überein.")
            continue
        return first


# ----------------------------------------------------------------- Befehle
def cmd_enroll(paths: ClientPaths, args) -> int:
    """Erste Kontaktaufnahme: Token gegen Registrierung."""
    _rule("Enrollment")
    ssh = Ssh()
    host = args.host or socket.gethostname().split(".")[0]
    validate_name("Hostname", host)

    if args.insecure:
        _warn("--insecure: das Serverzertifikat wird NICHT geprüft. "
              "Nur für den Ersttest einer neuen Instanz.")

    connection = Connection(
        args.server, ca_bundle=args.ca_bundle, ssh=ssh, insecure=args.insecure
    )
    info = connection.info()
    print(f"  Server:      {args.server}")
    print(f"  Anwendung:   {info.get('application')} {info.get('version')}")
    print(f"  CA:          {info.get('ca_fingerprint')}")
    print(f"  Hostname:    {host}")

    token = args.token or base_cli._getpass("  Enrollment-Token: ")
    if not token.strip():
        raise CaError("Ohne Token geht die erste Kontaktaufnahme nicht.")

    pubkey = generate_identity(ssh, paths, f"ssh-ca-client@{host}")
    result = connection.enroll(token.strip(), pubkey, host)

    state = ClientState(
        server=args.server.rstrip("/"),
        client_id=result["client_id"],
        user=result["user"],
        host=result["host"],
        ca_bundle=str(Path(args.ca_bundle).expanduser()) if args.ca_bundle else "",
        ca_fingerprint=result.get("ca_fingerprint", ""),
        enrolled_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        principals=result.get("principals", []),
        templates=result.get("templates", []),
    )
    paths.save_state(state)
    if result.get("ca_pubkey"):
        paths.ca_pub.write_text(result["ca_pubkey"] + "\n", encoding="utf-8")
        paths.ca_pub.chmod(0o644)

    _ok(f"Registriert als {state.client_id}")
    hours = result.get("max_validity_seconds", 0) // 3600
    _panel("Registrierung", [
        f"Server:         {state.server}",
        f"Client:         {state.client_id}",
        f"Prinzipale:     {', '.join(state.principals) or '(keine)'}",
        f"Vorlagen:       {', '.join(state.templates) or '(keine)'}",
        f"Max. Laufzeit:  {hours} h",
        f"CA-Public-Key:  {paths.ca_pub}",
        f"Identität:      {paths.identity}",
    ])
    print(_c(MUTED, "  Weiter mit: ssh-ca-client request"))
    return 0


def cmd_request(paths: ClientPaths, args) -> int:
    """Schluessel erzeugen und vom Server signieren lassen."""
    state = _require_enrolled(paths)
    _rule("Erneuern" if args.command == "renew" else "Neues Zertifikat")
    ssh = Ssh()
    connection = _connect(state, args, ssh)

    remote = connection.templates(paths.identity, state.client_id)
    templates = remote["templates"]
    limit = int(remote.get("max_validity_seconds", 0))
    template = _choose_template(templates, args)
    available = connection.principals(paths.identity, state.client_id)["principals"]
    if not available:
        raise CaError("Der Server gibt für diesen Client keine Prinzipale frei.")

    # Ohne -V gilt die Vorlage, gekürzt auf die Obergrenze des Servers — die
    # Rechnung ist dieselbe wie dort, damit die Zusammenfassung nicht etwas
    # anderes ankündigt als hinterher im Zertifikat steht.
    if args.validity:
        validity = args.validity
        note = ""
    else:
        validity = (
            cap_validity(template["validity"], limit)
            if limit else template["validity"]
        )
        note = (
            f"  (Vorlage {template['validity']}, Serverobergrenze)"
            if validity != template["validity"] else ""
        )
    principals = _choose_principals(available, args)

    key_path = paths.key_path(state.user, state.host)
    if key_path.exists() and args.command != "renew":
        raise CaError(
            f"Es gibt bereits einen Schlüssel unter {key_path}. "
            "Für eine neue Gültigkeit: ssh-ca-client renew"
        )

    _panel("Zusammenfassung", [
        f"Server:         {state.server}",
        f"Benutzer/Host:  {state.user}@{state.host}",
        f"Vorlage:        {template['name']}",
        f"Gültigkeit:     {validity}{note}",
        f"Prinzipale:     {', '.join(principals)}",
        f"Extensions:     {', '.join(template['extensions']) or '(keine)'}",
        f"Schlüssel:      {key_path}",
    ])
    if sys.stdin.isatty() and not args.yes:
        if not _ask_yesno("Schlüssel jetzt erzeugen und signieren lassen?",
                          default=True):
            print("  Abgebrochen.")
            return 1

    passphrase = _ask_key_passphrase(args)
    key_path = generate_key(ssh, paths, state.user, state.host, passphrase)
    pubkey = Path(str(key_path) + ".pub").read_text(encoding="utf-8").strip()

    try:
        result = connection.sign(
            paths.identity,
            state.client_id,
            {
                "pubkey": pubkey,
                "template": template["name"],
                "principals": principals,
                # Nur die ausdrückliche Wahl geht mit; sonst entscheidet der
                # Server anhand der Vorlage und seiner Obergrenze.
                "validity": args.validity or "",
                "host": state.host,
            },
        )
    except CaError:
        # Ein unsignierter Schluessel waere nur Ballast — dieselbe Regel wie
        # in der Kernschicht.
        for suffix in ("", ".pub"):
            Path(str(key_path) + suffix).unlink(missing_ok=True)
        raise

    cert_path = Path(str(key_path) + "-cert.pub")
    cert_path.write_text(result["certificate"] + "\n", encoding="utf-8")
    cert_path.chmod(0o644)

    _ok(f"Zertifikat erhalten: {state.user}@{state.host}")
    _panel("Zertifikat", [
        f"Seriennummer:   {result.get('serial', '-')}",
        f"Key ID:         {result.get('key_id', '-')}",
        f"Gültig bis:     {result.get('valid_to', '-').replace('T', ' ')}",
        f"Prinzipale:     {', '.join(result.get('principals', []))}",
        f"Extensions:     {', '.join(result.get('extensions', [])) or '(keine)'}",
        f"Schlüssel:      {key_path}",
        f"Zertifikat:     {cert_path}",
    ])
    principal = (result.get("principals") or [state.user])[0]
    print(_c(MUTED, "  Anmeldung:"))
    print(f"    ssh -i {key_path} {principal}@<Zielhost>")
    return 0


def cmd_status(paths: ClientPaths, args) -> int:
    state = paths.load_state()
    if not state.client_id:
        _warn("Dieser Client ist noch nicht registriert.")
        print(_c(MUTED, "  ssh-ca-client enroll --server https://<CA-Host>:"
                        f"{DEFAULT_PORT} --token <ID>.<Geheimnis>"))
        return 1
    lines = [
        f"Server:         {state.server}",
        f"Client:         {state.client_id}",
        f"Registriert:    {state.enrolled_at}",
        f"CA-Bundle:      {state.ca_bundle or '(Systemvorrat)'}",
        f"CA:             {state.ca_fingerprint}",
        f"Datenbasis:     {paths.base}",
    ]
    key_path = paths.key_path(state.user, state.host)
    cert_path = Path(str(key_path) + "-cert.pub")
    if cert_path.is_file():
        lines.append(f"Schlüssel:      {key_path}")
        lines.append(f"Zertifikat:     {cert_path}")
    else:
        lines.append("Zertifikat:     (noch keines — ssh-ca-client request)")
    _panel("Client", lines)

    if args.remote:
        try:
            connection = _connect(state, args, Ssh())
            entries = connection.certificates(
                paths.identity, state.client_id
            )["certificates"]
        except CaError as exc:
            _warn(str(exc))
            return 1
        _rule("Beim Server hinterlegt")
        if not entries:
            print(_c(MUTED, "  Keine Zertifikate."))
            return 0
        print("  " + _c(MUTED, _pad("SERIENNUMMER", 22) + " "
                        + _pad("GÜLTIG BIS", 20) + " " + _pad("STATUS", 22)
                        + " PRINZIPALE"))
        for entry in entries:
            print("  " + _pad(str(entry["serial"])[:22], 22) + " "
                  + _pad(entry["valid_to"].replace("T", " ")[:19], 20) + " "
                  + _pad(entry["status"], 22) + " "
                  + ", ".join(entry["principals"]))
    return 0


def cmd_principals(paths: ClientPaths, args) -> int:
    state = _require_enrolled(paths)
    connection = _connect(state, args, Ssh())
    result = connection.principals(paths.identity, state.client_id)
    _rule("Freigegebene Prinzipale")
    for name in result["principals"]:
        print(f"  {name}")
    if result.get("restricted"):
        print(_c(MUTED, "\n  Die Liste ist durch das Enrollment-Token begrenzt."))
    return 0


def cmd_templates(paths: ClientPaths, args) -> int:
    state = _require_enrolled(paths)
    connection = _connect(state, args, Ssh())
    result = connection.templates(paths.identity, state.client_id)
    for entry in result["templates"]:
        lines = [
            f"Gültigkeit:  {entry['validity']}",
            f"Prinzipale:  {', '.join(entry['principal_patterns'])}",
            f"Extensions:  {', '.join(entry['extensions']) or '(keine)'}",
        ]
        if entry["critical_options"]:
            lines.append("Critical:    " + ", ".join(
                f"{k}={v}" if v else k
                for k, v in entry["critical_options"].items()))
        if entry["description"]:
            lines.append(_c(MUTED, entry["description"]))
        _panel(entry["name"], lines)
    hours = result.get("max_validity_seconds", 0) // 3600
    print(_c(MUTED, f"  Obergrenze für diesen Client: {hours} h"))
    return 0


def cmd_ca(paths: ClientPaths, args) -> int:
    """Holt CA-Public-Key und KRL — zum Einrichten eigener Zielsysteme."""
    state = _require_enrolled(paths)
    connection = _connect(state, args, Ssh())
    result = connection.ca_material(paths.identity, state.client_id)
    paths.ca_pub.write_text(result["ca_pubkey"] + "\n", encoding="utf-8")
    paths.ca_pub.chmod(0o644)
    _ok(f"CA-Public-Key gespeichert: {paths.ca_pub}")
    if result.get("krl_base64"):
        import base64

        paths.krl.write_bytes(base64.b64decode(result["krl_base64"]))
        paths.krl.chmod(0o644)
        _ok(f"Widerrufsliste gespeichert: {paths.krl}")
    else:
        print(_c(MUTED, "  Der Server führt noch keine Widerrufsliste."))
    return 0


# ------------------------------------------------------------------ Parser
def _add_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-t", "--template", metavar="NAME",
                        help="Vorlage des Servers (Präfix genügt)")
    parser.add_argument("-p", "--principal", action="append", metavar="NAME",
                        help="Prinzipal aus der Serverliste (mehrfach möglich)")
    parser.add_argument("--all-principals", action="store_true",
                        help="alle freigegebenen Prinzipale übernehmen")
    parser.add_argument("-V", "--validity", metavar="SPEC",
                        help="Gültigkeit, z. B. +1h, +9h (Vorgabe: aus der Vorlage)")
    parser.add_argument("--no-key-pass", action="store_true",
                        help="Schlüssel ohne Passphrase erzeugen (Automatisierung)")
    parser.add_argument("--yes", action="store_true", help="nicht nachfragen")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-ca-client",
        description=f"{APP_NAME} {APP_VERSION} — Client des Signierdienstes",
    )
    parser.add_argument("--base", default=None, metavar="VERZ",
                        help="Datenverzeichnis des Clients "
                             "(Vorgabe: ~/.ssh-ca-client bzw. $SSH_CA_CLIENT_HOME)")
    parser.add_argument("--ca-bundle", default=None, metavar="DATEI",
                        help="CA-Bundle der X.509-PKI für die TLS-Prüfung")
    parser.add_argument("--insecure", action="store_true",
                        help="TLS-Prüfung abschalten (nur zum Ersttest)")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="BEFEHL")

    p = sub.add_parser("enroll", help="am Server registrieren (Token nötig)")
    p.add_argument("--server", required=True, metavar="URL",
                   help=f"https://<CA-Host>:{DEFAULT_PORT}")
    p.add_argument("--token", default="", metavar="ID.GEHEIMNIS",
                   help="Enrollment-Token (ohne Angabe wird danach gefragt)")
    p.add_argument("--host", default="", metavar="NAME",
                   help="Hostname für die Registrierung (Vorgabe: eigener)")

    p = sub.add_parser("request", help="Schlüssel erzeugen und signieren lassen")
    _add_request_options(p)

    p = sub.add_parser("renew", help="Schlüssel neu erzeugen und signieren lassen")
    _add_request_options(p)

    p = sub.add_parser("status", help="Zustand des Clients")
    p.add_argument("--remote", action="store_true",
                   help="zusätzlich den Bestand beim Server abfragen")

    sub.add_parser("principals", help="freigegebene Prinzipale anzeigen")
    sub.add_parser("templates", help="freigegebene Vorlagen anzeigen")
    sub.add_parser("ca", help="CA-Public-Key und Widerrufsliste holen")

    return parser


_HANDLERS = {
    "enroll": cmd_enroll,
    "request": cmd_request,
    "renew": cmd_request,
    "status": cmd_status,
    "principals": cmd_principals,
    "templates": cmd_templates,
    "ca": cmd_ca,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        if sys.stdout.isatty():
            print(_c(ACCENT, BANNER))
            print(_c(MUTED, f"  Client {APP_VERSION}"))
            print()
        parser.print_help()
        return 2
    paths = ClientPaths(args.base)
    try:
        return _HANDLERS[args.command](paths, args)
    except (CaError, SshKeygenError) as exc:
        return _err(str(exc))
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130
