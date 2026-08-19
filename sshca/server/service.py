"""Kommandozeile des Signierdienstes: ``ssh-ca-server``.

Enthaelt alles, was auf dem Server betrieben wird — ausser der Ausgabe von
Enrollment-Tokens. Die ist bewusst ein eigenes Programm
(``ssh-ca-enroll-token``): sie ist der einzige Vorgang, der ein Geheimnis
erzeugt, und sie soll sich getrennt berechtigen und getrennt protokollieren
lassen.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..config import APP_NAME, APP_VERSION, CaError
from ..keygen import SshKeygenError
from ..templates import (
    KNOWN_CRITICAL_OPTIONS,
    KNOWN_EXTENSIONS,
    Template,
    TemplateStore,
)
from .api import Api
from .config import DEFAULT_CONFIG, ServerConfig
from .registry import Registry


def _err(message: str) -> int:
    print(f"Fehler: {message}", file=sys.stderr)
    return 1


def _load(args) -> Api:
    return Api(ServerConfig.load(args.config))


# ---------------------------------------------------------------- Befehle
def cmd_run(args) -> int:
    from .http import serve

    return serve(_load(args))


def cmd_check(args) -> int:
    """Prueft Konfiguration, CA und Signierweg — ohne zu starten."""
    api = _load(args)
    config = api.config
    print(f"Konfiguration:  {config.source}")
    print(f"Adresse:        https://{config.listen}:{config.port}")
    print(f"Serverzert.:    {config.tls_cert}")
    print(f"Client-CA:      {config.tls_client_ca or '(kein mutual TLS)'}")
    print(f"CA-Daten:       {api.ca.paths.base}")
    print(f"CA:             {api.ca.ca_fingerprint()}")
    print(f"Signierweg:     {config.signing}")
    print(f"Zustand:        {config.state_dir}")
    clients = api.registry.list_clients()
    tokens = [t for t in api.registry.list_tokens() if t.state == "offen"]
    print(f"Registriert:    {len(clients)} Client(s), {len(tokens)} offene Token")
    problems = api.startup_check()
    if problems:
        print()
        for problem in problems:
            print(f"  ✗ {problem}")
        return 1
    print("\n  ✓ Der Dienst kann starten.")
    return 0


def cmd_install(args) -> int:
    from .install import install

    return install(
        apply=args.apply,
        service_user=args.user,
        config_path=Path(args.config),
        state_dir=Path(args.state_dir),
        ca_base=Path(args.ca_base) if args.ca_base else None,
        port=args.port,
        with_agent_unit=not args.no_agent_unit,
    )


def cmd_clients(args) -> int:
    registry = Registry(ServerConfig.load(args.config).state_dir)
    clients = registry.list_clients()
    if not clients:
        print("Noch kein Client registriert.")
        return 0
    print(f"{'CLIENT':<28} {'ZUSTAND':<10} {'ENROLLMENT':<20} "
          f"{'ZULETZT':<20} PRINZIPALE")
    for client in clients:
        state = "gesperrt" if client.disabled else "aktiv"
        principals = ", ".join(client.principals) if client.principals else "(alle)"
        print(
            f"{client.client_id[:28]:<28} {state:<10} {client.enrolled_at:<20} "
            f"{(client.last_seen or '-'):<20} {principals}"
        )
    return 0


def cmd_client(args) -> int:
    registry = Registry(ServerConfig.load(args.config).state_dir)
    if args.action == "show":
        client = registry.get_client(args.client_id)
        if client is None:
            return _err(f"Kein registrierter Client '{args.client_id}'.")
        print(f"Client:        {client.client_id}")
        print(f"Benutzer/Host: {client.user} / {client.host}")
        print(f"Zustand:       {'gesperrt' if client.disabled else 'aktiv'}")
        print(f"Enrollment:    {client.enrolled_at} von {client.enrolled_from}")
        print(f"Token:         {client.token_id}")
        print(f"Prinzipale:    {', '.join(client.principals) or '(alle erlaubten)'}")
        print(f"Vorlagen:      {', '.join(client.templates) or '(alle)'}")
        print(f"Max. Laufzeit: {client.max_validity or '(Servervorgabe)'}")
        print(f"Schlüssel:     {client.pubkey[:60]}…")
        return 0
    if args.action in ("disable", "enable"):
        client = registry.set_client_disabled(
            args.client_id, args.action == "disable"
        )
        print(f"{client.client_id}: "
              f"{'gesperrt' if client.disabled else 'wieder aktiv'}")
        return 0
    registry.remove_client(args.client_id)
    print(f"Registrierung entfernt: {args.client_id}")
    print("Der Client kann sich mit einem neuen Token erneut anmelden.")
    return 0


def cmd_template(args) -> int:
    """Vorlagen auf der Serverseite anlegen, anzeigen, entfernen.

    Es ist dieselbe ``templates.json``, die auch die lokalen Oberflaechen
    lesen — eine Vorlage, drei Oberflaechen und der Dienst.
    """
    api_paths = Api(ServerConfig.load(args.config)).ca.paths
    store = TemplateStore(api_paths.templates_file)
    templates = store.load()

    if args.action == "list":
        for template in templates:
            print(template.name)
            print(f"    Gültigkeit:  {template.validity}")
            print(f"    Prinzipale:  {', '.join(template.principal_patterns)}")
            print(f"    Extensions:  {', '.join(template.extensions) or '(keine)'}")
            if template.critical_options:
                joined = ", ".join(
                    f"{k}={v}" if v else k
                    for k, v in template.critical_options.items()
                )
                print(f"    Critical:    {joined}")
            if template.description:
                print(f"    {template.description}")
        return 0

    if args.action == "remove":
        remaining = [t for t in templates if t.name != args.name]
        if len(remaining) == len(templates):
            return _err(f"Keine Vorlage mit dem Namen '{args.name}'.")
        store.save(remaining)
        print(f"Vorlage entfernt: {args.name}")
        return 0

    # add
    if any(t.name == args.name for t in templates):
        return _err(
            f"Es gibt bereits eine Vorlage '{args.name}'. Erst entfernen "
            "oder einen anderen Namen wählen."
        )
    for ext in args.ext or []:
        if ext not in KNOWN_EXTENSIONS:
            return _err(f"Unbekannte Extension: {ext}")
    critical: dict[str, str] = {}
    if args.force_command:
        critical["force-command"] = args.force_command
    if args.source_address:
        critical["source-address"] = args.source_address
    if args.verify_required:
        critical["verify-required"] = ""

    template = Template(
        name=args.name,
        validity=args.validity,
        principal_patterns=args.principal or ["{user}", "{user}@{host}"],
        extensions=args.ext if args.ext is not None else ["permit-pty"],
        critical_options=critical,
        description=args.description or "",
    )
    store.save(templates + [template])
    print(f"Vorlage angelegt: {template.name} ({template.validity})")
    print("Clients wählen sie beim Erstellen mit -t aus.")
    return 0


# ----------------------------------------------------------------- Parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-ca-server",
        description=f"{APP_NAME} {APP_VERSION} — Signierdienst (HTTPS)",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), metavar="DATEI",
                        help=f"Konfiguration (Vorgabe: {DEFAULT_CONFIG})")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="BEFEHL")

    sub.add_parser("run", help="Dienst im Vordergrund starten (systemd)")
    sub.add_parser("check", help="Konfiguration, CA und Signierweg prüfen")

    p = sub.add_parser("install", help="systemd-Unit und Verzeichnisse anlegen")
    p.add_argument("--apply", action="store_true",
                   help="tatsächlich ausführen (ohne dies nur Trockenlauf)")
    p.add_argument("--user", default="ssh-ca", help="Dienstbenutzer")
    p.add_argument("--state-dir", default="/var/lib/ssh-ca-server",
                   help="Zustandsverzeichnis des Dienstes")
    p.add_argument("--ca-base", default=None,
                   help="CA-Datenverzeichnis (Vorgabe: ~<Dienstbenutzer>/.ssh-ca)")
    p.add_argument("--port", type=int, default=None, help="Port für die Vorlage")
    p.add_argument("--no-agent-unit", action="store_true",
                   help="keine ssh-ca-agent.service anlegen")

    sub.add_parser("clients", help="registrierte Clients auflisten")

    p = sub.add_parser("client", help="einen Client anzeigen oder sperren")
    p.add_argument("action", choices=["show", "disable", "enable", "remove"])
    p.add_argument("client_id", metavar="BENUTZER@HOST")

    p = sub.add_parser("template", help="Vorlagen verwalten")
    p.add_argument("action", choices=["list", "add", "remove"])
    p.add_argument("name", nargs="?", help="Name der Vorlage")
    p.add_argument("-V", "--validity", default="+1h", metavar="SPEC",
                   help="Gültigkeit, z. B. +1h, +9h (Vorgabe: +1h)")
    p.add_argument("-p", "--principal", action="append", metavar="MUSTER",
                   help="Prinzipalmuster mit {user}/{host} (mehrfach möglich)")
    p.add_argument("--ext", action="append", metavar="EXT",
                   choices=[*KNOWN_EXTENSIONS],
                   help=f"Extension ({', '.join(KNOWN_EXTENSIONS)})")
    p.add_argument("--force-command", metavar="CMD",
                   help=KNOWN_CRITICAL_OPTIONS["force-command"])
    p.add_argument("--source-address", metavar="NETZE",
                   help=KNOWN_CRITICAL_OPTIONS["source-address"])
    p.add_argument("--verify-required", action="store_true",
                   help=KNOWN_CRITICAL_OPTIONS["verify-required"])
    p.add_argument("--description", metavar="TEXT", help="Beschreibung")

    return parser


_HANDLERS = {
    "run": cmd_run,
    "check": cmd_check,
    "install": cmd_install,
    "clients": cmd_clients,
    "client": cmd_client,
    "template": cmd_template,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    if args.command == "template" and args.action != "list" and not args.name:
        return _err("Für 'template add' und 'template remove' fehlt der Name.")
    try:
        return _HANDLERS[args.command](args)
    except (CaError, SshKeygenError) as exc:
        return _err(str(exc))
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130
