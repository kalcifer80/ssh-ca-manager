"""Enrollment-Tokens ausgeben: ``ssh-ca-enroll-token``.

Bewusst ein eigenes Programm neben ``ssh-ca-server``. Es ist der einzige
Vorgang, der ein Geheimnis erzeugt — getrennt aufrufbar heisst: getrennt
berechtigbar (``sudo``-Regel nur auf dieses Programm) und getrennt sichtbar in
der Shell-Historie und im Audit.

Das Geheimnis wird genau einmal ausgegeben, hier. Auf der Platte liegt nur
sein SHA-256; ein verlorenes Token laesst sich nicht nachschlagen, nur
zurueckziehen und neu ausstellen.
"""

from __future__ import annotations

import argparse
import sys

from ..config import APP_NAME, APP_VERSION, CaError
from .config import DEFAULT_CONFIG, ServerConfig
from .registry import Registry


def _err(message: str) -> int:
    print(f"Fehler: {message}", file=sys.stderr)
    return 1


def _registry(args) -> Registry:
    registry = Registry(ServerConfig.load(args.config).state_dir)
    registry.ensure_layout()
    return registry


def cmd_create(args) -> int:
    registry = _registry(args)
    principals = [p.strip() for p in (args.principals or "").split(",") if p.strip()]
    templates = [t.strip() for t in (args.templates or "").split(",") if t.strip()]
    token, secret = registry.create_token(
        user=args.user,
        host=args.host or "",
        principals=principals,
        templates=templates,
        max_validity=args.max_validity or "",
        lifetime=args.valid,
        uses=args.uses,
        comment=args.comment or "",
    )

    width = 72
    print()
    print("─" * width)
    print("  Enrollment-Token — wird nur dieses eine Mal angezeigt")
    print("─" * width)
    print()
    print(f"  {secret}")
    print()
    print(f"  Gültig für:     {token.user}"
          + (f"@{token.host}" if token.host else " (Host wählt der Client)"))
    print(f"  Verwendungen:   {token.uses_left}")
    print(f"  Läuft ab:       {token.expires_at}")
    print(f"  Prinzipale:     {', '.join(token.principals) or '(alle erlaubten)'}")
    print(f"  Vorlagen:       {', '.join(token.templates) or '(alle)'}")
    print(f"  Max. Laufzeit:  {token.max_validity or '(Servervorgabe)'}")
    print(f"  Token-ID:       {token.id}")
    print()
    print("  Auf dem Client:")
    print("    ssh-ca-client enroll --server https://<CA-Host>:8443 \\")
    print(f"      --token {token.id}.… --ca-bundle /etc/ssl/certs/pki-root.pem")
    print()
    print("  Das Token gehört über einen Kanal zum Client, der nicht derselbe")
    print("  ist wie der spätere Zugang — es ersetzt für einen Moment die")
    print("  gesamte Authentisierung.")
    print("─" * width)
    return 0


def cmd_list(args) -> int:
    tokens = _registry(args).list_tokens()
    if not tokens:
        print("Keine Tokens vorhanden.")
        return 0
    print(f"{'ID':<10} {'ZUSTAND':<12} {'BENUTZER@HOST':<24} {'LÄUFT AB':<20} "
          f"{'REST':<5} KOMMENTAR")
    for token in sorted(tokens, key=lambda t: t.created_at):
        target = token.user + (f"@{token.host}" if token.host else "@*")
        print(
            f"{token.id:<10} {token.state:<12} {target[:24]:<24} "
            f"{token.expires_at:<20} {token.uses_left:<5} {token.comment}"
        )
    return 0


def cmd_revoke(args) -> int:
    _registry(args).revoke_token(args.token_id)
    print(f"Token zurückgezogen: {args.token_id}")
    return 0


def cmd_purge(args) -> int:
    """Raeumt verbrauchte und abgelaufene Tokens weg."""
    registry = _registry(args)
    gone = 0
    for token in registry.list_tokens():
        if token.state != "offen":
            registry.revoke_token(token.id)
            gone += 1
    print(f"{gone} verbrauchte oder abgelaufene Token entfernt.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-ca-enroll-token",
        description=f"{APP_NAME} {APP_VERSION} — Enrollment-Tokens für die "
                    "erste Kontaktaufnahme eines Clients",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), metavar="DATEI",
                        help=f"Serverkonfiguration (Vorgabe: {DEFAULT_CONFIG})")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="BEFEHL")

    p = sub.add_parser("create", help="Token ausgeben")
    p.add_argument("--user", required=True,
                   help="Benutzername, für den der Client Zertifikate bekommt")
    p.add_argument("--host", default="",
                   help="Hostname festschreiben (Vorgabe: der Client nennt ihn)")
    p.add_argument("--principals", default="", metavar="A,B,C",
                   help="erlaubte Prinzipale (Vorgabe: alle aus principals.conf)")
    p.add_argument("--templates", default="", metavar="A,B",
                   help="erlaubte Vorlagen (Vorgabe: alle)")
    p.add_argument("--max-validity", default="", metavar="SPEC",
                   help="Obergrenze der Gültigkeit, z. B. +1h")
    p.add_argument("--valid", default="24h", metavar="DAUER",
                   help="Laufzeit des Tokens selbst, z. B. 90m, 24h, 7d")
    p.add_argument("--uses", type=int, default=1,
                   help="Anzahl der Verwendungen (Vorgabe: 1)")
    p.add_argument("--comment", default="", help="Notiz für die Übersicht")

    sub.add_parser("list", help="Tokens auflisten")
    sub.add_parser("purge", help="verbrauchte und abgelaufene Tokens entfernen")

    p = sub.add_parser("revoke", help="Token zurückziehen")
    p.add_argument("token_id", metavar="ID")

    return parser


_HANDLERS = {
    "create": cmd_create,
    "list": cmd_list,
    "revoke": cmd_revoke,
    "purge": cmd_purge,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        return _HANDLERS[args.command](args)
    except CaError as exc:
        return _err(str(exc))
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130
