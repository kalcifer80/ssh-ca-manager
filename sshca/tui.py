"""Interaktiver Kommandozeilenmodus.

Startet, wenn ssh-ca-manager ohne Befehl auf einem Terminal aufgerufen wird.
Menuestruktur und gefuehrte Abfragen ueber derselben Kernschicht wie GUI und
Subcommand-CLI; das Farbschema entspricht der Oberflaeche (Bernstein auf
dunklem Grund).

Ein- und Ausgabe laufen ueber die Hooks cli._getpass und cli._input, damit
die Tests dieselben Fluesse ohne Terminal fahren koennen. Farben und das
Loeschen des Bildschirms gibt es nur, wenn stdout ein Terminal ist.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path

from . import cli
from .ca import CaError, CertificateAuthority, CertRequest
from .config import APP_VERSION, DEPLOYMENT_HELP, Paths
from .keygen import SshKeygenError
from .model import CertInfo, Status, parse_validity_spec
from .templates import KNOWN_CRITICAL_OPTIONS, KNOWN_EXTENSIONS, TemplateStore

# ------------------------------------------------------------- Darstellung
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

ACCENT = "38;5;215"     # Bernstein, wie die GUI
MUTED = "38;5;245"
FRAME = "38;5;240"
OK = "38;5;114"
WARN = "38;5;179"
BAD = "38;5;174"

WIDTH = 78

_STATUS_TUI = {
    Status.VALID: OK,
    Status.EXPIRING: WARN,
    Status.EXPIRED: BAD,
    Status.FUTURE: "38;5;110",
    Status.REVOKED: BAD,
    Status.STORED: "38;5;140",
    Status.UNKNOWN: MUTED,
}

BANNER = r"""
  ███████╗███████╗██╗  ██╗       ██████╗ █████╗
  ██╔════╝██╔════╝██║  ██║      ██╔════╝██╔══██╗
  ███████╗███████╗███████║█████╗██║     ███████║
  ╚════██║╚════██║██╔══██║╚════╝██║     ██╔══██║
  ███████║███████║██║  ██║      ╚██████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═╝       ╚═════╝╚═╝  ╚═╝
"""


def _tty() -> bool:
    return sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() else text


def _visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


def _clear() -> None:
    if _tty():
        print("\033[2J\033[H", end="")


def _rule(title: str = "") -> None:
    if title:
        line = f"── {title} " + "─" * max(0, WIDTH - len(title) - 4)
    else:
        line = "─" * WIDTH
    print(_c(FRAME, line))


def _panel(title: str, lines: list[str]) -> None:
    inner = WIDTH - 4
    wrapped: list[str] = []
    for line in lines:
        if _visible_len(line) <= inner:
            wrapped.append(line)
        elif "\033[" in line:
            # Farbige Zeilen nicht zerschneiden — kuerzen.
            plain = _ANSI_RE.sub("", line)
            wrapped.append(plain[: inner - 1] + "…")
        else:
            # Lange Pfade umbrechen; Folgezeilen unter dem Wert einruecken.
            wrapped.append(line[:inner])
            rest = line[inner:]
            while rest:
                wrapped.append("    " + rest[: inner - 4])
                rest = rest[inner - 4:]
    print(_c(FRAME, "┌─ ") + _c(ACCENT, title) + " "
          + _c(FRAME, "─" * max(0, WIDTH - len(title) - 5) + "┐"))
    for line in wrapped:
        print(_c(FRAME, "│ ") + _pad(line, inner) + _c(FRAME, " │"))
    print(_c(FRAME, "└" + "─" * (WIDTH - 2) + "┘"))


def _status(cert: CertInfo) -> str:
    return _c(_STATUS_TUI[cert.status()], cert.status_text())


def _ok(text: str) -> None:
    print(_c(OK, f"✓ {text}"))


def _warn(text: str) -> None:
    print(_c(WARN, f"! {text}"))


def _bad(text: str) -> None:
    print(_c(BAD, f"✗ {text}"))


def _pause() -> None:
    if _tty():
        cli._input(_c(MUTED, "\nWeiter mit Enter … "))


# --------------------------------------------------------------- Eingaben
def _ask(label: str, default: str = "", validate=None) -> str:
    """Fragt einen Wert ab; leere Eingabe uebernimmt die Vorgabe."""
    hint = _c(MUTED, f" [{default}]") if default else ""
    while True:
        raw = cli._input(_c(ACCENT, f"  {label}{hint}: ")).strip()
        value = raw or default
        if validate:
            problem = validate(value)
            if problem:
                _warn(problem)
                continue
        return value


def _ask_yesno(label: str, default: bool = False) -> bool:
    hint = "J/n" if default else "j/N"
    raw = cli._input(_c(ACCENT, f"  {label} [{hint}]: ")).strip().lower()
    if not raw:
        return default
    return raw in ("j", "ja", "y", "yes")


def _validate_name(value: str) -> str | None:
    if not value:
        return "Eingabe darf nicht leer sein."
    if any(ch.isspace() for ch in value) or "/" in value:
        return "Keine Leerzeichen und kein '/' erlaubt."
    return None


def _pick(title: str, entries: list[str], default: int = 1) -> int | None:
    """Nummerierte Auswahl; Rueckgabe ist der Index (0-basiert) oder None."""
    print(_c(MUTED, f"  {title}"))
    for number, entry in enumerate(entries, 1):
        marker = _c(ACCENT, f"{number:>3}") if number == default else f"{number:>3}"
        print(f"  {marker}  {entry}")
    raw = cli._input(
        _c(ACCENT, f"  Auswahl [{default}] (0 = zurück): ")
    ).strip()
    if not raw:
        return default - 1
    if not raw.isdigit():
        return None
    choice = int(raw)
    if choice == 0 or choice > len(entries):
        return None
    return choice - 1


def _pick_cert(ca: CertificateAuthority, allowed=None) -> CertInfo | None:
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    if allowed is not None:
        certs = [c for c in certs if c.status() in allowed]
    if not certs:
        _warn("Keine passenden Zertifikate vorhanden.")
        return None
    certs.sort(key=lambda c: (c.user, c.host))
    entries = [
        f"{_pad(c.user + '@' + c.host, 28)} {_pad(c.principals_csv[:24], 25)} "
        f"{_status(c)}"
        for c in certs
    ]
    index = _pick("Zertifikat wählen:", entries)
    if index is None:
        return None
    return certs[index]


# ----------------------------------------------------------------- Ansichten
def _cert_table(certs: list[CertInfo]) -> None:
    if not certs:
        print(_c(MUTED, "  Noch keine Zertifikate."))
        return
    header = (_pad("BENUTZER", 12) + " " + _pad("HOST", 18) + " "
              + _pad("GÜLTIG BIS", 17) + " " + _pad("PRINZIPALE", 26) + " STATUS")
    print("  " + _c(MUTED, header))
    for cert in sorted(certs, key=lambda c: (c.user, c.host)):
        until = ("unbegrenzt" if cert.forever
                 else f"{cert.valid_to:%Y-%m-%d %H:%M}" if cert.valid_to else "-")
        principals = cert.principals_csv
        if len(principals) > 26:
            principals = principals[:25] + "…"
        print("  " + _pad(cert.user[:12], 12) + " " + _pad(cert.host[:18], 18)
              + " " + _pad(until, 17) + " " + _pad(principals, 26)
              + " " + _status(cert))


def _cert_details(cert: CertInfo) -> None:
    lines = [
        f"Status:         {_status(cert)}",
        f"Key ID:         {cert.key_id}",
        f"Seriennummer:   {cert.serial}",
        f"Gültigkeit:     {cert.validity_text}",
        f"Prinzipale:     {cert.principals_csv}",
        f"Extensions:     {', '.join(sorted(cert.extensions)) or '(keine)'}",
    ]
    if cert.critical_options:
        joined = ", ".join(f"{k}={v}" if v else k
                           for k, v in cert.critical_options.items())
        lines.append(f"Critical:       {joined}")
    lines += [
        f"Fingerprint:    {cert.pubkey_fp}",
        f"Zertifikat:     {cert.cert_path}",
        f"Privater Key:   {cert.key_path if cert.has_private_key else 'fehlt'}",
    ]
    _panel(f"Zertifikat {cert.user}@{cert.host}", lines)


# ------------------------------------------------------------------- Flüsse
def _flow_list(ca: CertificateAuthority) -> None:
    _rule("Zertifikate")
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    _cert_table(certs)


def _collect_principals(template, user: str, host: str,
                        conf: list[str]) -> list[str]:
    principals = template.principals_for(user, host)
    while True:
        print(_c(MUTED, "  Prinzipale: ") + ", ".join(principals))
        prompt = "+name hinzufügen · -name entfernen"
        if conf:
            prompt += f" · a = alle aus principals.conf ({len(conf)})"
        prompt += " · Enter = weiter"
        raw = cli._input(_c(ACCENT, f"  {prompt}: ")).strip()
        if not raw:
            if principals:
                return principals
            _warn("Mindestens ein Prinzipal wird benötigt.")
            continue
        if raw == "a" and conf:
            for value in conf:
                if value not in principals:
                    principals.append(value)
        elif raw.startswith("+") and raw[1:].strip():
            value = raw[1:].strip()
            if value not in principals:
                principals.append(value)
        elif raw.startswith("-") and raw[1:].strip():
            value = raw[1:].strip()
            if value in principals:
                principals.remove(value)
        else:
            _warn("Eingabe nicht verstanden.")


def _collect_extensions(template) -> tuple[list[str], dict[str, str]]:
    extensions = list(template.extensions)
    critical = dict(template.critical_options)
    shown = ", ".join(extensions) or "(keine)"
    print(_c(MUTED, f"  Extensions laut Vorlage: {shown}"))
    if _ask_yesno("Extensions anpassen?", default=False):
        extensions = []
        for name, description in KNOWN_EXTENSIONS.items():
            if _ask_yesno(f"{name} — {description}",
                          default=name in template.extensions):
                extensions.append(name)
    if _ask_yesno("Critical Options setzen (force-command, source-address …)?",
                  default=bool(critical)):
        value = _ask("force-command",
                     default=critical.get("force-command", ""))
        if value:
            critical["force-command"] = value
        else:
            critical.pop("force-command", None)
        value = _ask("source-address",
                     default=critical.get("source-address", ""))
        if value:
            critical["source-address"] = value
        else:
            critical.pop("source-address", None)
        if _ask_yesno(KNOWN_CRITICAL_OPTIONS["verify-required"],
                      default="verify-required" in critical):
            critical["verify-required"] = ""
        else:
            critical.pop("verify-required", None)
    return extensions, critical


def _collect_key_passphrase() -> str:
    while True:
        first = cli._getpass("  Passphrase für den neuen Schlüssel (leer = ohne): ")
        if not first:
            if _ask_yesno("Wirklich ohne Passphrase (nur für Automatisierung)?",
                          default=False):
                return ""
            continue
        if len(first) < 8:
            _warn("Die Passphrase sollte mindestens 8 Zeichen haben.")
            continue
        if cli._getpass("  Wiederholen: ") != first:
            _warn("Die Eingaben stimmen nicht überein.")
            continue
        return first


def _collect_signing(ca: CertificateAuthority) -> tuple[bool, str]:
    if ca.ca_in_agent():
        print(_c(OK, "  Signatur über den ssh-agent (CA-Schlüssel ist geladen)."))
        return True, ""
    return False, cli._getpass("  CA-Passphrase: ")


def _flow_create(ca: CertificateAuthority,
                 fixed: CertInfo | None = None) -> None:
    _rule("Zertifikat erneuern" if fixed else "Neues Zertifikat")
    if fixed:
        user, host = fixed.user, fixed.host
        print(f"  Benutzer/Host: {_c(ACCENT, f'{user}@{host}')}")
    else:
        user = _ask("Benutzer", validate=_validate_name)
        host = _ask("Zielhost", validate=_validate_name)
        if ca.paths.key_path(user, host).exists():
            _bad(f"Es gibt bereits einen Schlüssel für {user}@{host} — "
                 "bitte „Erneuern“ verwenden.")
            return

    templates = TemplateStore(ca.paths.templates_file).load()
    entries = [
        f"{_pad(t.name, 26)} {_pad(t.validity, 6)} "
        + _c(MUTED, ", ".join(t.extensions) or "(keine Extensions)")
        for t in templates
    ]
    index = _pick("Vorlage wählen:", entries)
    if index is None:
        print("  Abgebrochen.")
        return
    template = templates[index]

    def check_validity(value: str) -> str | None:
        return None if value else "Gültigkeit wird benötigt."

    validity = _ask("Gültigkeit", default=template.validity,
                    validate=check_validity)
    span = parse_validity_spec(validity)
    if span:
        print(_c(MUTED, f"  → gültig bis {span[1]:%Y-%m-%d %H:%M}"))

    principals = _collect_principals(
        template, user, host, ca.paths.read_principals_conf()
    )
    extensions, critical = _collect_extensions(template)
    key_pass = _collect_key_passphrase()
    use_agent, ca_pass = _collect_signing(ca)

    summary = [
        f"Benutzer/Host:  {user}@{host}",
        f"Gültigkeit:     {validity}",
        f"Prinzipale:     {', '.join(principals)}",
        f"Extensions:     {', '.join(extensions) or '(keine)'}",
    ]
    if critical:
        summary.append("Critical:       " + ", ".join(
            f"{k}={v}" if v else k for k, v in critical.items()))
    summary.append("Schlüssel:      "
                   + ("mit Passphrase" if key_pass else "OHNE Passphrase"))
    summary.append("Signatur:       "
                   + ("ssh-agent" if use_agent else "CA-Passphrase"))
    _panel("Zusammenfassung", summary)
    if not _ask_yesno("Zertifikat jetzt erstellen?", default=True):
        print("  Abgebrochen.")
        return

    request = CertRequest(
        user=user, host=host, principals=principals, validity=validity,
        extensions=extensions, critical_options=critical,
        key_passphrase=key_pass, ca_passphrase=ca_pass, use_agent=use_agent,
    )
    if fixed:
        cert = ca.renew_certificate(fixed, request)
        _ok(f"Zertifikat erneuert: {cert.user}@{cert.host}")
    else:
        cert = ca.create_certificate(request)
        _ok(f"Zertifikat erstellt: {cert.user}@{cert.host}")
    _cert_details(cert)
    principal = cert.principals[0] if cert.principals else cert.user
    print(_c(MUTED, "  Anmeldung:"))
    print(f"    ssh -i {cert.key_path} {principal}@{cert.host}")


def _flow_show(ca: CertificateAuthority) -> None:
    _rule("Details")
    cert = _pick_cert(ca)
    if cert is None:
        return
    _cert_details(cert)
    if _ask_yesno("Rohausgabe von ssh-keygen -L anzeigen?", default=False):
        print(cert.raw.rstrip())


def _flow_renew(ca: CertificateAuthority) -> None:
    _rule("Erneuern")
    cert = _pick_cert(ca)
    if cert is None:
        return
    if not _ask_yesno(
        f"Schlüssel und Zertifikat für {cert.user}@{cert.host} neu erzeugen? "
        "Das bisherige Material wandert nach archive/",
        default=False,
    ):
        print("  Abgebrochen.")
        return
    _flow_create(ca, fixed=cert)


def _flow_revoke(ca: CertificateAuthority) -> None:
    _rule("Widerrufen / Sperren")
    cert = _pick_cert(ca)
    if cert is None:
        return
    index = _pick("Art des Vorgangs:", [
        "widerrufen — gilt nicht mehr",
        "gesperrt — Material kompromittiert",
    ])
    if index is None:
        print("  Abgebrochen.")
        return
    action = "gesperrt" if index == 1 else "widerrufen"
    reason = _ask("Grund", default="(kein Grund angegeben)")
    _warn("Der Vorgang ist ENDGÜLTIG — die KRL kennt keine Rücknahme.")
    if not _ask_yesno(f"{cert.user}@{cert.host} wirklich {action[:-1]}en?",
                      default=False):
        print("  Abgebrochen.")
        return
    use_agent, ca_pass = _collect_signing(ca)
    store = ca.revoke(cert, reason, action, ca_pass, use_agent)
    _ok(f"{action}: {cert.user}@{cert.host}")
    print(_c(MUTED, f"  Material ausgelagert nach: {store}"))
    print(_c(WARN, "  KRL auf den Zielsystemen neu hinterlegen: ")
          + str(ca.paths.krl))


def _flow_delete(ca: CertificateAuthority) -> None:
    _rule("Ungültiges löschen")
    cert = _pick_cert(ca, allowed=(Status.EXPIRED, Status.REVOKED))
    if cert is None:
        return
    if not _ask_yesno(
        f"Schlüssel, Public Key und Zertifikat für {cert.user}@{cert.host} "
        f"({cert.status_text()}) endgültig löschen — einschließlich archive/?",
        default=False,
    ):
        print("  Abgebrochen.")
        return
    ca.delete_certificate(cert)
    _ok(f"Gelöscht: {cert.user}@{cert.host}")


def _flow_export(ca: CertificateAuthority) -> None:
    _rule("Gültige exportieren")
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    valid = [c for c in certs if c.status() in (Status.VALID, Status.EXPIRING)]
    if not valid:
        _warn("Es gibt derzeit keine gültigen Zertifikate.")
        return
    index = _pick("Umfang:", [
        f"Alle gültigen ({len(valid)})",
        "Nur ein bestimmtes Zertifikat",
    ])
    if index is None:
        print("  Abgebrochen.")
        return
    if index == 1:
        cert = _pick_cert(ca, allowed=(Status.VALID, Status.EXPIRING))
        if cert is None:
            return
        to_export = [cert]
        default_name = f"{cert.host}_{cert.user}.tar.gz"
    else:
        to_export = valid
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_name = f"ssh-ca-export-{stamp}.tar.gz"
    destination = _ask("Zieldatei", default=str(Path.home() / default_name))
    path, count = ca.export_certificates(to_export, Path(destination))
    _ok(f"{count} Zertifikat(e) exportiert: {path}")


def _flow_revoked(ca: CertificateAuthority) -> None:
    _rule("Widerrufene / ausgelagerte Vorgänge")
    entries = list(ca.iter_revoked_entries())
    if not entries:
        print(_c(MUTED, "  Keine Vorgänge."))
        return
    print("  " + _c(MUTED, _pad("ART", 12) + " " + _pad("BENUTZER@HOST", 26)
                    + " " + _pad("ZEITPUNKT", 20) + " GRUND"))
    for entry in entries:
        color = "38;5;140" if entry.action == "gesperrt" else BAD
        print("  " + _pad(_c(color, entry.action), 12 + 11) + " "
              + _pad(f"{entry.user}@{entry.host}", 26) + " "
              + _pad(entry.revoked_at, 20) + " " + entry.reason)


def _flow_purge(ca: CertificateAuthority) -> None:
    _rule("Widerrufsablage löschen")
    entries = list(ca.iter_revoked_entries())
    if not entries:
        _warn("Keine Ablagen vorhanden.")
        return
    listing = [
        f"{_pad(e.user + '@' + e.host, 26)} {_pad(e.directory.name, 16)} "
        f"{e.action}, {e.reason}"
        for e in entries
    ]
    index = _pick("Ablage wählen:", listing)
    if index is None:
        print("  Abgebrochen.")
        return
    entry = entries[index]
    print(_c(MUTED, "  Der KRL-Eintrag bleibt bestehen — das Zertifikat bleibt "
                    "auf den Zielsystemen ungültig."))
    if not _ask_yesno(
        f"Material für {entry.user}@{entry.host} ({entry.directory.name}) "
        "endgültig löschen?",
        default=False,
    ):
        print("  Abgebrochen.")
        return
    ca.delete_revoked_entry(entry)
    _ok(f"Ablage gelöscht: {entry.directory}")


def _flow_ca_status(ca: CertificateAuthority) -> None:
    certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
    revoked = list(ca.iter_revoked_entries())
    agent = _c(OK, " · im ssh-agent geladen") if ca.ca_in_agent() else ""
    krl_state = "vorhanden" if ca.paths.krl.is_file() else "noch nicht angelegt"
    _panel("Certificate Authority", [
        f"Fingerprint:    {ca.ca_fingerprint()}{agent}",
        f"Schlüssel:      {ca.paths.ca_key}",
        f"KRL:            {ca.paths.krl} ({krl_state})",
        f"Zertifikate:    {len(certs)} aktiv, {len(revoked)} widerrufen/ausgelagert",
        f"Datenbasis:     {ca.paths.base}",
    ])


def _flow_pubkey(ca: CertificateAuthority) -> None:
    _rule("CA-Public-Key")
    print("  " + ca.ca_public_key())
    if _ask_yesno("In Datei speichern?", default=False):
        destination = _ask("Zieldatei", default=str(Path.home() / "ca_key.pub"))
        Path(destination).write_text(ca.ca_public_key() + "\n", encoding="utf-8")
        _ok(f"Gespeichert: {destination}")


def _flow_backup(ca: CertificateAuthority) -> None:
    _rule("Sichern")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    default = str(ca.paths.backup_dir / f"ssh-ca-backup-{stamp}.tar.gz")
    destination = _ask("Zieldatei", default=default)
    path = ca.backup(Path(destination))
    _ok(f"Sicherung geschrieben: {path}")


def _flow_restore(ca: CertificateAuthority) -> None:
    _rule("Sicherung einspielen")
    archive = _ask("Archivdatei")
    if not archive:
        return
    if not _ask_yesno("Vorhandene Dateien mit gleichem Namen werden "
                      "überschrieben. Fortfahren?", default=False):
        print("  Abgebrochen.")
        return
    ca.restore(Path(archive))
    _ok("Sicherung eingespielt.")


def _flow_templates(ca: CertificateAuthority) -> None:
    _rule("Vorlagen")
    for template in TemplateStore(ca.paths.templates_file).load():
        lines = [
            f"Gültigkeit:  {template.validity}",
            f"Prinzipale:  {', '.join(template.principal_patterns)}",
            f"Extensions:  {', '.join(template.extensions) or '(keine)'}",
        ]
        if template.critical_options:
            lines.append("Critical:    " + ", ".join(
                f"{k}={v}" if v else k
                for k, v in template.critical_options.items()))
        if template.description:
            lines.append(_c(MUTED, template.description))
        _panel(template.name, lines)


def _flow_log(ca: CertificateAuthority) -> None:
    _rule("Log")
    text = ca.read_log(30)
    print(text if text else "  Es gibt noch keine Logeinträge.")


def _flow_init(ca: CertificateAuthority) -> None:
    _rule("Neue CA anlegen")
    print(_c(MUTED, "  Der CA-Schlüssel ist die Wurzel des Vertrauens: wer ihn "
                    "besitzt, kann sich auf allen Zielsystemen anmelden."))
    comment = _ask("Kommentar", default="ssh-ca")
    while True:
        first = cli._getpass("  Passphrase für den CA-Schlüssel: ")
        if len(first) < 8:
            _warn("Die Passphrase sollte mindestens 8 Zeichen haben.")
            continue
        if cli._getpass("  Wiederholen: ") != first:
            _warn("Die Eingaben stimmen nicht überein.")
            continue
        break
    ca.init_ca(first, comment)
    _ok(f"CA erstellt: {ca.ca_fingerprint()}")
    print(_c(MUTED, f"  Public Key: {ca.paths.ca_pub}"))


def _flow_import(ca: CertificateAuthority) -> None:
    _rule("Bestehende CA importieren")
    keyfile = _ask("Pfad zum privaten CA-Schlüssel")
    if not keyfile:
        return
    passphrase = cli._getpass(
        "  Passphrase (leer lassen, falls eine .pub-Datei daneben liegt): "
    )
    ca.import_ca(Path(keyfile), passphrase)
    _ok(f"CA importiert: {ca.ca_fingerprint()}")


def _flow_deploy(ca: CertificateAuthority) -> None:
    print(DEPLOYMENT_HELP.format(
        ca_pub=ca.paths.ca_pub, krl=ca.paths.krl, base=ca.paths.base
    ))


# --------------------------------------------------------------------- Menü
_MENU_CERT = [
    ("1", "Zertifikate auflisten", _flow_list),
    ("2", "Neues Zertifikat", _flow_create),
    ("3", "Details anzeigen", _flow_show),
    ("4", "Erneuern", _flow_renew),
    ("5", "Widerrufen / Sperren", _flow_revoke),
    ("6", "Ungültiges löschen", _flow_delete),
    ("7", "Gültige exportieren (tar.gz)", _flow_export),
]
_MENU_REVOKED = [
    ("8", "Vorgänge auflisten", _flow_revoked),
    ("9", "Ablage löschen", _flow_purge),
]
_MENU_CA = [
    ("c", "CA-Status", _flow_ca_status),
    ("p", "Public Key anzeigen/speichern", _flow_pubkey),
    ("d", "Deployment-Anleitung", _flow_deploy),
    ("t", "Vorlagen anzeigen", _flow_templates),
]
_MENU_MAINT = [
    ("b", "Sichern", _flow_backup),
    ("r", "Sicherung einspielen", _flow_restore),
    ("l", "Log anzeigen", _flow_log),
]
_MENU_NO_CA = [
    ("i", "Neue CA anlegen", _flow_init),
    ("m", "Bestehende CA importieren", _flow_import),
]


def _print_menu_group(title: str, items) -> None:
    _rule(title)
    for key, label, _ in items:
        print(f"   {_c(ACCENT, key)}  {label}")


def _render_home(ca: CertificateAuthority) -> dict:
    _clear()
    print(_c(ACCENT, BANNER))
    print(_c(MUTED, f"  Certificate Manager {APP_VERSION} · {ca.paths.base}"))
    print()

    actions: dict = {}
    if ca.exists():
        certs = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
        revoked = list(ca.iter_revoked_entries())
        counts: dict[Status, int] = {}
        for cert in certs:
            counts[cert.status()] = counts.get(cert.status(), 0) + 1
        parts = [f"CA {ca.ca_fingerprint()[:27]}…"]
        if ca.ca_in_agent():
            parts.append(_c(OK, "Agent ✓"))
        for status in (Status.VALID, Status.EXPIRING, Status.EXPIRED):
            if counts.get(status):
                parts.append(_c(_STATUS_TUI[status],
                                f"{counts[status]} {status.value}"))
        parts.append(f"{len(revoked)} widerrufen/ausgelagert")
        print("  " + _c(MUTED, " · ").join(parts))
        print()
        for title, items in (("Zertifikate", _MENU_CERT),
                             ("Widerrufen", _MENU_REVOKED),
                             ("CA", _MENU_CA),
                             ("Wartung", _MENU_MAINT)):
            _print_menu_group(title, items)
            for key, _, handler in items:
                actions[key] = handler
    else:
        _warn("Noch keine CA vorhanden — zuerst anlegen oder importieren.")
        print()
        for title, items in (("Einrichtung", _MENU_NO_CA),
                             ("Wartung", (_MENU_MAINT[1], _MENU_MAINT[2]))):
            _print_menu_group(title, items)
            for key, _, handler in items:
                actions[key] = handler

    _rule()
    print(f"   {_c(ACCENT, 'q')}  Beenden"
          + _c(MUTED, "   ·   Skripting: ssh-ca-manager --help"))
    return actions


def run_menu(base: Path | None = None) -> int:
    ca = CertificateAuthority(Paths(base))
    while True:
        actions = _render_home(ca)
        try:
            choice = cli._input(_c(ACCENT, "\n  Auswahl: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("q", "quit", "exit", "0"):
            return 0
        handler = actions.get(choice)
        if handler is None:
            continue
        print()
        try:
            handler(ca)
        except (CaError, SshKeygenError) as exc:
            _bad(str(exc))
        except (EOFError, KeyboardInterrupt):
            print("\n  Abgebrochen.")
        _pause()
