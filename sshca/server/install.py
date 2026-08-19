"""Installation des Dienstes als systemd-Unit.

Vorgehen wie bei den Migrationsskripten des Projekts: **Trockenlauf ist die
Vorgabe.** Ohne ``--apply`` wird nur aufgeschrieben, was geschehen wuerde. Wer
Dateien unter ``/etc`` anlegt, soll sie vorher gelesen haben.

Angelegt werden:

* Systembenutzer und -gruppe (ohne Login-Shell, ohne Home im ueblichen Sinn)
* ``/etc/ssh-ca-server/server.conf`` aus der Vorlage — nur wenn nicht vorhanden
* das Zustandsverzeichnis des Dienstes
* ``/etc/systemd/system/ssh-ca-server.service``
* optional ``ssh-ca-agent.service``, damit der CA-Schluessel im Agent liegen
  kann statt als Passphrase auf der Platte
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

from ..config import CaError
from .config import CONFIG_TEMPLATE, DEFAULT_CONFIG, DEFAULT_STATE_DIR

DEFAULT_SERVICE_USER = "ssh-ca"
UNIT_PATH = Path("/etc/systemd/system/ssh-ca-server.service")
AGENT_UNIT_PATH = Path("/etc/systemd/system/ssh-ca-agent.service")
AGENT_SOCKET = Path("/run/ssh-ca/agent.sock")

UNIT_TEMPLATE = """\
[Unit]
Description=SSH-CA Manager — Signierdienst
Documentation=file://{docs}
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User={user}
Group={user}
ExecStart={python} {program} run --config {config}
Restart=on-failure
RestartSec=5s
UMask=0077

# Der CA-Schlüssel liegt im Agent (signing = agent). Für
# signing = passphrase-file kann die Zeile entfallen.
Environment=SSH_AUTH_SOCK={agent_socket}

# Härtung. Der Dienst braucht Netz, sein Zustandsverzeichnis und das
# CA-Datenverzeichnis — sonst nichts.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectProc=invisible
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths={writable}

[Install]
WantedBy=multi-user.target
"""

AGENT_UNIT_TEMPLATE = """\
[Unit]
Description=ssh-agent für den SSH-CA-Signierdienst
Before=ssh-ca-server.service

[Service]
Type=forking
User={user}
Group={user}
RuntimeDirectory=ssh-ca
RuntimeDirectoryMode=0700
Environment=SSH_AUTH_SOCK={agent_socket}
ExecStart=/usr/bin/ssh-agent -a {agent_socket}
ExecStop=/usr/bin/ssh-agent -k
Restart=on-failure
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


class Plan:
    """Sammelt Schritte, damit der Trockenlauf dasselbe zeigt wie der Lauf."""

    def __init__(self, apply: bool) -> None:
        self.apply = apply
        self.steps: list[str] = []
        self._directories: set[Path] = set()

    def note(self, text: str) -> None:
        self.steps.append(text)
        print(("  " if self.apply else "  [Trockenlauf] ") + text)

    def run(self, argv: list[str]) -> None:
        self.note("ausführen: " + " ".join(argv))
        if self.apply:
            subprocess.run(argv, check=True)

    def write(self, path: Path, content: str, mode: int) -> None:
        if path.exists():
            self.note(f"vorhanden, bleibt unverändert: {path}")
            return
        self.note(f"anlegen: {path} (Modus {mode:04o})")
        if self.apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            path.chmod(mode)

    def mkdir(self, path: Path, mode: int, owner: str | None = None) -> None:
        # Ein Pfad kann aus zwei Richtungen kommen (Home des Dienstbenutzers
        # und Zustandsverzeichnis koennen zusammenfallen). Der erste Eintrag
        # gewinnt, damit der Plan keine zwei Modi fuer dasselbe Verzeichnis
        # ausweist.
        if path in self._directories:
            return
        self._directories.add(path)
        self.note(
            f"Verzeichnis: {path} (Modus {mode:04o}, "
            f"Eigentümer {owner or 'root'})"
        )
        if self.apply:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
            if owner:
                entry = pwd.getpwnam(owner)
                os.chown(path, entry.pw_uid, entry.pw_gid)


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def install(
    apply: bool = False,
    service_user: str = DEFAULT_SERVICE_USER,
    config_path: Path = DEFAULT_CONFIG,
    state_dir: Path = DEFAULT_STATE_DIR,
    ca_base: Path | None = None,
    port: int | None = None,
    with_agent_unit: bool = True,
) -> int:
    """Legt Benutzer, Verzeichnisse, Konfiguration und Unit an."""
    if os.geteuid() != 0:
        raise CaError(
            "Die Installation legt Dateien unter /etc an und braucht root. "
            "Bitte mit sudo aufrufen."
        )
    program = (Path(__file__).resolve().parents[2] / "ssh-ca-server.py").resolve()
    if not program.is_file():
        raise CaError(f"Startskript nicht gefunden: {program}")
    docs = program.parent / "docs" / "SERVER-CLIENT.md"
    ca_base = Path(ca_base) if ca_base else Path(f"/var/lib/{service_user}/.ssh-ca")

    from ..protocol import DEFAULT_PORT

    plan = Plan(apply)
    print()
    print("SSH-CA-Signierdienst einrichten")
    print(f"  Dienstbenutzer:  {service_user}")
    print(f"  Konfiguration:   {config_path}")
    print(f"  Zustand:         {state_dir}")
    print(f"  CA-Daten:        {ca_base}")
    print(f"  Startskript:     {program}")
    print()

    if _user_exists(service_user):
        plan.note(f"Systembenutzer '{service_user}' existiert bereits")
    else:
        useradd = shutil.which("useradd")
        if useradd is None:
            raise CaError("useradd nicht gefunden — Benutzer bitte selbst anlegen.")
        plan.run(
            [
                useradd, "--system", "--create-home",
                "--home-dir", str(ca_base.parent),
                "--shell", "/usr/sbin/nologin",
                service_user,
            ]
        )

    plan.mkdir(ca_base.parent, 0o750, service_user)
    plan.mkdir(ca_base, 0o700, service_user)
    plan.mkdir(state_dir, 0o700, service_user)
    plan.mkdir(config_path.parent, 0o755, None)

    plan.write(
        config_path,
        CONFIG_TEMPLATE.format(
            port=port or DEFAULT_PORT, ca_base=ca_base, state_dir=state_dir
        ),
        0o644,
    )
    plan.write(
        UNIT_PATH,
        UNIT_TEMPLATE.format(
            user=service_user,
            python=sys.executable,
            program=program,
            config=config_path,
            docs=docs,
            agent_socket=AGENT_SOCKET,
            writable=f"{state_dir} {ca_base}",
        ),
        0o644,
    )
    if with_agent_unit:
        plan.write(
            AGENT_UNIT_PATH,
            AGENT_UNIT_TEMPLATE.format(
                user=service_user, agent_socket=AGENT_SOCKET
            ),
            0o644,
        )

    systemctl = shutil.which("systemctl")
    if systemctl:
        plan.run([systemctl, "daemon-reload"])
    else:
        plan.note("systemctl nicht gefunden — daemon-reload bitte selbst ausführen")

    print()
    if not apply:
        print("Nichts geändert. Für die Ausführung: ssh-ca-server install --apply")
        return 0

    print("Eingerichtet. Es fehlen noch die Schritte, die niemand raten kann:")
    print()
    print(f"  1) Serverzertifikat aus der PKI eintragen in {config_path}")
    print("     (tls_cert, tls_key — der Key darf nur für den Dienst lesbar sein)")
    print("  2) CA anlegen oder einspielen, als Dienstbenutzer:")
    print(f"       sudo -u {service_user} env SSH_CA_HOME={ca_base} \\")
    print("         ssh-ca-manager init")
    print("  3) CA-Schlüssel für den Dienst verfügbar machen:")
    if with_agent_unit:
        print("       sudo systemctl enable --now ssh-ca-agent.service")
        print(f"       sudo -u {service_user} env SSH_AUTH_SOCK={AGENT_SOCKET} \\")
        print(f"         ssh-add {ca_base}/ca/ca_key")
        print("     (oder in server.conf auf signing = passphrase-file umstellen)")
    print("  4) Dienst prüfen und starten:")
    print(f"       ssh-ca-server check --config {config_path}")
    print("       sudo systemctl enable --now ssh-ca-server.service")
    print("  5) Erstes Token ausgeben:")
    print("       sudo ssh-ca-enroll-token create --user dennis --valid 24h")
    print()
    return 0
