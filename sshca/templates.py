"""Vorlagen fuer Zertifikate — das Gegenstueck zu XCAs Templates.

Eine Vorlage buendelt Gueltigkeitsdauer, Prinzipalmuster, Extensions und
Critical Options unter einem Namen. In den Prinzipalmustern stehen ``{user}``
und ``{host}`` fuer die Eingaben des jeweiligen Zertifikats.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

#: Extensions, die OpenSSH fuer Benutzerzertifikate kennt.
KNOWN_EXTENSIONS = {
    "permit-pty": "Terminal zuweisen (ohne dies keine interaktive Sitzung)",
    "permit-agent-forwarding": "Weiterreichen des ssh-agent erlauben",
    "permit-port-forwarding": "Port-Weiterleitungen erlauben",
    "permit-X11-forwarding": "X11-Weiterleitung erlauben",
    "permit-user-rc": "~/.ssh/rc auf dem Zielsystem ausführen",
    "no-touch-required": "Bei FIDO-Schlüsseln keine Berührung verlangen",
}

#: Critical Options mit Wert. Werden sie gesetzt, muss der Server sie verstehen.
KNOWN_CRITICAL_OPTIONS = {
    "force-command": "Nur dieses Kommando ausführen, egal was angefordert wird",
    "source-address": "Nur von diesen Adressen/Netzen gültig (kommagetrennt)",
    "verify-required": "Bei FIDO-Schlüsseln PIN oder Biometrie verlangen",
}


@dataclass
class Template:
    name: str
    validity: str = "+1h"
    principal_patterns: list[str] = field(default_factory=lambda: ["{user}", "{user}@{host}"])
    extensions: list[str] = field(default_factory=lambda: ["permit-pty"])
    critical_options: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def principals_for(self, user: str, host: str) -> list[str]:
        seen: dict[str, None] = {}
        for pattern in self.principal_patterns:
            value = pattern.format(user=user, host=host).strip()
            if value:
                seen.setdefault(value, None)
        return list(seen)


DEFAULT_TEMPLATES = [
    Template(
        name="Kurzlebig (1 Stunde)",
        validity="+1h",
        extensions=["permit-pty", "permit-agent-forwarding"],
        description="Standardfall: Zugang für eine Sitzung.",
    ),
    Template(
        name="Arbeitstag (9 Stunden)",
        validity="+9h",
        extensions=["permit-pty", "permit-agent-forwarding", "permit-port-forwarding"],
        description="Ein Zertifikat, das den Arbeitstag überdauert.",
    ),
    Template(
        name="Automatisierung (Ansible)",
        validity="+2h",
        principal_patterns=["{user}", "automation"],
        extensions=[],
        critical_options={},
        description="Ohne Terminal und ohne Weiterleitungen — für Skripte.",
    ),
    Template(
        name="Notfallzugang",
        validity="+30m",
        extensions=["permit-pty"],
        critical_options={"source-address": "172.16.40.0/22"},
        description="Sehr kurz gültig und auf das interne Netz begrenzt.",
    ),
]


class TemplateStore:
    """Laedt und speichert Vorlagen als JSON."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self) -> list[Template]:
        if not self.path.is_file():
            self.save(DEFAULT_TEMPLATES)
            return list(DEFAULT_TEMPLATES)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return list(DEFAULT_TEMPLATES)
        result = []
        for item in raw:
            try:
                result.append(Template(**item))
            except TypeError:
                continue
        return result or list(DEFAULT_TEMPLATES)

    def save(self, templates: list[Template]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([asdict(t) for t in templates], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.path.chmod(0o600)
