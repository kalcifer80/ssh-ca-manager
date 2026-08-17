"""Datenmodell: Zertifikatsinformationen und deren Status.

Der Parser liest die Ausgabe von ``ssh-keygen -L -f <cert>``:

    /pfad/host_user_ed25519-cert.pub:
            Type: ssh-ed25519-cert-v01@openssh.com user certificate
            Public key: ED25519-CERT SHA256:…
            Signing CA: ED25519 SHA256:… (using ssh-ed25519)
            Key ID: "dennis-20260816120000"
            Serial: 123456789
            Valid: from 2026-08-16T12:00:00 to 2026-08-16T13:00:00
            Principals:
                    dennis
                    dennis@jump
            Critical Options: (none)
            Extensions:
                    permit-pty
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


class Status(enum.Enum):
    """Lebenszyklus-Status eines Zertifikats."""

    VALID = "gültig"
    EXPIRING = "läuft bald ab"
    EXPIRED = "abgelaufen"
    FUTURE = "noch nicht gültig"
    REVOKED = "widerrufen"
    STORED = "ausgelagert"
    UNKNOWN = "unbekannt"

    @property
    def color(self) -> str:
        return {
            Status.VALID: "#79d99a",
            Status.EXPIRING: "#eec46a",
            Status.EXPIRED: "#ee8073",
            Status.FUTURE: "#82b5ee",
            Status.REVOKED: "#ee8073",
            Status.STORED: "#c49aec",
            Status.UNKNOWN: "#9aa0aa",
        }[self]


def format_duration(seconds: float) -> str:
    """Sekunden als '45 s' / '12 min' / '3 h 15 min' / '5 d 4 h'."""
    s = int(max(0, seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        rest = (s % 3600) // 60
        return f"{s // 3600} h {rest} min" if rest else f"{s // 3600} h"
    rest = (s % 86400) // 3600
    return f"{s // 86400} d {rest} h" if rest else f"{s // 86400} d"


@dataclass
class CertInfo:
    """Ein Zertifikat samt zugehoerigem Schluesselmaterial."""

    cert_path: Path
    user: str = ""
    host: str = ""
    key_id: str = "-"
    serial: str = "-"
    cert_type: str = "-"
    principals: list[str] = field(default_factory=list)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    forever: bool = False
    pubkey_fp: str = "-"
    ca_fp: str = "-"
    extensions: dict[str, str] = field(default_factory=dict)
    critical_options: dict[str, str] = field(default_factory=dict)
    revoked: bool = False
    stored: bool = False
    raw: str = ""
    parse_error: str = ""

    # -- abgeleitete Pfade ------------------------------------------------
    @property
    def key_path(self) -> Path:
        return Path(str(self.cert_path).removesuffix("-cert.pub"))

    @property
    def pub_path(self) -> Path:
        return Path(str(self.key_path) + ".pub")

    @property
    def has_private_key(self) -> bool:
        return self.key_path.is_file()

    # -- Status -----------------------------------------------------------
    def status(self, now: datetime | None = None) -> Status:
        if self.parse_error:
            return Status.UNKNOWN
        if self.stored:
            return Status.STORED
        if self.revoked:
            return Status.REVOKED
        if self.forever:
            return Status.VALID
        if self.valid_from is None or self.valid_to is None:
            return Status.UNKNOWN
        now = now or datetime.now()
        if now < self.valid_from:
            return Status.FUTURE
        if now >= self.valid_to:
            return Status.EXPIRED
        total = (self.valid_to - self.valid_from).total_seconds()
        left = (self.valid_to - now).total_seconds()
        if total > 0 and left * 4 < total:
            return Status.EXPIRING
        return Status.VALID

    def status_text(self, now: datetime | None = None) -> str:
        st = self.status(now)
        now = now or datetime.now()
        if st in (Status.VALID, Status.EXPIRING) and self.valid_to and not self.forever:
            return f"{st.value} (noch {format_duration((self.valid_to - now).total_seconds())})"
        if st is Status.EXPIRED and self.valid_to:
            return f"{st.value} seit {format_duration((now - self.valid_to).total_seconds())}"
        if st is Status.FUTURE and self.valid_from:
            return f"{st.value} (ab {format_duration((self.valid_from - now).total_seconds())})"
        return st.value

    @property
    def principals_csv(self) -> str:
        return ", ".join(self.principals) if self.principals else "(keine)"

    @property
    def validity_text(self) -> str:
        if self.forever:
            return "unbegrenzt"
        if not self.valid_from or not self.valid_to:
            return "-"
        return (
            f"{self.valid_from:%Y-%m-%d %H:%M} – {self.valid_to:%Y-%m-%d %H:%M}"
        )


_SECTION_RE = re.compile(r"^\s{0,16}([A-Z][A-Za-z ]+):\s*(.*)$")
_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")


def _parse_time(text: str) -> datetime | None:
    match = _TIME_RE.search(text)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def parse_cert_listing(text: str, cert_path: Path) -> CertInfo:
    """Wandelt die Ausgabe von ``ssh-keygen -L`` in ein :class:`CertInfo`."""
    info = CertInfo(cert_path=cert_path, raw=text)
    section: str | None = None

    for line in text.splitlines():
        if not line.strip():
            continue
        match = _SECTION_RE.match(line)
        if match:
            name, value = match.group(1).strip(), match.group(2).strip()
            section = name
            if name == "Type":
                if "user certificate" in value:
                    info.cert_type = "user"
                elif "host certificate" in value:
                    info.cert_type = "host"
                else:
                    info.cert_type = value or "-"
            elif name == "Public key":
                parts = value.split()
                info.pubkey_fp = parts[-1] if parts else "-"
            elif name == "Signing CA":
                for part in value.split():
                    if part.startswith("SHA256:"):
                        info.ca_fp = part
                        break
            elif name == "Key ID":
                info.key_id = value.strip('"') or "-"
            elif name == "Serial":
                info.serial = value or "-"
            elif name == "Valid":
                if value.strip() == "forever":
                    info.forever = True
                else:
                    before, _, after = value.partition(" to ")
                    info.valid_from = _parse_time(before)
                    info.valid_to = _parse_time(after)
            continue

        # Eingerueckte Fortsetzungszeile einer Sektion.
        item = line.strip()
        if section == "Principals" and item != "(none)":
            info.principals.append(item)
        elif section in ("Extensions", "Critical Options") and item != "(none)":
            name, _, value = item.partition(" ")
            target = (
                info.extensions if section == "Extensions" else info.critical_options
            )
            target[name] = value.strip()

    return info


def parse_validity_spec(spec: str, now: datetime | None = None) -> tuple[datetime, datetime] | None:
    """Interpretiert eine ``-V``-Angabe fuer die Vorschau in der Oberflaeche.

    Unterstuetzt werden die haeufigen Faelle ``+1h``, ``+30m``, ``+7d``,
    ``+52w`` und ``always:forever``. Alles andere gibt None zurueck; ssh-keygen
    entscheidet dann selbst, die Vorschau bleibt leer.
    """
    now = now or datetime.now()
    spec = spec.strip()
    if not spec:
        return None
    if spec in ("always:forever", "forever"):
        return None
    match = re.fullmatch(r"\+(\d+)([mhdwMY]?)", spec)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    delta = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
        "M": timedelta(days=30 * amount),
        "Y": timedelta(days=365 * amount),
    }[unit]
    return now, now + delta


@dataclass
class RevokedEntry:
    """Ein ausgelagerter Vorgang unter ``revoked/<user>/<host>/<ts>/``."""

    directory: Path
    user: str = ""
    host: str = ""
    action: str = "-"
    revoked_at: str = "-"
    revoked_by: str = "-"
    reason: str = "-"
    key: str = "-"

    @classmethod
    def from_dir(cls, directory: Path) -> "RevokedEntry":
        entry = cls(directory=directory)
        entry.host = directory.parent.name
        entry.user = directory.parent.parent.name
        info = directory / "revoked.info"
        if info.is_file():
            for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                if hasattr(entry, key.strip()):
                    setattr(entry, key.strip(), value.strip())
        return entry

    @property
    def cert_path(self) -> Path | None:
        for candidate in sorted(self.directory.glob("*-cert.pub")):
            return candidate
        return None
