"""Kernschicht der Anwendung.

Alle Operationen sind nicht-interaktiv: sie nehmen Werte entgegen und liefern
Ergebnisse zurueck. Es gibt hier keine Ein- oder Ausgabe an den Benutzer — das
ist Aufgabe der Oberflaeche. Damit ist die Schicht auch ohne GUI testbar.
"""

from __future__ import annotations

import os
import secrets
import shutil
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import KDF_ROUNDS, KEY_TYPE, Paths, RESERVED_NAMES
from .keygen import Ssh, SshKeygenError
from .model import CertInfo, RevokedEntry, Status, parse_cert_listing


class CaError(RuntimeError):
    """Fachlicher Fehler, dessen Text direkt anzeigbar ist."""


@dataclass
class CertRequest:
    """Alles, was fuer ein neues Zertifikat gebraucht wird."""

    user: str
    host: str
    principals: list[str]
    validity: str = "+1h"
    extensions: list[str] | None = None
    critical_options: dict[str, str] | None = None
    key_passphrase: str = ""
    ca_passphrase: str = ""
    use_agent: bool = False
    key_id: str = ""

    def validate(self) -> None:
        if not self.user or not self.host:
            raise CaError("Benutzername und Hostname sind erforderlich.")
        for label, value in (("Benutzername", self.user), ("Hostname", self.host)):
            if any(ch.isspace() for ch in value) or "/" in value:
                raise CaError(f"{label} darf keine Leerzeichen und kein '/' enthalten.")
        if self.user in RESERVED_NAMES:
            raise CaError(f"Der Benutzername '{self.user}' ist reserviert.")
        if not self.principals:
            raise CaError("Mindestens ein Prinzipal ist erforderlich.")


class CertificateAuthority:
    """Die SSH-CA auf dieser Maschine."""

    def __init__(self, paths: Paths | None = None, ssh: Ssh | None = None) -> None:
        self.paths = paths or Paths()
        self.ssh = ssh or Ssh()
        self.paths.ensure_layout()

    # ------------------------------------------------------------------ Log
    def log(self, level: str, message: str) -> None:
        """Schreibt in dieselbe Logdatei wie das Bash-Skript."""
        line = (
            f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] [gui] {message}\n"
        )
        with self.paths.log_file.open("a", encoding="utf-8") as handle:
            handle.write(line)
        try:
            self.paths.log_file.chmod(0o600)
        except OSError:
            pass

    def read_log(self, lines: int = 500) -> str:
        if not self.paths.log_file.is_file():
            return ""
        content = self.paths.log_file.read_text(encoding="utf-8", errors="replace")
        return "\n".join(content.splitlines()[-lines:])

    # ------------------------------------------------------------------- CA
    def exists(self) -> bool:
        return self.paths.ca_key.is_file() and self.paths.ca_pub.is_file()

    def require(self) -> None:
        if not self.exists():
            raise CaError(
                "Es ist noch keine CA vorhanden. Lege zuerst eine an oder "
                "importiere eine bestehende."
            )

    def ca_fingerprint(self) -> str:
        if not self.paths.ca_pub.is_file():
            return "-"
        return self.ssh.fingerprint(self.paths.ca_pub)

    def ca_public_key(self) -> str:
        if not self.paths.ca_pub.is_file():
            return ""
        return self.paths.ca_pub.read_text(encoding="utf-8").strip()

    def ca_in_agent(self) -> bool:
        """Liegt der CA-Key im ssh-agent? Dann ist Signieren ohne Passphrase moeglich."""
        fp = self.ca_fingerprint()
        return fp != "-" and fp in self.ssh.agent_fingerprints()

    def init_ca(self, passphrase: str, comment: str = "ssh-ca", overwrite: bool = False) -> None:
        if self.exists() and not overwrite:
            raise CaError("Es existiert bereits eine CA an dieser Stelle.")
        if self.exists():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = self.paths.ca_dir / f"old-{stamp}"
            backup.mkdir(parents=True, exist_ok=True)
            for item in (self.paths.ca_key, self.paths.ca_pub):
                if item.exists():
                    shutil.move(str(item), backup / item.name)
            self.log("WARN", f"Bisherige CA nach {backup} verschoben")

        self.paths.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ssh.run(
            [
                "-t", KEY_TYPE,
                "-a", str(KDF_ROUNDS),
                "-f", str(self.paths.ca_key),
                "-C", comment,
            ],
            passphrases=[passphrase, passphrase],
        )
        self.paths.ca_key.chmod(0o600)
        self.paths.ca_pub.chmod(0o644)
        self.log("OK", f"CA erstellt ({self.ca_fingerprint()})")

    def import_ca(self, private_key: Path, passphrase: str = "") -> None:
        private_key = Path(private_key).expanduser()
        if not private_key.is_file():
            raise CaError(f"Datei nicht gefunden: {private_key}")
        if self.exists():
            raise CaError("Es existiert bereits eine CA. Bitte zuerst sichern und entfernen.")

        self.paths.ca_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(private_key, self.paths.ca_key)
        self.paths.ca_key.chmod(0o600)

        source_pub = private_key.with_suffix(private_key.suffix + ".pub")
        if private_key.with_name(private_key.name + ".pub").is_file():
            source_pub = private_key.with_name(private_key.name + ".pub")
        if source_pub.is_file():
            shutil.copy2(source_pub, self.paths.ca_pub)
        else:
            # Public Key aus dem privaten Schluessel ableiten.
            result = self.ssh.run(
                ["-y", "-f", str(self.paths.ca_key)], passphrases=[passphrase]
            )
            self.paths.ca_pub.write_text(result.stdout, encoding="utf-8")
        self.paths.ca_pub.chmod(0o644)
        self.log("OK", f"CA importiert aus {private_key} ({self.ca_fingerprint()})")

    # -------------------------------------------------------------- Serials
    def next_serial(self) -> int:
        """Seriennummer aus Zufallsanteil und Zaehler — wie im Skript."""
        counter = 1
        if self.paths.serial_file.is_file():
            try:
                counter = int(self.paths.serial_file.read_text().strip() or "1")
            except ValueError:
                counter = 1
        self.paths.serial_file.write_text(f"{counter + 1}\n", encoding="utf-8")
        self.paths.serial_file.chmod(0o600)
        random_part = secrets.token_hex(4)
        return int(f"{random_part}{counter % 65536:04x}", 16)

    # --------------------------------------------------------- Zertifikate
    def create_certificate(self, request: CertRequest) -> CertInfo:
        """Erzeugt Schluessel und signiertes Zertifikat."""
        self.require()
        request.validate()

        host_dir = self.paths.host_dir(request.user, request.host)
        (host_dir / "archive").mkdir(parents=True, exist_ok=True)
        host_dir.chmod(0o700)
        (host_dir / "archive").chmod(0o700)

        key_path = self.paths.key_path(request.user, request.host)
        if key_path.exists():
            raise CaError(
                f"Es gibt bereits einen Schlüssel unter {key_path}. "
                "Für eine neue Gültigkeit bitte 'Erneuern' verwenden."
            )

        first_principal = request.principals[0]
        self.ssh.run(
            [
                "-t", KEY_TYPE,
                "-a", str(KDF_ROUNDS),
                "-f", str(key_path),
                "-C", first_principal,
            ],
            passphrases=[request.key_passphrase, request.key_passphrase],
        )
        key_path.chmod(0o600)
        Path(str(key_path) + ".pub").chmod(0o644)

        try:
            info = self.sign(key_path, request)
        except Exception:
            # Ein unsignierter Schluessel waere nur Ballast: aufraeumen.
            for leftover in (key_path, Path(str(key_path) + ".pub")):
                leftover.unlink(missing_ok=True)
            raise
        self.log(
            "OK",
            f"Zertifikat erstellt: {request.user}@{request.host} "
            f"serial={info.serial} principals={info.principals_csv}",
        )
        return info

    def sign(self, key_path: Path, request: CertRequest) -> CertInfo:
        """Signiert einen vorhandenen Public Key mit der CA."""
        self.require()
        pub_path = Path(str(key_path) + ".pub")
        if not pub_path.is_file():
            raise CaError(f"Public Key nicht gefunden: {pub_path}")

        serial = self.next_serial()
        key_id = request.key_id or (
            f"{request.principals[0]}-{datetime.now():%Y%m%d%H%M%S}"
        )

        args: list[str] = []
        passphrases: list[str] | None
        if request.use_agent:
            # Signieren ueber den Agent: -U sagt ssh-keygen, dass der mit -s
            # angegebene Key ein Public Key ist, dessen privater Teil im Agent
            # liegt. Es wird keine Passphrase abgefragt.
            args += ["-Us", str(self.paths.ca_pub)]
            passphrases = None
        else:
            args += ["-s", str(self.paths.ca_key)]
            passphrases = [request.ca_passphrase]

        args += [
            "-I", key_id,
            "-n", ",".join(request.principals),
            "-V", request.validity,
            "-z", str(serial),
            "-O", "clear",
        ]
        for ext in request.extensions or []:
            args += ["-O", ext]
        for name, value in (request.critical_options or {}).items():
            args += ["-O", f"{name}={value}" if value else name]
        args.append(str(pub_path))

        self.ssh.run(args, passphrases=passphrases)
        cert_path = Path(str(key_path) + "-cert.pub")
        cert_path.chmod(0o644)
        return self.load_certificate(cert_path)

    def renew_certificate(self, cert: CertInfo, request: CertRequest) -> CertInfo:
        """Archiviert das alte Material und erstellt Schluessel und Zertifikat neu."""
        self.require()
        archive = cert.cert_path.parent / "archive"
        archive.mkdir(parents=True, exist_ok=True)
        archive.chmod(0o700)
        # Wie im Skript: nur die jeweils letzte Version aufheben.
        for old in archive.iterdir():
            if old.is_file():
                old.unlink()
        for item in (cert.key_path, cert.pub_path, cert.cert_path):
            if item.is_file():
                shutil.move(str(item), archive / item.name)
        self.log("INFO", f"Altes Material archiviert nach {archive}")
        return self.create_certificate(request)

    # ------------------------------------------------------------- Widerruf
    def is_revoked(self, cert_path: Path) -> bool:
        if not self.paths.krl.is_file():
            return False
        result = self.ssh.run(
            ["-Q", "-f", str(self.paths.krl), str(cert_path)], check=False
        )
        return "REVOKED" in result.stdout or "REVOKED" in result.stderr

    def krl_add(self, cert_path: Path, ca_passphrase: str, use_agent: bool = False) -> None:
        args = ["-k"]
        if self.paths.krl.is_file():
            args.append("-u")
        if use_agent:
            args += ["-Us", str(self.paths.ca_pub)]
            passphrases = None
        else:
            args += ["-s", str(self.paths.ca_key)]
            passphrases = [ca_passphrase]
        args += ["-f", str(self.paths.krl), str(cert_path)]
        self.ssh.run(args, passphrases=passphrases)
        self.paths.krl.chmod(0o600)

    def revoke(
        self,
        cert: CertInfo,
        reason: str,
        action: str = "widerrufen",
        ca_passphrase: str = "",
        use_agent: bool = False,
    ) -> Path:
        """Nimmt das Zertifikat in die KRL auf und lagert das Material aus.

        Reihenfolge wie im Skript: erst die KRL, dann verschieben. Schlaegt die
        KRL fehl, bleibt auf der Platte alles unveraendert.
        """
        self.require()
        user = cert.user or cert.cert_path.parent.parent.name
        host = cert.host or cert.cert_path.parent.name

        self.krl_add(cert.cert_path, ca_passphrase, use_agent)

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        store = self.paths.revoked_dir / user / host / stamp
        store.mkdir(parents=True, exist_ok=True)
        for directory in (store.parent.parent, store.parent, store):
            directory.chmod(0o700)

        for item in (cert.key_path, cert.pub_path, cert.cert_path):
            if item.is_file():
                shutil.move(str(item), store / item.name)
        moved_key = store / cert.key_path.name
        if moved_key.is_file():
            moved_key.chmod(0o400)

        info = store / "revoked.info"
        info.write_text(
            "# Widerrufsinformationen — erzeugt von SSH-CA Manager\n"
            f"action={action}\n"
            f"revoked_at={datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f"revoked_by={os.environ.get('USER', 'unknown')}\n"
            f"mode=gui\n"
            f"host={host}\n"
            f"user={user}\n"
            f"key={cert.key_path.name}\n"
            f"reason={reason or '(kein Grund angegeben)'}\n",
            encoding="utf-8",
        )
        info.chmod(0o600)
        self.log("INFO", f"{action}: {user}@{host} ({reason})")
        return store

    # --------------------------------------------------------------- Lesen
    def load_certificate(self, cert_path: Path) -> CertInfo:
        cert_path = Path(cert_path)
        result = self.ssh.run(["-L", "-f", str(cert_path)], check=False)
        if result.returncode != 0:
            info = CertInfo(cert_path=cert_path)
            info.parse_error = result.stderr.strip() or "ssh-keygen -L fehlgeschlagen"
        else:
            info = parse_cert_listing(result.stdout, cert_path)

        info.stored = str(cert_path).startswith(str(self.paths.revoked_dir) + os.sep)
        if info.stored:
            info.revoked = True
            info.host = cert_path.parent.parent.name
            info.user = cert_path.parent.parent.parent.name
        else:
            info.host = cert_path.parent.name
            info.user = cert_path.parent.parent.name
            info.revoked = self.is_revoked(cert_path)
        return info

    def iter_active_certificates(self):
        """Alle aktiven Zertifikate unter <user>/<host>/ (ohne archive/)."""
        for user_dir in sorted(self.paths.base.iterdir()):
            if not user_dir.is_dir() or user_dir.name in RESERVED_NAMES:
                continue
            for host_dir in sorted(user_dir.iterdir()):
                if not host_dir.is_dir():
                    continue
                for cert in sorted(host_dir.glob("*-cert.pub")):
                    yield cert

    def iter_revoked_entries(self):
        if not self.paths.revoked_dir.is_dir():
            return
        for user_dir in sorted(self.paths.revoked_dir.iterdir()):
            if not user_dir.is_dir():
                continue
            for host_dir in sorted(user_dir.iterdir()):
                if not host_dir.is_dir():
                    continue
                for stamp_dir in sorted(host_dir.iterdir(), reverse=True):
                    if stamp_dir.is_dir():
                        yield RevokedEntry.from_dir(stamp_dir)

    # ------------------------------------------------------------- Sicherung
    def export_certificates(
        self, certs: list[CertInfo], destination: Path
    ) -> tuple[Path, int]:
        """Exportiert Schluessel, Public Keys und Zertifikate als tar.gz.

        Es werden nur Zertifikate aufgenommen, die zum Zeitpunkt des Exports
        gueltig sind (inklusive 'laeuft bald ab'). Die Struktur im Archiv
        entspricht dem Datenverzeichnis: <user>/<host>/<dateien>.
        """
        valid = [
            cert for cert in certs
            if cert.status() in (Status.VALID, Status.EXPIRING)
        ]
        if not valid:
            raise CaError("Es gibt keine gültigen Zertifikate zum Exportieren.")

        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with tarfile.open(destination, "w:gz") as tar:
            for cert in valid:
                for item in (cert.key_path, cert.pub_path, cert.cert_path):
                    if item.is_file():
                        tar.add(
                            item,
                            arcname=f"{cert.user}/{cert.host}/{item.name}",
                        )
                count += 1
        destination.chmod(0o600)
        self.log("OK", f"{count} Zertifikat(e) exportiert nach {destination}")
        return destination, count

    # -------------------------------------------------------------- Loeschen
    def delete_certificate(self, cert: CertInfo) -> None:
        """Loescht das Material eines UNGUELTIGEN Zertifikats endgueltig.

        Erlaubt nur fuer abgelaufene oder widerrufene Zertifikate — gueltiges
        Material wird nicht geloescht, dafuer gibt es Widerruf und Sperrung.
        Mit entfernt wird das archive/-Verzeichnis des Host-Ordners sowie der
        Host-Ordner selbst, wenn er danach leer ist.
        """
        status = cert.status()
        if status not in (Status.EXPIRED, Status.REVOKED, Status.STORED):
            raise CaError(
                "Nur abgelaufene oder widerrufene Zertifikate können gelöscht "
                f"werden — dieses ist: {status.value}."
            )
        if cert.stored:
            raise CaError(
                "Ausgelagerte Einträge werden über die Widerrufsliste gelöscht."
            )

        removed: list[str] = []
        for item in (cert.key_path, cert.pub_path, cert.cert_path):
            if item.is_file():
                item.unlink()
                removed.append(item.name)

        host_dir = cert.cert_path.parent
        archive = host_dir / "archive"
        if archive.is_dir():
            shutil.rmtree(archive, ignore_errors=True)
        self._prune_empty_dirs(host_dir)
        self.log(
            "INFO",
            f"Gelöscht ({status.value}): {cert.user}@{cert.host} — {', '.join(removed)}",
        )

    def delete_revoked_entry(self, entry) -> None:
        """Loescht einen ausgelagerten Vorgang unter revoked/ endgueltig.

        Der KRL-Eintrag bleibt bestehen — die KRL kennt keine Ruecknahme, und
        genau so soll es sein: das Zertifikat bleibt auf den Zielsystemen
        ungueltig, nur das tote Material verschwindet vom Jumphost.
        """
        directory = Path(entry.directory)
        if not str(directory.resolve()).startswith(
            str(self.paths.revoked_dir.resolve()) + os.sep
        ):
            raise CaError(f"Unerwarteter Pfad: {directory}")
        if not directory.is_dir():
            raise CaError(f"Ablage nicht gefunden: {directory}")
        shutil.rmtree(directory)
        self._prune_empty_dirs(directory.parent)
        self.log(
            "INFO",
            f"Widerrufsablage gelöscht: {entry.user}@{entry.host} ({entry.revoked_at})",
        )

    def _prune_empty_dirs(self, start: Path) -> None:
        """Entfernt leere Verzeichnisse aufwaerts bis unterhalb der Basis."""
        current = Path(start)
        base = self.paths.base.resolve()
        while (
            current.is_dir()
            and current.resolve() != base
            and str(current.resolve()).startswith(str(base) + os.sep)
            and not any(current.iterdir())
        ):
            current.rmdir()
            current = current.parent

    def backup(self, destination: Path | None = None) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = Path(
            destination or self.paths.backup_dir / f"ssh-ca-backup-{stamp}.tar.gz"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(destination, "w:gz") as tar:
            for item in sorted(self.paths.base.iterdir()):
                if item == self.paths.backup_dir:
                    continue
                tar.add(item, arcname=item.name)
        destination.chmod(0o600)
        self.log("OK", f"Sicherung geschrieben: {destination}")
        return destination

    def restore(self, archive: Path) -> None:
        archive = Path(archive)
        if not archive.is_file():
            raise CaError(f"Sicherung nicht gefunden: {archive}")
        with tarfile.open(archive, "r:*") as tar:
            for member in tar.getmembers():
                target = (self.paths.base / member.name).resolve()
                if not str(target).startswith(str(self.paths.base.resolve())):
                    raise CaError(f"Unerwarteter Pfad in der Sicherung: {member.name}")
            tar.extractall(self.paths.base)
        self.log("OK", f"Sicherung eingespielt: {archive}")


__all__ = [
    "CertificateAuthority",
    "CertRequest",
    "CaError",
    "SshKeygenError",
]
