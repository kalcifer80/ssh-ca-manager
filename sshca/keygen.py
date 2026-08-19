"""Duenner Wrapper um ssh-keygen und ssh-add.

Alle Aufrufe laufen ueber :func:`run`. Passphrasen werden ueber einen
Askpass-Helfer und eine Pipe uebergeben (siehe sshca/askpass.py), niemals ueber
argv oder die Umgebung.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_ASKPASS_PY = Path(__file__).with_name("askpass.py")

#: Aufrufdauer, nach der ein Aufruf als haengend gilt. ssh-keygen -a 100
#: braucht auf langsamer Hardware durchaus einige Sekunden.
DEFAULT_TIMEOUT = 120


class SshKeygenError(RuntimeError):
    """Ein ssh-keygen-Aufruf ist fehlgeschlagen."""

    def __init__(self, argv: list[str], returncode: int, stderr: str) -> None:
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr.strip()
        detail = self.stderr or f"Exitcode {returncode}"
        super().__init__(f"{' '.join(argv[:2])} …: {detail}")

    @property
    def is_bad_passphrase(self) -> bool:
        text = self.stderr.lower()
        return "incorrect passphrase" in text or "load failed" in text


@dataclass
class Result:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


class Ssh:
    """Zugriff auf die OpenSSH-Kommandozeilenwerkzeuge."""

    def __init__(self, keygen: str | None = None, add: str | None = None) -> None:
        self.keygen = keygen or shutil.which("ssh-keygen") or "ssh-keygen"
        self.add = add or shutil.which("ssh-add") or "ssh-add"
        self._askpass_shim: Path | None = None
        self._shim_dir: tempfile.TemporaryDirectory | None = None

    # -- Askpass ----------------------------------------------------------
    def _askpass(self) -> Path:
        """Legt einmalig ein ausfuehrbares Shim an, das askpass.py startet."""
        if self._askpass_shim is not None:
            return self._askpass_shim
        self._shim_dir = tempfile.TemporaryDirectory(prefix="sshca-askpass-")
        shim = Path(self._shim_dir.name) / "askpass"
        import sys

        shim.write_text(
            "#!/bin/sh\n"
            f'exec "{sys.executable}" "{_ASKPASS_PY}" "$@"\n',
            encoding="utf-8",
        )
        shim.chmod(stat.S_IRWXU)
        self._askpass_shim = shim
        return shim

    # -- Ausfuehrung ------------------------------------------------------
    def run(
        self,
        args: list[str],
        passphrases: list[str] | None = None,
        binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        check: bool = True,
        cwd: Path | None = None,
        stdin_file: Path | None = None,
    ) -> Result:
        """Ruft ssh-keygen (oder ``binary``) auf.

        ``passphrases`` enthaelt die Antworten in der Reihenfolge, in der
        ssh-keygen danach fragt. Beim Erzeugen eines Schluessels sind das zwei
        identische Eintraege (Eingabe und Bestaetigung), beim Signieren einer.

        ``stdin_file`` haengt eine Datei an stdin. Genau ein Aufruf braucht
        das: ``ssh-keygen -Y verify`` liest die zu pruefende Nachricht
        ausschliesslich von stdin. Ohne Angabe bleibt stdin ``DEVNULL`` —
        nichts darf jemals auf eine Eingabe warten.
        """
        argv = [binary or self.keygen, *args]
        env = os.environ.copy()
        env.setdefault("LC_ALL", "C")
        read_fd: int | None = None
        pass_fds: tuple[int, ...] = ()

        if passphrases is not None:
            read_fd, write_fd = os.pipe()
            os.set_inheritable(read_fd, True)
            payload = "".join(p + "\n" for p in passphrases).encode("utf-8")
            with os.fdopen(write_fd, "wb") as handle:
                handle.write(payload)
            env["SSH_ASKPASS"] = str(self._askpass())
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["SSHCA_PASS_FD"] = str(read_fd)
            # Fuer OpenSSH < 8.4, das SSH_ASKPASS_REQUIRE noch nicht kennt und
            # stattdessen ein gesetztes DISPLAY verlangt.
            env.setdefault("DISPLAY", ":0")
            pass_fds = (read_fd,)
        else:
            # Ohne Passphrase darf ssh-keygen erst recht nicht interaktiv
            # werden: ein fehlendes Askpass fuehrt sonst zu einem Haenger.
            env["SSH_ASKPASS_REQUIRE"] = "never"

        stdin_handle = None
        try:
            if stdin_file is not None:
                stdin_handle = open(stdin_file, "rb")
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
                pass_fds=pass_fds,
                cwd=str(cwd) if cwd else None,
                stdin=stdin_handle or subprocess.DEVNULL,
            )
        finally:
            if stdin_handle is not None:
                stdin_handle.close()
            if read_fd is not None:
                os.close(read_fd)

        result = Result(argv, proc.returncode, proc.stdout, proc.stderr)
        if check and proc.returncode != 0:
            raise SshKeygenError(argv, proc.returncode, proc.stderr)
        return result

    # -- Bequemlichkeiten -------------------------------------------------
    def version(self) -> str:
        proc = subprocess.run(
            [self.keygen, "-?"], capture_output=True, text=True
        )
        first = (proc.stderr or proc.stdout).splitlines()
        return first[0].strip() if first else "unbekannt"

    def available(self) -> bool:
        return shutil.which(self.keygen) is not None or Path(self.keygen).exists()

    def fingerprint(self, path: Path) -> str:
        """SHA256-Fingerprint eines Public Keys oder Zertifikats."""
        res = self.run(["-l", "-f", str(path)], check=False)
        if res.returncode != 0:
            return "-"
        parts = res.stdout.split()
        return parts[1] if len(parts) > 1 else "-"

    def agent_fingerprints(self) -> list[str]:
        """Fingerprints der im ssh-agent geladenen Schluessel."""
        try:
            res = self.run(["-l"], binary=self.add, check=False, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return []
        if res.returncode != 0:
            return []
        out = []
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) > 1 and parts[1].startswith("SHA256:"):
                out.append(parts[1])
        return out
