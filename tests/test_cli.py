"""CLI-Test — kompletter Funktionsumfang ohne Terminal.

    python3 tests/test_cli.py

Passphrasen- und Bestätigungsabfragen laufen über die Test-Hooks _getpass
und _input des CLI-Moduls.
"""

from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshca import cli  # noqa: E402

CA_PASS = "ca-test-passphrase"
KEY_PASS = "key-test-passphrase"

ok_count = 0
_pass_queue: list[str] = []
_input_queue: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global ok_count
    print(f"[{'OK  ' if condition else 'FAIL'}] {label}"
          + (f" — {detail}" if detail else ""))
    if not condition:
        raise SystemExit(1)
    ok_count += 1


def fake_getpass(prompt: str = "") -> str:
    if not _pass_queue:
        raise AssertionError(f"unerwartete Passphrasen-Abfrage: {prompt}")
    return _pass_queue.pop(0)


def fake_input(prompt: str = "") -> str:
    if not _input_queue:
        raise AssertionError(f"unerwartete Eingabe-Abfrage: {prompt}")
    return _input_queue.pop(0)


cli._getpass = fake_getpass
cli._input = fake_input


def run(argv: list[str], passwords: list[str] | None = None,
        inputs: list[str] | None = None) -> tuple[int, str]:
    _pass_queue.clear()
    _pass_queue.extend(passwords or [])
    _input_queue.clear()
    _input_queue.extend(inputs or [])
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli.main(argv)
    return code, buffer.getvalue()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sshca-cli-") as tmp:
        base = str(Path(tmp) / "ssh-ca")
        b = ["--base", base]

        code, out = run(b + ["status"])
        check("status ohne CA meldet Fehlen", code == 1 and "Keine CA" in out)

        code, out = run(b + ["init", "--comment", "cli-test"],
                        passwords=[CA_PASS, CA_PASS])
        check("init legt CA an", code == 0 and "SHA256:" in out)

        code, out = run(b + ["init"], passwords=[])
        check("init verweigert zweite CA", code == 1)

        code, out = run(b + ["status"])
        check("status zeigt CA", code == 0 and "0 aktiv" in out)

        code, out = run(b + ["pubkey"])
        check("pubkey gibt Key aus", code == 0 and out.startswith("ssh-ed25519"))

        # Passphrasen-Wiederholung: erst zu kurz, dann uneinig, dann korrekt.
        code, out = run(
            b + ["create", "dennis", "jump", "--no-agent",
                 "-p", "dennis", "-p", "dennis@jump",
                 "--ext", "permit-pty", "--source-address", "172.16.40.0/22"],
            passwords=["kurz", KEY_PASS, "anders", KEY_PASS, KEY_PASS, CA_PASS],
        )
        check("create mit Wiederholungs-Logik", code == 0 and "erstellt" in out, out.splitlines()[0] if out else "")
        check("create zeigt Critical Option", "source-address=172.16.40.0/22" in out)
        check("create zeigt Anmeldebeispiel", "ssh -i " in out)

        code, out = run(b + ["create", "dennis", "jump", "--no-agent"], passwords=[])
        check("create verweigert Duplikat", code == 1)

        code, out = run(b + ["list"])
        check("list zeigt Zertifikat", code == 0 and "jump" in out and "gültig" in out)

        code, out = run(b + ["list", "--filter", "gibtsnicht"])
        check("list-Filter greift", code == 0 and "Keine passenden" in out)

        code, out = run(b + ["show", "dennis", "jump", "--raw"])
        check("show mit Rohausgabe", code == 0 and "ssh-keygen -L" in out
              and "Serial:" in out)

        code, out = run(b + ["show", "dennis", "fehlt"])
        check("show für Unbekanntes scheitert", code == 1)

        # Vorlagen anwenden
        code, out = run(b + ["templates"])
        check("templates listet Vorlagen", code == 0 and "Kurzlebig" in out)

        code, out = run(
            b + ["create", "ansible", "web01", "--no-agent",
                 "-t", "Automatisierung", "--no-key-pass"],
            passwords=[CA_PASS],
        )
        check("create aus Vorlage", code == 0 and "automation" in out)

        # Erneuern: Bestätigung erst ablehnen, dann zustimmen.
        code, out = run(b + ["renew", "dennis", "jump", "--no-agent"],
                        inputs=["n"])
        check("renew respektiert Ablehnung", code == 1 and "Abgebrochen" in out)

        code, out = run(
            b + ["renew", "dennis", "jump", "--no-agent", "--yes",
                 "-V", "+30m", "-p", "dennis"],
            passwords=[KEY_PASS, KEY_PASS, CA_PASS],
        )
        check("renew erzeugt neu", code == 0 and "erneuert" in out)

        # Export: alle gültigen und gezielt eines
        export_all = str(Path(tmp) / "alle.tar.gz")
        code, out = run(b + ["export", "-o", export_all])
        check("export alle gültigen", code == 0 and "2 Zertifikat(e)" in out)

        export_one = str(Path(tmp) / "eines.tar.gz")
        code, out = run(b + ["export", "ansible", "web01", "-o", export_one])
        check("export einzelnes", code == 0 and "1 Zertifikat(e)" in out)

        code, out = run(b + ["export", "ansible"])
        check("export mit halber Angabe scheitert", code == 1)

        # Widerruf mit --lock und Grund
        code, out = run(
            b + ["revoke", "ansible", "web01", "--no-agent", "--yes",
                 "--lock", "--reason", "Testlauf"],
            passwords=[CA_PASS],
        )
        check("revoke --lock", code == 0 and "gesperrt" in out)

        code, out = run(b + ["revoked"])
        check("revoked listet Vorgang", code == 0 and "Testlauf" in out)

        code, out = run(b + ["list", "--all"])
        check("gesperrtes nicht mehr aktiv", "web01" not in out)

        # delete: gültiges verweigern, abgelaufenes löschen
        code, out = run(b + ["delete", "dennis", "jump", "--yes"])
        check("delete verweigert gültiges", code == 1)

        code, out = run(
            b + ["create", "dennis", "old01", "--no-agent", "--no-key-pass",
                 "-V", "20200101120000:20210101120000"],
            passwords=[CA_PASS],
        )
        check("abgelaufenes Testzertifikat", code == 0)
        code, out = run(b + ["delete", "dennis", "old01", "--yes"])
        check("delete löscht abgelaufenes", code == 0 and "Gelöscht" in out)

        # purge über den Zeitstempel aus der revoked-Ausgabe
        code, out = run(b + ["revoked"])
        stamp = [l for l in out.splitlines() if "web01" in l][0].split()[5]
        code, out = run(b + ["purge", "ansible", "web01", stamp, "--yes"])
        check("purge löscht Ablage", code == 0 and "Ablage gelöscht" in out)
        code, out = run(b + ["revoked"])
        check("revoked danach leer", "Keine widerrufenen" in out)

        code, out = run(b + ["purge", "ansible", "web01", "--yes"])
        check("purge ohne Treffer scheitert", code == 1)

        # Sicherung, Anleitung, Log
        backup_file = str(Path(tmp) / "sicherung.tar.gz")
        code, out = run(b + ["backup", "-o", backup_file])
        check("backup schreibt Archiv", code == 0 and Path(backup_file).is_file())

        code, out = run(b + ["deploy"])
        check("deploy zeigt Anleitung", code == 0 and "TrustedUserCAKeys" in out)

        code, out = run(b + ["log", "-n", "100"])
        check("log zeigt Einträge", code == 0 and "Zertifikat erstellt" in out)

        code, out = run(b + [])
        check("ohne Befehl: Hilfe und Exitcode 2", code == 2 and "BEFEHL" in out)

    print(f"\n{ok_count} Prüfungen bestanden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
