"""TUI-Test — faehrt die gefuehrten Menue-Ablaeufe ohne Terminal.

    python3 tests/test_tui.py

Eingaben und Passphrasen kommen aus Queues ueber die Hooks des CLI-Moduls.
Laeuft eine Queue leer, schlaegt der Test laut fehl — damit fallen
Aenderungen an der Abfrage-Reihenfolge sofort auf.
"""

from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshca import cli, tui  # noqa: E402

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


def session(base: str, inputs: list[str],
            passwords: list[str] | None = None) -> str:
    """Faehrt eine komplette Menue-Sitzung; inputs muss mit 'q' enden."""
    _input_queue.clear()
    _input_queue.extend(inputs)
    _pass_queue.clear()
    _pass_queue.extend(passwords or [])
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = tui.run_menu(Path(base))
    if _input_queue:
        raise AssertionError(f"unverbrauchte Eingaben: {_input_queue}")
    if _pass_queue:
        raise AssertionError(f"unverbrauchte Passphrasen: {_pass_queue}")
    if code != 0:
        raise AssertionError(f"run_menu endete mit {code}")
    return buffer.getvalue()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sshca-tui-") as tmp:
        base = str(Path(tmp) / "ssh-ca")

        # --- Ohne CA: Einrichtungsmenü und init-Ablauf --------------------
        out = session(base,
                      inputs=["i", "", "q"],
                      passwords=["kurz", CA_PASS + "-x", CA_PASS + "-y",
                                 CA_PASS, CA_PASS])
        check("Banner wird gezeigt", "███" in out)
        check("Einrichtungsmenü ohne CA", "Neue CA anlegen" in out)
        check("init: Länge und Abgleich geprüft",
              "mindestens 8 Zeichen" in out and "stimmen nicht überein" in out)
        check("init legt CA an", "CA erstellt: SHA256:" in out)

        # --- Neues Zertifikat: geführter Ablauf ---------------------------
        out = session(
            base,
            inputs=[
                "2",            # Neues Zertifikat
                "dennis",       # Benutzer
                "jump",         # Zielhost
                "",             # Vorlage: Standard (Kurzlebig)
                "+2h",          # Gültigkeit überschreiben
                "+admins",      # Prinzipal ergänzen …
                "",             # … und weiter
                "",             # Extensions anpassen? → Nein
                "",             # Critical Options? → Nein
                "",             # Zusammenfassung bestätigen (Vorgabe Ja)
                "q",
            ],
            passwords=[KEY_PASS, KEY_PASS, CA_PASS],
        )
        check("Hauptmenü mit Gruppen", "── Zertifikate ──" in out
              and "── Wartung ──" in out)
        check("Vorlagenauswahl angeboten", "Kurzlebig" in out)
        check("Gültigkeitsvorschau", "→ gültig bis" in out)
        check("Prinzipal ergänzt", "dennis, dennis@jump, admins" in out)
        check("Zusammenfassung gezeigt", "Zusammenfassung" in out)
        check("Zertifikat erstellt", "Zertifikat erstellt: dennis@jump" in out)
        check("Anmeldebeispiel", "ssh -i " in out)

        # --- Duplikat wird vor den Passphrasen abgefangen ------------------
        out = session(base, inputs=["2", "dennis", "jump", "q"])
        check("Duplikat früh abgefangen", "bereits einen Schlüssel" in out)

        # --- Liste und Details ---------------------------------------------
        out = session(base, inputs=["1", "3", "", "", "q"])
        check("Liste zeigt Zertifikat", "dennis" in out and "jump" in out)
        check("Detailpanel", "Zertifikat dennis@jump" in out
              and "Seriennummer" in out)

        # --- Zweites Zertifikat mit Vorlage 3 + Critical Options ----------
        out = session(
            base,
            inputs=[
                "2", "ansible", "web01",
                "3",            # Vorlage: Automatisierung
                "",             # Gültigkeit aus Vorlage
                "",             # Prinzipale weiter
                "",             # Extensions anpassen? Nein
                "j",            # Critical Options setzen
                "",             # force-command leer
                "172.16.40.0/22",  # source-address
                "",             # verify-required Nein
                "",             # bestätigen
                "q",
            ],
            passwords=[KEY_PASS, KEY_PASS, CA_PASS],
        )
        check("Vorlage 3 angewendet", "automation" in out)
        check("Critical Option gesetzt", "source-address=172.16.40.0/22" in out)

        # --- Widerruf (Sperrung) mit strukturierter Abfrage ----------------
        out = session(
            base,
            inputs=[
                "5",
                "1",            # ansible@web01 (alphabetisch zuerst)
                "2",            # Art: gesperrt
                "Testlauf",     # Grund
                "j",            # endgültig bestätigen
                "q",
            ],
            passwords=[CA_PASS],
        )
        check("Endgültig-Warnung", "ENDGÜLTIG" in out)
        check("Sperrung durchgeführt", "gesperrt: ansible@web01" in out)
        check("KRL-Hinweis", "KRL auf den Zielsystemen" in out)

        # --- Vorgänge auflisten und Ablage löschen -------------------------
        out = session(base, inputs=["8", "9", "", "j", "q"])
        check("Vorgangsliste", "Testlauf" in out)
        check("KRL-bleibt-Hinweis", "KRL-Eintrag bleibt bestehen" in out)
        check("Ablage gelöscht", "Ablage gelöscht:" in out)

        # --- Export aller gültigen ------------------------------------------
        export_file = str(Path(tmp) / "export.tar.gz")
        out = session(base, inputs=["7", "", export_file, "q"])
        check("Export durchgeführt", "1 Zertifikat(e) exportiert" in out)
        check("Exportdatei existiert", Path(export_file).is_file())

        # --- Abgelaufenes erzeugen und über das Menü löschen ----------------
        out = session(
            base,
            inputs=[
                "2", "dennis", "old01", "",
                "20200101120000:20210101120000",
                "", "", "", "",
                "q",
            ],
            passwords=[KEY_PASS, KEY_PASS, CA_PASS],
        )
        check("abgelaufenes erstellt", "Zertifikat erstellt: dennis@old01" in out)

        out = session(base, inputs=["6", "", "j", "q"])
        check("Löschen zeigt nur Ungültige",
              "old01" in out and "gültig (" not in out.split("Ungültiges löschen")[1].split("Schlüssel,")[0])
        check("abgelaufenes gelöscht", "Gelöscht: dennis@old01" in out)

        # --- Externen Schlüssel signieren (geführt) --------------------------
        import subprocess as _sp
        foreign = Path(tmp) / "extern_rsa"
        _sp.run(["ssh-keygen", "-t", "rsa", "-b", "3072", "-f", str(foreign),
                 "-N", "", "-C", "extern@pc"], check=True, capture_output=True)
        out = session(
            base,
            inputs=[
                "s",
                str(foreign) + ".pub",   # eingereichte Datei
                "extern", "web01",       # Benutzer, Zielhost
                "",                      # Vorlage: Standard
                "",                      # Gültigkeit aus Vorlage
                "",                      # Prinzipale weiter
                "",                      # Extensions anpassen? Nein
                "",                      # Critical? Nein
                "",                      # signieren (Vorgabe Ja)
                "q",
            ],
            passwords=[CA_PASS],
        )
        check("TUI: externer Key signiert",
              "Externer Schlüssel signiert: extern@web01" in out)
        check("TUI: Hinweis auf Rückgabe", "Zertifikatsdatei" in out)

        # --- CA-Status, Vorlagen, Log ---------------------------------------
        out = session(base, inputs=["c", "t", "l", "q"])
        check("CA-Statuspanel", "Certificate Authority" in out
              and "Fingerprint" in out)
        check("Vorlagenpanels", "Notfallzugang" in out)
        check("Log im Menü", "Zertifikat erstellt" in out)

        # --- Sichern über geführte Abfrage ----------------------------------
        backup_file = str(Path(tmp) / "sicherung.tar.gz")
        out = session(base, inputs=["b", backup_file, "q"])
        check("Sicherung über Menü", Path(backup_file).is_file())

        # --- Unbekannte Eingabe wird ignoriert ------------------------------
        out = session(base, inputs=["x", "q"])
        check("Unbekannte Auswahl ignoriert", out.count("Beenden") == 2)

    print(f"\n{ok_count} Prüfungen bestanden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
