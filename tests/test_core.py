"""Rauchtest der Kernschicht — laeuft ohne Qt und ohne Benutzereingabe.

    python3 tests/test_core.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshca.ca import CaError, CertificateAuthority, CertRequest  # noqa: E402
from sshca.config import Paths  # noqa: E402
from sshca.model import Status, parse_validity_spec  # noqa: E402
from sshca.store import CertIndex, refresh_index  # noqa: E402
from sshca.templates import Template, TemplateStore  # noqa: E402

CA_PASS = "ca-test-passphrase"
KEY_PASS = "key-test-passphrase"

ok_count = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global ok_count
    mark = "OK  " if condition else "FAIL"
    print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))
    if condition:
        ok_count += 1
    else:
        raise SystemExit(1)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sshca-test-") as tmp:
        paths = Paths(Path(tmp) / "ssh-ca")
        ca = CertificateAuthority(paths)

        check("ssh-keygen gefunden", ca.ssh.available(), ca.ssh.keygen)
        check("Layout angelegt", paths.ca_dir.is_dir())
        check("noch keine CA", not ca.exists())

        # --- CA anlegen (Passphrase ueber Askpass/Pipe) --------------------
        ca.init_ca(CA_PASS, comment="test-ca")
        check("CA erstellt", ca.exists())
        fp = ca.ca_fingerprint()
        check("CA-Fingerprint gelesen", fp.startswith("SHA256:"), fp)
        check("CA-Key ist 0600", oct(paths.ca_key.stat().st_mode)[-3:] == "600")

        # --- Falsche Passphrase muss scheitern ----------------------------
        req_bad = CertRequest(
            user="dennis", host="jump",
            principals=["dennis", "dennis@jump"],
            key_passphrase=KEY_PASS, ca_passphrase="falsch",
        )
        try:
            ca.create_certificate(req_bad)
            check("falsche CA-Passphrase abgewiesen", False)
        except Exception as exc:  # noqa: BLE001
            check("falsche CA-Passphrase abgewiesen", True, type(exc).__name__)
        check(
            "kein Schlüsselrest nach Fehlschlag",
            not paths.key_path("dennis", "jump").exists(),
        )

        # --- Zertifikat erstellen ----------------------------------------
        req = CertRequest(
            user="dennis", host="jump",
            principals=["dennis", "dennis@jump", "admins"],
            validity="+1h",
            extensions=["permit-pty", "permit-agent-forwarding"],
            critical_options={"source-address": "172.16.40.0/22"},
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        )
        info = ca.create_certificate(req)
        check("Zertifikat erstellt", info.cert_path.is_file(), info.cert_path.name)
        check("Typ ist user", info.cert_type == "user", info.cert_type)
        check("Prinzipale geparst", info.principals == ["dennis", "dennis@jump", "admins"],
              info.principals_csv)
        check("Extensions geparst", set(info.extensions) == {"permit-pty", "permit-agent-forwarding"},
              ", ".join(info.extensions))
        check("Critical Option geparst", "source-address" in info.critical_options,
              str(info.critical_options))
        check("Seriennummer gesetzt", info.serial.isdigit(), info.serial)
        check("Gültigkeit geparst", info.valid_from is not None and info.valid_to is not None,
              info.validity_text)
        check("Status gültig", info.status() is Status.VALID, info.status_text())
        check("privater Key vorhanden", info.has_private_key)

        # --- Doppelte Anlage verhindern ----------------------------------
        try:
            ca.create_certificate(req)
            check("doppelte Anlage verhindert", False)
        except CaError:
            check("doppelte Anlage verhindert", True)

        # --- Index ---------------------------------------------------------
        index = CertIndex(paths.index_db)
        certs = refresh_index(ca, index)
        check("Index gefüllt", len(certs) == 1, f"{len(certs)} Eintrag/Einträge")
        check("Index aktuell", index.is_current(info.cert_path))
        certs2 = refresh_index(ca, index)
        check("zweiter Lauf aus Cache", len(certs2) == 1)

        # --- Erneuern -------------------------------------------------------
        req_renew = CertRequest(
            user="dennis", host="jump",
            principals=["dennis", "dennis@jump"],
            validity="+30m",
            extensions=["permit-pty"],
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        )
        renewed = ca.renew_certificate(info, req_renew)
        archive = info.cert_path.parent / "archive"
        check("altes Material archiviert", any(archive.glob("*-cert.pub")))
        check("neues Zertifikat gültig", renewed.status() is Status.VALID)
        check("neue Seriennummer", renewed.serial != info.serial,
              f"{info.serial} → {renewed.serial}")

        # --- Widerruf -------------------------------------------------------
        check("vor Widerruf nicht in KRL", not ca.is_revoked(renewed.cert_path))
        store_dir = ca.revoke(renewed, reason="Test", action="widerrufen",
                              ca_passphrase=CA_PASS)
        check("KRL angelegt", paths.krl.is_file())
        check("Material ausgelagert", any(store_dir.glob("*-cert.pub")), str(store_dir))
        check("revoked.info geschrieben", (store_dir / "revoked.info").is_file())
        moved_cert = next(store_dir.glob("*-cert.pub"))
        check("KRL erkennt Widerruf", ca.is_revoked(moved_cert))
        moved_pub = next(
            p for p in store_dir.glob("*.pub") if not p.name.endswith("-cert.pub")
        )
        check("Public Key ebenfalls gesperrt", ca.is_revoked(moved_pub),
              moved_pub.name)
        reloaded = ca.load_certificate(moved_cert)
        check("Status ausgelagert", reloaded.status() is Status.STORED, reloaded.status_text())
        entries = list(ca.iter_revoked_entries())
        check("Widerrufsliste gelesen", len(entries) == 1 and entries[0].reason == "Test",
              entries[0].reason if entries else "-")

        # --- Sicherung ------------------------------------------------------
        archive_file = ca.backup()
        check("Sicherung erstellt", archive_file.is_file() and archive_file.stat().st_size > 0,
              archive_file.name)

        # --- Export gültiger Zertifikate -------------------------------------
        import tarfile as _tarfile

        req_export = CertRequest(
            user="dennis", host="web01",
            principals=["dennis"],
            validity="+1h",
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        )
        exported_cert = ca.create_certificate(req_export)
        active = [ca.load_certificate(p) for p in ca.iter_active_certificates()]
        export_path, count = ca.export_certificates(
            active, Path(tmp) / "export" / "gueltige.tar.gz"
        )
        check("Export erstellt", export_path.is_file() and count == 1,
              f"{count} Zertifikat(e)")
        with _tarfile.open(export_path) as tar:
            names = sorted(tar.getnames())
        check("Exportstruktur user/host", names == [
            "dennis/web01/web01_dennis_ed25519",
            "dennis/web01/web01_dennis_ed25519-cert.pub",
            "dennis/web01/web01_dennis_ed25519.pub",
        ], ", ".join(names))
        check("Exportdatei ist 0600", oct(export_path.stat().st_mode)[-3:] == "600")
        try:
            ca.export_certificates([reloaded], Path(tmp) / "leer.tar.gz")
            check("Export ohne gültige abgewiesen", False)
        except CaError:
            check("Export ohne gültige abgewiesen", True)

        # --- Löschen: gültig verboten, abgelaufen erlaubt ---------------------
        try:
            ca.delete_certificate(exported_cert)
            check("Löschen gültiger verweigert", False)
        except CaError as exc:
            check("Löschen gültiger verweigert", True, str(exc)[:60])

        req_expired = CertRequest(
            user="dennis", host="old01",
            principals=["dennis"],
            validity="20200101120000:20210101120000",
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        )
        expired = ca.create_certificate(req_expired)
        check("abgelaufenes Testzertifikat", expired.status() is Status.EXPIRED,
              expired.status_text())
        ca.delete_certificate(expired)
        check("abgelaufenes gelöscht", not expired.cert_path.exists()
              and not expired.key_path.exists())
        check("leerer Host-Ordner entfernt", not expired.cert_path.parent.exists())
        check("Benutzer-Ordner mit Inhalt bleibt",
              (paths.base / "dennis").is_dir())

        # --- Externen Public Key signieren ------------------------------------
        import subprocess as _sp
        foreign = Path(tmp) / "foreign_ed25519"
        _sp.run(["ssh-keygen", "-t", "ed25519", "-f", str(foreign),
                 "-N", "", "-C", "max@laptop"], check=True, capture_output=True)
        req_ext = CertRequest(
            user="max", host="jump", principals=["max", "max@jump"],
            validity="+1h", extensions=["permit-pty"], ca_passphrase=CA_PASS,
        )
        ext = ca.import_and_sign_pubkey(Path(str(foreign) + ".pub"), req_ext)
        check("externer Key signiert", ext.cert_path.is_file(),
              ext.cert_path.name)
        check("kein privater Schlüssel im Bestand", not ext.has_private_key)
        check("externer Key: Status gültig", ext.status() is Status.VALID)

        ext2 = ca.import_and_sign_pubkey(
            Path(str(foreign) + ".pub").read_text(), req_ext)
        check("Wiedereinreichung rotiert", ext2.serial != ext.serial
              and any((ext2.cert_path.parent / "archive").glob("*-cert.pub")))

        foreign_rsa = Path(tmp) / "foreign_rsa"
        _sp.run(["ssh-keygen", "-t", "rsa", "-b", "3072", "-f",
                 str(foreign_rsa), "-N", "", "-C", "max@pc"],
                check=True, capture_output=True)
        ext_rsa = ca.import_and_sign_pubkey(
            Path(str(foreign_rsa) + ".pub"),
            CertRequest(user="max", host="web", principals=["max"],
                        validity="+1h", ca_passphrase=CA_PASS),
        )
        check("RSA-Key: Typ im Dateinamen", "_rsa-cert.pub" in ext_rsa.cert_path.name,
              ext_rsa.cert_path.name)

        try:
            ca.import_and_sign_pubkey("kein schlüssel", req_ext)
            check("Müll abgelehnt", False)
        except CaError:
            check("Müll abgelehnt", True)
        try:
            ca.import_and_sign_pubkey(foreign.read_text(), req_ext)
            check("privater Schlüssel abgelehnt", False)
        except CaError as exc:
            check("privater Schlüssel abgelehnt", "PRIVATER" in str(exc))
        try:
            ca.import_and_sign_pubkey(
                Path(str(foreign) + ".pub"),
                CertRequest(user="dennis", host="web01", principals=["dennis"],
                            validity="+1h", ca_passphrase=CA_PASS),
            )
            check("Konflikt mit lokalem Schlüssel erkannt", False)
        except CaError as exc:
            check("Konflikt mit lokalem Schlüssel erkannt",
                  "lokal verwaltet" in str(exc))

        # --- Widerrufsablage löschen ------------------------------------------
        entry = list(ca.iter_revoked_entries())[0]
        ca.delete_revoked_entry(entry)
        check("Widerrufsablage gelöscht", not Path(entry.directory).exists())
        check("Widerrufsliste danach leer", not list(ca.iter_revoked_entries()))
        check("KRL bleibt bestehen", paths.krl.is_file())

        # --- Vorlagen -------------------------------------------------------
        store = TemplateStore(paths.templates_file)
        templates = store.load()
        check("Vorlagen geladen", len(templates) >= 4, f"{len(templates)} Stück")
        rendered = templates[0].principals_for("dennis", "jump")
        check("Prinzipalmuster ersetzt", rendered == ["dennis", "dennis@jump"], str(rendered))
        store.save(templates + [Template(name="Eigene", validity="+15m")])
        check("Vorlage gespeichert", len(store.load()) == len(templates) + 1)

        # --- Hilfsfunktionen ------------------------------------------------
        span = parse_validity_spec("+2h")
        check("Gültigkeitsvorschau", span is not None
              and (span[1] - span[0]).total_seconds() == 7200)
        check("unbekannte Angabe toleriert", parse_validity_spec("20260101:20270101") is None)

        # --- Eingabeprüfung ---------------------------------------------------
        for bad_user, label in ((".." , "'..'"), ("a/b", "Schrägstrich"),
                                ("a b", "Leerzeichen"), ("", "leer")):
            try:
                ca.create_certificate(CertRequest(
                    user=bad_user, host="jump", principals=["x"],
                    key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
                ))
                check(f"Benutzername {label} abgewiesen", False)
            except CaError:
                check(f"Benutzername {label} abgewiesen", True)
        check("kein Ausbruch aus der Basis",
              not (paths.base.parent / "jump").exists())
        try:
            paths.host_dir("..", "jump")
            check("Paths weist '..' ab", False)
        except CaError:
            check("Paths weist '..' ab", True)

        for bad_principal, label in (("dennis,root", "Komma"),
                                     ("dennis root", "Leerzeichen"),
                                     ("  ", "leer")):
            try:
                CertRequest(user="dennis", host="jump",
                            principals=[bad_principal]).validate()
                check(f"Prinzipal mit {label} abgewiesen", False)
            except CaError:
                check(f"Prinzipal mit {label} abgewiesen", True)
        CertRequest(user="dennis", host="jump",
                    principals=["dennis", "dennis@jump"]).validate()
        check("gültige Prinzipale weiterhin erlaubt", True)

        # --- Wiederherstellung weist Ausbrüche ab -----------------------------
        import io as _io

        evil = Path(tmp) / "boese.tar.gz"
        with _tarfile.open(evil, "w:gz") as tar:
            payload = b"pwned\n"
            member = _tarfile.TarInfo("../ssh-ca-fremd/payload")
            member.size = len(payload)
            tar.addfile(member, _io.BytesIO(payload))
        try:
            ca.restore(evil)
            check("Sicherung mit '..' abgewiesen", False)
        except CaError:
            check("Sicherung mit '..' abgewiesen", True)
        check("nichts neben der Basis angelegt",
              not (Path(tmp) / "ssh-ca-fremd").exists())

        outside = Path(tmp) / "ziel"
        outside.mkdir()
        evil_link = Path(tmp) / "boese-link.tar.gz"
        with _tarfile.open(evil_link, "w:gz") as tar:
            link = _tarfile.TarInfo("link")
            link.type = _tarfile.SYMTYPE
            link.linkname = str(outside)
            tar.addfile(link)
            payload = b"x\n"
            through = _tarfile.TarInfo("link/durch")
            through.size = len(payload)
            tar.addfile(through, _io.BytesIO(payload))
        try:
            ca.restore(evil_link)
        except CaError:
            pass
        check("nicht durch Symlink geschrieben", not (outside / "durch").exists())

        # --- KRL-Sammelabfrage ------------------------------------------------
        gueltig = ca.create_certificate(CertRequest(
            user="sammel", host="jump", principals=["sammel"],
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        ))
        zu_widerrufen = ca.create_certificate(CertRequest(
            user="sammel", host="web", principals=["sammel"],
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        ))
        widerrufen_dir = ca.revoke(zu_widerrufen, reason="Sammeltest",
                                   ca_passphrase=CA_PASS)
        widerrufen_cert = next(widerrufen_dir.glob("*-cert.pub"))

        hits = ca.revoked_paths([widerrufen_cert, gueltig.cert_path])
        check("Sammelprüfung erkennt Widerruf",
              widerrufen_cert in hits and gueltig.cert_path not in hits)

        # Ein zweiter Widerruf darf den ersten nicht aus der KRL werfen.
        krl_vorher = paths.krl.stat().st_size
        zweiter = ca.create_certificate(CertRequest(
            user="sammel", host="db", principals=["sammel"],
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        ))
        zweiter_dir = ca.revoke(zweiter, reason="Sammeltest 2",
                                ca_passphrase=CA_PASS)
        zweiter_cert = next(zweiter_dir.glob("*-cert.pub"))
        check("KRL ist gewachsen", paths.krl.stat().st_size > krl_vorher,
              f"{krl_vorher} → {paths.krl.stat().st_size} Bytes")
        check("erster Widerruf bleibt bestehen", ca.is_revoked(widerrufen_cert))
        check("zweiter Widerruf eingetragen", ca.is_revoked(zweiter_cert))

        # Nur-Seriennummer-Variante für Sonderfälle (FIDO-Token o. Ä.).
        nur_serial = ca.create_certificate(CertRequest(
            user="sammel", host="token", principals=["sammel"],
            key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
        ))
        nur_serial_dir = ca.revoke(nur_serial, reason="nur Serial",
                                   ca_passphrase=CA_PASS, revoke_key=False)
        ns_cert = next(nur_serial_dir.glob("*-cert.pub"))
        ns_pub = next(
            p for p in nur_serial_dir.glob("*.pub")
            if not p.name.endswith("-cert.pub")
        )
        check("revoke_key=False: Zertifikat gesperrt", ca.is_revoked(ns_cert))
        check("revoke_key=False: Schlüssel bleibt frei", not ca.is_revoked(ns_pub))

        broken = paths.base / "sammel" / "jump" / "kaputt.pub"
        broken.write_text("kein Zertifikat\n", encoding="utf-8")
        hits = ca.revoked_paths([broken, widerrufen_cert])
        check("unlesbare Datei verdeckt keinen Widerruf",
              widerrufen_cert in hits and broken not in hits)
        broken.unlink()

        refresh_index(ca, index)                      # Cache aufwärmen
        calls = {"n": 0}
        original_run = ca.ssh.run

        def counting_run(*args, **kwargs):
            calls["n"] += 1
            return original_run(*args, **kwargs)

        ca.ssh.run = counting_run
        refresh_index(ca, index)
        ca.ssh.run = original_run
        check("Refresh aus dem Cache: ein einziger ssh-keygen-Aufruf",
              calls["n"] == 1, f"{calls['n']} Aufruf(e)")

        # --- Log --------------------------------------------------------------
        check("Log geschrieben", "Zertifikat erstellt" in ca.read_log())

        index.close()

    print(f"\n{ok_count} Prüfungen bestanden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
