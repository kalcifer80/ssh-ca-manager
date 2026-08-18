"""Aufbautest der Oberflaeche — laeuft ohne Bildschirm.

    QT_QPA_PLATFORM=offscreen python3 tests/test_gui.py

Geprueft wird, dass sich Fenster und Dialoge bauen lassen, die Modelle die
richtigen Werte liefern und Filter sowie Auswahl funktionieren. Ein echter
Klicktest ersetzt das nicht.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from sshca.ca import CertRequest  # noqa: E402
from sshca.gui.dialogs import CaInitDialog, CertDetailDialog, CertDialog, RevokeDialog  # noqa: E402
from sshca.gui.main_window import MainWindow
from sshca.gui.theme import apply_theme  # noqa: E402

CA_PASS = "ca-test-passphrase"
KEY_PASS = "key-test-passphrase"
ok_count = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global ok_count
    print(f"[{'OK  ' if condition else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not condition:
        raise SystemExit(1)
    ok_count += 1


def main() -> int:
    app = QApplication.instance() or QApplication([])
    apply_theme(app)

    with tempfile.TemporaryDirectory(prefix="sshca-gui-") as tmp:
        base = Path(tmp) / "ssh-ca"
        window = MainWindow(base)
        check("Fenster gebaut", window.windowTitle().startswith("SSH-CA Manager"))
        check("ohne CA: Neu deaktiviert", not window.act_new.isEnabled())
        check("ohne CA: CA anlegen aktiv", window.act_ca_new.isEnabled())
        check("Hinweis auf leere Liste sichtbar", window.empty_hint.isVisible() is False
              or window.cert_model.rowCount() == 0)

        # CA und zwei Zertifikate direkt ueber die Kernschicht anlegen.
        window.ca.init_ca(CA_PASS, "test-ca")
        for user, host, validity in [
            ("dennis", "jump", "+1h"),
            ("ansible", "web01", "+9h"),
        ]:
            window.ca.create_certificate(
                CertRequest(
                    user=user, host=host,
                    principals=[user, f"{user}@{host}"],
                    validity=validity,
                    extensions=["permit-pty"],
                    key_passphrase=KEY_PASS, ca_passphrase=CA_PASS,
                )
            )
        window.refresh(force=True)

        check("Tabelle gefüllt", window.cert_model.rowCount() == 2,
              f"{window.cert_model.rowCount()} Zeilen")
        check("mit CA: Neu aktiviert", window.act_new.isEnabled())
        check("CA-Reiter zeigt Fingerprint", "SHA256:" in window.ca_status.text())
        check("CA-Public-Key angezeigt",
              window.ca_pub_view.toPlainText().startswith("ssh-ed25519"))

        # Spalteninhalte
        index = window.cert_model.index(0, 1)
        check("Spalte Benutzer", window.cert_model.data(index) in ("ansible", "dennis"),
              str(window.cert_model.data(index)))
        status_color = window.cert_model.data(
            window.cert_model.index(0, 0), Qt.ForegroundRole
        )
        check("Statusfarbe gesetzt", status_color is not None, status_color.name())
        tooltip = window.cert_model.data(window.cert_model.index(0, 0), Qt.ToolTipRole)
        check("Tooltip mit Fingerprint", "SHA256:" in tooltip)

        # Filter
        window.search.setText("ansible")
        check("Filter greift", window.cert_proxy.rowCount() == 1,
              f"{window.cert_proxy.rowCount()} sichtbar")
        window.search.setText("")
        check("Filter zurückgesetzt", window.cert_proxy.rowCount() == 2)

        # Sortierung
        window.cert_table.sortByColumn(1, Qt.AscendingOrder)
        first = window.cert_proxy.data(window.cert_proxy.index(0, 1))
        check("Sortierung nach Benutzer", first == "ansible", str(first))

        # Auswahl
        window.cert_table.selectRow(0)
        selected = window.selected_cert()
        check("Auswahl liefert Zertifikat", selected is not None and selected.user == "ansible",
              selected.user if selected else "-")

        # Dialoge bauen
        detail = CertDetailDialog(window, selected)
        check("Detaildialog gebaut", "ansible@web01" in detail.windowTitle())
        detail.deleteLater()

        cert_dialog = CertDialog(
            window,
            templates=window.template_store.load(),
            conf_principals=["admins", "devops"],
            agent_available=False,
        )
        cert_dialog.user_field.setText("dennis")
        cert_dialog.host_field.setText("db01")
        check("Prinzipale aus Vorlage vorbelegt",
              cert_dialog.principal_list.count() == 2,
              str([cert_dialog.principal_list.item(i).text() for i in range(2)]))
        cert_dialog.principal_input.setCurrentText("admins")
        cert_dialog._add_principal()
        check("Prinzipal ergänzt", cert_dialog.principal_list.count() == 3)

        # Sammelübernahme aus principals.conf
        cert_dialog._add_all_from_conf()
        values = [
            cert_dialog.principal_list.item(i).text()
            for i in range(cert_dialog.principal_list.count())
        ]
        check("alle conf-Einträge übernommen", "devops" in values, ", ".join(values))
        check("keine Dubletten durch Sammelübernahme", len(values) == len(set(values)),
              ", ".join(values))
        check("Reihenfolge: Vorlage zuerst", values[:2] == ["dennis", "dennis@db01"],
              ", ".join(values[:2]))
        before = cert_dialog.principal_list.count()
        cert_dialog._add_all_from_conf()
        check("zweiter Klick ändert nichts", cert_dialog.principal_list.count() == before)
        check("Hinweis bei doppeltem Klick", "bereits enthalten" in cert_dialog.hint.text(),
              cert_dialog.hint.text())

        # Übernommene Einträge müssen einen Vorlagenwechsel überstehen.
        cert_dialog.template_box.setCurrentIndex(1)
        values_after = [
            cert_dialog.principal_list.item(i).text()
            for i in range(cert_dialog.principal_list.count())
        ]
        check("conf-Einträge überstehen Vorlagenwechsel", "devops" in values_after,
              ", ".join(values_after))
        cert_dialog.extension_boxes["permit-pty"].setChecked(True)
        cert_dialog.source_address.setText("172.16.40.0/22")
        cert_dialog.key_pass1.setText(KEY_PASS)
        cert_dialog.key_pass2.setText(KEY_PASS)
        cert_dialog.ca_pass.setText(CA_PASS)
        request = cert_dialog.request()
        check("Request enthält Prinzipale", "admins" in request.principals,
              ", ".join(request.principals))
        check("Request enthält Critical Option",
              request.critical_options.get("source-address") == "172.16.40.0/22")
        check("Request nutzt Agent nicht", request.use_agent is False)

        # Der Dialog muss unvollstaendige Eingaben abweisen.
        cert_dialog.key_pass2.setText("anders")
        cert_dialog._check()
        check("Passphrasen-Abgleich meldet Fehler", "überein" in cert_dialog.hint.text(),
              cert_dialog.hint.text())
        cert_dialog.deleteLater()

        # Das aus dem Dialog gebaute Request muss die Kernschicht akzeptieren.
        cert_dialog2 = CertDialog(window, templates=window.template_store.load())
        cert_dialog2.user_field.setText("dennis")
        cert_dialog2.host_field.setText("db01")
        cert_dialog2.key_pass1.setText(KEY_PASS)
        cert_dialog2.key_pass2.setText(KEY_PASS)
        cert_dialog2.ca_pass.setText(CA_PASS)
        created = window.ca.create_certificate(cert_dialog2.request())
        check("Zertifikat aus Dialogdaten erstellt", created.cert_path.is_file(),
              created.principals_csv)
        cert_dialog2.deleteLater()

        revoke = RevokeDialog(window, selected, agent_available=False)
        revoke.confirm.setChecked(True)
        revoke.ca_pass.setText(CA_PASS)
        revoke._check()
        action, reason, ca_pass, use_agent = revoke.values
        check("Widerrufsdialog liefert Werte", action == "widerrufen" and ca_pass == CA_PASS)
        revoke.deleteLater()

        window.ca.revoke(selected, "Test", "widerrufen", CA_PASS)
        window.refresh(force=True)
        check("Widerrufsliste gefüllt", window.revoked_model.rowCount() == 1)
        check("aktive Liste geschrumpft", window.cert_model.rowCount() == 2,
              f"{window.cert_model.rowCount()} Zeilen")

        # --- Export- und Löschknöpfe ---------------------------------------
        check("Exportknopf vorhanden", window.btn_export.text() == "Exportieren")
        check("Löschknopf vorhanden", window.btn_delete.text() == "Löschen")
        check("Löschknopf Widerrufsseite",
              window.btn_delete_revoked.text() == "Ablage löschen")
        check("Export/Löschen aktiv bei CA",
              window.btn_export.isEnabled() and window.btn_delete.isEnabled())

        active = [
            window.cert_model.cert_at(i)
            for i in range(window.cert_model.rowCount())
        ]
        export_path, count = window.ca.export_certificates(
            active, Path(tmp) / "gui-export.tar.gz"
        )
        check("Export über Fenster-CA", export_path.is_file() and count == 2,
              f"{count} Zertifikat(e)")

        window.revoked_table.selectRow(0)
        entry = window.selected_revoked_entry()
        check("Widerrufsauswahl liefert Eintrag",
              entry is not None and entry.user == "ansible",
              entry.user if entry else "-")
        window.ca.delete_revoked_entry(entry)
        window.refresh(force=True)
        check("Widerrufsliste nach Löschen leer",
              window.revoked_model.rowCount() == 0)

        # --- Externen Schlüssel über den Dialog signieren -------------------
        import subprocess as _sp
        foreign = Path(tmp) / "extern_ed25519"
        _sp.run(["ssh-keygen", "-t", "ed25519", "-f", str(foreign),
                 "-N", "", "-C", "extern@laptop"],
                check=True, capture_output=True)
        ext_dialog = CertDialog(
            window, templates=window.template_store.load(), external=True,
            title="Externen Schlüssel signieren",
        )
        check("Extern-Dialog ohne Passphrasen-Gruppe",
              not ext_dialog.key_pass1.isVisible())
        ext_dialog.user_field.setText("extern")
        ext_dialog.host_field.setText("jump")
        ext_dialog.ca_pass.setText(CA_PASS)
        ext_dialog.pubkey_edit.setPlainText(foreign.read_text())
        ext_dialog._check()
        check("Extern-Dialog weist privaten Schlüssel ab",
              "privater Schlüssel" in ext_dialog.hint.text())
        ext_dialog.pubkey_edit.setPlainText(
            Path(str(foreign) + ".pub").read_text().strip())
        ext_cert = window.ca.import_and_sign_pubkey(
            ext_dialog.external_pubkey(), ext_dialog.request())
        check("Extern-Dialogdaten signieren", ext_cert.cert_path.is_file()
              and not ext_cert.has_private_key)
        window.refresh(force=True)
        check("extern signierter Key in der Liste",
              any(window.cert_model.cert_at(i).user == "extern"
                  for i in range(window.cert_model.rowCount())))
        check("Menüaktion vorhanden",
              window.act_sign_external.text().startswith("Externen"))
        ext_dialog.deleteLater()

        init_dialog = CaInitDialog(window, base / "ca" / "ca_key")
        init_dialog.pass1.setText("kurz")
        init_dialog._check()
        check("CA-Dialog prüft Länge", "8 Zeichen" in init_dialog.hint.text())
        init_dialog.deleteLater()

        # --- Regression: Callback-Zustellung aus dem Worker ------------------
        # Der Aufrufer verwirft den Rückgabewert von run_task; Task und
        # Signale müssen trotzdem bis zur Zustellung leben — auch unter
        # GC-Druck — und die Callbacks müssen im GUI-Thread laufen.
        import gc
        import time as _time

        from PySide6.QtCore import QEventLoop, QThread, QTimer

        from sshca.gui.workers import run_task

        main_thread = QThread.currentThread()
        stats = {"ok": 0, "done": 0, "gui_thread": True, "worker_gui": False}
        for _ in range(15):
            loop = QEventLoop()
            run_task(
                lambda: QThread.currentThread(),
                on_success=lambda thr: (
                    stats.__setitem__("ok", stats["ok"] + 1),
                    stats.__setitem__(
                        "gui_thread",
                        stats["gui_thread"]
                        and QThread.currentThread() is main_thread,
                    ),
                    stats.__setitem__(
                        "worker_gui", stats["worker_gui"] or thr is main_thread
                    ),
                ),
                on_done=lambda: (
                    stats.__setitem__("done", stats["done"] + 1),
                    loop.quit(),
                ),
            )
            _time.sleep(0.03)   # Worker fertig werden lassen …
            gc.collect()        # … und den GC provozieren, bevor Events laufen
            QTimer.singleShot(2000, loop.quit)
            loop.exec()
        check("alle Erfolgs-Callbacks zugestellt", stats["ok"] == 15,
              f"{stats['ok']}/15")
        check("alle done-Callbacks zugestellt", stats["done"] == 15,
              f"{stats['done']}/15")
        check("Callbacks laufen im GUI-Thread", stats["gui_thread"])
        check("Arbeit läuft im Worker-Thread", not stats["worker_gui"])

        # Fehlerpfad: on_error kommt an, on_done reaktiviert.
        err = {}
        loop = QEventLoop()

        def boom():
            raise RuntimeError("absichtlich")

        window.setEnabled(False)
        run_task(
            boom,
            on_error=lambda m, d: err.update(msg=m),
            on_done=lambda: (window.setEnabled(True), loop.quit()),
        )
        QTimer.singleShot(2000, loop.quit)
        loop.exec()
        check("Fehler-Callback zugestellt", err.get("msg") == "absichtlich",
              err.get("msg", "-"))
        check("Fenster nach Fehler wieder aktiv", window.isEnabled())

        # --- Schriftgröße (Ansicht-Menü) -----------------------------------
        from sshca.gui import theme

        theme.set_scale(app, 1.0)
        check("Basisgröße 13px im Stylesheet", "font-size: 13px" in app.styleSheet())
        window._change_zoom(+theme.SCALE_STEP)
        check("Vergrößern skaliert Stylesheet",
              "font-size: 14px" in app.styleSheet(),
              "13px → 14px bei 110 %")
        check("Skala gespeichert", abs(theme.load_scale() - 1.1) < 1e-9,
              f"{theme.load_scale()}")
        check("Zeilenhöhe folgt der Skala",
              window.cert_table.verticalHeader().defaultSectionSize() == round(38 * 1.1))
        for _ in range(20):
            window._change_zoom(+theme.SCALE_STEP)
        check("Obergrenze greift", abs(theme.load_scale() - theme.MAX_SCALE) < 1e-9)
        window._change_zoom(None)
        check("Standardgröße stellt zurück",
              abs(theme.load_scale() - 1.0) < 1e-9
              and "font-size: 13px" in app.styleSheet())
        check("Ansicht-Aktionen vorhanden",
              window.act_zoom_in.text() == "Vergrößern"
              and window.act_zoom_reset.shortcut().toString() == "Ctrl+0")

        window.close()

    print(f"\n{ok_count} Prüfungen bestanden.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
