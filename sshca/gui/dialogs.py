"""Dialoge der Anwendung."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..ca import CertRequest
from ..model import CertInfo, parse_validity_spec
from ..templates import KNOWN_CRITICAL_OPTIONS, KNOWN_EXTENSIONS, Template

VALIDITY_PRESETS = ["+15m", "+1h", "+9h", "+1d", "+1w", "+52w"]


def monospace() -> QFont:
    font = QFont("JetBrains Mono")
    font.setStyleHint(QFont.Monospace)
    font.setFixedPitch(True)
    return font


class PassphraseDialog(QDialog):
    """Fragt eine Passphrase ab, optional mit Bestaetigung."""

    def __init__(self, parent=None, title="Passphrase", prompt="",
                 confirm=False, allow_empty=False) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)
        self.allow_empty = allow_empty

        layout = QVBoxLayout(self)
        if prompt:
            label = QLabel(prompt)
            label.setWordWrap(True)
            layout.addWidget(label)

        form = QFormLayout()
        self.field = QLineEdit()
        self.field.setEchoMode(QLineEdit.Password)
        form.addRow("Passphrase:", self.field)

        self.confirm_field: QLineEdit | None = None
        if confirm:
            self.confirm_field = QLineEdit()
            self.confirm_field.setEchoMode(QLineEdit.Password)
            form.addRow("Wiederholen:", self.confirm_field)
        layout.addLayout(form)

        show = QCheckBox("Passphrase anzeigen")
        show.toggled.connect(self._toggle_echo)
        layout.addWidget(show)

        self.hint = QLabel("")
        self.hint.setObjectName("hintError")
        layout.addWidget(self.hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._check_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.field.setFocus()

    def _toggle_echo(self, visible: bool) -> None:
        mode = QLineEdit.Normal if visible else QLineEdit.Password
        self.field.setEchoMode(mode)
        if self.confirm_field:
            self.confirm_field.setEchoMode(mode)

    def _check_and_accept(self) -> None:
        value = self.field.text()
        if not value and not self.allow_empty:
            self.hint.setText("Bitte eine Passphrase eingeben.")
            return
        if self.confirm_field and value != self.confirm_field.text():
            self.hint.setText("Die Eingaben stimmen nicht überein.")
            return
        self.accept()

    @property
    def passphrase(self) -> str:
        return self.field.text()

    @classmethod
    def ask(cls, parent, title, prompt, confirm=False, allow_empty=False) -> str | None:
        dialog = cls(parent, title, prompt, confirm, allow_empty)
        if dialog.exec() == QDialog.Accepted:
            return dialog.passphrase
        return None


class CaInitDialog(QDialog):
    """Legt eine neue CA an."""

    def __init__(self, parent=None, ca_path: Path | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Certificate Authority anlegen")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Der CA-Schlüssel wird als ed25519 mit 100 KDF-Runden erzeugt und "
            "mit einer Passphrase geschützt. Er ist die Wurzel des Vertrauens: "
            "wer ihn besitzt, kann sich auf allen Zielsystemen anmelden."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.comment = QLineEdit("ssh-ca")
        form.addRow("Kommentar:", self.comment)
        if ca_path:
            path_label = QLabel(str(ca_path))
            path_label.setFont(monospace())
            form.addRow("Ablage:", path_label)
        self.pass1 = QLineEdit()
        self.pass1.setEchoMode(QLineEdit.Password)
        self.pass2 = QLineEdit()
        self.pass2.setEchoMode(QLineEdit.Password)
        form.addRow("Passphrase:", self.pass1)
        form.addRow("Wiederholen:", self.pass2)
        layout.addLayout(form)

        self.hint = QLabel("")
        self.hint.setObjectName("hintError")
        layout.addWidget(self.hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("CA anlegen")
        buttons.button(QDialogButtonBox.Ok).setObjectName("primary")
        buttons.accepted.connect(self._check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _check(self) -> None:
        if len(self.pass1.text()) < 8:
            self.hint.setText("Die Passphrase sollte mindestens 8 Zeichen haben.")
            return
        if self.pass1.text() != self.pass2.text():
            self.hint.setText("Die Eingaben stimmen nicht überein.")
            return
        self.accept()

    @property
    def passphrase(self) -> str:
        return self.pass1.text()

    @property
    def comment_text(self) -> str:
        return self.comment.text().strip() or "ssh-ca"


class CertDialog(QDialog):
    """Erstellt oder erneuert ein Zertifikat."""

    def __init__(
        self,
        parent=None,
        templates: list[Template] | None = None,
        conf_principals: list[str] | None = None,
        agent_available: bool = False,
        fixed: tuple[str, str] | None = None,
        title: str = "Neues Zertifikat",
        external: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(620)
        self.templates = templates or []
        self.conf_principals = conf_principals or []
        self.external = external

        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        tabs.addTab(self._build_general_tab(fixed), "Allgemein")
        tabs.addTab(self._build_extensions_tab(), "Extensions")
        tabs.addTab(
            self._build_security_tab(agent_available),
            "Schlüssel && Signatur" if not external else "Signatur",
        )
        layout.addWidget(tabs)

        self.hint = QLabel("")
        self.hint.setObjectName("hintError")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Zertifikat erstellen")
        buttons.button(QDialogButtonBox.Ok).setObjectName("primary")
        buttons.accepted.connect(self._check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if self.templates:
            self._apply_template(0)

    # -- Reiter -----------------------------------------------------------
    def _build_general_tab(self, fixed: tuple[str, str] | None) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        form = QFormLayout()
        self.template_box = QComboBox()
        for template in self.templates:
            self.template_box.addItem(template.name)
        self.template_box.currentIndexChanged.connect(self._apply_template)
        form.addRow("Vorlage:", self.template_box)

        self.user_field = QLineEdit()
        self.host_field = QLineEdit()
        if fixed:
            self.user_field.setText(fixed[0])
            self.host_field.setText(fixed[1])
            self.user_field.setReadOnly(True)
            self.host_field.setReadOnly(True)
        self.user_field.textChanged.connect(self._refresh_default_principals)
        self.host_field.textChanged.connect(self._refresh_default_principals)
        form.addRow("Benutzer:", self.user_field)
        form.addRow("Zielhost:", self.host_field)

        self.validity_box = QComboBox()
        self.validity_box.setEditable(True)
        self.validity_box.addItems(VALIDITY_PRESETS)
        self.validity_box.currentTextChanged.connect(self._update_validity_preview)
        form.addRow("Gültigkeit:", self.validity_box)

        self.validity_preview = QLabel("")
        self.validity_preview.setObjectName("noteMuted")
        form.addRow("", self.validity_preview)
        outer.addLayout(form)

        group = QGroupBox("Prinzipale")
        box = QVBoxLayout(group)
        explain = QLabel(
            "Prinzipale entscheiden, als welcher Benutzer die Anmeldung auf dem "
            "Zielsystem möglich ist. Der erste Eintrag wird zusätzlich als "
            "Kommentar des Schlüssels gesetzt."
        )
        explain.setWordWrap(True)
        explain.setObjectName("noteMuted")
        box.addWidget(explain)

        self.principal_list = QListWidget()
        self.principal_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.principal_list.setMinimumHeight(120)
        box.addWidget(self.principal_list)

        row = QHBoxLayout()
        self.principal_input = QComboBox()
        self.principal_input.setEditable(True)
        self.principal_input.addItems(self.conf_principals)
        self.principal_input.setCurrentText("")
        self.principal_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        add_button = QPushButton("Hinzufügen")
        add_button.clicked.connect(self._add_principal)
        remove_button = QPushButton("Entfernen")
        remove_button.clicked.connect(self._remove_principal)
        row.addWidget(self.principal_input)
        row.addWidget(add_button)
        row.addWidget(remove_button)
        box.addLayout(row)

        conf_row = QHBoxLayout()
        self.add_all_button = QPushButton(
            f"Alle aus principals.conf übernehmen ({len(self.conf_principals)})"
        )
        self.add_all_button.clicked.connect(self._add_all_from_conf)
        self.add_all_button.setEnabled(bool(self.conf_principals))
        if self.conf_principals:
            self.add_all_button.setToolTip("\n".join(self.conf_principals))
        else:
            self.add_all_button.setText("Alle aus principals.conf übernehmen")
            self.add_all_button.setToolTip(
                "In principals.conf sind keine Einträge hinterlegt."
            )
        conf_row.addWidget(self.add_all_button)
        conf_row.addStretch(1)
        box.addLayout(conf_row)
        outer.addWidget(group)
        return page

    def _build_extensions_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        group = QGroupBox("Extensions")
        box = QVBoxLayout(group)
        note = QLabel(
            "Ohne gesetzte Extensions erlaubt das Zertifikat nur die Anmeldung "
            "selbst — kein Terminal, keine Weiterleitung."
        )
        note.setWordWrap(True)
        note.setObjectName("noteMuted")
        box.addWidget(note)
        self.extension_boxes: dict[str, QCheckBox] = {}
        for name, description in KNOWN_EXTENSIONS.items():
            check = QCheckBox(f"{name} — {description}")
            self.extension_boxes[name] = check
            box.addWidget(check)
        outer.addWidget(group)

        group2 = QGroupBox("Critical Options")
        form = QFormLayout(group2)
        note2 = QLabel(
            "Diese Angaben muss das Zielsystem verstehen, sonst wird das "
            "Zertifikat abgelehnt. Leer lassen heißt: nicht gesetzt."
        )
        note2.setWordWrap(True)
        note2.setObjectName("noteMuted")
        form.addRow(note2)
        self.force_command = QLineEdit()
        self.force_command.setPlaceholderText(KNOWN_CRITICAL_OPTIONS["force-command"])
        self.source_address = QLineEdit()
        self.source_address.setPlaceholderText(KNOWN_CRITICAL_OPTIONS["source-address"])
        self.verify_required = QCheckBox(KNOWN_CRITICAL_OPTIONS["verify-required"])
        form.addRow("force-command:", self.force_command)
        form.addRow("source-address:", self.source_address)
        form.addRow("verify-required:", self.verify_required)
        outer.addWidget(group2)
        outer.addStretch(1)
        return page

    def _build_security_tab(self, agent_available: bool) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)

        if self.external:
            group0 = QGroupBox("Eingereichter öffentlicher Schlüssel")
            box0 = QVBoxLayout(group0)
            note0 = QLabel(
                "Der Benutzer reicht nur den öffentlichen Teil (.pub) ein — "
                "ein privater Schlüssel wird hier weder erzeugt noch "
                "gespeichert. Der Dateiname im Bestand richtet sich nach dem "
                "Schlüsseltyp."
            )
            note0.setWordWrap(True)
            note0.setObjectName("noteMuted")
            box0.addWidget(note0)
            self.pubkey_edit = QPlainTextEdit()
            self.pubkey_edit.setPlaceholderText(
                "ssh-ed25519 AAAA… benutzer@rechner  (oder Datei laden)"
            )
            self.pubkey_edit.setFont(monospace())
            self.pubkey_edit.setMaximumHeight(96)
            box0.addWidget(self.pubkey_edit)
            load_button = QPushButton("Aus Datei laden …")
            load_button.clicked.connect(self._load_pubkey_file)
            row0 = QHBoxLayout()
            row0.addWidget(load_button)
            row0.addStretch(1)
            box0.addLayout(row0)
            outer.addWidget(group0)

        group = QGroupBox("Passphrase des neuen Schlüssels")
        form = QFormLayout(group)
        self.key_pass1 = QLineEdit()
        self.key_pass1.setEchoMode(QLineEdit.Password)
        self.key_pass2 = QLineEdit()
        self.key_pass2.setEchoMode(QLineEdit.Password)
        form.addRow("Passphrase:", self.key_pass1)
        form.addRow("Wiederholen:", self.key_pass2)
        self.empty_key_pass = QCheckBox(
            "Ohne Passphrase erzeugen (nur für Automatisierung sinnvoll)"
        )
        form.addRow("", self.empty_key_pass)
        outer.addWidget(group)
        if self.external:
            # Eingehängt (damit Qt die Widgets nicht wegräumt), aber
            # unsichtbar: bei externen Schlüsseln gibt es keine Passphrase.
            group.setVisible(False)

        group2 = QGroupBox("Signatur durch die CA")
        form2 = QFormLayout(group2)
        self.use_agent = QCheckBox("CA-Schlüssel aus dem ssh-agent verwenden")
        self.use_agent.setEnabled(agent_available)
        self.use_agent.setChecked(agent_available)
        if not agent_available:
            self.use_agent.setToolTip(
                "Der CA-Schlüssel ist derzeit nicht im ssh-agent geladen."
            )
        self.use_agent.toggled.connect(self._toggle_ca_pass)
        form2.addRow(self.use_agent)
        self.ca_pass = QLineEdit()
        self.ca_pass.setEchoMode(QLineEdit.Password)
        form2.addRow("CA-Passphrase:", self.ca_pass)
        outer.addWidget(group2)

        hint = QLabel(
            "Liegt der CA-Schlüssel im Agent, verlässt die CA-Passphrase diesen "
            "Prozess nie. Derselbe Weg trägt später einen CA-Schlüssel auf "
            "Smartcard oder Token."
        )
        hint.setWordWrap(True)
        hint.setObjectName("noteMuted")
        outer.addWidget(hint)
        outer.addStretch(1)
        self._toggle_ca_pass(self.use_agent.isChecked())
        return page

    # -- Verhalten --------------------------------------------------------
    def _toggle_ca_pass(self, use_agent: bool) -> None:
        self.ca_pass.setEnabled(not use_agent)
        self.ca_pass.setPlaceholderText(
            "wird über den Agent bereitgestellt" if use_agent else ""
        )

    def _apply_template(self, index: int) -> None:
        if not (0 <= index < len(self.templates)):
            return
        template = self.templates[index]
        self.validity_box.setCurrentText(template.validity)
        for name, check in self.extension_boxes.items():
            check.setChecked(name in template.extensions)
        self.force_command.setText(template.critical_options.get("force-command", ""))
        self.source_address.setText(template.critical_options.get("source-address", ""))
        self.verify_required.setChecked("verify-required" in template.critical_options)
        self._refresh_default_principals()

    def _refresh_default_principals(self) -> None:
        """Setzt die Vorgaben der Vorlage neu, behaelt manuelle Eintraege bei."""
        index = self.template_box.currentIndex()
        if not (0 <= index < len(self.templates)):
            return
        user = self.user_field.text().strip()
        host = self.host_field.text().strip()
        defaults = self.templates[index].principals_for(user or "{user}", host or "{host}")
        manual = [
            self.principal_list.item(i).text()
            for i in range(self.principal_list.count())
            if self.principal_list.item(i).data(Qt.UserRole) == "manual"
        ]
        self.principal_list.clear()
        for value in defaults:
            self.principal_list.addItem(value)
        for value in manual:
            if value not in defaults:
                item_index = self.principal_list.count()
                self.principal_list.addItem(value)
                self.principal_list.item(item_index).setData(Qt.UserRole, "manual")

    def _add_principal(self) -> None:
        value = self.principal_input.currentText().strip()
        if not value:
            return
        existing = {
            self.principal_list.item(i).text()
            for i in range(self.principal_list.count())
        }
        if value in existing:
            return
        self.principal_list.addItem(value)
        self.principal_list.item(self.principal_list.count() - 1).setData(
            Qt.UserRole, "manual"
        )
        self.principal_input.setCurrentText("")

    def _add_all_from_conf(self) -> None:
        """Uebernimmt alle Eintraege aus principals.conf in einem Schritt.

        Bereits vorhandene Prinzipale werden uebersprungen, die Reihenfolge der
        Datei bleibt erhalten. Die Eintraege gelten als manuell gesetzt und
        ueberstehen damit einen Wechsel der Vorlage.
        """
        existing = {
            self.principal_list.item(i).text()
            for i in range(self.principal_list.count())
        }
        added = 0
        for value in self.conf_principals:
            value = value.strip()
            if not value or value in existing:
                continue
            self.principal_list.addItem(value)
            self.principal_list.item(self.principal_list.count() - 1).setData(
                Qt.UserRole, "manual"
            )
            existing.add(value)
            added += 1
        if added:
            self.hint.setText("")
            self.principal_list.scrollToBottom()
        else:
            self.hint.setText("Alle Einträge aus principals.conf sind bereits enthalten.")

    def _remove_principal(self) -> None:
        for item in self.principal_list.selectedItems():
            self.principal_list.takeItem(self.principal_list.row(item))

    def _update_validity_preview(self, text: str) -> None:
        span = parse_validity_spec(text)
        if span:
            self.validity_preview.setText(
                f"gültig bis {span[1]:%Y-%m-%d %H:%M}"
            )
        else:
            self.validity_preview.setText(
                "Angabe wird unverändert an ssh-keygen übergeben"
            )

    def _load_pubkey_file(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        from pathlib import Path as _Path

        path, _ = QFileDialog.getOpenFileName(
            self, "Öffentlichen Schlüssel wählen", str(_Path.home()),
            "Public Key (*.pub);;Alle Dateien (*)",
        )
        if path:
            self.pubkey_edit.setPlainText(
                _Path(path).read_text(encoding="utf-8").strip()
            )

    def external_pubkey(self) -> str:
        return self.pubkey_edit.toPlainText().strip() if self.external else ""

    def _check(self) -> None:
        if not self.user_field.text().strip() or not self.host_field.text().strip():
            self.hint.setText("Benutzer und Zielhost werden benötigt.")
            return
        if self.principal_list.count() == 0:
            self.hint.setText("Mindestens ein Prinzipal wird benötigt.")
            return
        if self.external:
            text = self.external_pubkey()
            if "PRIVATE KEY" in text:
                self.hint.setText(
                    "Das ist ein privater Schlüssel — bitte den öffentlichen "
                    "Teil (.pub) einreichen."
                )
                return
            if not text or not text.split(None, 1)[0].startswith(
                ("ssh-", "ecdsa-", "sk-")
            ):
                self.hint.setText(
                    "Bitte einen öffentlichen Schlüssel einfügen oder laden."
                )
                return
        if not self.external and not self.empty_key_pass.isChecked():
            if len(self.key_pass1.text()) < 8:
                self.hint.setText(
                    "Die Passphrase des Schlüssels sollte mindestens 8 Zeichen haben."
                )
                return
            if self.key_pass1.text() != self.key_pass2.text():
                self.hint.setText("Die Passphrasen des Schlüssels stimmen nicht überein.")
                return
        if not self.use_agent.isChecked() and not self.ca_pass.text():
            self.hint.setText("Die CA-Passphrase wird zum Signieren benötigt.")
            return
        self.accept()

    # -- Ergebnis ---------------------------------------------------------
    def request(self) -> CertRequest:
        principals = [
            self.principal_list.item(i).text()
            for i in range(self.principal_list.count())
        ]
        extensions = [
            name for name, check in self.extension_boxes.items() if check.isChecked()
        ]
        critical: dict[str, str] = {}
        if self.force_command.text().strip():
            critical["force-command"] = self.force_command.text().strip()
        if self.source_address.text().strip():
            critical["source-address"] = self.source_address.text().strip()
        if self.verify_required.isChecked():
            critical["verify-required"] = ""
        return CertRequest(
            user=self.user_field.text().strip(),
            host=self.host_field.text().strip(),
            principals=principals,
            validity=self.validity_box.currentText().strip() or "+1h",
            extensions=extensions,
            critical_options=critical,
            key_passphrase="" if self.empty_key_pass.isChecked() else self.key_pass1.text(),
            ca_passphrase=self.ca_pass.text(),
            use_agent=self.use_agent.isChecked(),
        )


class CertDetailDialog(QDialog):
    """Zeigt alle Felder eines Zertifikats plus die Rohausgabe."""

    def __init__(self, parent, cert: CertInfo) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Zertifikat {cert.user}@{cert.host}")
        self.setMinimumSize(720, 560)
        self.cert = cert

        layout = QVBoxLayout(self)
        tabs = QTabWidget()

        overview = QWidget()
        form = QFormLayout(overview)
        status = QLabel(cert.status_text())
        status.setStyleSheet(f"color: {cert.status().color}; font-weight: bold;")
        form.addRow("Status:", status)
        for label, value in [
            ("Benutzer:", cert.user),
            ("Zielhost:", cert.host),
            ("Typ:", cert.cert_type),
            ("Key ID:", cert.key_id),
            ("Seriennummer:", cert.serial),
            ("Gültigkeit:", cert.validity_text),
            ("Prinzipale:", "\n".join(cert.principals) or "(keine)"),
            ("Extensions:", "\n".join(sorted(cert.extensions)) or "(keine)"),
            (
                "Critical Options:",
                "\n".join(
                    f"{k}={v}" if v else k for k, v in cert.critical_options.items()
                )
                or "(keine)",
            ),
            ("Fingerprint:", cert.pubkey_fp),
            ("Signierende CA:", cert.ca_fp),
            ("Zertifikatsdatei:", str(cert.cert_path)),
            (
                "Privater Schlüssel:",
                str(cert.key_path) if cert.has_private_key else "fehlt",
            ),
        ]:
            field = QLabel(value)
            field.setTextInteractionFlags(Qt.TextSelectableByMouse)
            field.setFont(monospace())
            form.addRow(label, field)
        tabs.addTab(overview, "Übersicht")

        raw = QPlainTextEdit(cert.raw or cert.parse_error)
        raw.setReadOnly(True)
        raw.setFont(monospace())
        tabs.addTab(raw, "ssh-keygen -L")

        usage = QPlainTextEdit(self._usage_text(cert))
        usage.setReadOnly(True)
        usage.setFont(monospace())
        tabs.addTab(usage, "Verwendung")

        layout.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        copy_button = QPushButton("Zertifikat kopieren")
        copy_button.clicked.connect(self._copy_cert)
        buttons.addButton(copy_button, QDialogButtonBox.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _usage_text(cert: CertInfo) -> str:
        return (
            "Anmeldung mit diesem Zertifikat\n"
            "-------------------------------\n"
            f"ssh -i {cert.key_path} {cert.principals[0] if cert.principals else cert.user}@{cert.host}\n\n"
            "Schlüssel in den Agent laden (Passphrase nur einmal eingeben):\n"
            f"ssh-add {cert.key_path}\n\n"
            "Key und Zertifikat müssen nebeneinander liegen — OpenSSH findet das\n"
            "Zertifikat anhand des Namens <key>-cert.pub automatisch.\n"
        )

    def _copy_cert(self) -> None:
        if self.cert.cert_path.is_file():
            QGuiApplication.clipboard().setText(
                self.cert.cert_path.read_text(encoding="utf-8")
            )


class RevokeDialog(QDialog):
    """Widerruf oder Sperrung — beides ist endgueltig."""

    def __init__(self, parent, cert: CertInfo, agent_available: bool) -> None:
        super().__init__(parent)
        self.setWindowTitle("Zertifikat widerrufen")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        warning = QLabel(
            f"Das Zertifikat für <b>{cert.user}@{cert.host}</b> wird in die KRL "
            "aufgenommen und das Schlüsselmaterial nach <code>revoked/</code> "
            "verschoben. Eine KRL kennt keine Rücknahme: Zugang entsteht danach "
            "nur über ein neues Zertifikat."
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        form = QFormLayout()
        self.action_box = QComboBox()
        self.action_box.addItem("widerrufen — gilt nicht mehr", "widerrufen")
        self.action_box.addItem("gesperrt — Material kompromittiert", "gesperrt")
        form.addRow("Art:", self.action_box)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("z. B. Benutzer ausgeschieden")
        form.addRow("Grund:", self.reason)
        self.ca_pass = QLineEdit()
        self.ca_pass.setEchoMode(QLineEdit.Password)
        form.addRow("CA-Passphrase:", self.ca_pass)
        layout.addLayout(form)

        self.use_agent = QCheckBox("CA-Schlüssel aus dem ssh-agent verwenden")
        self.use_agent.setEnabled(agent_available)
        self.use_agent.setChecked(agent_available)
        self.use_agent.toggled.connect(lambda on: self.ca_pass.setEnabled(not on))
        self.ca_pass.setEnabled(not self.use_agent.isChecked())
        layout.addWidget(self.use_agent)

        self.confirm = QCheckBox("Ich habe verstanden, dass der Vorgang endgültig ist")
        layout.addWidget(self.confirm)

        self.hint = QLabel("")
        self.hint.setObjectName("hintError")
        layout.addWidget(self.hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Widerrufen")
        buttons.button(QDialogButtonBox.Ok).setObjectName("danger")
        buttons.accepted.connect(self._check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _check(self) -> None:
        if not self.confirm.isChecked():
            self.hint.setText("Bitte den Vorgang bestätigen.")
            return
        if not self.use_agent.isChecked() and not self.ca_pass.text():
            self.hint.setText("Die CA-Passphrase wird für die KRL benötigt.")
            return
        self.accept()

    @property
    def values(self) -> tuple[str, str, str, bool]:
        return (
            self.action_box.currentData(),
            self.reason.text().strip(),
            self.ca_pass.text(),
            self.use_agent.isChecked(),
        )


class TextViewDialog(QDialog):
    """Einfacher Textbetrachter fuer Log, CA-Key und Anleitung."""

    def __init__(self, parent, title: str, text: str, mono: bool = True) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 620)
        layout = QVBoxLayout(self)
        view = QPlainTextEdit(text)
        view.setReadOnly(True)
        if mono:
            view.setFont(monospace())
        layout.addWidget(view)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        copy_button = QPushButton("In die Zwischenablage")
        copy_button.clicked.connect(lambda: QGuiApplication.clipboard().setText(text))
        buttons.addButton(copy_button, QDialogButtonBox.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def error_box(parent, title: str, message: str, details: str = "") -> None:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Warning)
    box.setWindowTitle(title)
    box.setText(message)
    if details:
        box.setDetailedText(details)
    box.exec()


def info_box(parent, title: str, message: str) -> None:
    QMessageBox.information(parent, title, message)


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")
