"""Hauptfenster.

Aufbau: links eine Seitenleiste mit den Bereichen (mit Zaehlern), rechts pro
Bereich eine Seite mit Kopfzeile und Inhalt. Alle Funktionen entsprechen dem
vorherigen Stand — geaendert ist nur die Darstellung.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QStatusBar,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ..ca import CaError, CertificateAuthority, CertRequest
from ..config import APP_NAME, APP_VERSION, DEPLOYMENT_HELP, Paths
from ..keygen import SshKeygenError
from ..model import CertInfo
from ..store import CertIndex, refresh_index
from ..templates import TemplateStore
from .dialogs import (
    CaInitDialog,
    CertDetailDialog,
    CertDialog,
    PassphraseDialog,
    RevokeDialog,
    TextViewDialog,
    error_box,
    info_box,
    monospace,
)
from .models import CertFilterProxy, CertTableModel, RevokedTableModel
from . import theme
from .theme import StatusPillDelegate
from .workers import run_task


PAGE_CERTS, PAGE_REVOKED, PAGE_CA = range(3)


def page_header(title: str, subtitle: str) -> tuple[QWidget, QLabel, QHBoxLayout]:
    """Kopfzeile einer Seite: Titel, Untertitel, rechts Platz fuer Aktionen."""
    wrap = QWidget()
    row = QHBoxLayout(wrap)
    row.setContentsMargins(0, 0, 0, 0)
    text_col = QVBoxLayout()
    text_col.setSpacing(2)
    title_label = QLabel(title)
    title_label.setObjectName("pageTitle")
    subtitle_label = QLabel(subtitle)
    subtitle_label.setObjectName("pageSubtitle")
    subtitle_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
    subtitle_label.setMinimumWidth(0)
    text_col.addWidget(title_label)
    text_col.addWidget(subtitle_label)
    row.addLayout(text_col)
    row.addStretch(1)
    actions = QHBoxLayout()
    actions.setSpacing(8)
    row.addLayout(actions)
    return wrap, subtitle_label, actions


class MainWindow(QMainWindow):
    def __init__(self, base: Path | None = None) -> None:
        super().__init__()
        self.paths = Paths(base)
        self.ca = CertificateAuthority(self.paths)
        self.index = CertIndex(self.paths.index_db)
        self.template_store = TemplateStore(self.paths.templates_file)

        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1280, 760)

        self._build_actions()
        self._build_menu()
        self._build_central()
        self.setStatusBar(QStatusBar())

        self.refresh()
        self._apply_row_heights(theme.load_scale())
        # Restlaufzeiten laufen weiter, auch wenn niemand etwas anklickt.
        self._clock = QTimer(self)
        self._clock.timeout.connect(self._repaint_table)
        self._clock.start(30_000)

    # ------------------------------------------------------------ Aktionen
    def _build_actions(self) -> None:
        self.act_new = QAction("Neues Zertifikat", self)
        self.act_new.setShortcut(QKeySequence.New)
        self.act_new.triggered.connect(self.new_certificate)

        self.act_details = QAction("Details", self)
        self.act_details.triggered.connect(self.show_details)

        self.act_renew = QAction("Erneuern", self)
        self.act_renew.triggered.connect(self.renew_certificate)

        self.act_revoke = QAction("Widerrufen", self)
        self.act_revoke.triggered.connect(self.revoke_certificate)

        self.act_export = QAction("Gültige exportieren …", self)
        self.act_export.triggered.connect(self.export_certificates)

        self.act_delete = QAction("Ungültiges löschen", self)
        self.act_delete.triggered.connect(self.delete_certificate)

        self.act_refresh = QAction("Aktualisieren", self)
        self.act_refresh.setShortcut(QKeySequence.Refresh)
        self.act_refresh.triggered.connect(lambda: self.refresh(force=True))

        self.act_ca_new = QAction("CA anlegen …", self)
        self.act_ca_new.triggered.connect(self.create_ca)

        self.act_ca_import = QAction("CA importieren …", self)
        self.act_ca_import.triggered.connect(self.import_ca)

        self.act_backup = QAction("Sichern …", self)
        self.act_backup.triggered.connect(self.backup)

        self.act_restore = QAction("Sicherung einspielen …", self)
        self.act_restore.triggered.connect(self.restore)

        self.act_deploy = QAction("Deployment-Anleitung", self)
        self.act_deploy.triggered.connect(self.show_deployment)

        self.act_log = QAction("Log anzeigen", self)
        self.act_log.triggered.connect(self.show_log)

        self.act_quit = QAction("Beenden", self)
        self.act_quit.setShortcut(QKeySequence.Quit)
        self.act_quit.triggered.connect(self.close)

        # -- Ansicht: Schriftgröße ----------------------------------------
        self.act_zoom_in = QAction("Vergrößern", self)
        self.act_zoom_in.setShortcuts([QKeySequence.ZoomIn, QKeySequence("Ctrl+=")])
        self.act_zoom_in.triggered.connect(lambda: self._change_zoom(+theme.SCALE_STEP))

        self.act_zoom_out = QAction("Verkleinern", self)
        self.act_zoom_out.setShortcut(QKeySequence.ZoomOut)
        self.act_zoom_out.triggered.connect(lambda: self._change_zoom(-theme.SCALE_STEP))

        self.act_zoom_reset = QAction("Standardgröße", self)
        self.act_zoom_reset.setShortcut(QKeySequence("Ctrl+0"))
        self.act_zoom_reset.triggered.connect(lambda: self._change_zoom(None))

    def _build_menu(self) -> None:
        menu = self.menuBar()
        file_menu = menu.addMenu("&Datei")
        file_menu.addAction(self.act_backup)
        file_menu.addAction(self.act_restore)
        file_menu.addSeparator()
        file_menu.addAction(self.act_quit)

        ca_menu = menu.addMenu("&CA")
        ca_menu.addAction(self.act_ca_new)
        ca_menu.addAction(self.act_ca_import)
        ca_menu.addSeparator()
        ca_menu.addAction(self.act_deploy)

        cert_menu = menu.addMenu("&Zertifikate")
        for action in (self.act_new, self.act_details, self.act_renew, self.act_revoke):
            cert_menu.addAction(action)
        cert_menu.addSeparator()
        cert_menu.addAction(self.act_export)
        cert_menu.addAction(self.act_delete)
        cert_menu.addSeparator()
        cert_menu.addAction(self.act_refresh)

        view_menu = menu.addMenu("&Ansicht")
        view_menu.addAction(self.act_zoom_in)
        view_menu.addAction(self.act_zoom_out)
        view_menu.addSeparator()
        view_menu.addAction(self.act_zoom_reset)

        help_menu = menu.addMenu("&Hilfe")
        help_menu.addAction(self.act_log)
        about = QAction("Über", self)
        about.triggered.connect(self.show_about)
        help_menu.addAction(about)

    # ------------------------------------------------------------- Aufbau
    def _build_central(self) -> None:
        central = QWidget()
        outer = QHBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # -- Seitenleiste --------------------------------------------------
        side_wrap = QWidget()
        side_wrap.setObjectName("sidebarWrap")
        side_wrap.setFixedWidth(216)
        side_col = QVBoxLayout(side_wrap)
        side_col.setContentsMargins(0, 0, 0, 0)
        side_col.setSpacing(0)

        app_title = QLabel("SSH-CA")
        app_title.setObjectName("appTitle")
        app_subtitle = QLabel("Certificate Manager")
        app_subtitle.setObjectName("appSubtitle")
        side_col.addWidget(app_title)
        side_col.addWidget(app_subtitle)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFrameShape(QFrame.NoFrame)
        for label in ("Zertifikate", "Widerrufen", "CA"):
            self.sidebar.addItem(QListWidgetItem(label))
        self.sidebar.setCurrentRow(PAGE_CERTS)
        side_col.addWidget(self.sidebar, 1)

        self.side_footer = QLabel("")
        self.side_footer.setObjectName("appSubtitle")
        self.side_footer.setWordWrap(True)
        side_col.addWidget(self.side_footer)
        outer.addWidget(side_wrap)

        # -- Seiten ----------------------------------------------------------
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_cert_page())
        self.pages.addWidget(self._build_revoked_page())
        self.pages.addWidget(self._build_ca_page())
        outer.addWidget(self.pages, 1)

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.setCentralWidget(central)

    def _build_cert_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        header, self.cert_subtitle, actions = page_header(
            "Zertifikate", "Aktive Schlüssel und Zertifikate dieser CA"
        )
        self.btn_details = QPushButton("Details")
        self.btn_details.clicked.connect(self.show_details)
        self.btn_renew = QPushButton("Erneuern")
        self.btn_renew.clicked.connect(self.renew_certificate)
        self.btn_export = QPushButton("Exportieren")
        self.btn_export.clicked.connect(self.export_certificates)
        self.btn_delete = QPushButton("Löschen")
        self.btn_delete.setObjectName("danger")
        self.btn_delete.setToolTip(
            "Löscht das Material eines abgelaufenen oder widerrufenen "
            "Zertifikats endgültig."
        )
        self.btn_delete.clicked.connect(self.delete_certificate)
        self.btn_revoke = QPushButton("Widerrufen")
        self.btn_revoke.setObjectName("danger")
        self.btn_revoke.clicked.connect(self.revoke_certificate)
        self.btn_new = QPushButton("Neues Zertifikat")
        self.btn_new.setObjectName("primary")
        self.btn_new.clicked.connect(self.new_certificate)
        for button in (
            self.btn_details,
            self.btn_renew,
            self.btn_export,
            self.btn_revoke,
            self.btn_delete,
            self.btn_new,
        ):
            actions.addWidget(button)
        layout.addWidget(header)

        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Filtern nach Benutzer, Host, Prinzipal, Seriennummer …"
        )
        self.search.setClearButtonEnabled(True)
        row.addWidget(self.search)
        self.hide_expired = QCheckBox("Abgelaufene ausblenden")
        row.addWidget(self.hide_expired)
        layout.addLayout(row)

        self.cert_model = CertTableModel(self)
        self.cert_proxy = CertFilterProxy(self)
        self.cert_proxy.setSourceModel(self.cert_model)
        self.search.textChanged.connect(self.cert_proxy.set_text)
        self.hide_expired.toggled.connect(self.cert_proxy.set_hide_expired)

        self.cert_table = QTableView()
        self.cert_table.setModel(self.cert_proxy)
        self.cert_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cert_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.cert_table.setSortingEnabled(True)
        self.cert_table.setAlternatingRowColors(True)
        self.cert_table.setShowGrid(False)
        self.cert_table.setWordWrap(False)
        self.cert_table.setTextElideMode(Qt.ElideRight)
        self.cert_table.setFrameShape(QFrame.NoFrame)
        self.cert_table.verticalHeader().setVisible(False)
        self.cert_table.verticalHeader().setDefaultSectionSize(38)
        self.cert_table.setItemDelegateForColumn(0, StatusPillDelegate(self.cert_table))
        self.cert_table.doubleClicked.connect(lambda _: self.show_details())
        header_view = self.cert_table.horizontalHeader()
        for column, (_, width) in enumerate(CertTableModel.COLUMNS):
            self.cert_table.setColumnWidth(column, width)
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(3, QHeaderView.Interactive)
        layout.addWidget(self.cert_table, 1)

        self.empty_hint = QLabel(
            "Noch keine Zertifikate.\nÜber „Neues Zertifikat“ das erste anlegen."
        )
        self.empty_hint.setObjectName("emptyState")
        self.empty_hint.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.empty_hint)
        return page

    def _build_revoked_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        header, self.revoked_subtitle, revoked_actions = page_header(
            "Widerrufen",
            "Vorgänge sind endgültig — die KRL kennt keine Rücknahme",
        )
        self.btn_delete_revoked = QPushButton("Ablage löschen")
        self.btn_delete_revoked.setObjectName("danger")
        self.btn_delete_revoked.setToolTip(
            "Entfernt das ausgelagerte Schlüsselmaterial endgültig.\n"
            "Der KRL-Eintrag bleibt bestehen — das Zertifikat bleibt auf den "
            "Zielsystemen ungültig."
        )
        self.btn_delete_revoked.clicked.connect(self.delete_revoked_entry)
        revoked_actions.addWidget(self.btn_delete_revoked)
        layout.addWidget(header)

        self.revoked_model = RevokedTableModel(self)
        self.revoked_table = QTableView()
        self.revoked_table.setModel(self.revoked_model)
        self.revoked_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.revoked_table.setAlternatingRowColors(True)
        self.revoked_table.setShowGrid(False)
        self.revoked_table.setWordWrap(False)
        self.revoked_table.setFrameShape(QFrame.NoFrame)
        self.revoked_table.verticalHeader().setVisible(False)
        self.revoked_table.verticalHeader().setDefaultSectionSize(38)
        self.revoked_table.setItemDelegateForColumn(
            0, StatusPillDelegate(self.revoked_table)
        )
        for column, (_, width) in enumerate(RevokedTableModel.COLUMNS):
            self.revoked_table.setColumnWidth(column, width)
        self.revoked_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.revoked_table, 1)
        return page

    def _build_ca_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        header, self.ca_subtitle, actions = page_header(
            "Certificate Authority", "Wurzel des Vertrauens dieser Umgebung"
        )
        self.btn_ca_new = QPushButton("CA anlegen")
        self.btn_ca_new.setObjectName("primary")
        self.btn_ca_new.clicked.connect(self.create_ca)
        self.btn_ca_import = QPushButton("CA importieren")
        self.btn_ca_import.clicked.connect(self.import_ca)
        actions.addWidget(self.btn_ca_import)
        actions.addWidget(self.btn_ca_new)
        layout.addWidget(header)

        card = QFrame()
        card.setObjectName("card")
        card_col = QVBoxLayout(card)
        card_col.setContentsMargins(16, 14, 16, 14)
        card_col.setSpacing(10)

        self.ca_status = QLabel()
        self.ca_status.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.ca_status.setWordWrap(True)
        card_col.addWidget(self.ca_status)

        self.ca_pub_view = QPlainTextEdit()
        self.ca_pub_view.setReadOnly(True)
        self.ca_pub_view.setMaximumHeight(96)
        self.ca_pub_view.setFont(monospace())
        card_col.addWidget(self.ca_pub_view)

        row = QHBoxLayout()
        copy_button = QPushButton("Public Key kopieren")
        copy_button.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(self.ca.ca_public_key())
        )
        export_button = QPushButton("Public Key speichern …")
        export_button.clicked.connect(self.export_ca_pub)
        deploy_button = QPushButton("Deployment-Anleitung")
        deploy_button.clicked.connect(self.show_deployment)
        row.addWidget(copy_button)
        row.addWidget(export_button)
        row.addWidget(deploy_button)
        row.addStretch(1)
        card_col.addLayout(row)
        layout.addWidget(card)
        layout.addStretch(1)
        return page

    # --------------------------------------------------------- Hilfsmittel
    def selected_cert(self) -> CertInfo | None:
        indexes = self.cert_table.selectionModel().selectedRows()
        if not indexes:
            return None
        source = self.cert_proxy.mapToSource(indexes[0])
        return self.cert_model.cert_at(source.row())

    def _require_selection(self) -> CertInfo | None:
        cert = self.selected_cert()
        if cert is None:
            info_box(self, "Kein Zertifikat gewählt", "Bitte zuerst eine Zeile auswählen.")
        return cert

    def _busy(self, message: str) -> None:
        self.statusBar().showMessage(message)
        self.setEnabled(False)

    def _ready(self, message: str = "") -> None:
        self.setEnabled(True)
        self.statusBar().showMessage(message, 8000)

    def _fail(self, message: str, details: str = "") -> None:
        self.setEnabled(True)
        self.statusBar().clearMessage()
        error_box(self, "Vorgang fehlgeschlagen", message, details)

    def _repaint_table(self) -> None:
        top = self.cert_model.index(0, 0)
        bottom = self.cert_model.index(
            max(0, self.cert_model.rowCount() - 1), self.cert_model.columnCount() - 1
        )
        self.cert_model.dataChanged.emit(top, bottom)

    def _change_zoom(self, delta: float | None) -> None:
        """Schriftgröße ändern; None setzt auf die Standardgröße zurück."""
        from PySide6.QtWidgets import QApplication

        app = QApplication.instance()
        if delta is None:
            scale = theme.set_scale(app, 1.0)
        else:
            scale = theme.set_scale(app, theme.load_scale() + delta)
        self._apply_row_heights(scale)
        self.statusBar().showMessage(f"Schriftgröße {round(scale * 100)} %", 4000)

    def _apply_row_heights(self, scale: float) -> None:
        height = max(30, round(38 * scale))
        for table, columns in (
            (self.cert_table, CertTableModel.COLUMNS),
            (self.revoked_table, RevokedTableModel.COLUMNS),
        ):
            table.verticalHeader().setDefaultSectionSize(height)
            for column, (_, width) in enumerate(columns):
                table.setColumnWidth(column, round(width * scale))
        self._repaint_table()

    def _update_sidebar_counts(self, certs: int, revoked: int) -> None:
        self.sidebar.item(PAGE_CERTS).setText(f"Zertifikate   ·  {certs}")
        self.sidebar.item(PAGE_REVOKED).setText(f"Widerrufen   ·  {revoked}")
        self.sidebar.item(PAGE_CA).setText("CA")

    # ------------------------------------------------------------- Aktionen
    def refresh(self, force: bool = False) -> None:
        certs = refresh_index(self.ca, self.index, force=force)
        self.cert_model.set_certificates(certs)
        revoked_entries = list(self.ca.iter_revoked_entries())
        self.revoked_model.set_entries(revoked_entries)
        self.empty_hint.setVisible(not certs)
        self.cert_table.setVisible(bool(certs))
        self._update_sidebar_counts(len(certs), len(revoked_entries))
        self.side_footer.setText(str(self.paths.base))

        has_ca = self.ca.exists()
        for action in (
            self.act_new, self.act_renew, self.act_revoke,
            self.act_export, self.act_delete,
        ):
            action.setEnabled(has_ca)
        for button in (
            self.btn_new, self.btn_renew, self.btn_revoke,
            self.btn_export, self.btn_delete,
        ):
            button.setEnabled(has_ca)
        self.act_ca_new.setEnabled(not has_ca)
        self.act_ca_import.setEnabled(not has_ca)
        self.btn_ca_new.setEnabled(not has_ca)
        self.btn_ca_import.setEnabled(not has_ca)

        if has_ca:
            agent = (
                " · <span style='color:#79d99a;'>im ssh-agent geladen</span>"
                if self.ca.ca_in_agent()
                else ""
            )
            self.ca_status.setText(
                f"<b>CA vorhanden</b>{agent}<br>"
                f"<span style='color:#8f959f;'>Fingerprint</span> "
                f"<code>{self.ca.ca_fingerprint()}</code><br>"
                f"<span style='color:#8f959f;'>Schlüssel</span> "
                f"<code>{self.paths.ca_key}</code><br>"
                f"<span style='color:#8f959f;'>KRL</span> <code>{self.paths.krl}</code> "
                f"({'vorhanden' if self.paths.krl.is_file() else 'noch nicht angelegt'})"
            )
            self.ca_pub_view.setPlainText(self.ca.ca_public_key())
            self.cert_subtitle.setText(
                f"{len(certs)} aktive Zertifikate · CA {self.ca.ca_fingerprint()[:24]}…"
            )
            self.statusBar().showMessage(
                f"{len(certs)} Zertifikate · {self.paths.base}", 5000
            )
        else:
            self.ca_status.setText(
                "<b>Keine CA vorhanden.</b><br>Eine neue anlegen oder eine "
                "bestehende importieren — erst danach lassen sich Zertifikate "
                "ausstellen."
            )
            self.ca_pub_view.setPlainText("")
            self.cert_subtitle.setText("Noch keine CA vorhanden")

    def create_ca(self) -> None:
        dialog = CaInitDialog(self, self.paths.ca_key)
        if dialog.exec() != CaInitDialog.Accepted:
            return
        self._busy("CA wird erzeugt …")
        run_task(
            self.ca.init_ca,
            dialog.passphrase,
            dialog.comment_text,
            on_success=lambda _: (self.refresh(), self._ready("CA angelegt.")),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def import_ca(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Privaten CA-Schlüssel wählen", str(Path.home()), "Alle Dateien (*)"
        )
        if not path:
            return
        passphrase = PassphraseDialog.ask(
            self,
            "Passphrase des CA-Schlüssels",
            "Wird nur benötigt, falls der öffentliche Teil neu abgeleitet werden muss.",
            allow_empty=True,
        )
        if passphrase is None:
            return
        self._busy("CA wird importiert …")
        run_task(
            self.ca.import_ca,
            Path(path),
            passphrase,
            on_success=lambda _: (self.refresh(), self._ready("CA importiert.")),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def new_certificate(self, fixed: tuple[str, str] | None = None,
                        renew_from: CertInfo | None = None) -> None:
        try:
            self.ca.require()
        except CaError as exc:
            info_box(self, "Keine CA", str(exc))
            return

        dialog = CertDialog(
            self,
            templates=self.template_store.load(),
            conf_principals=self.paths.read_principals_conf(),
            agent_available=self.ca.ca_in_agent(),
            fixed=fixed,
            title="Zertifikat erneuern" if renew_from else "Neues Zertifikat",
        )
        if dialog.exec() != CertDialog.Accepted:
            return
        request = dialog.request()

        if renew_from is not None:
            self._busy("Altes Material wird archiviert, neues Zertifikat entsteht …")
            run_task(
                self.ca.renew_certificate,
                renew_from,
                request,
                on_success=self._after_create,
                on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
            )
        else:
            self._busy("Schlüssel wird erzeugt und signiert …")
            run_task(
                self.ca.create_certificate,
                request,
                on_success=self._after_create,
                on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
            )

    def _after_create(self, cert: CertInfo) -> None:
        self.refresh(force=True)
        self._ready(f"Zertifikat erstellt: {cert.user}@{cert.host} · Serial {cert.serial}")
        CertDetailDialog(self, cert).exec()

    def renew_certificate(self) -> None:
        cert = self._require_selection()
        if cert is None:
            return
        answer = QMessageBox.question(
            self,
            "Zertifikat erneuern",
            f"Für {cert.user}@{cert.host} werden Schlüssel und Zertifikat neu "
            "erzeugt. Das bisherige Material wandert nach archive/ und ersetzt "
            "den dortigen Stand.\n\nFortfahren?",
        )
        if answer != QMessageBox.Yes:
            return
        self.new_certificate(fixed=(cert.user, cert.host), renew_from=cert)

    def revoke_certificate(self) -> None:
        cert = self._require_selection()
        if cert is None:
            return
        dialog = RevokeDialog(self, cert, self.ca.ca_in_agent())
        if dialog.exec() != RevokeDialog.Accepted:
            return
        action, reason, ca_pass, use_agent = dialog.values
        self._busy("KRL wird aktualisiert …")
        run_task(
            self.ca.revoke,
            cert,
            reason,
            action,
            ca_pass,
            use_agent,
            on_success=lambda store: (
                self.refresh(force=True),
                self._ready(f"{action} · Material liegt unter {store}"),
                info_box(
                    self,
                    "Widerruf abgeschlossen",
                    "Die KRL wurde aktualisiert. Damit der Widerruf auf den "
                    "Zielsystemen greift, muss die Datei\n\n"
                    f"{self.paths.krl}\n\ndort als RevokedKeys neu hinterlegt werden.",
                ),
            ),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    # ------------------------------------------------- Export und Löschen
    def export_certificates(self) -> None:
        """Exportiert gültige Zertifikate samt Schlüsseln als tar.gz."""
        from ..model import Status

        all_certs = [
            self.cert_model.cert_at(i) for i in range(self.cert_model.rowCount())
        ]
        valid = [
            c for c in all_certs
            if c and c.status() in (Status.VALID, Status.EXPIRING)
        ]
        if not valid:
            info_box(
                self, "Nichts zu exportieren",
                "Es gibt derzeit keine gültigen Zertifikate.",
            )
            return

        # Ist ein gültiges Zertifikat ausgewählt, zur Wahl stellen:
        # nur dieses oder alle gültigen.
        selection = self.selected_cert()
        to_export = valid
        suggested = "ssh-ca-export.tar.gz"
        if selection is not None and selection.status() in (
            Status.VALID, Status.EXPIRING
        ):
            box = QMessageBox(self)
            box.setWindowTitle("Exportieren")
            box.setText(
                f"Nur das ausgewählte Zertifikat ({selection.user}@{selection.host}) "
                f"exportieren oder alle {len(valid)} gültigen?"
            )
            only_button = box.addButton("Nur ausgewähltes", QMessageBox.AcceptRole)
            box.addButton(f"Alle gültigen ({len(valid)})", QMessageBox.AcceptRole)
            cancel_button = box.addButton(QMessageBox.Cancel)
            box.exec()
            if box.clickedButton() is cancel_button:
                return
            if box.clickedButton() is only_button:
                to_export = [selection]
                suggested = f"{selection.host}_{selection.user}.tar.gz"

        path, _ = QFileDialog.getSaveFileName(
            self, "Export speichern", str(Path.home() / suggested),
            "Archiv (*.tar.gz)",
        )
        if not path:
            return
        if not path.endswith((".tar.gz", ".tgz")):
            path += ".tar.gz"
        run_task(
            self.ca.export_certificates,
            to_export,
            Path(path),
            on_success=lambda result: self._ready(
                f"{result[1]} Zertifikat(e) exportiert: {result[0]}"
            ),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def delete_certificate(self) -> None:
        """Löscht das Material eines abgelaufenen/widerrufenen Zertifikats."""
        from ..model import Status

        cert = self._require_selection()
        if cert is None:
            return
        status = cert.status()
        if status not in (Status.EXPIRED, Status.REVOKED):
            info_box(
                self, "Löschen nicht möglich",
                f"Dieses Zertifikat ist „{cert.status_text()}“.\n\n"
                "Gelöscht werden können nur abgelaufene oder widerrufene "
                "Zertifikate. Für gültiges Material bitte Widerruf oder "
                "Sperrung verwenden.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Ungültiges Zertifikat löschen",
            f"Schlüssel, Public Key und Zertifikat für {cert.user}@{cert.host} "
            f"({cert.status_text()}) werden endgültig gelöscht — einschließlich "
            "des archive/-Bestands.\n\nFortfahren?",
        )
        if answer != QMessageBox.Yes:
            return
        self._busy("Material wird gelöscht …")
        run_task(
            self.ca.delete_certificate,
            cert,
            on_success=lambda _: (
                self.refresh(force=True),
                self._ready(f"Gelöscht: {cert.user}@{cert.host}"),
            ),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def selected_revoked_entry(self):
        indexes = self.revoked_table.selectionModel().selectedRows()
        if not indexes:
            return None
        return self.revoked_model.entry_at(indexes[0].row())

    def delete_revoked_entry(self) -> None:
        """Löscht eine ausgelagerte Widerrufsablage endgültig."""
        entry = self.selected_revoked_entry()
        if entry is None:
            info_box(self, "Kein Eintrag gewählt", "Bitte zuerst eine Zeile auswählen.")
            return
        answer = QMessageBox.question(
            self,
            "Widerrufsablage löschen",
            f"Das ausgelagerte Material für {entry.user}@{entry.host} "
            f"({entry.action} am {entry.revoked_at}) wird endgültig gelöscht.\n\n"
            "Der Eintrag in der KRL bleibt bestehen — das Zertifikat bleibt "
            "auf den Zielsystemen ungültig.\n\nFortfahren?",
        )
        if answer != QMessageBox.Yes:
            return
        self._busy("Ablage wird gelöscht …")
        run_task(
            self.ca.delete_revoked_entry,
            entry,
            on_success=lambda _: (
                self.refresh(force=True),
                self._ready(f"Ablage gelöscht: {entry.user}@{entry.host}"),
            ),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def show_details(self) -> None:
        cert = self._require_selection()
        if cert is None:
            return
        # Frisch von der Platte lesen, damit Rohausgabe und Status stimmen.
        try:
            cert = self.ca.load_certificate(cert.cert_path)
        except SshKeygenError:
            pass
        CertDetailDialog(self, cert).exec()

    def backup(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Sicherung speichern",
            str(self.paths.backup_dir / "ssh-ca-backup.tar.gz"),
            "Archiv (*.tar.gz)",
        )
        if not path:
            return
        run_task(
            self.ca.backup,
            Path(path),
            on_success=lambda dest: self._ready(f"Sicherung geschrieben: {dest}"),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Sicherung wählen", str(self.paths.backup_dir), "Archiv (*.tar.gz *.tgz)"
        )
        if not path:
            return
        answer = QMessageBox.question(
            self,
            "Sicherung einspielen",
            "Vorhandene Dateien mit gleichem Namen werden überschrieben. Fortfahren?",
        )
        if answer != QMessageBox.Yes:
            return
        run_task(
            self.ca.restore,
            Path(path),
            on_success=lambda _: (self.refresh(force=True), self._ready("Sicherung eingespielt.")),
            on_error=self._fail,
            on_done=lambda: self.setEnabled(True),
        )

    def export_ca_pub(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "CA-Public-Key speichern", str(Path.home() / "ca_key.pub"),
            "Public Key (*.pub)",
        )
        if path:
            Path(path).write_text(self.ca.ca_public_key() + "\n", encoding="utf-8")
            self._ready(f"Gespeichert: {path}")

    def show_deployment(self) -> None:
        TextViewDialog(
            self,
            "Deployment-Anleitung",
            DEPLOYMENT_HELP.format(
                ca_pub=self.paths.ca_pub, krl=self.paths.krl, base=self.paths.base
            ),
        ).exec()

    def show_log(self) -> None:
        text = self.ca.read_log() or "Es gibt noch keine Logeinträge."
        TextViewDialog(self, "Log", text).exec()

    def show_about(self) -> None:
        QMessageBox.about(
            self,
            "Über",
            f"<h3>{APP_NAME} {APP_VERSION}</h3>"
            "<p>Verwaltung einer SSH Certificate Authority.</p>"
            f"<p>Datenverzeichnis: <code>{self.paths.base}</code><br>"
            f"OpenSSH: <code>{self.ca.ssh.keygen}</code></p>",
        )

    def closeEvent(self, event) -> None:  # noqa: N802
        self.index.close()
        super().closeEvent(event)
