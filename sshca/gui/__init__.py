"""Qt-Oberflaeche."""

from __future__ import annotations

import sys
from pathlib import Path


def run(base: Path | None = None) -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from ..config import APP_NAME
    from ..keygen import Ssh
    from .main_window import MainWindow
    from .theme import apply_theme

    from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setDesktopFileName("ssh-ca-manager")
    apply_theme(app)

    # Standardknöpfe (OK, Abbrechen, Schließen) in der Systemsprache.
    translator = QTranslator(app)
    if translator.load(
        QLocale.system(), "qtbase", "_",
        QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath),
    ):
        app.installTranslator(translator)

    if not Ssh().available():
        QMessageBox.critical(
            None,
            APP_NAME,
            "ssh-keygen wurde nicht gefunden. Bitte openssh-client installieren.",
        )
        return 1

    window = MainWindow(base)
    window.show()
    return app.exec()
