"""Erscheinungsbild der Anwendung.

Dunkles Graphit mit Bernstein-Akzent. Der Stil "Fusion" dient als Basis, weil
er sich — anders als die Plattformstile — vollstaendig und vorhersagbar per
QSS gestalten laesst.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPalette
from PySide6.QtWidgets import QApplication, QStyle, QStyledItemDelegate

from ..model import Status

# ------------------------------------------------------------------ Palette
BG_WINDOW = "#14161a"      # Fensterhintergrund
BG_PANEL = "#1b1e24"       # Seitenleiste, Kopfzeilen
BG_RAISED = "#22262e"      # Eingaben, Tabellenkopf, Karten
BG_HOVER = "#282d36"
BORDER = "#2e333d"
BORDER_SOFT = "#262b33"
TEXT = "#e6e4df"
TEXT_MUTED = "#8f959f"
TEXT_FAINT = "#6a707a"

ACCENT = "#ffa94d"         # Bernstein — passend zum Terminal
ACCENT_HOVER = "#ffbd73"
ACCENT_PRESSED = "#e8923a"
ACCENT_DIM = "#3a2f20"     # Auswahl-Hintergrund
ON_ACCENT = "#191307"

#: Pillenfarben je Status: (Schrift, Hintergrund)
STATUS_PILL: dict[Status, tuple[str, str]] = {
    Status.VALID: ("#79d99a", "#1d3226"),
    Status.EXPIRING: ("#eec46a", "#382e18"),
    Status.EXPIRED: ("#ee8073", "#3a201d"),
    Status.FUTURE: ("#82b5ee", "#1e2a3c"),
    Status.REVOKED: ("#ee8073", "#3a201d"),
    Status.STORED: ("#c49aec", "#2e2239"),
    Status.UNKNOWN: ("#9aa0aa", "#262b33"),
}

def build_qss(scale: float = 1.0) -> str:
    """Stylesheet mit skalierten Schriftgroessen."""
    def px(value: float) -> int:
        return max(1, round(value * scale))

    return f"""
* {{
    outline: none;
}}
QMainWindow, QDialog {{
    background: {BG_WINDOW};
}}
QWidget {{
    color: {TEXT};
    font-size: {px(13)}px;
}}

/* ---------------- Menüleiste ---------------- */
QMenuBar {{
    background: {BG_WINDOW};
    border-bottom: 1px solid {BORDER_SOFT};
    padding: 2px 6px;
}}
QMenuBar::item {{
    padding: 5px 10px;
    border-radius: 6px;
    background: transparent;
}}
QMenuBar::item:selected {{ background: {BG_HOVER}; }}
QMenu {{
    background: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px;
}}
QMenu::item {{
    padding: 6px 26px 6px 12px;
    border-radius: 6px;
}}
QMenu::item:selected {{ background: {ACCENT_DIM}; color: {ACCENT_HOVER}; }}
QMenu::item:disabled {{ color: {TEXT_FAINT}; }}
QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 6px 8px;
}}

/* ---------------- Seitenleiste ---------------- */
QListWidget#sidebar {{
    background: {BG_PANEL};
    border: none;
    border-right: 1px solid {BORDER_SOFT};
    padding: 8px;
}}
QListWidget#sidebar::item {{
    color: {TEXT_MUTED};
    padding: 10px 12px;
    margin: 2px 0;
    border-radius: 8px;
}}
QListWidget#sidebar::item:hover {{ background: {BG_HOVER}; color: {TEXT}; }}
QListWidget#sidebar::item:selected {{
    background: {ACCENT_DIM};
    color: {ACCENT};
    font-weight: 600;
}}
QLabel#appTitle {{
    color: {TEXT};
    font-size: {px(15)}px;
    font-weight: 700;
    padding: 14px 14px 2px 14px;
}}
QLabel#appSubtitle {{
    color: {TEXT_FAINT};
    font-size: {px(11)}px;
    padding: 0 14px 10px 14px;
}}
QWidget#sidebarWrap {{
    background: {BG_PANEL};
    border-right: 1px solid {BORDER_SOFT};
}}

/* ---------------- Seitenkopf ---------------- */
QLabel#pageTitle {{
    font-size: {px(19)}px;
    font-weight: 700;
}}
QLabel#pageSubtitle {{
    color: {TEXT_MUTED};
    font-size: {px(12)}px;
}}

/* ---------------- Knöpfe ---------------- */
QPushButton {{
    background: {BG_RAISED};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 7px 14px;
    color: {TEXT};
}}
QPushButton:hover {{ background: {BG_HOVER}; border-color: {TEXT_FAINT}; }}
QPushButton:pressed {{ background: {BG_PANEL}; }}
QPushButton:disabled {{ color: {TEXT_FAINT}; border-color: {BORDER_SOFT}; }}
QPushButton#primary {{
    background: {ACCENT};
    border: 1px solid {ACCENT};
    color: {ON_ACCENT};
    font-weight: 600;
}}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_PRESSED}; }}
QPushButton#primary:disabled {{
    background: {BG_RAISED}; border-color: {BORDER}; color: {TEXT_FAINT};
}}
QPushButton#danger {{
    background: transparent;
    border: 1px solid #7a3b34;
    color: #ee8073;
}}
QPushButton#danger:hover {{ background: #3a201d; }}
QPushButton#danger:disabled {{ border-color: {BORDER}; color: {TEXT_FAINT}; }}
QDialogButtonBox QPushButton {{ min-width: 84px; }}

/* ---------------- Eingaben ---------------- */
QLineEdit, QComboBox, QPlainTextEdit, QSpinBox {{
    background: {BG_RAISED};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: {ACCENT_DIM};
    selection-color: {ACCENT_HOVER};
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{
    border-color: {ACCENT};
}}
QLineEdit:read-only {{ color: {TEXT_MUTED}; }}
QLineEdit:disabled, QComboBox:disabled {{ color: {TEXT_FAINT}; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {TEXT_MUTED};
    margin-right: 10px;
}}
QComboBox QAbstractItemView {{
    background: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
    selection-background-color: {ACCENT_DIM};
    selection-color: {ACCENT_HOVER};
    padding: 4px;
}}

/* ---------------- Checkboxen ---------------- */
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {BORDER};
    border-radius: 5px;
    background: {BG_RAISED};
}}
QCheckBox::indicator:hover {{ border-color: {TEXT_FAINT}; }}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border-color: {ACCENT};
    image: url(none);
}}
QCheckBox:disabled {{ color: {TEXT_FAINT}; }}

/* ---------------- Tabellen ---------------- */
QTableView {{
    background: {BG_WINDOW};
    alternate-background-color: {BG_PANEL};
    border: 1px solid {BORDER_SOFT};
    border-radius: 10px;
    gridline-color: transparent;
    selection-background-color: {ACCENT_DIM};
    selection-color: {TEXT};
}}
QTableView::item {{ padding: 0 8px; border: none; }}
QHeaderView::section {{
    background: {BG_RAISED};
    color: {TEXT_MUTED};
    font-size: {px(11)}px;
    font-weight: 600;
    text-transform: uppercase;
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 8px 10px;
}}
QTableCornerButton::section {{ background: {BG_RAISED}; border: none; }}

/* ---------------- Reiter (Dialoge) ---------------- */
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    top: -1px;
    background: {BG_PANEL};
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED};
    padding: 8px 16px;
    margin-right: 4px;
    border: 1px solid transparent;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}
QTabBar::tab:hover {{ color: {TEXT}; }}
QTabBar::tab:selected {{
    background: {BG_PANEL};
    color: {ACCENT};
    border-color: {BORDER};
    border-bottom-color: {BG_PANEL};
    font-weight: 600;
}}

/* ---------------- Gruppen ---------------- */
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    margin-top: 12px;
    padding-top: 8px;
    background: {BG_PANEL};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {ACCENT};
    font-weight: 600;
}}

/* ---------------- Listen ---------------- */
QListWidget {{
    background: {BG_RAISED};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 4px;
}}
QListWidget::item {{ padding: 5px 8px; border-radius: 6px; }}
QListWidget::item:selected {{ background: {ACCENT_DIM}; color: {ACCENT_HOVER}; }}

/* ---------------- Statuszeile, Scrollbalken, Tooltip ---------------- */
QStatusBar {{
    background: {BG_PANEL};
    color: {TEXT_MUTED};
    border-top: 1px solid {BORDER_SOFT};
}}
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {TEXT_FAINT}; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER}; border-radius: 5px; min-width: 30px;
}}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}
QToolTip {{
    background: {BG_RAISED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 8px;
}}
QMessageBox, QFileDialog {{ background: {BG_PANEL}; }}
QLabel#hintError {{ color: #ee8073; }}
QLabel#noteMuted {{ color: {TEXT_MUTED}; }}
QLabel#emptyState {{
    color: {TEXT_FAINT};
    font-size: {px(14)}px;
    padding: 28px;
}}
QFrame#card {{
    background: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
"""


MIN_SCALE = 0.8
MAX_SCALE = 1.8
SCALE_STEP = 0.1


def _settings() -> "QSettings":
    from PySide6.QtCore import QSettings

    return QSettings("ssh-ca-manager", "ui")


def load_scale() -> float:
    try:
        value = float(_settings().value("scale", 1.0))
    except (TypeError, ValueError):
        return 1.0
    return min(MAX_SCALE, max(MIN_SCALE, value))


def set_scale(app: QApplication, scale: float) -> float:
    """Wendet eine Schriftskala an, speichert sie und liefert den Wert."""
    scale = min(MAX_SCALE, max(MIN_SCALE, round(scale, 2)))
    app.setStyleSheet(build_qss(scale))
    _settings().setValue("scale", scale)
    return scale


def apply_theme(app: QApplication, scale: float | None = None) -> float:
    """Setzt Stil, Palette und Stylesheet fuer die ganze Anwendung."""
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(BG_WINDOW))
    palette.setColor(QPalette.WindowText, QColor(TEXT))
    palette.setColor(QPalette.Base, QColor(BG_RAISED))
    palette.setColor(QPalette.AlternateBase, QColor(BG_PANEL))
    palette.setColor(QPalette.Text, QColor(TEXT))
    palette.setColor(QPalette.Button, QColor(BG_RAISED))
    palette.setColor(QPalette.ButtonText, QColor(TEXT))
    palette.setColor(QPalette.Highlight, QColor(ACCENT_DIM))
    palette.setColor(QPalette.HighlightedText, QColor(ACCENT_HOVER))
    palette.setColor(QPalette.PlaceholderText, QColor(TEXT_FAINT))
    palette.setColor(QPalette.ToolTipBase, QColor(BG_RAISED))
    palette.setColor(QPalette.ToolTipText, QColor(TEXT))
    palette.setColor(QPalette.Link, QColor(ACCENT))
    app.setPalette(palette)

    font = app.font()
    if font.pointSize() > 0 and font.pointSize() < 10:
        font.setPointSize(10)
    app.setFont(font)

    if scale is None:
        scale = load_scale()
    scale = min(MAX_SCALE, max(MIN_SCALE, scale))
    app.setStyleSheet(build_qss(scale))
    return scale


class StatusPillDelegate(QStyledItemDelegate):
    """Zeichnet die Statusspalte als abgerundete Pille.

    Erwartet den :class:`Status` unter ``Qt.UserRole + 1`` und den Anzeigetext
    wie gewohnt unter ``Qt.DisplayRole``.
    """

    STATUS_ROLE = int(Qt.UserRole) + 1
    RADIUS = 9.0
    PAD_X = 10
    HEIGHT = 20

    def paint(self, painter: QPainter, option, index) -> None:
        status = index.data(self.STATUS_ROLE)
        text = index.data(Qt.DisplayRole) or ""
        if not isinstance(status, Status):
            super().paint(painter, option, index)
            return

        # Auswahl-/Zebra-Hintergrund der Zeile normal zeichnen lassen.
        option_copy = option
        self.initStyleOption(option_copy, index)
        option_copy.text = ""
        style = option_copy.widget.style() if option_copy.widget else None
        if style:
            style.drawControl(QStyle.CE_ItemViewItem, option_copy, painter,
                              option_copy.widget)

        fg, bg = STATUS_PILL[status]
        font = QFont(option.font)
        font.setPointSizeF(max(8.0, option.font.pointSizeF() - 1))
        font.setWeight(QFont.DemiBold)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setFont(font)
        metrics = painter.fontMetrics()
        height = max(self.HEIGHT, metrics.height() + 5)
        available = option.rect.width() - 16
        text = metrics.elidedText(text, Qt.ElideRight, available - 2 * self.PAD_X)
        width = metrics.horizontalAdvance(text) + 2 * self.PAD_X
        rect = QRectF(
            option.rect.x() + 8,
            option.rect.center().y() - height / 2,
            min(width, available),
            height,
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(rect, self.RADIUS, self.RADIUS)
        painter.setPen(QColor(fg))
        painter.drawText(rect, Qt.AlignCenter, text)
        painter.restore()
