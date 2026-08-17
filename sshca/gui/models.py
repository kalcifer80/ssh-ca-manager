"""Tabellenmodelle fuer die Listenansichten."""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..model import CertInfo, RevokedEntry, Status


class CertTableModel(QAbstractTableModel):
    COLUMNS = [
        ("Status", 185),
        ("Benutzer", 95),
        ("Host", 140),
        ("Prinzipale", 220),
        ("Gültig bis", 150),
        ("Seriennummer", 120),
        ("Key ID", 170),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[CertInfo] = []

    # -- Daten setzen -----------------------------------------------------
    def set_certificates(self, certs: list[CertInfo]) -> None:
        self.beginResetModel()
        self._rows = list(certs)
        self.endResetModel()

    def cert_at(self, row: int) -> CertInfo | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    # -- QAbstractTableModel ---------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLUMNS[section][0]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        cert = self._rows[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            return [
                cert.status_text(),
                cert.user,
                cert.host,
                cert.principals_csv,
                "unbegrenzt" if cert.forever else (
                    f"{cert.valid_to:%Y-%m-%d %H:%M}" if cert.valid_to else "-"
                ),
                cert.serial,
                cert.key_id,
            ][column]

        if role == Qt.ForegroundRole and column == 0:
            return QColor(cert.status().color)

        if role == int(Qt.UserRole) + 1 and column == 0:
            # Fuer den Pillen-Delegate: der Status selbst, nicht nur der Text.
            return cert.status()

        if role == Qt.ToolTipRole:
            lines = [
                f"Datei: {cert.cert_path}",
                f"Gültigkeit: {cert.validity_text}",
                f"Fingerprint: {cert.pubkey_fp}",
            ]
            if cert.extensions:
                lines.append("Extensions: " + ", ".join(sorted(cert.extensions)))
            if cert.critical_options:
                lines.append(
                    "Critical Options: "
                    + ", ".join(f"{k}={v}" for k, v in cert.critical_options.items())
                )
            if not cert.has_private_key:
                lines.append("Achtung: privater Schlüssel fehlt")
            if cert.parse_error:
                lines.append(f"Lesefehler: {cert.parse_error}")
            return "\n".join(lines)

        if role == Qt.UserRole:
            # Sortierschluessel: Restlaufzeit statt Anzeigetext.
            if column == 0:
                return cert.status().name
            if column == 4:
                return cert.valid_to.isoformat() if cert.valid_to else ""
            return self.data(index, Qt.DisplayRole)

        return None


class CertFilterProxy(QSortFilterProxyModel):
    """Freitextfilter plus Statusfilter."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setSortRole(Qt.UserRole)
        self._text = ""
        self._hide_expired = False

    def set_text(self, text: str) -> None:
        self._text = text.strip().lower()
        self.invalidateFilter()

    def set_hide_expired(self, hide: bool) -> None:
        self._hide_expired = hide
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:  # noqa: N802
        model: CertTableModel = self.sourceModel()
        cert = model.cert_at(row)
        if cert is None:
            return False
        if self._hide_expired and cert.status() in (Status.EXPIRED, Status.REVOKED):
            return False
        if not self._text:
            return True
        haystack = " ".join(
            [cert.user, cert.host, cert.key_id, cert.serial, cert.principals_csv]
        ).lower()
        return self._text in haystack


class RevokedTableModel(QAbstractTableModel):
    COLUMNS = [
        ("Art", 110),
        ("Benutzer", 110),
        ("Host", 140),
        ("Zeitpunkt", 160),
        ("Durch", 110),
        ("Grund", 260),
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[RevokedEntry] = []

    def set_entries(self, entries: list[RevokedEntry]) -> None:
        self.beginResetModel()
        self._rows = list(entries)
        self.endResetModel()

    def entry_at(self, row: int) -> RevokedEntry | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.COLUMNS[section][0]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self._rows[index.row()]
        if role == Qt.DisplayRole:
            return [
                entry.action,
                entry.user,
                entry.host,
                entry.revoked_at,
                entry.revoked_by,
                entry.reason,
            ][index.column()]
        if role == Qt.ForegroundRole and index.column() == 0:
            return QColor("#c49aec" if entry.action == "gesperrt" else "#ee8073")
        if role == int(Qt.UserRole) + 1 and index.column() == 0:
            from ..model import Status

            return Status.STORED if entry.action == "gesperrt" else Status.REVOKED
        if role == Qt.ToolTipRole:
            return f"Ablage: {entry.directory}"
        return None
