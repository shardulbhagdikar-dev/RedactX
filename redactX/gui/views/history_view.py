"""History View for RedactX GUI.

Implements Wireframe 3: Scan History with table view of previous scans.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from redactX.gui.theme import SEVERITY_COLORS
from redactX.reports.reporter import ReportGenerator
from redactX.storage.history import HistoryDatabase


def format_human_timestamp(raw_ts: str) -> str:
    """Convert raw ISO timestamp to a clean, human-readable local date and time."""
    if not raw_ts:
        return "N/A"
    try:
        clean_ts = raw_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt.strftime("%b %d, %Y, %I:%M:%S %p")
    except Exception:
        # Fallback without fractional seconds or timezone noise
        return raw_ts.replace("T", " ").split(".")[0]


class HistoryView(QWidget):
    """Scan History audit browser matching Wireframe 3."""

    def __init__(self, history_db: Optional[HistoryDatabase] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.history_db = history_db or HistoryDatabase()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(14)

        # Outer Container matching Wireframe 3
        card = QFrame(self)
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(14)

        # Container Header
        hdr_layout = QHBoxLayout()
        self.lbl_title = QLabel("Scan History", card)
        self.lbl_title.setStyleSheet("font-size: 18px; font-weight: 600; color: #FFFFFF;")
        hdr_layout.addWidget(self.lbl_title)
        hdr_layout.addStretch()

        self.btn_refresh = QPushButton("Refresh", card)
        self.btn_refresh.setProperty("class", "SecondaryButton")
        self.btn_refresh.clicked.connect(self.load_history)
        hdr_layout.addWidget(self.btn_refresh)

        self.btn_clear = QPushButton("Clear History", card)
        self.btn_clear.setProperty("class", "DangerButton")
        self.btn_clear.clicked.connect(self._clear_history)
        hdr_layout.addWidget(self.btn_clear)

        card_layout.addLayout(hdr_layout)

        # Inner Table View matching Wireframe 3
        self.table = QTableWidget(card)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "ID", "Date & Time", "Target Path", "Files", "Findings", "Overall Risk"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        card_layout.addWidget(self.table, 1)

        layout.addWidget(card)

        # Initial load
        self.load_history()

    def load_history(self) -> None:
        """Fetch and populate past scan entries from SQLite."""
        scans = self.history_db.get_recent_scans(limit=100)
        self.table.setRowCount(0)

        for row_idx, scan in enumerate(scans):
            self.table.insertRow(row_idx)

            scan_id_short = str(scan.get("id") or scan.get("scan_id") or "")[:8]
            raw_timestamp = str(scan.get("timestamp", ""))
            human_timestamp = format_human_timestamp(raw_timestamp)
            target_path = str(scan.get("target_path", ""))
            files_count = str(scan.get("total_files_scanned") or scan.get("total_files") or 0)
            findings_count = str(scan.get("total_findings", 0))
            risk_level = str(scan.get("overall_risk", "CLEAN"))

            item_id = QTableWidgetItem(scan_id_short)
            item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            item_ts = QTableWidgetItem(human_timestamp)
            item_ts.setToolTip(f"Raw UTC Timestamp: {raw_timestamp}")

            item_target = QTableWidgetItem(target_path)
            item_target.setToolTip(target_path)

            item_files = QTableWidgetItem(files_count)
            item_files.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            item_findings = QTableWidgetItem(findings_count)
            item_findings.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            item_risk = QTableWidgetItem(risk_level)
            item_risk.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Color risk badge
            color = SEVERITY_COLORS.get(risk_level, "#FFFFFF")
            item_risk.setForeground(QColor(color))

            self.table.setItem(row_idx, 0, item_id)
            self.table.setItem(row_idx, 1, item_ts)
            self.table.setItem(row_idx, 2, item_target)
            self.table.setItem(row_idx, 3, item_files)
            self.table.setItem(row_idx, 4, item_findings)
            self.table.setItem(row_idx, 5, item_risk)

        # Optimize column widths for clean readability
        self.table.resizeColumnToContents(0)
        self.table.resizeColumnToContents(1)
        self.table.resizeColumnToContents(3)
        self.table.resizeColumnToContents(4)
        self.table.resizeColumnToContents(5)

    def _clear_history(self) -> None:
        confirm = QMessageBox.question(
            self,
            "Clear Scan History",
            "Are you sure you want to delete all historical scan records from local database?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            self.history_db.clear_history()
            self.load_history()
