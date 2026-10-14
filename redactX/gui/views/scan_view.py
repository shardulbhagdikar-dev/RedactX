"""Scan View for RedactX GUI.

Implements Wireframe 1 (Upload hero container with file -> red arrow -> lock)
and Wireframe 2 (Scanning files state with progress and results).
"""

from pathlib import Path
from typing import Optional, Union

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from redactX.gui.icons import VectorIconFactory
from redactX.gui.theme import (
    COLOR_ACCENT_GREEN,
    COLOR_ACCENT_RED,
    COLOR_BORDER_DASHED,
    COLOR_SURFACE,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    SEVERITY_COLORS,
)
from redactX.gui.worker import ScanWorker
from redactX.models.result import ScanSummary
from redactX.scanner.scanner import ScanEngine


# ==============================================================================
# Custom Hero Dropzone Widget (Wireframe 1)
# ==============================================================================
class DropzoneHeroWidget(QFrame):
    """Custom painted dropzone matching Wireframe 1 exactly."""

    clicked = Signal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("DropzoneFrame")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(220)
        self.is_drag_active = False

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Dashed Border Frame
        pen_color = QColor(COLOR_ACCENT_RED if self.is_drag_active else COLOR_BORDER_DASHED)
        border_pen = QPen(pen_color, 2.0, Qt.PenStyle.DashLine)
        border_pen.setDashPattern([6, 6])
        painter.setPen(border_pen)
        painter.setBrush(QColor(33, 35, 45, 120) if self.is_drag_active else QColor(23, 24, 31, 100))
        painter.drawRoundedRect(QRectF(4, 4, w - 8, h - 8), 16, 16)

        # Center Y
        cy = h * 0.40

        # Draw Left File Icon
        icon_size = 56.0
        left_icon_rect = QRectF(w * 0.16, cy - icon_size / 2.0, icon_size, icon_size * 1.25)
        VectorIconFactory.draw_file_outline(painter, left_icon_rect, color="#E5E7EB", stroke_width=2.5)

        # Draw Right Lock File Icon
        right_icon_rect = QRectF(w * 0.84 - icon_size, cy - icon_size / 2.0, icon_size, icon_size * 1.25)
        VectorIconFactory.draw_lock_file(painter, right_icon_rect, color="#E5E7EB", stroke_width=2.5)

        # Draw Connecting Red Arrow
        arrow_start_x = left_icon_rect.right() + 30.0
        arrow_end_x = right_icon_rect.left() - 30.0
        if arrow_end_x > arrow_start_x:
            arrow_pen = QPen(QColor(COLOR_ACCENT_RED), 2.0)
            arrow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(arrow_pen)
            painter.drawLine(QPointF(arrow_start_x, cy + 8), QPointF(arrow_end_x, cy + 8))
            # Arrow head pointing right
            painter.drawLine(QPointF(arrow_end_x, cy + 8), QPointF(arrow_end_x - 8, cy + 3))
            painter.drawLine(QPointF(arrow_end_x, cy + 8), QPointF(arrow_end_x - 8, cy + 13))

        # Text: UPLOAD FILES or FOLDERS
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        font_title = QFont("Segoe UI", 16, QFont.Weight.DemiBold)
        font_title.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.2)
        painter.setFont(font_title)
        painter.drawText(
            QRectF(0, h * 0.62, w, 28),
            Qt.AlignmentFlag.AlignCenter,
            "UPLOAD FILES or FOLDERS",
        )

        # Subtitle: .txt .csv json
        painter.setPen(QColor(COLOR_TEXT_SECONDARY))
        font_sub = QFont("Segoe UI", 12)
        painter.setFont(font_sub)
        painter.drawText(
            QRectF(0, h * 0.76, w, 22),
            Qt.AlignmentFlag.AlignCenter,
            ".txt  .csv  .json",
        )

        painter.end()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


# ==============================================================================
# Scanning Animation / Icon Widget (Wireframe 2)
# ==============================================================================
class ScanningStatusWidget(QWidget):
    """Draws the Wireframe 2 'Scanning Files' hero icon."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedHeight(120)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())

        # Centered Search File Icon
        icon_w = 46.0
        icon_h = 58.0
        rect = QRectF((w - icon_w) / 2.0, (h - icon_h) / 2.0, icon_w, icon_h)
        VectorIconFactory.draw_search_file(painter, rect, color="#E5E7EB", stroke_width=2.5)
        painter.end()


# ==============================================================================
# Main Scan View Container
# ==============================================================================
class ScanView(QWidget):
    """Scan ingestion and active scanning view."""

    # Emitted when a scan starts
    scan_started = Signal()
    # Emitted when an individual file finishes scanning during an active scan: (result, current, total)
    file_scanned_live = Signal(object, int, int)
    # Emitted when a scan completes with results: summary, findings_count
    scan_ready_for_redaction = Signal(object, int)

    def __init__(self, engine: ScanEngine, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.engine = engine
        self.active_worker: Optional[ScanWorker] = None
        self.last_summary: Optional[ScanSummary] = None

        # Accept Drag and Drop
        self.setAcceptDrops(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(16)

        # Stacked widget for the 3 visual states:
        # 0: Upload Dropzone (Wireframe 1)
        # 1: Scanning In Progress (Wireframe 2)
        # 2: Scan Prepared / Findings Summary
        self.stack = QStackedWidget(self)
        layout.addWidget(self.stack)

        self._build_upload_state()
        self._build_scanning_state()
        self._build_prepared_state()

        self.stack.setCurrentIndex(0)

    # --------------------------------------------------------------------------
    # State 0: Upload Dropzone
    # --------------------------------------------------------------------------
    def _build_upload_state(self) -> None:
        page = QWidget()
        vbox = QVBoxLayout(page)
        vbox.setContentsMargins(10, 20, 10, 20)
        vbox.setSpacing(20)

        # Hero Dropzone
        self.dropzone = DropzoneHeroWidget(page)
        self.dropzone.clicked.connect(self._prompt_file_or_folder)
        vbox.addWidget(self.dropzone, 1)

        # Quick action buttons row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        btn_row.addStretch()

        self.btn_select_file = QPushButton("Choose File(s)", page)
        self.btn_select_file.setProperty("class", "SecondaryButton")
        self.btn_select_file.clicked.connect(self._choose_files)
        btn_row.addWidget(self.btn_select_file)

        self.btn_select_folder = QPushButton("Choose Folder", page)
        self.btn_select_folder.setProperty("class", "SecondaryButton")
        self.btn_select_folder.clicked.connect(self._choose_folder)
        btn_row.addWidget(self.btn_select_folder)

        btn_row.addStretch()
        vbox.addLayout(btn_row)

        self.stack.addWidget(page)

    # --------------------------------------------------------------------------
    # State 1: Scanning In Progress (Wireframe 2)
    # --------------------------------------------------------------------------
    def _build_scanning_state(self) -> None:
        page = QWidget()
        card = QFrame(page)
        card.setObjectName("CardFrame")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(30, 40, 30, 40)
        card_layout.setSpacing(16)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Header Title: Scanning Files
        self.lbl_scan_title = QLabel("Scanning Files", card)
        self.lbl_scan_title.setStyleSheet("font-size: 20px; font-weight: 600; color: #FFFFFF;")
        self.lbl_scan_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(self.lbl_scan_title)

        # Center Search File Icon
        self.scan_anim = ScanningStatusWidget(card)
        card_layout.addWidget(self.scan_anim)

        # File Status Label
        self.lbl_scan_status = QLabel("Discovering files...", card)
        self.lbl_scan_status.setObjectName("MutedLabel")
        self.lbl_scan_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(self.lbl_scan_status)

        # Progress Bar
        self.progress_bar = QProgressBar(card)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedWidth(380)
        card_layout.addWidget(self.progress_bar)

        # Cancel Button
        self.btn_cancel = QPushButton("Cancel Scan", card)
        self.btn_cancel.setProperty("class", "DangerButton")
        self.btn_cancel.clicked.connect(self._cancel_scan)
        card_layout.addWidget(self.btn_cancel)

        page_layout = QVBoxLayout(page)
        page_layout.addWidget(card)
        self.stack.addWidget(page)

    # --------------------------------------------------------------------------
    # State 2: Scan Prepared / Findings Summary
    # --------------------------------------------------------------------------
    def _build_prepared_state(self) -> None:
        page = QWidget()
        vbox = QVBoxLayout(page)
        vbox.setContentsMargins(10, 10, 10, 10)
        vbox.setSpacing(12)

        # Summary Header Banner
        header_card = QFrame(page)
        header_card.setObjectName("CardFrame")
        h_layout = QHBoxLayout(header_card)
        h_layout.setContentsMargins(16, 12, 16, 12)

        self.lbl_results_summary = QLabel("Scan Complete", header_card)
        self.lbl_results_summary.setStyleSheet("font-size: 16px; font-weight: 600;")
        h_layout.addWidget(self.lbl_results_summary)
        h_layout.addStretch()

        self.btn_new_scan = QPushButton("Scan Another Target", header_card)
        self.btn_new_scan.setProperty("class", "SecondaryButton")
        self.btn_new_scan.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        h_layout.addWidget(self.btn_new_scan)
        vbox.addWidget(header_card)

        # Quick Findings Table
        self.table = QTableWidget(page)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["File", "Sensitive Entity", "Severity", "Line:Col", "Masked Preview"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        vbox.addWidget(self.table, 1)

        self.stack.addWidget(page)

    # --------------------------------------------------------------------------
    # Target Ingestion Handlers
    # --------------------------------------------------------------------------
    def _prompt_file_or_folder(self) -> None:
        self._choose_folder()

    def _choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Target Files to Scan",
            "",
            "Supported Files (*.txt *.csv *.json);;All Files (*.*)",
        )
        if files:
            self.start_scan(files[0] if len(files) == 1 else Path(files[0]).parent)

    def _choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Select Target Folder to Scan")
        if folder:
            self.start_scan(folder)

    # --------------------------------------------------------------------------
    # Drag and Drop Events
    # --------------------------------------------------------------------------
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.dropzone.is_drag_active = True
            self.dropzone.update()

    def dragLeaveEvent(self, event) -> None:
        self.dropzone.is_drag_active = False
        self.dropzone.update()

    def dropEvent(self, event) -> None:
        self.dropzone.is_drag_active = False
        self.dropzone.update()

        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.start_scan(path)

    # --------------------------------------------------------------------------
    # Scan Execution
    # --------------------------------------------------------------------------
    def start_scan(self, target_path: Union[str, Path]) -> None:
        target = Path(target_path)
        if not target.exists():
            return

        self.stack.setCurrentIndex(1)
        self.lbl_scan_status.setText(f"Scanning target: {target.name}")
        self.progress_bar.setValue(0)

        self.scan_started.emit()

        # Launch QThread Worker
        self.active_worker = ScanWorker(
            engine=self.engine,
            target_path=target,
            recursive=True,
            save_to_history=True,
            parent=self,
        )
        self.active_worker.file_started.connect(self._on_file_started)
        self.active_worker.file_completed.connect(self._on_file_completed)
        self.active_worker.progress.connect(self._on_progress)
        self.active_worker.scan_finished.connect(self._on_scan_finished)
        self.active_worker.scan_error.connect(self._on_scan_error)
        self.active_worker.start()

    def _on_file_completed(self, result: object, current: int, total: int) -> None:
        self.file_scanned_live.emit(result, current, total)

    def _on_file_started(self, path_str: str, current: int, total: int) -> None:
        fname = Path(path_str).name
        self.lbl_scan_status.setText(f"Inspecting file {current}/{total}: {fname}")

    def _on_progress(self, current: int, total: int) -> None:
        if total > 0:
            pct = int((current / total) * 100)
            self.progress_bar.setValue(pct)

    def _on_scan_finished(self, summary: ScanSummary) -> None:
        self.last_summary = summary
        self.stack.setCurrentIndex(2)

        # Populate findings preview table
        self.table.setRowCount(0)
        row_idx = 0
        for res in summary.file_results:
            for f in res.findings:
                self.table.insertRow(row_idx)

                item_file = QTableWidgetItem(res.file_name)
                item_entity = QTableWidgetItem(f.entity_type.display_name)
                item_sev = QTableWidgetItem(f.severity.value)

                # Color severity
                color = SEVERITY_COLORS.get(f.severity.value, "#FFFFFF")
                item_sev.setForeground(QColor(color))

                item_loc = QTableWidgetItem(f"{f.line_number}:{f.column_number}")
                item_mask = QTableWidgetItem(f.masked_value)

                self.table.setItem(row_idx, 0, item_file)
                self.table.setItem(row_idx, 1, item_entity)
                self.table.setItem(row_idx, 2, item_sev)
                self.table.setItem(row_idx, 3, item_loc)
                self.table.setItem(row_idx, 4, item_mask)
                row_idx += 1

        self.lbl_results_summary.setText(
            f"Scan Complete: {summary.total_findings} findings detected across {summary.total_files_scanned} file(s) ({summary.duration_seconds:.2f}s)"
        )

        # Signal main window with findings count to wake up "Create RedactX" button!
        self.scan_ready_for_redaction.emit(summary, summary.total_findings)

    def _on_scan_error(self, err_msg: str) -> None:
        self.lbl_scan_status.setText(f"Error during scan: {err_msg}")

    def _cancel_scan(self) -> None:
        if self.active_worker and self.active_worker.isRunning():
            self.active_worker.cancel()
            self.lbl_scan_status.setText("Cancelling scan...")
