"""Main Window for RedactX GUI.

Implements the top header, stacked multi-view display, fixed bottom pill navigation,
and the reactive 'Create RedactX' button that blurs until findings are discovered.
"""

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from redactX.detectors.registry import DetectorRegistry
from redactX.gui.nav_bar import BottomNavBar
from redactX.gui.theme import DARK_THEME_QSS
from redactX.gui.views.dashboard_view import DashboardView
from redactX.gui.views.history_view import HistoryView
from redactX.gui.views.scan_view import ScanView
from redactX.gui.views.settings_view import SettingsView
from redactX.gui.worker import RedactionWorker
from redactX.models.result import ScanSummary
from redactX.reports.reporter import ReportGenerator
from redactX.scanner.scanner import ScanEngine
from redactX.storage.history import HistoryDatabase


class MainWindow(QMainWindow):
    """Primary application window for RedactX."""

    def __init__(
        self,
        engine: Optional[ScanEngine] = None,
        history_db: Optional[HistoryDatabase] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("RedactX — Privacy-Preserving DLP")
        self.resize(1000, 680)
        self.setMinimumSize(850, 560)

        # Apply Dark Theme QSS
        self.setStyleSheet(DARK_THEME_QSS)

        # Core Engines
        self.history_db = history_db or HistoryDatabase()
        self.registry = DetectorRegistry(load_defaults=True)
        self.engine = engine or ScanEngine(registry=self.registry, history_db=self.history_db)

        self.current_summary: Optional[ScanSummary] = None
        self.active_redactor: Optional[RedactionWorker] = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        # Central Main Container
        central_widget = QWidget(self)
        central_widget.setObjectName("CentralContainer")
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(24, 20, 24, 18)
        main_layout.setSpacing(14)

        # 1. Top Header: 'RedactX' Logo
        header_layout = QHBoxLayout()
        lbl_logo = QLabel("RedactX", central_widget)
        lbl_logo.setObjectName("AppTitle")
        header_layout.addWidget(lbl_logo)
        header_layout.addStretch()

        lbl_badge = QLabel("100% Offline • Zero Cloud", central_widget)
        lbl_badge.setStyleSheet(
            "background-color: #17181F; border: 1px solid #2B2D3A; "
            "border-radius: 12px; padding: 4px 12px; color: #10B981; font-size: 11px; font-weight: 600;"
        )
        header_layout.addWidget(lbl_badge)
        main_layout.addLayout(header_layout)

        # 2. Central Multi-View Stacked Area
        self.view_stack = QStackedWidget(central_widget)
        main_layout.addWidget(self.view_stack, 1)

        # Page 0: Scan / Upload View
        self.scan_view = ScanView(engine=self.engine, parent=self)
        self.scan_view.scan_started.connect(self._on_scan_started)
        self.scan_view.file_scanned_live.connect(self._on_live_file_scanned)
        self.scan_view.scan_ready_for_redaction.connect(self._on_scan_ready_for_redaction)
        self.view_stack.addWidget(self.scan_view)

        # Page 1: History View
        self.history_view = HistoryView(history_db=self.history_db, parent=self)
        self.view_stack.addWidget(self.history_view)

        # Page 2: Dashboard View
        self.dashboard_view = DashboardView(history_db=self.history_db, parent=self)
        self.view_stack.addWidget(self.dashboard_view)

        # Page 3: Settings View
        self.settings_view = SettingsView(registry=self.registry, parent=self)
        self.view_stack.addWidget(self.settings_view)

        # 3. Fixed Bottom Bar matching Wireframes
        bottom_bar = QHBoxLayout()
        bottom_bar.setContentsMargins(4, 4, 4, 4)
        bottom_bar.setSpacing(16)

        # Left: Pill Navbar with 4 icons
        self.nav_bar = BottomNavBar(central_widget)
        self.nav_bar.tab_changed.connect(self._on_tab_changed)
        bottom_bar.addWidget(self.nav_bar)

        bottom_bar.addStretch()

        # Right: 'Create RedactX' Action Button
        # Starts blurred / disabled until a scan discovers redactable sensitive data
        self.btn_create_redactx = QPushButton("Create RedactX", central_widget)
        self.btn_create_redactx.setObjectName("CreateRedactXButton")
        self.btn_create_redactx.setEnabled(False)
        self.btn_create_redactx.setToolTip("Will activate once files are scanned and sensitive info is found.")
        self.btn_create_redactx.clicked.connect(self._execute_redaction)
        bottom_bar.addWidget(self.btn_create_redactx)

        main_layout.addLayout(bottom_bar)

    # --------------------------------------------------------------------------
    # Navigation & View Switching
    # --------------------------------------------------------------------------
    def _on_tab_changed(self, tab_index: int) -> None:
        self.view_stack.setCurrentIndex(tab_index)
        if tab_index == 1:
            self.history_view.load_history()
        elif tab_index == 2:
            self.dashboard_view.refresh_from_database()

    # --------------------------------------------------------------------------
    # Live Scan Streaming & Button Activation
    # --------------------------------------------------------------------------
    def _on_scan_started(self) -> None:
        self.btn_create_redactx.setEnabled(False)
        self.btn_create_redactx.setText("Scanning Target...")
        self.dashboard_view.on_scan_started()

    def _on_live_file_scanned(self, result: object, current_idx: int, total_count: int) -> None:
        self.dashboard_view.on_live_file_scanned(result, current_idx, total_count)

    def _on_scan_ready_for_redaction(self, summary: ScanSummary, findings_count: int) -> None:
        self.current_summary = summary

        # Update Dashboard with fresh scan metrics
        self.dashboard_view.update_from_summary(summary)

        # The 'Create RedactX' button comes alive if findings are present!
        if findings_count > 0:
            self.btn_create_redactx.setEnabled(True)
            self.btn_create_redactx.setText(f"Create RedactX ({findings_count} PII)")
            self.btn_create_redactx.setToolTip(f"Ready to sanitize {findings_count} sensitive entities across files.")
        else:
            self.btn_create_redactx.setEnabled(False)
            self.btn_create_redactx.setText("Create RedactX")
            self.btn_create_redactx.setToolTip("Target clean: no sensitive information detected to redact.")

    # --------------------------------------------------------------------------
    # Redaction Execution
    # --------------------------------------------------------------------------
    def _execute_redaction(self) -> None:
        if not self.current_summary:
            return

        files_with_findings = [r for r in self.current_summary.file_results if r.findings]
        if not files_with_findings:
            QMessageBox.information(self, "No Findings", "No sensitive items found in the current scan to redact.")
            return

        strategy = self.settings_view.get_selected_strategy()

        # Disable button during redaction
        self.btn_create_redactx.setEnabled(False)
        self.btn_create_redactx.setText("Redacting Files...")

        # Run batch redaction on worker thread
        self.active_redactor = RedactionWorker(
            results_with_findings=files_with_findings,
            strategy=strategy,
            parent=self,
        )
        self.active_redactor.redaction_finished.connect(self._on_redaction_finished)
        self.active_redactor.redaction_error.connect(self._on_redaction_error)
        self.active_redactor.start()

    def _on_redaction_finished(self, redacted_paths: list[str]) -> None:
        self.btn_create_redactx.setEnabled(True)
        self.btn_create_redactx.setText("Redaction Complete ✓")

        msg = (
            f"Successfully generated {len(redacted_paths)} sanitized file(s)!\n\n"
            f"Original files remain 100% untouched.\n"
            f"Redacted copies saved with the '_REDACTED' suffix:\n"
            + "\n".join(f"• {Path(p).name}" for p in redacted_paths[:5])
        )
        if len(redacted_paths) > 5:
            msg += f"\n...and {len(redacted_paths) - 5} more."

        # Show notification with Report Export option
        reply = QMessageBox.information(
            self,
            "Redaction Complete",
            msg,
            QMessageBox.StandardButton.Ok,
        )

        # Refresh dashboard and history
        self.history_view.load_history()
        self.dashboard_view.refresh_from_database()

    def _on_redaction_error(self, err_msg: str) -> None:
        self.btn_create_redactx.setEnabled(True)
        self.btn_create_redactx.setText("Create RedactX")
        QMessageBox.critical(self, "Redaction Error", f"Failed to redact files: {err_msg}")
