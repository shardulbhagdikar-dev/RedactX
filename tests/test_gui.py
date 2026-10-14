"""Tests for RedactX GUI components and view interactions.

Runs in Qt offscreen/headless mode for fast, headless test validation.
"""

import os
import tempfile
from pathlib import Path

# Ensure Qt runs headlessly in test mode
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtWidgets import QApplication

from redactX.gui.charts import (
    CategoryBarChart,
    DataLineageFlowGraph,
    SeverityDonutChart,
    TrendAreaChart,
)
from redactX.gui.main_window import MainWindow
from redactX.gui.nav_bar import BottomNavBar
from redactX.gui.views.dashboard_view import DashboardView
from redactX.gui.views.history_view import HistoryView
from redactX.gui.views.scan_view import ScanView
from redactX.gui.views.settings_view import SettingsView
from redactX.models.enums import EntityType, FileFormat, ScanStatus, Severity
from redactX.models.finding import CandidateMatch, Finding
from redactX.models.result import FileScanResult, ScanSummary
from redactX.redaction.redactor import MaskingStrategy
from redactX.scanner.scanner import ScanEngine
from redactX.storage.history import HistoryDatabase


@pytest.fixture(scope="session")
def qapp():
    """Ensure a singleton QApplication exists for the test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_db():
    """Provide a temporary SQLite database for testing."""
    import shutil
    tmp_dir = tempfile.mkdtemp()
    db_path = Path(tmp_dir) / "test_gui_history.db"
    db = HistoryDatabase(db_path=db_path)
    yield db
    shutil.rmtree(tmp_dir, ignore_errors=True)


class TestGUIComponents:
    """Test suite for GUI widgets, views, and navigation."""

    def test_bottom_nav_bar(self, qapp):
        nav = BottomNavBar()
        assert len(nav.buttons) == 4
        assert nav.buttons[0].isChecked()

        # Switch tab
        received_tabs = []
        nav.tab_changed.connect(lambda idx: received_tabs.append(idx))

        nav.buttons[2].click()
        assert received_tabs == [2]
        assert nav.buttons[2].isChecked()

    def test_charts_rendering_and_updates(self, qapp):
        # 1. Trend Area Chart
        trend_chart = TrendAreaChart()
        trend_chart.set_data([("10:00", 2), ("11:00", 8)])
        assert len(trend_chart.data_points) == 2

        # 2. Category Bar Chart
        bar_chart = CategoryBarChart()
        bar_chart.set_data([("Aadhaar", 5, "#EF4444")])
        assert len(bar_chart.categories) == 1

        # 3. Severity Donut Chart
        donut_chart = SeverityDonutChart()
        donut_chart.set_data({"CRITICAL": 3, "HIGH": 1, "MEDIUM": 0, "LOW": 0})
        assert donut_chart.severity_counts["CRITICAL"] == 3

        # 4. Data Lineage Flow Graph
        flow_chart = DataLineageFlowGraph()
        assert flow_chart.minimumSize().width() >= 200

    def test_settings_view_toggles(self, qapp):
        settings = SettingsView()
        det_name = "CreditCardDetector"
        cb = settings.checkboxes[det_name]

        # Toggle off
        cb.setChecked(False)
        assert not settings.registry.get_detector(det_name).enabled

        # Toggle back on
        cb.setChecked(True)
        assert settings.registry.get_detector(det_name).enabled

        # Strategy check
        assert settings.get_selected_strategy() == MaskingStrategy.PARTIAL

    def test_history_view_loads_scans(self, qapp, temp_db):
        # Create a sample scan result with one finding
        candidate = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532015112830366",
            start_idx=0,
            end_idx=16,
            line_number=1,
            column_number=1,
        )
        finding = Finding.from_candidate(
            candidate=candidate,
            severity=Severity.HIGH,
            context_snippet="card: 4532015112830366",
        )
        file_res = FileScanResult(
            file_path="C:/test/file.txt",
            file_name="file.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=100,
            findings=[finding],
            overall_risk=Severity.HIGH,
        )
        summary = ScanSummary.from_results(
            target_path="C:/test/folder",
            results=[file_res],
            duration_seconds=0.15,
        )
        temp_db.save_scan(summary)

        history_view = HistoryView(history_db=temp_db)
        assert history_view.table.rowCount() == 1
        assert history_view.table.item(0, 4).text() == "1"

        # Verify human-readable Date & Time column formatting
        date_item = history_view.table.item(0, 1)
        assert date_item is not None
        assert "+00:00" not in date_item.text()
        assert "T" not in date_item.text()
        assert "Raw UTC Timestamp:" in date_item.toolTip()

    def test_dashboard_view_updates(self, qapp, temp_db):
        dash = DashboardView(history_db=temp_db)
        # 1. Clean Zero State Verification
        assert dash.chart_trends.data_points == []
        assert dash.chart_violators.categories == []
        assert dash.chart_severity.severity_counts == {}
        assert dash.chart_lineage.files_count == 0
        assert dash.chart_lineage.findings_count == 0

        # 2. Live Scan Streaming Verification
        dash.on_scan_started()
        cand = CandidateMatch(
            entity_type=EntityType.AADHAAR,
            raw_value="987654321098",
            start_idx=0,
            end_idx=12,
            line_number=1,
            column_number=1,
        )
        finding = Finding.from_candidate(cand, severity=Severity.CRITICAL, context_snippet="aadhaar: 987654321098")
        file_res = FileScanResult(
            file_path="C:/test/id.txt",
            file_name="id.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=50,
            status=ScanStatus.COMPLETED,
            findings=[finding],
            overall_risk=Severity.CRITICAL,
        )

        dash.on_live_file_scanned(file_res, current_idx=1, total_count=1)
        assert dash.chart_severity.severity_counts.get("CRITICAL") == 1
        assert len(dash.chart_violators.categories) == 1
        assert dash.chart_violators.categories[0][0] == EntityType.AADHAAR.display_name
        assert dash.chart_lineage.files_count == 1
        assert dash.chart_lineage.findings_count == 1

        # 3. Summary Finalization & Trend Points
        summary = ScanSummary.from_results("C:/test", [file_res], duration_seconds=0.08)
        dash.update_from_summary(summary)
        assert len(dash.chart_trends.data_points) == 1
        assert dash.chart_trends.data_points[0][1] == 1

        # 4. Redaction Sanitization Node
        dash.on_redaction_completed(1)
        assert dash.chart_lineage.redacted_count == 1

    def test_main_window_state_and_reactive_button(self, qapp, temp_db):
        engine = ScanEngine(history_db=temp_db)
        window = MainWindow(engine=engine, history_db=temp_db)

        # Initial state: 'Create RedactX' button must be blurred/disabled
        assert not window.btn_create_redactx.isEnabled()
        assert window.btn_create_redactx.text() == "Create RedactX"

        # Tab navigation switching
        window.nav_bar.buttons[1].click()
        assert window.view_stack.currentIndex() == 1  # History view

        window.nav_bar.buttons[2].click()
        assert window.view_stack.currentIndex() == 2  # Dashboard view

        window.nav_bar.buttons[0].click()
        assert window.view_stack.currentIndex() == 0  # Scan view

        # Simulate finding discovery: button must come alive!
        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532015112830366",
            start_idx=0,
            end_idx=16,
            line_number=1,
            column_number=1,
        )
        mock_finding = Finding.from_candidate(
            cand,
            severity=Severity.CRITICAL,
            context_snippet="card: 4532015112830366",
        )
        file_result = FileScanResult(
            file_path="dummy.txt",
            file_name="dummy.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=100,
            status=ScanStatus.COMPLETED,
            findings=[mock_finding],
            overall_risk=Severity.CRITICAL,
        )
        mock_summary = ScanSummary.from_results(
            target_path="dummy.txt",
            results=[file_result],
            duration_seconds=0.05,
        )

        window._on_scan_ready_for_redaction(mock_summary, findings_count=1)

        # Button should now be ALIVE (enabled)
        assert window.btn_create_redactx.isEnabled()
        assert "1 PII" in window.btn_create_redactx.text()

    def test_redaction_worker(self, qapp, tmp_path):
        from redactX.gui.worker import RedactionWorker

        test_file = tmp_path / "secret_doc.txt"
        test_file.write_text("Customer: John, Card: 4532015112830366\n", encoding="utf-8")

        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532015112830366",
            start_idx=22,
            end_idx=38,
            line_number=1,
            column_number=23,
        )
        finding = Finding.from_candidate(cand, severity=Severity.CRITICAL, context_snippet="Card: 4532015112830366")
        file_res = FileScanResult(
            file_path=str(test_file),
            file_name=test_file.name,
            file_format=FileFormat.TXT,
            file_size_bytes=test_file.stat().st_size,
            status=ScanStatus.COMPLETED,
            findings=[finding],
            overall_risk=Severity.CRITICAL,
        )

        redacted_paths = []
        worker = RedactionWorker([file_res], strategy=MaskingStrategy.PARTIAL)
        worker.redaction_finished.connect(lambda paths: redacted_paths.extend(paths))
        worker.run()

        assert len(redacted_paths) == 1
        redacted_path = Path(redacted_paths[0])
        assert redacted_path.exists()
        assert "secret_doc_REDACTED.txt" in redacted_path.name
        content = redacted_path.read_text(encoding="utf-8")
        assert "4532015112830366" not in content
        assert "0366" in content  # Partial mask retains last 4 digits
        # Original untouched
        assert test_file.read_text(encoding="utf-8") == "Customer: John, Card: 4532015112830366\n"
