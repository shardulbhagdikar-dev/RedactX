"""Unit tests for the SQLite HistoryDatabase component."""

from pathlib import Path

import pytest
from redactX.models.enums import Confidence, EntityType, FileFormat, ScanStatus, Severity
from redactX.models.finding import Finding
from redactX.models.result import FileScanResult, ScanSummary
from redactX.storage.history import HistoryDatabase


@pytest.fixture
def sample_summary() -> ScanSummary:
    f1 = Finding(
        entity_type=EntityType.CREDIT_CARD,
        masked_value="**** **** **** 0366",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        confidence_score=0.95,
        line_number=2,
        column_number=10,
        start_idx=15,
        end_idx=31,
        context_snippet="card: **** **** **** 0366",
        explanation="Luhn validated",
        validator_passed=True,
        raw_value="4532015112830366",
    )

    f2 = Finding(
        entity_type=EntityType.EMAIL,
        masked_value="u***@corp.in",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        confidence_score=0.90,
        line_number=5,
        column_number=1,
        start_idx=40,
        end_idx=52,
        context_snippet="contact: u***@corp.in",
        explanation="RFC format",
        validator_passed=True,
        raw_value="user@corp.in",
    )

    res1 = FileScanResult(
        file_path="C:/data/file1.csv",
        file_name="file1.csv",
        file_format=FileFormat.CSV,
        file_size_bytes=1024,
        status=ScanStatus.COMPLETED,
        findings=[f1, f2],
        overall_risk=Severity.CRITICAL,
        scan_duration_ms=25.0,
    )

    return ScanSummary.from_results(
        target_path="C:/data",
        results=[res1],
        duration_seconds=0.15,
        scan_id="test_scan_01",
    )


class TestHistoryDatabase:
    def test_init_and_save_scan(self, tmp_path: Path, sample_summary: ScanSummary):
        db_file = tmp_path / "test_history.db"
        db = HistoryDatabase(db_file)

        saved_id = db.save_scan(sample_summary)
        assert saved_id == "test_scan_01"
        assert db_file.exists()

    def test_get_recent_scans_and_details(self, tmp_path: Path, sample_summary: ScanSummary):
        db_file = tmp_path / "test_history.db"
        db = HistoryDatabase(db_file)
        db.save_scan(sample_summary)

        recent = db.get_recent_scans(limit=10)
        assert len(recent) == 1
        assert recent[0]["id"] == "test_scan_01"
        assert recent[0]["overall_risk"] == "CRITICAL"
        assert recent[0]["total_findings"] == 2
        assert isinstance(recent[0]["severity_breakdown"], dict)

        # Get details
        details = db.get_scan_details("test_scan_01")
        assert details is not None
        assert details["target_path"] == "C:/data"
        assert len(details["findings"]) == 2

        # Check finding details and zero-leak compliance
        finding_item = details["findings"][0]
        assert finding_item["entity_type"] == "CREDIT_CARD"
        assert finding_item["masked_value"] == "**** **** **** 0366"
        assert "raw_value" not in finding_item

    def test_delete_scan_cascades_findings(self, tmp_path: Path, sample_summary: ScanSummary):
        db_file = tmp_path / "test_history.db"
        db = HistoryDatabase(db_file)
        db.save_scan(sample_summary)

        # Delete scan
        deleted = db.delete_scan("test_scan_01")
        assert deleted is True

        # Verify scan and child findings are gone
        assert db.get_scan_details("test_scan_01") is None
        assert len(db.get_recent_scans()) == 0

    def test_clear_history(self, tmp_path: Path, sample_summary: ScanSummary):
        db_file = tmp_path / "test_history.db"
        db = HistoryDatabase(db_file)
        db.save_scan(sample_summary)

        count = db.clear_history()
        assert count == 1
        assert len(db.get_recent_scans()) == 0

    def test_get_statistics(self, tmp_path: Path, sample_summary: ScanSummary):
        db_file = tmp_path / "test_history.db"
        db = HistoryDatabase(db_file)
        db.save_scan(sample_summary)

        stats = db.get_statistics()
        assert stats["total_scans"] == 1
        assert stats["total_files"] == 1
        assert stats["total_findings"] == 2
        assert stats["severity_counts"]["CRITICAL"] == 1
        assert stats["severity_counts"]["LOW"] == 1
        assert "CREDIT_CARD" in stats["top_entities"]
