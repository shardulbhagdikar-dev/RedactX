"""Unit tests for the Report Generator component."""

import csv
import json
from pathlib import Path

import pytest
from redactX.models.enums import Confidence, EntityType, FileFormat, ScanStatus, Severity
from redactX.models.finding import Finding
from redactX.models.result import FileScanResult, ScanSummary
from redactX.reports.reporter import ReportGenerator


@pytest.fixture
def mock_summary() -> ScanSummary:
    raw_secret_card = "4532015112830366"
    raw_secret_token = "sk_test_1234567890abcdef1234"

    f1 = Finding(
        entity_type=EntityType.CREDIT_CARD,
        masked_value="**** **** **** 0366",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        confidence_score=0.96,
        line_number=2,
        column_number=15,
        start_idx=25,
        end_idx=41,
        context_snippet="billing card: **** **** **** 0366",
        explanation="Passed Luhn checksum validation (Visa)",
        validator_passed=True,
        raw_value=raw_secret_card,
    )

    f2 = Finding(
        entity_type=EntityType.API_KEY,
        masked_value="sk_test_********...1234",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        confidence_score=0.92,
        line_number=10,
        column_number=5,
        start_idx=120,
        end_idx=148,
        context_snippet="api_key = sk_test_********...1234",
        explanation="High entropy token structure",
        validator_passed=True,
        raw_value=raw_secret_token,
    )

    res1 = FileScanResult(
        file_path="C:/data/finance.csv",
        file_name="finance.csv",
        file_format=FileFormat.CSV,
        file_size_bytes=2048,
        status=ScanStatus.COMPLETED,
        findings=[f1],
        overall_risk=Severity.CRITICAL,
        scan_duration_ms=12.5,
    )

    res2 = FileScanResult(
        file_path="C:/data/config.json",
        file_name="config.json",
        file_format=FileFormat.JSON,
        file_size_bytes=1024,
        status=ScanStatus.COMPLETED,
        findings=[f2],
        overall_risk=Severity.CRITICAL,
        scan_duration_ms=8.2,
    )

    res3 = FileScanResult(
        file_path="C:/data/clean.txt",
        file_name="clean.txt",
        file_format=FileFormat.TXT,
        file_size_bytes=512,
        status=ScanStatus.COMPLETED,
        findings=[],
        overall_risk=Severity.CLEAN,
        scan_duration_ms=3.1,
    )

    return ScanSummary.from_results(
        target_path="C:/data",
        results=[res1, res2, res3],
        duration_seconds=0.24,
    )


class TestReportGenerator:
    def test_text_report_generation_and_zero_leak(self, mock_summary: ScanSummary):
        report = ReportGenerator.generate_text_report(mock_summary)

        assert "REDACTX SECURITY AUDIT REPORT" in report
        assert "Overall Risk:     CRITICAL" in report
        assert "Total Files Scanned:       3" in report
        assert "Files With Findings:       2" in report
        assert "Total Findings Detected:   2" in report
        assert "**** **** **** 0366" in report
        assert "Passed Luhn checksum validation (Visa)" in report

        # Zero-leak assertion: raw secrets MUST NOT be present in output
        assert "4532015112830366" not in report
        assert "sk_test_1234567890abcdef1234" not in report

    def test_text_report_clean_environment(self):
        clean_res = FileScanResult(
            file_path="C:/data/clean.txt",
            file_name="clean.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=100,
            findings=[],
        )
        clean_summary = ScanSummary.from_results(
            target_path="C:/data",
            results=[clean_res],
            duration_seconds=0.05,
        )

        report = ReportGenerator.generate_text_report(clean_summary)
        assert "Target environment is CLEAN" in report
        assert "Overall Risk:     CLEAN" in report

    def test_json_report_generation(self, mock_summary: ScanSummary):
        json_str = ReportGenerator.generate_json_report(mock_summary)
        data = json.loads(json_str)

        assert data["overall_risk"] == "CRITICAL"
        assert data["total_findings"] == 2
        assert len(data["file_results"]) == 3

        # Zero-leak verification in serialized JSON
        assert "raw_value" not in json_str
        assert "4532015112830366" not in json_str

    def test_csv_report_generation(self, mock_summary: ScanSummary):
        csv_str = ReportGenerator.generate_csv_report(mock_summary)
        reader = csv.reader(csv_str.strip().splitlines())
        rows = list(reader)

        # Header + 2 findings = 3 rows
        assert len(rows) == 3
        headers = rows[0]
        assert "Entity Type" in headers
        assert "Masked Value" in headers
        assert "Severity" in headers

        # Row 1 check
        assert rows[1][5] == "CREDIT_CARD"
        assert rows[1][7] == "CRITICAL"
        assert rows[1][10] == "**** **** **** 0366"

        # Zero-leak check
        assert "4532015112830366" not in csv_str

    def test_export_report_to_files(self, mock_summary: ScanSummary, tmp_path: Path):
        # 1. Export TXT
        txt_file = tmp_path / "audit.txt"
        ReportGenerator.export_report(mock_summary, txt_file)
        assert txt_file.exists()
        assert "REDACTX SECURITY AUDIT REPORT" in txt_file.read_text(encoding="utf-8")

        # 2. Export JSON
        json_file = tmp_path / "audit.json"
        ReportGenerator.export_report(mock_summary, json_file)
        assert json_file.exists()
        loaded = json.loads(json_file.read_text(encoding="utf-8"))
        assert loaded["total_findings"] == 2

        # 3. Export CSV
        csv_file = tmp_path / "audit.csv"
        ReportGenerator.export_report(mock_summary, csv_file)
        assert csv_file.exists()
        with open(csv_file, "r", encoding="utf-8") as f:
            lines = list(csv.reader(f))
        assert len(lines) == 3

        # 4. Invalid format error
        bad_file = tmp_path / "audit.pdf"
        with pytest.raises(ValueError, match="Unsupported report export format"):
            ReportGenerator.export_report(mock_summary, bad_file)
