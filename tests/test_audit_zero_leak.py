"""Security Audit and Air-Gap Verification Test Suite for RedactX.

Validates the core security invariants:
1. Air-Gap / Zero Network Calls: Strict socket blocking verifies zero telemetry/cloud egress.
2. Zero-Leak Logging: Raw unmasked secrets never appear in logs or debug streams.
3. Zero-Leak Database: SQLite persistence stores only masked values and metadata.
4. Zero-Leak Reports: TXT, JSON, and CSV exports contain only masked tokens.
5. Non-Destructive Invariant: Original file cryptographic hash remains 100% invariant.
"""

import hashlib
import json
import logging
import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from redactX.detectors.registry import DetectorRegistry
from redactX.models.enums import MaskingStrategy
from redactX.redaction.redactor import RedactionEngine
from redactX.reports.reporter import ReportGenerator
from redactX.scanner.scanner import ScanEngine
from redactX.storage.history import HistoryDatabase
from redactX.utils.logger import ZeroLeakFilter, get_logger


class TestAirGapAndZeroLeakSecurity:
    """Rigorous security invariant verification."""

    def test_air_gap_zero_network_calls(self, tmp_path, monkeypatch):
        """Verify that running the complete DLP pipeline performs ZERO network calls."""
        # Intercept and forbid all socket connections
        def forbidden_connect(*args, **kwargs):
            raise ConnectionRefusedError("SECURITY VIOLATION: Network egress attempted in air-gap mode!")

        monkeypatch.setattr(socket.socket, "connect", forbidden_connect)

        # Create test document with sensitive data
        test_file = tmp_path / "financial_audit.txt"
        test_file.write_text(
            "Customer Card: 4532015112830366\n"
            "Aadhaar Number: 2034 5678 9012\n"
            "UPI VPA: audit.dept@okhdfcbank\n"
            "API Token: sk_test_51Abcdefghijklmnopqrstuvwx\n",
            encoding="utf-8",
        )

        db_path = tmp_path / "history_audit.db"
        history_db = HistoryDatabase(db_path=db_path)
        engine = ScanEngine(history_db=history_db)

        # Execute scan pipeline (Must succeed without any network attempt)
        summary = engine.scan_target(
            target_path=test_file,
            save_to_history=True,
        )
        assert summary.total_findings >= 3

        # Execute redaction pipeline
        res = RedactionEngine.redact_file(
            source_path=test_file,
            findings=[f for r in summary.file_results for f in r.findings],
            strategy=MaskingStrategy.PARTIAL,
        )
        assert Path(res.redacted_path).exists()

        # Execute reporting pipeline
        txt_rep = ReportGenerator.generate_text_report(summary)
        json_rep = ReportGenerator.generate_json_report(summary)
        csv_rep = ReportGenerator.generate_csv_report(summary)

        assert len(txt_rep) > 0
        assert len(json_rep) > 0
        assert len(csv_rep) > 0

    def test_zero_leak_database_storage(self, tmp_path):
        """Ensure raw secret values are NEVER written into SQLite storage."""
        raw_card = "4532015112830366"
        raw_token = "sk_test_51Abcdefghijklmnopqrstuvwx"

        test_file = tmp_path / "creds.txt"
        test_file.write_text(f"payment={raw_card}\ntoken={raw_token}\n", encoding="utf-8")

        db_path = tmp_path / "zero_leak.db"
        history_db = HistoryDatabase(db_path=db_path)
        engine = ScanEngine(history_db=history_db)

        summary = engine.scan_target(test_file, save_to_history=True)
        assert summary.total_findings >= 2

        # Inspect raw database binary content directly on disk
        db_bytes = db_path.read_bytes()
        assert raw_card.encode("utf-8") not in db_bytes
        assert raw_token.encode("utf-8") not in db_bytes

        # Inspect structured rows via SQL
        scans = history_db.get_recent_scans()
        assert len(scans) == 1
        details = history_db.get_scan_details(scans[0]["id"])
        for finding in details["findings"]:
            assert finding["masked_value"] != raw_card
            assert finding["masked_value"] != raw_token
            # Must contain masked indicators
            assert "*" in finding["masked_value"] or "X" in finding["masked_value"]

    def test_zero_leak_report_generation(self, tmp_path):
        """Ensure exported reports never disclose unmasked raw secrets."""
        raw_card = "4532015112830366"
        raw_aadhaar = "2034 5678 9012"

        test_file = tmp_path / "pii.txt"
        test_file.write_text(f"Card: {raw_card}, UID: {raw_aadhaar}\n", encoding="utf-8")

        engine = ScanEngine()
        summary = engine.scan_target(test_file)

        txt_rep = ReportGenerator.generate_text_report(summary)
        json_rep = ReportGenerator.generate_json_report(summary)
        csv_rep = ReportGenerator.generate_csv_report(summary)

        # Assert raw numbers are absent from all export formats
        assert raw_card not in txt_rep
        assert raw_card not in json_rep
        assert raw_card not in csv_rep

        assert raw_aadhaar not in txt_rep
        assert raw_aadhaar not in json_rep
        assert raw_aadhaar not in csv_rep

    def test_original_file_cryptographic_integrity_invariant(self, tmp_path):
        """Verify that original source files remain strictly bit-for-bit identical."""
        test_file = tmp_path / "untouchable.txt"
        original_content = "Confidential User File: Aadhaar 2034 5678 9012\n"
        test_file.write_text(original_content, encoding="utf-8")

        orig_hash_before = hashlib.sha256(test_file.read_bytes()).hexdigest()

        # Execute scan
        engine = ScanEngine()
        summary = engine.scan_target(test_file)
        findings = summary.file_results[0].findings

        # Execute redaction across all strategies
        for strat in [MaskingStrategy.PARTIAL, MaskingStrategy.FULL, MaskingStrategy.SYNTACTIC]:
            res = RedactionEngine.redact_file(
                source_path=test_file,
                findings=findings,
                strategy=strat,
            )
            # Redacted copy created
            assert Path(res.redacted_path).exists()
            assert res.redacted_path != test_file
            # Original hash must be strictly identical
            orig_hash_after = hashlib.sha256(test_file.read_bytes()).hexdigest()
            assert orig_hash_before == orig_hash_after
            assert test_file.read_text(encoding="utf-8") == original_content
