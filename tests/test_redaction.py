"""Unit tests for the Redaction Engine."""

import csv
import json
from pathlib import Path

import pytest
from redactX.analysis.risk import RiskEngine
from redactX.detectors.registry import DetectorRegistry
from redactX.models.enums import Confidence, EntityType, Severity
from redactX.models.finding import Finding
from redactX.redaction.redactor import (
    MaskingStrategy,
    RedactionEngine,
    generate_replacement,
    redact_text,
)
from redactX.scanner.file_parser import FileParser


class TestMaskingStrategies:
    def test_generate_replacements(self):
        finding = Finding(
            entity_type=EntityType.EMAIL,
            masked_value="a***e@example.com",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            confidence_score=0.9,
            line_number=1,
            column_number=1,
            start_idx=0,
            end_idx=17,
            context_snippet="",
            explanation="Valid email",
            validator_passed=True,
            raw_value="alice@example.com",
        )

        # Partial
        assert generate_replacement(finding, MaskingStrategy.PARTIAL) == "a***e@example.com"

        # Full placeholder
        assert generate_replacement(finding, MaskingStrategy.FULL) == "[REDACTED_EMAIL]"

        # Syntactic (preserves @ and .)
        syntactic = generate_replacement(finding, MaskingStrategy.SYNTACTIC)
        assert "@" in syntactic
        assert "." in syntactic
        assert "alice" not in syntactic

        # Hash pseudonymization
        hashed = generate_replacement(finding, MaskingStrategy.HASH)
        assert hashed.startswith("[HASH:")
        assert hashed.endswith("]")


class TestReverseOffsetRedaction:
    def test_multi_finding_zero_drift(self):
        text = "Users: alice@corp.in and bob@corp.in in system."
        # Spans:
        # 'alice@corp.in': [7:20]
        # 'bob@corp.in': [25:36]
        f_alice = Finding(
            entity_type=EntityType.EMAIL,
            masked_value="[ALICE]",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            confidence_score=0.9,
            line_number=1,
            column_number=8,
            start_idx=7,
            end_idx=20,
            context_snippet="",
            explanation="",
            validator_passed=True,
            raw_value="alice@corp.in",
        )

        f_bob = Finding(
            entity_type=EntityType.EMAIL,
            masked_value="[BOB]",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            confidence_score=0.9,
            line_number=1,
            column_number=26,
            start_idx=25,
            end_idx=36,
            context_snippet="",
            explanation="",
            validator_passed=True,
            raw_value="bob@corp.in",
        )

        # Pass in ascending order to test that reverse sorting prevents drift
        redacted = redact_text(text, [f_alice, f_bob], strategy=MaskingStrategy.PARTIAL)
        assert redacted == "Users: [ALICE] and [BOB] in system."


class TestNonDestructiveFileRedaction:
    def test_txt_file_redaction_and_original_integrity(self, tmp_path: Path):
        orig_file = tmp_path / "notes.txt"
        orig_content = "Confidential note: api_key = test_secret_token_1234567890abcdef12345678 for admin."
        orig_file.write_text(orig_content, encoding="utf-8", newline="\n")

        # Scan with detector and risk engine
        parsed = FileParser.parse(orig_file)
        registry = DetectorRegistry()
        candidates = registry.detect_all(parsed)
        findings = RiskEngine.evaluate_candidates(candidates, parsed)

        assert len(findings) == 1

        # Redact
        res = RedactionEngine.redact_file(orig_file, findings, strategy=MaskingStrategy.FULL)

        redacted_path = Path(res.redacted_path)
        assert redacted_path.exists()
        assert redacted_path.name == "notes_REDACTED.txt"

        # Check original file content is strictly unchanged
        assert orig_file.read_text(encoding="utf-8") == orig_content

        # Check redacted file content
        redacted_content = redacted_path.read_text(encoding="utf-8")
        assert "test_secret_token_1234567890abcdef12345678" not in redacted_content
        assert "[REDACTED_API_KEY]" in redacted_content

    def test_overwriting_original_is_blocked(self, tmp_path: Path):
        test_file = tmp_path / "safe.txt"
        test_file.write_text("sample content", encoding="utf-8")

        with pytest.raises(ValueError, match="Non-Destructive Violation"):
            RedactionEngine.redact_file(test_file, [], output_path=test_file)

    def test_csv_file_redaction_validity(self, tmp_path: Path):
        csv_file = tmp_path / "employees.csv"
        csv_content = (
            "id,name,email,card\n"
            "1,Alice,alice@corp.in,4532015112830366\n"
            "2,Bob,bob@corp.in,5412-7512-3412-3452\n"
        )
        csv_file.write_text(csv_content, encoding="utf-8", newline="\n")

        parsed = FileParser.parse(csv_file)
        registry = DetectorRegistry()
        candidates = registry.detect_all(parsed)
        findings = RiskEngine.evaluate_candidates(candidates, parsed)

        res = RedactionEngine.redact_file(csv_file, findings, strategy=MaskingStrategy.PARTIAL)
        redacted_path = Path(res.redacted_path)

        # Ensure redacted CSV parses cleanly as valid tabular data
        with open(redacted_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0] == ["id", "name", "email", "card"]
        # Raw card numbers should not be present
        assert "4532015112830366" not in rows[1][3]
        assert "****" in rows[1][3]

    def test_json_file_redaction_validity(self, tmp_path: Path):
        json_file = tmp_path / "secrets.json"
        data = {
            "app": "RedactX",
            "auth": {
                "admin_email": "admin@redactx.io",
                "api_key": "redactx_mock_api_token_51HzT1234567890"
            }
        }
        json_file.write_text(json.dumps(data, indent=2), encoding="utf-8", newline="\n")

        parsed = FileParser.parse(json_file)
        registry = DetectorRegistry()
        candidates = registry.detect_all(parsed)
        findings = RiskEngine.evaluate_candidates(candidates, parsed)

        res = RedactionEngine.redact_file(json_file, findings, strategy=MaskingStrategy.PARTIAL)
        redacted_path = Path(res.redacted_path)

        # Ensure redacted JSON parses cleanly with json.loads
        with open(redacted_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded["app"] == "RedactX"
        assert loaded["auth"]["api_key"] != "redactx_mock_api_token_51HzT1234567890"
        assert "admin@redactx.io" not in loaded["auth"]["admin_email"]
