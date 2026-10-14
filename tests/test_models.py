"""Unit tests for RedactX domain models and enumerations."""

import pytest
from redactX.models import (
    CandidateMatch,
    Confidence,
    EntityType,
    FileFormat,
    FileInfo,
    FileScanResult,
    Finding,
    ScanStatus,
    ScanSummary,
    Severity,
)


class TestEnums:
    def test_severity_ordering_and_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.CLEAN

        # Sorting check
        severities = [Severity.MEDIUM, Severity.CRITICAL, Severity.CLEAN, Severity.LOW]
        assert sorted(severities) == [
            Severity.CLEAN,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.CRITICAL,
        ]

        # Weights check
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.CLEAN.weight == 0.0

    def test_confidence_mapping(self):
        assert Confidence.HIGH > Confidence.MEDIUM > Confidence.LOW
        assert Confidence.from_score(0.95) == Confidence.HIGH
        assert Confidence.from_score(0.70) == Confidence.MEDIUM
        assert Confidence.from_score(0.30) == Confidence.LOW

    def test_entity_type_defaults(self):
        assert EntityType.CREDIT_CARD.default_severity == Severity.CRITICAL
        assert EntityType.AADHAAR.default_severity == Severity.CRITICAL
        assert EntityType.API_KEY.default_severity == Severity.CRITICAL
        assert EntityType.UPI_ID.default_severity == Severity.HIGH
        assert EntityType.PHONE_NUMBER.default_severity == Severity.MEDIUM
        assert EntityType.EMAIL.default_severity == Severity.LOW
        assert EntityType.IPV4_ADDRESS.default_severity == Severity.LOW

    def test_file_format_from_extension(self):
        assert FileFormat.from_extension(".txt") == FileFormat.TXT
        assert FileFormat.from_extension("CSV") == FileFormat.CSV
        assert FileFormat.from_extension(".json") == FileFormat.JSON

        with pytest.raises(ValueError):
            FileFormat.from_extension(".exe")


class TestCandidateMatchAndFinding:
    def test_candidate_creation(self):
        cand = CandidateMatch(
            entity_type=EntityType.EMAIL,
            raw_value="alice@example.com",
            start_idx=10,
            end_idx=27,
            line_number=2,
            column_number=11,
            metadata={"source": "test"},
        )
        assert cand.length == 17
        assert cand.entity_type == EntityType.EMAIL

    def test_finding_masking_and_privacy_guarantee(self):
        raw_secret = "4532015112830366"
        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value=raw_secret,
            start_idx=0,
            end_idx=16,
            line_number=1,
            column_number=1,
        )
        finding = Finding.from_candidate(
            candidate=cand,
            confidence_score=0.95,
            context_snippet="Card: 4532015112830366",
            explanation="Luhn validated",
        )

        assert finding.masked_value == "************0366"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.HIGH
        assert finding.validator_passed is True

        # Ensure raw_value is NOT in repr
        repr_str = repr(finding)
        assert raw_secret not in repr_str

        # Ensure raw_value is NOT in default to_dict()
        dict_repr = finding.to_dict()
        assert "raw_value" not in dict_repr
        assert dict_repr["masked_value"] == "************0366"

        # Explicitly requested include_raw
        dict_with_raw = finding.to_dict(include_raw=True)
        assert dict_with_raw["raw_value"] == raw_secret

    def test_aadhaar_masking(self):
        cand = CandidateMatch(
            entity_type=EntityType.AADHAAR,
            raw_value="1234 5678 9012",
            start_idx=0,
            end_idx=14,
            line_number=1,
            column_number=1,
        )
        finding = Finding.from_candidate(cand)
        assert finding.masked_value == "XXXX XXXX 9012"

    def test_upi_masking(self):
        cand = CandidateMatch(
            entity_type=EntityType.UPI_ID,
            raw_value="rohit.sharma@okaxis",
            start_idx=0,
            end_idx=19,
            line_number=1,
            column_number=1,
        )
        finding = Finding.from_candidate(cand)
        assert finding.masked_value.startswith("r***")
        assert "@okaxis" in finding.masked_value


class TestScanResultAndSummary:
    def test_file_scan_result_risk_computation(self):
        result = FileScanResult(
            file_path="C:/data/test.csv",
            file_name="test.csv",
            file_format=FileFormat.CSV,
            file_size_bytes=1024,
            status=ScanStatus.COMPLETED,
        )
        assert result.overall_risk == Severity.CLEAN
        assert result.finding_count == 0

        # Add Low finding
        cand_email = CandidateMatch(EntityType.EMAIL, "a@b.com", 0, 7, 1, 1)
        finding_email = Finding.from_candidate(cand_email)
        result.findings.append(finding_email)
        result.compute_overall_risk()
        assert result.overall_risk == Severity.LOW

        # Add Critical finding
        cand_card = CandidateMatch(EntityType.CREDIT_CARD, "4532015112830366", 10, 26, 2, 1)
        finding_card = Finding.from_candidate(cand_card)
        result.findings.append(finding_card)
        result.compute_overall_risk()
        assert result.overall_risk == Severity.CRITICAL
        assert result.finding_count == 2
        assert result.findings_by_severity[Severity.CRITICAL] == 1
        assert result.findings_by_severity[Severity.LOW] == 1

    def test_scan_summary_aggregation(self):
        cand1 = CandidateMatch(EntityType.EMAIL, "a@b.com", 0, 7, 1, 1)
        cand2 = CandidateMatch(EntityType.UPI_ID, "user@upi", 10, 18, 2, 1)

        res1 = FileScanResult(
            file_path="f1.txt",
            file_name="f1.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=100,
            findings=[Finding.from_candidate(cand1)],
        )
        res1.compute_overall_risk()

        res2 = FileScanResult(
            file_path="f2.json",
            file_name="f2.json",
            file_format=FileFormat.JSON,
            file_size_bytes=200,
            findings=[Finding.from_candidate(cand2)],
        )
        res2.compute_overall_risk()

        res3 = FileScanResult(
            file_path="clean.txt",
            file_name="clean.txt",
            file_format=FileFormat.TXT,
            file_size_bytes=50,
            findings=[],
        )
        res3.compute_overall_risk()

        summary = ScanSummary.from_results(
            target_path="C:/data",
            results=[res1, res2, res3],
            duration_seconds=0.42,
        )

        assert summary.total_files_scanned == 3
        assert summary.total_files_with_findings == 2
        assert summary.total_findings == 2
        assert summary.overall_risk == Severity.HIGH  # Highest between LOW (res1) and HIGH (res2)
        assert summary.severity_breakdown[Severity.HIGH.value] == 1
        assert summary.severity_breakdown[Severity.LOW.value] == 1
        assert summary.entity_breakdown[EntityType.EMAIL.value] == 1
        assert summary.entity_breakdown[EntityType.UPI_ID.value] == 1


class TestMaskingHelper:
    def test_mask_all_entity_types(self):
        from redactX.utils.masking_helper import mask_sensitive_value

        # Email
        assert mask_sensitive_value("admin@example.com", EntityType.EMAIL) == "a***n@example.com"
        assert mask_sensitive_value("a@b.com", EntityType.EMAIL) == "a***@b.com"

        # Phone Number
        phone_masked = mask_sensitive_value("+91 9876543210", EntityType.PHONE_NUMBER)
        assert phone_masked.startswith("+91")
        assert phone_masked.endswith("10")
        assert "*" in phone_masked

        # Aadhaar
        assert mask_sensitive_value("1234-5678-9012", EntityType.AADHAAR) == "XXXX-XXXX-9012"
        assert mask_sensitive_value("123456789012", EntityType.AADHAAR) == "XXXXXXXX9012"

        # Card
        assert mask_sensitive_value("4111 2222 3333 4444", EntityType.CREDIT_CARD) == "**** **** **** 4444"
        assert mask_sensitive_value("4111-2222-3333-4444", EntityType.CREDIT_CARD) == "****-****-****-4444"

        # API Key
        api_masked = mask_sensitive_value("sk_test_abcdef1234567890", EntityType.API_KEY)
        assert api_masked.startswith("sk_test")
        assert "..." in api_masked
        assert api_masked.endswith("7890")

        # Password
        pwd_masked = mask_sensitive_value("SuperSecret123!", EntityType.PASSWORD)
        assert pwd_masked == "*" * 15

        # IPv4
        ip_masked = mask_sensitive_value("192.168.1.100", EntityType.IPV4_ADDRESS)
        assert ip_masked == "192.168.*.*"

        # Empty string handling
        assert mask_sensitive_value("", EntityType.EMAIL) == ""


class TestFileInfo:
    def test_file_info_creation_and_hash(self, tmp_path):
        test_file = tmp_path / "sample.txt"
        test_file.write_text("Hello RedactX!", encoding="utf-8")

        info = FileInfo.from_path(test_file, compute_hash=True)
        assert info.name == "sample.txt"
        assert info.format == FileFormat.TXT
        assert info.size_bytes == 14
        assert info.sha256_hash is not None
        assert len(info.sha256_hash) == 64

