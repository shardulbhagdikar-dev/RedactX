"""Unit tests for the Risk & Scoring Engine."""

import pytest
from redactX.analysis.risk import RiskEngine, RiskScore
from redactX.models.enums import Confidence, EntityType, Severity
from redactX.models.finding import CandidateMatch, Finding


class TestRiskEngineCandidateEvaluation:
    def test_evaluate_valid_credit_card(self):
        text = "Customer billing card: 4532 0151 1283 0366 on file."
        start_idx = text.index("4532 0151 1283 0366")
        end_idx = start_idx + len("4532 0151 1283 0366")

        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532 0151 1283 0366",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        finding = RiskEngine.evaluate_candidate(cand, text)
        assert finding.entity_type == EntityType.CREDIT_CARD
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.HIGH
        assert finding.validator_passed is True
        assert finding.masked_value == "**** **** **** 0366"
        assert "Visa" in finding.explanation
        assert "Passed Luhn" in finding.explanation

    def test_evaluate_invalid_credit_card_downgrade(self):
        # 16 digits that fail Luhn checksum
        text = "Account reference: 4532 0151 1283 0367 recorded."
        start_idx = text.index("4532 0151 1283 0367")
        end_idx = start_idx + len("4532 0151 1283 0367")

        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532 0151 1283 0367",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        finding = RiskEngine.evaluate_candidate(cand, text)
        assert finding.validator_passed is False
        # Failed mathematical check downgrades severity to LOW and confidence to LOW
        assert finding.severity == Severity.LOW
        assert finding.confidence == Confidence.LOW
        assert finding.confidence_score <= 0.35
        assert "Failed Luhn" in finding.explanation

    def test_evaluate_high_entropy_api_key(self):
        text = "production_api_key = 'd9g8h3j2k1l4m5n6p7q8r9s0t1u2v3w4'"
        start_idx = text.index("d9g8h3j2k1l4m5n6p7q8r9s0t1u2v3w4")
        end_idx = start_idx + len("d9g8h3j2k1l4m5n6p7q8r9s0t1u2v3w4")

        cand = CandidateMatch(
            entity_type=EntityType.API_KEY,
            raw_value="d9g8h3j2k1l4m5n6p7q8r9s0t1u2v3w4",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        finding = RiskEngine.evaluate_candidate(cand, text)
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.HIGH
        assert finding.entropy_score is not None
        assert finding.entropy_score >= 3.8
        assert "Entropy:" in finding.explanation

    def test_batch_candidates_evaluation(self):
        text = "Contact: test@domain.com, Server: 192.168.1.1"
        cands = [
            CandidateMatch(EntityType.EMAIL, "test@domain.com", 9, 24, 1, 10),
            CandidateMatch(EntityType.IPV4_ADDRESS, "192.168.1.1", 34, 45, 1, 35),
        ]

        findings = RiskEngine.evaluate_candidates(cands, text)
        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)


class TestRiskEngineFileRiskAggregation:
    def test_calculate_file_risk_clean(self):
        risk = RiskEngine.calculate_file_risk([])
        assert risk.severity == Severity.CLEAN
        assert risk.score == 0.0
        assert risk.findings_count == 0
        assert "No sensitive data" in risk.summary_text

    def test_calculate_file_risk_with_mixed_findings(self):
        f_low = Finding(
            entity_type=EntityType.EMAIL,
            masked_value="t***@d.com",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            confidence_score=0.70,
            line_number=1,
            column_number=1,
            start_idx=0,
            end_idx=10,
            context_snippet="",
            explanation="Valid email",
            validator_passed=True,
        )

        f_crit = Finding(
            entity_type=EntityType.CREDIT_CARD,
            masked_value="**** **** **** 0366",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            confidence_score=0.95,
            line_number=2,
            column_number=1,
            start_idx=20,
            end_idx=36,
            context_snippet="",
            explanation="Visa card",
            validator_passed=True,
        )

        risk = RiskEngine.calculate_file_risk([f_low, f_crit])
        assert risk.severity == Severity.CRITICAL
        assert risk.findings_count == 2
        assert risk.critical_count == 1
        assert risk.low_count == 1
        assert risk.score > 0.0
        assert risk.score <= 100.0
        assert "Critical: 1" in risk.summary_text
