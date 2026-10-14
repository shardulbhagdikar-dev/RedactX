"""Unit tests for Shannon Entropy analysis and Context Proximity analysis."""

import pytest
from redactX.analysis.context import ContextAnalyzer
from redactX.analysis.entropy import EntropyAnalyzer
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch


class TestEntropyAnalyzer:
    def test_shannon_entropy_mathematical_vectors(self):
        # Monotonous string has zero entropy
        assert EntropyAnalyzer.calculate_shannon_entropy("aaaa") == 0.0

        # Two symbols with equal probability: - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0
        assert EntropyAnalyzer.calculate_shannon_entropy("abab") == 1.0

        # Four symbols with equal probability: log2(4) = 2.0
        assert EntropyAnalyzer.calculate_shannon_entropy("abcd") == 2.0

        # Empty string
        assert EntropyAnalyzer.calculate_shannon_entropy("") == 0.0

    def test_charset_classification(self):
        assert EntropyAnalyzer.detect_charset("0123456789abcdefABCDEF") == "hex"
        assert EntropyAnalyzer.detect_charset("TokenWithAlphanumeric123") == "alphanumeric"
        assert EntropyAnalyzer.detect_charset("Base64+Token/Value==") == "base64"
        assert EntropyAnalyzer.detect_charset("Special!@#Token$%^") == "general"

    def test_high_entropy_secret_detection(self):
        # Standard pseudo-random API token
        random_secret = "d9g8h3j2k1l4m5n6p7q8r9s0t1u2v3w4"
        res = EntropyAnalyzer.analyze(random_secret)

        assert res.is_high_entropy is True
        assert res.confidence_boost > 0
        assert res.raw_entropy >= 3.8
        assert 0.0 <= res.normalized_entropy <= 1.0

    def test_low_entropy_repetitive_string_penalty(self):
        # Repetitive sequence: low randomness
        low_entropy = "abcabcabcabcabcabcabcabc"
        res = EntropyAnalyzer.analyze(low_entropy)

        assert res.is_high_entropy is False
        assert res.confidence_boost <= 0.0


class TestContextAnalyzer:
    def test_positive_context_detection_and_boost(self):
        full_text = "Here is the production secret: api_key = sk_test_9876543210abcdef in config."
        start_idx = full_text.index("sk_test_9876543210abcdef")
        end_idx = start_idx + len("sk_test_9876543210abcdef")

        cand = CandidateMatch(
            entity_type=EntityType.API_KEY,
            raw_value="sk_test_9876543210abcdef",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        res = ContextAnalyzer.analyze(cand, full_text)
        assert res.has_positive_context is True
        assert "api_key" in res.matched_keywords or "secret" in res.matched_keywords
        assert res.context_score > 0.0
        assert res.confidence_boost > 0.0
        assert "sk_test_9876543210abcdef" in res.snippet

    def test_negative_context_indicators(self):
        full_text = "This is a dummy test fixture: password = SuperSecretPassword123 for unit testing."
        start_idx = full_text.index("SuperSecretPassword123")
        end_idx = start_idx + len("SuperSecretPassword123")

        cand = CandidateMatch(
            entity_type=EntityType.PASSWORD,
            raw_value="SuperSecretPassword123",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        res = ContextAnalyzer.analyze(cand, full_text)
        assert res.has_negative_context is True
        assert "dummy" in res.negative_keywords or "test" in res.negative_keywords
        # Negative indicators pull down the composite context score
        assert len(res.negative_keywords) >= 2

    def test_metadata_context_boost_for_csv_and_json(self):
        text = "4532015112830366"
        cand = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value=text,
            start_idx=0,
            end_idx=16,
            line_number=2,
            column_number=1,
            metadata={"header": "card_number", "path": "billing.payment_card"},
        )

        res = ContextAnalyzer.analyze(cand, text)
        assert res.has_positive_context is True
        assert any("meta:" in kw for kw in res.matched_keywords)
        assert res.confidence_boost > 0.0

    def test_neutral_context_without_keywords(self):
        text = "Just arbitrary text with 9876543210 appearing in between sentences."
        start_idx = text.index("9876543210")
        end_idx = start_idx + len("9876543210")

        cand = CandidateMatch(
            entity_type=EntityType.PHONE_NUMBER,
            raw_value="9876543210",
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=1,
            column_number=start_idx + 1,
        )

        res = ContextAnalyzer.analyze(cand, text)
        assert res.has_positive_context is False
        assert res.context_score == 0.0
        assert res.confidence_boost == 0.0
