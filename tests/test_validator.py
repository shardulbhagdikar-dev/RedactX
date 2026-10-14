"""Unit tests for the Validation Engine (Luhn, Verhoeff, IPv4, UPI, Telecom)."""

import pytest
from redactX.analysis.validator import (
    ValidationEngine,
    validate_api_key,
    validate_email,
    validate_indian_phone,
    validate_phone,
    validate_ipv4,
    validate_luhn,
    validate_password,
    validate_upi,
    validate_verhoeff,
)
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch


class TestLuhnValidator:
    def test_valid_credit_cards(self):
        # Visa 16 digits
        is_valid, brand, reason = validate_luhn("4532 0151 1283 0366")
        assert is_valid is True
        assert brand == "Visa"
        assert "Passed Luhn" in reason

        # MasterCard 16 digits (Luhn valid test card: 5412-7512-3412-3452)
        is_valid, brand, _ = validate_luhn("5412-7512-3412-3452")
        assert is_valid is True
        assert brand == "MasterCard"

        # Amex 15 digits (378282246310005)
        is_valid, brand, _ = validate_luhn("378282246310005")
        assert is_valid is True
        assert brand == "American Express"

        # RuPay 16 digits (6070123456789017)
        is_valid, brand, _ = validate_luhn("6070123456789017")
        assert is_valid is True
        assert brand == "RuPay"

    def test_invalid_credit_cards(self):
        # Changed last digit of valid Visa
        is_valid, _, reason = validate_luhn("4532 0151 1283 0367")
        assert is_valid is False
        assert "Failed Luhn" in reason

        # Arbitrary digits that fail checksum
        is_valid, _, _ = validate_luhn("1234567890123456")
        assert is_valid is False

        # Invalid length
        is_valid, _, reason = validate_luhn("123456789")
        assert is_valid is False
        assert "Invalid digit count" in reason


class TestVerhoeffValidator:
    def test_valid_aadhaar_numbers(self):
        # 234123412346 is a mathematically valid Verhoeff Aadhaar checksum
        is_valid, reason = validate_verhoeff("2341 2341 2346")
        assert is_valid is True
        assert "Passed Verhoeff" in reason

        # Contiguous format
        is_valid, _ = validate_verhoeff("234123412346")
        assert is_valid is True

    def test_invalid_aadhaar_numbers(self):
        # Fails start-digit rule (starts with 0 or 1)
        is_valid, reason = validate_verhoeff("1234 5678 9012")
        assert is_valid is False
        assert "cannot begin with 0 or 1" in reason

        is_valid, reason = validate_verhoeff("0123 4567 8901")
        assert is_valid is False
        assert "cannot begin with 0 or 1" in reason

        # Valid start digit but invalid check digit (corrupted 234123412346 -> 234123412345)
        is_valid, reason = validate_verhoeff("2341 2341 2345")
        assert is_valid is False
        assert "Failed Verhoeff checksum" in reason

        # Invalid length
        is_valid, reason = validate_verhoeff("23412341234")
        assert is_valid is False
        assert "Invalid Aadhaar length" in reason


class TestNetworkAndTelecomValidators:
    def test_ipv4_validator(self):
        # Private IP
        is_valid, reason, meta = validate_ipv4("192.168.1.1")
        assert is_valid is True
        assert meta["is_private"] is True
        assert "private" in reason

        # Loopback
        is_valid, _, meta = validate_ipv4("127.0.0.1")
        assert is_valid is True
        assert meta["is_loopback"] is True

        # Public IP
        is_valid, _, meta = validate_ipv4("8.8.8.8")
        assert is_valid is True
        assert meta["is_global"] is True

        # Malformed
        is_valid, reason, _ = validate_ipv4("999.1.1.1")
        assert is_valid is False
        assert "Malformed" in reason

    def test_upi_validator(self):
        # Known PSP handle
        is_valid, reason, meta = validate_upi("rahul@okaxis")
        assert is_valid is True
        assert meta["is_known_psp"] is True
        assert "Verified Indian UPI VPA" in reason

        # Valid generic PSP
        is_valid, reason, meta = validate_upi("merchant@newpsp")
        assert is_valid is True
        assert meta["is_known_psp"] is False

        # Invalid: dot in domain (email)
        is_valid, reason, _ = validate_upi("user@gmail.com")
        assert is_valid is False
        assert "contains dot" in reason

        # Invalid: username too short
        is_valid, reason, _ = validate_upi("a@okaxis")
        assert is_valid is False
        assert "too short" in reason

    def test_indian_phone_validator(self):
        # Valid +91
        is_valid, reason, meta = validate_indian_phone("+91 98765 12345")
        assert is_valid is True
        assert meta["normalized_number"] == "9876512345"

        # Valid leading 0
        is_valid, _, meta = validate_indian_phone("08765432109")
        assert is_valid is True
        assert meta["normalized_number"] == "8765432109"

        # Invalid start digit (not 6, 7, 8, 9)
        is_valid, reason, _ = validate_indian_phone("5123456789")
        assert is_valid is False
        assert "must begin with 6, 7, 8, or 9" in reason

        # Dummy number
        is_valid, reason, meta = validate_indian_phone("9999999999")
        assert is_valid is False
        assert "dummy" in reason

    def test_general_and_international_phone_validator(self):
        # Valid US/NANP with extension
        is_valid, reason, meta = validate_phone("(971)643-6089x9160")
        assert is_valid is True
        assert meta["extension"] == "9160"
        assert meta["base_digits"] == "9716436089"

        # Valid 001 prefix
        is_valid, reason, meta = validate_phone("001-314-829-5014x1792")
        assert is_valid is True
        assert meta["base_digits"] == "3148295014"

        # Valid dot-separated
        is_valid, reason, meta = validate_phone("645.665.5931")
        assert is_valid is True

        # Valid Indian format via general validate_phone
        is_valid, reason, meta = validate_phone("+91 98765 12345")
        assert is_valid is True
        assert meta["format"] == "indian_mobile"

        # Invalid short
        is_valid, reason, _ = validate_phone("1234")
        assert is_valid is False
        assert "too short" in reason

        # Invalid dummy / no variance
        is_valid, reason, _ = validate_phone("1111111111")
        assert is_valid is False


class TestSecretsAndAuthValidators:
    def test_api_key_validator(self):
        valid_key = "sk_test_51HzT1234567890abcdef1234"
        is_valid, _ = validate_api_key(valid_key)
        assert is_valid is True

        # Too short
        is_valid, reason = validate_api_key("short_token")
        assert is_valid is False
        assert "too short" in reason

        # All digits
        is_valid, reason = validate_api_key("12345678901234567890")
        assert is_valid is False
        assert "cannot consist solely of digits" in reason

    def test_password_validator(self):
        is_valid, _ = validate_password("SuperSecurePwd987!")
        assert is_valid is True

        is_valid, reason = validate_password("123")
        assert is_valid is False
        assert "too short" in reason

    def test_email_validator(self):
        is_valid, _ = validate_email("support@redactx.io")
        assert is_valid is True

        is_valid, _ = validate_email("invalid_email")
        assert is_valid is False


class TestValidationEngineIntegration:
    def test_validation_engine_card(self):
        cand_valid = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532015112830366",
            start_idx=0,
            end_idx=16,
            line_number=1,
            column_number=1,
        )
        res_valid = ValidationEngine.validate(cand_valid)
        assert res_valid.is_valid is True
        assert res_valid.confidence_boost > 0
        assert res_valid.metadata["brand"] == "Visa"

        cand_invalid = CandidateMatch(
            entity_type=EntityType.CREDIT_CARD,
            raw_value="4532015112830367",
            start_idx=0,
            end_idx=16,
            line_number=1,
            column_number=1,
        )
        res_invalid = ValidationEngine.validate(cand_invalid)
        assert res_invalid.is_valid is False
        assert res_invalid.confidence_boost < 0

    def test_validation_engine_batch(self):
        cands = [
            CandidateMatch(EntityType.EMAIL, "a@b.com", 0, 7, 1, 1),
            CandidateMatch(EntityType.IPV4_ADDRESS, "192.168.1.1", 10, 21, 1, 11),
        ]
        results = ValidationEngine.validate_all(cands)
        assert len(results) == 2
        assert results[0][1].is_valid is True
        assert results[1][1].is_valid is True
