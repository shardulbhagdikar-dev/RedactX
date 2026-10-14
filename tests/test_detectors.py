"""Unit tests for RedactX sensitive data detectors and DetectorRegistry."""

import pytest
from redactX.detectors import (
    AadhaarDetector,
    APIKeyDetector,
    CreditCardDetector,
    DetectorRegistry,
    EmailDetector,
    IPAddressDetector,
    PasswordDetector,
    PhoneDetector,
    UPIDetector,
)
from redactX.models.enums import EntityType, Severity
from redactX.scanner.file_parser import FileParser


class TestIndividualDetectors:
    def test_email_detector(self):
        detector = EmailDetector()
        text = "Contact us at support@redactx.io or admin.team+fcs@sub.domain.org."
        matches = detector.detect(text)

        assert len(matches) == 2
        assert matches[0].raw_value == "support@redactx.io"
        assert matches[0].entity_type == EntityType.EMAIL
        assert matches[1].raw_value == "admin.team+fcs@sub.domain.org"

    def test_phone_detector_indian_formats(self):
        detector = PhoneDetector()
        text = """
        Call +91 9876543210 or +91-98765-43210 or 09876543210.
        Local: 9876543210 and spaced 98765 43210.
        Invalid: 12345 (too short) and 1234567890 (starts with 1, not Indian mobile).
        """
        matches = detector.detect(text)
        found_values = [m.raw_value.strip() for m in matches]

        assert "+91 9876543210" in found_values
        assert "+91-98765-43210" in found_values
        assert "09876543210" in found_values
        assert "9876543210" in found_values
        assert "98765 43210" in found_values
        assert len(matches) == 5

    def test_phone_detector_international_and_nanp(self):
        detector = PhoneDetector()
        text = """
        Office contacts:
        1. US Standard: (971) 643-6089 and (971)643-6089
        2. With extension: (971)643-6089x9160 and 355-863-2311x6315
        3. Prefix +1: +1-114-355-1841x78347 and +1-607-333-9911
        4. Prefix 001: 001-314-829-5014x1792
        5. Dot-separated: 645.665.5931 and 903.237.1120x705
        6. Standard dash: 507-684-0331
        """
        matches = detector.detect(text)
        found_values = [m.raw_value.strip() for m in matches]

        assert "(971) 643-6089" in found_values
        assert "(971)643-6089" in found_values
        assert "(971)643-6089x9160" in found_values
        assert "355-863-2311x6315" in found_values
        assert "+1-114-355-1841x78347" in found_values
        assert "+1-607-333-9911" in found_values
        assert "001-314-829-5014x1792" in found_values
        assert "645.665.5931" in found_values
        assert "903.237.1120x705" in found_values
        assert "507-684-0331" in found_values

    def test_aadhaar_detector(self):
        detector = AadhaarDetector()
        text = "Aadhaar IDs: 1234 5678 9012, 9876-5432-1098, and 234567890123."
        matches = detector.detect(text)

        assert len(matches) == 3
        assert matches[0].raw_value == "1234 5678 9012"
        assert matches[1].raw_value == "9876-5432-1098"
        assert matches[2].raw_value == "234567890123"

    def test_credit_card_detector(self):
        detector = CreditCardDetector()
        text = """
        Visa: 4532 0151 1283 0366
        MasterCard: 5412-7512-3412-3456
        Amex: 3782 822463 10005
        Contiguous: 4111222233334444
        """
        matches = detector.detect(text)
        found = [m.raw_value.strip() for m in matches]

        assert "4532 0151 1283 0366" in found
        assert "5412-7512-3412-3456" in found
        assert "3782 822463 10005" in found
        assert "4111222233334444" in found
        assert len(matches) == 4

    def test_upi_detector(self):
        detector = UPIDetector()
        text = "Pay to rahul@okaxis, payment.test@okhdfcbank, 9876543210@paytm, or bot@upi. Not an email: user@gmail.com."
        matches = detector.detect(text)
        found = [m.raw_value.strip() for m in matches]

        assert "rahul@okaxis" in found
        assert "payment.test@okhdfcbank" in found
        assert "9876543210@paytm" in found
        assert "bot@upi" in found
        # user@gmail.com contains a dot in domain, should not match UPIDetector
        assert "user@gmail.com" not in found
        assert len(matches) == 4

    def test_api_key_detector(self):
        detector = APIKeyDetector()
        text = """
        Stripe: sk_test_51HzT1234567890abcdef12345678
        GitHub: ghp_1234567890abcdefghijklmnopqrstuvwxyz
        AWS: AKIAIOSFODNN7EXAMPLE
        Generic: api_key = "abcdef12345678901234"
        """
        matches = detector.detect(text)
        found = [m.raw_value.strip() for m in matches]

        assert "sk_test_51HzT1234567890abcdef12345678" in found
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" in found
        assert "AKIAIOSFODNN7EXAMPLE" in found
        assert "abcdef12345678901234" in found

    def test_password_detector(self):
        detector = PasswordDetector()
        text = """
        db_password = "SuperSecretPassword123!"
        password: "MyProdPassword456"
        dummy: password = "changeme"
        """
        matches = detector.detect(text)
        found = [m.raw_value.strip() for m in matches]

        assert "SuperSecretPassword123!" in found
        assert "MyProdPassword456" in found
        # "changeme" is an excluded placeholder
        assert "changeme" not in found
        assert len(matches) == 2

    def test_ip_address_detector(self):
        detector = IPAddressDetector()
        text = "Servers: 192.168.1.1, 10.0.0.255, 127.0.0.1. Invalid: 999.999.999.999 or 1.2.3.4.5"
        matches = detector.detect(text)
        found = [m.raw_value.strip() for m in matches]

        assert "192.168.1.1" in found
        assert "10.0.0.255" in found
        assert "127.0.0.1" in found
        assert len(matches) == 3


class TestDetectorRegistry:
    def test_registry_lifecycle(self):
        reg = DetectorRegistry(load_defaults=True)
        assert len(reg.list_detectors()) == 8

        # Lookup
        email_det = reg.get_detector(EntityType.EMAIL)
        assert email_det is not None
        assert email_det.name == "EmailDetector"

        # Toggle disable/enable
        assert reg.disable_detector(EntityType.EMAIL) is True
        assert email_det.enabled is False
        assert reg.enable_detector(EntityType.EMAIL) is True
        assert email_det.enabled is True

        # Unregister
        removed = reg.unregister(EntityType.IPV4_ADDRESS)
        assert removed is not None
        assert reg.get_detector(EntityType.IPV4_ADDRESS) is None
        assert len(reg.list_detectors()) == 7

    def test_registry_detect_all_with_file_coordinates(self, tmp_path):
        sample = tmp_path / "data.txt"
        content = (
            "Line 1: User email is alice@company.com\n"
            "Line 2: Phone is +91 9876543210\n"
            "Line 3: Card is 4532 0151 1283 0366\n"
        )
        sample.write_text(content, encoding="utf-8", newline="\n")

        parsed = FileParser.parse_txt(sample)
        reg = DetectorRegistry()
        candidates = reg.detect_all(parsed)

        assert len(candidates) == 3
        # Match 1: Email on Line 1
        assert candidates[0].entity_type == EntityType.EMAIL
        assert candidates[0].line_number == 1
        assert candidates[0].raw_value == "alice@company.com"

        # Match 2: Phone on Line 2
        assert candidates[1].entity_type == EntityType.PHONE_NUMBER
        assert candidates[1].line_number == 2
        assert candidates[1].raw_value == "+91 9876543210"

        # Match 3: Credit Card on Line 3
        assert candidates[2].entity_type == EntityType.CREDIT_CARD
        assert candidates[2].line_number == 3
        assert candidates[2].raw_value == "4532 0151 1283 0366"

    def test_registry_overlap_resolution(self):
        # A 16-digit card number could potentially overlap with contiguous numbers
        reg = DetectorRegistry()
        # Text with 16 digits: should be discovered as CREDIT_CARD (CRITICAL) rather than partial matches
        text = "Payment: 4532015112830366"
        candidates = reg.detect_all(text)

        assert len(candidates) == 1
        assert candidates[0].entity_type == EntityType.CREDIT_CARD
        assert candidates[0].raw_value == "4532015112830366"
