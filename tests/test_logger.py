"""Unit tests for the ZeroLeak logger filter and utilities."""

import io
import logging
from redactX.utils.logger import ZeroLeakFilter, setup_logging


class TestZeroLeakLogging:
    def test_filter_scrubs_credit_card(self):
        filt = ZeroLeakFilter()
        record = logging.LogRecord(
            name="redactx.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="User entered credit card 4532015112830366 during checkout",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert "4532015112830366" not in record.msg
        assert "[REDACTED_BY_LOGGER]" in record.msg

    def test_filter_scrubs_aadhaar(self):
        filt = ZeroLeakFilter()
        record = logging.LogRecord(
            name="redactx.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=20,
            msg="Parsed Aadhaar 1234 5678 9012 for validation",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert "1234 5678 9012" not in record.msg
        assert "[REDACTED_BY_LOGGER]" in record.msg

    def test_filter_scrubs_api_key_and_password(self):
        filt = ZeroLeakFilter()
        record = logging.LogRecord(
            name="redactx.test",
            level=logging.WARNING,
            pathname=__file__,
            lineno=30,
            msg="Found api_key=sk_test_1234567890abcdef and password=SuperSecretPassword123",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert "sk_test_1234567890abcdef" not in record.msg
        assert "SuperSecretPassword123" not in record.msg
        assert "[REDACTED_BY_LOGGER]" in record.msg

    def test_clean_message_unaltered(self):
        filt = ZeroLeakFilter()
        record = logging.LogRecord(
            name="redactx.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=40,
            msg="Scanning completed for 15 files successfully.",
            args=(),
            exc_info=None,
        )
        filt.filter(record)
        assert record.msg == "Scanning completed for 15 files successfully."
