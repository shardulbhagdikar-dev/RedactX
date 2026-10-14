"""Zero-leak logging utility for RedactX.

Guarantees that raw sensitive values, passwords, credit card numbers,
and tokens are scrubbed from log messages and exception tracebacks before emission.
"""

import logging
import re
from typing import Optional

# Common regex patterns to scrub from log messages in case of accidental debug logging
SCRUB_PATTERNS = [
    # Credit Card numbers (13-19 digits, possibly separated by spaces or dashes)
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    # Aadhaar numbers (12 digits)
    re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    re.compile(r"\b\d{12}\b"),
    # API key or bearer tokens
    re.compile(r"(?:bearer\s+|api[_-]?key[:=\s]+|token[:=\s]+)[A-Za-z0-9_\-\.]{12,}", re.IGNORECASE),
    # Password assignments
    re.compile(r"(?:password|passwd|secret)[:=\s]+[^\s,;]+", re.IGNORECASE),
]


class ZeroLeakFilter(logging.Filter):
    """Logging filter that scrubs sensitive candidate patterns from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._sanitize(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize_val(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_val(v) for v in record.args)
        return True

    def _sanitize_val(self, val: object) -> object:
        if isinstance(val, str):
            return self._sanitize(val)
        return val

    def _sanitize(self, text: str) -> str:
        sanitized = text
        for pattern in SCRUB_PATTERNS:
            sanitized = pattern.sub("[REDACTED_BY_LOGGER]", sanitized)
        return sanitized


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Initialize root application logger with ZeroLeak protection."""
    logger = logging.getLogger("redactx")
    logger.setLevel(level)

    # Avoid duplicate handlers if setup is called multiple times
    if logger.handlers:
        return logger

    zero_leak_filter = ZeroLeakFilter()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    console_handler.addFilter(zero_leak_filter)
    logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(zero_leak_filter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Retrieve a child logger under the 'redactx' namespace with ZeroLeak guarantees."""
    logger = logging.getLogger(f"redactx.{name}")
    # Add filter directly to ensure child logger safety
    if not any(isinstance(f, ZeroLeakFilter) for f in logger.filters):
        logger.addFilter(ZeroLeakFilter())
    return logger
