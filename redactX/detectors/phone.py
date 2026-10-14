from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Matches Indian mobile numbers and International/NANP formats:
# 1. Indian formats (+91/91, 0-prefix, 5-5 split, 10 continuous starting with 6-9)
# 2. North American (NANP): (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX, +1-..., 001-...
# 3. Numbers with extensions: x123, ext 1234
# 4. General E.164 international numbers: +CountryCode Area Subscriber
PHONE_REGEX = re.compile(
    r"(?<![\w+])"
    r"(?:"
    # NANP / International with parentheses or separators (e.g., (971)643-6089, +1-114-355-1841, 001-314-829-5014)
    r"(?:(?:\+|00)?1[\s.-]?)?(?:\(\d{3}\)|\b\d{3})[\s.-]\d{3}[\s.-]\d{4}(?:[\s]?(?:x|ext\.?)\s*\d{1,5})?"
    r"|"
    r"\(\d{3}\)\s*\d{3}[\s.-]?\d{4}(?:[\s]?(?:x|ext\.?)\s*\d{1,5})?"
    r"|"
    # Dot-separated 10-digit (e.g., 903.237.1120 or 903.237.1120x705)
    r"\b\d{3}\.\d{3}\.\d{4}(?:[\s]?(?:x|ext\.?)\s*\d{1,5})?"
    r"|"
    # Triple prefix with 001/prefixes (e.g., 001-887-131-9735x6172)
    r"\b(?:001|\+1)[\s.-]\d{3}[\s.-]\d{3}[\s.-]\d{4}(?:[\s]?(?:x|ext\.?)\s*\d{1,5})?"
    r"|"
    # Indian formats: +91 9876543210, +91-98765-43210, 98765 43210, 09876543210
    r"(?:(?:\+91[\s.-]?|91[\s.-]?)?[6-9]\d{4}[\s.-]?\d{5}|0?[6-9]\d{9})"
    r"|"
    # Generic continuous 10 digits starting with valid NANP/DoT area code (2-9)
    r"\b[2-9]\d{9}\b"
    r"|"
    # E.164 general international: + followed by country code, then formatted digits
    r"\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?:[\s]?(?:x|ext\.?)\s*\d{1,5})?"
    r")"
    r"(?![\w])"
)


class PhoneDetector(BaseDetector):
    """Detects candidate phone numbers (Indian mobile and International/NANP formats)."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="PhoneDetector", entity_type=EntityType.PHONE_NUMBER, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in PHONE_REGEX.finditer(text):
            raw = match.group()
            # Basic sanity check on extracted digits length (7 to 20 digits to accommodate prefixes & extensions)
            digits = "".join(ch for ch in raw if ch.isdigit())
            if 7 <= len(digits) <= 20:
                start, end = match.span()
                candidates.append(
                    self._create_candidate(
                        raw,
                        start,
                        end,
                        parsed,
                        metadata={"digits": digits},
                    )
                )

        return candidates
