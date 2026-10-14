from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Matches major card formats (13 to 19 digits):
# - Standard 16 digits (4-4-4-4): 4532 0151 1283 0366 or 4532-0151-1283-0366 or contiguous
# - Amex 15 digits (4-6-5): 3782 822463 10005
# - RuPay, Visa, MasterCard, Discover, Diners (13 to 19 digits)
CARD_REGEX = re.compile(
    r"(?<!\d)(?:"
    r"4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|"  # Visa 16-digit
    r"5[1-5]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|"  # MasterCard
    r"2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|"  # MC 2xxx
    r"3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|"  # Amex 15-digit
    r"6(?:011|5\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|"  # Discover
    r"(?:60|65|81|82)\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|"  # RuPay
    r"\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|"  # Generic 4-4-4-4 formatted
    r"\d{13,19}"  # Contiguous 13-19 digit candidate
    r")(?!\d)"
)


class CreditCardDetector(BaseDetector):
    """Detects candidate credit and debit card number patterns."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="CreditCardDetector", entity_type=EntityType.CREDIT_CARD, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in CARD_REGEX.finditer(text):
            raw = match.group()
            digits = "".join(ch for ch in raw if ch.isdigit())
            # Credit/debit card numbers must be between 13 and 19 digits
            if 13 <= len(digits) <= 19:
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
