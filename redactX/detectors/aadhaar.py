from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Aadhaar candidate discovery:
# 12 digits grouped 4-4-4 with space or hyphen, or contiguous 12 digits.
# Strict validation (Verhoeff checksum, starting digit rules) is performed in the Validation Engine.
AADHAAR_REGEX = re.compile(
    r"(?<!\d)(\d{4}[ -]\d{4}[ -]\d{4}|\d{12})(?!\d)"
)


class AadhaarDetector(BaseDetector):
    """Detects candidate 12-digit Indian Aadhaar numbers."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="AadhaarDetector", entity_type=EntityType.AADHAAR, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in AADHAAR_REGEX.finditer(text):
            raw = match.group()
            digits = "".join(ch for ch in raw if ch.isdigit())
            if len(digits) == 12:
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
