from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# RFC 5322 simplified pattern with word boundaries
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b"
)


class EmailDetector(BaseDetector):
    """Detects candidate email addresses."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="EmailDetector", entity_type=EntityType.EMAIL, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in EMAIL_REGEX.finditer(text):
            raw = match.group()
            start, end = match.span()
            candidates.append(self._create_candidate(raw, start, end, parsed))

        return candidates
