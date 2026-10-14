from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# IPv4 Regex with strict octet checking 0-255 and boundary protection
# Lookahead (?!\d|\.\d) ensures trailing punctuation (e.g. at end of sentence) does not invalidate the IP
IPV4_REGEX = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?!\d|\.\d)"
)


class IPAddressDetector(BaseDetector):
    """Detects candidate IPv4 addresses."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="IPAddressDetector", entity_type=EntityType.IPV4_ADDRESS, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in IPV4_REGEX.finditer(text):
            raw = match.group()
            start, end = match.span()
            candidates.append(
                self._create_candidate(
                    raw,
                    start,
                    end,
                    parsed,
                    metadata={"octets": raw.split(".")},
                )
            )

        return candidates
