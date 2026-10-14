from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Matches UPI IDs: username@psp_handle
# Negative lookahead (?!\.[a-zA-Z]) ensures email domains (e.g. user@gmail.com) are not matched as UPI
UPI_REGEX = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z0-9]{2,32}(?!\.[a-zA-Z])\b"
)

# Known common Indian UPI PSP handles
COMMON_UPI_HANDLES = {
    "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ybl", "ibl",
    "axl", "apl", "upi", "barodampay", "federal", "airtel", "idfcbank",
    "kotak", "indus", "freecharge", "icici", "hdfcbank", "sbi", "axisbank",
    "postbank", "aubank", "jupiteraxis", "slice", "fam"
}


class UPIDetector(BaseDetector):
    """Detects candidate Indian UPI IDs / Virtual Payment Addresses."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="UPIDetector", entity_type=EntityType.UPI_ID, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in UPI_REGEX.finditer(text):
            raw = match.group()
            if "@" in raw:
                user, psp = raw.split("@", 1)
                # Ensure PSP handle is not empty, does not contain dots, and is not a common file/code term
                psp_lower = psp.lower()
                if psp_lower.isalpha() and len(psp_lower) >= 2:
                    is_known = psp_lower in COMMON_UPI_HANDLES
                    start, end = match.span()
                    candidates.append(
                        self._create_candidate(
                            raw,
                            start,
                            end,
                            parsed,
                            metadata={"user": user, "psp": psp_lower, "is_known_psp": is_known},
                        )
                    )

        return candidates
