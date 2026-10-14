from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

PASSWORD_ASSIGNMENT_REGEX = re.compile(
    r"""(?i)["']?\b(?:password|passwd|pwd|db_pass(?:word)?|user_pass(?:word)?|admin_pass(?:word)?)\b["']?\s*[:=]\s*["']?([^\s"'`]{6,64})["']?"""
)

# Placeholders to ignore
EXCLUDED_PLACEHOLDERS = {
    "password", "changeme", "change_me", "your_password", "null", "none",
    "true", "false", "undefined", "secret", "********", "xxxxxx", "<password>"
}


class PasswordDetector(BaseDetector):
    """Detects candidate passwords declared near password keywords."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="PasswordDetector", entity_type=EntityType.PASSWORD, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []

        for match in PASSWORD_ASSIGNMENT_REGEX.finditer(text):
            raw_pwd = match.group(1)
            # Filter obvious dummy placeholders
            if raw_pwd.lower() in EXCLUDED_PLACEHOLDERS:
                continue

            start = match.start(1)
            end = match.end(1)
            candidates.append(
                self._create_candidate(
                    raw_pwd,
                    start,
                    end,
                    parsed,
                    metadata={"password_assignment": True},
                )
            )

        return candidates
