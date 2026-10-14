from __future__ import annotations

import re
from typing import TYPE_CHECKING, Union

from redactX.detectors.base import BaseDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Common high-confidence provider token prefixes
PROVIDER_PATTERNS = [
    # Stripe Secret & Publishable keys
    re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    # GitHub Personal Access Tokens
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    # AWS Access Key ID
    re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    # Google API Key
    re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    # Slack Bot/User Token
    re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b"),
    # JSON Web Token (JWT) format: eyJ...
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]

# Generic assignment pattern: api_key = "xyz123...", token: "abc..."
GENERIC_KEY_ASSIGNMENT = re.compile(
    r"""(?i)["']?\b(?:aws[_-]?)?(?:api[_-]?key|secret[_-]?access[_-]?key|access[_-]?key(?:[_-]?id)?|access[_-]?token|secret[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key|bearer)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-\./+=]{16,})["']?"""
)


class APIKeyDetector(BaseDetector):
    """Detects candidate API keys, access tokens, and cloud credentials."""

    def __init__(self, enabled: bool = True):
        super().__init__(name="APIKeyDetector", entity_type=EntityType.API_KEY, enabled=enabled)

    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        if not self.enabled:
            return []

        text, parsed = self._get_target_text_and_coords(target)
        candidates: list[CandidateMatch] = []
        seen_spans: set[tuple[int, int]] = set()

        # 1. Check well-known provider patterns
        for pattern in PROVIDER_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group()
                start, end = match.span()
                if (start, end) not in seen_spans:
                    seen_spans.add((start, end))
                    candidates.append(
                        self._create_candidate(
                            raw,
                            start,
                            end,
                            parsed,
                            metadata={"provider_pattern": True},
                        )
                    )

        # 2. Check generic keyword assignment patterns
        for match in GENERIC_KEY_ASSIGNMENT.finditer(text):
            raw_token = match.group(1)
            # The span of the token value itself
            start = match.start(1)
            end = match.end(1)
            if (start, end) not in seen_spans:
                seen_spans.add((start, end))
                candidates.append(
                    self._create_candidate(
                        raw_token,
                        start,
                        end,
                        parsed,
                        metadata={"assignment_pattern": True},
                    )
                )

        return candidates
