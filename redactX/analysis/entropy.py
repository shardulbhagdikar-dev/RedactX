"""Shannon Entropy calculation and randomness analysis for candidate secrets."""

import math
import string
from collections import Counter
from dataclasses import dataclass
from typing import Optional

HEX_CHARS = set(string.hexdigits)
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=-_")
ALPHANUMERIC_CHARS = set(string.ascii_letters + string.digits)


@dataclass(slots=True)
class EntropyResult:
    """Outcome of entropy analysis on a candidate string."""

    raw_entropy: float
    normalized_entropy: float  # Value between 0.0 and 1.0
    charset: str  # 'hex', 'base64', 'alphanumeric', or 'general'
    is_high_entropy: bool
    confidence_boost: float  # Calculated boost for candidate confidence (-0.3 to +0.3)


class EntropyAnalyzer:
    """Analyzes character randomness of candidate secrets using Shannon entropy."""

    # Default thresholds for high entropy classification
    HEX_THRESHOLD: float = 3.0
    BASE64_THRESHOLD: float = 4.3
    ALPHANUMERIC_THRESHOLD: float = 3.8
    GENERAL_THRESHOLD: float = 4.0

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculate raw Shannon Entropy: H(X) = -sum(p(x) * log2(p(x)))."""
        if not text:
            return 0.0

        length = len(text)
        counts = Counter(text)
        entropy = 0.0

        for count in counts.values():
            p_x = count / length
            entropy -= p_x * math.log2(p_x)

        return round(entropy, 4)

    @classmethod
    def detect_charset(cls, text: str) -> str:
        """Classify the dominant character set of the token."""
        char_set = set(text)
        if char_set.issubset(HEX_CHARS):
            return "hex"
        elif char_set.issubset(ALPHANUMERIC_CHARS):
            return "alphanumeric"
        elif char_set.issubset(BASE64_CHARS):
            return "base64"
        return "general"

    @classmethod
    def analyze(cls, text: str, custom_threshold: Optional[float] = None) -> EntropyResult:
        """Perform comprehensive entropy analysis on candidate string."""
        cleaned = text.strip("'\" \t\r\n")
        if not cleaned:
            return EntropyResult(
                raw_entropy=0.0,
                normalized_entropy=0.0,
                charset="general",
                is_high_entropy=False,
                confidence_boost=-0.2,
            )

        raw_entropy = cls.calculate_shannon_entropy(cleaned)
        charset = cls.detect_charset(cleaned)

        # Max theoretical entropy depends on unique symbols allowed by the charset
        max_theoretical = {
            "hex": math.log2(16),  # 4.0
            "alphanumeric": math.log2(62),  # ~5.95
            "base64": math.log2(64),  # 6.0
            "general": math.log2(95),  # printable ascii ~6.57
        }.get(charset, 6.0)

        # Max possible entropy for this specific length: log2(len)
        max_for_length = math.log2(max(1, len(cleaned)))
        effective_max = min(max_theoretical, max_for_length)

        normalized = round(raw_entropy / effective_max, 4) if effective_max > 0 else 0.0
        normalized = min(1.0, max(0.0, normalized))

        # Select threshold
        if custom_threshold is not None:
            threshold = custom_threshold
        elif charset == "hex":
            threshold = cls.HEX_THRESHOLD
        elif charset == "base64":
            threshold = cls.BASE64_THRESHOLD
        elif charset == "alphanumeric":
            threshold = cls.ALPHANUMERIC_THRESHOLD
        else:
            threshold = cls.GENERAL_THRESHOLD

        is_high = raw_entropy >= threshold and len(cleaned) >= 8

        # Confidence boost: positive for high entropy, negative for repetitive/low
        if is_high:
            boost = round(min(0.3, (raw_entropy - threshold) * 0.15 + 0.1), 3)
        elif len(cleaned) >= 12 and raw_entropy < (threshold - 1.0):
            boost = -0.2
        else:
            boost = 0.0

        return EntropyResult(
            raw_entropy=raw_entropy,
            normalized_entropy=normalized,
            charset=charset,
            is_high_entropy=is_high,
            confidence_boost=boost,
        )
