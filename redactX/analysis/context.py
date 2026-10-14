from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, Union

from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent

# Entity-specific positive contextual anchors
POSITIVE_KEYWORDS: dict[EntityType, set[str]] = {
    EntityType.API_KEY: {
        "api_key", "apikey", "api-key", "access_token", "secret", "token",
        "bearer", "auth", "client_secret", "private_key", "credentials", "jwt"
    },
    EntityType.PASSWORD: {
        "password", "passwd", "pwd", "db_pass", "admin_pass", "secret",
        "credentials", "passphrase"
    },
    EntityType.AADHAAR: {
        "aadhaar", "uidai", "aadhar", "identity", "id_card", "uid", "resident"
    },
    EntityType.CREDIT_CARD: {
        "credit", "debit", "card", "card_number", "cvv", "expiry", "visa",
        "mastercard", "amex", "payment", "billing", "pan", "rupay"
    },
    EntityType.UPI_ID: {
        "upi", "vpa", "payment", "gpay", "phonepe", "paytm", "bhim", "transact"
    },
    EntityType.PHONE_NUMBER: {
        "phone", "mobile", "contact", "tel", "cell", "call", "whatsapp"
    },
    EntityType.EMAIL: {
        "email", "mail", "contact", "recipient", "from", "to", "sender", "cc"
    },
    EntityType.IPV4_ADDRESS: {
        "ip", "host", "server", "dns", "gateway", "addr", "endpoint", "node"
    },
}

# Negative contextual anchors that suggest test, mock, or placeholder data
NEGATIVE_KEYWORDS = {
    "test", "dummy", "mock", "fake", "example", "fixture", "placeholder",
    "sample", "temp", "template"
}


@dataclass(slots=True)
class ContextResult:
    """Outcome of contextual proximity and surrounding text analysis."""

    matched_keywords: list[str] = field(default_factory=list)
    negative_keywords: list[str] = field(default_factory=list)
    has_positive_context: bool = False
    has_negative_context: bool = False
    context_score: float = 0.0  # Normalized score between -1.0 and +1.0
    confidence_boost: float = 0.0  # Confidence adjustment between -0.3 and +0.3
    snippet: str = ""


class ContextAnalyzer:
    """Evaluates text surrounding candidate matches to boost or penalize confidence."""

    WINDOW_SIZE: int = 60

    @classmethod
    def analyze(
        cls,
        candidate: CandidateMatch,
        source: Union[ParsedContent, str],
        window_size: Optional[int] = None,
    ) -> ContextResult:
        """Inspect the text window around candidate for positive and negative indicators."""
        raw_text = source.raw_text if hasattr(source, "raw_text") else str(source)
        window = window_size or cls.WINDOW_SIZE

        # Extract surrounding slice
        start_bound = max(0, candidate.start_idx - window)
        end_bound = min(len(raw_text), candidate.end_idx + window)

        before_text = raw_text[start_bound:candidate.start_idx]
        after_text = raw_text[candidate.end_idx:end_bound]
        surrounding_text = (before_text + " " + after_text).lower()

        # Build clean snippet for display
        snippet = raw_text[start_bound:end_bound].replace("\r\n", " ").replace("\n", " ").strip()

        entity = candidate.entity_type
        pos_keywords = POSITIVE_KEYWORDS.get(entity, set())

        matched_pos: list[str] = []
        matched_neg: list[str] = []

        # 1. Search text window for positive keywords with proximity weighting
        pos_score = 0.0
        for kw in pos_keywords:
            # Word boundary search for accurate matching
            kw_regex = re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
            
            # Check before candidate (usually carries strongest intent, e.g. "api_key = ")
            for m in kw_regex.finditer(before_text):
                matched_pos.append(kw)
                dist = len(before_text) - m.end()
                proximity_weight = max(0.3, 1.0 - (dist / window))
                pos_score += proximity_weight * 0.5

            # Check after candidate (e.g. "1234 5678 9012 (Aadhaar)")
            for m in kw_regex.finditer(after_text):
                matched_pos.append(kw)
                dist = m.start()
                proximity_weight = max(0.2, 0.8 - (dist / window))
                pos_score += proximity_weight * 0.3

        # 2. Check metadata anchors (CSV headers, JSON field paths)
        meta_signals = []
        if "header" in candidate.metadata and candidate.metadata["header"]:
            meta_signals.append(str(candidate.metadata["header"]).lower())
        if "path" in candidate.metadata and candidate.metadata["path"]:
            meta_signals.append(str(candidate.metadata["path"]).lower())

        for meta_str in meta_signals:
            for kw in pos_keywords:
                if kw in meta_str:
                    matched_pos.append(f"meta:{kw}")
                    pos_score += 0.4

        # 3. Search text window for negative keywords
        neg_score = 0.0
        for nkw in NEGATIVE_KEYWORDS:
            if re.search(rf"\b{re.escape(nkw)}\b", surrounding_text):
                matched_neg.append(nkw)
                neg_score += 0.4

        # Deduplicate matched keywords
        matched_pos = sorted(list(set(matched_pos)))
        matched_neg = sorted(list(set(matched_neg)))

        # Compute composite context score (-1.0 to 1.0)
        composite = min(1.0, pos_score) - min(1.0, neg_score)
        composite = round(max(-1.0, min(1.0, composite)), 3)

        # Confidence boost: positive context adds up to +0.3; negative context subtracts up to -0.3
        if composite > 0:
            boost = round(min(0.3, composite * 0.3), 3)
        elif composite < 0:
            boost = round(max(-0.3, composite * 0.3), 3)
        else:
            boost = 0.0

        return ContextResult(
            matched_keywords=matched_pos,
            negative_keywords=matched_neg,
            has_positive_context=len(matched_pos) > 0,
            has_negative_context=len(matched_neg) > 0,
            context_score=composite,
            confidence_boost=boost,
            snippet=snippet,
        )
