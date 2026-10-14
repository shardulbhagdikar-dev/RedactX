"""Finding and Candidate data structures for sensitive data matches."""

import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from redactX.models.enums import Confidence, EntityType, Severity
from redactX.utils.masking_helper import mask_sensitive_value


@dataclass(slots=True)
class CandidateMatch:
    """Raw, unvalidated candidate match detected by a regex or heuristic rule."""

    entity_type: EntityType
    raw_value: str
    start_idx: int
    end_idx: int
    line_number: int
    column_number: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end_idx - self.start_idx


@dataclass(slots=True)
class Finding:
    """A classified, validated, and risk-scored sensitive data finding.
    
    Zero-Leak Guarantee:
    - `raw_value` is excluded from the standard `__repr__` and `to_dict()` outputs.
    - `masked_value` is always safe for UI display, reporting, and persistent storage.
    """

    entity_type: EntityType
    masked_value: str
    severity: Severity
    confidence: Confidence
    confidence_score: float
    line_number: int
    column_number: int
    start_idx: int
    end_idx: int
    context_snippet: str
    explanation: str
    validator_passed: bool
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    entropy_score: Optional[float] = None
    file_path: Optional[str] = None
    # raw_value is retained in-memory strictly for redaction, never in logs/repr/exports
    raw_value: Optional[str] = field(default=None, repr=False)

    @classmethod
    def from_candidate(
        cls,
        candidate: CandidateMatch,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        confidence_score: float = 0.5,
        context_snippet: str = "",
        explanation: str = "",
        validator_passed: bool = True,
        entropy_score: Optional[float] = None,
        file_path: Optional[str] = None,
    ) -> "Finding":
        """Instantiate a Finding from a CandidateMatch with default or calculated attributes."""
        eff_severity = severity or candidate.entity_type.default_severity
        eff_confidence = confidence or Confidence.from_score(confidence_score)
        masked = mask_sensitive_value(candidate.raw_value, candidate.entity_type)

        # Ensure context snippet does not leak raw sensitive string
        safe_snippet = context_snippet
        if candidate.raw_value and candidate.raw_value in safe_snippet:
            safe_snippet = safe_snippet.replace(candidate.raw_value, masked)

        return cls(
            entity_type=candidate.entity_type,
            masked_value=masked,
            severity=eff_severity,
            confidence=eff_confidence,
            confidence_score=round(confidence_score, 4),
            line_number=candidate.line_number,
            column_number=candidate.column_number,
            start_idx=candidate.start_idx,
            end_idx=candidate.end_idx,
            context_snippet=safe_snippet,
            explanation=explanation,
            validator_passed=validator_passed,
            entropy_score=round(entropy_score, 4) if entropy_score is not None else None,
            file_path=file_path,
            raw_value=candidate.raw_value,
        )

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        """Convert finding to dictionary representation.
        
        Args:
            include_raw: If False (default), raw_value is omitted to prevent sensitive leaks.
        """
        payload: dict[str, Any] = {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "entity_name": self.entity_type.display_name,
            "masked_value": self.masked_value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "start_idx": self.start_idx,
            "end_idx": self.end_idx,
            "context_snippet": self.context_snippet,
            "explanation": self.explanation,
            "validator_passed": self.validator_passed,
            "entropy_score": self.entropy_score,
            "file_path": self.file_path,
        }
        if include_raw:
            payload["raw_value"] = self.raw_value
        return payload
