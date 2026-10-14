"""Risk & Scoring Engine for RedactX.

Combines detection signals, mathematical validation, contextual proximity,
and Shannon entropy into calibrated confidence scores, severity ratings,
and file-level risk assessments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Union

from redactX.analysis.context import ContextAnalyzer, ContextResult
from redactX.analysis.entropy import EntropyAnalyzer, EntropyResult
from redactX.analysis.validator import ValidationEngine, ValidationResult
from redactX.models.enums import Confidence, EntityType, Severity
from redactX.models.finding import CandidateMatch, Finding

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent


@dataclass(slots=True)
class RiskScore:
    """Quantitative and qualitative risk assessment for a file or collection of findings."""

    severity: Severity
    score: float  # Quantitative risk score from 0.0 to 100.0
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    summary_text: str


class RiskEngine:
    """Evaluates findings, calculates risk metrics, and constructs Finding instances."""

    # Baseline confidence scores for candidates prior to validation/context
    BASELINE_CONFIDENCE: dict[EntityType, float] = {
        EntityType.CREDIT_CARD: 0.50,
        EntityType.AADHAAR: 0.50,
        EntityType.API_KEY: 0.50,
        EntityType.PASSWORD: 0.50,
        EntityType.UPI_ID: 0.55,
        EntityType.PHONE_NUMBER: 0.55,
        EntityType.EMAIL: 0.65,
        EntityType.IPV4_ADDRESS: 0.60,
    }

    @classmethod
    def compute_confidence(
        cls,
        candidate: CandidateMatch,
        val_res: ValidationResult,
        ctx_res: ContextResult,
        ent_res: Optional[EntropyResult],
    ) -> tuple[Confidence, float]:
        """Compute the final calibrated confidence score (0.05 to 0.99) and Confidence level."""
        base = cls.BASELINE_CONFIDENCE.get(candidate.entity_type, 0.50)

        # 1. Validation impact
        val_impact = val_res.confidence_boost

        # 2. Contextual impact
        ctx_impact = ctx_res.confidence_boost

        # 3. Entropy impact (only applicable for secrets and passwords)
        ent_impact = ent_res.confidence_boost if ent_res is not None else 0.0

        raw_score = base + val_impact + ctx_impact + ent_impact

        # Hard guardrails:
        # If mathematical checksum failed (Luhn, Verhoeff), clamp to maximum 0.35 (LOW)
        if not val_res.is_valid and candidate.entity_type in (
            EntityType.CREDIT_CARD,
            EntityType.AADHAAR,
            EntityType.PHONE_NUMBER,
        ):
            final_score = min(0.35, max(0.05, raw_score))
        else:
            final_score = min(0.99, max(0.05, raw_score))

        final_score = round(final_score, 4)
        conf_level = Confidence.from_score(final_score)
        return conf_level, final_score

    @classmethod
    def compute_severity(
        cls, candidate: CandidateMatch, val_res: ValidationResult
    ) -> Severity:
        """Derive finding severity, with downgrades for failed candidate validations."""
        default_sev = candidate.entity_type.default_severity

        # If a candidate failed mathematical validation (e.g. invalid Luhn check digit),
        # downgrade severity to LOW to reflect likely false positive.
        if not val_res.is_valid:
            return Severity.LOW

        return default_sev

    @classmethod
    def build_explanation(
        cls,
        candidate: CandidateMatch,
        val_res: ValidationResult,
        ctx_res: ContextResult,
        ent_res: Optional[EntropyResult],
        confidence: Confidence,
        confidence_score: float,
    ) -> str:
        """Generate human-understandable security explanation for the finding."""
        entity_name = candidate.entity_type.display_name
        parts: list[str] = []

        # Validation narrative
        parts.append(val_res.reason)

        # Context narrative
        if ctx_res.has_positive_context:
            kw_list = ", ".join(ctx_res.matched_keywords[:3])
            parts.append(f"Matching context keyword(s): [{kw_list}]")
        if ctx_res.has_negative_context:
            neg_list = ", ".join(ctx_res.negative_keywords[:2])
            parts.append(f"Mock/test indicator(s) detected: [{neg_list}]")

        # Entropy narrative
        if ent_res is not None and candidate.entity_type in (
            EntityType.API_KEY,
            EntityType.PASSWORD,
        ):
            parts.append(
                f"Entropy: {ent_res.raw_entropy} bits ({ent_res.charset}, high_randomness={ent_res.is_high_entropy})"
            )

        details = "; ".join(parts)
        pct = int(confidence_score * 100)
        return f"{entity_name} ({details}) -> Confidence: {confidence.value} ({pct}%)"

    @classmethod
    def evaluate_candidate(
        cls,
        candidate: CandidateMatch,
        source: Union[ParsedContent, str],
        file_path: Optional[str] = None,
    ) -> Finding:
        """Run candidate through Validation, Context, and Entropy engines to create a Finding."""
        # 1. Validation
        val_res = ValidationEngine.validate(candidate)

        # 2. Context Analysis
        ctx_res = ContextAnalyzer.analyze(candidate, source)

        # 3. Entropy Analysis (for secrets, API keys, and passwords)
        ent_res: Optional[EntropyResult] = None
        if candidate.entity_type in (EntityType.API_KEY, EntityType.PASSWORD):
            ent_res = EntropyAnalyzer.analyze(candidate.raw_value)

        # 4. Confidence & Severity
        conf_level, conf_score = cls.compute_confidence(
            candidate, val_res, ctx_res, ent_res
        )
        severity = cls.compute_severity(candidate, val_res)

        # 5. Explanation
        explanation = cls.build_explanation(
            candidate, val_res, ctx_res, ent_res, conf_level, conf_score
        )

        return Finding.from_candidate(
            candidate=candidate,
            severity=severity,
            confidence=conf_level,
            confidence_score=conf_score,
            context_snippet=ctx_res.snippet,
            explanation=explanation,
            validator_passed=val_res.is_valid,
            entropy_score=ent_res.raw_entropy if ent_res is not None else None,
            file_path=file_path,
        )

    @classmethod
    def evaluate_candidates(
        cls,
        candidates: list[CandidateMatch],
        source: Union[ParsedContent, str],
        file_path: Optional[str] = None,
    ) -> list[Finding]:
        """Evaluate a collection of candidates into Finding instances with multi-finding snippet sanitization."""
        findings: list[Finding] = []
        for c in candidates:
            val_res = ValidationEngine.validate(c)
            ctx_res = ContextAnalyzer.analyze(c, source)

            # False Positive Suppression for Candidates Failing Mathematical Validation:
            # 1. Credit card candidates that fail Luhn checksum AND lack positive context keywords
            if c.entity_type == EntityType.CREDIT_CARD and not val_res.is_valid:
                if not ctx_res.has_positive_context:
                    continue

            # 2. Aadhaar candidates that fail Verhoeff checksum AND lack positive context keywords
            if c.entity_type == EntityType.AADHAAR and not val_res.is_valid:
                if not ctx_res.has_positive_context:
                    continue

            # 3. Generic API key assignment candidates with low entropy (< 2.5) and no provider signature
            if c.entity_type == EntityType.API_KEY and not c.metadata.get("provider_pattern", False):
                ent_res = EntropyAnalyzer.analyze(c.raw_value)
                if ent_res.raw_entropy < 2.5:
                    continue

            finding = cls.evaluate_candidate(c, source, file_path=file_path)
            findings.append(finding)

        # Zero-Leak Cross-Sanitization:
        # If multiple sensitive items appear within each other's context windows,
        # ensure every finding's context snippet has ALL discovered raw secrets masked.
        raw_to_masked: dict[str, str] = {
            f.raw_value: f.masked_value
            for f in findings
            if f.raw_value
        }
        sorted_pairs = sorted(raw_to_masked.items(), key=lambda x: len(x[0]), reverse=True)

        for f in findings:
            snippet = f.context_snippet
            for raw_val, masked_val in sorted_pairs:
                if raw_val in snippet:
                    snippet = snippet.replace(raw_val, masked_val)
            f.context_snippet = snippet

        return findings

    @classmethod
    def calculate_file_risk(cls, findings: list[Finding]) -> RiskScore:
        """Compute aggregate risk score and severity for a collection of findings."""
        if not findings:
            return RiskScore(
                severity=Severity.CLEAN,
                score=0.0,
                findings_count=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                summary_text="No sensitive data findings detected.",
            )

        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }
        weighted_points = 0.0

        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
            # Weighted formula: Severity weight * confidence score
            weighted_points += f.severity.weight * f.confidence_score * 5.0

        # Max severity among findings
        max_severity = max(f.severity for f in findings)
        overall_score = round(min(100.0, weighted_points), 1)

        summary = (
            f"Overall Risk: {max_severity.value} (Score: {overall_score}/100) - "
            f"{len(findings)} finding(s) [Critical: {counts[Severity.CRITICAL]}, "
            f"High: {counts[Severity.HIGH]}, Medium: {counts[Severity.MEDIUM]}, Low: {counts[Severity.LOW]}]"
        )

        return RiskScore(
            severity=max_severity,
            score=overall_score,
            findings_count=len(findings),
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            summary_text=summary,
        )
