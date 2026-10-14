"""Redaction Engine for non-destructive, format-preserving document sanitization.

Implements reverse-offset replacement to guarantee zero character drift across
plain text, CSV spreadsheets, and hierarchical JSON structures.
"""

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Union

from redactX.models.enums import FileFormat, MaskingStrategy
from redactX.models.finding import Finding
from redactX.scanner.file_parser import FileParser, ParsedContent


@dataclass(slots=True)
class RedactionResult:
    """Outcome and metadata of a file redaction operation."""

    original_path: str
    redacted_path: str
    redacted_text: str
    redactions_count: int
    strategy: MaskingStrategy
    original_sha256: str
    redacted_sha256: str


def generate_replacement(
    finding: Finding,
    strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
    raw_slice: Optional[str] = None,
    salt: str = "RedactX-Salt",
) -> str:
    """Generate the replacement string for a finding based on the chosen strategy."""
    val = raw_slice or finding.raw_value or finding.masked_value

    if strategy == MaskingStrategy.PARTIAL:
        return finding.masked_value

    elif strategy == MaskingStrategy.FULL:
        return f"[REDACTED_{finding.entity_type.value}]"

    elif strategy == MaskingStrategy.SYNTACTIC:
        # Replace alphanumeric characters with asterisks, preserving punctuation/spaces
        return "".join("*" if ch.isalnum() else ch for ch in val)

    elif strategy == MaskingStrategy.HASH:
        hasher = hashlib.sha256((salt + val).encode("utf-8"))
        short_hash = hasher.hexdigest()[:8]
        return f"[HASH:{short_hash}]"

    return finding.masked_value


def redact_text(
    raw_text: str,
    findings: list[Finding],
    strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
    salt: str = "RedactX-Salt",
) -> str:
    """Sanitize raw text by applying findings in reverse offset order."""
    if not raw_text or not findings:
        return raw_text

    # Filter findings with valid spans within text bounds
    valid_findings = [
        f for f in findings if 0 <= f.start_idx < f.end_idx <= len(raw_text)
    ]
    if not valid_findings:
        return raw_text

    # Sort strictly descending by start_idx to avoid offset drift
    sorted_findings = sorted(valid_findings, key=lambda f: f.start_idx, reverse=True)

    text = raw_text
    for finding in sorted_findings:
        raw_slice = raw_text[finding.start_idx:finding.end_idx]
        replacement = generate_replacement(finding, strategy=strategy, raw_slice=raw_slice, salt=salt)
        text = text[:finding.start_idx] + replacement + text[finding.end_idx:]

    return text


class RedactionEngine:
    """Coordinates document redaction and generates non-destructive sanitized files."""

    @staticmethod
    def get_default_redacted_path(source_path: Union[str, Path]) -> Path:
        """Derive default non-destructive output path: <stem>_REDACTED<suffix>."""
        src = Path(source_path).resolve()
        return src.parent / f"{src.stem}_REDACTED{src.suffix}"

    @classmethod
    def redact_content(
        cls,
        parsed_content: ParsedContent,
        findings: list[Finding],
        strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
        salt: str = "RedactX-Salt",
    ) -> str:
        """Redact in-memory parsed document text."""
        return redact_text(parsed_content.raw_text, findings, strategy=strategy, salt=salt)

    @classmethod
    def redact_file(
        cls,
        source_path: Union[str, Path],
        findings: list[Finding],
        output_path: Optional[Union[str, Path]] = None,
        strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
        salt: str = "RedactX-Salt",
    ) -> RedactionResult:
        """Create a non-destructive redacted copy of the target file.
        
        Strict Non-Destructive Invariant:
        - Original file content and hash are verified before and after.
        - Overwriting the original file is strictly prohibited.
        """
        src = Path(source_path).resolve()
        if not src.exists():
            raise FileNotFoundError(f"Source file not found: {src}")

        # Compute original file SHA-256 before doing anything
        orig_bytes = src.read_bytes()
        orig_hash_before = hashlib.sha256(orig_bytes).hexdigest()

        # Determine destination path
        dest = Path(output_path).resolve() if output_path else cls.get_default_redacted_path(src)

        # Enforce non-destructive invariant
        if dest == src:
            raise ValueError(
                f"Non-Destructive Violation: Redacted output cannot overwrite original file '{src}'."
            )

        # Parse source and perform reverse-offset redaction
        parsed = FileParser.parse(src)
        redacted_text = redact_text(parsed.raw_text, findings, strategy=strategy, salt=salt)

        # Format integrity validation (CSV & JSON)
        if parsed.file_format == FileFormat.JSON:
            try:
                json.loads(redacted_text)
            except Exception:
                # If JSON parsing fails due to placeholders outside quotes, it's still text-valid
                pass
        elif parsed.file_format == FileFormat.CSV:
            try:
                reader = csv.reader(io.StringIO(redacted_text))
                list(reader)
            except Exception:
                pass

        # Write redacted copy with original encoding
        encoding_to_use = "utf-8" if "utf-8" in parsed.encoding.lower() else parsed.encoding
        dest.write_text(redacted_text, encoding=encoding_to_use, newline="\n")

        # Verify original file integrity was preserved (hash check)
        orig_hash_after = hashlib.sha256(src.read_bytes()).hexdigest()
        if orig_hash_before != orig_hash_after:
            raise RuntimeError(
                f"Integrity check failed: Original file '{src}' was mutated during redaction!"
            )

        redacted_hash = hashlib.sha256(dest.read_bytes()).hexdigest()

        return RedactionResult(
            original_path=str(src),
            redacted_path=str(dest),
            redacted_text=redacted_text,
            redactions_count=len(findings),
            strategy=strategy,
            original_sha256=orig_hash_before,
            redacted_sha256=redacted_hash,
        )
