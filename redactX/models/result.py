"""Scan results and summary models."""

import datetime
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from redactX.models.enums import EntityType, FileFormat, ScanStatus, Severity
from redactX.models.finding import Finding


@dataclass(slots=True)
class FileInfo:
    """Metadata regarding a local file candidate for scanning."""

    path: str
    name: str
    format: FileFormat
    size_bytes: int
    sha256_hash: Optional[str] = None

    @classmethod
    def from_path(cls, file_path: str | Path, compute_hash: bool = False) -> "FileInfo":
        p = Path(file_path).resolve()
        fmt = FileFormat.from_extension(p.suffix)
        size = p.stat().st_size if p.exists() else 0
        sha = None
        if compute_hash and p.exists():
            import hashlib

            hasher = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha = hasher.hexdigest()

        return cls(
            path=str(p),
            name=p.name,
            format=fmt,
            size_bytes=size,
            sha256_hash=sha,
        )


@dataclass(slots=True)
class FileScanResult:
    """Aggregated scan findings and risk assessment for a single file."""

    file_path: str
    file_name: str
    file_format: FileFormat
    file_size_bytes: int
    status: ScanStatus = ScanStatus.PENDING
    error_message: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    overall_risk: Severity = Severity.CLEAN
    scan_duration_ms: float = 0.0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def findings_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity if s != Severity.CLEAN}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def compute_overall_risk(self) -> Severity:
        """Derive overall file risk based on the highest finding severity."""
        if not self.findings:
            self.overall_risk = Severity.CLEAN
            return Severity.CLEAN
        highest = max(f.severity for f in self.findings)
        self.overall_risk = highest
        return highest

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_format": self.file_format.value,
            "file_size_bytes": self.file_size_bytes,
            "status": self.status.value,
            "error_message": self.error_message,
            "finding_count": self.finding_count,
            "overall_risk": self.overall_risk.value,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "findings": [f.to_dict(include_raw=include_raw) for f in self.findings],
        }


@dataclass(slots=True)
class ScanSummary:
    """Session-level summary across multiple scanned files or directory."""

    target_path: str
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    total_files_scanned: int = 0
    total_files_with_findings: int = 0
    total_findings: int = 0
    overall_risk: Severity = Severity.CLEAN
    duration_seconds: float = 0.0
    file_results: list[FileScanResult] = field(default_factory=list)
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    entity_breakdown: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_results(
        cls,
        target_path: str,
        results: list[FileScanResult],
        duration_seconds: float = 0.0,
        scan_id: Optional[str] = None,
    ) -> "ScanSummary":
        total_files = len(results)
        files_with_findings = sum(1 for r in results if r.has_findings)
        all_findings = [f for r in results for f in r.findings]
        total_findings = len(all_findings)

        overall_risk = Severity.CLEAN
        if all_findings:
            overall_risk = max(f.severity for f in all_findings)

        severity_counts: dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
        }
        for f in all_findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        entity_counts: dict[str, int] = {}
        for f in all_findings:
            entity_counts[f.entity_type.value] = entity_counts.get(f.entity_type.value, 0) + 1

        return cls(
            target_path=target_path,
            scan_id=scan_id or uuid.uuid4().hex[:10],
            total_files_scanned=total_files,
            total_files_with_findings=files_with_findings,
            total_findings=total_findings,
            overall_risk=overall_risk,
            duration_seconds=round(duration_seconds, 2),
            file_results=results,
            severity_breakdown=severity_counts,
            entity_breakdown=entity_counts,
        )

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "total_files_scanned": self.total_files_scanned,
            "total_files_with_findings": self.total_files_with_findings,
            "total_findings": self.total_findings,
            "overall_risk": self.overall_risk.value,
            "duration_seconds": self.duration_seconds,
            "severity_breakdown": self.severity_breakdown,
            "entity_breakdown": self.entity_breakdown,
            "file_results": [r.to_dict(include_raw=include_raw) for r in self.file_results],
        }
