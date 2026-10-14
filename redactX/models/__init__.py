"""Domain models and core data structures for RedactX."""

from redactX.models.enums import (
    Severity,
    Confidence,
    EntityType,
    FileFormat,
    ScanStatus,
)
from redactX.models.finding import CandidateMatch, Finding
from redactX.models.result import FileInfo, FileScanResult, ScanSummary

__all__ = [
    "Severity",
    "Confidence",
    "EntityType",
    "FileFormat",
    "ScanStatus",
    "CandidateMatch",
    "Finding",
    "FileInfo",
    "FileScanResult",
    "ScanSummary",
]
