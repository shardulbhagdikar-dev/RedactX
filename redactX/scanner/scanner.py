"""Scan Engine orchestrating end-to-end scanning across local files and folders.

Integrates FileParser, DetectorRegistry, ValidationEngine, ContextAnalyzer,
EntropyAnalyzer, and RiskEngine into a cohesive, thread-safe pipeline.
"""

import time
from pathlib import Path
from typing import Callable, Optional, Union

from redactX.analysis.risk import RiskEngine
from redactX.detectors.registry import DetectorRegistry
from redactX.models.enums import FileFormat, ScanStatus, Severity
from redactX.models.result import FileScanResult, ScanSummary
from redactX.scanner.file_parser import FileParser
from redactX.scanner.walker import DirectoryWalker
from redactX.storage.history import HistoryDatabase
from redactX.utils.logger import get_logger

logger = get_logger("scanner.engine")


class CancellationToken:
    """Thread-safe cooperative cancellation signal for long-running scans."""

    def __init__(self):
        self._cancelled: bool = False

    def cancel(self) -> None:
        """Trigger cancellation."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def reset(self) -> None:
        self._cancelled = False


class ScanEngine:
    """Core orchestrator for discovering, scanning, and analyzing local files."""

    def __init__(
        self,
        registry: Optional[DetectorRegistry] = None,
        walker: Optional[DirectoryWalker] = None,
        history_db: Optional[HistoryDatabase] = None,
    ):
        self.registry = registry or DetectorRegistry(load_defaults=True)
        self.walker = walker or DirectoryWalker()
        self.history_db = history_db

    def scan_file(self, file_path: Union[str, Path]) -> FileScanResult:
        """Execute the full DLP scanning pipeline on an individual file."""
        path = Path(file_path).resolve()
        start_time = time.perf_counter()

        try:
            fmt = FileFormat.from_extension(path.suffix)
        except ValueError as exc:
            return FileScanResult(
                file_path=str(path),
                file_name=path.name,
                file_format=FileFormat.TXT,
                file_size_bytes=path.stat().st_size if path.exists() else 0,
                status=ScanStatus.SKIPPED,
                error_message=str(exc),
                scan_duration_ms=0.0,
            )

        file_size = path.stat().st_size if path.exists() else 0

        try:
            # 1. Parse document
            parsed_content = FileParser.parse(path)

            # 2. Discover candidate sensitive spans
            candidates = self.registry.detect_all(parsed_content)

            # 3. Validate candidates, inspect context/entropy, and compute risk
            findings = RiskEngine.evaluate_candidates(
                candidates=candidates,
                source=parsed_content,
                file_path=str(path),
            )

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            result = FileScanResult(
                file_path=str(path),
                file_name=path.name,
                file_format=fmt,
                file_size_bytes=file_size,
                status=ScanStatus.COMPLETED,
                findings=findings,
                scan_duration_ms=round(duration_ms, 2),
            )
            result.compute_overall_risk()
            return result

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("Error scanning %s: %s", path.name, exc, exc_info=True)
            return FileScanResult(
                file_path=str(path),
                file_name=path.name,
                file_format=fmt,
                file_size_bytes=file_size,
                status=ScanStatus.FAILED,
                error_message=str(exc),
                overall_risk=Severity.CLEAN,
                scan_duration_ms=round(duration_ms, 2),
            )

    def scan_target(
        self,
        target_path: Union[str, Path],
        recursive: bool = True,
        save_to_history: bool = False,
        cancellation_token: Optional[CancellationToken] = None,
        on_file_started: Optional[Callable[[str, int, int], None]] = None,
        on_file_completed: Optional[Callable[[FileScanResult, int, int], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> ScanSummary:
        """Scan a file or directory with real-time event callbacks and cancellation.
        
        Args:
            target_path: File or directory path.
            recursive: If True, recursively scan subdirectories.
            save_to_history: If True and history_db is available, persist scan record.
            cancellation_token: Signal to cancel scan gracefully mid-progress.
            on_file_started: Callback signature (file_path: str, index: int, total: int).
            on_file_completed: Callback signature (result: FileScanResult, index: int, total: int).
            on_progress: Callback signature (current: int, total: int).
        """
        target = Path(target_path).resolve()
        start_time = time.perf_counter()

        # Discover all target files
        files_to_scan = self.walker.find_files(target, recursive=recursive)
        total_files = len(files_to_scan)

        results: list[FileScanResult] = []

        for idx, file_path in enumerate(files_to_scan, start=1):
            if cancellation_token and cancellation_token.is_cancelled:
                logger.info("Scan cancelled by user at file %d/%d", idx, total_files)
                break

            str_path = str(file_path)
            if on_file_started:
                try:
                    on_file_started(str_path, idx, total_files)
                except Exception as exc:
                    logger.debug("on_file_started callback error: %s", exc)

            # Perform file scan
            file_result = self.scan_file(file_path)
            results.append(file_result)

            if on_file_completed:
                try:
                    on_file_completed(file_result, idx, total_files)
                except Exception as exc:
                    logger.debug("on_file_completed callback error: %s", exc)

            if on_progress:
                try:
                    on_progress(idx, total_files)
                except Exception as exc:
                    logger.debug("on_progress callback error: %s", exc)

        total_duration = time.perf_counter() - start_time

        summary = ScanSummary.from_results(
            target_path=str(target),
            results=results,
            duration_seconds=round(total_duration, 2),
        )

        if save_to_history and self.history_db:
            try:
                self.history_db.save_scan(summary)
            except Exception as exc:
                logger.error("Failed to auto-save scan to history: %s", exc)

        return summary
