"""Background QThread worker threads for scanning and redaction.

Ensures the PySide6 UI stays 100% responsive at 60 FPS while scanning
large directories or processing documents.
"""

from pathlib import Path
from typing import Optional, Union

from PySide6.QtCore import QObject, QThread, Signal

from redactX.models.result import FileScanResult, ScanSummary
from redactX.redaction.redactor import MaskingStrategy, RedactionEngine
from redactX.scanner.scanner import CancellationToken, ScanEngine
from redactX.utils.logger import get_logger

logger = get_logger("gui.worker")


class ScanWorker(QThread):
    """Background worker thread for executing directory and file DLP scans."""

    # Qt Signals
    file_started = Signal(str, int, int)       # file_path, current_idx, total_count
    file_completed = Signal(object, int, int)   # FileScanResult, current_idx, total_count
    progress = Signal(int, int)                # current_idx, total_count
    scan_finished = Signal(object)             # ScanSummary
    scan_error = Signal(str)                   # error message

    def __init__(
        self,
        engine: ScanEngine,
        target_path: Union[str, Path],
        recursive: bool = True,
        save_to_history: bool = True,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.engine = engine
        self.target_path = Path(target_path)
        self.recursive = recursive
        self.save_to_history = save_to_history
        self.cancellation_token = CancellationToken()

    def cancel(self) -> None:
        """Request cooperative scan termination."""
        self.cancellation_token.cancel()

    def run(self) -> None:
        """Run scan pipeline on the worker thread."""
        try:
            summary = self.engine.scan_target(
                target_path=self.target_path,
                recursive=self.recursive,
                save_to_history=self.save_to_history,
                cancellation_token=self.cancellation_token,
                on_file_started=lambda path, curr, total: self.file_started.emit(path, curr, total),
                on_file_completed=lambda res, curr, total: self.file_completed.emit(res, curr, total),
                on_progress=lambda curr, total: self.progress.emit(curr, total),
            )
            self.scan_finished.emit(summary)
        except Exception as exc:
            logger.error("Scan worker crashed: %s", exc, exc_info=True)
            self.scan_error.emit(str(exc))


class RedactionWorker(QThread):
    """Background worker thread for executing batch redaction."""

    file_redacted = Signal(str, str)          # original_path, redacted_path
    redaction_finished = Signal(list)         # list of redacted paths
    redaction_error = Signal(str)             # error message

    def __init__(
        self,
        results_with_findings: list[FileScanResult],
        strategy: MaskingStrategy = MaskingStrategy.PARTIAL,
        output_dir: Optional[Union[str, Path]] = None,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self.results = results_with_findings
        self.strategy = strategy
        self.output_dir = output_dir

    def run(self) -> None:
        """Execute redaction on each file with findings."""
        redacted_files: list[str] = []
        try:
            for res in self.results:
                if not res.findings:
                    continue
                output_file = (
                    Path(self.output_dir) / f"{Path(res.file_path).stem}_REDACTED{Path(res.file_path).suffix}"
                    if self.output_dir
                    else None
                )
                redaction_result = RedactionEngine.redact_file(
                    source_path=res.file_path,
                    findings=res.findings,
                    strategy=self.strategy,
                    output_path=output_file,
                )
                redacted_str = str(redaction_result.redacted_path)
                redacted_files.append(redacted_str)
                self.file_redacted.emit(res.file_path, redacted_str)

            self.redaction_finished.emit(redacted_files)
        except Exception as exc:
            logger.error("Redaction worker error: %s", exc, exc_info=True)
            self.redaction_error.emit(str(exc))
