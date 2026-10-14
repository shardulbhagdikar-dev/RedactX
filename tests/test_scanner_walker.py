"""Unit tests for DirectoryWalker and ScanEngine."""

from pathlib import Path

import pytest
from redactX.models.enums import FileFormat, ScanStatus, Severity
from redactX.scanner.scanner import CancellationToken, ScanEngine
from redactX.scanner.walker import DirectoryWalker
from redactX.storage.history import HistoryDatabase


class TestDirectoryWalker:
    def test_single_file_discovery(self, tmp_path: Path):
        txt_file = tmp_path / "document.txt"
        txt_file.write_text("Hello", encoding="utf-8")

        walker = DirectoryWalker()
        found = walker.find_files(txt_file)
        assert len(found) == 1
        assert found[0] == txt_file

    def test_single_unsupported_file_ignored(self, tmp_path: Path):
        bin_file = tmp_path / "image.png"
        bin_file.write_bytes(b"\x89PNG")

        walker = DirectoryWalker()
        found = walker.find_files(bin_file)
        assert len(found) == 0

    def test_nonexistent_path_raises(self, tmp_path: Path):
        walker = DirectoryWalker()
        with pytest.raises(FileNotFoundError):
            walker.find_files(tmp_path / "missing.txt")

    def test_recursive_discovery_and_directory_pruning(self, tmp_path: Path):
        # Create standard files
        (tmp_path / "file1.txt").write_text("Text", encoding="utf-8")
        sub_dir = tmp_path / "subdir"
        sub_dir.mkdir()
        (sub_dir / "file2.csv").write_text("id,val", encoding="utf-8")
        (sub_dir / "file3.json").write_text("{}", encoding="utf-8")

        # Create ignored directory trees
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "git_config.txt").write_text("should_ignore", encoding="utf-8")

        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "pip.json").write_text("should_ignore", encoding="utf-8")

        walker = DirectoryWalker()
        found = walker.find_files(tmp_path, recursive=True)
        found_names = {p.name for p in found}

        assert "file1.txt" in found_names
        assert "file2.csv" in found_names
        assert "file3.json" in found_names
        # Excluded directory files must not be present
        assert "git_config.txt" not in found_names
        assert "pip.json" not in found_names
        assert len(found) == 3


class TestScanEngine:
    def test_scan_single_file_with_findings(self, tmp_path: Path):
        card_file = tmp_path / "finance.txt"
        card_file.write_text("Card: 4532 0151 1283 0366 on file.", encoding="utf-8")

        engine = ScanEngine()
        result = engine.scan_file(card_file)

        assert result.status == ScanStatus.COMPLETED
        assert result.overall_risk == Severity.CRITICAL
        assert result.finding_count == 1
        assert result.findings[0].masked_value == "**** **** **** 0366"
        assert result.scan_duration_ms >= 0.0

    def test_scan_clean_file(self, tmp_path: Path):
        clean_file = tmp_path / "clean.txt"
        clean_file.write_text("Clean document without any sensitive data.", encoding="utf-8")

        engine = ScanEngine()
        result = engine.scan_file(clean_file)

        assert result.status == ScanStatus.COMPLETED
        assert result.overall_risk == Severity.CLEAN
        assert result.finding_count == 0

    def test_scan_target_directory_and_callbacks(self, tmp_path: Path):
        (tmp_path / "f1.txt").write_text("Email: admin@redactx.io", encoding="utf-8")
        (tmp_path / "f2.csv").write_text("name,card\nBob,4532015112830366", encoding="utf-8")

        started_events: list[tuple[str, int, int]] = []
        completed_events: list[tuple[str, int, int]] = []
        progress_events: list[tuple[int, int]] = []

        def on_start(path: str, cur: int, tot: int):
            started_events.append((path, cur, tot))

        def on_done(res, cur: int, tot: int):
            completed_events.append((res.file_name, cur, tot))

        def on_prog(cur: int, tot: int):
            progress_events.append((cur, tot))

        engine = ScanEngine()
        summary = engine.scan_target(
            tmp_path,
            on_file_started=on_start,
            on_file_completed=on_done,
            on_progress=on_prog,
        )

        assert summary.total_files_scanned == 2
        assert summary.total_findings >= 2
        assert len(started_events) == 2
        assert len(completed_events) == 2
        assert len(progress_events) == 2
        assert progress_events[-1] == (2, 2)

    def test_cancellation_token(self, tmp_path: Path):
        for i in range(5):
            (tmp_path / f"doc_{i}.txt").write_text(f"Document {i}", encoding="utf-8")

        cancel_token = CancellationToken()

        def cancel_on_second_file(res, cur: int, tot: int):
            if cur == 2:
                cancel_token.cancel()

        engine = ScanEngine()
        summary = engine.scan_target(
            tmp_path,
            cancellation_token=cancel_token,
            on_file_completed=cancel_on_second_file,
        )

        # Scanned files should stop early after cancellation trigger
        assert summary.total_files_scanned <= 3
        assert cancel_token.is_cancelled is True

    def test_scan_and_auto_save_to_history(self, tmp_path: Path):
        test_file = tmp_path / "data.txt"
        test_file.write_text("User email: test@example.com", encoding="utf-8")

        db_file = tmp_path / "history.db"
        history_db = HistoryDatabase(db_file)
        engine = ScanEngine(history_db=history_db)

        summary = engine.scan_target(tmp_path, save_to_history=True)
        assert summary.total_files_scanned == 1

        # Verify scan record is saved in SQLite database
        recent_scans = history_db.get_recent_scans()
        assert len(recent_scans) == 1
        assert recent_scans[0]["id"] == summary.scan_id
