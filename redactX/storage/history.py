"""Local SQLite history database for RedactX audit log and session persistence.

Guarantees:
- Zero raw secrets stored: Only sanitized masked values and metadata are persisted.
- Isolated local file storage: Stored in %APPDATA%/RedactX/history.db or custom path.
- Foreign key cascaded deletions and indexing.
"""

import contextlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Generator, Optional, Union

from redactX.models.result import ScanSummary
from redactX.utils.logger import get_logger

logger = get_logger("storage.history")


def get_default_db_path() -> Path:
    """Return default platform database path (%APPDATA%/RedactX/history.db)."""
    appdata = os.environ.get("APPDATA")
    if appdata:
        base_dir = Path(appdata) / "RedactX"
    else:
        base_dir = Path.home() / ".redactx"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "history.db"


class HistoryDatabase:
    """Manages persistent SQLite scan session history and audit logs."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self._is_memory = str(db_path) == ":memory:" if db_path else False
        if self._is_memory:
            self.db_path = ":memory:"
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        else:
            self._mem_conn = None
            self.db_path = Path(db_path) if db_path else get_default_db_path()
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Create a database connection context that automatically commits and closes."""
        if self._is_memory and self._mem_conn:
            with self._mem_conn:
                yield self._mem_conn
            return

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema with tables and indices."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    total_files_scanned INTEGER NOT NULL,
                    total_files_with_findings INTEGER NOT NULL,
                    total_findings INTEGER NOT NULL,
                    overall_risk TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    severity_breakdown TEXT NOT NULL,
                    entity_breakdown TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_format TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    column_number INTEGER NOT NULL,
                    entity_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    masked_value TEXT NOT NULL,
                    validator_passed INTEGER NOT NULL,
                    explanation TEXT NOT NULL,
                    context_snippet TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id);
            """)

    def save_scan(self, summary: ScanSummary) -> str:
        """Save a scan session and its findings to the database.
        
        Zero-Leak: Only masked values and metadata are written.
        """
        sev_json = json.dumps(summary.severity_breakdown)
        ent_json = json.dumps(summary.entity_breakdown)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO scans (
                    id, timestamp, target_path, total_files_scanned,
                    total_files_with_findings, total_findings, overall_risk,
                    duration_seconds, severity_breakdown, entity_breakdown
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.scan_id,
                    summary.timestamp,
                    summary.target_path,
                    summary.total_files_scanned,
                    summary.total_files_with_findings,
                    summary.total_findings,
                    summary.overall_risk.value,
                    summary.duration_seconds,
                    sev_json,
                    ent_json,
                ),
            )

            # Insert findings
            for file_res in summary.file_results:
                for f in file_res.findings:
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO scan_findings (
                            id, scan_id, file_path, file_format, line_number,
                            column_number, entity_type, severity, confidence,
                            confidence_score, masked_value, validator_passed,
                            explanation, context_snippet
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f.id,
                            summary.scan_id,
                            file_res.file_path,
                            file_res.file_format.value,
                            f.line_number,
                            f.column_number,
                            f.entity_type.value,
                            f.severity.value,
                            f.confidence.value,
                            f.confidence_score,
                            f.masked_value,
                            1 if f.validator_passed else 0,
                            f.explanation,
                            f.context_snippet,
                        ),
                    )

            logger.info("Persisted scan %s with %d findings to SQLite", summary.scan_id, summary.total_findings)
        return summary.scan_id

    def get_recent_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieve recent scan sessions ordered by timestamp descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scans
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["severity_breakdown"] = json.loads(item["severity_breakdown"])
                item["entity_breakdown"] = json.loads(item["entity_breakdown"])
                results.append(item)
            return results

    def get_scan_details(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Retrieve full details of a scan session including all findings."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                return None

            scan_dict = dict(scan_row)
            scan_dict["severity_breakdown"] = json.loads(scan_dict["severity_breakdown"])
            scan_dict["entity_breakdown"] = json.loads(scan_dict["entity_breakdown"])

            cursor.execute(
                "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY line_number, column_number",
                (scan_id,),
            )
            findings_rows = cursor.fetchall()
            scan_dict["findings"] = [dict(r) for r in findings_rows]
            return scan_dict

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated findings (via foreign key cascade)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cursor.rowcount > 0

    def clear_history(self) -> int:
        """Clear all historical scans and findings. Returns number of scans deleted."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT count(*) FROM scans")
            total = cursor.fetchone()[0]
            cursor.execute("DELETE FROM scans")
            return total

    def get_statistics(self) -> dict[str, Any]:
        """Compute aggregated audit metrics across all recorded scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    count(*) as total_scans,
                    coalesce(sum(total_files_scanned), 0) as total_files,
                    coalesce(sum(total_findings), 0) as total_findings
                FROM scans
            """)
            stats_row = dict(cursor.fetchone())

            cursor.execute("""
                SELECT severity, count(*) as count
                FROM scan_findings
                GROUP BY severity
            """)
            sev_counts = {r["severity"]: r["count"] for r in cursor.fetchall()}

            cursor.execute("""
                SELECT entity_type, count(*) as count
                FROM scan_findings
                GROUP BY entity_type
                ORDER BY count DESC
                LIMIT 5
            """)
            top_entities = {r["entity_type"]: r["count"] for r in cursor.fetchall()}

            stats_row["severity_counts"] = sev_counts
            stats_row["findings_by_severity"] = sev_counts
            stats_row["top_entities"] = top_entities
            stats_row["findings_by_entity"] = top_entities
            return stats_row
