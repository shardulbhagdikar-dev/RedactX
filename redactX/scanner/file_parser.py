"""Resilient file parser for TXT, CSV, and JSON formats.

Maintains exact line and character offset coordinates for candidate localization,
risk analysis, and format-preserving redaction.
"""

import bisect
import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from redactX.models.enums import FileFormat
from redactX.utils.logger import get_logger

logger = get_logger("scanner.file_parser")

# Candidate encodings to attempt in priority order
SUPPORTED_ENCODINGS = ("utf-8", "utf-8-sig", "cp1252", "latin-1")


@dataclass(slots=True)
class CSVCell:
    """Represents a specific cell coordinate in a parsed CSV document."""

    row_index: int  # 1-indexed row in the CSV file
    col_index: int  # 1-indexed column
    header: Optional[str]
    value: str


@dataclass(slots=True)
class JSONField:
    """Represents an extracted leaf string value within a JSON document hierarchy."""

    path: str  # e.g., 'users[0].auth.api_key'
    value: str


@dataclass(slots=True)
class ParsedContent:
    """Base container for text extracted from a file with coordinate mapping."""

    file_path: str
    file_format: FileFormat
    raw_text: str
    encoding: str
    line_starts: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.line_starts:
            self._compute_line_starts()

    def _compute_line_starts(self) -> None:
        """Precompute character offset indices of each line start for fast O(log N) lookup."""
        starts = [0]
        for idx, ch in enumerate(self.raw_text):
            if ch == "\n":
                starts.append(idx + 1)
        self.line_starts = starts

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def get_coordinates(self, offset: int) -> tuple[int, int]:
        """Convert an absolute character offset to 1-indexed (line_number, column_number)."""
        if not self.raw_text:
            return 1, 1

        offset = max(0, min(offset, len(self.raw_text)))
        line_idx = bisect.bisect_right(self.line_starts, offset) - 1
        line_num = line_idx + 1
        line_start = self.line_starts[line_idx]
        col_num = (offset - line_start) + 1
        return line_num, col_num

    def get_snippet(self, start_idx: int, end_idx: int, padding: int = 40) -> str:
        """Extract a bounded context window around a candidate match."""
        start = max(0, start_idx - padding)
        end = min(len(self.raw_text), end_idx + padding)
        snippet = self.raw_text[start:end]
        # Normalize newlines to spaces for clean display
        return snippet.replace("\r\n", " ").replace("\n", " ").strip()


@dataclass(slots=True)
class ParsedCSVContent(ParsedContent):
    """Parsed representation of a CSV document."""

    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    delimiter: str = ","

    def get_cell_for_coordinate(self, line_number: int, target_value: str) -> Optional[CSVCell]:
        """Attempt to locate the specific CSV cell corresponding to a line and text match."""
        # Row 1 is header if present, rows list is 0-indexed data
        row_idx = line_number - 1  # 0-indexed row line
        if 0 <= row_idx < len(self.rows):
            row_data = self.rows[row_idx]
            for col_idx, cell_val in enumerate(row_data):
                if target_value in cell_val:
                    header = self.headers[col_idx] if col_idx < len(self.headers) else None
                    return CSVCell(
                        row_index=line_number,
                        col_index=col_idx + 1,
                        header=header,
                        value=cell_val,
                    )
        return None


@dataclass(slots=True)
class ParsedJSONContent(ParsedContent):
    """Parsed representation of a JSON document."""

    parsed_data: Any = None
    is_valid_json: bool = True
    json_error: Optional[str] = None
    fields: list[JSONField] = field(default_factory=list)

    def find_fields_containing(self, target_value: str) -> list[JSONField]:
        """Return JSON field paths whose values contain the target string."""
        return [f for f in self.fields if target_value in f.value]


class FileParser:
    """Extracts text content and coordinate indices from supported file formats."""

    @staticmethod
    def read_file_resilient(file_path: str | Path) -> tuple[str, str]:
        """Read text from file with resilient encoding fallback.
        
        Tries UTF-8, UTF-8-SIG, CP1252, and Latin-1 in sequence.
        If all fail, reads with Latin-1 replacing invalid characters,
        guaranteeing that parsing never crashes.
        """
        path = Path(file_path)
        raw_bytes = path.read_bytes()

        for enc in SUPPORTED_ENCODINGS:
            try:
                text = raw_bytes.decode(enc)
                return text, enc
            except UnicodeDecodeError:
                continue

        # Ultimate fallback
        logger.warning("Falling back to latin-1 replacement decoding for %s", path.name)
        return raw_bytes.decode("latin-1", errors="replace"), "latin-1 (fallback)"

    @classmethod
    def parse_txt(cls, file_path: str | Path) -> ParsedContent:
        """Parse a plain text file."""
        text, enc = cls.read_file_resilient(file_path)
        return ParsedContent(
            file_path=str(file_path),
            file_format=FileFormat.TXT,
            raw_text=text,
            encoding=enc,
        )

    @classmethod
    def parse_csv(cls, file_path: str | Path) -> ParsedCSVContent:
        """Parse a CSV document, identifying delimiter, headers, and rows."""
        text, enc = cls.read_file_resilient(file_path)
        delimiter = ","

        # Attempt to sniff delimiter
        sample = text[:4096]
        if sample:
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ","

        rows: list[list[str]] = []
        headers: list[str] = []

        try:
            reader = csv.reader(io.StringIO(text), delimiter=delimiter)
            all_rows = list(reader)
            if all_rows:
                headers = all_rows[0]
                rows = all_rows
        except Exception as exc:
            logger.warning("Error reading CSV structure in %s: %s", Path(file_path).name, exc)
            # If CSV structure parsing fails, we still retain raw_text for regex scanning
            rows = []

        return ParsedCSVContent(
            file_path=str(file_path),
            file_format=FileFormat.CSV,
            raw_text=text,
            encoding=enc,
            headers=headers,
            rows=rows,
            delimiter=delimiter,
        )

    @classmethod
    def parse_json(cls, file_path: str | Path) -> ParsedJSONContent:
        """Parse a JSON document and extract hierarchical leaf field paths."""
        text, enc = cls.read_file_resilient(file_path)
        is_valid = True
        json_error = None
        parsed_data = None
        fields: list[JSONField] = []

        try:
            parsed_data = json.loads(text)
            fields = cls._extract_json_fields(parsed_data)
        except Exception as exc:
            is_valid = False
            json_error = str(exc)
            logger.warning("Malformed JSON in %s: %s (falling back to raw text scan)", Path(file_path).name, exc)

        return ParsedJSONContent(
            file_path=str(file_path),
            file_format=FileFormat.JSON,
            raw_text=text,
            encoding=enc,
            parsed_data=parsed_data,
            is_valid_json=is_valid,
            json_error=json_error,
            fields=fields,
        )

    @classmethod
    def parse(cls, file_path: str | Path) -> ParsedContent:
        """Route to appropriate parser based on file extension."""
        path = Path(file_path)
        fmt = FileFormat.from_extension(path.suffix)

        if fmt == FileFormat.CSV:
            return cls.parse_csv(path)
        elif fmt == FileFormat.JSON:
            return cls.parse_json(path)
        else:
            return cls.parse_txt(path)

    @classmethod
    def _extract_json_fields(cls, obj: Any, path: str = "") -> list[JSONField]:
        """Recursively traverse JSON objects to map key paths to values."""
        results: list[JSONField] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                curr_path = f"{path}.{k}" if path else str(k)
                if isinstance(v, (dict, list)):
                    results.extend(cls._extract_json_fields(v, curr_path))
                else:
                    results.append(JSONField(path=curr_path, value=str(v)))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                curr_path = f"{path}[{idx}]"
                if isinstance(item, (dict, list)):
                    results.extend(cls._extract_json_fields(item, curr_path))
                else:
                    results.append(JSONField(path=curr_path, value=str(item)))
        return results
