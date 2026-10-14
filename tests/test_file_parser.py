"""Unit tests for the FileParser component."""

import json
from pathlib import Path

import pytest
from redactX.models.enums import FileFormat
from redactX.scanner.file_parser import FileParser, ParsedCSVContent, ParsedJSONContent


class TestFileParserTxt:
    def test_parse_txt_coordinates(self, tmp_path: Path):
        file_path = tmp_path / "sample.txt"
        content = "Line 1: Hello\nLine 2: World\nLine 3: 1234 5678"
        file_path.write_text(content, encoding="utf-8", newline="\n")

        parsed = FileParser.parse(file_path)
        assert parsed.file_format == FileFormat.TXT
        assert parsed.raw_text == content
        assert parsed.line_count == 3

        # Coordinates for "Hello" (offset 8)
        # Line 1: 'Line 1: Hello\n' -> len is 14. 'Hello' starts at index 8.
        line, col = parsed.get_coordinates(8)
        assert line == 1
        assert col == 9  # 1-indexed column

        # Coordinates for "World" (offset 22)
        # Line 2 starts at index 14. 'World' is at index 22.
        line, col = parsed.get_coordinates(22)
        assert line == 2
        assert col == 9

        # Coordinate boundary checks (0, EOF)
        assert parsed.get_coordinates(0) == (1, 1)
        last_line, _ = parsed.get_coordinates(len(content))
        assert last_line == 3

    def test_parse_txt_crlf_coordinates(self, tmp_path: Path):
        file_path = tmp_path / "crlf.txt"
        content = "Line 1\r\nLine 2: Secret"
        file_path.write_bytes(content.encode("utf-8"))

        parsed = FileParser.parse(file_path)
        assert parsed.line_count == 2
        # 'Line 1\r\n' length is 8. Index 8 is 'L' of Line 2.
        line, col = parsed.get_coordinates(8)
        assert line == 2
        assert col == 1

    def test_get_snippet(self, tmp_path: Path):
        file_path = tmp_path / "snippet.txt"
        content = "Prefix text with api_key=sk_test_12345678 and suffix"
        file_path.write_text(content, encoding="utf-8")

        parsed = FileParser.parse_txt(file_path)
        # 'sk_test_12345678' is at [25:43]
        start_idx = content.index("sk_test_12345678")
        end_idx = start_idx + len("sk_test_12345678")

        snippet = parsed.get_snippet(start_idx, end_idx, padding=10)
        assert "sk_test_12345678" in snippet
        assert "api_key=" in snippet


class TestFileParserEncodings:
    def test_utf8_sig_bom_encoding(self, tmp_path: Path):
        file_path = tmp_path / "bom.txt"
        file_path.write_text("Text with UTF-8 BOM", encoding="utf-8-sig")

        parsed = FileParser.parse_txt(file_path)
        assert "Text with UTF-8 BOM" in parsed.raw_text
        assert parsed.encoding in ("utf-8", "utf-8-sig")

    def test_cp1252_encoding(self, tmp_path: Path):
        file_path = tmp_path / "windows.txt"
        # 0x93 and 0x94 are smart quotes in cp1252, invalid in utf-8
        raw_bytes = b'Quote: \x93Hello\x94'
        file_path.write_bytes(raw_bytes)

        parsed = FileParser.parse_txt(file_path)
        assert "Quote:" in parsed.raw_text
        assert parsed.encoding == "cp1252"

    def test_latin1_fallback_resilience(self, tmp_path: Path):
        file_path = tmp_path / "binary_like.txt"
        # Random arbitrary byte stream with non-ASCII bytes
        raw_bytes = b"Header: \xff\xfe\xaa\xbb raw data"
        file_path.write_bytes(raw_bytes)

        # Should never raise an exception
        parsed = FileParser.parse_txt(file_path)
        assert "Header:" in parsed.raw_text
        assert parsed.raw_text is not None


class TestFileParserCSV:
    def test_parse_standard_csv(self, tmp_path: Path):
        file_path = tmp_path / "users.csv"
        csv_data = "name,email,card\nAlice,alice@gmail.com,4111222233334444\nBob,bob@corp.in,4532015112830366\n"
        file_path.write_text(csv_data, encoding="utf-8")

        parsed = FileParser.parse_csv(file_path)
        assert isinstance(parsed, ParsedCSVContent)
        assert parsed.file_format == FileFormat.CSV
        assert parsed.headers == ["name", "email", "card"]
        assert len(parsed.rows) == 3

        # Locate cell for line 2 (Alice row)
        cell = parsed.get_cell_for_coordinate(2, "alice@gmail.com")
        assert cell is not None
        assert cell.row_index == 2
        assert cell.col_index == 2
        assert cell.header == "email"
        assert cell.value == "alice@gmail.com"

        # Locate card cell in line 3 (Bob row)
        cell_card = parsed.get_cell_for_coordinate(3, "4532015112830366")
        assert cell_card is not None
        assert cell_card.header == "card"
        assert cell_card.col_index == 3

    def test_parse_semicolon_delimited_csv(self, tmp_path: Path):
        file_path = tmp_path / "semi.csv"
        csv_data = "id;username;phone\n1;rahul;+91 9876543210\n"
        file_path.write_text(csv_data, encoding="utf-8")

        parsed = FileParser.parse_csv(file_path)
        assert parsed.delimiter == ";"
        assert parsed.headers == ["id", "username", "phone"]

    def test_ragged_csv_handling(self, tmp_path: Path):
        file_path = tmp_path / "ragged.csv"
        csv_data = "col1,col2\nval1\nval1,val2,val3\n"
        file_path.write_text(csv_data, encoding="utf-8")

        parsed = FileParser.parse_csv(file_path)
        assert len(parsed.rows) == 3


class TestFileParserJSON:
    def test_parse_valid_json(self, tmp_path: Path):
        file_path = tmp_path / "config.json"
        data = {
            "version": "1.0",
            "server": {
                "host": "192.168.1.1",
                "auth": {
                    "api_key": "sk_test_secret_token",
                    "admin_email": "admin@redactx.local"
                }
            },
            "contacts": [
                {"name": "Support", "phone": "+91 9876543210"}
            ]
        }
        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        parsed = FileParser.parse_json(file_path)
        assert isinstance(parsed, ParsedJSONContent)
        assert parsed.is_valid_json is True
        assert parsed.json_error is None

        # Verify extracted leaf field paths
        matched_fields = parsed.find_fields_containing("sk_test_secret_token")
        assert len(matched_fields) == 1
        assert matched_fields[0].path == "server.auth.api_key"
        assert matched_fields[0].value == "sk_test_secret_token"

        matched_phone = parsed.find_fields_containing("+91 9876543210")
        assert len(matched_phone) == 1
        assert matched_phone[0].path == "contacts[0].phone"

    def test_parse_malformed_json_fallback(self, tmp_path: Path):
        file_path = tmp_path / "broken.json"
        bad_json = '{\n  "key": "value",\n  "api_token": "sk_test_123" MISSING_CLOSING_BRACE'
        file_path.write_text(bad_json, encoding="utf-8")

        # Parser should not crash; flags is_valid_json = False and preserves raw_text
        parsed = FileParser.parse_json(file_path)
        assert parsed.is_valid_json is False
        assert parsed.json_error is not None
        assert "sk_test_123" in parsed.raw_text
        assert parsed.line_count == 3


class TestFileParserDispatcher:
    def test_unsupported_extension_error(self, tmp_path: Path):
        file_path = tmp_path / "image.png"
        file_path.write_bytes(b"\x89PNG")

        with pytest.raises(ValueError, match="Unsupported file extension"):
            FileParser.parse(file_path)
