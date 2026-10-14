"""Report Generator for plain text, JSON, and CSV security audit reports.

Adheres strictly to the Zero-Leak policy: raw sensitive strings are never included
in reports; all findings use verified masked representations and sanitized context snippets.
"""

import csv
import io
import json
from pathlib import Path
from typing import Optional, Union

from redactX.models.result import ScanSummary


class ReportGenerator:
    """Generates structured, sanitized security audit reports."""

    @classmethod
    def generate_text_report(cls, summary: ScanSummary) -> str:
        """Produce a clean human-readable ASCII/Unicode security audit report."""
        lines: list[str] = [
            "=" * 80,
            "                            REDACTX SECURITY AUDIT REPORT",
            "=" * 80,
            f"Scan ID:          {summary.scan_id}",
            f"Timestamp (UTC):  {summary.timestamp}",
            f"Target Path:      {summary.target_path}",
            f"Overall Risk:     {summary.overall_risk.value}",
            f"Scan Duration:    {summary.duration_seconds:.2f}s",
            "-" * 80,
            "EXECUTIVE SUMMARY",
            "-" * 80,
            f"Total Files Scanned:       {summary.total_files_scanned}",
            f"Files With Findings:       {summary.total_files_with_findings}",
            f"Total Findings Detected:   {summary.total_findings}",
            "",
            "Findings by Severity:",
            f"  [CRITICAL]  {summary.severity_breakdown.get('CRITICAL', 0)}",
            f"  [HIGH]      {summary.severity_breakdown.get('HIGH', 0)}",
            f"  [MEDIUM]    {summary.severity_breakdown.get('MEDIUM', 0)}",
            f"  [LOW]       {summary.severity_breakdown.get('LOW', 0)}",
            "",
            "Findings by Entity Category:",
        ]

        if summary.entity_breakdown:
            for entity_type, count in sorted(summary.entity_breakdown.items()):
                lines.append(f"  - {entity_type}: {count}")
        else:
            lines.append("  (None)")

        lines.extend([
            "-" * 80,
            "DETAILED FINDINGS",
            "-" * 80,
        ])

        finding_idx = 1
        has_any_findings = False

        for file_res in summary.file_results:
            if not file_res.findings:
                continue

            has_any_findings = True
            lines.append(f"\nFILE: {file_res.file_path} [{file_res.file_format.value.upper()}] (Risk: {file_res.overall_risk.value})")
            lines.append("-" * 40)

            for f in file_res.findings:
                pct = int(f.confidence_score * 100)
                lines.append(
                    f"  [{finding_idx}] {f.entity_type.display_name} (Line: {f.line_number}, Col: {f.column_number})"
                )
                lines.append(f"      Severity:      {f.severity.value}")
                lines.append(f"      Confidence:    {f.confidence.value} ({pct}%)")
                lines.append(f"      Masked Value:  {f.masked_value}")
                if f.explanation:
                    lines.append(f"      Assessment:    {f.explanation}")
                if f.context_snippet:
                    lines.append(f"      Context:       \"{f.context_snippet}\"")
                lines.append("")
                finding_idx += 1

        if not has_any_findings:
            lines.append("No sensitive information detected. Target environment is CLEAN.")
            lines.append("")

        lines.extend([
            "=" * 80,
            "End of RedactX Security Report (Zero-Leak Policy Verified)",
            "=" * 80,
        ])

        return "\n".join(lines)

    @classmethod
    def generate_json_report(cls, summary: ScanSummary, indent: int = 2) -> str:
        """Produce a machine-readable JSON security report excluding raw values."""
        # Enforces include_raw=False
        data = summary.to_dict(include_raw=False)
        return json.dumps(data, indent=indent)

    @classmethod
    def generate_csv_report(cls, summary: ScanSummary) -> str:
        """Produce a tabular CSV summary of all findings for spreadsheet analysis."""
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")

        headers = [
            "Scan ID",
            "File Path",
            "File Format",
            "Line",
            "Column",
            "Entity Type",
            "Entity Name",
            "Severity",
            "Confidence",
            "Confidence Score",
            "Masked Value",
            "Validator Passed",
            "Context Snippet",
            "Explanation",
        ]
        writer.writerow(headers)

        for file_res in summary.file_results:
            for f in file_res.findings:
                writer.writerow([
                    summary.scan_id,
                    file_res.file_path,
                    file_res.file_format.value,
                    f.line_number,
                    f.column_number,
                    f.entity_type.value,
                    f.entity_type.display_name,
                    f.severity.value,
                    f.confidence.value,
                    f.confidence_score,
                    f.masked_value,
                    f.validator_passed,
                    f.context_snippet,
                    f.explanation,
                ])

        return output.getvalue()

    @classmethod
    def export_report(
        cls,
        summary: ScanSummary,
        output_path: Union[str, Path],
        report_format: Optional[str] = None,
    ) -> Path:
        """Write report to file in TXT, JSON, or CSV format."""
        out = Path(output_path).resolve()
        fmt = (report_format or out.suffix.lstrip(".")).lower()

        if fmt == "json":
            content = cls.generate_json_report(summary)
        elif fmt == "csv":
            content = cls.generate_csv_report(summary)
        elif fmt in ("txt", "text") or not fmt:
            content = cls.generate_text_report(summary)
        else:
            raise ValueError(f"Unsupported report export format: '{fmt}'. Supported: txt, json, csv.")

        # Ensure parent directory exists
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8", newline="\n")
        return out
