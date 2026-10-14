"""Dashboard View for RedactX GUI.

Implements Wireframe 4: Analytics Dashboard with a 2x2 grid of security charts:
1. Line & Area Chart: Real-time incident trends & threat spikes over time
2. Bar & Column Graph: Real policy violations by entity type
3. Pie & Donut Chart: Real breakdown by severity level
4. Data Lineage & Flow Graph: Live dynamic tracking of files scanned, detected, verified, and sanitized
"""

from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from redactX.gui.charts import (
    CategoryBarChart,
    DataLineageFlowGraph,
    SeverityDonutChart,
    TrendAreaChart,
)
from redactX.models.enums import EntityType
from redactX.models.result import FileScanResult, ScanSummary
from redactX.storage.history import HistoryDatabase


class DashboardView(QWidget):
    """Analytics Dashboard matching Wireframe 4 with a 2x2 dynamic chart grid."""

    def __init__(self, history_db: Optional[HistoryDatabase] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.history_db = history_db or HistoryDatabase()

        # In-memory tracking for live active scan streaming
        self._live_files_scanned: int = 0
        self._live_findings_count: int = 0
        self._live_entity_counts: dict[str, int] = {}
        self._live_sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(14)

        # Outer Container matching Wireframe 4
        card = QFrame(self)
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(12)

        # Container Header
        hdr = QHBoxLayout()
        self.lbl_title = QLabel("Dashboard", card)
        self.lbl_title.setStyleSheet("font-size: 18px; font-weight: 600; color: #FFFFFF;")
        hdr.addWidget(self.lbl_title)
        hdr.addStretch()

        self.btn_refresh = QPushButton("Refresh Analytics", card)
        self.btn_refresh.setProperty("class", "SecondaryButton")
        self.btn_refresh.clicked.connect(self.refresh_from_database)
        hdr.addWidget(self.btn_refresh)
        card_layout.addLayout(hdr)

        # 2x2 Chart Grid matching Wireframe 4
        grid = QGridLayout()
        grid.setSpacing(14)

        # 1. Top-Left: Line & Area Chart (Incident Trends)
        self.chart_trends = TrendAreaChart(card)
        grid.addWidget(self.chart_trends, 0, 0)

        # 2. Top-Right: Bar & Column Graph (Top Policy Violators)
        self.chart_violators = CategoryBarChart(card)
        grid.addWidget(self.chart_violators, 0, 1)

        # 3. Bottom-Left: Pie & Donut Chart (Severity Breakdown)
        self.chart_severity = SeverityDonutChart(card)
        grid.addWidget(self.chart_severity, 1, 0)

        # 4. Bottom-Right: Data Lineage & Flow Graph (Sensitive File Journey)
        self.chart_lineage = DataLineageFlowGraph(card)
        grid.addWidget(self.chart_lineage, 1, 1)

        card_layout.addLayout(grid)
        layout.addWidget(card)

        # Populate initial historical data from database
        self.refresh_from_database()

    def refresh_from_database(self) -> None:
        """Fetch statistics and historical scans from local SQLite database to populate charts."""
        scans = self.history_db.get_recent_scans(limit=20)
        stats = self.history_db.get_statistics()

        total_scans = stats.get("total_scans", 0)
        total_findings = stats.get("total_findings", 0)
        by_entity = dict(stats.get("top_entities") or stats.get("findings_by_entity") or {})
        by_sev = dict(stats.get("severity_counts") or stats.get("findings_by_severity") or {})

        # Fallback aggregation directly from recorded scans if summary stats dictionary was empty
        if scans and (not by_sev or not any(v > 0 for v in by_sev.values())):
            by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for s in scans:
                sb = s.get("severity_breakdown", {})
                if isinstance(sb, dict):
                    for k, v in sb.items():
                        if k in by_sev:
                            by_sev[k] += int(v)

        if scans and (not by_entity or not any(v > 0 for v in by_entity.values())):
            by_entity = {}
            for s in scans:
                eb = s.get("entity_breakdown", {})
                if isinstance(eb, dict):
                    for k, v in eb.items():
                        by_entity[k] = by_entity.get(k, 0) + int(v)

        # 1. Line & Area Chart: Plot real historical scan trend points
        if scans:
            trend_points: list[tuple[str, int]] = []
            for s in reversed(scans):
                raw_ts = str(s.get("timestamp", ""))
                time_part = "Scan"
                try:
                    clean_ts = raw_ts.replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_ts)
                    if dt.tzinfo is not None:
                        dt = dt.astimezone()
                    time_part = dt.strftime("%H:%M")
                except Exception:
                    if "T" in raw_ts:
                        time_part = raw_ts.split("T")[-1][:5]
                    elif " " in raw_ts:
                        time_part = raw_ts.split(" ")[-1][:5]
                    else:
                        time_part = raw_ts[-5:]
                count = int(s.get("total_findings", 0))
                trend_points.append((time_part or "Scan", count))
            self.chart_trends.set_data(trend_points)
        else:
            self.chart_trends.set_data([])

        # 2. Donut Chart: Plot real severity breakdown
        if by_sev and any(v > 0 for v in by_sev.values()):
            sev_map = {
                "CRITICAL": by_sev.get("CRITICAL", 0),
                "HIGH": by_sev.get("HIGH", 0),
                "MEDIUM": by_sev.get("MEDIUM", 0),
                "LOW": by_sev.get("LOW", 0),
            }
            self.chart_severity.set_data(sev_map)
        else:
            self.chart_severity.set_data({})

        # 3. Bar Chart: Plot top policy violation entity categories
        if by_entity and any(v > 0 for v in by_entity.values()):
            colors = ["#EF4444", "#F97316", "#EC4899", "#EAB308", "#38BDF8", "#10B981"]
            bar_data = []
            for i, (k, count) in enumerate(sorted(by_entity.items(), key=lambda x: x[1], reverse=True)[:5]):
                try:
                    display_title = EntityType(k).display_name
                except Exception:
                    display_title = str(k).replace("_", " ").title()
                bar_data.append((display_title, count, colors[i % len(colors)]))
            self.chart_violators.set_data(bar_data)
        else:
            self.chart_violators.set_data([])

        # 4. Data Lineage Flow Graph: Set live metrics
        self.chart_lineage.set_metrics(
            files=total_scans,
            findings=total_findings,
            verified=total_findings,
            redacted=0,
        )

    # --------------------------------------------------------------------------
    # Live Streaming Plotting (As Data Arrives During Scans)
    # --------------------------------------------------------------------------
    def on_scan_started(self) -> None:
        """Reset live streaming session counters when a new scan commences."""
        self._live_files_scanned = 0
        self._live_findings_count = 0
        self._live_entity_counts.clear()
        self._live_sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def on_live_file_scanned(self, result: FileScanResult, current_idx: int, total_count: int) -> None:
        """Stream real-time findings into dashboard as each file finishes scanning."""
        self._live_files_scanned = current_idx

        for f in result.findings:
            self._live_findings_count += 1
            sev = f.severity.value
            if sev in self._live_sev_counts:
                self._live_sev_counts[sev] += 1
            ename = f.entity_type.display_name
            self._live_entity_counts[ename] = self._live_entity_counts.get(ename, 0) + 1

        # Live Update Donut
        if self._live_findings_count > 0:
            self.chart_severity.set_data(dict(self._live_sev_counts))

        # Live Update Bar Chart
        if self._live_entity_counts:
            colors = ["#EF4444", "#F97316", "#EC4899", "#EAB308", "#38BDF8", "#10B981"]
            bar_data = [
                (k, v, colors[i % len(colors)])
                for i, (k, v) in enumerate(sorted(self._live_entity_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            ]
            self.chart_violators.set_data(bar_data)

        # Live Update Lineage Flow Graph
        self.chart_lineage.set_metrics(
            files=self._live_files_scanned,
            findings=self._live_findings_count,
            verified=self._live_findings_count,
            redacted=0,
        )

    def update_from_summary(self, summary: ScanSummary) -> None:
        """Update charts immediately upon full scan session completion."""
        # Update Donut
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        entity_counts: dict[str, int] = {}

        for res in summary.file_results:
            for f in res.findings:
                s = f.severity.value
                if s in sev_counts:
                    sev_counts[s] += 1
                ename = f.entity_type.display_name
                entity_counts[ename] = entity_counts.get(ename, 0) + 1

        self.chart_severity.set_data(sev_counts)

        if entity_counts:
            colors = ["#EF4444", "#F97316", "#EC4899", "#EAB308", "#38BDF8", "#10B981"]
            bar_data = [
                (k, v, colors[i % len(colors)])
                for i, (k, v) in enumerate(sorted(entity_counts.items(), key=lambda x: x[1], reverse=True)[:5])
            ]
            self.chart_violators.set_data(bar_data)
        else:
            self.chart_violators.set_data([])

        # Update Trend Area Chart with this new scan point
        current_points = list(self.chart_trends.data_points)
        try:
            clean_ts = summary.timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            ts_label = dt.strftime("%H:%M")
        except Exception:
            ts_label = summary.timestamp.split("T")[-1][:5] if "T" in summary.timestamp else summary.timestamp[-5:]
        current_points.append((ts_label or "Scan", summary.total_findings))
        self.chart_trends.set_data(current_points[-10:])

        # Update Lineage Flow Graph
        self.chart_lineage.set_metrics(
            files=summary.total_files_scanned,
            findings=summary.total_findings,
            verified=summary.total_findings,
            redacted=0,
        )

    def on_redaction_completed(self, redacted_count: int) -> None:
        """Update the Vault node in the Flow Graph after redaction finishes."""
        self.chart_lineage.redacted_count += redacted_count
        self.chart_lineage.update()
