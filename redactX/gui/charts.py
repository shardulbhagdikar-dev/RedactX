"""Dashboard Security Charts and Flow Graphs for RedactX GUI.

Implements the 4 visual analytics components requested in the wireframe:
1. Line & Area Chart (Incident activity trends over time)
2. Bar & Column Graph (Top policy violators & channels)
3. Pie & Donut Chart (Incidents broken down by severity level)
4. Data Lineage & Flow Graph (Interactive node-and-edge map of sensitive data journey)

All charts are 100% dynamic: they start in clean zero/empty states and render
live data as scans execute and history accumulates.
"""

import math
from typing import Optional

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
)
from PySide6.QtWidgets import QWidget

from redactX.gui.theme import (
    COLOR_ACCENT_BLUE,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_GREEN,
    COLOR_ACCENT_RED,
    COLOR_BORDER,
    COLOR_BORDER_LIGHT,
    COLOR_SURFACE,
    COLOR_SURFACE_LIGHT,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    SEVERITY_COLORS,
)


# ==============================================================================
# 1. Line & Area Chart (Incident Trend Activity)
# ==============================================================================
class TrendAreaChart(QWidget):
    """Line and Area chart displaying incident activity and security spikes over time."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(280, 180)
        # Dynamic timeline data: list of (label, incident_count)
        self.data_points: list[tuple[str, int]] = []

    def set_data(self, points: list[tuple[str, int]]) -> None:
        self.data_points = points or []
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())
        pad_x, pad_y = 40.0, 34.0
        plot_w = w - (pad_x * 2)
        plot_h = h - (pad_y * 2)

        # Background Card
        painter.setBrush(QColor(COLOR_SURFACE))
        painter.setPen(QPen(QColor(COLOR_BORDER), 1))
        painter.drawRoundedRect(QRectF(2, 2, w - 4, h - 4), 10, 10)

        # Header Title
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        font = QFont("Segoe UI", 10, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(QPointF(16, 22), "Incident Activity & Spikes")

        # Empty State
        if not self.data_points:
            # Subtle baseline
            painter.setPen(QPen(QColor(COLOR_BORDER_LIGHT), 1, Qt.PenStyle.DashLine))
            painter.drawLine(QPointF(pad_x, h / 2.0), QPointF(w - pad_x, h / 2.0))

            painter.setPen(QColor(COLOR_TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 9))
            painter.drawText(
                QRectF(0, h * 0.45, w, 30),
                Qt.AlignmentFlag.AlignCenter,
                "No scan activity recorded yet\nRun a scan to monitor threat spikes",
            )
            painter.end()
            return

        max_val = max(max(pt[1] for pt in self.data_points), 4)
        num_points = len(self.data_points)

        # Draw horizontal grid lines
        painter.setPen(QPen(QColor(COLOR_BORDER_LIGHT), 1, Qt.PenStyle.DashLine))
        grid_steps = 3
        for i in range(grid_steps + 1):
            y = pad_y + (plot_h / grid_steps) * i
            painter.drawLine(QPointF(pad_x, y), QPointF(w - pad_x, y))
            # Grid label
            lbl_val = int(max_val * (1.0 - (i / grid_steps)))
            painter.setPen(QColor(COLOR_TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 8))
            painter.drawText(QPointF(10, y + 4), str(lbl_val))
            painter.setPen(QPen(QColor(COLOR_BORDER_LIGHT), 1, Qt.PenStyle.DashLine))

        # Calculate coordinates
        coords: list[QPointF] = []
        step_x = plot_w / max(num_points - 1, 1) if num_points > 1 else plot_w / 2.0

        if num_points == 1:
            # Single point centered
            val = self.data_points[0][1]
            cx = w / 2.0
            cy = pad_y + plot_h - (val / max_val) * plot_h
            coords.append(QPointF(cx, cy))
        else:
            for i, (label, val) in enumerate(self.data_points):
                cx = pad_x + i * step_x
                cy = pad_y + plot_h - (val / max_val) * plot_h
                coords.append(QPointF(cx, cy))

        # Area gradient fill
        if len(coords) > 1:
            area_path = QPainterPath()
            area_path.moveTo(coords[0].x(), pad_y + plot_h)
            for pt in coords:
                area_path.lineTo(pt)
            area_path.lineTo(coords[-1].x(), pad_y + plot_h)
            area_path.closeSubpath()

            grad = QLinearGradient(0, pad_y, 0, pad_y + plot_h)
            grad.setColorAt(0.0, QColor(239, 68, 68, 120))
            grad.setColorAt(1.0, QColor(239, 68, 68, 5))
            painter.fillPath(area_path, QBrush(grad))

            # Line stroke
            line_path = QPainterPath()
            line_path.moveTo(coords[0])
            for pt in coords[1:]:
                line_path.lineTo(pt)

            painter.setPen(QPen(QColor(COLOR_ACCENT_RED), 2.5))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(line_path)

        # Plot point dots & X-axis labels
        painter.setFont(QFont("Segoe UI", 8))
        for i, pt in enumerate(coords):
            # Glowing outer dot
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(239, 68, 68, 80))
            painter.drawEllipse(pt, 5.0, 5.0)
            # Solid inner dot
            painter.setBrush(QColor(255, 255, 255))
            painter.drawEllipse(pt, 2.5, 2.5)

            # X Label
            x_label = self.data_points[i][0]
            painter.setPen(QColor(COLOR_TEXT_SECONDARY))
            painter.drawText(QPointF(pt.x() - 14, h - 8), x_label)

        painter.end()


# ==============================================================================
# 2. Bar & Column Graph (Top Policy Violators & Data Types)
# ==============================================================================
class CategoryBarChart(QWidget):
    """Bar graph displaying top violation categories and data policy triggers."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(280, 180)
        # Dynamic categories list: (entity_name, count, color_hex)
        self.categories: list[tuple[str, int, str]] = []

    def set_data(self, cat_data: list[tuple[str, int, str]]) -> None:
        self.categories = cat_data or []
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())

        # Card Container
        painter.setBrush(QColor(COLOR_SURFACE))
        painter.setPen(QPen(QColor(COLOR_BORDER), 1))
        painter.drawRoundedRect(QRectF(2, 2, w - 4, h - 4), 10, 10)

        # Header Title
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(QPointF(16, 22), "Top Violations by Entity Type")

        # Empty State
        if not self.categories:
            painter.setPen(QColor(COLOR_TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 9))
            painter.drawText(
                QRectF(0, h * 0.45, w, 30),
                Qt.AlignmentFlag.AlignCenter,
                "No violations detected\nScan files to view entity breakdown",
            )
            painter.end()
            return

        font_label = QFont("Segoe UI", 8)
        fm = QFontMetrics(font_label)
        max_label_w = max((fm.horizontalAdvance(item[0]) for item in self.categories), default=80)
        # Allocate comfortable padding on left so entity names are never pushed outside border
        pad_left = max(130.0, min(float(max_label_w + 24), w * 0.42))
        pad_top = 36.0
        pad_right, pad_bottom = 45.0, 16.0
        avail_w = max(w - pad_left - pad_right, 60.0)
        avail_h = h - pad_top - pad_bottom

        max_val = max(max(item[1] for item in self.categories), 1)
        bar_count = len(self.categories)
        row_height = avail_h / max(bar_count, 1)
        bar_thickness = max(min(row_height * 0.45, 14.0), 6.0)

        for i, (name, count, color_hex) in enumerate(self.categories):
            cy = pad_top + i * row_height + (row_height - bar_thickness) / 2.0
            track_w = avail_w - 20.0
            bar_w = (count / max_val) * track_w

            # Category Label with generous padding inside card
            painter.setPen(QColor(COLOR_TEXT_SECONDARY))
            painter.setFont(font_label)
            label_rect = QRectF(12.0, cy - 2, pad_left - 20.0, bar_thickness + 4)
            elided_name = fm.elidedText(name, Qt.TextElideMode.ElideRight, int(label_rect.width()))
            painter.drawText(
                label_rect,
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                elided_name,
            )

            # Bar Track
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(COLOR_SURFACE_LIGHT))
            painter.drawRoundedRect(QRectF(pad_left, cy, track_w, bar_thickness), 4, 4)

            # Active Bar
            bar_color = QColor(color_hex)
            grad = QLinearGradient(pad_left, cy, pad_left + bar_w, cy)
            grad.setColorAt(0.0, bar_color.darker(110))
            grad.setColorAt(1.0, bar_color)
            painter.setBrush(QBrush(grad))
            painter.drawRoundedRect(QRectF(pad_left, cy, max(bar_w, 4.0), bar_thickness), 4, 4)

            # Value label
            painter.setPen(QColor(COLOR_TEXT_PRIMARY))
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            painter.drawText(
                QPointF(pad_left + bar_w + 8, cy + bar_thickness * 0.85),
                str(count),
            )

        painter.end()


# ==============================================================================
# 3. Pie & Donut Chart (Severity Breakdown)
# ==============================================================================
class SeverityDonutChart(QWidget):
    """Donut chart showing distribution across security severity ratings."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(280, 180)
        # Dynamic severity map
        self.severity_counts: dict[str, int] = {}

    def set_data(self, counts: dict[str, int]) -> None:
        self.severity_counts = counts or {}
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())

        # Card Container
        painter.setBrush(QColor(COLOR_SURFACE))
        painter.setPen(QPen(QColor(COLOR_BORDER), 1))
        painter.drawRoundedRect(QRectF(2, 2, w - 4, h - 4), 10, 10)

        # Header Title
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(QPointF(16, 22), "Incidents by Severity Level")

        total = sum(self.severity_counts.values()) if self.severity_counts else 0
        cx = w * 0.35
        cy = h * 0.58
        outer_r = min(w * 0.22, h * 0.35)
        inner_r = outer_r * 0.62

        outer_rect = QRectF(cx - outer_r, cy - outer_r, outer_r * 2, outer_r * 2)
        inner_rect = QRectF(cx - inner_r, cy - inner_r, inner_r * 2, inner_r * 2)

        # Empty / Clean State
        if total == 0:
            # Draw subtle neutral track
            painter.setPen(QPen(QColor(COLOR_BORDER_LIGHT), 10))
            painter.drawEllipse(outer_rect)

            painter.setPen(QColor(COLOR_ACCENT_GREEN))
            painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            painter.drawText(
                QRectF(cx - inner_r, cy - 12, inner_r * 2, 16),
                Qt.AlignmentFlag.AlignCenter,
                "0",
            )
            painter.setPen(QColor(COLOR_TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 7))
            painter.drawText(
                QRectF(cx - inner_r, cy + 4, inner_r * 2, 14),
                Qt.AlignmentFlag.AlignCenter,
                "CLEAN",
            )

            # Neutral Legend
            leg_x = w * 0.62
            leg_y = h * 0.34
            painter.setPen(QColor(COLOR_TEXT_MUTED))
            painter.setFont(QFont("Segoe UI", 8))
            painter.drawText(QPointF(leg_x, leg_y + 12), "No active threats")
            painter.drawText(QPointF(leg_x, leg_y + 30), "Environment: 100% Clean")
            painter.end()
            return

        # Draw donut arcs with real counts
        start_angle = 90.0 * 16.0
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = self.severity_counts.get(sev, 0)
            if count <= 0:
                continue
            span_angle = (count / total) * 360.0 * 16.0
            color = QColor(SEVERITY_COLORS.get(sev, "#9CA3AF"))

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawPie(outer_rect, int(start_angle), int(span_angle))
            start_angle += span_angle

        # Cutout center hole for Donut effect
        painter.setBrush(QColor(COLOR_SURFACE))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(inner_rect)

        # Total count in center
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        painter.drawText(
            QRectF(cx - inner_r, cy - 14, inner_r * 2, 16),
            Qt.AlignmentFlag.AlignCenter,
            str(total),
        )
        painter.setPen(QColor(COLOR_TEXT_MUTED))
        painter.setFont(QFont("Segoe UI", 7))
        painter.drawText(
            QRectF(cx - inner_r, cy + 2, inner_r * 2, 14),
            Qt.AlignmentFlag.AlignCenter,
            "FINDINGS",
        )

        # Legend on right side
        leg_x = w * 0.64
        leg_y = h * 0.30
        row_h = 18.0

        for idx, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
            count = self.severity_counts.get(sev, 0)
            cur_y = leg_y + idx * row_h
            color = QColor(SEVERITY_COLORS.get(sev, "#9CA3AF"))

            # Dot
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(QRectF(leg_x, cur_y, 8, 8), 2, 2)

            # Name & Count
            painter.setPen(QColor(COLOR_TEXT_SECONDARY))
            painter.setFont(QFont("Segoe UI", 8))
            pct = int((count / total) * 100) if total else 0
            painter.drawText(QPointF(leg_x + 14, cur_y + 8), f"{sev}: {count} ({pct}%)")

        painter.end()


# ==============================================================================
# 4. Data Lineage & Flow Graph (Interactive Sensitive Data Journey)
# ==============================================================================
class DataLineageFlowGraph(QWidget):
    """Dynamic node-and-edge graph tracing sensitive file journey from origin to redaction."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setMinimumSize(280, 180)
        self.files_count: int = 0
        self.findings_count: int = 0
        self.verified_count: int = 0
        self.redacted_count: int = 0

    def set_metrics(self, files: int, findings: int, verified: int, redacted: int) -> None:
        """Update live metrics for each node in the lineage pipeline."""
        self.files_count = files
        self.findings_count = findings
        self.verified_count = verified
        self.redacted_count = redacted
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = float(self.width()), float(self.height())

        # Card Container
        painter.setBrush(QColor(COLOR_SURFACE))
        painter.setPen(QPen(QColor(COLOR_BORDER), 1))
        painter.drawRoundedRect(QRectF(2, 2, w - 4, h - 4), 10, 10)

        # Header Title
        painter.setPen(QColor(COLOR_TEXT_PRIMARY))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(QPointF(16, 22), "Data Lineage & Redaction Flow")

        # 4 Dynamic Nodes
        sub_files = f"{self.files_count} Scanned" if self.files_count else "0 Files"
        sub_det = f"{self.findings_count} Discovered" if self.findings_count else "0 Detected"
        sub_val = f"{self.verified_count} Verified" if self.verified_count else "0 Verified"
        sub_vault = f"{self.redacted_count} Sanitized" if self.redacted_count else "0 Vaulted"

        nodes = [
            ("Origin Files", sub_files, COLOR_ACCENT_BLUE),
            ("Detection", sub_det, COLOR_ACCENT_RED),
            ("Analysis", sub_val, COLOR_ACCENT_CYAN),
            ("Vault", sub_vault, COLOR_ACCENT_GREEN),
        ]

        node_w = min((w - 70.0) / 4.0, 75.0)
        node_h = 48.0
        cy = h * 0.54
        spacing = (w - 40.0 - (len(nodes) * node_w)) / max(len(nodes) - 1, 1)

        node_rects: list[QRectF] = []
        for i, (title, subtitle, color_hex) in enumerate(nodes):
            nx = 20.0 + i * (node_w + spacing)
            ny = cy - (node_h / 2.0)
            rect = QRectF(nx, ny, node_w, node_h)
            node_rects.append(rect)

        # Draw connecting arrows between nodes
        arrow_pen = QPen(QColor(COLOR_BORDER_LIGHT), 2)
        arrow_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arrow_pen)

        for i in range(len(node_rects) - 1):
            r1 = node_rects[i]
            r2 = node_rects[i + 1]
            p1 = QPointF(r1.right() + 2, cy)
            p2 = QPointF(r2.left() - 2, cy)

            # Connecting line
            painter.drawLine(p1, p2)
            # Arrow head
            painter.drawLine(p2, QPointF(p2.x() - 5, p2.y() - 4))
            painter.drawLine(p2, QPointF(p2.x() - 5, p2.y() + 4))

        # Draw each node card
        for i, (title, subtitle, color_hex) in enumerate(nodes):
            rect = node_rects[i]
            painter.setPen(QPen(QColor(color_hex), 1.2))
            painter.setBrush(QColor(COLOR_SURFACE_LIGHT))
            painter.drawRoundedRect(rect, 8, 8)

            # Node Title
            painter.setPen(QColor(COLOR_TEXT_PRIMARY))
            painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            painter.drawText(
                QRectF(rect.x() + 2, rect.y() + 6, rect.width() - 4, 14),
                Qt.AlignmentFlag.AlignCenter,
                title,
            )

            # Subtitle
            painter.setPen(QColor(color_hex))
            painter.setFont(QFont("Segoe UI", 6))
            painter.drawText(
                QRectF(rect.x() + 2, rect.y() + 22, rect.width() - 4, 18),
                Qt.AlignmentFlag.AlignCenter,
                subtitle,
            )

        painter.end()
