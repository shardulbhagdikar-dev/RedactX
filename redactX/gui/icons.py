"""Vector icon generators for RedactX GUI.

Uses QPainter to dynamically generate high-resolution, anti-aliased icons
matching the wireframes without external asset dependencies.
"""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap


class VectorIconFactory:
    """Creates crisp vector QIcons rendered at runtime."""

    @staticmethod
    def create_nav_icon(icon_type: str, color: str = "#9CA3AF", size: int = 32) -> QIcon:
        """Render a navigation bar icon."""
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pen = QPen(QColor(color))
        pen.setWidthF(2.0)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)

        w, h = float(size), float(size)
        pad = w * 0.2

        if icon_type == "plus":
            # Circle with plus
            cx, cy = w / 2.0, h / 2.0
            r = (w / 2.0) - pad
            painter.drawEllipse(QPointF(cx, cy), r, r)
            painter.drawLine(QPointF(cx, cy - r * 0.5), QPointF(cx, cy + r * 0.5))
            painter.drawLine(QPointF(cx - r * 0.5, cy), QPointF(cx + r * 0.5, cy))

        elif icon_type == "history":
            # Clock / counterclockwise arrow
            cx, cy = w / 2.0, h / 2.0
            r = (w / 2.0) - pad
            # Arc
            path = QPainterPath()
            path.arcMoveTo(QRectF(cx - r, cy - r, r * 2, r * 2), 45)
            path.arcTo(QRectF(cx - r, cy - r, r * 2, r * 2), 45, 270)
            painter.drawPath(path)
            # Clock hands
            painter.drawLine(QPointF(cx, cy), QPointF(cx, cy - r * 0.5))
            painter.drawLine(QPointF(cx, cy), QPointF(cx + r * 0.4, cy))

        elif icon_type == "dashboard":
            # Overlapping documents / sheets or bar chart
            r1 = QRectF(pad, pad + 4, w - pad * 2 - 4, h - pad * 2 - 4)
            painter.drawRoundedRect(r1, 3, 3)
            r2 = QRectF(pad + 4, pad, w - pad * 2 - 4, h - pad * 2 - 4)
            painter.drawRoundedRect(r2, 3, 3)

        elif icon_type == "settings":
            # Gear icon
            cx, cy = w / 2.0, h / 2.0
            r = (w / 2.0) - pad * 1.2
            painter.drawEllipse(QPointF(cx, cy), r * 0.45, r * 0.45)
            # Teeth
            import math
            for i in range(6):
                angle = i * (math.pi / 3)
                x1 = cx + (r * 0.7) * math.cos(angle)
                y1 = cy + (r * 0.7) * math.sin(angle)
                x2 = cx + r * math.cos(angle)
                y2 = cy + r * math.sin(angle)
                painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        painter.end()
        return QIcon(pixmap)

    @staticmethod
    def draw_file_outline(painter: QPainter, rect: QRectF, color: str = "#E5E7EB", stroke_width: float = 2.5):
        """Draw an outlined document icon with folded top-right corner."""
        painter.save()
        pen = QPen(QColor(color))
        pen.setWidthF(stroke_width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
        fold = w * 0.28

        path = QPainterPath()
        path.moveTo(x + fold, y)
        path.lineTo(x + w - fold, y)
        path.lineTo(x + w, y + fold)
        path.lineTo(x + w, y + h - fold)
        path.quadTo(x + w, y + h, x + w - fold, y + h)
        path.lineTo(x + fold, y + h)
        path.quadTo(x, y + h, x, y + h - fold)
        path.lineTo(x, y + fold)
        path.quadTo(x, y, x + fold, y)
        painter.drawPath(path)

        # Corner fold line
        fold_path = QPainterPath()
        fold_path.moveTo(x + w - fold, y)
        fold_path.lineTo(x + w - fold, y + fold)
        fold_path.lineTo(x + w, y + fold)
        painter.drawPath(fold_path)
        painter.restore()

    @staticmethod
    def draw_lock_file(painter: QPainter, rect: QRectF, color: str = "#E5E7EB", stroke_width: float = 2.5):
        """Draw a file container with a padlock inside matching wireframe 1."""
        painter.save()
        VectorIconFactory.draw_file_outline(painter, rect, color=color, stroke_width=stroke_width)

        # Padlock in center
        cx = rect.center().x()
        cy = rect.center().y()
        lock_w = rect.width() * 0.42
        lock_h = rect.height() * 0.35

        pen = QPen(QColor(color))
        pen.setWidthF(stroke_width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)

        # Shackle
        shackle_rect = QRectF(cx - lock_w * 0.32, cy - lock_h * 0.6, lock_w * 0.64, lock_h * 0.6)
        path = QPainterPath()
        path.arcMoveTo(shackle_rect, 0)
        path.arcTo(shackle_rect, 0, 180)
        painter.drawPath(path)

        # Body
        body_rect = QRectF(cx - lock_w * 0.5, cy - lock_h * 0.05, lock_w, lock_h * 0.7)
        painter.drawRoundedRect(body_rect, 4, 4)

        # Keyhole
        painter.drawPoint(QPointF(cx, cy + lock_h * 0.25))
        painter.restore()

    @staticmethod
    def draw_search_file(painter: QPainter, rect: QRectF, color: str = "#E5E7EB", stroke_width: float = 2.5):
        """Draw a file with magnifying glass matching wireframe 2."""
        painter.save()
        VectorIconFactory.draw_file_outline(painter, rect, color=color, stroke_width=stroke_width)

        # Magnifying glass in center-lower
        cx = rect.center().x() - 4
        cy = rect.center().y() + 4
        r = rect.width() * 0.2

        pen = QPen(QColor(color))
        pen.setWidthF(stroke_width)
        painter.setPen(pen)

        painter.drawEllipse(QPointF(cx, cy), r, r)
        painter.drawLine(
            QPointF(cx + r * 0.7, cy + r * 0.7),
            QPointF(cx + r * 1.5, cy + r * 1.5)
        )
        painter.restore()
