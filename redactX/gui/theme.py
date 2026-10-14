"""Theme, styling, and design system constants for RedactX GUI.

Implements a modern, deep charcoal/obsidian dark aesthetic matching the wireframes:
- Fixed bottom pill navbar
- Dashed upload dropzone with accent red highlights
- Blurred/inactive and glowing/active 'Create RedactX' button states
- High-contrast severity colors
"""

# Color Palette Constants
COLOR_BG_DARK = "#101114"          # Deep obsidian background
COLOR_SURFACE = "#17181F"          # Elevated card surface
COLOR_SURFACE_LIGHT = "#21232D"    # Secondary container surface
COLOR_BORDER = "#2B2D3A"           # Subdued border
COLOR_BORDER_LIGHT = "#3E4154"     # Card border / hover border
COLOR_BORDER_DASHED = "#52566D"    # Upload dropzone dashed border

# Text Colors
COLOR_TEXT_PRIMARY = "#F3F4F6"
COLOR_TEXT_SECONDARY = "#9CA3AF"
COLOR_TEXT_MUTED = "#6B7280"

# Accent Colors
COLOR_ACCENT_RED = "#EF4444"       # Vibrant security red (arrow & critical alerts)
COLOR_ACCENT_CORAL = "#F87171"
COLOR_ACCENT_CYAN = "#06B6D4"      # Secondary electric accent
COLOR_ACCENT_BLUE = "#3B82F6"      # Primary interactive accent
COLOR_ACCENT_GREEN = "#10B981"     # Success & clean badge

# Severity Color Map
SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#FBBF24",
    "LOW": "#38BDF8",
    "CLEAN": "#10B981",
}

# Master Dark Stylesheet (QSS)
DARK_THEME_QSS = f"""
QMainWindow {{
    background-color: {COLOR_BG_DARK};
}}

QWidget#CentralContainer {{
    background-color: {COLOR_BG_DARK};
}}

/* Typography */
QLabel {{
    color: {COLOR_TEXT_PRIMARY};
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "Roboto", sans-serif;
}}

QLabel#AppTitle {{
    font-size: 26px;
    font-weight: 700;
    color: {COLOR_TEXT_PRIMARY};
    letter-spacing: -0.5px;
}}

QLabel#SectionTitle {{
    font-size: 18px;
    font-weight: 600;
    color: {COLOR_TEXT_PRIMARY};
    margin-bottom: 8px;
}}

QLabel#MutedLabel {{
    color: {COLOR_TEXT_SECONDARY};
    font-size: 13px;
}}

/* Card Container */
QFrame#CardFrame {{
    background-color: {COLOR_SURFACE};
    border: 1px solid {COLOR_BORDER};
    border-radius: 12px;
}}

QFrame#InnerCardFrame {{
    background-color: {COLOR_SURFACE_LIGHT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 10px;
}}

/* Upload Hero Dropzone */
QFrame#DropzoneFrame {{
    background-color: transparent;
    border: none;
}}

QFrame#DropzoneFrame:hover {{
    background-color: transparent;
    border: none;
}}

/* Fixed Bottom Pill Navbar */
QFrame#BottomNavPill {{
    background-color: {COLOR_SURFACE};
    border: 1px solid {COLOR_BORDER_LIGHT};
    border-radius: 24px;
    padding: 4px 8px;
}}

QToolButton#NavButton {{
    background: transparent;
    border: none;
    border-radius: 18px;
    padding: 8px 16px;
    color: {COLOR_TEXT_SECONDARY};
    font-size: 16px;
}}

QToolButton#NavButton:hover {{
    background-color: rgba(255, 255, 255, 0.08);
    color: {COLOR_TEXT_PRIMARY};
}}

QToolButton#NavButton:checked {{
    background-color: rgba(239, 68, 68, 0.18);
    color: #FFFFFF;
    border: 1px solid rgba(239, 68, 68, 0.4);
}}

/* 'Create RedactX' Action Button */
QPushButton#CreateRedactXButton {{
    font-family: "Segoe UI", sans-serif;
    font-size: 15px;
    font-weight: 600;
    border-radius: 22px;
    padding: 10px 28px;
    border: none;
}}

/* State: BLURRED / DISABLED */
QPushButton#CreateRedactXButton:disabled {{
    background-color: #1A1C24;
    color: #4B5563;
    border: 1px solid #2B2D3A;
}}

/* State: ALIVE / READY TO REDACT */
QPushButton#CreateRedactXButton:enabled {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #EF4444, stop:1 #F97316);
    color: #FFFFFF;
    border: 1px solid #F87171;
}}

QPushButton#CreateRedactXButton:enabled:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #F87171, stop:1 #FB923C);
}}

QPushButton#CreateRedactXButton:enabled:pressed {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #DC2626, stop:1 #EA580C);
}}

/* Standard Push Buttons */
QPushButton.SecondaryButton {{
    background-color: {COLOR_SURFACE_LIGHT};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 500;
}}

QPushButton.SecondaryButton:hover {{
    background-color: #2D303E;
    border-color: {COLOR_BORDER_LIGHT};
}}

QPushButton.DangerButton {{
    background-color: rgba(239, 68, 68, 0.15);
    color: #F87171;
    border: 1px solid rgba(239, 68, 68, 0.4);
    border-radius: 8px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 500;
}}

QPushButton.DangerButton:hover {{
    background-color: rgba(239, 68, 68, 0.28);
}}

/* Progress Bar */
QProgressBar {{
    background-color: {COLOR_SURFACE_LIGHT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    text-align: center;
    color: {COLOR_TEXT_PRIMARY};
    font-size: 12px;
    font-weight: 600;
    height: 18px;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #EF4444, stop:1 #F97316);
    border-radius: 7px;
}}

/* Tables */
QTableWidget, QTableView {{
    background-color: {COLOR_SURFACE};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    gridline-color: {COLOR_BORDER};
    color: {COLOR_TEXT_PRIMARY};
    selection-background-color: rgba(239, 68, 68, 0.2);
    selection-color: #FFFFFF;
    font-size: 13px;
}}

QHeaderView::section {{
    background-color: {COLOR_SURFACE_LIGHT};
    color: {COLOR_TEXT_SECONDARY};
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid {COLOR_BORDER};
    font-weight: 600;
    font-size: 12px;
}}

QTableWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid #1F212A;
}}

/* Scrollbar */
QScrollBar:vertical {{
    background: {COLOR_SURFACE};
    width: 10px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background: {COLOR_BORDER_LIGHT};
    min-height: 20px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: #5A5E7A;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* Checkboxes */
QCheckBox {{
    color: {COLOR_TEXT_PRIMARY};
    font-size: 13px;
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid {COLOR_BORDER_LIGHT};
    background-color: {COLOR_SURFACE_LIGHT};
}}

QCheckBox::indicator:checked {{
    background-color: {COLOR_ACCENT_RED};
    border-color: {COLOR_ACCENT_RED};
}}

/* ComboBox */
QComboBox {{
    background-color: {COLOR_SURFACE_LIGHT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 6px 12px;
    color: {COLOR_TEXT_PRIMARY};
    font-size: 13px;
}}

QComboBox::drop-down {{
    border: none;
}}

QComboBox QAbstractItemView {{
    background-color: {COLOR_SURFACE};
    border: 1px solid {COLOR_BORDER};
    selection-background-color: {COLOR_ACCENT_RED};
    color: {COLOR_TEXT_PRIMARY};
}}
"""
