"""Fixed bottom navigation bar pill widget for RedactX GUI.

Implements the floating pill navbar with 4 view selector icons:
- [+] New Scan & Upload
- [🕒] Scan History
- [📊] Analytics Dashboard
- [⚙] Settings & Detectors
"""

from typing import Optional

from PySide6.QtCore import QSize, Signal
from PySide6.QtWidgets import QButtonGroup, QFrame, QHBoxLayout, QToolButton, QWidget

from redactX.gui.icons import VectorIconFactory
from redactX.gui.theme import COLOR_TEXT_PRIMARY, COLOR_TEXT_SECONDARY


class BottomNavBar(QFrame):
    """Pill-shaped bottom navigation container matching the wireframe design."""

    # Signal emitting selected tab index (0: Scan, 1: History, 2: Dashboard, 3: Settings)
    tab_changed = Signal(int)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("BottomNavPill")
        self.setFixedHeight(56)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(10)

        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        self.buttons: list[QToolButton] = []

        # Define 4 tabs
        tab_defs = [
            ("plus", "New Scan"),
            ("history", "Scan History"),
            ("dashboard", "Security Dashboard"),
            ("settings", "Settings & Detectors"),
        ]

        for idx, (icon_type, tooltip) in enumerate(tab_defs):
            btn = QToolButton(self)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setToolTip(tooltip)
            btn.setIcon(VectorIconFactory.create_nav_icon(icon_type, color=COLOR_TEXT_SECONDARY, size=24))
            btn.setIconSize(QSize(22, 22))

            # Store icon type for dynamic active color switching
            btn.setProperty("icon_type", icon_type)

            self.button_group.addButton(btn, idx)
            layout.addWidget(btn)
            self.buttons.append(btn)

        self.button_group.idClicked.connect(self._on_button_clicked)

        # Default select tab 0 (New Scan)
        if self.buttons:
            self.buttons[0].setChecked(True)
            self._update_icon_colors(0)

    def _on_button_clicked(self, tab_id: int) -> None:
        self._update_icon_colors(tab_id)
        self.tab_changed.emit(tab_id)

    def _update_icon_colors(self, active_id: int) -> None:
        for idx, btn in enumerate(self.buttons):
            icon_type = btn.property("icon_type")
            color = "#FFFFFF" if idx == active_id else COLOR_TEXT_SECONDARY
            btn.setIcon(VectorIconFactory.create_nav_icon(icon_type, color=color, size=24))

    def set_active_tab(self, tab_id: int) -> None:
        if 0 <= tab_id < len(self.buttons):
            self.buttons[tab_id].setChecked(True)
            self._update_icon_colors(tab_id)
