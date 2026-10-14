"""Settings and Detector Configuration View for RedactX GUI."""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from redactX.detectors.registry import DetectorRegistry
from redactX.redaction.redactor import MaskingStrategy


class SettingsView(QWidget):
    """Settings view for configuring active detectors and redaction strategies."""

    def __init__(self, registry: Optional[DetectorRegistry] = None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.registry = registry or DetectorRegistry()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(14)

        # Outer Container
        card = QFrame(self)
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 20, 24, 20)
        card_layout.setSpacing(16)

        # Title
        lbl_title = QLabel("Settings & Detection Policies", card)
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 600; color: #FFFFFF;")
        card_layout.addWidget(lbl_title)

        # 1. Detector Toggles Section
        lbl_detectors = QLabel("Active Sensitive Information Detectors", card)
        lbl_detectors.setStyleSheet("font-size: 14px; font-weight: 600; color: #E5E7EB; margin-top: 8px;")
        card_layout.addWidget(lbl_detectors)

        grid = QGridLayout()
        grid.setSpacing(12)

        self.checkboxes: dict[str, QCheckBox] = {}
        detector_items = [
            ("AadhaarDetector", "Indian Aadhaar ID (Verhoeff checksum)"),
            ("PhoneDetector", "Phone Numbers (Indian & International)"),
            ("UPIDetector", "UPI Virtual Payment Addresses"),
            ("CreditCardDetector", "Credit / Debit Cards (Luhn Mod-10)"),
            ("APIKeyDetector", "API Keys & Tokens (Entropy Engine)"),
            ("PasswordDetector", "Hardcoded Passwords & Credentials"),
            ("IPAddressDetector", "IPv4 Network Addresses"),
            ("EmailDetector", "Email Addresses (RFC-5322)"),
        ]

        for idx, (det_name, display_label) in enumerate(detector_items):
            cb = QCheckBox(display_label, card)
            det = self.registry.get_detector(det_name)
            cb.setChecked(det.enabled if det else True)
            cb.toggled.connect(lambda checked, name=det_name: self._toggle_detector(name, checked))
            row = idx // 2
            col = idx % 2
            grid.addWidget(cb, row, col)
            self.checkboxes[det_name] = cb

        card_layout.addLayout(grid)

        # Separator line
        sep = QFrame(card)
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #2B2D3A;")
        card_layout.addWidget(sep)

        # 2. Redaction Strategy Selector
        lbl_strategy = QLabel("Default Redaction Masking Strategy", card)
        lbl_strategy.setStyleSheet("font-size: 14px; font-weight: 600; color: #E5E7EB;")
        card_layout.addWidget(lbl_strategy)

        strat_row = QHBoxLayout()
        strat_row.setSpacing(12)

        self.combo_strategy = QComboBox(card)
        self.combo_strategy.addItem("PARTIAL — Mask center digits (e.g. 98******10, u***@site.com)", MaskingStrategy.PARTIAL)
        self.combo_strategy.addItem("FULL — Replace with token (e.g. [REDACTED_AADHAAR])", MaskingStrategy.FULL)
        self.combo_strategy.addItem("SYNTACTIC — Mask digits preserving separators (e.g. ****-****-****-1234)", MaskingStrategy.SYNTACTIC)
        self.combo_strategy.addItem("HASH — Keyed cryptographic SHA-256 hash", MaskingStrategy.HASH)
        self.combo_strategy.setFixedWidth(520)
        strat_row.addWidget(self.combo_strategy)
        strat_row.addStretch()

        card_layout.addLayout(strat_row)
        card_layout.addStretch()

        layout.addWidget(card)

    def _toggle_detector(self, name: str, enabled: bool) -> None:
        det = self.registry.get_detector(name)
        if det:
            det.enabled = enabled

    def get_selected_strategy(self) -> MaskingStrategy:
        return self.combo_strategy.currentData()
