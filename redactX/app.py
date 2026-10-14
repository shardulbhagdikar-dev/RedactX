"""Application Entrypoint for RedactX.

Launches the native PySide6 desktop interface with high-DPI scaling and dark theme.
"""

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from redactX.gui.main_window import MainWindow
from redactX.utils.logger import get_logger

logger = get_logger("app")


def main() -> int:
    """Launch RedactX Desktop Application."""
    # Ensure correct application-level DPI attributes
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("RedactX")
    app.setOrganizationName("RedactX")

    window = MainWindow()
    window.show()

    logger.info("RedactX Desktop GUI launched successfully.")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
