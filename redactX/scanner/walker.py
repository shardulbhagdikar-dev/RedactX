"""Directory Walker for discovering supported target files in RedactX.

Performs recursive filesystem traversal with automatic exclusion of hidden,
virtual environment, cache, and system directories.
"""

import os
from pathlib import Path
from typing import Optional, Union

from redactX.utils.logger import get_logger

logger = get_logger("scanner.walker")

SUPPORTED_EXTENSIONS: set[str] = {".txt", ".csv", ".json"}

DEFAULT_EXCLUDED_DIRS: set[str] = {
    ".git", ".svn", ".hg", ".venv", "venv", "env",
    "__pycache__", ".idea", ".vscode", "node_modules",
    "dist", "build", ".pytest_cache", ".tox"
}


class DirectoryWalker:
    """Discovers supported files for scanning across paths and directories."""

    def __init__(
        self,
        supported_extensions: Optional[set[str]] = None,
        excluded_directories: Optional[set[str]] = None,
    ):
        self.extensions = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in (supported_extensions or SUPPORTED_EXTENSIONS)
        }
        self.excluded_dirs = {
            d.lower() for d in (excluded_directories or DEFAULT_EXCLUDED_DIRS)
        }

    def find_files(
        self,
        target_path: Union[str, Path],
        recursive: bool = True,
    ) -> list[Path]:
        """Discover all supported files under target path.
        
        Args:
            target_path: File or directory path to inspect.
            recursive: If True, recursively traverse subdirectories.
        """
        path = Path(target_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Target path does not exist: {path}")

        # Single file case
        if path.is_file():
            if path.suffix.lower() in self.extensions:
                return [path]
            return []

        # Directory traversal
        discovered: list[Path] = []

        if not recursive:
            try:
                for entry in path.iterdir():
                    if entry.is_file() and entry.suffix.lower() in self.extensions:
                        discovered.append(entry)
            except (PermissionError, OSError) as exc:
                logger.warning("Permission denied accessing %s: %s", path, exc)
            return sorted(discovered)

        # Recursive walk with os.walk to allow directory pruning
        for root_str, dirnames, filenames in os.walk(str(path), followlinks=False):
            # In-place directory pruning to avoid traversing excluded/hidden trees
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in self.excluded_dirs and not d.startswith(".")
            ]

            root_path = Path(root_str)
            for fname in filenames:
                file_path = root_path / fname
                if file_path.suffix.lower() in self.extensions:
                    discovered.append(file_path)

        return sorted(discovered)

    def count_supported_files(self, target_path: Union[str, Path], recursive: bool = True) -> int:
        """Count the number of supported files without retaining all Path objects."""
        return len(self.find_files(target_path, recursive=recursive))
