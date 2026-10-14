"""Storage and persistence package for RedactX scan history."""

from redactX.storage.history import HistoryDatabase, get_default_db_path

__all__ = ["HistoryDatabase", "get_default_db_path"]
