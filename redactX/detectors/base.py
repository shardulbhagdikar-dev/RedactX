from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Union

from redactX.models.enums import EntityType, Severity
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent


class BaseDetector(ABC):
    """Abstract base class that all sensitive data detectors must implement."""

    def __init__(self, name: str, entity_type: EntityType, enabled: bool = True):
        self.name = name
        self.entity_type = entity_type
        self.enabled = enabled

    @property
    def default_severity(self) -> Severity:
        return self.entity_type.default_severity

    @abstractmethod
    def detect(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        """Discover candidate sensitive spans in the provided text or ParsedContent."""
        pass

    def _get_target_text_and_coords(
        self, target: Union[ParsedContent, str]
    ) -> tuple[str, Optional[ParsedContent]]:
        """Utility to normalize input target and extract text."""
        if hasattr(target, "raw_text"):
            return target.raw_text, target
        return str(target), None

    def _create_candidate(
        self,
        raw_value: str,
        start_idx: int,
        end_idx: int,
        parsed_content: Optional[ParsedContent] = None,
        metadata: Optional[dict] = None,
    ) -> CandidateMatch:
        """Create a CandidateMatch with line and column coordinates."""
        meta = dict(metadata or {})
        if parsed_content is not None:
            line_num, col_num = parsed_content.get_coordinates(start_idx)
            if hasattr(parsed_content, "get_cell_for_coordinate"):
                cell = parsed_content.get_cell_for_coordinate(line_num, raw_value)
                if cell and cell.header:
                    meta["header"] = cell.header
            elif hasattr(parsed_content, "find_fields_containing"):
                fields = parsed_content.find_fields_containing(raw_value)
                if fields:
                    meta["path"] = fields[0].path
        else:
            line_num = 1
            col_num = start_idx + 1

        return CandidateMatch(
            entity_type=self.entity_type,
            raw_value=raw_value,
            start_idx=start_idx,
            end_idx=end_idx,
            line_number=line_num,
            column_number=col_num,
            metadata=meta,
        )
