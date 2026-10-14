"""Detector Registry for managing and orchestrating sensitive data detectors."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Union

from redactX.detectors.aadhaar import AadhaarDetector
from redactX.detectors.api_key import APIKeyDetector
from redactX.detectors.base import BaseDetector
from redactX.detectors.credit_card import CreditCardDetector
from redactX.detectors.email import EmailDetector
from redactX.detectors.ip_address import IPAddressDetector
from redactX.detectors.password import PasswordDetector
from redactX.detectors.phone import PhoneDetector
from redactX.detectors.upi import UPIDetector
from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

if TYPE_CHECKING:
    from redactX.scanner.file_parser import ParsedContent


class DetectorRegistry:
    """Central registry and execution coordinator for sensitive data detectors."""

    def __init__(self, load_defaults: bool = True):
        self._detectors: dict[str, BaseDetector] = {}
        if load_defaults:
            self._load_default_detectors()

    def _load_default_detectors(self) -> None:
        defaults: list[BaseDetector] = [
            EmailDetector(),
            PhoneDetector(),
            AadhaarDetector(),
            CreditCardDetector(),
            UPIDetector(),
            APIKeyDetector(),
            PasswordDetector(),
            IPAddressDetector(),
        ]
        for detector in defaults:
            self.register(detector)

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance in the registry."""
        self._detectors[detector.name] = detector

    def unregister(self, identifier: Union[str, EntityType]) -> Optional[BaseDetector]:
        """Remove a detector by name or entity type."""
        for name, det in list(self._detectors.items()):
            if name == identifier or det.entity_type == identifier:
                return self._detectors.pop(name)
        return None

    def get_detector(self, identifier: Union[str, EntityType]) -> Optional[BaseDetector]:
        """Look up a detector by name or entity type."""
        for name, det in self._detectors.items():
            if name == identifier or det.entity_type == identifier:
                return det
        return None

    def enable_detector(self, identifier: Union[str, EntityType]) -> bool:
        det = self.get_detector(identifier)
        if det:
            det.enabled = True
            return True
        return False

    def disable_detector(self, identifier: Union[str, EntityType]) -> bool:
        det = self.get_detector(identifier)
        if det:
            det.enabled = False
            return True
        return False

    def list_detectors(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def detect_all(self, target: Union[ParsedContent, str]) -> list[CandidateMatch]:
        """Run all enabled detectors and resolve overlapping candidate spans."""
        all_candidates: list[CandidateMatch] = []

        for detector in self._detectors.values():
            if detector.enabled:
                matches = detector.detect(target)
                all_candidates.extend(matches)

        if not all_candidates:
            return []

        # Sort candidates primarily by start index, then by length descending
        all_candidates.sort(key=lambda c: (c.start_idx, -c.length))

        # Deduplicate and resolve overlapping spans
        return self._resolve_overlapping_spans(all_candidates)

    @staticmethod
    def _resolve_overlapping_spans(candidates: list[CandidateMatch]) -> list[CandidateMatch]:
        """Resolve overlapping spans, prioritizing higher severity entities."""
        resolved: list[CandidateMatch] = []

        for cand in candidates:
            if not resolved:
                resolved.append(cand)
                continue

            last = resolved[-1]
            # Check for overlap: last.start_idx < cand.end_idx and cand.start_idx < last.end_idx
            if cand.start_idx < last.end_idx:
                # Conflict detected: pick higher severity, or longer span if severities match
                last_sev = last.entity_type.default_severity
                cand_sev = cand.entity_type.default_severity

                if cand_sev > last_sev or (cand_sev == last_sev and cand.length > last.length):
                    # Replace last with higher-priority candidate
                    resolved[-1] = cand
                # Else: keep `last`, drop `cand`
            else:
                resolved.append(cand)

        return resolved
