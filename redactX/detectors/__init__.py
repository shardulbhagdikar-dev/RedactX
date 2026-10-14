"""Detectors package for RedactX sensitive data discovery."""

from redactX.detectors.aadhaar import AadhaarDetector
from redactX.detectors.api_key import APIKeyDetector
from redactX.detectors.base import BaseDetector
from redactX.detectors.credit_card import CreditCardDetector
from redactX.detectors.email import EmailDetector
from redactX.detectors.ip_address import IPAddressDetector
from redactX.detectors.password import PasswordDetector
from redactX.detectors.phone import PhoneDetector
from redactX.detectors.registry import DetectorRegistry
from redactX.detectors.upi import UPIDetector

__all__ = [
    "BaseDetector",
    "DetectorRegistry",
    "EmailDetector",
    "PhoneDetector",
    "AadhaarDetector",
    "CreditCardDetector",
    "UPIDetector",
    "APIKeyDetector",
    "PasswordDetector",
    "IPAddressDetector",
]
