"""Enumerations for RedactX domain models."""

from enum import Enum


class Severity(Enum):
    """Severity classification for sensitive data findings."""

    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparisons."""
        _ranks = {
            "CLEAN": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return _ranks[self.value]

    @property
    def weight(self) -> float:
        """Weight factor used in risk scoring calculations."""
        _weights = {
            "CLEAN": 0.0,
            "LOW": 1.0,
            "MEDIUM": 3.0,
            "HIGH": 6.0,
            "CRITICAL": 10.0,
        }
        return _weights[self.value]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank == other.rank
        if isinstance(other, str):
            return self.value == other
        return False

    def __hash__(self) -> int:
        return hash(self.value)


class Confidence(Enum):
    """Confidence level assigned to a finding after validation & analysis."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def __str__(self) -> str:
        return self.value

    @property
    def rank(self) -> int:
        _ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        return _ranks[self.value]

    @property
    def score_multiplier(self) -> float:
        _mults = {"LOW": 0.4, "MEDIUM": 0.75, "HIGH": 1.0}
        return _mults[self.value]

    # Dunder method to implement 
    def __lt__(self, other: object) -> bool:
        if isinstance(other, Confidence):
            return self.rank < other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Confidence):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Confidence):
            return self.rank <= other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Confidence):
            return self.rank >= other.rank
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Confidence):
            return self.rank == other.rank
        if isinstance(other, str):
            return self.value == other
        return False

    def __hash__(self) -> int:
        return hash(self.value)

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        """Map a normalized 0.0 - 1.0 score to a Confidence level."""
        if score >= 0.8:
            return cls.HIGH
        if score >= 0.5:
            return cls.MEDIUM
        return cls.LOW


class EntityType(str, Enum):
    """Supported sensitive data entity categories."""

    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    AADHAAR = "AADHAAR"
    CREDIT_CARD = "CREDIT_CARD"
    UPI_ID = "UPI_ID"
    API_KEY = "API_KEY"
    PASSWORD = "PASSWORD"
    IPV4_ADDRESS = "IPV4_ADDRESS"

    @property
    def default_severity(self) -> Severity:
        """Default baseline severity mapping as specified in the RedactX policy."""
        _mapping = {
            EntityType.EMAIL: Severity.LOW,
            EntityType.IPV4_ADDRESS: Severity.LOW,
            EntityType.PHONE_NUMBER: Severity.MEDIUM,
            EntityType.UPI_ID: Severity.HIGH,
            EntityType.AADHAAR: Severity.CRITICAL,
            EntityType.CREDIT_CARD: Severity.CRITICAL,
            EntityType.API_KEY: Severity.CRITICAL,
            EntityType.PASSWORD: Severity.CRITICAL,
        }
        return _mapping[self]

    @property
    def display_name(self) -> str:
        """Human-readable display title."""
        _names = {
            EntityType.EMAIL: "Email Address",
            EntityType.PHONE_NUMBER: "Phone Number",
            EntityType.AADHAAR: "Aadhaar Number",
            EntityType.CREDIT_CARD: "Credit/Debit Card",
            EntityType.UPI_ID: "UPI ID / VPA",
            EntityType.API_KEY: "API Key / Token",
            EntityType.PASSWORD: "Password / Secret",
            EntityType.IPV4_ADDRESS: "IPv4 Address",
        }
        return _names[self]


class FileFormat(str, Enum):
    """Supported file formats for parsing and redaction."""

    TXT = "txt"
    CSV = "csv"
    JSON = "json"

    @classmethod
    def from_extension(cls, ext: str) -> "FileFormat":
        normalized = ext.lower().lstrip(".")
        for fmt in cls:
            if fmt.value == normalized:
                return fmt
        raise ValueError(f"Unsupported file extension: '{ext}'")


class ScanStatus(str, Enum):
    """Status of an individual file or entire scan operation."""

    PENDING = "PENDING"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class MaskingStrategy(str, Enum):
    """Supported redaction masking strategies."""

    PARTIAL = "PARTIAL"
    FULL = "FULL"
    SYNTACTIC = "SYNTACTIC"
    HASH = "HASH"
