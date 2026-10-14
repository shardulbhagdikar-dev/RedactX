"""Validation Engine for deterministic and mathematical verification of sensitive candidates.

Implements:
- Luhn Algorithm (Mod 10) for Credit/Debit Cards
- Verhoeff Algorithm (Dihedral Group D5) for Indian Aadhaar Numbers
- Standard IPv4 Octet & Network Classification
- UPI Virtual Payment Address & PSP Structure Checks
- Indian Telecom Series & Dummy Sequence Filters
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from redactX.models.enums import EntityType
from redactX.models.finding import CandidateMatch

COMMON_UPI_HANDLES: set[str] = {
    "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ybl", "ibl",
    "axl", "apl", "upi", "barodampay", "federal", "airtel", "idfcbank",
    "kotak", "indus", "freecharge", "icici", "hdfcbank", "sbi", "axisbank",
    "postbank", "aubank", "jupiteraxis", "slice", "fam"
}

# --- Verhoeff Algorithm Tables (D5 Dihedral Group) ---
VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

# Known dummy phone numbers
DUMMY_PHONES = {
    "1234567890", "0123456789", "9876543210",
    "9999999999", "8888888888", "7777777777", "6666666666",
    "0000000000", "1111111111",
}


@dataclass(slots=True)
class ValidationResult:
    """Outcome of validating a candidate match."""

    is_valid: bool
    confidence_boost: float  # Value between -0.5 and +0.5 to adjust confidence
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


def validate_luhn(raw: str) -> tuple[bool, Optional[str], str]:
    """Validate credit/debit card number using the Luhn (Mod 10) algorithm."""
    digits = [int(c) for c in raw if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False, None, "Invalid digit count for payment card (must be 13-19 digits)"

    # Identify Card Brand
    digits_str = "".join(map(str, digits))
    brand = None
    if digits_str.startswith("4"):
        brand = "Visa"
    elif digits_str.startswith(("51", "52", "53", "54", "55")) or (
        len(digits_str) >= 4 and 2221 <= int(digits_str[:4]) <= 2720
    ):
        brand = "MasterCard"
    elif digits_str.startswith(("34", "37")):
        brand = "American Express"
    elif digits_str.startswith(("60", "65", "81", "82")):
        brand = "RuPay"
    elif digits_str.startswith("6011"):
        brand = "Discover"
    else:
        brand = "Payment Card"

    # Luhn checksum calculation
    total = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d

    is_valid = (total % 10 == 0)
    if is_valid:
        return True, brand, f"Passed Luhn checksum validation ({brand})"
    return False, brand, f"Failed Luhn checksum validation ({brand})"


def validate_verhoeff(raw: str) -> tuple[bool, str]:
    """Validate 12-digit Indian Aadhaar number using the Verhoeff D5 algorithm."""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) != 12:
        return False, f"Invalid Aadhaar length: expected 12 digits, got {len(digits)}"

    if digits[0] in "01":
        return False, "Invalid Aadhaar: cannot begin with 0 or 1 per UIDAI standard"

    # Verhoeff Checksum calculation
    check = 0
    for i, digit_char in enumerate(reversed(digits)):
        digit = int(digit_char)
        check = VERHOEFF_D[check][VERHOEFF_P[i % 8][digit]]

    if check == 0:
        return True, "Passed Verhoeff (D5 group) checksum validation"
    return False, "Failed Verhoeff checksum validation (invalid check digit)"


def validate_ipv4(raw: str) -> tuple[bool, str, dict[str, Any]]:
    """Validate IPv4 address and classify network routing category."""
    try:
        ip = ipaddress.IPv4Address(raw.strip())
    except (ipaddress.AddressValueError, ValueError):
        return False, "Malformed IPv4 address", {}

    ip_type = "public"
    if ip.is_loopback:
        ip_type = "loopback"
    elif ip.is_private:
        ip_type = "private (RFC 1918)"
    elif ip.is_link_local:
        ip_type = "link-local"
    elif ip.is_reserved or ip.is_unspecified:
        ip_type = "reserved"

    meta = {
        "ip_type": ip_type,
        "is_private": ip.is_private,
        "is_loopback": ip.is_loopback,
        "is_global": ip.is_global,
    }
    return True, f"Valid IPv4 address ({ip_type})", meta


def validate_upi(raw: str) -> tuple[bool, str, dict[str, Any]]:
    """Validate UPI VPA handle structure and recognized PSP bank suffixes."""
    if "@" not in raw:
        return False, "Missing @ separator in UPI VPA", {}

    user, psp = raw.strip().split("@", 1)
    if len(user) < 2:
        return False, "UPI handle username too short (< 2 characters)", {}

    psp_lower = psp.lower()
    if "." in psp_lower:
        return False, "PSP handle contains dot (likely an email domain)", {}

    is_known = psp_lower in COMMON_UPI_HANDLES
    meta = {"psp": psp_lower, "is_known_psp": is_known}

    if is_known:
        return True, f"Verified Indian UPI VPA with known PSP handle (@{psp_lower})", meta
    return True, f"Syntactically valid UPI VPA (@{psp_lower})", meta


def validate_indian_phone(raw: str) -> tuple[bool, str, dict[str, Any]]:
    """Validate 10-digit Indian mobile number against TRAI numbering series."""
    digits = "".join(ch for ch in raw if ch.isdigit())

    # Normalize: strip leading 91 or 0
    if len(digits) == 12 and digits.startswith("91"):
        normalized = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        normalized = digits[1:]
    elif len(digits) == 10:
        normalized = digits
    else:
        return False, f"Invalid mobile digit length ({len(digits)})", {}

    if normalized[0] not in "6789":
        return False, f"Indian mobile numbers must begin with 6, 7, 8, or 9 (got '{normalized[0]}')", {}

    is_dummy = normalized in DUMMY_PHONES
    meta = {"normalized_number": normalized, "is_dummy": is_dummy}

    if is_dummy:
        return False, f"Likely dummy/example mobile number '{normalized}'", meta

    return True, f"Valid Indian mobile number ({normalized[:5]}-{normalized[5:]})", meta


def validate_phone(raw: str) -> tuple[bool, str, dict[str, Any]]:
    """Validate candidate phone numbers supporting both Indian (TRAI) and International/NANP formats."""
    has_extension = bool(re.search(r"[xX]|ext", raw))
    digits = "".join(ch for ch in raw if ch.isdigit())

    # Check for Indian number indicators
    is_explicit_indian = "+91" in raw or raw.strip().startswith("91-") or raw.strip().startswith("91 ")
    is_plain_10_indian = len(digits) == 10 and digits[0] in "6789" and not has_extension and not raw.startswith("+") and not raw.startswith("00")
    is_trunk_indian = len(digits) == 11 and digits[0] == "0" and digits[1] in "6789" and not has_extension

    if is_explicit_indian or is_plain_10_indian or is_trunk_indian:
        is_valid_ind, reason_ind, meta_ind = validate_indian_phone(raw)
        if is_valid_ind or is_explicit_indian:
            meta_ind["format"] = "indian_mobile"
            return is_valid_ind, reason_ind, meta_ind

    # International / NANP validation
    base_raw = raw
    ext_part = ""
    if has_extension:
        parts = re.split(r"[xX]|ext\.?", raw, maxsplit=1)
        base_raw = parts[0]
        ext_part = parts[1].strip() if len(parts) > 1 else ""

    base_digits = "".join(ch for ch in base_raw if ch.isdigit())

    # Strip NANP country code prefixes (+1, 001, 1)
    if base_digits.startswith("001") and len(base_digits) == 13:
        base_digits = base_digits[3:]
    elif base_digits.startswith("1") and len(base_digits) == 11:
        base_digits = base_digits[1:]

    if len(base_digits) < 7:
        return False, f"Phone number too short ({len(base_digits)} base digits)", {}
    if len(base_digits) > 15:
        return False, f"Phone number exceeds ITU-T E.164 maximum ({len(base_digits)} digits)", {}

    if len(set(base_digits)) < 3 or base_digits in DUMMY_PHONES:
        return False, "Phone number has insufficient digit variance or is a dummy number", {}

    meta = {
        "raw": raw,
        "base_digits": base_digits,
        "extension": ext_part or None,
        "format": "international_nanp",
    }

    if len(base_digits) == 10:
        area_code = base_digits[:3]
        exchange = base_digits[3:6]
        subscriber = base_digits[6:]
        formatted = f"({area_code}) {exchange}-{subscriber}"
        if ext_part:
            formatted += f" ext. {ext_part}"
        return True, f"Valid 10-digit phone number {formatted}", meta

    return True, f"Valid International phone number ({base_digits})", meta


def validate_api_key(raw: str) -> tuple[bool, str]:
    """Validate candidate API key / token length and character variance."""
    cleaned = raw.strip("'\"")
    if len(cleaned) < 16:
        return False, f"API key too short ({len(cleaned)} chars, minimum 16 required)"

    # Reject all digits or all same characters
    if cleaned.isdigit():
        return False, "API key cannot consist solely of digits"
    if len(set(cleaned)) < 4:
        return False, "API key has insufficient character variance"

    return True, "Valid API key / token candidate structure"


def validate_password(raw: str) -> tuple[bool, str]:
    """Validate candidate password length and non-triviality."""
    cleaned = raw.strip("'\"")
    if len(cleaned) < 6:
        return False, f"Password too short ({len(cleaned)} chars, minimum 6 required)"
    if len(set(cleaned)) < 3:
        return False, "Password has insufficient character variance"

    return True, "Valid credential/password candidate structure"


def validate_email(raw: str) -> tuple[bool, str]:
    """Validate email address syntax and domain extension."""
    if "@" not in raw or "." not in raw.split("@")[-1]:
        return False, "Invalid email format"
    domain = raw.split("@")[-1]
    tld = domain.split(".")[-1]
    if len(tld) < 2:
        return False, "Email top-level domain must be at least 2 characters"
    return True, f"Valid email address format (domain: {domain})"


class ValidationEngine:
    """Orchestrates candidate validation and applies confidence boosts."""

    @classmethod
    def validate(cls, candidate: CandidateMatch) -> ValidationResult:
        entity = candidate.entity_type
        raw = candidate.raw_value

        if entity == EntityType.CREDIT_CARD:
            is_valid, brand, reason = validate_luhn(raw)
            boost = 0.4 if is_valid else -0.4
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
                metadata={"brand": brand},
            )

        elif entity == EntityType.AADHAAR:
            is_valid, reason = validate_verhoeff(raw)
            boost = 0.4 if is_valid else -0.4
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
            )

        elif entity == EntityType.IPV4_ADDRESS:
            is_valid, reason, meta = validate_ipv4(raw)
            boost = 0.2 if is_valid else -0.3
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
                metadata=meta,
            )

        elif entity == EntityType.UPI_ID:
            is_valid, reason, meta = validate_upi(raw)
            boost = 0.3 if meta.get("is_known_psp") else 0.1
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost if is_valid else -0.3,
                reason=reason,
                metadata=meta,
            )

        elif entity == EntityType.PHONE_NUMBER:
            is_valid, reason, meta = validate_phone(raw)
            boost = 0.2 if is_valid else -0.3
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
                metadata=meta,
            )

        elif entity == EntityType.API_KEY:
            is_valid, reason = validate_api_key(raw)
            boost = 0.3 if is_valid else -0.2
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
            )

        elif entity == EntityType.PASSWORD:
            is_valid, reason = validate_password(raw)
            boost = 0.2 if is_valid else -0.2
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
            )

        elif entity == EntityType.EMAIL:
            is_valid, reason = validate_email(raw)
            boost = 0.2 if is_valid else -0.3
            return ValidationResult(
                is_valid=is_valid,
                confidence_boost=boost,
                reason=reason,
            )

        # Fallback for unexpected entity types
        return ValidationResult(
            is_valid=True,
            confidence_boost=0.0,
            reason="No specialized validator available for entity type",
        )

    @classmethod
    def validate_all(
        cls, candidates: list[CandidateMatch]
    ) -> list[tuple[CandidateMatch, ValidationResult]]:
        """Validate a list of candidates and return candidate-result pairs."""
        return [(c, cls.validate(c)) for c in candidates]
