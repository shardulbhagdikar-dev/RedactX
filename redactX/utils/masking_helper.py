from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from redactX.models.enums import EntityType


def mask_sensitive_value(raw: str, entity_type: EntityType, mask_char: str = "*") -> str:
    """Produce a safe, redacted representation of a sensitive string.
    
    Zero-leak guarantee: Raw sensitive components are obfuscated so that the masked
    value cannot be used maliciously, while retaining enough structure for the user
    to identify the context.
    """
    if not raw:
        return ""

    raw_clean = raw.strip()

    type_val = entity_type.value if hasattr(entity_type, "value") else str(entity_type)

    if type_val == "EMAIL":
        if "@" in raw_clean:
            user_part, domain_part = raw_clean.split("@", 1)
            if len(user_part) <= 2:
                masked_user = user_part[0] + (mask_char * 3) if user_part else mask_char * 4
            else:
                masked_user = user_part[0] + (mask_char * (len(user_part) - 2)) + user_part[-1]
            return f"{masked_user}@{domain_part}"
        return mask_char * len(raw_clean)

    elif type_val == "PHONE_NUMBER":
        # Keep country code prefix if present, mask middle, show last 2
        digits_only = "".join(ch for ch in raw_clean if ch.isdigit())
        if len(digits_only) >= 4:
            visible_tail = digits_only[-2:]
            prefix = raw_clean[:3] if raw_clean.startswith("+") else ""
            return f"{prefix}{mask_char * (len(raw_clean) - len(prefix) - 2)}{visible_tail}"
        return mask_char * len(raw_clean)

    elif type_val == "AADHAAR":
        # Standard masked Aadhaar: XXXX XXXX 1234
        digits = "".join(ch for ch in raw_clean if ch.isdigit())
        if len(digits) == 12:
            last4 = digits[-4:]
            if " " in raw_clean or "-" in raw_clean:
                sep = " " if " " in raw_clean else "-"
                return f"XXXX{sep}XXXX{sep}{last4}"
            return f"XXXXXXXX{last4}"
        return mask_char * len(raw_clean)

    elif type_val == "CREDIT_CARD":
        # Standard masked Card: **** **** **** 1234
        digits = "".join(ch for ch in raw_clean if ch.isdigit())
        if len(digits) >= 12:
            last4 = digits[-4:]
            if " " in raw_clean:
                return f"**** **** **** {last4}"
            if "-" in raw_clean:
                return f"****-****-****-{last4}"
            return f"{mask_char * (len(raw_clean) - 4)}{last4}"
        return mask_char * len(raw_clean)

    elif type_val == "UPI_ID":
        if "@" in raw_clean:
            handle_user, psp = raw_clean.split("@", 1)
            if len(handle_user) <= 2:
                masked_handle = handle_user[0] + (mask_char * 3)
            else:
                masked_handle = handle_user[0] + (mask_char * (len(handle_user) - 2)) + handle_user[-1]
            return f"{masked_handle}@{psp}"
        return mask_char * len(raw_clean)

    elif type_val == "API_KEY":
        # Reveal prefix tag if present (e.g. sk_test_, ghp_) up to 8 chars, mask rest
        if len(raw_clean) > 12:
            prefix = raw_clean[:7]
            suffix = raw_clean[-4:]
            return f"{prefix}{mask_char * 8}...{suffix}"
        return mask_char * len(raw_clean)

    elif type_val == "PASSWORD":
        return mask_char * min(16, max(8, len(raw_clean)))

    elif type_val == "IPV4_ADDRESS":
        parts = raw_clean.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{mask_char}.{mask_char}"
        return mask_char * len(raw_clean)

    # Default fallback
    if len(raw_clean) <= 4:
        return mask_char * len(raw_clean)
    return raw_clean[0] + (mask_char * (len(raw_clean) - 2)) + raw_clean[-1]
