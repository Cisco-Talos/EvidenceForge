"""Utility functions for generating log-specific identifiers."""

import string

from evidenceforge.utils.rng import _get_rng

# Base62 alphabet (used by Zeek for UIDs)
BASE62_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits


def generate_zeek_uid(prefix: str = "C") -> str:
    """Generate a realistic Zeek UID.

    Zeek UIDs are base62-encoded identifiers that appear in various Zeek logs
    to correlate events. Real Zeek encodes two uint32 values in base62,
    producing variable-length strings (typically 17-19 chars total).
    Different log types use different prefixes:
    - 'C' for conn.log (also shared by dns.log, http.log, ssl.log, etc.)
    - 'F' for files.log
    etc.

    Args:
        prefix: Single character prefix (default: 'C' for conn.log)

    Returns:
        A Zeek UID string of 17-19 characters (e.g., "C1ck9l41y7i2i3gGo2")

    Example:
        >>> uid = generate_zeek_uid()
        >>> 17 <= len(uid) <= 19
        True
        >>> uid[0]
        'C'
    """
    if len(prefix) != 1:
        raise ValueError(f"Prefix must be a single character, got: {prefix}")

    # Real Zeek UIDs vary in length (17-19 chars total including prefix).
    # Weight distribution based on observed real Zeek traffic.
    rng = _get_rng()
    length = rng.choices([17, 18, 19], weights=[10, 60, 30], k=1)[0]
    random_chars = "".join(rng.choices(BASE62_CHARS, k=length - 1))

    return prefix + random_chars
