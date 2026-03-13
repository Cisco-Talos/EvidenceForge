"""Utility functions for generating log-specific identifiers."""

import random
import string


# Base62 alphabet (used by Zeek for UIDs)
BASE62_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits


def generate_zeek_uid(prefix: str = "C") -> str:
    """Generate a realistic Zeek UID.

    Zeek UIDs are 18-character base62-encoded identifiers that appear in various
    Zeek logs to correlate events. Different log types use different prefixes:
    - 'C' for conn.log
    - 'D' for dns.log
    - 'F' for files.log
    - 'H' for http.log
    etc.

    Args:
        prefix: Single character prefix (default: 'C' for conn.log)

    Returns:
        An 18-character Zeek UID string (e.g., "C1ck9l41y7i2i3gGo2")

    Example:
        >>> uid = generate_zeek_uid()
        >>> len(uid)
        18
        >>> uid[0]
        'C'
        >>> uid = generate_zeek_uid("D")
        >>> uid[0]
        'D'
    """
    if len(prefix) != 1:
        raise ValueError(f"Prefix must be a single character, got: {prefix}")

    # Generate 17 random base62 characters after the prefix (18 total)
    random_chars = "".join(random.choices(BASE62_CHARS, k=17))

    return prefix + random_chars
