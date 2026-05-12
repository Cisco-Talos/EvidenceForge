# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Utility functions for generating log-specific identifiers."""

import random
import string

from evidenceforge.utils.rng import _get_rng, _stable_seed

# Base62 alphabet (used by Zeek for UIDs)
BASE62_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits
SYNTHETIC_MARKER_SUBSTRINGS = ("FAKE",)


def _has_synthetic_marker(value: str) -> bool:
    """Return whether an identifier contains an obvious synthetic marker."""
    upper_value = value.upper()
    return any(marker in upper_value for marker in SYNTHETIC_MARKER_SUBSTRINGS)


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
    uid = prefix + "".join(rng.choices(BASE62_CHARS, k=length - 1))
    while _has_synthetic_marker(uid):
        uid = prefix + "".join(rng.choices(BASE62_CHARS, k=length - 1))
    return uid


def generate_stable_zeek_uid(prefix: str, seed: str) -> str:
    """Generate a deterministic Zeek UID with the same shape as runtime UIDs."""
    if len(prefix) != 1:
        raise ValueError(f"Prefix must be a single character, got: {prefix}")

    rng = random.Random(_stable_seed(f"zeek_uid:{prefix}:{seed}"))
    length = rng.choices([17, 18, 19], weights=[10, 60, 30], k=1)[0]
    uid = prefix + "".join(rng.choices(BASE62_CHARS, k=length - 1))
    while _has_synthetic_marker(uid):
        uid = prefix + "".join(rng.choices(BASE62_CHARS, k=length - 1))
    return uid
