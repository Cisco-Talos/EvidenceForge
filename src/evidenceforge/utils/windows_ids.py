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

"""Helpers for source-native Windows process and thread identifiers."""

import random
from typing import Any


def align_windows_id(value: int) -> int:
    """Return a Windows-native PID/TID-style value aligned to a 4-byte boundary."""
    if value <= 0:
        return value
    return ((value + 3) // 4) * 4


_WINDOWS_ID_MAX = 0xFFFFFFFF
_WINDOWS_ID_MAX_DIGITS = len(str(_WINDOWS_ID_MAX))


def normalize_windows_id_value(value: Any) -> Any:
    """Safely align an int or bounded decimal-string Windows PID/TID value.

    Raw scenario events may supply provider Execution PID/TID fields as arbitrary
    strings. Only convert decimal strings that fit in the Windows 32-bit ID range;
    leave oversized values untouched so malformed raw input cannot abort rendering.
    """
    if isinstance(value, int):
        return align_windows_id(value)
    if not isinstance(value, str) or not value.isdecimal():
        return value
    if len(value) > _WINDOWS_ID_MAX_DIGITS:
        return value
    parsed = int(value)
    aligned = align_windows_id(parsed)
    if aligned > _WINDOWS_ID_MAX:
        return value
    return str(aligned)


def windows_id_randint(rng: random.Random, minimum: int, maximum: int) -> int:
    """Return a random aligned Windows PID/TID-style integer within the range."""
    if minimum > maximum:
        raise ValueError("minimum must be less than or equal to maximum")
    aligned_minimum = align_windows_id(minimum)
    aligned_maximum = maximum - (maximum % 4)
    if aligned_minimum > aligned_maximum:
        return align_windows_id(minimum)
    return rng.randrange(aligned_minimum, aligned_maximum + 1, 4)
