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

"""Thread-safe deterministic random number generation.

Provides a thread-local RNG that ensures each thread gets its own
Random instance, avoiding GIL contention on shared state.
"""

import hashlib
import random
from threading import local

_thread_local = local()


def _get_rng() -> random.Random:
    """Get thread-local Random instance.

    Each thread gets its own RNG instance. Instances are seeded with 42
    for the simplicity; thread-local storage ensures no cross-thread
    interference.

    Returns:
        Thread-local Random instance
    """
    if not hasattr(_thread_local, "rng"):
        _thread_local.rng = random.Random(42)
    return _thread_local.rng


def _stable_seed(key: str) -> int:
    """Create a deterministic integer seed from a string.

    Uses SHA-256 instead of hash() to avoid PYTHONHASHSEED randomization.
    Produces the same seed across processes and Python invocations.
    """
    return int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)
