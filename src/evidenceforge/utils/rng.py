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
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import local

_thread_local = local()
DEFAULT_GENERATION_SEED = 42
MAX_GENERATION_SEED = 2**64 - 1
_generation_seed: ContextVar[int] = ContextVar(
    "evidenceforge_generation_seed",
    default=DEFAULT_GENERATION_SEED,
)


def current_generation_seed() -> int:
    """Return the immutable seed namespace active in the current execution context."""

    return _generation_seed.get()


@contextmanager
def generation_seed_scope(seed: int) -> Iterator[None]:
    """Activate one generation seed for the current context and its copied workers."""

    if not 0 <= seed <= MAX_GENERATION_SEED:
        raise ValueError(f"generation seed must be between 0 and {MAX_GENERATION_SEED}")
    token = _generation_seed.set(seed)
    try:
        yield
    finally:
        _generation_seed.reset(token)


def _get_rng() -> random.Random:
    """Get thread-local Random instance.

    Each thread gets its own RNG instance in the active public-seed namespace;
    thread-local storage ensures no cross-thread interference.

    Returns:
        Thread-local Random instance
    """
    seed = current_generation_seed()
    if not hasattr(_thread_local, "rng") or getattr(_thread_local, "rng_seed", None) != seed:
        _thread_local.rng = random.Random(seed)
        _thread_local.rng_seed = seed
    return _thread_local.rng


def reset_thread_rng(seed: int | None = None) -> None:
    """Reset the current thread's deterministic RNG stream."""

    if seed is None:
        seed = current_generation_seed()
    _thread_local.rng = random.Random(seed)
    _thread_local.rng_seed = seed


def _stable_seed(key: str) -> int:
    """Create a deterministic integer seed from a string.

    Uses SHA-256 instead of hash() to avoid PYTHONHASHSEED randomization.
    Produces the same seed across processes and Python invocations.
    """
    seed = current_generation_seed()
    scoped_key = key if seed == DEFAULT_GENERATION_SEED else f"seed:{seed}:{key}"
    return int(hashlib.sha256(scoped_key.encode()).hexdigest(), 16) % (2**32)


def stable_uuid(namespace: str, *parts: object) -> str:
    """Create a deterministic UUIDv4-shaped identifier from stable semantic parts."""
    normalized = "|".join("" if part is None else str(part) for part in parts)
    seed = current_generation_seed()
    prefix = "evidenceforge" if seed == DEFAULT_GENERATION_SEED else f"evidenceforge:seed:{seed}"
    digest = bytearray(hashlib.sha256(f"{prefix}:{namespace}:{normalized}".encode()).digest()[:16])
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))
