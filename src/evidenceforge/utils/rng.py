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
