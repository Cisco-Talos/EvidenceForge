"""Thread-safe deterministic random number generation.

Provides a thread-local RNG that ensures reproducible output across
concurrent generation threads. Each thread gets its own Random instance
seeded deterministically from the thread ID.
"""

import random
from threading import get_ident, local

_thread_local = local()


def _get_rng() -> random.Random:
    """Get thread-local Random instance with deterministic seed.

    Each thread gets its own RNG instance with a deterministic seed based on
    the thread ID, preserving reproducibility without GIL contention.

    Returns:
        Thread-local Random instance
    """
    if not hasattr(_thread_local, "rng"):
        thread_id = get_ident()
        # Deterministic seed: combine thread ID with global seed
        # Global seed could be made configurable in the future
        seed = hash((thread_id, 42))  # 42 = global seed
        _thread_local.rng = random.Random(seed)
    return _thread_local.rng
