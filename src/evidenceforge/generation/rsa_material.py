# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic RSA numbers for synthetic public-key evidence only."""

from __future__ import annotations

import random
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric import rsa

from evidenceforge.config.provider import _register_trusted_derived_cache
from evidenceforge.utils.rng import _stable_seed, stable_hex_digest

_PUBLIC_EXPONENT = 65537
_PRIMALITY_ROUNDS = 32


def _small_primes() -> tuple[int, ...]:
    """Compute a small trial-division sieve, independent of material identities."""
    sieve = bytearray(b"\x01") * 1000
    sieve[:2] = b"\x00\x00"
    for candidate in range(2, 32):
        if sieve[candidate]:
            for multiple in range(candidate * candidate, len(sieve), candidate):
                sieve[multiple] = 0
    return tuple(index for index, prime in enumerate(sieve) if prime)


_TRIAL_PRIMES = _small_primes()


def _is_probable_prime(candidate: int, rng: random.Random) -> bool:
    """Test a large candidate with trial division and scoped Miller–Rabin bases."""
    if candidate < 2:
        return False
    for prime in _TRIAL_PRIMES:
        if candidate % prime == 0:
            return candidate == prime
    odd_part = candidate - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        powers_of_two += 1
    for _ in range(_PRIMALITY_ROUNDS):
        witness = rng.randrange(2, candidate - 1)
        residue = pow(witness, odd_part, candidate)
        if residue in {1, candidate - 1}:
            continue
        for _ in range(powers_of_two - 1):
            residue = pow(residue, 2, candidate)
            if residue == candidate - 1:
                break
        else:
            return False
    return True


def _deterministic_rsa_prime(identity: str, bits: int) -> int:
    """Search one independently seeded prime stream without retaining secret state."""
    # The caller supplied a full-width, generation-scoped identity. Keeping it
    # intact avoids collapsing distinct factor streams to a 32-bit seed.
    rng = random.Random(f"rsa-public-material-prime:{identity}:{bits}")
    while True:
        candidate = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if (candidate - 1) % _PUBLIC_EXPONENT and _is_probable_prime(candidate, rng):
            return candidate


@lru_cache(maxsize=512)
def _deterministic_rsa_modulus(identity: str, key_size: int) -> int:
    """Memoize only immutable public moduli under bounded fixed-width identities."""
    prime_bits = key_size // 2
    first = _deterministic_rsa_prime(f"{identity}:p", prime_bits)
    attempt = 0
    while True:
        second = _deterministic_rsa_prime(f"{identity}:q:{attempt}", prime_bits)
        if abs(first - second) > 1 << (prime_bits - 100):
            return first * second
        attempt += 1


def deterministic_rsa_public_numbers(identity: str, key_size: int) -> rsa.RSAPublicNumbers:
    """Build reproducible synthetic public evidence, never communication secrets.

    Full semantic identity and generation-seed scope survive before prime
    planning. A bounded computation memo avoids repeating primality searches
    during canonical binding checks; it retains no factors or private keys.
    """
    if key_size not in {2048, 3072, 4096}:
        raise ValueError("Synthetic RSA public material requires 2048, 3072 or 4096 bits")
    scope = f"rsa-public-material:{identity}:{key_size}"
    scoped_identity = stable_hex_digest(
        "rsa-public-material", scope, _stable_seed(scope), length=64
    )
    return rsa.RSAPublicNumbers(
        _PUBLIC_EXPONENT, _deterministic_rsa_modulus(scoped_identity, key_size)
    )


_register_trusted_derived_cache(
    __name__, "_deterministic_rsa_modulus", globals(), _deterministic_rsa_modulus
)
