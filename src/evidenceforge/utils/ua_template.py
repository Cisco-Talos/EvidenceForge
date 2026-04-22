# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""User-agent template substitution for scanner presets.

Scanner UAs may contain per-request tokens that vary on each request,
matching the behavior of the real scanner. Token naming convention:
scanner-specific tokens embed the scanner name (e.g., @NIKTO_TESTID@)
so the intent is obvious. Generic tokens use a descriptive suffix.

Current tokens:
  @NIKTO_TESTID@   Random 6-digit numeric test ID, matching Nikto's
                   per-request @TESTID substitution in nikto.conf.

Future tokens (add only when a preset needs them):
  @NONCE_HEX8@     Random 8-character hex string
  @UUID@           Random UUID4

UAs without tokens pass through unchanged.
"""

from __future__ import annotations

import random
import re

# Registry maps token name → generator function (rng) -> str
_TOKEN_GENERATORS: dict[str, Callable[[random.Random], str]] = {}  # noqa: F821


def _register(token: str):
    def decorator(fn):
        _TOKEN_GENERATORS[token] = fn
        return fn

    return decorator


@_register("NIKTO_TESTID")
def _nikto_testid(rng: random.Random) -> str:
    return str(rng.randint(100000, 999999))


_TOKEN_PATTERN = re.compile(r"@([A-Z0-9_]+)@")


def render_ua(template: str, rng: random.Random) -> str:
    """Substitute scanner tokens in a UA template string.

    Each occurrence of a known @TOKEN@ is replaced with a freshly
    generated value. Unknown tokens are left unchanged so future
    presets can use tokens before the generator is registered.

    Args:
        template: UA string, possibly containing @TOKEN@ placeholders.
        rng: Random number generator for reproducible output.

    Returns:
        UA string with all known tokens substituted.
    """
    if "@" not in template:
        return template

    def replace(m: re.Match) -> str:
        token_name = m.group(1)
        gen = _TOKEN_GENERATORS.get(token_name)
        if gen is not None:
            return gen(rng)
        return m.group(0)  # pass unknown tokens through

    return _TOKEN_PATTERN.sub(replace, template)
