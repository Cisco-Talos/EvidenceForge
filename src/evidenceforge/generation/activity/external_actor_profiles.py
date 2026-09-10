# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deprecated 2.x Python adapters for canonical public identity profiles."""

from __future__ import annotations

import random
from typing import Any, Literal

from evidenceforge.generation.activity.public_identity_profiles import (
    legacy_external_actor_projection,
    legacy_pool_role,
    pick_public_identity_ip,
    reset_public_identity_profiles_cache,
)

ExternalActorPool = Literal["logon_source_ips", "failed_logon_source_ips", "connection_c2_ips"]


def load_external_actor_profiles() -> dict[str, Any]:
    """Return canonical identities through the deprecated 2.x mapping shape."""

    return legacy_external_actor_projection()


def reset_external_actor_profiles_cache() -> None:
    """Clear the canonical registry loader cache. Intended for compatibility tests."""

    reset_public_identity_profiles_cache()


def pick_external_actor_ip(pool: ExternalActorPool, rng: random.Random) -> str:
    """Pick through the canonical role while preserving the deprecated helper signature."""

    semantic_key = f"legacy-picker:{pool}:{rng.getrandbits(128):032x}"
    return pick_public_identity_ip(legacy_pool_role(pool), semantic_key)
