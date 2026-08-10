# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Durable client credential and authentication policy for modeled SSH sessions."""

import random

from evidenceforge.utils.rng import _stable_seed


def baseline_ssh_client_key(source_ip: str, username: str) -> tuple[str, str]:
    """Return the durable public-key identity owned by one SSH client user."""
    key_rng = random.Random(_stable_seed(f"ssh_client_key:{source_ip}:{username}"))
    key_type = key_rng.choice(["RSA", "ED25519", "ECDSA"])
    key_hash = "".join(
        key_rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=43)
    )
    return key_type, f"SHA256:{key_hash}"


def baseline_ssh_auth_method(source_ip: str, target_ip: str, username: str) -> str:
    """Return the stable authentication policy for one client/user/target tuple."""
    policy_rng = random.Random(_stable_seed(f"ssh_auth_policy:{source_ip}:{target_ip}:{username}"))
    return "publickey" if policy_rng.random() < 0.7 else "password"
