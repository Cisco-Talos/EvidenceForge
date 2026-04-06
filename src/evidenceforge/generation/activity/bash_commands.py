# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Per-role bash command vocabularies for realistic bash_history generation.

Loads command pools from bash_commands.yaml and provides pick_bash_command()
for role-aware command selection with template parameterization.

Follows the same data-driven pattern as spawn_rules.py.
"""

import random
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.utils.rng import _stable_seed

_COMMANDS_PATH = Path(__file__).parent / "bash_commands.yaml"
_CACHED_COMMANDS: dict[str, Any] | None = None

# Typo modes and their relative base weights. Per-user profiles
# re-weight these deterministically so each user has a "typo fingerprint".
_TYPO_MODES = ["adjacent_key", "transposition", "omission", "doubling"]


def load_bash_commands() -> dict[str, Any]:
    """Load bash command vocabularies from YAML. Cached after first call."""
    global _CACHED_COMMANDS
    if _CACHED_COMMANDS is not None:
        return _CACHED_COMMANDS

    with open(_COMMANDS_PATH) as f:
        _CACHED_COMMANDS = yaml.safe_load(f)
    return _CACHED_COMMANDS


def _resolve_server_role(hostname: str, services: list[str]) -> str:
    """Determine server role from hostname and services.

    Returns one of: 'db', 'web', 'log', 'generic'.
    """
    hostname_lower = hostname.lower()
    services_lower = {s.lower() for s in services}

    if (
        services_lower & {"mysql", "postgresql", "mariadb", "mongodb", "sql", "redis"}
        or "db" in hostname_lower
    ):
        return "db"
    if services_lower & {"apache", "nginx", "httpd", "tomcat"} or "web" in hostname_lower:
        return "web"
    if "log" in hostname_lower or services_lower & {
        "splunk",
        "elasticsearch",
        "syslog",
        "logstash",
    }:
        return "log"
    return "generic"


def _resolve_template(template: str, rng: random.Random, params: dict[str, list[str]]) -> str:
    """Resolve {placeholder} tokens in a command template."""
    result = template
    # Iterate to handle templates with multiple placeholders
    for key, values in params.items():
        token = "{" + key + "}"
        while token in result:
            result = result.replace(token, rng.choice(values), 1)
    return result


def _get_role_pool(persona: str, server_role: str) -> str:
    """Map persona + server role to the command pool key in the YAML."""
    persona_lower = persona.lower() if persona else ""

    if persona_lower == "sysadmin":
        return "sysadmin"
    if persona_lower in ("developer",):
        if server_role == "db":
            return "dba"
        if server_role == "web":
            return "webadmin"
        return "developer"
    if persona_lower in ("security_analyst",):
        return "security"
    if persona_lower in ("data_analyst", "analyst"):
        return "dba"
    if persona_lower == "help_desk":
        return "sysadmin"
    return "sysadmin"  # Default for unknown admin personas


def _apply_typo_mode(
    word: str, mode: str, adjacency: dict[str, list[str]], rng: random.Random
) -> str | None:
    """Apply a single typo mode to a word. Returns None if mode can't apply."""
    if len(word) < 2:
        return None

    if mode == "adjacent_key":
        # Replace one alpha char with an adjacent key
        alpha_indices = [i for i, c in enumerate(word) if c.isalpha() and c.lower() in adjacency]
        if not alpha_indices:
            return None
        idx = rng.choice(alpha_indices)
        neighbors = adjacency.get(word[idx].lower(), [])
        alpha_neighbors = [n for n in neighbors if n.isalpha()]
        if not alpha_neighbors:
            return None
        return word[:idx] + rng.choice(alpha_neighbors) + word[idx + 1 :]

    elif mode == "transposition":
        # Swap two adjacent characters
        idx = rng.randint(0, len(word) - 2)
        return word[:idx] + word[idx + 1] + word[idx] + word[idx + 2 :]

    elif mode == "omission":
        # Drop one non-first character
        if len(word) < 3:
            return None
        idx = rng.randint(1, len(word) - 1)
        return word[:idx] + word[idx + 1 :]

    elif mode == "doubling":
        # Double one character
        idx = rng.randint(0, len(word) - 1)
        return word[:idx] + word[idx] + word[idx:]

    return None


def _generate_typo(rng: random.Random, username: str, commands: dict[str, Any]) -> str:
    """Generate a per-user typo using their deterministic typo fingerprint.

    Each user gets a characteristic distribution of typo modes (adjacent_key,
    transposition, omission, doubling) so that different users produce
    different typo patterns.
    """
    adjacency = commands.get("keyboard_adjacency", {})

    # Per-user typo profile: deterministic mode weights
    user_seed = _stable_seed(f"typo_profile_{username}")
    user_rng = random.Random(user_seed)
    # Shuffle base weights to create a unique profile per user
    weights = [user_rng.randint(10, 70) for _ in _TYPO_MODES]

    # Pick a common command as the "intended" command
    common = commands.get("common", ["ls", "cd", "pwd"])
    intended = rng.choice(common)
    # Extract just the first word (the command name) for typo application
    parts = intended.split()
    target_word = parts[0]

    # Try modes in weighted-random order until one produces a change
    mode_order = rng.choices(_TYPO_MODES, weights=weights, k=len(_TYPO_MODES))
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_modes = []
    for m in mode_order:
        if m not in seen:
            seen.add(m)
            unique_modes.append(m)

    for mode in unique_modes:
        result = _apply_typo_mode(target_word, mode, adjacency, rng)
        if result is not None and result != target_word:
            # Return just the corrupted command name (not the full command with args)
            return result

    # All modes failed (very rare) — return a simple transposition of "ls"
    return "sl"


def pick_bash_command(
    rng: random.Random,
    persona: str,
    system_hostname: str,
    system_services: list[str],
    username: str = "",
) -> str:
    """Pick a bash command appropriate for the user's role on this server.

    Distribution: 60% common, 35% role-specific, 5% typo.
    Templates with {placeholder} tokens are resolved from the params section.
    """
    commands = load_bash_commands()
    params = commands.get("params", {})
    server_role = _resolve_server_role(system_hostname, system_services)

    roll = rng.random()

    if roll < 0.05:
        # Typo: generate a per-user corrupted command
        return _generate_typo(rng, username, commands)

    if roll < 0.40:
        # Role-specific command
        pool_key = _get_role_pool(persona, server_role)
        pool = commands.get(pool_key, commands.get("common", ["ls"]))
        template = rng.choice(pool)
        return _resolve_template(template, rng, params)

    # Common command (60%)
    common = commands.get("common", ["ls"])
    template = rng.choice(common)
    return _resolve_template(template, rng, params)
