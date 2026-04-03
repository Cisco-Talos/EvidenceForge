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

_COMMANDS_PATH = Path(__file__).parent / "bash_commands.yaml"
_CACHED_COMMANDS: dict[str, Any] | None = None


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


def pick_bash_command(
    rng: random.Random,
    persona: str,
    system_hostname: str,
    system_services: list[str],
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
        # Typo: return a corrupted common command
        typos = commands.get("typos", [])
        if typos:
            _original, typo = rng.choice(typos)
            return typo
        # Fallback if no typos defined
        return "sl"

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
