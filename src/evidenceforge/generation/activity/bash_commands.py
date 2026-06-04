# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Per-role bash command vocabularies for realistic bash_history generation.

Loads command pools from bash_commands.yaml and provides pick_bash_command()
for role-aware command selection with template parameterization.

Follows the same data-driven pattern as spawn_rules.py.
"""

import math
import random
from collections import Counter, deque
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_COMMANDS_PATH = get_activity_directory() / "bash_commands.yaml"
_CACHED_COMMANDS: dict[str, Any] | None = None

# Typo modes and their relative base weights. Per-user profiles
# re-weight these deterministically so each user has a "typo fingerprint".
_TYPO_MODES = ["adjacent_key", "transposition", "omission", "doubling"]


def _merge_bash_commands(default: dict, overlay: dict) -> dict:
    """Merge bash commands overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_bash_commands() -> dict[str, Any]:
    """Load bash command vocabularies from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_COMMANDS
    if _CACHED_COMMANDS is not None:
        return _CACHED_COMMANDS

    _CACHED_COMMANDS = load_with_overlay(
        _COMMANDS_PATH,
        "activity/bash_commands.yaml",
        _merge_bash_commands,
    )
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


def _service_template_values(system_services: list[str] | None, fallback: list[str]) -> list[str]:
    """Return safe service placeholder values that fit the current host when possible."""
    contextual: list[str] = []
    for service in system_services or []:
        normalized = service.strip().lower()
        if (
            not normalized
            or normalized in {"dns-client", "systemd"}
            or "{" in normalized
            or "}" in normalized
        ):
            continue
        if normalized == "ssh":
            normalized = "sshd"
        contextual.append(normalized)
    return contextual or fallback


def _resolve_template(
    template: str,
    rng: random.Random,
    params: dict[str, list[str]],
    system_services: list[str] | None = None,
) -> str:
    """Resolve {placeholder} tokens in a command template."""
    result = template
    # Resolve only the occurrences present for each token when that token is visited.
    # Scenario-controlled service names are filtered above, but this bound also prevents
    # any replacement value from recursively expanding the same token forever.
    for key, values in params.items():
        token = "{" + key + "}"
        candidates = (
            _service_template_values(system_services, values) if key == "service" else values
        )
        for _ in range(result.count(token)):
            result = result.replace(token, rng.choice(candidates), 1)
    return result


def _get_role_pool(
    persona: str,
    server_role: str,
    *,
    workstation_like: bool = False,
) -> str:
    """Map persona + server role to the command pool key in the YAML.

    Built-in alias mappings (developer→dba on DB servers, etc.) are checked
    first. Then checks for an exact persona name match in the loaded data
    (supports custom/overlay personas with their own command pools).
    Falls back to sysadmin for unknown personas.
    """
    data = load_bash_commands()
    persona_lower = persona.lower() if persona else ""

    # These stock personas have workstation-normal pools, but those pools should
    # not leak desktop diagnostics across Linux servers.
    if (
        persona_lower in {"help_desk", "data_analyst"}
        and workstation_like
        and persona_lower in data
    ):
        return persona_lower

    # Built-in alias mappings that depend on server_role context
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

    # Exact match: persona has its own command pool in the YAML
    # (custom/overlay personas, or stock personas like sysadmin)
    if persona_lower in data:
        return persona_lower

    return "sysadmin"  # Default for unknown personas without a custom pool


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


def _typo_rate(username: str, commands: dict[str, Any]) -> float:
    """Return deterministic per-user typo rate bounded by YAML config."""
    typo_model = commands.get("typo_model", {})
    max_rate = float(typo_model.get("max_rate", 0.08))
    max_bucket = max(0, int(round(max_rate * 100)))
    if max_bucket <= 0:
        return 0.0
    return (_stable_seed(f"typo_rate_{username}") % (max_bucket + 1)) / 100.0


def _typo_allowed(
    commands: dict[str, Any],
    *,
    session_command_count: int | None,
    prior_typo_count: int,
) -> bool:
    """Return whether another typo is plausible for the current history length."""
    typo_model = commands.get("typo_model", {})
    short_threshold = int(typo_model.get("short_history_threshold", 8))
    short_max = int(typo_model.get("short_history_max_typos", 1))
    if session_command_count is not None and session_command_count <= short_threshold:
        return prior_typo_count < short_max
    return True


_USER_TOOL_AFFINITY: dict[tuple[str, tuple[str, ...]], list[str]] = {}
_COMMAND_RECENCY_LIMIT = 24
_COMMAND_CANDIDATE_ATTEMPTS = 96
_COMMAND_RECENCY: dict[tuple[str, str], deque[str]] = {}
_COMMAND_USER_RECENCY: dict[str, deque[str]] = {}
_COMMAND_GLOBAL_COUNTS: Counter[str] = Counter()
_COMMAND_GLOBAL_LOW_REPEAT_COUNTS: Counter[str] = Counter()
_WORKFLOW_SELECTION_PROBABILITY = 0.65
_MAX_WORKFLOW_WEIGHT = 1_000_000.0
_DEFAULT_PACKAGE_MANAGER_MODEL: dict[str, Any] = {
    "families": {
        "debian": {
            "os_keywords": ["ubuntu", "debian"],
            "command_prefixes": ["apt ", "apt-get ", "apt-cache ", "dpkg "],
        },
        "rpm": {
            "os_keywords": ["centos", "fedora", "red hat", "rhel", "rocky", "alma"],
            "command_prefixes": ["yum ", "dnf ", "rpm "],
        },
    }
}
_LOW_REPEAT_EXACT_COMMANDS = {
    "cat /proc/cpuinfo | grep 'model name' | head -1",
    "df -h /tmp",
    "journalctl -p err --no-pager -n 10",
    "systemctl --failed --no-pager",
    "systemctl status sshd",
}
_NON_WORKSTATION_SERVICE_HINTS = {
    "ad-ds",
    "apache2",
    "dns",
    "gunicorn",
    "kerberos",
    "ldap",
    "mysql",
    "nginx",
    "php-fpm",
    "postgresql",
    "redis",
    "smb",
    "squid",
}
_WORKSTATION_HOST_PREFIXES = ("desktop", "laptop", "lt-", "pc-", "wks-", "ws-")
_WORKSTATION_ONLY_COMMAND_MARKERS = (
    "~/downloads",
    "~/.cache",
    "~/.config",
    "~/.local/share",
    "~/.xsession-errors",
    "apt-cache policy google-chrome-stable",
    "apt-cache policy slack-desktop",
    "bluetoothctl",
    "flatpak list",
    "lpstat",
    "snap list",
    "systemctl status cups",
    "systemctl status fwupd",
    "systemctl status packagekit",
    "lsusb",
)


def reset_bash_command_memory() -> None:
    """Clear per-generation bash command memory."""
    _COMMAND_RECENCY.clear()
    _COMMAND_USER_RECENCY.clear()
    _COMMAND_GLOBAL_COUNTS.clear()
    _COMMAND_GLOBAL_LOW_REPEAT_COUNTS.clear()


def _get_user_pool(username: str, full_pool: list[str]) -> list[str]:
    """Return a user-specific subset of the command pool for tool affinity.

    Each user gets 1-2 primary tool "families" (deterministic by username).
    80% of role-specific commands come from the primary tools, 20% from
    the full pool — so users have consistent tooling preferences.
    """
    cache_key = (username, tuple(full_pool))
    if cache_key in _USER_TOOL_AFFINITY:
        return _USER_TOOL_AFFINITY[cache_key]

    # Identify tool families by prefix keywords
    _TOOL_FAMILIES = {
        "python": ["python", "pip", "pytest", "venv"],
        "node": ["npm", "node", "yarn", "webpack"],
        "docker": ["docker"],
        "go": ["go "],
        "rust": ["cargo"],
        "c_cpp": ["gcc", "make", "cmake", "g++"],
        "git": ["git "],
        "k8s": ["kubectl", "helm"],
    }

    # Pick 1-2 primary families seeded by username
    seed = _stable_seed(f"tool_affinity_{username}")
    family_names = list(_TOOL_FAMILIES.keys())
    affinity_rng = random.Random(seed)
    n_primary = affinity_rng.choice([1, 1, 2])  # Favor 1 primary
    primary_families = affinity_rng.sample(family_names, min(n_primary, len(family_names)))

    # Filter pool to commands matching primary families
    primary_keywords: list[str] = []
    for fam in primary_families:
        primary_keywords.extend(_TOOL_FAMILIES[fam])

    primary_pool = [cmd for cmd in full_pool if any(kw in cmd.lower() for kw in primary_keywords)]
    # If we filtered too aggressively, keep the full pool
    if len(primary_pool) < 3:
        primary_pool = full_pool

    _USER_TOOL_AFFINITY[cache_key] = primary_pool
    return primary_pool


def _is_workstation_like_system(system_hostname: str, system_services: list[str] | None) -> bool:
    """Return whether a Linux shell host should receive desktop-oriented commands."""
    hostname = system_hostname.lower()
    if hostname.startswith(_WORKSTATION_HOST_PREFIXES):
        return True
    services = {service.lower() for service in system_services or []}
    if services & _NON_WORKSTATION_SERVICE_HINTS:
        return False
    return False


def _string_list(value: Any) -> list[str]:
    """Return stripped strings from a YAML value."""
    if not isinstance(value, list):
        return []
    return [str(item).strip().lower() for item in value if str(item).strip()]


def _package_manager_model(commands: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the package-manager compatibility model from config."""
    if commands is None:
        commands = load_bash_commands()
    model = commands.get("package_manager_model")
    return model if isinstance(model, dict) else _DEFAULT_PACKAGE_MANAGER_MODEL


def package_manager_family_for_os(
    system_os: str | None,
    commands: dict[str, Any] | None = None,
) -> str | None:
    """Return the configured package-manager family for an OS string."""
    if not system_os:
        return None
    os_lower = system_os.lower()
    families = _package_manager_model(commands).get("families", {})
    if not isinstance(families, dict):
        return None
    for family, config in families.items():
        if not isinstance(config, dict):
            continue
        keywords = _string_list(config.get("os_keywords"))
        if any(keyword in os_lower for keyword in keywords):
            return str(family)
    return None


def _command_package_family(command: str, commands: dict[str, Any] | None = None) -> str | None:
    """Return the configured package-manager family for a command string."""
    normalized = " ".join(command.strip().lower().split())
    if normalized.startswith("sudo "):
        normalized = normalized[5:]
    for prefix in ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    families = _package_manager_model(commands).get("families", {})
    if not isinstance(families, dict):
        return None
    for family, config in families.items():
        if not isinstance(config, dict):
            continue
        prefixes = _string_list(config.get("command_prefixes"))
        if any(normalized.startswith(prefix) for prefix in prefixes):
            return str(family)
    return None


def _filter_pool_for_system(
    pool: list[str],
    system_hostname: str,
    system_services: list[str] | None,
    system_os: str | None = None,
) -> list[str]:
    """Remove host-incompatible commands from command pools."""
    if _is_workstation_like_system(system_hostname, system_services):
        filtered = list(pool)
    else:
        filtered = [
            command
            for command in pool
            if not any(marker in command.lower() for marker in _WORKSTATION_ONLY_COMMAND_MARKERS)
        ]

    commands = load_bash_commands()
    os_package_family = package_manager_family_for_os(system_os, commands)
    if os_package_family:
        distro_filtered = [
            command
            for command in filtered
            if (family := _command_package_family(command, commands)) is None
            or family == os_package_family
        ]
        if distro_filtered:
            filtered = distro_filtered

    return filtered or pool


def _remember_command(system_hostname: str, username: str, command: str) -> None:
    """Record command selection so later picks avoid exact repeated strings."""
    key = (system_hostname.lower(), username.lower())
    recent = _COMMAND_RECENCY.setdefault(key, deque(maxlen=_COMMAND_RECENCY_LIMIT))
    recent.append(command)
    if username:
        user_recent = _COMMAND_USER_RECENCY.setdefault(
            username.lower(), deque(maxlen=_COMMAND_RECENCY_LIMIT * 2)
        )
        user_recent.append(command)
    _COMMAND_GLOBAL_COUNTS[command] += 1
    if low_repeat_key := _low_repeat_group(command):
        _COMMAND_GLOBAL_LOW_REPEAT_COUNTS[low_repeat_key] += 1


def _low_repeat_group(command: str) -> str | None:
    """Return a canonical low-repeat budget key for equivalent diagnostic commands."""
    normalized = " ".join(command.split())
    if family := _command_package_family(normalized):
        if any(token in normalized for token in ("update", "upgradable", "makecache")):
            return f"package_manager_{family}_refresh"
    if normalized in _LOW_REPEAT_EXACT_COMMANDS:
        return normalized.replace(" ", "_").replace("/", "_")
    if normalized.startswith("cat /proc/cpuinfo | grep 'model name'"):
        return "cpuinfo_model_name"
    if normalized == "df -h /tmp":
        return "df_tmp"
    if normalized in {"command -v python3", "python3 -V 2>&1", "which python3"}:
        return "python3_discovery"
    if normalized in {"history", "history | tail -15", "history | tail -20"}:
        return "history_review"
    if normalized == "hostnamectl":
        return "hostnamectl"
    if normalized.startswith("ip addr show"):
        return "ip_addr_show"
    if normalized.startswith("ip -br addr"):
        return "ip_br_addr"
    if normalized.startswith("ip -o addr show"):
        return "ip_o_addr"
    if normalized.startswith("ip route get "):
        return "ip_route_get"
    if normalized.startswith("journalctl -p warning"):
        return "journalctl_warnings"
    if normalized.startswith("journalctl -p err"):
        return "journalctl_errors"
    if normalized.startswith("journalctl -u NetworkManager"):
        return "journalctl_networkmanager"
    if normalized.startswith("loginctl "):
        return normalized.replace(" ", "_")
    if normalized.startswith("nmcli connection show"):
        return "nmcli_connection_show"
    if normalized.startswith("nmcli device status"):
        return "nmcli_device_status"
    if normalized.startswith("resolvectl query login.microsoftonline.com"):
        return "resolvectl_login_microsoftonline"
    if normalized.startswith("resolvectl status"):
        return "resolvectl_status"
    if normalized.startswith("systemctl --user status"):
        return "systemctl_user_status"
    if normalized.startswith("systemctl --failed"):
        return "systemctl_failed"
    if normalized.startswith("systemctl status "):
        parts = normalized.split()
        if len(parts) >= 3:
            return f"systemctl_status_{parts[2]}"
    if normalized in {"tail -20 /var/log/auth.log", "tail -50 /var/log/auth.log"}:
        return "auth_log_tail_generic"
    if normalized == "timedatectl":
        return "timedatectl"
    if normalized in {"uname -a", "uname -sr", "uname -mrs"}:
        return "uname_kernel"
    if normalized == "systemctl status sshd" or normalized.startswith("systemctl status sshd "):
        return "systemctl_sshd"
    return None


def _global_repeat_limit(command: str, pool_size: int) -> int:
    """Return the generation-wide soft repeat limit for an exact command."""
    if _low_repeat_group(command):
        return 2
    return max(2, min(3, max(1, pool_size // 14)))


def _below_global_repeat_limit(command: str, pool_size: int, *, slack: int = 0) -> bool:
    """Return whether a command is still below its global repeat budget."""
    limit = _global_repeat_limit(command, pool_size)
    if low_repeat_key := _low_repeat_group(command):
        slack = 0
        return _COMMAND_GLOBAL_LOW_REPEAT_COUNTS[low_repeat_key] < limit
    return _COMMAND_GLOBAL_COUNTS[command] < limit + slack


def _choose_template_with_memory(
    rng: random.Random,
    pool: list[str],
    params: dict[str, list[str]],
    system_services: list[str] | None,
    system_hostname: str,
    username: str,
    system_os: str | None = None,
) -> str:
    """Pick a command while suppressing recent and globally overused exact repeats."""
    pool = _filter_pool_for_system(pool, system_hostname, system_services, system_os)
    if not pool:
        return "ls"

    key = (system_hostname.lower(), username.lower())
    recent = set(_COMMAND_RECENCY.get(key, ()))
    if username:
        recent.update(_COMMAND_USER_RECENCY.get(username.lower(), ()))
    attempts = _COMMAND_CANDIDATE_ATTEMPTS
    candidates: list[str] = []
    for _ in range(attempts):
        template = rng.choice(pool)
        command = _resolve_template(template, rng, params, system_services)
        candidates.append(command)
        if command not in recent and _below_global_repeat_limit(command, len(pool)):
            _remember_command(system_hostname, username, command)
            return command

    for command in candidates:
        if command not in recent and _below_global_repeat_limit(command, len(pool)):
            _remember_command(system_hostname, username, command)
            return command

    command = min(
        candidates,
        key=lambda candidate: (
            not _below_global_repeat_limit(candidate, len(pool)),
            _low_repeat_group(candidate) is not None,
            _COMMAND_GLOBAL_LOW_REPEAT_COUNTS[_low_repeat_group(candidate)]
            if _low_repeat_group(candidate)
            else _COMMAND_GLOBAL_COUNTS[candidate],
        ),
    )
    _remember_command(system_hostname, username, command)
    return command


def _try_choose_fresh_workflow_template(
    rng: random.Random,
    pool: list[str],
    params: dict[str, list[str]],
    system_services: list[str] | None,
    system_hostname: str,
    username: str,
    system_os: str | None = None,
) -> str | None:
    """Pick a workflow step only while its exact variants still have repeat budget."""
    pool = _filter_pool_for_system(pool, system_hostname, system_services, system_os)
    if not pool:
        return None

    key = (system_hostname.lower(), username.lower())
    recent = set(_COMMAND_RECENCY.get(key, ()))
    if username:
        recent.update(_COMMAND_USER_RECENCY.get(username.lower(), ()))

    candidates: list[str] = []
    for _ in range(_COMMAND_CANDIDATE_ATTEMPTS):
        template = rng.choice(pool)
        command = _resolve_template(template, rng, params, system_services)
        candidates.append(command)
        if command not in recent and _below_global_repeat_limit(command, len(pool)):
            _remember_command(system_hostname, username, command)
            return command

    fresh_candidates = [
        command
        for command in candidates
        if command not in recent and _below_global_repeat_limit(command, len(pool))
    ]
    if not fresh_candidates:
        return None
    command = min(fresh_candidates, key=lambda candidate: _COMMAND_GLOBAL_COUNTS[candidate])
    _remember_command(system_hostname, username, command)
    return command


def _workflow_candidates(commands: dict[str, Any], pool_key: str) -> list[dict[str, Any]]:
    """Return workflow candidates for a role, including shared fallback workflows."""
    workflows = commands.get("workflows", {})
    if not isinstance(workflows, dict):
        return []
    candidates: list[dict[str, Any]] = []
    for key in ("common", pool_key):
        value = workflows.get(key, [])
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
    return [item for item in candidates if isinstance(item.get("steps"), list)]


def _coerce_probability(value: Any, fallback: float) -> float:
    """Convert a config value into a finite bounded probability with safe fallback."""
    try:
        probability = float(value)
    except (TypeError, ValueError, OverflowError):
        return fallback
    if not math.isfinite(probability):
        return fallback
    return min(1.0, max(0.0, probability))


def _coerce_workflow_weight(value: Any) -> float:
    """Convert a workflow weight into a finite bounded selection weight."""
    try:
        weight = float(value)
    except (TypeError, ValueError, OverflowError):
        return 1.0
    if not math.isfinite(weight):
        return 1.0
    if weight <= 0:
        return 0.0
    return min(weight, _MAX_WORKFLOW_WEIGHT)


def _choose_workflow(rng: random.Random, workflows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Pick one configured shell workflow by weight."""
    if not workflows:
        return None
    weights = [_coerce_workflow_weight(workflow.get("weight", 1.0)) for workflow in workflows]
    if not any(weights):
        return rng.choice(workflows)
    return rng.choices(workflows, weights=weights, k=1)[0]


def _workflow_step_templates(step: Any) -> list[str]:
    """Normalize a workflow step to a non-empty list of command templates."""
    if isinstance(step, str):
        return [step]
    if isinstance(step, list):
        return [item for item in step if isinstance(item, str) and item.strip()]
    return []


def _pick_workflow_commands(
    rng: random.Random,
    workflow: dict[str, Any],
    params: dict[str, list[str]],
    system_services: list[str] | None,
    system_hostname: str,
    username: str,
    command_count: int,
    system_os: str | None = None,
) -> list[str]:
    """Materialize a configured workflow into source-native bash commands."""
    commands: list[str] = []
    steps = workflow.get("steps", [])
    for step in steps:
        if len(commands) >= command_count:
            break
        templates = _workflow_step_templates(step)
        if not templates:
            continue
        command = _try_choose_fresh_workflow_template(
            rng,
            templates,
            params,
            system_services,
            system_hostname,
            username,
            system_os,
        )
        if command is not None:
            commands.append(command)
    return commands


def pick_bash_session_commands(
    rng: random.Random,
    persona: str,
    system_hostname: str,
    system_services: list[str],
    username: str,
    command_count: int,
    system_os: str | None = None,
) -> list[tuple[str, bool]]:
    """Pick a coherent shell-session command list.

    Most interactive sessions should read like a short workflow, not a bag of
    unrelated diagnostics. Configured workflows provide role/host-specific
    command sequences; any remaining slots fall back to the regular picker.
    """
    if command_count <= 0:
        return []

    commands = load_bash_commands()
    params = commands.get("params", {})
    server_role = _resolve_server_role(system_hostname, system_services)
    workstation_like = _is_workstation_like_system(system_hostname, system_services)
    pool_key = _get_role_pool(persona, server_role, workstation_like=workstation_like)
    selected: list[tuple[str, bool]] = []

    workflows = _workflow_candidates(commands, pool_key)
    workflow_model = commands.get("workflow_model", {})
    selection_probability = _coerce_probability(
        workflow_model.get("selection_probability", _WORKFLOW_SELECTION_PROBABILITY)
        if isinstance(workflow_model, dict)
        else _WORKFLOW_SELECTION_PROBABILITY,
        _WORKFLOW_SELECTION_PROBABILITY,
    )
    if command_count >= 2 and workflows and rng.random() < selection_probability:
        workflow = _choose_workflow(rng, workflows)
        if workflow is not None:
            for command in _pick_workflow_commands(
                rng,
                workflow,
                params,
                system_services,
                system_hostname,
                username,
                command_count,
                system_os,
            ):
                selected.append((command, False))

    typo_count = 0
    while len(selected) < command_count:
        command, is_typo = pick_bash_command_entry(
            rng,
            persona,
            system_hostname,
            system_services,
            username=username,
            session_command_count=command_count,
            prior_typo_count=typo_count,
            system_os=system_os,
        )
        selected.append((command, is_typo))
        if is_typo:
            typo_count += 1
    return selected


def pick_bash_command(
    rng: random.Random,
    persona: str,
    system_hostname: str,
    system_services: list[str],
    username: str = "",
    session_command_count: int | None = None,
    prior_typo_count: int = 0,
    system_os: str | None = None,
) -> str:
    """Pick a bash command appropriate for the user's role on this server.

    Distribution: roughly 45% common, 50% role-specific, up to 5% typo.
    Role-specific commands use per-user tool affinity (80% primary tools,
    20% full pool) for consistent user behavior.
    """
    command, _is_typo = pick_bash_command_entry(
        rng,
        persona,
        system_hostname,
        system_services,
        username=username,
        session_command_count=session_command_count,
        prior_typo_count=prior_typo_count,
        system_os=system_os,
    )
    return command


def pick_bash_command_entry(
    rng: random.Random,
    persona: str,
    system_hostname: str,
    system_services: list[str],
    username: str = "",
    session_command_count: int | None = None,
    prior_typo_count: int = 0,
    system_os: str | None = None,
) -> tuple[str, bool]:
    """Pick a bash command and return whether it is a generated typo."""
    commands = load_bash_commands()
    params = commands.get("params", {})
    server_role = _resolve_server_role(system_hostname, system_services)

    roll = rng.random()

    _user_typo_rate = _typo_rate(username, commands)
    if roll < _user_typo_rate and _typo_allowed(
        commands,
        session_command_count=session_command_count,
        prior_typo_count=prior_typo_count,
    ):
        command = _generate_typo(rng, username, commands)
        _remember_command(system_hostname, username, command)
        return command, True

    # Scale remaining thresholds into the non-typo portion
    _remaining = 1.0 - _user_typo_rate
    if roll < _user_typo_rate + _remaining * 0.52:
        # Role-specific command with per-user tool affinity
        workstation_like = _is_workstation_like_system(system_hostname, system_services)
        pool_key = _get_role_pool(persona, server_role, workstation_like=workstation_like)
        pool = commands.get(pool_key, commands.get("common", ["ls"]))
        if username and rng.random() < 0.80:
            pool = _get_user_pool(username, pool)
        return (
            _choose_template_with_memory(
                rng,
                pool,
                params,
                system_services,
                system_hostname,
                username,
                system_os,
            ),
            False,
        )

    # Common command (60%)
    common = commands.get("common", ["ls"])
    return (
        _choose_template_with_memory(
            rng,
            common,
            params,
            system_services,
            system_hostname,
            username,
            system_os,
        ),
        False,
    )
