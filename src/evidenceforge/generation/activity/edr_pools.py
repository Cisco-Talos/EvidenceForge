# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Loader for EDR object diversity pools.

Loads edr_pools.yaml from the package config directory, merged with
a user overlay from .eforge/config/activity/edr_pools.yaml if present.
"""

from __future__ import annotations

import codecs
import logging
import random
import re
import shlex
from typing import Any

import yaml

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_EDR_POOLS_PATH = get_activity_directory() / "edr_pools.yaml"
_CACHED: dict[str, Any] | None = None
logger = logging.getLogger(__name__)

_DEFENDER_PLATFORM_VERSIONS = ("4.18.2301.6-0", "4.18.24010.12-0", "4.18.24030.9-0")
_DEFAULT_RUNMRU_COMMANDS = (
    "cmd.exe /k dir",
    "cmd.exe /k whoami",
    "cmd.exe /c ipconfig",
    "powershell.exe -NoExit Get-ChildItem",
    "notepad.exe",
)
_USERASSIST_RUNPATHS = (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Slack.lnk",
    r"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Teams.lnk",
    r"C:\Windows\System32\mstsc.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
)
_DEFAULT_INSTALLED_SOFTWARE_PRODUCTS = (
    {
        "name": "Microsoft Update Health Tools",
        "publisher": "Microsoft Corporation",
        "version": "5.72.0.0",
    },
)
_WINDOWS_SERVICE_USERS = {
    "ANONYMOUS LOGON",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "SYSTEM",
}
_LINUX_SERVICE_USERS = {
    "_apt",
    "apache",
    "backup",
    "chrony",
    "daemon",
    "dnsmasq",
    "games",
    "gnats",
    "httpd",
    "irc",
    "list",
    "lp",
    "mail",
    "man",
    "messagebus",
    "mysql",
    "news",
    "nginx",
    "nobody",
    "ntp",
    "postgres",
    "proxy",
    "redis",
    "root",
    "sshd",
    "sync",
    "sys",
    "syslog",
    "systemd-network",
    "systemd-resolve",
    "systemd-timesync",
    "tomcat",
    "uucp",
    "www-data",
}
_LINUX_ROOT_ONLY_FILE_PREFIXES = (
    "/var/cache/apt/",
    "/var/lib/apt/",
    "/var/lib/dnf/",
    "/var/lib/dpkg/",
    "/var/log/apt/",
)


def _merge_edr_pools(default: dict, overlay: dict) -> dict:
    """Merge overlay into defaults — top-level keys replace entirely.

    A user who overrides `file_paths_windows:` gets exactly their list,
    not a merge with the defaults. Sections not present in the overlay
    are preserved from the defaults.
    """
    result = dict(default)
    for key, value in overlay.items():
        result[key] = value
    return result


def load_edr_pools() -> dict[str, Any]:
    """Load EDR pool config, merged with overlay. Cached after first call."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    with open(_EDR_POOLS_PATH) as f:
        defaults = yaml.safe_load(f)

    merged = load_with_overlay(
        _EDR_POOLS_PATH,
        "activity/edr_pools.yaml",
        _merge_edr_pools,
    )
    _CACHED = _sanitize_edr_pools(defaults, merged)
    return _CACHED


def _is_valid_string_list(value: Any) -> bool:
    return (
        isinstance(value, list) and len(value) > 0 and all(isinstance(item, str) for item in value)
    )


def _is_valid_registry_pool(value: Any) -> bool:
    if not isinstance(value, list) or len(value) == 0:
        return False
    for item in value:
        if not isinstance(item, list | tuple) or len(item) != 3:
            return False
        if not all(isinstance(field, str) and field for field in item):
            return False
    return True


def _is_valid_installed_software_products(value: Any) -> bool:
    if not isinstance(value, list) or len(value) == 0:
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        required = ("name", "publisher", "version")
        if any(not isinstance(item.get(field), str) or not item.get(field) for field in required):
            return False
    return True


def _sanitize_edr_pools(defaults: dict[str, Any], merged: dict[str, Any]) -> dict[str, Any]:
    """Validate merged EDR pools and fall back to defaults for malformed sections."""
    validators: dict[str, Any] = {
        "file_paths_windows": _is_valid_string_list,
        "file_paths_linux": _is_valid_string_list,
        "dll_pool": _is_valid_string_list,
        "runmru_commands": _is_valid_string_list,
        "registry_keys_hkcu": _is_valid_registry_pool,
        "registry_keys_hklm": _is_valid_registry_pool,
        "installed_software_products": _is_valid_installed_software_products,
    }
    sanitized = dict(defaults)
    for key, validator in validators.items():
        candidate = merged.get(key)
        if validator(candidate):
            sanitized[key] = candidate
        else:
            logger.warning(
                "Invalid EDR pool section %s in overlay-merged config; falling back to package defaults",
                key,
            )
    candidate_profiles = merged.get("file_side_effect_profiles")
    if isinstance(candidate_profiles, list) and all(
        isinstance(p, dict) for p in candidate_profiles
    ):
        sanitized["file_side_effect_profiles"] = candidate_profiles
    elif "file_side_effect_profiles" in defaults:
        sanitized["file_side_effect_profiles"] = defaults["file_side_effect_profiles"]
    return sanitized


def get_file_paths(os_category: str) -> list[str]:
    """Return file path pool for the given OS category."""
    pools = load_edr_pools()
    key = "file_paths_windows" if os_category == "windows" else "file_paths_linux"
    return pools.get(key, [])


def _principal_name(user: str) -> str:
    """Return the account leaf name from a source-native principal string."""
    return user.rsplit("\\", 1)[-1].strip()


def is_service_account(os_category: str, user: str) -> bool:
    """Return True when a principal should not use an interactive profile path."""
    account = _principal_name(user)
    if not account:
        return True
    if os_category == "windows":
        return account.upper() in _WINDOWS_SERVICE_USERS or account.endswith("$")
    return account.lower() in _LINUX_SERVICE_USERS


def file_path_templates_for_user(
    templates: list[str],
    os_category: str,
    user: str,
) -> list[str]:
    """Return templates compatible with the account's source-native profile model."""
    compatible = list(templates)

    if is_service_account(os_category, user):
        if os_category == "windows":
            filtered = [
                template
                for template in compatible
                if not template.lower().startswith(r"c:\users\{user}".lower())
            ]
        else:
            filtered = [
                template for template in compatible if not template.startswith("/home/{user}/")
            ]
        compatible = filtered or compatible

    if os_category == "linux" and _principal_name(user).lower() != "root":
        compatible = [
            template for template in compatible if not _requires_linux_root_file_ownership(template)
        ]

    return compatible


def _requires_linux_root_file_ownership(template: str) -> bool:
    """Return True when a Linux file template should only be written by root."""
    normalized = template.lower()
    return any(normalized.startswith(prefix) for prefix in _LINUX_ROOT_ONLY_FILE_PREFIXES)


def _uses_interactive_profile_template(template: str, os_category: str) -> bool:
    """Return True when a file template requires a normal user profile root."""
    if os_category == "windows":
        return template.lower().startswith(r"c:\users\{user}".lower())
    return template.startswith("/home/{user}/")


def get_registry_keys_hkcu() -> list[tuple[str, str, str]]:
    """Return HKCU registry key pool as (key, value_name, details) tuples."""
    pools = load_edr_pools()
    return [(k, vn, d) for k, vn, d in pools.get("registry_keys_hkcu", [])]


def get_registry_keys_hklm() -> list[tuple[str, str, str]]:
    """Return HKLM registry key pool as (key, value_name, details) tuples."""
    pools = load_edr_pools()
    return [(k, vn, d) for k, vn, d in pools.get("registry_keys_hklm", [])]


def get_dll_pool() -> list[str]:
    """Return DLL path pool for module load events."""
    pools = load_edr_pools()
    return pools.get("dll_pool", [])


def _installed_software_product(rng: random.Random) -> dict[str, str]:
    """Return one data-driven installed software product template."""
    products = load_edr_pools().get(
        "installed_software_products",
        list(_DEFAULT_INSTALLED_SOFTWARE_PRODUCTS),
    )
    if not _is_valid_installed_software_products(products):
        products = list(_DEFAULT_INSTALLED_SOFTWARE_PRODUCTS)
    product = rng.choice(products)
    return {
        "name": str(product["name"]),
        "publisher": str(product["publisher"]),
        "version": str(product["version"]),
    }


def _installed_product_guid(host_key: str, product_name: str) -> str:
    """Return a host-stable uninstall key GUID for an installed product."""
    seed_key = f"installed_product_guid:{host_key or 'default'}:{product_name}"
    return (
        f"{_stable_seed(seed_key) & 0xFFFFFFFF:08X}-"
        f"{(_stable_seed(f'{seed_key}:a') >> 16) & 0xFFFF:04X}-"
        f"{(_stable_seed(f'{seed_key}:b') >> 16) & 0xFFFF:04X}-"
        f"{(_stable_seed(f'{seed_key}:c') >> 16) & 0xFFFF:04X}-"
        f"{_stable_seed(f'{seed_key}:d') & 0xFFFFFFFFFFFF:012X}"
    )


def defender_platform_version(host_key: str) -> str:
    """Return one stable Windows Defender platform version for a host."""
    seed = _stable_seed(f"defender_platform_version:{host_key or 'default'}")
    return _DEFENDER_PLATFORM_VERSIONS[seed % len(_DEFENDER_PLATFORM_VERSIONS)]


def normalize_defender_platform_path(path: str, host_key: str) -> str:
    """Keep Windows Defender Platform paths version-consistent per host."""
    normalized = path.replace("/", "\\")
    marker = "\\Windows Defender\\Platform\\"
    marker_index = normalized.lower().find(marker.lower())
    if marker_index == -1:
        return path

    prefix_end = marker_index + len(marker)
    prefix = normalized[:prefix_end]
    suffix = normalized[prefix_end:]
    if not suffix:
        return f"{prefix}{defender_platform_version(host_key)}"

    first, separator, remainder = suffix.partition("\\")
    if first.lower().startswith("4.18.") and separator:
        suffix = remainder
    return f"{prefix}{defender_platform_version(host_key)}\\{suffix}"


def _windows_component_build(host_os: str, host_key: str) -> str:
    """Return the CBS package build family for a Windows host."""
    normalized = host_os.lower()
    if "server 2022" in normalized or "windows server 2022" in normalized:
        return "10.0.20348"
    if "server 2019" in normalized or "windows server 2019" in normalized:
        return "10.0.17763"
    if "windows 11" in normalized:
        return "10.0.22621"
    if "server" in normalized and "2022" in normalized:
        return "10.0.20348"
    if "server" in normalized and "2019" in normalized:
        return "10.0.17763"
    if "10" in normalized:
        return "10.0.19041"

    # Unknown Windows hosts still get a stable build family instead of a single
    # hardcoded value across the whole environment.
    fallback = ("10.0.19041", "10.0.17763", "10.0.20348", "10.0.22621")
    return fallback[
        _stable_seed(f"windows_component_build:{host_key or 'default'}") % len(fallback)
    ]


def _interface_guid(rng: random.Random, host_key: str, host_ip: str) -> str:
    """Return a stable interface GUID when host context is known."""
    if not host_key and not host_ip:
        return (
            f"{rng.getrandbits(32):08X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(48):012X}"
        )
    seed_key = f"interface_guid:{host_key}:{host_ip}"
    return (
        f"{_stable_seed(seed_key) & 0xFFFFFFFF:08X}-"
        f"{(_stable_seed(f'{seed_key}:a') >> 16) & 0xFFFF:04X}-"
        f"{(_stable_seed(f'{seed_key}:b') >> 16) & 0xFFFF:04X}-"
        f"{(_stable_seed(f'{seed_key}:c') >> 16) & 0xFFFF:04X}-"
        f"{_stable_seed(f'{seed_key}:d') & 0xFFFFFFFFFFFF:012X}"
    )


def _userassist_value_name(rng: random.Random, user: str) -> str:
    """Return a ROT13 UserAssist run-path value name with a real path payload."""
    username = user if user and user.upper() != "SYSTEM" else "Default"
    path = rng.choice(_USERASSIST_RUNPATHS).format(user=username)
    return codecs.decode(f"UEME_RUNPATH:{path}", "rot_13")


def _userassist_binary_details(rng: random.Random) -> str:
    """Return plausible REG_BINARY-looking UserAssist details, not a tiny placeholder."""
    byte_count = rng.choice([32, 40, 48])
    return " ".join(f"{rng.getrandbits(8):02X}" for _ in range(byte_count))


def _runmru_value_name(rng: random.Random) -> str:
    """Return a plausible RunMRU value slot."""
    return chr(ord("a") + rng.randint(0, 15))


def _runmru_command(rng: random.Random, user: str) -> str:
    """Return a varied RunMRU command with the source-native terminator."""
    commands = load_edr_pools().get("runmru_commands", _DEFAULT_RUNMRU_COMMANDS)
    command_template = str(rng.choice(commands))
    username = user or "Default"
    command = re.sub(r"\{(user|username)\}", username, command_template)
    return command if command.endswith("\\1") else f"{command}\\1"


def materialize_edr_template(
    template: str,
    rng: random.Random,
    user: str = "SYSTEM",
    *,
    host_ip: str = "",
    host_key: str = "",
    host_os: str = "",
) -> str:
    """Materialize common EDR pool template placeholders deterministically from an RNG."""
    version = rng.choice(["1.0", "2.1", "4.8", "16.0", "24.2", "125.0", "2024.3"])
    installed_product = _installed_software_product(rng)
    template_lower = template.lower()
    if "windows defender\\platform" in template_lower:
        version = defender_platform_version(host_key)
    elif "google\\chrome\\application" in template_lower:
        version = rng.choice(["121.0.6167.185", "122.0.6261.129", "123.0.6312.86"])
    elif "microsoft onedrive" in template_lower:
        version = rng.choice(["24.020.0128.0003", "24.045.0303.0002", "24.070.0407.0003"])
    replacements = {
        "user": user,
        "username": user,
        "host_ip": host_ip,
        "rand": f"{rng.randint(10000, 99999)}",
        "small": str(rng.randint(1, 80)),
        "minute": f"{rng.randint(0, 59):02d}",
        "hex": f"{rng.getrandbits(32):08X}",
        "os_build": _windows_component_build(host_os, host_key),
        "installed_product_guid": _installed_product_guid(host_key, installed_product["name"]),
        "installed_product_name": installed_product["name"],
        "installed_product_publisher": installed_product["publisher"],
        "installed_product_version": installed_product["version"],
        "guid": (
            _interface_guid(rng, host_key, host_ip)
            if "services\\tcpip\\parameters\\interfaces" in template_lower
            else f"{rng.getrandbits(32):08X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(48):012X}"
        ),
        "mru": str(rng.randint(0, 24)),
        "runmru_name": _runmru_value_name(rng),
        "runmru_command": _runmru_command(rng, user),
        "doc": str(rng.randint(1, 80)),
        "userassist_value": _userassist_value_name(rng, user),
        "userassist_binary": _userassist_binary_details(rng),
        "package": rng.choice(
            [
                "Package_for_RollupFix",
                "Package_for_ServicingStack",
                "Package_for_KB5034122",
                "Package_for_DotNetRollup",
                "Microsoft-Windows-Client-Features",
            ]
        ),
        "version": version,
    }

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        return str(replacements[token]) if token in replacements else match.group(0)

    materialized = re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, template)
    materialized = materialized.replace("{{", "{").replace("}}", "}")
    return normalize_defender_platform_path(materialized, host_key)


def materialize_edr_template_group(
    templates: tuple[str, ...],
    rng: random.Random,
    user: str = "SYSTEM",
    *,
    host_key: str = "",
    host_ip: str = "",
    host_os: str = "",
) -> tuple[str, ...]:
    """Materialize related templates with one shared placeholder context."""
    version = rng.choice(["1.0", "2.1", "4.8", "16.0", "24.2", "125.0", "2024.3"])
    installed_product = _installed_software_product(rng)
    combined_lower = "\n".join(templates).lower()
    if "windows defender\\platform" in combined_lower:
        version = defender_platform_version(host_key)
    elif "google\\chrome\\application" in combined_lower:
        version = rng.choice(["121.0.6167.185", "122.0.6261.129", "123.0.6312.86"])
    elif "microsoft onedrive" in combined_lower:
        version = rng.choice(["24.020.0128.0003", "24.045.0303.0002", "24.070.0407.0003"])
    replacements = {
        "user": user,
        "username": user,
        "host_ip": host_ip,
        "rand": f"{rng.randint(10000, 99999)}",
        "small": str(rng.randint(1, 80)),
        "minute": f"{rng.randint(0, 59):02d}",
        "hex": f"{rng.getrandbits(32):08X}",
        "os_build": _windows_component_build(host_os, host_key),
        "installed_product_guid": _installed_product_guid(host_key, installed_product["name"]),
        "installed_product_name": installed_product["name"],
        "installed_product_publisher": installed_product["publisher"],
        "installed_product_version": installed_product["version"],
        "guid": (
            _interface_guid(rng, host_key, host_ip)
            if "services\\tcpip\\parameters\\interfaces" in combined_lower
            else f"{rng.getrandbits(32):08X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(16):04X}-"
            f"{rng.getrandbits(48):012X}"
        ),
        "mru": str(rng.randint(0, 24)),
        "runmru_name": _runmru_value_name(rng),
        "runmru_command": _runmru_command(rng, user),
        "doc": str(rng.randint(1, 80)),
        "userassist_value": _userassist_value_name(rng, user),
        "userassist_binary": _userassist_binary_details(rng),
        "package": rng.choice(
            [
                "Package_for_RollupFix",
                "Package_for_ServicingStack",
                "Package_for_KB5034122",
                "Package_for_DotNetRollup",
                "Microsoft-Windows-Client-Features",
            ]
        ),
        "version": version,
    }

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        return str(replacements[token]) if token in replacements else match.group(0)

    return tuple(
        normalize_defender_platform_path(
            re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, template)
            .replace("{{", "{")
            .replace("}}", "}"),
            host_key,
        )
        for template in templates
    )


def select_file_side_effect(
    process_name: str,
    command_line: str,
    os_category: str,
    rng: random.Random,
    user: str = "SYSTEM",
) -> tuple[str, str] | None:
    """Return a process-aware file side effect from data-driven EDR profiles."""
    exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command_lower = command_line.lower()
    semantic_effect = _select_command_semantic_file_effect(exe, command_line)
    if semantic_effect is not None:
        return semantic_effect

    profiles = load_edr_pools().get("file_side_effect_profiles", [])
    for profile in profiles:
        exact = {str(item).lower() for item in profile.get("executables", [])}
        contains = [str(item).lower() for item in profile.get("executable_contains", [])]
        command_contains = [str(item).lower() for item in profile.get("command_contains", [])]
        if exe not in exact and not any(marker in exe for marker in contains):
            if not any(marker in command_lower for marker in command_contains):
                continue

        probability = float(profile.get("probability", 1.0))
        if probability <= 0 or rng.random() > probability:
            return None

        paths_key = "paths_windows" if os_category == "windows" else "paths_linux"
        paths = profile.get(paths_key, [])
        actions = profile.get("actions", ["modify"])
        if not paths or not actions:
            return None
        action = str(rng.choice(actions)).lower()
        raw_path_templates = [str(path) for path in paths]
        path_templates = file_path_templates_for_user(raw_path_templates, os_category, user)
        if not path_templates:
            return None
        if (
            is_service_account(os_category, user)
            and path_templates == raw_path_templates
            and any(
                _uses_interactive_profile_template(template, os_category)
                for template in raw_path_templates
            )
        ):
            return None
        path = materialize_edr_template(str(rng.choice(path_templates)), rng, user=user)
        if (
            exe in {"bash", "sh"}
            and user.lower() in {"apache", "www-data", "nginx", "httpd", "tomcat"}
            and path.endswith("/.bash_history")
        ):
            non_history_paths = _exclude_paths(path_templates, ("/.bash_history",))
            if not non_history_paths:
                return None
            path = materialize_edr_template(str(rng.choice(non_history_paths)), rng, user=user)
        if os_category == "windows" and _is_windows_powershell_history_path(path):
            if not _allows_psreadline_history(exe, command_line, user):
                non_history_paths = _exclude_paths(
                    path_templates,
                    ("\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",),
                )
                if not non_history_paths:
                    return None
                path = materialize_edr_template(str(rng.choice(non_history_paths)), rng, user=user)
        if os_category == "linux" and user == "root":
            path = path.replace("/home/root/", "/root/")
        return action, path
    return None


def select_ambient_file_churn_effect(
    process_name: str,
    command_line: str,
    os_category: str,
    rng: random.Random,
    user: str,
    path_templates: list[str],
    actions: list[str],
    weights: list[int],
    *,
    host_ip: str = "",
    host_key: str = "",
    host_os: str = "",
) -> tuple[str, str] | None:
    """Return an account-compatible ambient FILE churn action and path."""
    if os_category == "linux" and is_service_account(os_category, user):
        return select_file_side_effect(process_name, command_line, os_category, rng, user=user)

    candidates = file_path_templates_for_user(path_templates, os_category, user)
    if not candidates:
        return None

    action = str(rng.choices(actions, weights=weights, k=1)[0])
    path = materialize_edr_template(
        str(rng.choice(candidates)),
        rng,
        user,
        host_ip=host_ip,
        host_key=host_key,
        host_os=host_os,
    )
    if os_category == "linux" and user == "root":
        path = path.replace("/home/root/", "/root/")
    return action, path


def select_command_file_side_effect(process_name: str, command_line: str) -> tuple[str, str] | None:
    """Return a guaranteed command-owned file artifact when the syntax identifies one."""
    exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    return _select_command_semantic_file_effect(exe, command_line)


def _select_command_semantic_file_effect(
    exe: str,
    command_line: str,
) -> tuple[str, str] | None:
    """Return command-owned file artifacts for common shell tools."""
    command_lower = command_line.lower()
    if exe == "mysqldump":
        match = re.search(r">\s*(?P<path>\S+)", command_line)
        if match:
            return "create", _clean_extracted_path(match.group("path"))

    if exe in {"powershell.exe", "powershell", "pwsh.exe", "pwsh"} and "compress-archive" in (
        command_lower
    ):
        match = re.search(
            r"-(?:DestinationPath|Destination)\s+(?:'(?P<sq>[^']+)'|\"(?P<dq>[^\"]+)\"|(?P<bare>\S+))",
            command_line,
            flags=re.IGNORECASE,
        )
        if match:
            return "create", _clean_extracted_path(
                match.group("sq") or match.group("dq") or match.group("bare")
            )

    if exe == "gzip":
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()
        operands = [part for part in parts[1:] if not part.startswith("-")]
        if operands:
            return "create", f"{_clean_extracted_path(operands[-1])}.gz"

    if exe in {"tar", "zip"}:
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()
        for idx, part in enumerate(parts):
            if part in {"-f", "--file"} and idx + 1 < len(parts):
                return "create", _clean_extracted_path(parts[idx + 1])
            if part.endswith((".tar", ".tar.gz", ".tgz", ".zip")):
                return "create", _clean_extracted_path(part)

    return None


def _clean_extracted_path(path: str) -> str:
    """Trim command-shell quoting artifacts from a path captured by syntax."""
    return path.strip().strip("\"'")


def _exclude_paths(paths: list[Any], suffixes: tuple[str, ...]) -> list[Any]:
    """Return path templates that do not end with any forbidden suffix."""
    normalized_suffixes = tuple(suffix.replace("/", "\\").lower() for suffix in suffixes)
    return [
        candidate
        for candidate in paths
        if not str(candidate).replace("/", "\\").lower().endswith(normalized_suffixes)
    ]


def _is_windows_powershell_history_path(path: str) -> bool:
    normalized = path.replace("/", "\\").lower()
    return normalized.endswith("\\powershell\\psreadline\\consolehost_history.txt")


def _allows_psreadline_history(exe: str, command_line: str, user: str) -> bool:
    """Return whether a Windows process can realistically write PSReadLine history."""
    if exe not in {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}:
        return False
    if user.lower() in {"system", "local service", "network service"}:
        return False
    command_lower = command_line.lower()
    noninteractive_markers = (
        "-command",
        "-encodedcommand",
        "-enc",
        "-file",
        "-noninteractive",
    )
    return not any(marker in command_lower for marker in noninteractive_markers)
