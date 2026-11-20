# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared process execution policy and timing helpers."""

from __future__ import annotations

import logging
import ntpath
import random
import re
import shlex
from datetime import datetime
from typing import Any

from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.activity.process_lifetimes import (
    numeric_sleep_seconds as numeric_sleep_seconds,
)
from evidenceforge.generation.activity.process_lifetimes import (
    posix_command_lifetime,
    unwrapped_command,
)
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)

_SYSTEM_ACCOUNTS = {"SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"}

_SYSTEM_ACCOUNT_LOGON_IDS = {
    "SYSTEM": "0x3e7",
    "LOCAL SERVICE": "0x3e5",
    "NETWORK SERVICE": "0x3e4",
}

_PROCESS_ENDPOINT_ACTION_COHORT_MEMBER_LIMIT = 256


def normalize_process_command(
    process_name: str,
    command_line: str,
    *,
    os_category: str,
    hostname: str,
) -> tuple[str, str, str]:
    """Return the normalized image, command and executable classification without sampling."""
    if os_category == "windows":
        process_name, command_line = _windows_script_host_process(process_name, command_line)
    executable = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if os_category == "windows" and executable == "psexesvc.exe":
        process_name = r"C:\Windows\PSEXESVC.exe"
        if "accepteula" in command_line.lower():
            command_line = r"C:\Windows\PSEXESVC.exe"
    return normalize_defender_platform_path(process_name, hostname), command_line, executable


def _windows_script_host_process(
    process_name: str,
    command_line: str,
) -> tuple[str, str]:
    """Return the real Windows process image for batch-script execution."""
    basename = ntpath.basename(process_name).lower()
    if not basename.endswith((".cmd", ".bat")):
        return process_name, command_line

    host_image = r"C:\Windows\System32\cmd.exe"
    stripped = command_line.strip()
    command_lower = stripped.lower()
    if command_lower.startswith(("cmd.exe ", r"c:\windows\system32\cmd.exe ")):
        return host_image, command_line
    if command_lower.startswith("cmd "):
        return host_image, f"cmd.exe {stripped[4:]}"
    return host_image, f"cmd.exe /c {stripped or ntpath.basename(process_name)}"


def _windows_service_process_account(process_name: str, command_line: str) -> str | None:
    """Return the built-in service identity for service-hosted Windows processes."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    normalized_path = ntpath.normpath(process_name.replace("/", "\\")).lower()
    if exe_name in {"psexesvc.exe", "healthmonitorsvc.exe"} or normalized_path == (
        r"c:\windows\system32\searchindexer.exe"
    ):
        return "SYSTEM"
    if exe_name != "svchost.exe":
        return None
    if "localservice" in command:
        return "LOCAL SERVICE"
    if "networkservice" in command:
        return "NETWORK SERVICE"
    if "dcomlaunch" in command or "netsvcs" in command or "-s schedule" in command:
        return "SYSTEM"
    return None


def _linux_foreground_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Estimate foreground Linux command lifetime for shell-history ordering."""
    return posix_command_lifetime(process_name, command_line)


def _linux_shell_process_reserves_foreground(process_name: str, command_line: str) -> bool:
    """Return whether a shell child owns its interactive shell's foreground slot."""
    normalized = f" {command_line.strip().lower()} "
    if not command_line.strip():
        return False
    if command_line.rstrip().endswith("&") or " nohup " in normalized:
        return False
    if any(pattern in normalized for pattern in (" tail -f ", " watch ", " --follow ")):
        return False
    if any(
        marker in normalized
        for marker in (
            " tmux new-session -d ",
            " tmux new -d ",
            " screen -d -m ",
            " setsid ",
        )
    ):
        return False
    exe_name = process_name.rsplit("/", 1)[-1].lower()
    return exe_name not in {"code", "codium", "gnome-terminal", "konsole", "xterm"}


def _macos_foreground_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Classify a Mac foreground command's lifetime.

    A command admitted by its spawn profile's short templates keeps that profile's
    timing. Application bundles and their helpers, and catalogued long-lived Mac
    applications, stay unbounded (session or operation owned). Every other command,
    including a catalogued short command used in another form, uses the lifetime
    table shared with Linux: it ends as it would there, and listeners, followed
    output and interactive shells stay unbounded on both.
    """
    from evidenceforge.generation.activity.spawn_rules import get_parent_config

    name = process_name.rsplit("/", 1)[-1]
    profile = get_parent_config("macos", name)
    profiled = _macos_profiled_short_lifetime(profile, command_line)
    if profiled is not None:
        return profiled
    wrapped = unwrapped_command(process_name, command_line)
    if wrapped is not None:
        return _macos_foreground_lifetime(*wrapped)
    if ".app/Contents/" in process_name or profile.get("lifetime") == "long":
        return None
    return posix_command_lifetime(process_name, command_line)


def _macos_profiled_short_lifetime(
    profile: dict[str, Any], command_line: str
) -> tuple[float, float] | None:
    """Bound a command only when it matches one of its profile's short templates.

    These are modeled bounds, not calibrated workstation measurements. Existing
    overlay templates control admission.
    """
    if profile.get("lifetime") != "short":
        return None
    try:
        command = shlex.split(command_line)
    except ValueError:
        return None
    for template in profile.get("command_templates", []):
        try:
            expected = shlex.split(template)
        except ValueError:
            continue
        if len(command) != len(expected):
            continue
        # Placeholder values stay within their original argv element; a new
        # option or shell operator cannot turn an admitted query into a daemon.
        if all(
            re.fullmatch(re.sub(r"\\\{[a-zA-Z_]+\\\}", ".+", re.escape(pattern)), value)
            for pattern, value in zip(expected, command, strict=True)
        ):
            timing = profile.get("short_timing")
            if timing is not None:
                from evidenceforge.config.schemas import ShortCommandTiming

                bounds = ShortCommandTiming.model_validate(timing)
                return (bounds.minimum, bounds.maximum)
            return (0.05, 45.0)
    return None


def _posix_foreground_lifetime(
    os_category: str, process_name: str, command_line: str
) -> tuple[float, float] | None:
    """Select platform policy while preserving existing Linux timing exactly."""
    if os_category == "macos":
        return _macos_foreground_lifetime(process_name, command_line)
    return _linux_foreground_lifetime(process_name, command_line)


def _macos_process_uses_shell(process_name: str) -> bool:
    """Read explicit launch ownership before the legacy application-path fallback."""
    from evidenceforge.generation.activity.spawn_rules import get_parent_config

    profile = get_parent_config("macos", process_name.rsplit("/", 1)[-1])
    if profile.get("launch_kind") is not None:
        return profile["launch_kind"] == "shell"
    return ".app/Contents/MacOS/" not in process_name


def _posix_shell_process_reserves_foreground(
    os_category: str, process_name: str, command_line: str
) -> bool:
    """Recognize shell occupancy without importing Linux daemon policy into Mac."""
    if os_category != "macos":
        return _linux_shell_process_reserves_foreground(process_name, command_line)
    if not _macos_process_uses_shell(process_name) or not command_line.strip():
        return False
    # Following output still occupies a Mac foreground shell. Only explicit
    # background intent releases it; an unknown end is never a fabricated exit.
    return not command_line.rstrip().endswith("&")


def _is_bare_windows_explorer_launch(process_name: str, command_line: str) -> bool:
    """Return whether Explorer represents the durable desktop shell itself."""

    process_exe = process_name.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    if process_exe != "explorer.exe":
        return False
    normalized_command = command_line.strip().strip('"').replace("/", "\\").casefold()
    return normalized_command in {
        "explorer.exe",
        r"c:\windows\explorer.exe",
    }


def _process_termination_delay_after_activity_seconds(
    *,
    hostname: str,
    pid: int,
    last_activity_time: datetime,
) -> float:
    """Return the stable grace period after a process's last activity."""
    delay_rng = random.Random(
        _stable_seed(
            f"process_terminate_after_activity:{hostname}:{pid}:{last_activity_time.isoformat()}"
        )
    )
    return delay_rng.uniform(2.0, 30.0)
