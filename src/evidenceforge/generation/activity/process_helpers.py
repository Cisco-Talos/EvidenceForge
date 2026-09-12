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
from decimal import Decimal, InvalidOperation

from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
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
    exe_name = process_name.rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    follows_output = (
        any(pattern in command for pattern in ("tail -f", "watch ", "--follow"))
        or (exe_name == "journalctl" and " -f " in f" {command} ")
        or (
            exe_name in {"docker", "kubectl"}
            and " logs " in f" {command} "
            and " -f " in f" {command} "
        )
    )
    if follows_output:
        return None
    if "/usr/lib/apt/methods/" in process_name.lower() or command.startswith(
        "/usr/lib/apt/methods/"
    ):
        return (5.0, 60.0)
    if exe_name in {"python", "python3", "node", "npm", "git"} and any(
        marker in f" {command} " for marker in (" --version ", " -v ", " version ")
    ):
        return (0.05, 2.0)
    if exe_name in {"apt", "apt-get", "dnf", "yum"} and any(
        token in command for token in ("update", "upgradable", "makecache", "check-update")
    ):
        return (20.0, 180.0)
    if exe_name in {
        "cat",
        "date",
        "ls",
        "pwd",
        "true",
        "whoami",
        "id",
        "uname",
        "hostname",
        "df",
        "free",
    }:
        return (0.05, 0.8)
    if exe_name == "sleep":
        try:
            argv = shlex.split(command_line)
        except ValueError:
            argv = []
        if (
            len(argv) == 2
            and argv[0].rsplit("/", 1)[-1].lower() == "sleep"
            and re.fullmatch(r"(?:\d+(?:\.\d*)?|\.\d+)", argv[1]) is not None
        ):
            try:
                requested = Decimal(argv[1])
            except InvalidOperation:
                requested = Decimal(-1)
            if requested.is_finite() and requested >= 0:
                bounded = min(requested, Decimal(86_400))
                bounded_seconds = float(bounded)
                lower = max(0.05, bounded_seconds)
                completion_slack = min(2.0, max(0.05, bounded_seconds * 0.02))
                return (lower, lower + completion_slack)
        return (0.2, 2.0)
    if exe_name == "test":
        return (0.2, 2.0)
    if exe_name in {"mysql", "psql"}:
        if " -p " in f" {command} " or command.endswith(" -p"):
            return (8.0, 45.0)
        return (1.5, 12.0)
    if exe_name in {"sqlite3", "redis-cli", "pg_isready"}:
        return (0.8, 8.0)
    if exe_name in {"systemctl", "journalctl"}:
        return (0.8, 9.0)
    if exe_name in {"du", "find"}:
        return (0.8, 8.0)
    if exe_name in {"grep", "head", "tail", "wc", "env", "printenv", "ss", "ip", "ps"}:
        return (0.35, 5.0)
    if exe_name in {"curl", "wget"}:
        return (0.8, 12.0)
    if exe_name == "smbclient":
        return (1.0, 20.0) if " -c " in f" {command} " else None
    if exe_name == "git":
        if any(token in f" {command} " for token in (" pull ", " fetch ", " clone ")):
            return (3.0, 90.0)
        return (0.3, 12.0)
    if exe_name == "npm" and " run build" in command:
        return (8.0, 180.0)
    if exe_name == "ssh":
        return (30.0, 3600.0)
    if exe_name in {"gzip", "tar", "zip", "scp", "kubectl", "docker"}:
        return (3.0, 18.0)
    if exe_name in {"make", "gcc", "cargo", "npm", "python", "python3", "mysqldump"}:
        return (8.0, 45.0)
    if exe_name in {"code", "codium"}:
        return None
    if exe_name in {"vim", "vi", "nano", "emacs"}:
        return (20.0, 95.0)
    return (1.0, 8.0)


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
