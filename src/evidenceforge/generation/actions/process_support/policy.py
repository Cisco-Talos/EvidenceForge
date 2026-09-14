# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared pure process, shell, image and lifecycle policy."""

from __future__ import annotations

import logging
import random
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from evidenceforge.events.authentication import WINDOWS_DESKTOP_LOGON_TYPES
from evidenceforge.events.content_identity import Platform
from evidenceforge.generation.actions import (
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ProcessExecutionRequest,
)
from evidenceforge.generation.actions.endpoint_effects import PreparedProcessEffectActor
from evidenceforge.generation.actions.process_execution import (
    ProcessLifetimeMode,
    ProcessLifetimePlan,
)
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.network_common import _command_tokens as _command_tokens
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNT_LOGON_IDS
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS as _SYSTEM_ACCOUNTS
from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime as _linux_foreground_lifetime,
)
from evidenceforge.generation.runtime_content import RuntimeArtifactOwnerKind
from evidenceforge.generation.timing import (
    DistributionSpec,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
)
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

logger = logging.getLogger(__name__)

_WINDOWS_SINGLETON_SERVICE_EXES = frozenset(
    {
        "spoolsv.exe",
        "dns.exe",
        "dfsr.exe",
        "ismserv.exe",
        "msdtc.exe",
        "searchindexer.exe",
    }
)

_WINDOWS_SINGLETON_SERVICE_PATHS = {
    exe: {f"c:\\windows\\system32\\{exe}"} for exe in _WINDOWS_SINGLETON_SERVICE_EXES
}

_FOREGROUND_SHELL_INITIAL_READY_MIN_MS = 1_800

_FOREGROUND_SHELL_INITIAL_READY_SPAN_MS = 5_200

_PROCESS_SOURCE_BOUND_MAX_ANCESTORS = 65_536

_WINDOWS_SINGLETON_SYSTEM_PROCESSES = {
    "smss.exe": "smss",
    "csrss.exe": "csrss_s0",
    "wininit.exe": "wininit",
    "services.exe": "services",
    "lsass.exe": "lsass",
    "searchindexer.exe": "search_indexer",
}

_WINDOWS_USER_SESSION_PROCESSES = {
    "sihost.exe",
    "searchhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "runtimebroker.exe",
    "textinputhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "applicationframehost.exe",
}

_WINDOWS_ONE_SHOT_CLI_EXES = {
    "dsquery.exe",
    "gpresult.exe",
    "gpupdate.exe",
    "ipconfig.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "quser.exe",
    "qwinsta.exe",
    "tasklist.exe",
    "whoami.exe",
    "wmic.exe",
}

_WINDOWS_BROWSER_EXES = frozenset(
    {"chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe", "opera.exe"}
)

_PERSISTENT_USER_APP_EXES = frozenset(
    {
        "evolution",
        "outlook.exe",
        "onedrive.exe",
        "teams.exe",
        "thunderbird",
        "thunderbird.exe",
    }
)

_WINDOWS_BROWSER_CHILD_MARKERS = (
    "--type=",
    "--utility-sub-type=",
    "-contentproc",
    " -childid ",
    " /prefetch:",
)

_WINDOWS_ELECTRON_CHILD_EXES = frozenset({"slack.exe", "teams.exe", "zoom.exe"})

_WINDOWS_ELECTRON_CHILD_MARKERS = (
    "--type=",
    "--utility-sub-type=",
)

_WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES = WINDOWS_DESKTOP_LOGON_TYPES


def _session_started_by(session: Any, time: datetime) -> bool:
    """Return whether a session exists at the given activity time."""
    session_start = session.start_time
    if session_start.tzinfo is None:
        session_start = session_start.replace(tzinfo=UTC)
    else:
        session_start = session_start.astimezone(UTC)
    activity_time = time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)
    return session_start <= activity_time


def _session_activity_end_time(session: Any) -> datetime | None:
    """Return the earliest canonical boundary that ends session-owned activity."""
    deadlines: list[datetime] = []
    end_plan = getattr(session, "end_plan", None)
    if end_plan is not None:
        deadlines.append(ensure_utc(end_plan.canonical_end))
    network_close_time = getattr(session, "network_close_time", None)
    if network_close_time is not None:
        deadlines.append(ensure_utc(network_close_time))
    return min(deadlines) if deadlines else None


def _session_active_for_activity(
    session: Any, time: datetime, *, margin_seconds: float = 0.0
) -> bool:
    """Return whether a session can own activity at the given visible time."""
    if not _session_started_by(session, time):
        return False
    activity_end = _session_activity_end_time(session)
    if activity_end is None:
        return True
    activity_time = time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)
    return activity_time < activity_end - timedelta(seconds=margin_seconds)


def _session_source_ready_time(session: Any) -> datetime | None:
    """Return when source-visible child activity may begin for this session."""
    ready_time = getattr(session, "source_ready_time", None)
    return ensure_utc(ready_time) if ready_time is not None else None


def _extract_image_from_command(command_line: str) -> str:
    """Extract an executable image from a command line without truncating paths with spaces."""
    cleaned = command_line.strip()
    if not cleaned:
        return ""
    if cleaned[0] == '"':
        closing = cleaned.find('"', 1)
        if closing > 1:
            return cleaned[1:closing]

    import re

    match = re.match(r"^([A-Za-z]:\\.*?\.exe)\b", cleaned, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.match(r"^(/[^ ]+)", cleaned)
    if match:
        return match.group(1)
    return cleaned.split()[0]


_LINUX_FOREGROUND_SHELL_RELEASE_MAX_MS = 1_400

_LINUX_ONE_SHOT_NETWORK_EXES: set[str] = {
    "apt",
    "apt-get",
    "curl",
    "dnf",
    "git",
    "npm",
    "python3",
    "smbclient",
    "wget",
    "scp",
    "kubectl",
    "ldapsearch",
    "mysqldump",
}

_WINDOWS_SESSION_OWNED_EXECUTABLES = {
    "acrobat.exe",
    "chrome.exe",
    "code.exe",
    "excel.exe",
    "firefox.exe",
    "iexplore.exe",
    "msedge.exe",
    "notepad++.exe",
    "outlook.exe",
    "powerpnt.exe",
    "sublime_text.exe",
    "teams.exe",
    "winword.exe",
}


def _bounded_windows_lifetime(
    minimum_seconds: float,
    maximum_seconds: float,
    classification: str,
    *,
    mode: ProcessLifetimeMode = ProcessLifetimeMode.BOUNDED,
) -> ProcessLifetimePlan:
    """Build one validated bounded Windows process lifetime plan."""

    return ProcessLifetimePlan(
        mode=mode,
        minimum_seconds=minimum_seconds,
        maximum_seconds=maximum_seconds,
        classification=classification,
    )


def _windows_process_lifetime_plan(
    process_name: str,
    command_line: str,
) -> ProcessLifetimePlan:
    """Classify one Windows process lifetime before canonical publication."""

    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    padded_command = f" {command} "
    if any(
        pattern in command
        for pattern in (
            "tcpclient",
            "tcplistener",
            "$s.read",
            "start-sleep -seconds 99",
            "while(true)",
            "while true",
            " -listen",
            " -l ",
        )
    ):
        return ProcessLifetimePlan(
            mode=ProcessLifetimeMode.PERSISTENT,
            classification="explicit-continuous-command",
        )
    if exe_name in _WINDOWS_SESSION_OWNED_EXECUTABLES:
        return ProcessLifetimePlan(
            mode=ProcessLifetimeMode.SESSION_OWNED,
            classification="interactive-desktop-application",
        )
    if exe_name in {"runas.exe", "runas"}:
        return _bounded_windows_lifetime(0.4, 8.0, "runas-launcher")
    if exe_name in {"git.exe", "git"}:
        if any(
            marker in padded_command
            for marker in (" clone ", " fetch ", " pull ", " push ", " lfs ")
        ):
            return _bounded_windows_lifetime(
                3.0,
                180.0,
                "git-network-operation",
                mode=ProcessLifetimeMode.OPERATION_OWNED,
            )
        return _bounded_windows_lifetime(0.3, 20.0, "git-one-shot")
    if exe_name in {"kubectl.exe", "kubectl"}:
        continuous_markers = (
            " port-forward ",
            " proxy ",
            " logs -f ",
            " logs --follow ",
            " --watch ",
            " -w ",
        )
        if any(marker in padded_command for marker in continuous_markers):
            return ProcessLifetimePlan(
                mode=ProcessLifetimeMode.PERSISTENT,
                classification="kubectl-continuous-operation",
            )
        if " exec " in padded_command and any(
            marker in padded_command for marker in (" -it ", " -i ", " -t ")
        ):
            return ProcessLifetimePlan(
                mode=ProcessLifetimeMode.SESSION_OWNED,
                classification="kubectl-interactive-exec",
            )
        operation_mode = any(
            marker in padded_command
            for marker in (" apply ", " cp ", " create ", " delete ", " rollout ")
        )
        return _bounded_windows_lifetime(
            0.8,
            90.0 if operation_mode else 20.0,
            "kubectl-operation" if operation_mode else "kubectl-one-shot",
            mode=(
                ProcessLifetimeMode.OPERATION_OWNED
                if operation_mode
                else ProcessLifetimeMode.BOUNDED
            ),
        )
    if exe_name in {"curl.exe", "curl", "wget.exe", "wget"}:
        return _bounded_windows_lifetime(0.8, 12.0, "http-client")
    if exe_name == "service-healthcheck.exe":
        if "--service" in command:
            return ProcessLifetimePlan(
                mode=ProcessLifetimeMode.PERSISTENT,
                classification="service-health-worker",
            )
        return _bounded_windows_lifetime(2.0, 45.0, "service-health-check")
    if " check --once" in f" {command} ":
        return _bounded_windows_lifetime(2.0, 45.0, "explicit-one-shot-check")
    if any(marker in command for marker in ("--silent", " /quiet", " /norestart")) and any(
        marker in exe_name for marker in ("setup", "installer", "update", "updater", "msi")
    ):
        return _bounded_windows_lifetime(8.0, 360.0, "unattended-installer")
    if exe_name in {
        "whoami.exe",
        "hostname.exe",
        "ipconfig.exe",
        "nltest.exe",
        "klist.exe",
        "qwinsta.exe",
        "quser.exe",
        "query.exe",
        "cmdkey.exe",
        "net.exe",
        "net1.exe",
        "dsquery.exe",
        "dsget.exe",
        "dsmod.exe",
        "gpresult.exe",
        "gpupdate.exe",
        "tasklist.exe",
        "arp.exe",
        "route.exe",
        "netstat.exe",
        "sc.exe",
        "wevtutil.exe",
    }:
        return _bounded_windows_lifetime(0.4, 6.0, "administrative-utility")
    if exe_name == "cmd.exe":
        if " /c " in padded_command:
            return _bounded_windows_lifetime(0.4, 8.0, "cmd-one-shot-wrapper")
        return ProcessLifetimePlan(
            mode=ProcessLifetimeMode.SESSION_OWNED,
            classification="interactive-command-shell",
        )
    if exe_name in {"powershell.exe", "pwsh.exe"}:
        one_shot_markers = (
            " -command ",
            " -encodedcommand ",
            " -enc ",
            " -file ",
            " invoke-webrequest",
            " iwr ",
            " downloadstring",
        )
        if any(marker in padded_command for marker in one_shot_markers):
            return _bounded_windows_lifetime(2.0, 25.0, "powershell-one-shot")
        return ProcessLifetimePlan(
            mode=ProcessLifetimeMode.SESSION_OWNED,
            classification="interactive-powershell",
        )
    if exe_name in {"wmic.exe", "certutil.exe"}:
        return _bounded_windows_lifetime(4.0, 35.0, "administrative-operation")
    if exe_name == "sqlcmd.exe" and " -q " in f" {command} ":
        return _bounded_windows_lifetime(2.0, 25.0, "sql-query")
    return _bounded_windows_lifetime(
        1.0,
        8.0,
        "unclassified-foreground-candidate",
        mode=ProcessLifetimeMode.UNCLASSIFIED,
    )


def _windows_foreground_lifetime(
    process_name: str, command_line: str
) -> tuple[float, float] | None:
    """Return bounded legacy lifetime semantics for known Windows foreground tools."""

    plan = _windows_process_lifetime_plan(process_name, command_line)
    if plan.mode == ProcessLifetimeMode.UNCLASSIFIED:
        return None
    return plan.bounds


_LINUX_SERVICE_PARENT_KEYS = ("apache2", "httpd", "nginx", "php-fpm")

_LINUX_SERVICE_USERS = {"apache", "www-data", "nginx", "httpd"}

_LINUX_SHELLS = {"/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/bash", "/usr/bin/zsh"}

_WINDOWS_GUI_APPS = {
    "outlook.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "teams.exe",
    "onedrive.exe",
    "acrobat.exe",
    "7zfm.exe",
    "notepad++.exe",
    "idea64.exe",
    "sublime_text.exe",
    "code.exe",
}

_WINDOWS_SERVICE_SHELL_CHILDREN = {
    "arp.exe",
    "certutil.exe",
    "dcdiag.exe",
    "dnscmd.exe",
    "dsquery.exe",
    "gpresult.exe",
    "gpupdate.exe",
    "hostname.exe",
    "ipconfig.exe",
    "klist.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "nslookup.exe",
    "ping.exe",
    "reg.exe",
    "repadmin.exe",
    "route.exe",
    "sc.exe",
    "schtasks.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "tracert.exe",
    "wevtutil.exe",
    "whoami.exe",
    "wmic.exe",
}

_WINDOWS_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "WindowsTerminal.exe"}

_WINDOWS_SHELL_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}

_WINDOWS_SPAWNERS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "WindowsTerminal.exe",
    "outlook.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
}


def _is_top_level_browser_launch(process_name: str, command_line: str) -> bool:
    """Return whether a Windows browser command represents a user-facing process."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if exe_name not in _WINDOWS_BROWSER_EXES:
        return False
    command = f" {command_line.lower()} "
    return not any(marker in command for marker in _WINDOWS_BROWSER_CHILD_MARKERS)


def _is_one_shot_shell_command(process_name: str, command_line: str) -> bool:
    """Return whether a shell command is a short-lived command wrapper."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if exe_name not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
        return False
    return _windows_foreground_lifetime(process_name, command_line) is not None


def _windows_one_shot_shell_payload(process_name: str, command_line: str) -> str:
    """Return the inline command executed by a one-shot Windows shell."""
    shell_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.strip()
    if shell_exe == "cmd.exe":
        match = re.search(r"(?i)(?:^|\s)/(?:c|k)\s+(.+)$", command)
        return match.group(1).strip().strip('"') if match else ""
    if shell_exe in {"powershell.exe", "pwsh.exe"}:
        match = re.search(r"(?i)(?:^|\s)-(?:command|c)\s+(.+)$", command)
        return match.group(1).strip().strip('"') if match else ""
    return ""


def _windows_shell_command_signature(command_line: str) -> tuple[str, ...]:
    """Normalize a Windows command line for shell parent/child matching."""
    tokens = _command_tokens(command_line)
    if not tokens:
        return ()
    normalized: list[str] = []
    for index, token in enumerate(tokens):
        value = token.strip().strip('"').lower()
        if index == 0:
            value = value.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if value.endswith(".exe"):
                value = value[:-4]
        normalized.append(value)
    return tuple(normalized)


def _windows_child_command_signatures(
    process_name: str,
    command_line: str,
) -> set[tuple[str, ...]]:
    """Return command signatures that can represent a child process launch."""
    process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    process_stem = process_exe.removesuffix(".exe")
    signatures: set[tuple[str, ...]] = set()
    command_signature = _windows_shell_command_signature(command_line)
    if command_signature:
        signatures.add(command_signature)
        if command_signature[0] != process_stem:
            signatures.add((process_stem, *command_signature))
    else:
        signatures.add((process_stem,))
    return signatures


def _is_bare_interactive_windows_shell(process_name: str, command_line: str) -> bool:
    """Return whether a shell is an interactive prompt rather than an inline command."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if exe_name not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
        return False
    return not _is_one_shot_shell_command(process_name, command_line)


def _user_profile_directory(username: str) -> str:
    """Return the Windows profile directory for a process owner."""
    account = username.split("\\")[-1]
    if account in _SYSTEM_ACCOUNTS or account.endswith("$"):
        return r"C:\Windows\System32"
    return rf"C:\Users\{account}"


def _foreground_shell_release_time(
    *,
    system: System,
    username: str,
    logon_id: str,
    parent_pid: int,
    termination_time: datetime,
    seed_text: str,
) -> datetime:
    """Compute the established deterministic gap after an actual shell release."""
    rng = random.Random(
        _stable_seed(
            f"foreground_shell_release:{system.hostname}:{username}:{logon_id}:"
            f"{parent_pid}:{seed_text}:{termination_time.timestamp()}"
        )
    )
    return termination_time + timedelta(
        milliseconds=rng.randint(180, _LINUX_FOREGROUND_SHELL_RELEASE_MAX_MS)
    )


def _foreground_process_lifetime_for_attribution(
    system: System,
    proc: Any,
) -> tuple[float, float] | None:
    """Return bounded foreground lifetime for process-owned network attribution."""
    os_category = _get_os_category(system.os)
    if os_category == "windows":
        return _windows_foreground_lifetime(proc.image, proc.command_line)
    if os_category == "linux":
        exe_name = proc.image.rsplit("/", 1)[-1].lower()
        if "/usr/lib/apt/methods/" in str(proc.image).lower():
            return _linux_foreground_lifetime(proc.image, proc.command_line)
        if exe_name not in _LINUX_ONE_SHOT_NETWORK_EXES:
            return None
        return _linux_foreground_lifetime(proc.image, proc.command_line)
    return None


def _linux_background_helper_username(process_name: str, command_line: str) -> str:
    """Return the service principal for a Linux background helper process."""
    exe_name = process_name.lower().rsplit("/", 1)[-1]
    if exe_name == "java" and "integration-worker" in command_line.lower():
        return "www-data"
    return "root"


def _linux_process_is_system_background_helper(process_name: str, command_line: str) -> bool:
    """Return whether a Linux helper should be modeled as daemon/timer-owned."""
    image_lower = process_name.lower()
    command_lower = command_line.lower()
    exe_name = image_lower.rsplit("/", 1)[-1]
    if image_lower.startswith("/usr/lib/apt/methods/"):
        return True
    if exe_name in {"dnf", "yum"} and any(
        token in command_lower for token in ("makecache", "check-update", "update")
    ):
        return True
    if exe_name == "service-healthcheck":
        return True
    return exe_name == "java" and "integration-worker" in command_lower


def _process_provisional_termination_timing_request(
    request: ProcessExecutionRequest,
    actor: PreparedProcessEffectActor,
    lifetime_plan: ProcessLifetimePlan,
) -> tuple[DistributionSpec, str, TimingScope, str]:
    """Return one deterministic lifetime draw request for preview and commit."""

    lifetime = lifetime_plan.bounds
    if lifetime is None:
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_PLAN,
            "provisional process termination timing requires bounded lifetime ownership",
        )
    minimum_seconds, maximum_seconds = lifetime
    mode_seconds = minimum_seconds + (maximum_seconds - minimum_seconds) * 0.34
    os_category = _get_os_category(request.system.os)
    if os_category == "windows":
        distribution: DistributionSpec = TriangularDistribution(
            minimum=minimum_seconds * 1_000_000,
            mode=mode_seconds * 1_000_000,
            maximum=maximum_seconds * 1_000_000,
        )
        relationship_key = "activity.process.windows_foreground_lifetime"
        sample_key = f"provisional_close:{actor.stable_id}:{lifetime_plan.mode.value}"
    elif os_category == "linux":
        distribution = TruncatedLognormalDistribution(
            median=mode_seconds * 1_000_000,
            sigma=0.78,
            minimum=minimum_seconds * 1_000_000,
            maximum=maximum_seconds * 1_000_000,
        )
        relationship_key = "activity.process.linux_foreground_lifetime"
        sample_key = "provisional_close"
    else:
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_PLAN,
            "provisional process termination timing requires Windows or Linux",
        )
    return (
        distribution,
        relationship_key,
        TimingScope(
            stable_id=request.stable_id,
            host=request.system.hostname,
            source="endpoint_process",
            lifecycle_id=actor.lifecycle_id,
        ),
        sample_key,
    )


def _materialize_module_profile_path(
    path: str,
    *,
    system: System,
    username: str,
    pid: int,
    process_start: datetime,
) -> str:
    """Resolve one module template without consuming an ambient RNG stream."""
    from evidenceforge.generation.activity.edr_pools import materialize_edr_template

    rng = random.Random(
        _stable_seed(f"module-profile:{system.hostname}:{pid}:{process_start.isoformat()}:{path}")
    )
    return materialize_edr_template(
        path,
        rng,
        username,
        host_key=system.hostname,
        host_ip=system.ip,
        host_os=system.os,
    )


def _reconcile_generator_cleanup(
    primary: BaseException,
    label: str,
    cleanup: Callable[[], object],
) -> bool:
    """Run one idempotent cleanup twice at most without masking its primary."""

    failures: list[BaseException] = []
    for _attempt in range(2):
        try:
            cleanup()
            return True
        except BaseException as failure:
            failures.append(failure)
    for failure in failures:
        try:
            primary.add_note(
                f"Generator {label} cleanup also failed with "
                f"{type(failure).__module__}.{type(failure).__qualname__}"
            )
        except BaseException:
            continue
    return False


_WINDOWS_SHELL_UWP_USER_PROCESS_EXES = frozenset(
    {
        "sihost.exe",
        "searchhost.exe",
        "runtimebroker.exe",
        "backgroundtaskhost.exe",
        "textinputhost.exe",
        "startmenuexperiencehost.exe",
        "shellexperiencehost.exe",
        "applicationframehost.exe",
    }
)


def system_process_roles(
    existing: dict[str, dict[str, int]] | None,
) -> dict[str, dict[str, int]]:
    """Use the existing role table, or a fresh fallback for an unseeded generator read."""
    return existing if existing is not None else {}


_FILE_ACTION_EVENT_TYPES = {
    "read": "file_read",
    "create": "file_create",
    "modify": "file_modify",
    "delete": "file_delete",
}


def _runtime_artifact_owner_kind(
    platform: Platform,
    principal: str,
    logon_id: str,
) -> RuntimeArtifactOwnerKind:
    """Classify one process owner consistently for runtime artifact publication."""

    if (
        principal in _SYSTEM_ACCOUNTS
        or logon_id in _SYSTEM_ACCOUNT_LOGON_IDS.values()
        or (platform == "linux" and principal == "root")
    ):
        return "system"
    return "user"
