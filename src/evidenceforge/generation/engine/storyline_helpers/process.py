# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Storyline process helpers without coordinator dependencies."""

import re
import shlex

from evidenceforge.generation.activity.application_catalog import resolve_image_path

_IPV4_LITERAL_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _normalize_storyline_process_image(
    process_name: str,
    os_category: str,
    username: str = "",
) -> str:
    """Normalize a storyline executable to the canonical full path when possible."""
    if "\\" in process_name or "/" in process_name:
        return process_name
    return resolve_image_path(process_name, os_category, username=username)


def _linux_shell_process_command_line(process_name: str, command_line: str) -> str | None:
    """Return an explicit shell invocation for Linux shell process specs."""
    exe = process_name.rsplit("/", 1)[-1].lower()
    if exe not in {"bash", "dash", "sh", "zsh"}:
        return None
    try:
        parts = shlex.split(command_line, comments=False, posix=True)
    except ValueError:
        parts = command_line.split()
    if not parts:
        return f"{exe} -c ''"
    first = parts[0].rsplit("/", 1)[-1].lower()
    if first == exe:
        return command_line
    return f"{exe} -c {shlex.quote(command_line)}"


_SHORT_COMMANDS: set[str] = {
    # Windows recon
    "whoami",
    "whoami.exe",
    "ipconfig",
    "ipconfig.exe",
    "hostname",
    "hostname.exe",
    "systeminfo",
    "systeminfo.exe",
    "tasklist",
    "tasklist.exe",
    "nltest",
    "nltest.exe",
    "dir",
    "type",
    "findstr",
    "findstr.exe",
    "reg",
    "reg.exe",
    "net.exe",
    "net1.exe",
    "net",
    "net1",
    "query",
    "klist",
    "klist.exe",
    "nslookup",
    "nslookup.exe",
    "netstat",
    "netstat.exe",
    "arp",
    "arp.exe",
    "route",
    "route.exe",
    "qwinsta",
    "qwinsta.exe",
    "dsquery",
    "dsquery.exe",
    # Linux recon
    "id",
    "uname",
    "ifconfig",
    "cat",
    "ls",
    "ps",
    "ss",
    "find",
    "grep",
    "awk",
    "head",
    "tail",
    "wc",
    "env",
    "printenv",
    "df",
    "mount",
    "w",
    "last",
    "ip",
    "hostnamectl",
}


_MEDIUM_COMMANDS: set[str] = {
    "powershell.exe",
    "powershell",
    "pwsh",
    "certutil",
    "certutil.exe",
    "bitsadmin",
    "bitsadmin.exe",
    "wmic",
    "wmic.exe",
    "schtasks",
    "schtasks.exe",
    "sc",
    "sc.exe",
    "mshta",
    "mshta.exe",
    "cscript",
    "cscript.exe",
    "wscript",
    "wscript.exe",
    "rundll32",
    "rundll32.exe",
    "cmd.exe",
    "cmd",  # cmd itself is medium; the inner command may be short
    "msbuild",
    "msbuild.exe",
    "regsvr32",
    "regsvr32.exe",
    # Linux attack tools
    "curl",
    "wget",
    "python",
    "python3",
    "perl",
    "ruby",
    "mysqldump",
    "pg_dump",
    "tar",
    "gzip",
    "zip",
    "scp",
}


_LONG_RUNNING_PATTERNS: list[str] = [
    "TCPClient",
    "TCPListener",
    "$s.Read",
    "ncat",
    "socat",
    "nc -l",
    "nc.exe -l",
    "meterpreter",
    "beacon",
    "reverse_tcp",
    "bind_tcp",
    "-persist",
    "--keep-alive",
    "while(true)",
    "while True",
    "Start-Sleep -Seconds 99",
    "tail -f",
]


_LONG_RUNNING_EXES: set[str] = {
    "mstsc.exe",
    "mstsc",
    "rdpclip.exe",
    "rdpclip",
    "healthmonitorsvc.exe",
    "ncat",
    "ncat.exe",
    "nc",
    "nc.exe",
    "socat",
}


def _estimate_process_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Estimate how long a story process should run before terminating.

    Returns (min_seconds, max_seconds) for the termination delay,
    or None if the process should be left running (long-lived/persistent).
    """
    # Extract bare executable name
    if "\\" in process_name:
        exe = process_name.rsplit("\\", 1)[-1].lower()
    elif "/" in process_name:
        exe = process_name.rsplit("/", 1)[-1].lower()
    else:
        exe = process_name.lower()

    if exe == "psexesvc.exe":
        return (8.0, 45.0)

    # Check long-running first
    if exe in _LONG_RUNNING_EXES:
        return None
    cl_lower = command_line.lower()
    for pattern in _LONG_RUNNING_PATTERNS:
        if pattern.lower() in cl_lower:
            return None

    # For cmd.exe /c, classify based on the inner command
    if exe in ("cmd.exe", "cmd") and "/c " in cl_lower:
        inner = cl_lower.split("/c ", 1)[1].strip()
        inner_exe = inner.split()[0] if inner else ""
        # Strip path from inner exe
        if "\\" in inner_exe:
            inner_exe = inner_exe.rsplit("\\", 1)[-1]
        elif "/" in inner_exe:
            inner_exe = inner_exe.rsplit("/", 1)[-1]
        if inner_exe in _SHORT_COMMANDS:
            return (0.3, 3.0)
        if inner_exe in _MEDIUM_COMMANDS:
            return (3.0, 20.0)

    if exe in _SHORT_COMMANDS:
        return (0.3, 5.0)
    if exe in _MEDIUM_COMMANDS:
        return (5.0, 30.0)

    # Default: medium-lived unknown command
    return (2.0, 15.0)


def _extract_schtasks_option(command_line: str, option: str) -> str:
    """Extract a quoted or bare schtasks.exe option value."""
    if not command_line:
        return ""
    option_name = option.lstrip("/")
    match = re.search(
        rf'(?:^|\s)/{re.escape(option_name)}\s+(?:"(?P<quoted>[^"]*)"|(?P<bare>\S+))',
        command_line,
        flags=re.IGNORECASE,
    )
    if match is None:
        return ""
    return (match.group("quoted") or match.group("bare") or "").strip()


def _extract_sc_create_service_start_type(command_line: str) -> tuple[str, str] | None:
    """Extract service name and native start type from an sc.exe create command."""
    if not command_line:
        return None
    match = re.search(
        r'\bsc(?:\.exe)?\s+create\s+(\S+)\s+binpath=\s*"?([^"]+)"?',
        command_line,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    service_name = match.group(1)
    service_start_type = "3"
    start_match = re.search(
        r"\bstart=\s*(delayed-auto|auto|demand|disabled|boot|system)\b",
        command_line,
        flags=re.IGNORECASE,
    )
    if start_match is not None:
        service_start_type = {
            "boot": "0",
            "system": "1",
            "auto": "2",
            "delayed-auto": "2",
            "demand": "3",
            "disabled": "4",
        }[start_match.group(1).lower()]
    return service_name, service_start_type
