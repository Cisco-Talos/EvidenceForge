# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Suspicious-but-benign ambient noise generator.

Generates occasional events that look suspicious in isolation but have
legitimate explanations. These make the dataset feel more realistic by
ensuring analysts encounter false leads alongside real attack activity.

Configurable via baseline_activity.suspicious_noise:
  low=~1/hr, medium=~2/hr, high=~3/hr, ludicrous=~5/hr
"""

import base64
import logging
import random
from datetime import datetime, timedelta

from evidenceforge.models.scenario import Persona, System, User

logger = logging.getLogger(__name__)

# Intensity mapping: level -> (mean events per hour)
SUSPICIOUS_NOISE_INTENSITY = {
    "low": 2.0,
    "medium": 4.0,
    "high": 6.0,
    "ludicrous": 10.0,
}

# PowerShell commands that look suspicious but are benign admin/dev tasks
_BENIGN_POWERSHELL = [
    r"powershell.exe -Command Get-Service | Where-Object {$_.Status -eq 'Stopped'}",
    r"powershell.exe -Command Get-EventLog -LogName System -Newest 50",
    r"powershell.exe -Command Test-Connection -ComputerName dc01 -Count 2",
    r"powershell.exe -Command Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
    r"powershell.exe -Command Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, FreeSpace",
    r"powershell.exe -Command Invoke-WebRequest -Uri https://packages.nuget.org/api/v2 -UseBasicParsing",
    r"powershell.exe -Command Get-ADUser -Filter * -SearchBase 'OU=IT,DC=corp,DC=local'",
    r"powershell.exe -Command Get-ChildItem C:\Logs -Recurse -Filter *.log | Measure-Object",
]

# cmd.exe commands that look like recon but are routine admin tasks
_BENIGN_CMD = [
    "cmd.exe /c net user /domain",
    'cmd.exe /c net group "Domain Admins" /domain',
    "cmd.exe /c netstat -an | findstr LISTENING",
    "cmd.exe /c tasklist /svc",
    "cmd.exe /c systeminfo",
    "cmd.exe /c dir \\\\fileserv\\shared$ /s /b",
    "cmd.exe /c wmic process list brief",
    "cmd.exe /c ipconfig /all",
]

# Linux commands that look suspicious but are normal sysadmin tasks
_BENIGN_LINUX_CMD = [
    "find / -perm -4000 -type f 2>/dev/null",
    "cat /etc/shadow",
    "ss -tulnp",
    "curl -s http://169.254.169.254/latest/meta-data/",
    "awk -F: '$3 == 0 {print $1}' /etc/passwd",
    "last -n 50",
    "journalctl -u sshd --since '1 hour ago'",
    "lsof -i :22",
]


def get_suspicious_event_count(noise_level: str, rng: random.Random) -> int:
    """Get the number of suspicious events to generate for this hour.

    Uses a Poisson-like distribution around the mean for the noise level.
    """
    mean = SUSPICIOUS_NOISE_INTENSITY.get(noise_level, 3.0)
    # Poisson-distributed count (approximated via random choices)
    count = 0
    for _ in range(int(mean * 2)):
        if rng.random() < 0.5:
            count += 1
    return count


def pick_suspicious_pattern(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    personas: list[Persona] | None,
    current_hour: datetime,
) -> dict | None:
    """Pick a suspicious-but-benign event pattern for this hour.

    Returns a dict with pattern info or None if no suitable pattern found.
    Weights patterns by environment composition.
    """
    if not users or not systems:
        return None

    # Build available pattern types weighted by environment
    patterns = []

    # After-hours admin activity (weight higher if sysadmin personas exist)
    has_sysadmins = _has_persona_type(users, personas, "sysadmin")
    patterns.append(("after_hours_admin", 3 if has_sysadmins else 1))

    # PowerShell/cmd on non-admin workstations (weight higher if developers exist)
    has_developers = _has_persona_type(users, personas, "developer")
    patterns.append(("suspicious_cli", 3 if has_developers else 1))

    # Failed logon burst (always relevant)
    patterns.append(("failed_logon_burst", 2))

    # Service account anomaly (weight higher if service_accounts exist)
    patterns.append(("service_account_anomaly", 2))

    # Network-level red herrings
    patterns.append(("suspicious_dns", 2))
    patterns.append(("unusual_outbound", 2))
    patterns.append(("scheduled_scan_overlap", 1))

    # Process-based anomalies
    patterns.append(("temp_dir_execution", 2))
    patterns.append(("unusual_powershell", 2 if has_sysadmins else 1))

    pattern_names = [p[0] for p in patterns]
    pattern_weights = [p[1] for p in patterns]

    chosen = rng.choices(pattern_names, weights=pattern_weights, k=1)[0]

    return {
        "type": chosen,
        "users": users,
        "systems": systems,
        "current_hour": current_hour,
    }


def _has_persona_type(users: list[User], personas: list[Persona] | None, persona_name: str) -> bool:
    """Check if any user has the specified persona type."""
    return any(u.persona == persona_name for u in users)


def generate_after_hours_admin(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate an after-hours admin login event.

    Returns dict with user, system, time, and activity info for the caller
    to execute via ActivityGenerator.
    """
    # Pick sysadmin or any admin-like user
    admin_users = [u for u in users if u.persona in ("sysadmin", "help_desk", "security_analyst")]
    if not admin_users:
        admin_users = users[:3]  # Fallback: pick from first few users

    user = rng.choice(admin_users)
    servers = [s for s in systems if s.type in ("server", "domain_controller")]
    system = rng.choice(servers) if servers else rng.choice(systems)

    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    return {
        "pattern": "after_hours_admin",
        "user": user,
        "system": system,
        "time": event_time,
        "logon_type": 10 if rng.random() < 0.4 else 3,  # RDP or network
    }


def generate_suspicious_cli(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate a suspicious CLI command from a non-attacker user."""
    user = rng.choice(users)
    system_candidates = [s for s in systems if s.assigned_user == user.username]
    system = rng.choice(system_candidates) if system_candidates else rng.choice(systems)

    os_cat = _get_os_category(system)
    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    if os_cat == "windows":
        if rng.random() < 0.6:
            cmd = rng.choice(_BENIGN_POWERSHELL)
            process = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        else:
            cmd = rng.choice(_BENIGN_CMD)
            process = r"C:\Windows\System32\cmd.exe"
    else:
        cmd = rng.choice(_BENIGN_LINUX_CMD)
        process = cmd.split()[0]
        # Resolve to full path for common tools
        if "/" not in process:
            process = f"/usr/bin/{process}"

    return {
        "pattern": "suspicious_cli",
        "user": user,
        "system": system,
        "time": event_time,
        "process_name": process,
        "command_line": cmd,
    }


def generate_failed_logon_burst(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate a burst of failed logons followed by success (fat-fingered password)."""
    user = rng.choice(users)
    system_candidates = [s for s in systems if s.assigned_user == user.username]
    system = rng.choice(system_candidates) if system_candidates else rng.choice(systems)

    offset = timedelta(seconds=rng.randint(0, 3500))
    start_time = current_hour + offset
    num_failures = rng.randint(2, 5)

    return {
        "pattern": "failed_logon_burst",
        "user": user,
        "system": system,
        "time": start_time,
        "num_failures": num_failures,
    }


def generate_service_account_anomaly(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate a service account logging in from an unusual host."""
    # Find service-like users
    svc_users = [u for u in users if u.username.lower().startswith(("svc", "sa_", "_"))]
    if not svc_users:
        # Use any user as fallback
        svc_users = users[:2]

    user = rng.choice(svc_users)

    # Pick a system that's NOT the user's primary (unusual host)
    other_systems = [s for s in systems if s.hostname != (user.primary_system or "")]
    system = rng.choice(other_systems) if other_systems else rng.choice(systems)

    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    return {
        "pattern": "service_account_anomaly",
        "user": user,
        "system": system,
        "time": event_time,
        "logon_type": 3,
    }


# Suspicious-looking but legitimate DNS query patterns
_BENIGN_SUSPICIOUS_DNS_HOSTS = [
    # High-entropy CDN/analytics subdomains (look like DGA but are legitimate)
    "a1b2c3d4e5.cloudfront.net",
    "x7k9m2.akamaized.net",
    "cdn-b4f8a2.azureedge.net",
    "f3d7e1a9b2c4.fastly.net",
    "tr-8a2f4b.doubleclick.net",
    # DNS-over-HTTPS / privacy services (look like tunneling)
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "doh.opendns.com",
    # Rare TLDs that look suspicious but are legitimate
    "corp-updates.io",
    "developer-portal.dev",
    "status-monitor.app",
    "internal-metrics.cloud",
    # Long subdomains (look like encoding/tunneling)
    "session-f8a2b4c6d8e0-tracking.analytics.customeriq.net",
    "pixel-7f3a9b2e1d4c.marketing-cdn.com",
    "telemetry-x9k2m4.windows.com",
]

# Unusual but legitimate outbound connection targets
_BENIGN_UNUSUAL_CONNECTIONS = [
    # Cloud regions the org doesn't normally use
    {
        "dst_ip": "13.236.8.128",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "ec2.ap-southeast-2.amazonaws.com",
        "desc": "AWS ap-southeast-2 (dev testing)",
    },
    {
        "dst_ip": "20.205.243.166",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "copilot.github.com",
        "desc": "GitHub Copilot endpoint",
    },
    {
        "dst_ip": "104.16.0.35",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "api.cloudflare.com",
        "desc": "Cloudflare API",
    },
    # Package registries and dev tools
    {
        "dst_ip": "151.101.0.63",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "pypi.org",
        "desc": "PyPI package download",
    },
    {
        "dst_ip": "185.125.190.39",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "snapcraft.io",
        "desc": "Ubuntu snap store",
    },
    {
        "dst_ip": "34.104.35.123",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "gcr.io",
        "desc": "Google Container Registry",
    },
    # Large outbound transfers (look like exfil but are backup/sync)
    {
        "dst_ip": "52.216.84.0",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "s3.amazonaws.com",
        "desc": "AWS S3 backup sync",
    },
    {
        "dst_ip": "13.107.42.14",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "onedrive.live.com",
        "desc": "OneDrive sync",
    },
    {
        "dst_ip": "142.250.80.46",
        "dst_port": 443,
        "service": "ssl",
        "hostname": "drive.google.com",
        "desc": "Google Drive upload",
    },
]


def generate_suspicious_dns(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate suspicious-looking but benign DNS query.

    Produces queries to high-entropy CDN subdomains, DNS-over-HTTPS
    providers, or rare TLDs that might trigger DGA detection rules
    but are actually legitimate.
    """
    system = rng.choice(systems)
    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset
    hostname = rng.choice(_BENIGN_SUSPICIOUS_DNS_HOSTS)

    return {
        "pattern": "suspicious_dns",
        "system": system,
        "time": event_time,
        "hostname": hostname,
    }


def generate_unusual_outbound(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate unusual but legitimate outbound connection.

    Connections to unfamiliar cloud regions, dev tool endpoints, or
    large outbound transfers that are actually backup/sync operations.
    """
    # Prefer workstations as source (dev testing, cloud sync)
    workstations = [s for s in systems if s.type == "workstation"]
    system = rng.choice(workstations) if workstations else rng.choice(systems)

    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset
    conn_info = rng.choice(_BENIGN_UNUSUAL_CONNECTIONS)

    return {
        "pattern": "unusual_outbound",
        "system": system,
        "time": event_time,
        "dst_ip": conn_info["dst_ip"],
        "dst_port": conn_info["dst_port"],
        "service": conn_info["service"],
        "hostname": conn_info.get("hostname"),
        "large_transfer": "backup" in conn_info["desc"].lower()
        or "sync" in conn_info["desc"].lower(),
    }


def generate_scheduled_scan_overlap(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate vulnerability scan traffic that overlaps with attack window.

    Multi-port connection burst from a server that looks like network
    scanning but is actually a scheduled Nessus/Qualys scan.
    """
    servers = [s for s in systems if s.type in ("server", "domain_controller")]
    if not servers or len(systems) < 3:
        return None

    scanner = rng.choice(servers)
    targets = rng.sample(
        [s for s in systems if s != scanner],
        min(rng.randint(3, 6), len(systems) - 1),
    )
    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    return {
        "pattern": "scheduled_scan_overlap",
        "scanner": scanner,
        "targets": targets,
        "time": event_time,
    }


def generate_temp_dir_execution(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate a process execution from a temp directory (benign installer/update)."""
    user = rng.choice(users)
    system_candidates = [s for s in systems if s.assigned_user == user.username]
    system = rng.choice(system_candidates) if system_candidates else rng.choice(systems)

    os_cat = _get_os_category(system)
    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    if os_cat == "windows":
        temp_exes = [
            (r"C:\Users\{user}\AppData\Local\Temp\vs_installer.exe", "vs_installer.exe /quiet"),
            (r"C:\Users\{user}\AppData\Local\Temp\ChromeSetup.exe", "ChromeSetup.exe --silent"),
            (r"C:\Users\{user}\AppData\Local\Temp\msi_update.exe", "msi_update.exe /norestart"),
            (
                r"C:\Users\{user}\AppData\Local\Temp\dotnet-sdk-installer.exe",
                "dotnet-sdk-installer.exe /install /quiet",
            ),
            (r"C:\Windows\Temp\KB5034441_update.exe", "KB5034441_update.exe /quiet"),
        ]
        exe_path, cmd = rng.choice(temp_exes)
        exe_path = exe_path.replace("{user}", user.username)
    else:
        temp_exes = [
            ("/tmp/pip-install-cache/setup.py", "python3 /tmp/pip-install-cache/setup.py install"),
            ("/tmp/go-build-cache/main", "/tmp/go-build-cache/main --test"),
            ("/tmp/npm-postinstall.sh", "bash /tmp/npm-postinstall.sh"),
        ]
        exe_path, cmd = rng.choice(temp_exes)

    return {
        "pattern": "temp_dir_execution",
        "user": user,
        "system": system,
        "time": event_time,
        "process_name": exe_path,
        "command_line": cmd,
    }


# Benign PowerShell command templates for base64-encoded commands.
# Each invocation picks a template, substitutes parameters, then encodes
# as UTF-16LE + base64 (matching real PowerShell -EncodedCommand format).
_ENCODED_PS_TEMPLATES = [
    "Get-Service -Name {svc}",
    "Get-EventLog -LogName {log} -Newest {n}",
    "Test-NetConnection {host} -Port {port}",
    "Get-Process -Name {proc}",
    "Get-ChildItem -Path C:\\{dir} -Recurse | Measure-Object",
    "Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, FreeSpace",
    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First {n}",
]

_ENCODED_PS_PARAMS: dict[str, list[str]] = {
    "svc": ["Spooler", "W32Time", "wuauserv", "BITS", "WinRM", "Dhcp", "Dnscache", "EventLog"],
    "log": ["System", "Application", "Security", "Setup"],
    "n": ["10", "25", "50", "100"],
    "host": ["dc01", "fileserver", "10.0.0.1", "localhost", "gateway"],
    "port": ["80", "443", "3389", "5985", "22"],
    "proc": ["svchost", "explorer", "chrome", "outlook", "code", "winlogon"],
    "dir": ["Logs", "Temp", "Reports", "Users\\Public"],
}


def _generate_encoded_command(rng: random.Random) -> str:
    """Generate a unique base64-encoded benign PowerShell command.

    Picks a random template, substitutes parameters, then encodes as
    UTF-16LE base64 — matching real Windows PowerShell -EncodedCommand format.
    """
    template = rng.choice(_ENCODED_PS_TEMPLATES)
    cmd = template
    for key, values in _ENCODED_PS_PARAMS.items():
        placeholder = "{" + key + "}"
        if placeholder in cmd:
            cmd = cmd.replace(placeholder, rng.choice(values))
    return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")


def generate_unusual_powershell(
    rng: random.Random,
    users: list[User],
    systems: list[System],
    current_hour: datetime,
) -> dict | None:
    """Generate PowerShell with suspicious-looking flags (benign admin scripts)."""
    # Only Windows systems
    windows_systems = [s for s in systems if "windows" in s.os.lower()]
    if not windows_systems:
        return None

    user = rng.choice(users)
    system_candidates = [s for s in windows_systems if s.assigned_user == user.username]
    system = rng.choice(system_candidates) if system_candidates else rng.choice(windows_systems)

    offset = timedelta(seconds=rng.randint(0, 3599))
    event_time = current_hour + offset

    _LOG_DIRS = ["Logs", "AppLogs", "EventExport", "Temp\\Logs", "Audit"]
    _BACKUP_NAMES = ["logs-backup", "archive", "audit-export", "monthly-logs", "cleanup"]
    _SCRIPT_NAMES = [
        "deploy-monitoring.ps1",
        "health-check.ps1",
        "patch-audit.ps1",
        "compliance-scan.ps1",
        "cert-renewal.ps1",
    ]
    _REPORT_NAMES = ["audit", "security-review", "compliance", "weekly-report", "incident"]
    _API_PATHS = ["/health", "/status", "/api/v1/check", "/metrics", "/readiness"]

    log_dir = rng.choice(_LOG_DIRS)
    backup = rng.choice(_BACKUP_NAMES)
    script = rng.choice(_SCRIPT_NAMES)
    report = rng.choice(_REPORT_NAMES)
    api_path = rng.choice(_API_PATHS)

    suspicious_ps = [
        rf'powershell.exe -WindowStyle Hidden -Command "Get-WinEvent -LogName Security -MaxEvents {rng.choice([50, 100, 200, 500])} | Export-Csv C:\Reports\{report}.csv"',
        f"powershell.exe -EncodedCommand {_generate_encoded_command(rng)}",
        rf"powershell.exe -Exec Bypass -File C:\Scripts\{script}",
        rf'powershell.exe -NonInteractive -Command "Invoke-RestMethod -Uri https://internal-api.corp.local{api_path}"',
        rf'powershell.exe -WindowStyle Hidden -Command "Compress-Archive -Path C:\{log_dir}\*.log -DestinationPath C:\Backups\{backup}.zip"',
    ]

    cmd = rng.choice(suspicious_ps)
    return {
        "pattern": "unusual_powershell",
        "user": user,
        "system": system,
        "time": event_time,
        "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": cmd,
    }


def _get_os_category(system: System) -> str:
    """Determine OS category from system OS string."""
    os_lower = system.os.lower()
    if "windows" in os_lower:
        return "windows"
    return "linux"
