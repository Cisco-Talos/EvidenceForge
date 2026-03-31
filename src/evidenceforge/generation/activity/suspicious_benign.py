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

import logging
import random
from datetime import datetime, timedelta

from evidenceforge.models.scenario import Persona, System, User

logger = logging.getLogger(__name__)

# Intensity mapping: level -> (mean events per hour)
SUSPICIOUS_NOISE_INTENSITY = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
    "ludicrous": 5.0,
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


def _get_os_category(system: System) -> str:
    """Determine OS category from system OS string."""
    os_lower = system.os.lower()
    if "windows" in os_lower:
        return "windows"
    return "linux"
