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

"""Activity generation logic for log events.

This module provides the ActivityGenerator class which generates specific
activity events (logon, logoff, process creation, network connections) and
coordinates them across multiple log formats for consistency.
"""

import base64
import hashlib
import heapq
import ipaddress
import itertools
import logging
import math
import ntpath
import quopri
import random
import re
import shlex
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Optional
from urllib.parse import urlsplit

import yaml

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    EdrContext,
    EmailContext,
    FileContext,
    FileTransferContext,
    FirewallContext,
    HostContext,
    HttpContext,
    IdsContext,
    ImageLoadContext,
    KerberosContext,
    NetworkContext,
    OcspContext,
    PeContext,
    ProcessAccessContext,
    ProcessContext,
    ProxyContext,
    RegistryContext,
    RemoteThreadContext,
    SmtpContext,
    SslContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions import (
    AccountChangedActionBundle,
    AccountChangedRequest,
    AccountCreatedActionBundle,
    AccountCreatedRequest,
    AccountDeletedActionBundle,
    AccountDeletedRequest,
    AnonymousLogonActionBundle,
    AnonymousLogonRequest,
    CreateRemoteThreadActionBundle,
    CreateRemoteThreadRequest,
    DhcpLeaseActionBundle,
    DhcpLeaseRequest,
    DnsLookupActionBundle,
    DnsLookupRequest,
    EmailAccessActionBundle,
    EmailAccessRequest,
    EmailDeliveryActionBundle,
    EmailDeliveryRequest,
    EmailDeliveryResult,
    ExplicitCredentialUseActionBundle,
    ExplicitCredentialUseRequest,
    FailedLogonActionBundle,
    FailedLogonRequest,
    GroupMembershipChangeActionBundle,
    GroupMembershipChangeRequest,
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
    KerberosConnectionAuditActionBundle,
    KerberosConnectionAuditRequest,
    KerberosLogonTicketsActionBundle,
    KerberosLogonTicketsRequest,
    KerberosPreauthFailureActionBundle,
    KerberosPreauthFailureRequest,
    KerberosServiceTicketActionBundle,
    KerberosServiceTicketRequest,
    KerberosTgtActionBundle,
    KerberosTgtRenewalActionBundle,
    KerberosTgtRenewalRequest,
    KerberosTgtRequest,
    LinuxShellCommandActionBundle,
    LinuxShellCommandRequest,
    LogClearedActionBundle,
    LogClearedRequest,
    LogoffActionBundle,
    LogoffRequest,
    LogonActionBundle,
    LogonRequest,
    MachineAccountLogonActionBundle,
    MachineAccountLogonRequest,
    NetworkConnectionActionBundle,
    NetworkConnectionRequest,
    NmapCommandProbeActionBundle,
    NmapCommandProbeRequest,
    NtlmValidationActionBundle,
    NtlmValidationRequest,
    PasswordChangeActionBundle,
    PasswordChangeRequest,
    PasswordResetActionBundle,
    PasswordResetRequest,
    ProcessAccessActionBundle,
    ProcessAccessRequest,
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
    ProcessTerminationActionBundle,
    ProcessTerminationRequest,
    ProxyTransactionActionBundle,
    ProxyTransactionRequest,
    RdpSessionActionBundle,
    RdpSessionRequest,
    RdpSourceProcessFactory,
    ScheduledTaskActionBundle,
    ScheduledTaskRequest,
    ServiceLogonActionBundle,
    ServiceLogonRequest,
    SmbFileTransferMetadataActionBundle,
    SmbFileTransferMetadataRequest,
    SshSessionActionBundle,
    SshSessionRequest,
    WindowsServiceInstallActionBundle,
    WindowsServiceInstallRequest,
    WorkstationLockActionBundle,
    WorkstationLockRequest,
    WorkstationUnlockActionBundle,
    WorkstationUnlockRequest,
    file_transfer_hashes,
    http_response_parent_duration_floor,
)
from evidenceforge.generation.activity.dns_txt import choose_dns_txt_query, dns_registrable_domain
from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.activity.linux_interfaces import linux_primary_interface
from evidenceforge.generation.activity.proxy_uri import (
    get_proxy_domain_class,
    is_browser_like_proxy_domain,
)
from evidenceforge.generation.activity.proxy_user_agents import (
    normalize_proxy_user_agent_for_os,
    pick_proxy_domain_user_agent,
    pick_proxy_user_agent,
)
from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    sample_packet_timing_delta,
    sample_timing_delta,
)
from evidenceforge.generation.activity.windows_auth_realism import (
    failed_logon_config,
    min_unlock_gap_seconds,
    special_privileges_config,
)
from evidenceforge.generation.causal.engine import CausalExpansionEngine, ExpansionContext
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.identity import IdentityDirectory, default_linux_uid_for_user
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.models.scenario import EmailMessageEventSpec, ProxyAuthPolicyConfig, System, User
from evidenceforge.models.state import ActiveSession, RunningProcess
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc
from evidenceforge.utils.windows_ids import windows_id_randint

from .helpers import _get_os_category, _get_rng, _parameterize_command
from .network import (
    _AD_SRV_QUERIES,
    _IPV6_MAP,
    _SRV_PORT_MAP,
    EXTERNAL_IPS,
    REVERSE_DNS,
    _generate_internal_hostname,
    _generate_random_external_ip,
    _generate_random_hostname,
    _generate_rdns_name,
    _get_http_status,
    _ipv4_to_fake_ipv6,
    _is_invalid_network_connection,
    _is_private_ip,
)

logger = logging.getLogger(__name__)

_WINDOWS_INBOUND_SERVICE_PID_CANDIDATES: dict[int, tuple[str, ...]] = {
    53: ("dns", "svchost_netsvcs", "svchost_net_svc"),
    88: ("lsass",),
    135: ("svchost_dcom", "svchost_netsvcs"),
    139: ("system",),
    389: ("lsass",),
    445: ("system", "lanmanserver"),
    464: ("lsass",),
    636: ("lsass",),
    3268: ("lsass",),
    3269: ("lsass",),
    3389: ("svchost_termservice", "svchost_netsvcs"),
    5985: ("svchost_netsvcs",),
    5986: ("svchost_netsvcs",),
}


def _format_windows_account_attribute_time(value: datetime) -> str:
    """Format account-management attribute timestamps like Event Viewer XML data."""
    timestamp = ensure_utc(value)
    hour = timestamp.hour % 12 or 12
    meridiem = "AM" if timestamp.hour < 12 else "PM"
    return f"{timestamp.month}/{timestamp.day}/{timestamp.year} {hour}:{timestamp:%M:%S} {meridiem}"


def _is_modeled_local_ip(executor: Any, ip: str) -> bool:
    """Return whether an IP belongs to the modeled organization/network."""
    if hasattr(executor, "_ip_to_system") and ip in executor._ip_to_system:
        return True
    environment = getattr(executor, "_scenario_environment", None)
    network = getattr(environment, "network", None)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if network is not None:
        for segment in getattr(network, "segments", []) or []:
            if getattr(segment, "exposure", "internal") not in {"internal", "both"}:
                continue
            try:
                if address in ipaddress.ip_network(segment.cidr, strict=False):
                    return True
            except ValueError:
                continue
        for rule in getattr(network, "nat_rules", []) or []:
            if ip in {
                str(getattr(rule, "mapped_ip", "") or ""),
                str(getattr(rule, "real_ip", "") or ""),
            }:
                return True
    dispatcher = getattr(executor, "dispatcher", None)
    visibility = getattr(dispatcher, "visibility_engine", None)
    if visibility is not None:
        vip_to_real = getattr(visibility, "_vip_to_real_ip", {})
        if ip in vip_to_real or ip in set(vip_to_real.values()):
            return True
    return False


@dataclass(slots=True)
class _HttpPersistentConnection:
    close_deadline: datetime
    uid: str
    src_port: int
    next_trans_depth: int
    orig_budget: int
    resp_budget: int
    used_orig: int
    used_resp: int


_HTTP_PERSISTENT_REUSE_GUARD = timedelta(milliseconds=900)
_RECENT_CONNECTION_REUSE_WINDOW_SECONDS = 86_400.0


_WINDOWS_SINGLETON_SERVICE_EXES = frozenset(
    {
        "spoolsv.exe",
        "dns.exe",
        "dfsr.exe",
        "ismserv.exe",
        "msdtc.exe",
    }
)
_FILE_ACTION_EVENT_TYPES = {
    "read": "file_read",
    "create": "file_create",
    "modify": "file_modify",
    "delete": "file_delete",
}
_SYSTEM_ACCOUNTS = {"SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"}
_USER_MODEL_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._$-]+$")
_LINUX_LOCAL_ACCOUNTS = {
    "apache",
    "mysql",
    "nginx",
    "postgres",
    "root",
    "sshd",
    "www-data",
}
_SYSTEM_ACCOUNT_SIDS = {
    "SYSTEM": "S-1-5-18",
    "LOCAL SERVICE": "S-1-5-19",
    "NETWORK SERVICE": "S-1-5-20",
}
_SYSTEM_ACCOUNT_LOGON_IDS = {
    "SYSTEM": "0x3e7",
    "LOCAL SERVICE": "0x3e5",
    "NETWORK SERVICE": "0x3e4",
}
_BASH_BLOCKING_PREFIXES = (
    "nano ",
    "vim ",
    "vi ",
    "emacs ",
    "emacs -nw ",
    "code ",
    "make",
    "mysqldump",
    "npm ",
    "npm run",
    "docker build",
    "cargo build",
    "python3 -m pytest",
    "python3 ",
    "python ",
    "pytest",
    "apt ",
    "apt-get ",
    "yum ",
    "dnf ",
    "pip install",
    "tail -f ",
)
_BASH_TRANSFER_PREFIXES = ("gzip ", "scp ", "tar ", "zip ")
_BASH_MEDIUM_PREFIXES = ("curl ", "wget ", "ssh ", "mysql ", "psql ", "git ")
_BASH_BUILTIN_COMMANDS = {
    ".",
    "alias",
    "bg",
    "cd",
    "clear",
    "echo",
    "exit",
    "export",
    "fg",
    "history",
    "jobs",
    "logout",
    "pwd",
    "read",
    "source",
    "ulimit",
    "umask",
    "unset",
}
_LINUX_COMMAND_IMAGE_OVERRIDES = {
    "awk": "/usr/bin/awk",
    "cat": "/usr/bin/cat",
    "chmod": "/usr/bin/chmod",
    "chown": "/usr/bin/chown",
    "code": "/usr/bin/code",
    "cp": "/usr/bin/cp",
    "curl": "/usr/bin/curl",
    "cut": "/usr/bin/cut",
    "date": "/usr/bin/date",
    "df": "/usr/bin/df",
    "docker": "/usr/bin/docker",
    "du": "/usr/bin/du",
    "emacs": "/usr/bin/emacs",
    "file": "/usr/bin/file",
    "find": "/usr/bin/find",
    "free": "/usr/bin/free",
    "gcc": "/usr/bin/gcc",
    "git": "/usr/bin/git",
    "google-chrome": "/usr/bin/google-chrome",
    "grep": "/usr/bin/grep",
    "groups": "/usr/bin/groups",
    "gzip": "/usr/bin/gzip",
    "head": "/usr/bin/head",
    "hostname": "/usr/bin/hostname",
    "hostnamectl": "/usr/bin/hostnamectl",
    "id": "/usr/bin/id",
    "ip": "/usr/sbin/ip",
    "journalctl": "/usr/bin/journalctl",
    "kubectl": "/usr/local/bin/kubectl",
    "last": "/usr/bin/last",
    "loginctl": "/usr/bin/loginctl",
    "ls": "/usr/bin/ls",
    "lsblk": "/usr/bin/lsblk",
    "make": "/usr/bin/make",
    "mount": "/usr/bin/mount",
    "mysql": "/usr/bin/mysql",
    "mysqldump": "/usr/bin/mysqldump",
    "nano": "/usr/bin/nano",
    "nginx": "/usr/sbin/nginx",
    "nmap": "/usr/bin/nmap",
    "nmcli": "/usr/bin/nmcli",
    "npm": "/usr/bin/npm",
    "ps": "/usr/bin/ps",
    "psql": "/usr/bin/psql",
    "pt-query-digest": "/usr/bin/pt-query-digest",
    "python": "/usr/bin/python",
    "python3": "/usr/bin/python3",
    "redis-cli": "/usr/bin/redis-cli",
    "resolvectl": "/usr/bin/resolvectl",
    "rm": "/usr/bin/rm",
    "scp": "/usr/bin/scp",
    "sed": "/usr/bin/sed",
    "sha256sum": "/usr/bin/sha256sum",
    "shred": "/usr/bin/shred",
    "sqlite3": "/usr/bin/sqlite3",
    "ss": "/usr/sbin/ss",
    "ssh": "/usr/bin/ssh",
    "stat": "/usr/bin/stat",
    "systemctl": "/usr/bin/systemctl",
    "tail": "/usr/bin/tail",
    "tar": "/usr/bin/tar",
    "timedatectl": "/usr/bin/timedatectl",
    "top": "/usr/bin/top",
    "uname": "/usr/bin/uname",
    "uptime": "/usr/bin/uptime",
    "users": "/usr/bin/users",
    "vim": "/usr/bin/vim",
    "vmstat": "/usr/bin/vmstat",
    "w": "/usr/bin/w",
    "wc": "/usr/bin/wc",
    "wget": "/usr/bin/wget",
    "who": "/usr/bin/who",
    "whoami": "/usr/bin/whoami",
}
_LINUX_ALIAS_COMMANDS = {
    "ll": ("/usr/bin/ls", "ls -la"),
    "la": ("/usr/bin/ls", "ls -A"),
    "l": ("/usr/bin/ls", "ls -CF"),
}
_LINUX_SHELL_MAX_INFERRED_PROCESSES = 4
_LINUX_SHELL_MAX_INFER_STAGES = 32
_LINUX_SHELL_MAX_STAGE_CHARS = 4096
_LINUX_SHELL_MAX_SCAN_CHARS = 32768
_NMAP_PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "ssl",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http",
}
_NMAP_SERVICE_ALIASES = {
    21: {"ftp", "vsftpd", "ftpd"},
    22: {"ssh", "sshd", "openssh"},
    25: {"smtp", "postfix", "sendmail", "mail"},
    53: {"dns", "bind", "named", "ad-ds"},
    80: {"http", "apache", "apache2", "nginx", "httpd", "iis", "gunicorn"},
    443: {"https", "ssl", "tls", "apache", "apache2", "nginx", "httpd", "iis"},
    445: {"smb", "samba", "lanmanserver", "ad-ds"},
    3306: {"mysql", "mariadb"},
    3389: {"rdp", "termservice", "terminal-services"},
    5432: {"postgres", "postgresql"},
    8080: {"http", "apache", "apache2", "nginx", "httpd", "gunicorn", "tomcat", "squid"},
}


def _bash_command_dwell_seconds(command: str) -> float:
    """Return a minimum foreground dwell time before the next shell command."""
    normalized = command.strip().lower()
    if normalized.endswith("&") or " nohup " in f" {normalized} ":
        return 1.0
    if any(normalized.startswith(prefix) for prefix in _BASH_BLOCKING_PREFIXES):
        return 45.0
    if any(normalized.startswith(prefix) for prefix in _BASH_TRANSFER_PREFIXES):
        return 14.0
    if any(normalized.startswith(prefix) for prefix in _BASH_MEDIUM_PREFIXES):
        return 8.0
    return 2.0


def _background_linux_shell_command_if_needed(command: str) -> str:
    """Mark long-running shell commands as backgrounded when more shell activity follows."""
    stripped = command.rstrip()
    normalized = stripped.lower()
    if not stripped or normalized.endswith("&") or " nohup " in f" {normalized} ":
        return command
    if any(pattern in normalized for pattern in ("tail -f", "watch ", "--follow")):
        return f"{stripped} &"
    return command


_WINDOWS_SINGLETON_SYSTEM_PROCESSES = {
    "smss.exe": "smss",
    "csrss.exe": "csrss_s0",
    "wininit.exe": "wininit",
    "services.exe": "services",
    "lsass.exe": "lsass",
}


def _extract_nmap_ports(command_line: str) -> list[int]:
    """Extract an nmap ``-p`` port list from a command line."""
    tokens = command_line.replace(",", " ").split()
    ports: list[int] = []
    for idx, token in enumerate(tokens):
        if token == "-p" and idx + 1 < len(tokens):
            ports.extend(_parse_port_tokens(tokens[idx + 1 : idx + 13]))
            break
        if token.startswith("-p") and len(token) > 2:
            ports.extend(_parse_port_tokens([token[2:]]))
            break
    return list(dict.fromkeys(port for port in ports if 0 < port <= 65535))


def _extract_http_url_from_command(command_line: str) -> str | None:
    """Return the first valid HTTP(S) URL embedded in a process command line."""
    for match in re.finditer(r"https?://[^\s'\"<>]+", command_line):
        candidate = match.group(0).rstrip(").,;]")
        try:
            parsed = urlsplit(candidate)
            _ = parsed.port
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return candidate
    return None


def _http_user_agent_for_process(process_name: str, command_line: str) -> str:
    """Return a source-native HTTP User-Agent for command-line HTTP clients."""
    exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    if exe in {"curl", "curl.exe"} or command.startswith("curl "):
        return "curl/7.88.1"
    if exe in {"wget", "wget.exe"} or command.startswith("wget "):
        return "Wget/1.21.3"
    if "python" in exe and "requests" in command:
        return "python-requests/2.31.0"
    return ""


def _is_tool_http_user_agent(user_agent: str) -> bool:
    """Return true when the UA identifies a command-line/library HTTP client."""
    ua = user_agent.strip().lower()
    return ua.startswith(
        (
            "curl/",
            "wget/",
            "python-requests/",
            "go-http-client/",
            "apache-httpclient/",
            "powershell/",
        )
    )


def _source_native_http_referrer(
    user_agent: str,
    referrer: str,
    *,
    request_scheme: str | None = None,
    request_port: int | None = None,
) -> str:
    """Return a referrer that agrees with the HTTP client family."""
    if not referrer:
        return ""
    if _is_tool_http_user_agent(user_agent):
        return ""
    target_is_plaintext = request_scheme == "http" or request_port == 80
    if target_is_plaintext:
        try:
            if urlsplit(referrer).scheme == "https":
                return ""
        except ValueError:
            return ""
    return referrer


def _http_method_for_process_command(command_line: str) -> str:
    """Infer the HTTP method visible for a simple CLI HTTP command."""
    lowered = f" {command_line.lower()} "
    if " -i " in lowered or " --head " in lowered or " --head" in lowered:
        return "HEAD"
    method_match = re.search(r"(?:\s-X\s+|\s--request\s+)([A-Za-z]+)", command_line)
    if method_match:
        return method_match.group(1).upper()
    return "GET"


def _http_context_from_process_command(
    process_name: str,
    command_line: str,
    *,
    response_body_len: int,
) -> tuple[HttpContext, str, int, str] | None:
    """Build canonical HTTP request metadata from a process command URL.

    Returns ``(context, host, port, service)`` so the owning process, proxy, and
    Zeek records agree on host, path, method, and User-Agent for the same flow.
    """
    http_url = _extract_http_url_from_command(command_line)
    if not http_url:
        return None
    try:
        parsed = urlsplit(http_url)
        host = parsed.hostname or ""
        if not host:
            return None
        service = "ssl" if parsed.scheme == "https" else "http"
        port = parsed.port or (443 if service == "ssl" else 80)
    except ValueError:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    user_agent = _http_user_agent_for_process(process_name, command_line)
    if not user_agent:
        return None

    from evidenceforge.generation.activity.http_content import (
        infer_mime_type_from_path,
        is_stable_resource_path,
        response_mime_types_for_status,
        response_size_for_status,
    )

    mime_type = infer_mime_type_from_path(path)
    method = _http_method_for_process_command(command_line)
    body_len = 0 if method == "HEAD" else response_body_len
    if method != "HEAD" and is_stable_resource_path(path):
        body_len = response_size_for_status(200, host, path)
    context = HttpContext(
        method=method,
        host=host if port in (80, 443) else f"{host}:{port}",
        uri=path,
        version="1.1",
        user_agent=user_agent,
        request_body_len=0,
        response_body_len=body_len,
        status_code=200,
        status_msg="OK",
        referrer="",
        resp_mime_types=response_mime_types_for_status(
            200,
            mime_type,
            body_len,
            method=method,
        ),
        tags=[],
    )
    return context, host, port, service


def _normalize_http_context_for_source_native_response(http: HttpContext) -> HttpContext:
    """Keep caller-provided HTTP metadata source-native before cross-source fan-out."""
    from evidenceforge.generation.activity.http_content import (
        coerce_response_size_for_mime,
        http_status_message,
        is_download_scale_mime,
        is_stable_resource_path,
        normalize_mime_type_for_path,
        response_mime_types_for_status,
    )

    method = (http.method or "GET").upper()
    status_code = http.status_code
    response_body_len = max(0, http.response_body_len)
    status_msg = http.status_msg
    bodyless_status = status_code in {204, 304}

    if bodyless_status:
        response_body_len = 0
    elif (
        status_code == 200
        and response_body_len == 0
        and method not in {"CONNECT", "HEAD"}
        and is_stable_resource_path(http.uri)
    ):
        status_code = 304
        status_msg = http_status_message(status_code)
    elif method != "CONNECT":
        status_msg = http_status_message(status_code)

    resp_mime_types = list(http.resp_mime_types)
    if 200 <= status_code < 300 and method not in {"CONNECT", "HEAD"}:
        mime_type = (
            resp_mime_types[0]
            if resp_mime_types
            else normalize_mime_type_for_path(
                http.uri,
                "text/html",
            )
        )
        if is_download_scale_mime(mime_type):
            response_body_len = coerce_response_size_for_mime(
                random.Random(
                    _stable_seed(
                        "http_context_body_size:"
                        f"{http.host}:{http.uri}:{mime_type}:{response_body_len}"
                    )
                ),
                mime_type,
                response_body_len,
            )
    if (
        not resp_mime_types
        or response_body_len <= 0
        or method == "HEAD"
        or bodyless_status
        or status_code in {301, 302}
        or status_code >= 400
    ):
        mime_type = resp_mime_types[0] if resp_mime_types else ""
        resp_mime_types = response_mime_types_for_status(
            status_code,
            mime_type,
            response_body_len,
            method=method,
        )

    if (
        status_code == http.status_code
        and status_msg == http.status_msg
        and response_body_len == http.response_body_len
        and resp_mime_types == list(http.resp_mime_types)
    ):
        return http
    return replace(
        http,
        response_body_len=response_body_len,
        status_code=status_code,
        status_msg=status_msg,
        resp_mime_types=resp_mime_types,
    )


def _apply_plaintext_http_policy(
    http: HttpContext,
    *,
    hostname: str | None,
    dst_ip: str,
    dst_port: int,
) -> HttpContext:
    """Apply public-domain plaintext HTTP policy to caller-provided HTTP context."""
    if not hostname or dst_port != 80:
        return http

    from evidenceforge.generation.activity.http_content import (
        http_status_message,
        response_mime_types_for_status,
        response_size_for_status,
    )
    from evidenceforge.generation.activity.proxy_uri import plaintext_http_redirect_status

    redirect_status = plaintext_http_redirect_status(
        hostname,
        port=dst_port,
        path=http.uri,
        dst_ip=dst_ip,
    )
    if redirect_status is None or http.status_code in {301, 302}:
        return http

    response_body_len = response_size_for_status(redirect_status, hostname, http.uri)
    resp_mime_types = response_mime_types_for_status(
        redirect_status,
        "text/html",
        response_body_len,
        method=http.method,
    )
    return replace(
        http,
        response_body_len=response_body_len,
        flow_response_body_len=response_body_len
        if http.flow_response_body_len is not None
        else None,
        status_code=redirect_status,
        status_msg=http_status_message(redirect_status),
        resp_mime_types=resp_mime_types,
    )


_HTTP_FILE_TRANSFER_MIME_TYPES = {
    "application/octet-stream",
    "application/pdf",
    "application/vnd.debian.binary-package",
    "application/vnd.ms-cab-compressed",
    "application/x-gzip",
    "application/x-msdownload",
    "application/zip",
}
_HTTP_FILE_TRANSFER_BODY_THRESHOLD = 64 * 1024
_HTTP_FILE_TRANSFER_LARGE_BODY_THRESHOLD = 1_000_000
_SSH_CLIENT_IDENTITY_FILES = (
    "~/.ssh/id_ed25519",
    "~/.ssh/id_rsa",
    "~/.ssh/work_ed25519",
)


def _linux_ssh_client_command_line(
    *,
    exe_name: str,
    username: str,
    target_host: str,
    target_ip: str,
    source_hostname: str,
    source_port: int,
    requested_time: datetime,
) -> str:
    """Return a deterministic source-native SSH/SCP client command line."""
    seed = _stable_seed(
        "linux_ssh_client_command:"
        f"{source_hostname}:{username}:{target_host}:{target_ip}:"
        f"{source_port}:{ensure_utc(requested_time).isoformat()}:{exe_name}"
    )
    rng = random.Random(seed)
    short_host = target_host.split(".", 1)[0]
    host_forms = [target_host]
    weights = [6]
    if short_host and short_host != target_host:
        host_forms.append(short_host)
        weights.append(3)
    if target_ip:
        host_forms.append(target_ip)
        weights.append(1)
    host = rng.choices(host_forms, weights=weights, k=1)[0]
    identity_file = rng.choice(_SSH_CLIENT_IDENTITY_FILES)

    if exe_name == "scp":
        remote_path = rng.choice(
            (
                "~/remote-file",
                "/var/tmp/archive.tgz",
                "/tmp/support-bundle.tgz",
                "~/logs/support.log",
            )
        )
        local_path = rng.choice(("./remote-file", "./archive.tgz", "/tmp/support-bundle.tgz"))
        variants = (
            f"scp {username}@{host}:{remote_path} {local_path}",
            f"scp -p {username}@{host}:{remote_path} {local_path}",
            f"scp -i {identity_file} {username}@{host}:{remote_path} {local_path}",
            f"scp -o ConnectTimeout=10 {username}@{host}:{remote_path} {local_path}",
        )
        return rng.choice(variants)

    variants = (
        f"ssh {username}@{host}",
        f"ssh {username}@{host}",
        f"ssh -l {username} {host}",
        f"ssh -i {identity_file} {username}@{host}",
        f"ssh -o ConnectTimeout=10 {username}@{host}",
        f"ssh -o ServerAliveInterval=30 {username}@{host}",
        f"ssh -A {username}@{host}",
        f"ssh -tt {username}@{host}",
        f"ssh -p 22 {username}@{host}",
    )
    return rng.choice(variants)


def _http_response_requires_file_transfer(http: HttpContext) -> bool:
    """Return whether Zeek should always analyze this HTTP response body as a file."""

    if http.response_body_len >= _HTTP_FILE_TRANSFER_LARGE_BODY_THRESHOLD:
        return True
    mime_type = http.resp_mime_types[0] if http.resp_mime_types else ""
    return (
        http.response_body_len >= _HTTP_FILE_TRANSFER_BODY_THRESHOLD
        and mime_type in _HTTP_FILE_TRANSFER_MIME_TYPES
    )


def _attach_http_response_file_transfer(
    event: SecurityEvent,
    *,
    dst_ip: str,
    rng: random.Random,
    probabilistic_file_analysis: bool,
) -> None:
    """Attach source-native Zeek files.log metadata for eligible HTTP responses."""

    if event.network is None or event.http is None or event.file_transfer is not None:
        return
    if event.network.service != "http" or event.network.conn_state != "SF":
        return
    http = event.http
    method = (http.method or "GET").upper()
    if (
        method in {"CONNECT", "HEAD"}
        or not (200 <= http.status_code < 300)
        or http.response_body_len <= 100
        or not http.resp_mime_types
    ):
        return

    required = _http_response_requires_file_transfer(http)
    if probabilistic_file_analysis:
        sampled = rng.random() < 0.3
        should_attach = required or sampled
    else:
        should_attach = required
    if not should_attach:
        return

    duration_floor = http_response_parent_duration_floor(http.response_body_len)
    if duration_floor > 0:
        floor_rng = random.Random(
            _stable_seed(
                "http_response_file_transfer_parent_duration:"
                f"{event.network.src_ip}:{event.network.src_port}:"
                f"{event.network.dst_ip}:{event.network.dst_port}:"
                f"{http.host}:{http.uri}:{http.response_body_len}:"
                f"{event.timestamp.isoformat()}"
            )
        )
        min_http_file_duration = duration_floor + floor_rng.uniform(0.05, 0.55)
        event.network.duration = max(event.network.duration or 0.0, min_http_file_duration)
        if event.proxy is not None:
            event.proxy.time_taken = _proxy_time_taken_ms(
                event.network.duration,
                rng,
                method=event.proxy.method,
                status_code=event.proxy.status_code,
                cache_result=event.proxy.cache_result,
            )

    file_result = HttpResponseFileTransferActionBundle(
        HttpResponseFileTransferRequest(
            host=http.host,
            uri=http.uri,
            dst_ip=dst_ip,
            response_body_len=http.response_body_len,
            response_mime_types=list(http.resp_mime_types),
            timestamp=event.timestamp,
            parent_duration=event.network.duration,
        ),
        rng,
    ).execute()
    event.file_transfer = file_result.file_transfer
    event.http.resp_fuids = [event.file_transfer.fuid]
    event.http.resp_mime_types = [event.file_transfer.mime_type]
    event.pe = file_result.pe


def _http_context_flow_body_len(http: HttpContext, side: str) -> int:
    """Return the HTTP body bytes represented by the parent TCP flow."""
    if side == "request":
        value = http.flow_request_body_len
        fallback = http.request_body_len
    else:
        value = http.flow_response_body_len
        fallback = http.response_body_len
    if value is None:
        value = fallback
    return max(0, value or 0)


def _http_context_flow_transaction_count(http: HttpContext) -> int:
    """Return the number of HTTP transactions represented by the parent TCP flow."""
    return max(1, http.flow_transaction_count or 1)


def _http_request_header_len(http: HttpContext, transaction_count: int) -> int:
    """Approximate source-native HTTP request header bytes for conn.log payload accounting."""
    method = (http.method or "GET").upper()
    version = http.version or "1.1"
    uri = http.uri or "/"
    host = http.host or "-"
    user_agent = http.user_agent or ""
    body_len = _http_context_flow_body_len(http, "request")
    seed = _stable_seed(
        f"http_request_headers:{method}:{host}:{uri}:{user_agent}:{transaction_count}:{body_len}"
    )
    accept = "*/*" if not user_agent else "text/html,application/xhtml+xml,*/*;q=0.8"
    header_lines = [
        f"{method} {uri} HTTP/{version}",
        f"Host: {host}",
        f"Accept: {accept}",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: keep-alive" if transaction_count > 1 else "Connection: close",
    ]
    if user_agent:
        header_lines.append(f"User-Agent: {user_agent}")
    if http.referrer:
        header_lines.append(f"Referer: {http.referrer}")
    if http.status_code == 304:
        header_lines.append(f'If-None-Match: W/"{seed & 0xFFFFFFFF:x}"')
    if body_len > 0:
        header_lines.append(f"Content-Length: {body_len}")
        header_lines.append("Content-Type: application/x-www-form-urlencoded")
    base_len = sum(len(line.encode("utf-8")) + 2 for line in header_lines) + 2
    per_transaction_extra = 24 + (seed % 97)
    return (base_len + per_transaction_extra) * transaction_count


def _http_response_header_len(http: HttpContext, transaction_count: int) -> int:
    """Approximate source-native HTTP response header bytes for conn.log payload accounting."""
    method = (http.method or "GET").upper()
    status_code = int(http.status_code or 0)
    status_msg = http.status_msg or "OK"
    host = http.host or "-"
    uri = http.uri or "/"
    body_len = _http_context_flow_body_len(http, "response")
    seed = _stable_seed(
        f"http_response_headers:{method}:{status_code}:{status_msg}:{host}:{uri}:"
        f"{transaction_count}:{body_len}"
    )
    content_type = http.resp_mime_types[0] if http.resp_mime_types else "text/html"
    header_lines = [
        f"HTTP/{http.version or '1.1'} {status_code} {status_msg}",
        "Server: nginx",
        f"Content-Length: {0 if method == 'HEAD' else body_len}",
        "Connection: keep-alive" if transaction_count > 1 else "Connection: close",
    ]
    if method != "HEAD" and status_code not in {204, 304}:
        header_lines.append(f"Content-Type: {content_type}")
    if status_code in {301, 302}:
        header_lines.append(f"Location: https://{host}{uri if uri.startswith('/') else '/'}")
    if status_code == 304:
        header_lines.append(f'ETag: W/"{seed & 0xFFFFFFFF:x}"')
        header_lines.append("Cache-Control: max-age=300")
    if 200 <= status_code < 300:
        header_lines.append(f"Date: {seed % 28 + 1:02d} May 2026 12:00:00 GMT")
    base_len = sum(len(line.encode("utf-8")) + 2 for line in header_lines) + 2
    per_transaction_extra = 16 + (seed % 83)
    return (base_len + per_transaction_extra) * transaction_count


def _http_flow_payload_bytes(http: HttpContext) -> tuple[int, int]:
    """Return TCP payload byte counts implied by source-native HTTP metadata."""
    transaction_count = _http_context_flow_transaction_count(http)
    request_bytes = _http_context_flow_body_len(http, "request") + _http_request_header_len(
        http,
        transaction_count,
    )
    response_body_len = _http_context_flow_body_len(http, "response")
    response_header_len = _http_response_header_len(http, transaction_count)
    response_bytes = response_header_len
    if (http.method or "GET").upper() != "HEAD":
        response_bytes += response_body_len
    return request_bytes, response_bytes


def _dhcp_message_payload_size(
    rng: random.Random,
    msg_type: str,
) -> int:
    """Return a source-native DHCP message payload size with option-list texture."""
    msg_type = msg_type.upper()
    if msg_type == "DISCOVER":
        return rng.randint(286, 342)
    if msg_type == "OFFER":
        return rng.randint(300, 366)
    if msg_type == "REQUEST":
        return rng.randint(292, 358)
    if msg_type == "ACK":
        return rng.randint(304, 374)
    return rng.randint(276, 344)


def _dhcp_payload_accounting(
    *,
    hostname: str,
    mac: str,
    server_addr: str,
    time: datetime,
    msg_types: list[str],
) -> tuple[int, int, int, int, int, int]:
    """Return DHCP conn.log payload, packet, and IP-byte accounting."""
    rng = random.Random(
        _stable_seed(
            "dhcp_payload_accounting:"
            f"{hostname}:{mac}:{server_addr}:{time.isoformat()}:{','.join(msg_types)}"
        )
    )
    orig_msg_types = [msg for msg in msg_types if msg.upper() in {"DISCOVER", "REQUEST", "INFORM"}]
    resp_msg_types = [msg for msg in msg_types if msg.upper() in {"OFFER", "ACK", "NAK"}]
    if not orig_msg_types:
        orig_msg_types = ["REQUEST"]
    if not resp_msg_types:
        resp_msg_types = ["ACK"]

    orig_bytes = sum(_dhcp_message_payload_size(rng, msg) for msg in orig_msg_types)
    resp_bytes = sum(_dhcp_message_payload_size(rng, msg) for msg in resp_msg_types)
    orig_pkts = len(orig_msg_types)
    resp_pkts = len(resp_msg_types)
    overhead = 28
    return (
        orig_bytes,
        resp_bytes,
        orig_pkts,
        resp_pkts,
        orig_bytes + (orig_pkts * overhead),
        resp_bytes + (resp_pkts * overhead),
    )


def _network_effect_context_for_process(
    process_name: str,
    command_line: str,
    effect_process_name: str,
    effect_command_line: str,
) -> tuple[str, str]:
    """Choose the process identity used for immediate network side effects."""
    if _extract_http_url_from_command(command_line) and _http_user_agent_for_process(
        process_name,
        command_line,
    ):
        return process_name, command_line
    return effect_process_name, effect_command_line


def _is_ip_literal(value: str) -> bool:
    """Return whether a command target is an IP literal."""
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


def _normalize_command_host_token(value: str) -> str:
    """Normalize a host token from command-line arguments."""
    host = value.strip().strip("'\"")
    if not host:
        return ""
    if "://" in host:
        parsed = urlsplit(host)
        host = parsed.hostname or host
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    host = host.strip("[]")
    if ":" in host and not _is_ip_literal(host):
        name, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            host = name
    return host.rstrip(".")


def _command_tokens(command_line: str) -> list[str]:
    """Split a process command line enough to recover network target arguments."""
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        tokens = command_line.split()
    return [token.strip().strip("'\"") for token in tokens if token.strip().strip("'\"")]


def _extract_network_command_target(command_line: str, service: str) -> str | None:
    """Extract a user-visible network target from common client command lines."""
    normalized_service = service.lower()
    if normalized_service == "ssh":
        tokens = _command_tokens(command_line)
        if not tokens:
            return None
        option_args = {
            "-b",
            "-c",
            "-e",
            "-f",
            "-i",
            "-j",
            "-l",
            "-m",
            "-o",
            "-p",
            "-s",
            "-w",
        }
        skip_next = False
        for token in tokens[1:]:
            lower = token.lower()
            if skip_next:
                skip_next = False
                continue
            if lower in option_args:
                skip_next = True
                continue
            if lower.startswith("-"):
                continue
            target = _normalize_command_host_token(token)
            if target:
                return target
        return None
    if normalized_service == "rdp":
        match = re.search(r"(?:^|\s)/v:([^\s]+)", command_line, re.IGNORECASE)
        return _normalize_command_host_token(match.group(1)) if match else None
    if normalized_service == "ldap":
        match = re.search(r"ldap://([^\s/\"']+)", command_line, re.IGNORECASE)
        return _normalize_command_host_token(match.group(1)) if match else None
    if normalized_service == "mssql":
        tokens = _command_tokens(command_line)
        for idx, token in enumerate(tokens[1:], start=1):
            lower = token.lower()
            candidate = ""
            if lower in {"-s", "/s", "-server", "--server"} and idx + 1 < len(tokens):
                candidate = tokens[idx + 1]
            elif lower.startswith("-s") and len(token) > 2:
                candidate = token[2:]
            elif lower.startswith("/s") and len(token) > 2:
                candidate = token[2:]
            elif lower.startswith("--server="):
                candidate = token.split("=", 1)[1]
            if candidate:
                return _normalize_database_command_target(candidate)
        return None
    if normalized_service in {"mysql", "postgresql"}:
        tokens = _command_tokens(command_line)
        for idx, token in enumerate(tokens[1:], start=1):
            lower = token.lower()
            candidate = ""
            if lower in {"-h", "--host", "--hostname"} and idx + 1 < len(tokens):
                candidate = tokens[idx + 1]
            elif lower.startswith("-h") and len(token) > 2:
                candidate = token[2:]
            elif lower.startswith("--host="):
                candidate = token.split("=", 1)[1]
            elif lower.startswith("--hostname="):
                candidate = token.split("=", 1)[1]
            if candidate:
                return _normalize_database_command_target(candidate)
        return None
    return None


def _normalize_database_command_target(value: str) -> str:
    """Normalize a database client target while preserving the user-visible host."""
    host = _normalize_command_host_token(value)
    lower = host.lower()
    for prefix in ("tcp:", "np:", "lpc:"):
        if lower.startswith(prefix):
            host = host[len(prefix) :]
            lower = host.lower()
            break
    if "," in host:
        host = host.split(",", 1)[0]
    if "\\" in host and not _is_local_database_instance_target(host):
        host = host.split("\\", 1)[0]
    return host.strip().rstrip(".")


def _is_local_database_instance_target(target: str) -> bool:
    """Return whether a DB target names a local-only instance with no network effect."""
    normalized = _normalize_command_host_token(target).lower()
    if not normalized:
        return True
    if normalized in {"localhost", "127.0.0.1", "::1", ".", "(local)", "local"}:
        return True
    if normalized in {"sqlexpress", "mssqllocaldb"}:
        return True
    if normalized.startswith(("localhost\\", ".\\", "(local)\\")):
        return True
    if normalized.startswith("(localdb)\\") or "mssqllocaldb" in normalized:
        return True
    return False


def _parse_port_tokens(tokens: list[str]) -> list[int]:
    """Parse nmap port tokens until the next option or target token."""
    ports: list[int] = []
    for token in tokens:
        stripped = token.strip("'\"")
        if stripped.startswith("-") or "/" in stripped:
            break
        for value in stripped.split(","):
            if "-" in value:
                start_text, end_text = value.split("-", 1)
                if start_text.isdigit() and end_text.isdigit():
                    start = int(start_text)
                    end = min(int(end_text), start + 20)
                    ports.extend(range(start, end + 1))
                continue
            if value.isdigit():
                ports.append(int(value))
    return ports


def _service_for_port(port: int) -> str | None:
    """Return a common service name for an nmap destination port."""
    return _NMAP_PORT_SERVICES.get(port)


def _inventory_token(value: str) -> str:
    """Normalize scenario inventory labels for lightweight matching."""
    return value.lower().replace(" ", "-").replace("_", "-")


def _nmap_target_exposes_port(port: int, target_system: System | None) -> bool:
    """Return whether target inventory suggests a scanned port is open."""
    if target_system is None:
        return False
    services = {_inventory_token(service) for service in target_system.services}
    roles = {_inventory_token(role) for role in target_system.roles}
    system_type = _inventory_token(target_system.type)
    aliases = _NMAP_SERVICE_ALIASES.get(port, set())
    if services & aliases:
        return True
    if port in {80, 443, 8080} and roles & {"web-server", "app-server", "forward-proxy"}:
        return True
    if port == 445 and (system_type == "domain-controller" or "file-server" in roles):
        return True
    if port == 3306 and "database" in roles:
        return True
    if port == 53 and "dns-server" in roles:
        return True
    if port == 3389 and "windows" in target_system.os.lower():
        return True
    return False


def _nmap_probe_profile(
    port: int,
    target_system: System | None,
    rng: random.Random,
) -> tuple[str, str, float, int, int]:
    """Return source-native connection fields for one nmap TCP probe."""
    if _nmap_target_exposes_port(port, target_system):
        conn_state = rng.choices(["SF", "RSTO", "RSTR"], weights=[82, 10, 8], k=1)[0]
        service = _service_for_port(port) or ""
        if conn_state == "SF":
            return (
                conn_state,
                service,
                rng.uniform(0.04, 0.9),
                rng.randint(0, 180),
                rng.randint(0, 900),
            )
        return (
            conn_state,
            service,
            rng.uniform(0.01, 0.35),
            rng.randint(0, 140),
            rng.randint(0, 240),
        )

    conn_state = rng.choices(["REJ", "S0", "RSTO"], weights=[54, 38, 8], k=1)[0]
    if conn_state == "S0":
        return conn_state, "", rng.uniform(1.5, 6.0), rng.randint(0, 64), 0
    return conn_state, "", rng.uniform(0.003, 0.18), rng.randint(0, 96), rng.randint(0, 80)


def _nmap_conn_state(port: int, target_system: System | None = None) -> str:
    """Return a plausible Zeek conn_state for a TCP-connect scan probe."""
    rng = random.Random(_stable_seed(f"nmap_conn_state:{port}:{getattr(target_system, 'ip', '')}"))
    return _nmap_probe_profile(port, target_system, rng)[0]


_WINDOWS_USER_SESSION_PROCESSES = {
    "sihost.exe",
    "searchhost.exe",
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "searchindexer.exe",
    "runtimebroker.exe",
    "textinputhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "applicationframehost.exe",
}
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
_WINDOWS_BROWSER_CHILD_MARKERS = (
    "--type=",
    "--utility-sub-type=",
    "-contentproc",
    " -childid ",
    " /prefetch:",
)
_WINDOWS_ELECTRON_CHILD_EXES = frozenset({"teams.exe"})
_WINDOWS_ELECTRON_CHILD_MARKERS = (
    "--type=",
    "--utility-sub-type=",
)
_WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES = frozenset({2, 10, 11})
_WINDOWS_WORKSTATION_SESSION_LOGON_TYPES = frozenset({2, 11})
_WINDOWS_REMOTE_SESSION_KINDS = frozenset({"network", "service", "rdp", "ssh"})
_LINUX_LOCAL_SESSION_LOGON_TYPES = frozenset({2, 11})
_LINUX_REMOTE_SESSION_KINDS = frozenset({"network", "service", "ssh"})
_SSH_SYSLOG_MICRO_JITTER_BANDS = {
    "connection": 101,
    "accepted": 301,
    "pam": 501,
    "logind": 701,
    "closed": 901,
}


def _is_windows_workstation_session(session: ActiveSession) -> bool:
    """Return true when a session can own local workstation lock/unlock evidence."""
    return (
        session.logon_type in _WINDOWS_WORKSTATION_SESSION_LOGON_TYPES
        and session.session_kind not in _WINDOWS_REMOTE_SESSION_KINDS
    )


def _ssh_syslog_time(
    base_time: datetime,
    label: str,
    milliseconds: int,
    *seed_parts: Any,
    before: bool = False,
) -> datetime:
    """Return an SSH syslog lifecycle timestamp with non-repeating sub-ms texture."""
    band_start = _SSH_SYSLOG_MICRO_JITTER_BANDS.get(label, 101)
    seed = _stable_seed(
        "ssh_syslog_micro_jitter:" + label + ":" + ":".join(str(part) for part in seed_parts)
    )
    delta = timedelta(milliseconds=milliseconds, microseconds=band_start + (seed % 89))
    return base_time - delta if before else base_time + delta


def _zeek_conn_observation_time(
    base_time: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: str,
    service: str,
) -> datetime:
    """Return a deterministic canonical spacing time for same-scheduled flows."""
    return base_time + sample_packet_timing_delta(
        "network.connection_start_jitter",
        seed_parts=(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            service,
            base_time,
        ),
    )


def _session_started_by(session: Any, time: datetime) -> bool:
    """Return whether a session exists at the given activity time."""
    session_start = session.start_time
    if session_start.tzinfo is None:
        session_start = session_start.replace(tzinfo=UTC)
    else:
        session_start = session_start.astimezone(UTC)
    activity_time = time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)
    return session_start <= activity_time


def _session_active_for_activity(
    session: Any, time: datetime, *, margin_seconds: float = 0.0
) -> bool:
    """Return whether a session can own activity at the given visible time."""
    if not _session_started_by(session, time):
        return False
    network_close_time = getattr(session, "network_close_time", None)
    if network_close_time is None:
        return True
    if network_close_time.tzinfo is None:
        network_close_time = network_close_time.replace(tzinfo=UTC)
    else:
        network_close_time = network_close_time.astimezone(UTC)
    activity_time = time.replace(tzinfo=UTC) if time.tzinfo is None else time.astimezone(UTC)
    return activity_time < network_close_time - timedelta(seconds=margin_seconds)


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


def _windows_token_profile(username: str, integrity_level: str) -> tuple[str, str, str]:
    """Return source-native Windows token fields for a process owner."""
    normalized = username.upper().split("\\")[-1]
    if normalized in _SYSTEM_ACCOUNTS:
        return "System", "%%1936", "S-1-16-16384"
    if integrity_level == "High":
        return "High", "%%1936", "S-1-16-12288"
    if integrity_level == "Low":
        return "Low", "%%1938", "S-1-16-4096"
    return "Medium", "%%1938", "S-1-16-8192"


def _windows_service_process_account(process_name: str, command_line: str) -> str | None:
    """Return the built-in service identity for service-hosted Windows processes."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    if exe_name in {"psexesvc.exe", "healthmonitorsvc.exe"}:
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


def _account_leaf_name(username: str) -> str:
    """Return the username component suitable for profile-path templates."""
    return username.rsplit("\\", 1)[-1] if "\\" in username else username


def _materialize_username_path(path: str, username: str) -> str:
    """Resolve common user placeholders that must never reach endpoint logs."""
    if not path:
        return path
    account = _account_leaf_name(username or "SYSTEM")
    return path.replace("{username}", account).replace("{user}", account)


def _ldap_base_dn(domain: str) -> str:
    """Render a DNS domain as a lower-case LDAP base DN for command-line tools."""
    labels = [label for label in domain.strip(".").lower().split(".") if label]
    if not labels:
        labels = ["corp", "local"]
    return ",".join(f"dc={label}" for label in labels)


def _certificate_validity_window(
    reference_time: datetime,
    rng: random.Random,
    *,
    validity_days_min: int,
    validity_days_max: int,
    not_before_max_days: int,
    not_before_min_days: int = 1,
) -> tuple[int, int]:
    """Create a stable certificate validity window independent of observation seconds."""
    reference_epoch = int(reference_time.timestamp())
    validity_days = rng.randint(validity_days_min, max(validity_days_max, validity_days_min))
    max_back_days = min(not_before_max_days, max(validity_days - 1, not_before_min_days))
    min_back_days = min(not_before_min_days, max_back_days)
    not_before_days = rng.randint(min_back_days, max_back_days)
    issued_day_epoch = ((reference_epoch // 86400) - not_before_days) * 86400
    not_valid_before = issued_day_epoch + rng.randint(0, 86399)
    not_valid_after = not_valid_before + validity_days * 86400
    return not_valid_before, not_valid_after


def _bound_certificate_validity_to_issuer_window(
    validity: tuple[int, int],
    issuer_name: str,
    reference_time: datetime,
) -> tuple[int, int]:
    """Clamp a child certificate validity window to its configured issuer profile."""
    from evidenceforge.generation.activity.tls_realism import certificate_authority_profile

    issuer_profile = certificate_authority_profile(issuer_name)
    if issuer_profile is None:
        return validity

    issuer_not_before = int(issuer_profile["not_valid_before"])
    issuer_not_after = int(issuer_profile["not_valid_after"])
    reference_epoch = int(reference_time.timestamp())
    if not (issuer_not_before < reference_epoch < issuer_not_after):
        return validity

    not_valid_before = max(validity[0], issuer_not_before)
    not_valid_after = min(validity[1], issuer_not_after)
    if not_valid_before >= reference_epoch:
        not_valid_before = max(issuer_not_before, reference_epoch - 86400)
    if not_valid_after <= reference_epoch:
        not_valid_after = min(issuer_not_after, reference_epoch + 86400)
    if not_valid_after <= not_valid_before:
        not_valid_before = max(issuer_not_before, min(reference_epoch - 86400, issuer_not_after))
        not_valid_after = min(issuer_not_after, max(reference_epoch + 86400, not_valid_before + 1))
    if not_valid_after <= not_valid_before:
        return validity
    return int(not_valid_before), int(not_valid_after)


def _linux_foreground_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Estimate foreground Linux command lifetime for shell-history ordering."""
    exe_name = process_name.rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    if any(pattern in command for pattern in ("tail -f", "watch ", "--follow", " -f ")):
        return None
    if "/usr/lib/apt/methods/" in process_name.lower() or command.startswith(
        "/usr/lib/apt/methods/"
    ):
        return (20.0, 180.0)
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
    if exe_name in {"sleep", "test"}:
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


_LINUX_ONE_SHOT_NETWORK_EXES: set[str] = {
    "apt",
    "apt-get",
    "curl",
    "dnf",
    "python3",
    "wget",
    "scp",
    "kubectl",
    "ldapsearch",
    "mysqldump",
}


def _windows_foreground_lifetime(
    process_name: str, command_line: str
) -> tuple[float, float] | None:
    """Estimate Windows foreground command lifetime for baseline process state."""
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
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
        return None
    if exe_name in {"curl.exe", "curl", "wget.exe", "wget"}:
        return (0.8, 12.0)
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
        return (0.4, 6.0)
    padded_command = f" {command} "
    if exe_name == "cmd.exe":
        if " /c " in padded_command:
            return (0.4, 8.0)
        return None
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
            return (2.0, 25.0)
        return None
    if exe_name in {"wmic.exe", "certutil.exe"}:
        return (4.0, 35.0)
    if exe_name == "sqlcmd.exe" and " -q " in f" {command} ":
        return (2.0, 25.0)
    return None


_DNS_QTYPE_RDATA_LENGTHS = {
    "A": 4,
    "AAAA": 16,
}


def _dns_name_wire_size(name: str) -> int:
    """Return the encoded DNS owner-name size, including label lengths and root."""
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        return 1
    return sum(1 + len(label.encode("utf-8", errors="ignore")) for label in labels) + 1


def _dns_question_wire_size(query: str) -> int:
    """Return DNS question section size for one IN-class query."""
    return _dns_name_wire_size(query) + 4


def _dns_payload_padding(*, query: str, query_type: str, response: bool) -> int:
    """Return stable EDNS/client-padding texture for DNS payload accounting."""
    seed = _stable_seed(f"dns_payload_padding:{query.lower()}:{query_type}:{response}")
    rng = random.Random(seed)
    if query_type in {"TXT", "NULL"}:
        choices = (0, 11, 23, 47, 71)
        weights = (30, 35, 20, 10, 5)
    elif response:
        choices = (0, 11, 23, 35)
        weights = (45, 35, 15, 5)
    else:
        choices = (0, 11, 23)
        weights = (35, 50, 15)
    return rng.choices(choices, weights=weights, k=1)[0]


def _dns_rr_rdata_size(query_type: str, answer: str) -> int:
    """Return an approximate RDATA length for a source-native DNS answer."""
    if query_type in _DNS_QTYPE_RDATA_LENGTHS:
        return _DNS_QTYPE_RDATA_LENGTHS[query_type]
    if query_type in {"CNAME", "PTR", "NS"}:
        return _dns_name_wire_size(answer)
    if query_type == "MX":
        parts = answer.split(maxsplit=1)
        exchange = parts[1] if len(parts) == 2 else answer
        return 2 + _dns_name_wire_size(exchange)
    if query_type == "SRV":
        parts = answer.split()
        target = parts[-1] if parts else answer
        return 6 + _dns_name_wire_size(target)
    if query_type == "SOA":
        parts = answer.split()
        if len(parts) >= 2:
            return _dns_name_wire_size(parts[0]) + _dns_name_wire_size(parts[1]) + 20
        return max(24, len(answer.encode("utf-8", errors="ignore")))
    if query_type == "TXT":
        text_len = len(answer.encode("utf-8", errors="ignore"))
        return text_len + max(1, math.ceil(text_len / 255))
    return max(4, len(answer.encode("utf-8", errors="ignore")))


def _dns_response_wire_size(*, dns: DnsContext, question_size: int, query_type: str) -> int:
    """Return DNS response payload bytes derived from the visible DNS context."""
    base_size = 12 + question_size
    answers = dns.answers or []
    if answers:
        rr_bytes = 0
        for answer in answers:
            rdata_size = _dns_rr_rdata_size(query_type, str(answer))
            rr_bytes += 2 + 10 + rdata_size  # compressed owner pointer + RR metadata
        return (
            base_size
            + rr_bytes
            + _dns_payload_padding(
                query=dns.query,
                query_type=query_type,
                response=True,
            )
        )

    rcode = (dns.rcode or "").upper()
    if rcode in {"NXDOMAIN", "SERVFAIL", "REFUSED"} or dns.rcode_num in {2, 3, 5}:
        failure_seed = _stable_seed(f"dns_failure_payload:{dns.query}:{query_type}:{rcode}")
        failure_rng = random.Random(failure_seed)
        authority_bytes = {
            "NXDOMAIN": failure_rng.randint(36, 92),
            "SERVFAIL": failure_rng.randint(18, 46),
            "REFUSED": failure_rng.randint(18, 54),
        }.get(rcode, failure_rng.randint(18, 54))
        return (
            base_size
            + authority_bytes
            + _dns_payload_padding(
                query=dns.query,
                query_type=query_type,
                response=True,
            )
        )

    if rcode == "NOERROR" or dns.rcode_num == 0:
        return base_size + _dns_payload_padding(
            query=dns.query,
            query_type=query_type,
            response=True,
        )
    return 0


def _dns_payload_accounting(
    *,
    dns: DnsContext,
    duration: float | None,
    orig_bytes: int | None,
    resp_bytes: int | None,
) -> tuple[float | None, int, int]:
    """Normalize DNS conn.log payload accounting to the DNS transaction."""
    query = dns.query or ""
    query_type = (dns.query_type or "").upper()
    response_rcodes = {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
    has_response = (
        dns.rtt is not None
        or bool(dns.answers)
        or dns.rcode.upper() in response_rcodes
        or dns.rcode_num in {0, 2, 3, 5}
    )
    question_size = _dns_question_wire_size(query)
    query_payload_size = (
        12
        + question_size
        + _dns_payload_padding(
            query=query,
            query_type=query_type,
            response=False,
        )
    )
    normalized_orig = max(28, min(query_payload_size, 1232))

    if not has_response:
        normalized_resp = 0
    else:
        response_payload_size = _dns_response_wire_size(
            dns=dns,
            question_size=question_size,
            query_type=query_type,
        )
        normalized_resp = max(40, min(response_payload_size, 1232))

    normalized_duration = duration
    if dns.rtt is not None:
        normalized_duration = dns.rtt

    return normalized_duration, normalized_orig, normalized_resp


_NONINTERACTIVE_BASH_USERS = {"apache", "www-data", "nginx", "httpd", "tomcat"}


def _is_noninteractive_bash_user(user: User) -> bool:
    """Return True for service accounts that should not render shell history."""
    return user.username.lower() in _NONINTERACTIVE_BASH_USERS


# Fixed baseline activity patterns (no LLM expansion)
# Format: (activity_type, probability)
# Phase 5.6: Widened probability gaps for user diversity scoring
BASELINE_PATTERNS = {
    "developer": [
        ("logon", 0.7),
        ("process_code", 0.75),  # Dominant: code editors
        ("connection_git", 0.5),  # Heavy git usage
        ("process_build", 0.45),  # Frequent builds
        ("process_user_apps", 0.15),  # Minimal app usage
    ],
    "executive": [
        ("logon", 0.9),
        ("connection_web", 0.8),  # Dominant: browsing
        ("connection_email", 0.75),  # Heavy email
        ("process_user_apps", 0.7),  # Heavy Office/apps
    ],
    "analyst": [
        ("logon", 0.85),
        ("process_query", 0.7),  # Dominant: database queries
        ("connection_db", 0.6),  # Heavy DB connections
        ("process_user_apps", 0.45),  # Moderate apps (Excel, etc.)
    ],
    "sysadmin": [
        ("logon", 0.9),
        ("process_system", 0.65),  # Dominant: system tools
        ("process_code", 0.35),
        ("process_query", 0.3),
        ("connection_web", 0.2),
        ("process_user_apps", 0.1),  # Minimal app usage
    ],
    "default": [
        ("logon", 0.75),
        ("connection_web", 0.5),
        ("process_user_apps", 0.35),
    ],
}

# Organic bash commands for noise injection between storyline events
# and baseline Linux user activity. Common admin/orientation commands.
# Process names and command lines for baseline activities (Windows)
PROCESS_TEMPLATES = {
    "process_code": [
        ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe --folder-uri {project_path}"),
        (
            "C:\\Program Files (x86)\\Notepad++\\notepad++.exe",
            "notepad++ {source_file}",
        ),
        ("C:\\Program Files\\JetBrains\\IntelliJ IDEA\\bin\\idea64.exe", "idea64.exe"),
        (
            "C:\\Program Files\\Sublime Text\\sublime_text.exe",
            "sublime_text.exe {source_file}",
        ),
    ],
    "process_build": [
        (
            "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
            "MSBuild.exe {solution_name} /t:Build /p:Configuration={build_config}",
        ),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c npm run {npm_script}"),
        (
            "C:\\Program Files\\dotnet\\dotnet.exe",
            "dotnet.exe build -c {build_config}",
        ),
        ("C:\\Program Files\\nodejs\\node.exe", "node.exe scripts/build.js"),
    ],
    "process_query": [
        (
            "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
            'sqlcmd.exe -S {db_server} -Q "{sql_query}"',
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            'powershell.exe -Command "{ps_command}"',
        ),
        (
            "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe",
            'sqlcmd.exe -S {db_server} -d {db_name} -Q "{sql_query}"',
        ),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -ExecutionPolicy Bypass -File {ps_script}",
        ),
        ("C:\\Windows\\System32\\wbem\\WMIC.exe", "WMIC.exe {wmic_query}"),
        (
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            'powershell.exe -Command "{ps_command}"',
        ),
    ],
    "process_user_apps": [
        # Index 0: Chrome main process (child renderers spawned separately)
        ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
        # Index 1: Firefox main process (child content procs spawned separately)
        ("C:\\Program Files\\Mozilla Firefox\\firefox.exe", "firefox.exe"),
        # Index 2: Outlook
        ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
        # Index 3: Word
        (
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            'WINWORD.EXE /n "{doc_path}"',
        ),
        # Index 4: Excel
        (
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
            'EXCEL.EXE "{spreadsheet_path}"',
        ),
        # Index 5: Edge main process (child renderers spawned separately)
        ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe"),
        # Index 6: Teams main process (utility procs spawned separately)
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
            "Teams.exe",
        ),
        # Index 7: OneDrive main process (background proc spawned separately)
        (
            "C:\\Users\\{username}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
            "OneDrive.exe",
        ),
        # Index 8: Acrobat
        ("C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe", "Acrobat.exe"),
        # Index 9: 7-Zip
        ("C:\\Program Files\\7-Zip\\7zFM.exe", "7zFM.exe"),
    ],
    "process_system": [
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p -s Schedule"),
        (
            "C:\\Windows\\System32\\svchost.exe",
            "svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog",
        ),
        ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k DcomLaunch -p"),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\explorer.exe"),
        (
            "C:\\Windows\\System32\\RuntimeBroker.exe",
            "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        ),
        (
            "C:\\Windows\\System32\\SearchIndexer.exe",
            "C:\\Windows\\System32\\SearchIndexer.exe /Embedding",
        ),
        ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
        ("C:\\Windows\\System32\\conhost.exe", "conhost.exe 0x4"),
        (
            "C:\\Windows\\System32\\dllhost.exe",
            "dllhost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}",
        ),
        ("C:\\Windows\\System32\\sihost.exe", "sihost.exe"),
    ],
}

# Process names and command lines for baseline activities (Linux) - Phase 2.10
PROCESS_TEMPLATES_LINUX = {
    "process_code": [
        ("/usr/bin/vim", "vim {linux_project}/{linux_source_file}"),
        ("/usr/bin/nano", "nano {linux_project}/{linux_source_file}"),
        ("/usr/bin/code", "code --no-sandbox {linux_project}"),
        ("/usr/bin/emacs", "emacs -nw {linux_project}/{linux_source_file}"),
    ],
    "process_build": [
        ("/usr/bin/make", "make -j4 -C {linux_project}"),
        ("/usr/bin/gcc", "gcc -o output {c_source_file}"),
        ("/usr/bin/npm", "npm run {npm_script}"),
        ("/usr/bin/cargo", "cargo build --release"),
        ("/usr/bin/python3", "python3 -m pip install -e {linux_project}"),
    ],
    "process_query": [
        ("/usr/bin/mysql", "mysql --defaults-extra-file=~/.my.cnf {mysql_db}"),
        ("/usr/bin/psql", "psql -U postgres -d {psql_db}"),
        ("/usr/bin/redis-cli", "{redis_cmd}"),
    ],
    "process_user_apps": [
        ("/usr/bin/firefox", "firefox --new-tab {internal_url}"),
        ("/usr/bin/thunderbird", "thunderbird"),
        ("/usr/bin/git", "git pull origin {git_branch}"),
        ("/usr/bin/docker", "docker ps"),
        ("/usr/bin/python3", "python3 -m pytest tests/"),
        ("/usr/bin/ssh", "ssh {username}@remote-host"),
        ("/usr/bin/curl", "curl -s https://api.example.com/status"),
        ("/usr/bin/kubectl", "kubectl get pods -n production"),
    ],
    "process_system": [
        ("/usr/lib/systemd/systemd", "systemd --user"),
        ("/usr/sbin/cron", "/usr/sbin/cron -f"),
        ("/usr/sbin/sshd", "/usr/sbin/sshd -D"),
        ("/usr/sbin/rsyslogd", "/usr/sbin/rsyslogd -n"),
        ("/usr/sbin/NetworkManager", "/usr/sbin/NetworkManager --no-daemon"),
        ("/usr/bin/dbus-daemon", "dbus-daemon --system --address=systemd:"),
        ("/usr/sbin/atd", "/usr/sbin/atd -f"),
    ],
}

# Per-persona process type weights (Phase 5.1)
# Maps persona name to relative probability of each process template category
PERSONA_PROCESS_WEIGHTS = {
    "developer": {
        "process_code": 0.5,
        "process_build": 0.3,
        "process_user_apps": 0.15,
        "process_system": 0.05,
    },
    "executive": {
        "process_code": 0.05,
        "process_build": 0.0,
        "process_user_apps": 0.8,
        "process_system": 0.15,
    },
    "analyst": {
        "process_code": 0.1,
        "process_build": 0.05,
        "process_query": 0.5,
        "process_user_apps": 0.3,
        "process_system": 0.05,
    },
    "sysadmin": {
        "process_code": 0.2,
        "process_build": 0.1,
        "process_query": 0.2,
        "process_user_apps": 0.1,
        "process_system": 0.4,
    },
    "default": {
        "process_code": 0.15,
        "process_build": 0.05,
        "process_user_apps": 0.6,
        "process_system": 0.2,
    },
}

# Per-persona app subsets for process_user_apps (Phase 5.6: user diversity)
# Each persona favors a different mix of applications from PROCESS_TEMPLATES['process_user_apps']
# Index references into PROCESS_TEMPLATES['process_user_apps']:
#   0=Chrome, 1=Firefox, 2=Outlook, 3=Word, 4=Excel, 5=Edge, 6=Teams, 7=OneDrive, 8=Acrobat, 9=7-Zip
PERSONA_APP_INDICES = {
    "developer": [0, 6, 7, 9],  # Chrome, Teams, OneDrive, 7-Zip
    "executive": [2, 3, 5, 6, 8],  # Outlook, Word, Edge, Teams, Acrobat
    "analyst": [0, 4, 2, 6, 8],  # Chrome, Excel, Outlook, Teams, Acrobat
    "sysadmin": [1, 5, 6, 9],  # Firefox, Edge, Teams, 7-Zip
    "default": [0, 2, 6, 7],  # Chrome, Outlook, Teams, OneDrive
}

# Per-persona app subsets for Linux process_user_apps
# Index references into PROCESS_TEMPLATES_LINUX['process_user_apps']:
#   0=firefox, 1=thunderbird, 2=git, 3=docker, 4=pytest, 5=ssh, 6=curl, 7=kubectl
PERSONA_APP_INDICES_LINUX = {
    "developer": [0, 2, 3, 4, 6],  # firefox, git, docker, pytest, curl
    "executive": [0, 1],  # firefox, thunderbird
    "analyst": [0, 5, 6],  # firefox, ssh, curl
    "sysadmin": [2, 3, 5, 6, 7],  # git, docker, ssh, curl, kubectl
    "default": [0, 2, 5, 6],  # firefox, git, ssh, curl
}

# Zeek TCP connection state distribution with matching history strings
# Format: (conn_state, weight, history_string)
# Rebalanced: SF ~62% (real enterprise: 55-75%), non-SF states expanded
TCP_CONN_STATE_DISTRIBUTION = [
    # Normal completions (SF) — ~62% total (real: 55-75%)
    ("SF", 21, "ShADadfF"),  # Standard: SYN→SYN-ACK→data→FIN
    ("SF", 11, "ShADaDadfF"),  # Multiple data exchanges before FIN
    ("SF", 6, "ShADadTtFf"),  # Normal with retransmissions (T=orig retx, t=resp retx)
    ("SF", 5, "ShADadfFa"),  # FIN-ACK with trailing ACK
    ("SF", 5, "ShADaDaDadfF"),  # Bulk transfer (many data rounds)
    ("SF", 4, "ShADadFf"),  # Originator FIN first (client closes)
    ("SF", 4, "ShADaDadfFa"),  # Multi-exchange with trailing ACK
    ("SF", 3, "ShADadTFf"),  # Retransmit then FIN
    ("SF", 2, "ShADaDadFf"),  # Multi data then client closes
    ("SF", 1, "ShADaDaTtdfF"),  # Multi data with retransmissions
    # Connection attempts (S0) — ~14% (timeouts, unreachable hosts, scanning)
    ("S0", 9, "S"),  # Single SYN, no reply
    ("S0", 5, "S"),  # SYN retransmit (Zeek deduplicates to single 'S')
    # Partial handshakes (S1) — ~3%
    ("S1", 2, "ShR"),  # SYN-ACK seen, RST
    ("S1", 1, "Sh"),  # SYN-ACK seen, no further data
    # Rejected connections (REJ) — ~5% (refused ports, firewall rejects)
    ("REJ", 3, "Sr"),  # RST from responder immediately
    ("REJ", 2, "Srr"),  # Multiple RSTs from responder
    # Reset by originator (RSTO) — ~8% (client aborts, load balancer health checks)
    ("RSTO", 4, "ShADaR"),  # Data exchange then originator RST
    ("RSTO", 2, "ShADadTR"),  # Data + retransmit then RST
    ("RSTO", 2, "ShAR"),  # Quick RST after handshake
    # Reset by responder (RSTR) — ~5% (server resets, IDS/WAF termination)
    ("RSTR", 3, "ShADadR"),  # Data exchange then responder RST
    ("RSTR", 2, "ShAdR"),  # Partial data then responder RST
    # Half-closed states — ~2% (one side closed, other didn't respond)
    ("S2", 1, "ShADadF"),  # Orig sent FIN, responder never replied
    ("S3", 1, "ShADadf"),  # Resp sent FIN, originator never replied
    # Midstream (OTH) — ~1% (partial captures, NAT state loss)
    ("OTH", 1, "Cc"),  # Midstream traffic (no SYN/SYN-ACK seen)
]

# Zeek UDP connection state distribution
# UDP has no TCP handshake — only D/d datagram flags
# Rebalanced: SF ~72% (more S0 timeouts for realistic DNS/NTP failures)
UDP_CONN_STATE_DISTRIBUTION = [
    ("SF", 55, "Dd"),  # Normal bidirectional exchange (query + response)
    ("SF", 8, "DdDd"),  # Multi-packet exchange
    ("SF", 5, "DdDdDd"),  # Extended multi-packet exchange
    ("SF", 4, "DDd"),  # Retransmitted query before response
    ("S0", 12, "D"),  # Originator only, no response (timeout)
    ("S0", 6, "DD"),  # Retransmitted datagram, no response
    ("OTH", 6, "Dd"),  # Midstream UDP exchange
    ("OTH", 4, "DdDd"),  # Midstream multi-packet exchange
]

# Pre-extract for random.choices — TCP (select full tuples, not just states)
_TCP_CONN_ENTRIES = TCP_CONN_STATE_DISTRIBUTION
_TCP_CONN_WEIGHTS = [s[1] for s in TCP_CONN_STATE_DISTRIBUTION]
_TCP_SUCCESS_HISTORY_ENTRIES = [
    (history, weight) for conn_state, weight, history in _TCP_CONN_ENTRIES if conn_state == "SF"
]
_TCP_SUCCESS_HISTORY_WEIGHTS = [weight for _history, weight in _TCP_SUCCESS_HISTORY_ENTRIES]

# Pre-extract for random.choices — UDP
_UDP_CONN_ENTRIES = UDP_CONN_STATE_DISTRIBUTION
_UDP_CONN_WEIGHTS = [s[1] for s in UDP_CONN_STATE_DISTRIBUTION]


def _tcp_success_history(rng: random.Random) -> str:
    """Choose a plausible Zeek history string for a completed TCP connection."""
    return rng.choices(
        [history for history, _weight in _TCP_SUCCESS_HISTORY_ENTRIES],
        weights=_TCP_SUCCESS_HISTORY_WEIGHTS,
        k=1,
    )[0]


# Legacy aliases for backward compatibility
CONN_STATE_DISTRIBUTION = TCP_CONN_STATE_DISTRIBUTION
_CONN_STATES = [s[0] for s in TCP_CONN_STATE_DISTRIBUTION]
_CONN_WEIGHTS = _TCP_CONN_WEIGHTS
_CONN_HISTORY = {s[0]: s[2] for s in TCP_CONN_STATE_DISTRIBUTION}

# --- Network realism constants ---

# UDP/IP header overhead: standard IPv4 (28), VLAN/QinQ and IP options variants.
# Keep this bounded by the physical IPv4 maximum: IP header 60 + UDP header 8.
_UDP_OVERHEAD_VALUES = (28, 32, 52, 60, 68)
_UDP_OVERHEAD_WEIGHTS = (93, 5, 1, 0.5, 0.5)

# TCP header overhead: bimodal around 40/52/60
# 40=no options (legacy), 52=timestamps (dominant), 60=SACK+ts, 64=full
_TCP_OVERHEAD_VALUES = (40, 52, 60, 64)
_TCP_OVERHEAD_WEIGHTS = (10, 75, 10, 5)
_TCP_MSS_BYTES = 1460
_TCP_MSS_VALUES = (1200, 1320, 1360, 1448, 1460)
_TCP_MSS_WEIGHTS = (2, 4, 10, 22, 62)
_TCP_ACK_FLOOR_PAYLOAD_BYTES = 64 * 1024
_CLIENT_FIRST_TCP_PAYLOAD_SERVICES = frozenset(
    {
        "dce_rpc",
        "dns",
        "http",
        "https",
        "kerberos",
        "ldap",
        "ldaps",
        "mssql",
        "mysql",
        "postgresql",
        "rdp",
        "smb",
        "ssl",
        "tds",
        "winrm",
    }
)
_CLIENT_FIRST_TCP_PAYLOAD_PORTS = frozenset(
    {
        53,
        80,
        88,
        135,
        389,
        443,
        445,
        464,
        636,
        1433,
        3268,
        3269,
        3306,
        3389,
        5432,
        5985,
        5986,
        8080,
        8443,
    }
)


def _tcp_effective_mss_bytes(rng: random.Random) -> int:
    """Return a plausible effective TCP MSS for source packet accounting."""
    return rng.choices(_TCP_MSS_VALUES, weights=_TCP_MSS_WEIGHTS, k=1)[0]


def _tcp_payload_segment_count(
    payload_bytes: int | None,
    mss_bytes: int = _TCP_MSS_BYTES,
) -> int:
    """Return the minimum TCP payload segment count for Zeek packet accounting."""
    if payload_bytes is None or payload_bytes <= 0:
        return 0
    effective_mss = max(1, mss_bytes)
    return max(1, (payload_bytes + effective_mss - 1) // effective_mss)


def _tcp_payload_packet_count(payload_bytes: int | None, rng: random.Random) -> int:
    """Return source-visible TCP data packets with MSS and segmentation texture."""
    segments = _tcp_payload_segment_count(payload_bytes, _tcp_effective_mss_bytes(rng))
    if segments <= 0:
        return 0
    if segments >= 8:
        extra_fraction = rng.choices(
            (0.0, 0.001, 0.0025, 0.005, 0.01),
            weights=(35, 20, 20, 15, 10),
            k=1,
        )[0]
        if extra_fraction > 0:
            segments += max(1, int(round(segments * extra_fraction)))
        elif rng.random() < 0.35:
            segments += 1
    return segments


def _tcp_history_packet_counts(history: str | None) -> tuple[int, int, int, int]:
    """Return total and non-data packet markers by Zeek history side."""
    text = history or ""
    orig_total = sum(1 for char in text if char.isupper())
    resp_total = sum(1 for char in text if char.islower())
    orig_control = sum(1 for char in text if char.isupper() and char != "D")
    resp_control = sum(1 for char in text if char.islower() and char != "d")
    return orig_total, resp_total, orig_control, resp_control


def _tcp_packet_counts_from_payload_and_history(
    orig_bytes: int | None,
    resp_bytes: int | None,
    history: str | None,
    rng: random.Random,
) -> tuple[int, int]:
    """Return TCP packet counts including payload segments and visible control packets."""
    orig_total, resp_total, orig_control, resp_control = _tcp_history_packet_counts(history)
    orig_data = _tcp_payload_packet_count(orig_bytes, rng)
    resp_data = _tcp_payload_packet_count(resp_bytes, rng)

    orig_pkts = max(orig_total, orig_data + orig_control) if orig_data else orig_total
    resp_pkts = max(resp_total, resp_data + resp_control) if resp_data else resp_total
    return _apply_tcp_ack_packet_floors(orig_pkts, resp_pkts, orig_bytes, resp_bytes, rng)


def _tcp_payload_bytes_consistent_with_history(
    orig_bytes: int | None,
    resp_bytes: int | None,
    history: str | None,
) -> tuple[int | None, int | None]:
    """Return TCP payload byte counts that agree with Zeek history data markers."""
    if not history or history == "-":
        return orig_bytes, resp_bytes

    normalized_orig = orig_bytes
    normalized_resp = resp_bytes
    if (orig_bytes or 0) > 0 and "D" not in history:
        normalized_orig = 0
    if (resp_bytes or 0) > 0 and "d" not in history:
        normalized_resp = 0
    return normalized_orig, normalized_resp


def _tcp_service_requires_client_payload_first(service: str | None, dst_port: int) -> bool:
    """Return whether responder payload requires prior originator payload."""
    normalized_service = (service or "").strip().lower()
    return (
        normalized_service in _CLIENT_FIRST_TCP_PAYLOAD_SERVICES
        or dst_port in _CLIENT_FIRST_TCP_PAYLOAD_PORTS
    )


def _insert_originator_payload_before_responder_payload(history: str) -> str:
    """Add a Zeek originator data marker before the first responder data marker."""
    if "D" in history or "d" not in history:
        return history
    resp_index = history.index("d")
    if resp_index > 0 and history[resp_index - 1] == "A":
        return f"{history[:resp_index]}Da{history[resp_index:]}"
    return f"{history[:resp_index]}D{history[resp_index:]}"


def _client_first_originator_payload_floor(
    service: str | None,
    dst_port: int,
    rng: random.Random,
) -> int:
    """Return a plausible minimum request/client-hello payload for client-first TCP."""
    normalized_service = (service or "").strip().lower()
    if normalized_service in {"ssl", "https"} or dst_port in {443, 8443}:
        return rng.randint(180, 900)
    if normalized_service == "http" or dst_port in {80, 8080}:
        return rng.randint(120, 620)
    if normalized_service in {"smb", "ldap", "ldaps", "kerberos", "dce_rpc", "rdp", "winrm"}:
        return rng.randint(72, 420)
    if normalized_service in {"mssql", "mysql", "postgresql", "tds"} or dst_port in {
        1433,
        3306,
        5432,
    }:
        return rng.randint(64, 360)
    if normalized_service == "dns" or dst_port == 53:
        return rng.randint(40, 220)
    return rng.randint(72, 480)


def _enforce_client_first_tcp_payload_order(net: NetworkContext, rng: random.Random) -> bool:
    """Ensure client-first TCP responses have visible originator application payload."""
    if (
        net.protocol != "tcp"
        or net.conn_state in {"S0", "REJ", "S1", "SH", "SHR", "OTH"}
        or not _tcp_service_requires_client_payload_first(net.service, net.dst_port)
        or (net.resp_bytes or 0) <= 0
        or "d" not in (net.history or "")
    ):
        return False

    changed = False
    history = net.history or ""
    normalized_history = _insert_originator_payload_before_responder_payload(history)
    if normalized_history != history:
        net.history = normalized_history
        changed = True

    if (net.orig_bytes or 0) <= 0:
        net.orig_bytes = _client_first_originator_payload_floor(net.service, net.dst_port, rng)
        changed = True

    return changed


def _align_tcp_network_payload_with_history(
    net: NetworkContext,
    rng: random.Random,
) -> bool:
    """Align TCP payload, packet, and IP-byte fields with Zeek history markers."""
    if net.protocol != "tcp":
        return False
    changed = _enforce_client_first_tcp_payload_order(net, rng)
    orig_bytes, resp_bytes = _tcp_payload_bytes_consistent_with_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
    )
    if not changed and orig_bytes == net.orig_bytes and resp_bytes == net.resp_bytes:
        return False

    net.orig_bytes = orig_bytes
    net.resp_bytes = resp_bytes
    net.orig_pkts, net.resp_pkts = _tcp_packet_counts_from_payload_and_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
        rng,
    )
    net.orig_ip_bytes = _tcp_ip_byte_count(net.orig_bytes, net.orig_pkts, rng)
    net.resp_ip_bytes = _tcp_ip_byte_count(net.resp_bytes, net.resp_pkts, rng)
    return True


def _preserve_explicit_tcp_payload_overrides(
    net: NetworkContext,
    *,
    explicit_orig_bytes: int | None,
    explicit_resp_bytes: int | None,
    rng: random.Random,
) -> bool:
    """Re-apply explicit author payload intent after protocol shaping."""
    if net.protocol != "tcp" or net.conn_state != "SF":
        return False

    changed = False
    if explicit_orig_bytes is not None and explicit_orig_bytes > (net.orig_bytes or 0):
        net.orig_bytes = explicit_orig_bytes
        changed = True
    if explicit_resp_bytes is not None and explicit_resp_bytes > (net.resp_bytes or 0):
        net.resp_bytes = explicit_resp_bytes
        changed = True
    if not changed:
        return False

    net.orig_pkts, net.resp_pkts = _tcp_packet_counts_from_payload_and_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
        rng,
    )
    net.orig_ip_bytes = _tcp_ip_byte_count(net.orig_bytes, net.orig_pkts, rng)
    net.resp_ip_bytes = _tcp_ip_byte_count(net.resp_bytes, net.resp_pkts, rng)
    return True


def _tcp_ip_byte_count(
    payload_bytes: int | None,
    packet_count: int,
    rng: random.Random,
    *,
    overhead_override: int | None = None,
) -> int:
    """Return TCP IP-byte accounting with header and control-packet texture."""
    if packet_count <= 0:
        return 0
    if overhead_override is not None:
        return (payload_bytes or 0) + packet_count * overhead_override
    overhead = rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
    option_extra = 0
    if packet_count > 1:
        textured_packets = min(
            packet_count,
            8192,
            max(1, int(round(packet_count * rng.uniform(0.001, 0.018)))),
        )
        max_option_extra = packet_count * (max(_TCP_OVERHEAD_VALUES) - overhead)
        option_extra = min(max_option_extra, textured_packets * rng.choice((4, 8, 12)))
    return (payload_bytes or 0) + packet_count * overhead + option_extra


def _tcp_ack_packet_floor(peer_payload_bytes: int | None, rng: random.Random) -> int:
    """Return a plausible ACK-only packet floor for a peer's large TCP payload."""
    segments = _tcp_payload_segment_count(peer_payload_bytes)
    if segments == 0 or (peer_payload_bytes or 0) < _TCP_ACK_FLOOR_PAYLOAD_BYTES:
        return 0
    ack_every_segments = rng.choices((2, 3, 4), weights=(70, 20, 10), k=1)[0]
    return max(16, (segments + ack_every_segments - 1) // ack_every_segments)


def _apply_tcp_ack_packet_floors(
    orig_pkts: int,
    resp_pkts: int,
    orig_bytes: int | None,
    resp_bytes: int | None,
    rng: random.Random,
) -> tuple[int, int]:
    """Ensure large one-way TCP transfers include plausible reverse ACK packets."""
    orig_ack_floor = _tcp_ack_packet_floor(resp_bytes, rng)
    resp_ack_floor = _tcp_ack_packet_floor(orig_bytes, rng)
    return max(orig_pkts, orig_ack_floor), max(resp_pkts, resp_ack_floor)


# NTP stratum-based timing: (mean_ms, sigma) for lognormal
_NTP_STRATUM_TIMING = {
    1: (2.0, 0.5),  # GPS-connected
    2: (10.0, 0.7),  # synced to stratum 1
    3: (30.0, 0.8),  # synced to stratum 2
}

# TLS cipher distributions (weighted)
_TLS_VERSION_VALUES = ("TLSv12", "TLSv13")
_TLS_VERSION_WEIGHTS = (45, 55)

_TLS12_CIPHER_DIST = (
    ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 60),
    ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 25),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 10),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 5),
)
_TLS12_CIPHER_VALUES = tuple(c[0] for c in _TLS12_CIPHER_DIST)
_TLS12_CIPHER_WEIGHTS = tuple(c[1] for c in _TLS12_CIPHER_DIST)

_TLS13_CIPHER_DIST = (
    ("TLS_AES_128_GCM_SHA256", 55),
    ("TLS_AES_256_GCM_SHA384", 30),
    ("TLS_CHACHA20_POLY1305_SHA256", 15),
)
_TLS13_CIPHER_VALUES = tuple(c[0] for c in _TLS13_CIPHER_DIST)
_TLS13_CIPHER_WEIGHTS = tuple(c[1] for c in _TLS13_CIPHER_DIST)

# SSL history patterns (weighted).  Zeek's ssl_history values are handshake
# message-type codes, not conn.log-style originator/responder direction flags;
# established TLS rows should include "S" for the ServerHello.
_SSL_HISTORY_TLS12_SUCCESS = (
    ("CSXKNGIFIFD", 34),  # ECDHE full handshake plus encrypted app data
    ("CSXNGIFIFD", 18),  # RSA/static-key full handshake
    ("CSXKNGIFIFT", 18),  # full handshake with NewSessionTicket
    ("CSIFIFD", 20),  # abbreviated/resumed session
    ("CSXKNGIFIFL", 10),  # established then alert/close
)
_SSL_HISTORY_TLS13_SUCCESS = (
    ("CSOXYFFD", 36),  # full TLS 1.3 handshake plus encrypted app data
    ("CSOFFD", 26),  # resumed/PSK-style handshake
    ("CSOXYFFTD", 18),  # full handshake with ticket
    ("CSJOXYFFD", 8),  # HelloRetryRequest path
    ("CSOXYFFL", 12),  # established then alert/close
)
_SSL_HISTORY_SUCCESS = _SSL_HISTORY_TLS12_SUCCESS + _SSL_HISTORY_TLS13_SUCCESS
_SSL_HIST_SUCCESS_VALUES = tuple(h[0] for h in _SSL_HISTORY_SUCCESS)
_SSL_HIST_SUCCESS_WEIGHTS = tuple(h[1] for h in _SSL_HISTORY_SUCCESS)

_SSL_HISTORY_FAILURE = (
    ("C", 45),  # client hello only, no visible server response
    ("CS", 30),  # server hello seen, handshake did not complete
    ("CSL", 25),  # server alert during handshake
)
_SSL_HIST_FAILURE_VALUES = tuple(h[0] for h in _SSL_HISTORY_FAILURE)
_SSL_HIST_FAILURE_WEIGHTS = tuple(h[1] for h in _SSL_HISTORY_FAILURE)

_SSL_FAILURE_RATE = 0.02  # ~2% handshake failure


def _choose_ssl_history(
    rng: random.Random,
    *,
    tls_version: str,
    established: bool,
    resumed: bool,
) -> str:
    """Choose a Zeek ssl_history value that matches TLS version and outcome."""
    return _choose_ssl_history_from_roll(
        rng.random(),
        tls_version=tls_version,
        established=established,
        resumed=resumed,
    )


def _choose_ssl_history_from_roll(
    roll: float,
    *,
    tls_version: str,
    established: bool,
    resumed: bool,
) -> str:
    """Map a pre-drawn random roll onto a Zeek ssl_history value."""
    if not established:
        return _weighted_choice_from_roll(
            _SSL_HIST_FAILURE_VALUES,
            _SSL_HIST_FAILURE_WEIGHTS,
            roll,
        )

    if tls_version == "TLSv13":
        if resumed:
            values = ("CSOFFD", "CSOXYFFTD", "CSOXYFFD")
            weights = (60, 25, 15)
        else:
            values = tuple(history for history, _ in _SSL_HISTORY_TLS13_SUCCESS)
            weights = tuple(weight for _, weight in _SSL_HISTORY_TLS13_SUCCESS)
    elif resumed:
        values = ("CSIFIFD", "CSXKNGIFIFT", "CSXKNGIFIFD")
        weights = (55, 30, 15)
    else:
        values = tuple(history for history, _ in _SSL_HISTORY_TLS12_SUCCESS)
        weights = tuple(weight for _, weight in _SSL_HISTORY_TLS12_SUCCESS)

    return _weighted_choice_from_roll(values, weights, roll)


def _weighted_choice_from_roll(
    values: tuple[str, ...], weights: tuple[int, ...], roll: float
) -> str:
    """Return a deterministic weighted choice from an already consumed RNG roll."""
    total = sum(weights)
    threshold = max(0.0, min(roll, 0.999999999999)) * total
    cumulative = 0.0
    for value, weight in zip(values, weights, strict=True):
        cumulative += weight
        if threshold < cumulative:
            return value
    return values[-1]


# Proxy header overhead ranges (bytes)
_PROXY_CS_OVERHEAD = (80, 350)  # Via, X-Forwarded-For, etc.
_PROXY_SC_OVERHEAD = (50, 250)  # Via, X-Cache, Age, etc.
_AUTO_WEIRD_ENABLED = False  # weird.log realism is deferred; explicit contexts still render.
_EXPLICIT_PROXY_TUNNEL_TIMEOUT_S = 240
_PROXY_MACHINE_USER_AGENT_MARKERS = (
    "adobearm/",
    "cisco secure client/",
    "dell command update/",
    "globalprotect/",
    "googleupdate/",
    "hp image assistant",
    "lenovo system update",
    "microsoft-cryptoapi/",
    "windows-update-agent/",
    "zscaler client connector/",
)

# Kerberos TGS service name distribution (weighted)
_KERBEROS_SVC_DIST = (
    ("cifs/{hostname}", 45),  # file share access dominates
    ("host/{hostname}", 20),  # generic host service
    ("http/{hostname}", 15),  # web services
    ("ldap/{hostname}", 10),  # directory queries
    ("krbtgt/{domain}", 5),  # TGT renewals
    ("DNS/{hostname}", 5),  # DNS service tickets
)
_KERBEROS_SVC_VALUES = tuple(s[0] for s in _KERBEROS_SVC_DIST)
_KERBEROS_SVC_WEIGHTS = tuple(s[1] for s in _KERBEROS_SVC_DIST)


def _ephemeral_port(rng: random.Random, os_category: str = "windows") -> int:
    """Generate a random ephemeral port appropriate for the OS.

    Linux uses 32768-60999 (net.ipv4.ip_local_port_range default).
    Windows uses 49152-65535 (IANA dynamic port range).
    """
    if os_category == "linux":
        return rng.randint(32768, 60999)
    return rng.randint(49152, 65535)


def _dns_rtt(rng: random.Random, resolver_ip: str | None = None) -> float:
    """Generate a realistic DNS round-trip time using a mixture model.

    Models real DNS traffic distribution:
    - Internal resolvers: cache/local responses can be sub-ms
    - Public resolvers: LAN-to-resolver RTT should rarely be sub-ms

    Returns:
        RTT in seconds.
    """
    if resolver_ip and not _is_private_ip(resolver_ip):
        roll = rng.random()
        if roll < 0.08:
            return rng.uniform(0.002, 0.008)  # Very close public resolver / warmed path
        if roll < 0.70:
            return rng.uniform(0.008, 0.035)  # Common enterprise egress latency
        if roll < 0.95:
            return rng.uniform(0.035, 0.120)  # Recursive/cache miss or distance
        return rng.uniform(0.120, 0.350)  # Slow/distant resolver response

    roll = rng.random()
    if roll < 0.60:
        return rng.uniform(0.0001, 0.001)  # Cache hit: 0.1-1ms
    elif roll < 0.85:
        return rng.uniform(0.001, 0.010)  # Local resolver: 1-10ms
    elif roll < 0.97:
        return rng.uniform(0.010, 0.080)  # Recursive lookup: 10-80ms
    else:
        return rng.uniform(0.080, 0.250)  # Slow/distant: 80-250ms


def _jitter_default_connection_duration(
    duration: float | None,
    *,
    caller_provided_duration: bool,
    seed_parts: tuple[Any, ...],
) -> float | None:
    """Diversify generator-owned placeholder durations without changing authored values."""
    if caller_provided_duration or duration is None:
        return duration
    anchors = (0.8, 2.0, 0.2, 0.1, 0.02, 0.01)
    if not any(math.isclose(duration, anchor, rel_tol=0.0, abs_tol=1e-9) for anchor in anchors):
        return duration
    seed = _stable_seed("default_conn_duration:" + ":".join(str(part) for part in seed_parts))
    rng = random.Random(seed)
    if duration <= 0.02:
        return max(0.0005, duration * rng.uniform(0.55, 1.85) + rng.uniform(0.0002, 0.004))
    return max(0.001, duration * rng.uniform(0.82, 1.24) + rng.uniform(-0.015, 0.035))


def _dns_registrable_domain(hostname: str) -> str:
    """Return a practical DNS owner name for mail/TXT companion lookups."""
    return dns_registrable_domain(hostname)


def _dns_reverse_query(ip: str) -> str:
    """Return the in-addr.arpa owner name for an IPv4 address."""
    octets = ip.split(".")
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def _public_dns_ptr_response(ip: str, forward_hostname: str | None) -> tuple[str, int, list[str]]:
    """Return a resolver-visible public PTR response for companion lookups."""
    rng = random.Random(_stable_seed(f"public_dns_ptr:{ip}:{forward_hostname or ''}"))
    # Public reverse DNS is often absent for SaaS/CDN destinations observed
    # through enterprise resolvers. Keep that incompleteness stable per tuple.
    if rng.random() < 0.28:
        return "NXDOMAIN", 3, []
    return "NOERROR", 0, [_generate_rdns_name(rng, ip, forward_hostname)]


def _public_dns_profile(kind: str, domain: str) -> dict[str, Any]:
    """Return a stable provider-style public DNS profile for a domain."""
    from evidenceforge.generation.activity.public_dns_profiles import load_public_dns_profiles

    profiles = load_public_dns_profiles().get(kind, [])
    lowered = domain.lower().rstrip(".")
    for profile in profiles:
        suffixes = [str(suffix).lower().rstrip(".") for suffix in profile.get("match_suffixes", [])]
        if any(lowered == suffix or lowered.endswith(f".{suffix}") for suffix in suffixes):
            return profile

    weighted = [profile for profile in profiles if int(profile.get("weight", 0)) > 0]
    if not weighted:
        return {}
    rng = random.Random(_stable_seed(f"public_dns_profile:{kind}:{lowered}"))
    weights = [int(profile.get("weight", 0)) for profile in weighted]
    return rng.choices(weighted, weights=weights, k=1)[0]


def _public_dns_matched_profile(kind: str, domain: str) -> dict[str, Any]:
    """Return a profile only when the domain matches an explicit suffix."""
    from evidenceforge.generation.activity.public_dns_profiles import load_public_dns_profiles

    profiles = load_public_dns_profiles().get(kind, [])
    lowered = domain.lower().rstrip(".")
    for profile in profiles:
        suffixes = [str(suffix).lower().rstrip(".") for suffix in profile.get("match_suffixes", [])]
        if any(lowered == suffix or lowered.endswith(f".{suffix}") for suffix in suffixes):
            return profile
    return {}


def _render_public_dns_answer(template: str, domain: str) -> str:
    """Render a public DNS answer template using source-owned domain tokens."""
    from evidenceforge.config.public_dns_templates import render_public_dns_answer_template

    return render_public_dns_answer_template(template, domain)


def _public_dns_answer_set(kind: str, domain: str) -> list[str]:
    """Return stable provider-style answers for a public DNS record family."""
    profile = _public_dns_profile(kind, domain)
    answer_sets = profile.get("answer_sets", [])
    if not answer_sets:
        return []
    rng = random.Random(_stable_seed(f"public_dns_answers:{kind}:{domain}:{profile.get('name')}"))
    answers = rng.choice(answer_sets)
    return [_render_public_dns_answer(str(answer), domain) for answer in answers]


def _public_dns_ns_answers(domain: str) -> list[str]:
    """Return realistic public NS answers for a domain."""
    answers = _public_dns_answer_set("nameserver_profiles", domain)
    return answers or [f"ns1.{domain}", f"ns2.{domain}"]


def _public_dns_mx_answers(domain: str) -> list[str]:
    """Return realistic public MX answers for a domain."""
    answers = _public_dns_answer_set("mail_profiles", domain)
    return answers or [f"10 mail.{domain}"]


def _public_dns_has_explicit_owner_profile(domain: str) -> bool:
    """Return whether public DNS profile data recognizes this owner family."""
    return any(
        _public_dns_matched_profile(kind, domain)
        for kind in ("nameserver_profiles", "mail_profiles", "aaaa_profiles")
    )


def _public_dns_aaaa_answers(hostname: str, dst_ip: str, *, is_internal: bool = False) -> list[str]:
    """Return source-owned AAAA answers for a lookup target."""
    if ":" in dst_ip:
        return [dst_ip]

    if is_internal or _is_private_ip(dst_ip):
        ipv6_answer = _IPV6_MAP.get(dst_ip)
        if ipv6_answer is not None:
            return [ipv6_answer]
        return [_ipv4_to_fake_ipv6(dst_ip)]

    owner = _dns_registrable_domain(hostname)
    profile = _public_dns_matched_profile("aaaa_profiles", hostname) or _public_dns_matched_profile(
        "aaaa_profiles", owner
    )
    if profile:
        answer_sets = profile.get("answer_sets", [])
        if not answer_sets:
            return []
        rng = random.Random(_stable_seed(f"public_dns_answers:aaaa_profiles:{hostname}:{dst_ip}"))
        answers = rng.choice(answer_sets)
        return [_render_public_dns_answer(str(answer), owner) for answer in answers]

    if _public_dns_has_explicit_owner_profile(hostname) or _public_dns_has_explicit_owner_profile(
        owner
    ):
        return []

    ipv6_answer = _IPV6_MAP.get(dst_ip)
    if ipv6_answer is not None:
        return [ipv6_answer]

    return [_ipv4_to_fake_ipv6(dst_ip)]


def _dns_soa_answer(domain: str, mname: str, rname: str, seed_context: str = "") -> str:
    """Return source-native SOA RDATA with serial and timer fields."""
    owner = domain.lower().rstrip(".")
    seed = _stable_seed(f"dns_soa:{owner}:{mname}:{rname}:{seed_context}")
    rng = random.Random(seed)
    # Avoid date-coded YYYYMMDDnn serials for generated companion answers.
    # Without owning the zone's real edit history, arbitrary monotonically
    # shaped serials are less misleading than future or invalid date encodings.
    serial = 1_600_000_000 + rng.randint(0, 180_000_000)
    refresh = rng.choice((1800, 3600, 7200, 10800, 14400))
    retry = rng.choice((300, 600, 900, 1200, 1800))
    expire = rng.choice((604800, 1209600, 2419200))
    minimum = rng.choice((60, 300, 600, 900, 1800, 3600))
    return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"


def _public_dns_soa_answers(domain: str) -> list[str]:
    """Return a realistic public SOA answer for a domain."""
    profile = _public_dns_profile("nameserver_profiles", domain)
    nameservers = _public_dns_ns_answers(domain)
    rnames = profile.get("soa_rnames", []) if profile else []
    if rnames:
        rng = random.Random(_stable_seed(f"public_dns_soa_rname:{domain}:{profile.get('name')}"))
        rname = _render_public_dns_answer(str(rng.choice(rnames)), domain)
    else:
        rname = f"dns-admin.{domain}"
    return [_dns_soa_answer(domain, nameservers[0], rname, str(profile.get("name", "")))]


def _dns_txt_query_and_answer(rng: random.Random, hostname: str) -> tuple[str, str, int]:
    """Build a plausible TXT lookup for mail/authentication background noise."""
    return choose_dns_txt_query(hostname, roll=rng.random())


def _dns_address_rrset(hostname: str | None, dst_ip: str, *, is_internal: bool) -> list[str]:
    """Return the canonical resolver-visible address RRset for a connection target."""
    if is_internal or not hostname:
        return [dst_ip]

    from evidenceforge.generation.activity.dns_registry import get_domain_ips

    domain_ips = list(dict.fromkeys(get_domain_ips(hostname)))
    if not domain_ips:
        return [dst_ip]
    if dst_ip not in domain_ips:
        domain_ips.insert(0, dst_ip)
    elif domain_ips[0] != dst_ip:
        domain_ips = [dst_ip, *(ip for ip in domain_ips if ip != dst_ip)]
    if len(domain_ips) <= 4:
        return domain_ips

    ranked = sorted(
        domain_ips,
        key=lambda ip: _stable_seed(f"dns_address_rrset:{hostname.lower()}:{ip}"),
    )
    selected = set(ranked[:4])
    selected.add(dst_ip)
    return [dst_ip, *(ip for ip in domain_ips if ip in selected and ip != dst_ip)]


def _dns_hostname_allows_mx(hostname: str) -> bool:
    """Return whether a hostname is plausible owner context for MX lookups."""
    lowered = hostname.lower().rstrip(".")
    if "." not in lowered:
        return False
    cdn_suffixes = (
        "cloudfront.net",
        "akamaiedge.net",
        "akamaitechnologies.com",
        "fastly.net",
        "global.ssl.fastly.net",
        "cdn.cloudflare.net",
    )
    if lowered.endswith(cdn_suffixes):
        return False
    service_labels = {"cdn", "static", "assets", "media", "img", "js", "css"}
    return lowered.split(".", 1)[0] not in service_labels


def _linux_uid_for_user(username: str) -> int:
    """Return a stable plausible Linux UID for a login username."""
    return default_linux_uid_for_user(username)


def _icmp_echo_payload_size(rng: random.Random, requested: int | None) -> int:
    """Return a varied but source-native ICMP echo payload size."""
    common_sizes = [32, 48, 56, 64, 84, 120, 256, 512, 1024, 1200, 1472]
    weights = [8, 10, 18, 18, 10, 8, 7, 7, 5, 4, 5]
    if requested is not None and 32 <= requested <= 1472 and rng.random() < 0.45:
        jitter = rng.choice([-16, -8, 0, 0, 0, 8, 16])
        return max(32, min(1472, requested + jitter))
    return rng.choices(common_sizes, weights=weights, k=1)[0]


def _icmp_echo_duration(rng: random.Random, requested: float | None) -> float:
    """Return realistic ICMP RTT without leaving clamp-shaped plateaus."""
    if requested is not None and 0.001 <= requested <= 0.15 and rng.random() < 0.65:
        return requested
    if rng.random() < 0.85:
        return rng.uniform(0.001, 0.045)
    return rng.uniform(0.045, 0.145)


def _linux_command_process_from_shell(
    command: str,
    *,
    username: str = "",
) -> tuple[str, str] | None:
    """Infer the first process image and command line for a Linux shell-history command."""
    processes = _linux_command_processes_from_shell(command, max_processes=1, username=username)
    return processes[0] if processes else None


def _linux_catalog_processes_from_shell_command(
    process_name: str,
    command_line: str,
    *,
    username: str = "",
) -> list[tuple[str, str]]:
    """Return source-native Linux process argv entries for a catalog shell command."""
    processes = _linux_command_processes_from_shell(command_line, username=username)
    return processes or [(process_name, command_line)]


def _linux_command_processes_from_shell(
    command: str,
    *,
    max_processes: int | None = _LINUX_SHELL_MAX_INFERRED_PROCESSES,
    max_stages: int = _LINUX_SHELL_MAX_INFER_STAGES,
    username: str = "",
) -> list[tuple[str, str]]:
    """Infer bounded source-native process argv entries from a Linux shell command."""
    if max_processes is not None and max_processes <= 0:
        return []

    processes: list[tuple[str, str]] = []
    for stage in _iter_linux_pipeline_stages(command, max_stages=max_stages):
        if username:
            process = _linux_command_process_from_stage(stage, username=username)
        else:
            process = _linux_command_process_from_stage(stage)
        if process is None:
            continue
        processes.append(process)
        if max_processes is not None and len(processes) >= max_processes:
            break
    return processes


def _split_linux_pipeline(
    command: str, *, max_stages: int = _LINUX_SHELL_MAX_INFER_STAGES
) -> list[str]:
    """Split a shell command on unquoted pipeline/control separators with a stage cap."""
    return list(_iter_linux_pipeline_stages(command, max_stages=max_stages))


def _contains_unquoted_shell_pipe(command: str) -> bool:
    """Return whether a shell command contains an unquoted pipe operator."""
    quote: str | None = None
    escaped = False
    scan_limit = min(len(command), _LINUX_SHELL_MAX_SCAN_CHARS)
    for char in command[:scan_limit]:
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "|":
            return True
    return False


def _iter_linux_pipeline_stages(command: str, *, max_stages: int) -> Iterator[str]:
    """Yield bounded unquoted pipeline/control stages from a Linux shell command."""
    if max_stages <= 0:
        return

    current: list[str] = []
    current_too_long = False
    quote: str | None = None
    escaped = False
    yielded = 0
    index = 0
    scan_limit = min(len(command), _LINUX_SHELL_MAX_SCAN_CHARS)

    def append_current(char: str) -> None:
        nonlocal current_too_long
        if current_too_long:
            return
        if len(current) >= _LINUX_SHELL_MAX_STAGE_CHARS:
            current.clear()
            current_too_long = True
            return
        current.append(char)

    def finish_stage() -> str | None:
        nonlocal current, current_too_long
        if current_too_long:
            current = []
            current_too_long = False
            return None
        stage = "".join(current).strip()
        current = []
        return stage or None

    while index < scan_limit and yielded < max_stages:
        char = command[index]
        if escaped:
            append_current(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            append_current(char)
            escaped = True
            index += 1
            continue
        if quote:
            append_current(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            append_current(char)
            index += 1
            continue
        separator_width = 0
        if char in {"|", ";"}:
            separator_width = 2 if command[index : index + 2] == "||" else 1
        elif command[index : index + 2] == "&&":
            separator_width = 2
        if separator_width:
            stage = finish_stage()
            if stage is not None:
                yielded += 1
                yield stage
            index += separator_width
            continue
        append_current(char)
        index += 1

    if yielded < max_stages:
        stage = finish_stage()
        if stage is not None:
            yield stage


def _linux_command_process_from_stage(
    stage: str,
    *,
    username: str = "",
) -> tuple[str, str] | None:
    """Infer a source-native process image/argv pair from one shell pipeline stage."""
    if not stage:
        return None
    try:
        raw_parts = shlex.split(stage, comments=False, posix=True)
    except ValueError:
        return None
    parts = _strip_linux_shell_redirections(raw_parts)
    parts = _expand_linux_home_argv(parts, username)
    if parts and parts[-1] == "&":
        parts = parts[:-1]
    if not parts:
        return None

    index = 0
    while index < len(parts):
        token = parts[index]
        if "=" in token and not token.startswith(("/", "./", "../")):
            name, _, _value = token.partition("=")
            if name.replace("_", "").isalnum():
                index += 1
                continue
        if token in {"sudo", "time"}:
            index += 1
            continue
        if token == "env":
            index += 1
            while index < len(parts) and "=" in parts[index]:
                index += 1
            continue
        break

    if index >= len(parts):
        return None
    executable = parts[index].rsplit("/", 1)[-1]
    if executable in _BASH_BUILTIN_COMMANDS:
        return None
    alias = _LINUX_ALIAS_COMMANDS.get(executable)
    if alias is not None:
        image, command_line = alias
        if index + 1 < len(parts):
            command_line = f"{command_line} {_shell_display_join(parts[index + 1 :], executable)}"
        return image, command_line
    command_line = _shell_display_join(parts[index:], executable)
    if parts[index].startswith("/"):
        return parts[index], command_line
    mapped = _LINUX_COMMAND_IMAGE_OVERRIDES.get(executable)
    if mapped is not None:
        return mapped, command_line
    return None


def _expand_linux_home_argv(parts: list[str], username: str) -> list[str]:
    """Render generated shell home shortcuts as exec-style absolute argv paths."""
    if not username:
        return parts
    home = "/root" if username == "root" else f"/home/{username}"
    expanded: list[str] = []
    for part in parts:
        if part == "~":
            expanded.append(home)
        elif part.startswith("~/"):
            expanded.append(f"{home}/{part[2:]}")
        else:
            expanded.append(part)
    return expanded


def _shell_display_join(parts: list[str], executable: str | None = None) -> str:
    """Render shell argv for telemetry without quoting expandable glob tokens."""
    rendered: list[str] = []
    sql_query_index = _mysql_sql_query_arg_index(parts, executable)
    for index, part in enumerate(parts):
        if sql_query_index is not None and index == sql_query_index:
            rendered.append(shlex.quote(part))
            continue
        if any(marker in part for marker in ("*", "?", "[")):
            rendered.append(part)
        else:
            rendered.append(shlex.quote(part))
    return " ".join(rendered)


def _mysql_sql_query_arg_index(parts: list[str], executable: str | None) -> int | None:
    """Return the mysql -e SQL argument index, if this argv contains one."""
    if not parts:
        return None
    command = (executable or parts[0].rsplit("/", 1)[-1]).lower()
    if command != "mysql":
        return None
    for index, part in enumerate(parts[:-1]):
        if part == "-e":
            return index + 1
        if part.startswith("-e") and len(part) > 2:
            return index
    return None


def _strip_linux_shell_redirections(parts: list[str]) -> list[str]:
    """Remove shell redirection operators and targets from argv tokens."""
    cleaned: list[str] = []
    skip_next = False
    redirect_ops = {">", ">>", "<", "<<", "<>", ">|", "&>", "&>>"}
    redirect_prefix_re = re.compile(r"^(?:\d?>&\d+|\d?>>?|&>>?|<<?|<>|>\|).+")
    attached_redirect_re = re.compile(r"^(?P<arg>.+?)(?:\d?>>?|>>?|<<?|<>|>\|).+")
    for token in parts:
        if skip_next:
            skip_next = False
            continue
        if token in redirect_ops or re.fullmatch(r"\d?>>?", token):
            skip_next = True
            continue
        if redirect_prefix_re.match(token):
            continue
        attached = attached_redirect_re.match(token)
        if attached:
            arg = attached.group("arg")
            if arg:
                cleaned.append(arg)
            continue
        cleaned.append(token)
    return cleaned


def _dns_base_ttl(query: str, is_internal: bool) -> int:
    """Return a stable authoritative TTL for a DNS query name."""
    domain_seed = random.Random(_stable_seed(f"dns_ttl_{query}"))
    if is_internal:
        return domain_seed.choice([300, 600, 1800, 3600, 7200, 86400])
    return domain_seed.choice([30, 60, 120, 300, 600, 1800, 3600])


def _dns_is_internal_name(query: str, ad_domain: str) -> bool:
    """Return whether a DNS query belongs to the scenario's internal namespace."""
    lowered = query.rstrip(".").lower()
    domain = ad_domain.rstrip(".").lower()
    return lowered.endswith(f".{domain}") or lowered == domain or lowered.endswith(".local")


def _dns_nxdomain_companion_queries(hostname: str | None, ad_domain: str) -> list[str]:
    """Return realistic low-volume resolver miss probes for DNS companion noise."""
    suffix_queries: list[str] = []
    if (
        hostname
        and "." in hostname
        and not hostname.endswith(f".{ad_domain}")
        and not hostname.endswith(".local")
    ):
        suffix_queries.append(f"{hostname}.{ad_domain}")
    return suffix_queries + [
        f"wpad.{ad_domain}",
        "wpad.local",
        "wpad",
        f"isatap.{ad_domain}",
        "isatap",
        f"oldserver.{ad_domain}",
        f"printer01.{ad_domain}",
    ]


def _proxy_request_allows_cache_hit(
    *,
    method: str,
    url: str,
    content_type: str,
    domain_tags: list[str] | tuple[str, ...],
) -> bool:
    """Return whether a proxy request can plausibly be served from cache."""
    if method.upper() not in {"GET", "HEAD"}:
        return False
    url_l = url.lower()
    content_l = content_type.lower()
    if any(tag in {"c2", "malware", "beacon", "command-control"} for tag in domain_tags):
        return False
    if any(marker in url_l for marker in ("/api/", "/checkin", "/beacon", "/task", "/gate")):
        return False
    if content_l in {"application/json", "application/octet-stream"}:
        return False
    return content_l.startswith(("image/", "font/")) or content_l in {
        "application/javascript",
        "text/css",
    }


def _origin_form_uri_from_proxy_url(url: str) -> str:
    """Return the origin-form URI represented by an explicit-proxy request URL."""
    parsed = urlsplit(url)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path
    if not url:
        return "/"
    return url if url.startswith(("/", "*")) else f"/{url}"


def _proxy_http_response_body_len(
    proxy_context: ProxyContext,
    *,
    resp_bytes: int | None,
    http: HttpContext | None = None,
) -> int:
    """Return Zeek HTTP entity-body length for an explicit proxy response."""
    from evidenceforge.generation.activity.http_content import (
        coerce_response_size_for_mime,
        response_size_for_status,
    )

    if proxy_context.status_code in {204, 304} or proxy_context.method == "HEAD":
        return 0
    if proxy_context.status_code in {301, 302}:
        return response_size_for_status(
            proxy_context.status_code,
            proxy_context.host,
            _origin_form_uri_from_proxy_url(proxy_context.url),
        )
    if proxy_context.status_code >= 400:
        return max(0, proxy_context.sc_bytes)
    if http is not None and http.status_code == proxy_context.status_code:
        return max(0, http.response_body_len)
    if resp_bytes is not None:
        return coerce_response_size_for_mime(
            random.Random(
                _stable_seed(
                    "proxy_http_body_size:"
                    f"{proxy_context.host}:{proxy_context.url}:{proxy_context.content_type}:"
                    f"{resp_bytes}"
                )
            ),
            proxy_context.content_type or "text/html",
            resp_bytes,
        )
    return coerce_response_size_for_mime(
        random.Random(
            _stable_seed(
                "proxy_http_body_size:"
                f"{proxy_context.host}:{proxy_context.url}:{proxy_context.content_type}:"
                f"{proxy_context.sc_bytes}"
            )
        ),
        proxy_context.content_type or "text/html",
        max(0, proxy_context.sc_bytes - _PROXY_SC_OVERHEAD[1]),
    )


def _proxy_time_taken_ms(
    duration: float | None,
    rng: random.Random,
    *,
    method: str,
    status_code: int,
    cache_result: str = "",
    minimum_ms: int = 1,
) -> int:
    """Return proxy-side service time without mirroring wire duration exactly."""
    base_ms = max(1, int((duration or 0.0) * 1000))
    method_upper = method.upper()
    cache_upper = cache_result.upper()
    uniform = getattr(rng, "uniform", None)
    lognormvariate = getattr(rng, "lognormvariate", None)

    def _uniform(low: float, high: float) -> float:
        if callable(uniform):
            return float(uniform(low, high))
        return low + ((high - low) * rng.random())

    def _lognormvariate(mu: float, sigma: float) -> float:
        if callable(lognormvariate):
            return float(lognormvariate(mu, sigma))
        return random.Random(
            _stable_seed(f"proxy_time_lognorm:{base_ms}:{mu}:{sigma}")
        ).lognormvariate(mu, sigma)

    if status_code >= 400:
        if method_upper == "CONNECT":
            sampled_ms = rng.randint(20, 1500)
        else:
            sampled_ms = rng.randint(35, 2400)
    elif cache_upper == "HIT":
        sampled_ms = max(8, int(base_ms * _uniform(0.08, 0.42))) + rng.randint(3, 95)
    elif method_upper == "CONNECT":
        overhead_ms = rng.randint(19, 420)
        if base_ms > 10_000:
            overhead_ms += min(950, int(_lognormvariate(4.1, 0.55)))
        sampled_ms = base_ms + overhead_ms + rng.randint(-11, 47)
    else:
        overhead_ms = rng.randint(7, 180)
        if base_ms > 5000:
            overhead_ms += min(500, int(_lognormvariate(3.2, 0.5)))
        sampled_ms = base_ms + overhead_ms + rng.randint(-9, 35)

    sampled_ms = max(minimum_ms, sampled_ms)
    if duration is not None and sampled_ms == base_ms:
        sampled_ms += rng.choice((-7, 11, 17))
    return max(minimum_ms, sampled_ms)


def _proxy_action_for_context(
    *,
    method: str,
    url: str,
    status_code: int,
    cache_result: str,
    dst_port: int | None = None,
    explicit_mode: bool = False,
) -> str:
    """Return a source-native proxy policy/action hint for proxy events."""
    normalized_cache = (cache_result or "").upper()
    if normalized_cache == "DENIED":
        return "deny"
    if normalized_cache == "AUTH_REQUIRED":
        return "auth-required"
    if normalized_cache == "GATEWAY_ERROR":
        return "gateway-error"
    normalized_method = method.upper()
    normalized_url = url.lower()
    if normalized_method == "CONNECT":
        return "tunnel"
    if dst_port == 443 or normalized_url.startswith("https://"):
        return "ssl-inspect"
    return "forward"


def _is_machine_context_proxy_user_agent(user_agent: str) -> bool:
    """Return whether a proxy User-Agent usually authenticates as a device."""
    normalized = user_agent.strip().lower()
    return any(marker in normalized for marker in _PROXY_MACHINE_USER_AGENT_MARKERS)


# Bound the free-form timestamp middle so malformed raw syslog messages cannot trigger
# repeated long scans/backtracking while preserving Apache timestamp variants with
# fractional seconds or timezone tokens.
_APACHE_EMBEDDED_TS_RE = re.compile(r"\[[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} [^\]]{1,40} \d{4}\]")
_APACHE_CLIENT_RE = re.compile(r"\[client (?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)\]")
_APACHE_PID_RE = re.compile(r"\[pid (?P<pid>\d+)\]")


def _tls_san_dns_names(cert_name: str) -> list[str]:
    """Build deterministic but varied DNS SANs without public-suffix wildcards."""
    from evidenceforge.generation.activity.tls_realism import load_tls_realism

    try:
        import ipaddress as _ipa

        _ipa.ip_address(cert_name)
        return []
    except ValueError:
        pass

    normalized = cert_name.rstrip(".").lower()
    labels = [part for part in normalized.split(".") if part]
    if len(labels) < 2:
        return [normalized]

    base_domain = _dns_registrable_domain(normalized)
    is_apex = normalized == base_domain
    default_weights = {
        "apex_exact": 34,
        "apex_www": 26,
        "apex_wildcard": 14,
        "subdomain_exact": 34,
        "subdomain_parent": 18,
        "subdomain_wildcard": 16,
        "subdomain_sibling": 12,
    }
    config_weights = load_tls_realism().get("san", {}).get("profile_weights", {})
    weights_by_name = {**default_weights, **config_weights}
    profile_names = (
        ("apex_exact", "apex_www", "apex_wildcard")
        if is_apex
        else ("subdomain_exact", "subdomain_parent", "subdomain_wildcard", "subdomain_sibling")
    )
    weights = [max(0, int(weights_by_name.get(name, 0))) for name in profile_names]
    if sum(weights) <= 0:
        weights = [1] * len(profile_names)
    rng = random.Random(_stable_seed(f"tls_san_profile:{normalized}"))
    profile = rng.choices(profile_names, weights=weights, k=1)[0]

    names = [normalized]
    if profile == "apex_www":
        names.append(f"www.{base_domain}")
    elif profile == "apex_wildcard":
        names.append(f"*.{base_domain}")
    elif profile == "subdomain_parent":
        names.append(base_domain)
    elif profile == "subdomain_wildcard":
        names.append(f"*.{base_domain}")
    elif profile == "subdomain_sibling":
        sibling = rng.choice(("api", "assets", "cdn", "static", "www"))
        names.append(f"{sibling}.{base_domain}")
    return list(dict.fromkeys(names))


def _is_ip_literal(value: str) -> bool:
    """Return whether a certificate/SNI identity is an IP literal."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _tls_certificate_serial(seed: str) -> str:
    """Return a stable certificate serial with CA-realistic length variation."""
    from evidenceforge.config.schemas import TLS_SERIAL_LENGTH_MAX_WEIGHT
    from evidenceforge.generation.activity.tls_realism import serial_number_config

    configured_lengths = serial_number_config().get("byte_lengths", [])
    weighted_lengths: dict[int, int] = {}
    for entry in configured_lengths:
        if not isinstance(entry, dict):
            continue
        try:
            byte_length = int(entry.get("bytes", 0))
            weight = int(entry.get("weight", 0))
        except (OverflowError, TypeError, ValueError):
            continue
        if 1 <= byte_length <= 20 and 0 < weight <= TLS_SERIAL_LENGTH_MAX_WEIGHT:
            weighted_lengths[byte_length] = min(
                weighted_lengths.get(byte_length, 0) + weight,
                TLS_SERIAL_LENGTH_MAX_WEIGHT,
            )

    if weighted_lengths:
        lengths = list(weighted_lengths)
        weights = list(weighted_lengths.values())
    else:
        lengths = [8, 9, 10, 12, 16, 18, 20]
        weights = [8, 6, 6, 14, 40, 12, 14]

    length_rng = random.Random(_stable_seed(f"tls_serial_length:{seed}"))
    byte_length = length_rng.choices(lengths, weights=weights, k=1)[0]
    value_rng = random.Random(_stable_seed(f"tls_serial_value:{seed}:{byte_length}"))
    value = value_rng.getrandbits(byte_length * 8) or 1
    return f"{value:0{byte_length * 2}X}"


def _raw_ip_tls_issuer(cert_name: str) -> dict[str, Any]:
    """Return a non-public-CA profile for raw-IP TLS certificates."""
    return {
        "name": f"CN={cert_name}",
        "weight": 0,
        "validity_days_min": 30,
        "validity_days_max": 397,
        "not_before_max_days": 180,
        "key_types": [{"type": "rsa", "length": 2048, "weight": 100}],
    }


def _ocsp_status_for_certificate(
    cert_name: str,
    serial_number: str,
    *,
    suppress_revoked: bool = False,
) -> str:
    """Pick a stable mostly-good OCSP status per certificate identity."""
    from evidenceforge.generation.activity.tls_realism import ocsp_config

    config = ocsp_config()
    weights = config.get("status_weights", {"good": 90, "unknown": 7, "revoked": 3})
    cert_name_lower = cert_name.rstrip(".").lower()
    suppress_suffixes = {
        str(suffix).lower()
        for suffix in config.get("suppress_revoked_suffixes", [])
        if str(suffix).strip()
    }
    if suppress_revoked or any(
        cert_name_lower == suffix.lstrip(".") or cert_name_lower.endswith(suffix)
        for suffix in suppress_suffixes
    ):
        weights = {**weights, "revoked": 0}
    ordered = ("good", "unknown", "revoked")
    total = sum(max(0, int(weights.get(status, 0))) for status in ordered)
    if total <= 0:
        return "good"
    bucket = _stable_seed(f"ocsp_status:{cert_name}:{serial_number}") % total
    cumulative = 0
    for status in ordered:
        cumulative += max(0, int(weights.get(status, 0)))
        if bucket < cumulative:
            return status
    return "good"


def _ntp_stratum_and_ref_id(dst_ip: str) -> tuple[int, str]:
    """Return stable NTP server metadata for a destination."""
    from evidenceforge.generation.activity.network_params import public_ntp_servers

    for server in public_ntp_servers():
        if server.get("ip") == dst_ip:
            stratum = int(server.get("stratum", 2))
            ref_id = str(server.get("ref_id", ".GPS."))
            return stratum, ref_id

    rng = random.Random(_stable_seed(f"ntp_server_profile:{dst_ip}"))
    if _is_private_ip(dst_ip):
        return rng.choice([2, 2, 3, 3, 4]), rng.choice(
            [
                server.get("ip")
                for server in public_ntp_servers()
                if isinstance(server.get("ip"), str) and server.get("ip") != dst_ip
            ]
            or ["129.6.15.28", "132.163.97.1", "132.163.96.1", "192.5.41.40"]
        )
    return rng.choice([1, 1, 2]), rng.choice([".GPS.", ".PPS.", ".GOES.", ".ACTS."])


_NTP_ASSOCIATION_POLL_CYCLE = (1024, 2048, 2048, 4096, 4096)


def _ntp_poll_component(ip: str) -> int:
    """Return a stable integer component for poll selection."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return _stable_seed(ip)


def _ntp_association_poll_seconds(src_ip: str, dst_ip: str) -> int:
    """Return the stable poll interval for an NTP client/server association."""
    bucket = (
        _ntp_poll_component(src_ip)
        + _stable_seed(f"ntp_poll_server:{dst_ip}") % len(_NTP_ASSOCIATION_POLL_CYCLE)
    ) % len(_NTP_ASSOCIATION_POLL_CYCLE)
    return _NTP_ASSOCIATION_POLL_CYCLE[bucket]


def _ntp_precision_interval_seconds(precision_exponent: int) -> float:
    """Convert the NTP wire precision exponent into Zeek's interval field."""
    return float(2**precision_exponent)


def _ntp_parser_min_gap_seconds(poll_seconds: float) -> float:
    """Return the minimum plausible gap between successful parser observations."""
    return max(300.0, poll_seconds * 0.40)


def _ntp_payload_accounting(
    *,
    src_ip: str,
    dst_ip: str,
    time: datetime,
    conn_state: str | None,
    history: str | None,
    orig_bytes: int | None,
    resp_bytes: int | None,
    duration: float | None,
) -> tuple[int | None, int | None, float | None]:
    """Return source-native NTP UDP payload sizes for conn.log accounting."""
    rng = random.Random(
        _stable_seed(
            "ntp_payload_accounting:"
            f"{src_ip}:{dst_ip}:{time.isoformat()}:{conn_state or ''}:{history or ''}"
        )
    )
    request_datagrams = max(1, (history or "").count("D"))
    response_datagrams = (history or "").count("d") if (resp_bytes or 0) > 0 else 0

    def sample_payload_size() -> int:
        return int(
            rng.choices(
                (48, 48, 56, 64, 68, 76, 88, 96, 112, 120),
                weights=(34, 20, 14, 9, 7, 5, 4, 3, 2, 2),
                k=1,
            )[0]
        )

    normalized_orig = sum(sample_payload_size() for _ in range(request_datagrams))
    normalized_resp = (
        sum(sample_payload_size() for _ in range(response_datagrams))
        if conn_state not in {"S0", "REJ"} and response_datagrams > 0
        else 0
    )
    normalized_duration = duration
    if normalized_resp > 0 and (normalized_duration is None or normalized_duration > 0.25):
        normalized_duration = rng.uniform(0.003, 0.12)
    return normalized_orig, normalized_resp, normalized_duration


def _ntp_observed_response_fields(
    server_response: dict[str, float],
    *,
    dst_ip: str,
    event_time: datetime,
) -> dict[str, float]:
    """Return NTP response fields with stable server traits and per-poll texture."""
    root_delay = float(server_response["root_delay"])
    root_disp = float(server_response["root_disp"])
    rng = random.Random(_stable_seed(f"ntp_observed_response:{dst_ip}:{event_time.isoformat()}"))
    observed_delay = root_delay * rng.uniform(0.91, 1.12) + rng.uniform(-0.00025, 0.00035)
    observed_disp = root_disp * rng.uniform(0.88, 1.16) + rng.uniform(-0.00015, 0.0004)
    if rng.random() < 0.18:
        observed_disp += rng.uniform(0.00035, 0.0018)
    return {
        "precision": float(server_response["precision"]),
        "root_delay": round(max(0.00025, observed_delay), 6),
        "root_disp": round(max(0.00025, observed_disp), 6),
    }


def _select_public_ntp_ip(src_ip: str, dst_ip: str, time: datetime) -> str | None:
    """Return a configured public NTP server IP for inferred public NTP traffic."""
    from evidenceforge.generation.activity.network_params import public_ntp_servers

    servers = [
        server
        for server in public_ntp_servers()
        if isinstance(server.get("ip"), str) and server["ip"]
    ]
    if not servers:
        return None
    rng = random.Random(
        _stable_seed(
            "public_ntp_destination:"
            f"{src_ip}:{dst_ip}:{time.replace(minute=0, second=0, microsecond=0).isoformat()}"
        )
    )
    weights = [
        max(0.1, float(server.get("weight", 1.0)))
        if isinstance(server.get("weight", 1.0), int | float)
        else 1.0
        for server in servers
    ]
    return str(rng.choices([server["ip"] for server in servers], weights=weights, k=1)[0])


def _file_transfer_hashes(seed_material: str, analyzers: list[str]) -> dict[str, str]:
    """Return deterministic Zeek files.log hashes for requested analyzers."""

    return file_transfer_hashes(seed_material, analyzers)


def _enterprise_org_from_domain(ad_domain: str) -> str:
    """Derive a readable organization stem from the scenario AD domain."""
    generic_labels = {"corp", "local", "internal", "test", "com", "net", "org", "lan"}
    for label in ad_domain.split("."):
        cleaned = label.strip().replace("-", " ").replace("_", " ")
        if cleaned and cleaned.lower() not in generic_labels:
            return cleaned.title()
    return "Enterprise"


def _enterprise_tls_issuer(ad_domain: str = "") -> dict[str, Any]:
    """Return the configured enterprise issuer for internal TLS certificates."""
    from evidenceforge.generation.activity.tls_issuers import load_tls_issuers

    org_name = _enterprise_org_from_domain(ad_domain)
    issuer_name = f"CN={org_name} Enterprise Issuing CA, O={org_name}, C=US"
    fallback_name = "CN=Acme Enterprise Issuing CA, O=Acme Corp, C=US"
    for issuer in load_tls_issuers().get("issuers", []):
        if issuer.get("name") == issuer_name:
            return issuer
        if issuer.get("name") == fallback_name:
            return {**issuer, "name": issuer_name}
    return {
        "name": issuer_name,
        "weight": 0,
        "validity_days_min": 180,
        "validity_days_max": 825,
        "not_before_max_days": 730,
        "key_types": [{"type": "rsa", "length": 2048, "weight": 100}],
    }


def _tls_key_for_certificate_name(
    cert_name: str,
    key_type: str,
    key_length: int,
) -> tuple[str, int]:
    """Align generated certificate key metadata with RSA/ECC naming conventions."""
    name = cert_name.lower()
    if "rsa" in name:
        return "rsa", max(key_length if key_type == "rsa" else 0, 2048)
    if any(marker in name for marker in ("ecdsa", "ecc", " ec ", "-ec")):
        return "ecdsa", 256 if key_type != "ecdsa" else key_length
    return key_type, key_length


def _tls_signature_algorithm_for_issuer(
    issuer_name: str,
    *,
    fallback_key_type: str = "rsa",
    fallback_key_length: int = 2048,
) -> str:
    """Return the certificate signature algorithm implied by the issuer key."""
    from evidenceforge.generation.activity.tls_realism import signature_algorithm_for_issuer

    return signature_algorithm_for_issuer(
        issuer_name,
        fallback_type=fallback_key_type,
        fallback_length=fallback_key_length,
    )


@dataclass(frozen=True, slots=True)
class EmailCorpusEntry:
    """Scenario-authored deterministic email content."""

    entry_id: str
    subject: str
    body: str
    user_agent: str = ""
    headers: dict[str, str] | None = None
    attachments: tuple[dict[str, Any], ...] = ()
    tags: tuple[str, ...] = ()
    background: bool = False
    storyline: bool = True


class ActivityGenerator:
    """Generates specific activity events using StateManager and emitters.

    Coordinates event generation across multiple log formats to maintain
    cross-log consistency (LogonIDs, PIDs, timestamps, etc.).

    Attributes:
        state_manager: StateManager instance for state tracking
        emitters: Dict mapping format name to emitter instance
        event_record_counter: Counter for Windows EventRecordID generation
    """

    def __init__(
        self,
        state_manager: StateManager,
        emitters: dict[str, WindowsEventEmitter | ZeekEmitter],
        event_record_counter: int = 10000,
        network_visibility=None,
        sid_registry: dict[str, str] | None = None,
        identity_directory: IdentityDirectory | None = None,
        source_timing_profile: str = "complete",
        dispatcher: EventDispatcher | None = None,
        causal_engine: CausalExpansionEngine | None = None,
    ):
        """Initialize activity generator.

        Args:
            state_manager: StateManager instance
            emitters: Dict of emitters by format name
            event_record_counter: Starting EventRecordID
            network_visibility: Optional NetworkVisibilityEngine for sensor-based filtering
            sid_registry: Optional dict mapping usernames to Windows SIDs
            identity_directory: Optional logical/platform account directory
            source_timing_profile: Named endpoint clock/source timing profile
            dispatcher: Optional EventDispatcher for canonical event model (Phase 7)
            causal_engine: Optional CausalExpansionEngine for auto-generating
                prerequisite events (DNS before connections, Kerberos before
                logons, etc.)
        """
        self.state_manager = state_manager
        if dispatcher is None and emitters:
            # Auto-create dispatcher for backward compat with tests
            dispatcher = EventDispatcher(
                state_manager=state_manager,
                emitters=emitters,
            )
        self.dispatcher = dispatcher
        self._event_record_counters: dict[str, int] = {}
        self._counter_lock = Lock()  # Thread-safe counter for EventRecordID
        self.sid_registry = sid_registry or {}
        self.identity_directory = identity_directory

        # IP→System lookup for HostContext resolution on connection events
        self._ip_to_system: dict[str, Any] = {}

        # Process tree tracking: recent user processes per (hostname, username)
        # Used by _select_parent_pid() for realistic parent-child relationships
        self._user_process_history: dict[tuple[str, str], list[tuple[int, str]]] = {}

        # Network visibility stored on dispatcher; keep local ref for fast-path check
        self._network_visibility = network_visibility
        self._proxy_mode = "transparent"
        self._proxy_listener_port = 8080
        self._proxy_auth_policy = ProxyAuthPolicyConfig()
        self._proxy_service_accounts: list[str] = []
        self._explicit_proxy_tunnels: dict[
            tuple[str, str, str, str, int, str], tuple[datetime, str]
        ] = {}
        self._http_persistent_connections: dict[
            tuple[str, str, int, str, str], _HttpPersistentConnection
        ] = {}
        self._recent_connection_tuples: dict[tuple[str, int, str, int, str], float] = {}
        self._recent_connection_tuple_heap: list[tuple[float, tuple[str, int, str, int, str]]] = []
        self._kerberos_source_port_reservations: dict[tuple[str, str], list[tuple[float, int]]] = {}
        self._kerberos_audit_tuple_times: dict[tuple[str, str, int], list[float]] = {}
        self._kerberos_tgt_cache_until: dict[tuple[str, str, str], datetime] = {}
        self._next_icmp_observation_ts_us: dict[tuple[str, int, str, int], int] = {}
        self._ssh_source_ports: set[tuple[str, str, int]] = set()
        self._terminated_process_keys: set[tuple[str, int, datetime | None]] = set()
        self._dns_cache: dict[tuple[str, str, str, str], float] = {}
        self._dns_resolver_rrset_cache: dict[
            tuple[str, str, str, tuple[str, ...]], tuple[float, float]
        ] = {}
        self._dns_cache_last_prune = 0.0
        self._tls_seen_server_names: set[str] = set()
        self._tls_seen_client_server_pairs: set[tuple[str, str, int, str]] = set()
        self._tls_cert_validity: dict[str, tuple[int, int]] = {}
        self._tls_intermediate_profiles: dict[tuple[str, str], dict[str, Any]] = {}
        self._tls_ocsp_windows: dict[tuple[str, str, int], tuple[int, int]] = {}
        self._tls_ocsp_response_sizes: dict[tuple[str, str, str, float, float, str], int] = {}
        self._ntp_association_profiles: dict[tuple[str, str], dict[str, float | int]] = {}
        self._ntp_server_response_profiles: dict[str, dict[str, float]] = {}
        self._ntp_last_parser_times: dict[tuple[str, str], datetime] = {}
        self._bash_history_next_time: dict[tuple[str, str], datetime] = {}
        self._bash_history_command_counts: dict[tuple[str, str], int] = {}
        self._bash_history_quick_streaks: dict[tuple[str, str], int] = {}
        self._bash_history_user_seconds: dict[tuple[str, int], int] = {}
        self._linux_shell_last_session_close: dict[tuple[str, str], datetime] = {}
        self._linux_local_logon_syslog_sessions: set[str] = set()
        self._linux_local_logind_session_ids: dict[str, int] = {}
        self._ssh_session_ready_times: dict[str, datetime] = {}
        self._foreground_shell_next_time: dict[tuple[str, str, str, int], datetime] = {}
        self._foreground_process_finalizers: dict[
            tuple[str, int], tuple[System, str, str, str, datetime]
        ] = {}
        self._loaded_modules_by_process: set[tuple[str, int, str, str]] = set()
        self._last_one_shot_cli_launch_by_exe: dict[tuple[str, str, str, str], datetime] = {}
        self._last_one_shot_cli_launch_by_command: dict[
            tuple[str, str, str, str, str], datetime
        ] = {}
        self._preferred_browser_by_session: dict[tuple[str, str, str], str] = {}
        self._last_browser_launch_by_session: dict[tuple[str, str, str], datetime] = {}
        self._process_source_create_times: dict[tuple[str, int], datetime] = {}
        self._process_source_terminate_times: dict[tuple[str, int], datetime] = {}
        self._source_timing_planner = SourceTimingPlanner(clock_profile_name=source_timing_profile)

        # Causal expansion engine (auto-created if not provided) and recursion guard
        self._causal_engine = causal_engine or CausalExpansionEngine()
        self._expanding_types: set[str] = set()
        self._last_connection_effective_dst_ip = ""
        self._last_connection_effective_tuple: tuple[str, int, str, int, str] | None = None
        self._last_connection_effective_time: datetime | None = None

    def _process_termination_recorded(
        self,
        hostname: str,
        pid: int,
        start_time: datetime | None,
    ) -> bool:
        """Return whether a process instance termination was already generated."""
        if start_time is None:
            return any(
                terminated_host == hostname and terminated_pid == pid
                for terminated_host, terminated_pid, _ in self._terminated_process_keys
            )
        return (hostname, pid, start_time) in self._terminated_process_keys

    def _remember_foreground_process_finalizer(
        self,
        *,
        system: System,
        user: User,
        pid: int,
        process_name: str,
        logon_id: str,
        termination_time: datetime,
    ) -> None:
        """Track a bounded foreground process until its terminate event is observed."""
        self._foreground_process_finalizers[(system.hostname, pid)] = (
            system,
            user.username,
            process_name,
            logon_id,
            ensure_utc(termination_time),
        )

    def finalize_foreground_process_lifetimes(self, end_time: datetime) -> None:
        """Close any tracked one-shot foreground shell processes still running.

        Most shell telemetry emits its terminate row immediately after the create row. This
        finalization pass is a safety net for slice-end and session-interleaving edge cases
        where a bounded foreground command stayed active in state despite its expected
        lifetime being inside the visible window.
        """
        known_users = getattr(self, "_users_by_username", {})
        window_end = ensure_utc(end_time)
        for key, (
            system,
            username,
            process_name,
            logon_id,
            termination_time,
        ) in sorted(self._foreground_process_finalizers.items(), key=lambda item: item[1][4]):
            if termination_time > window_end:
                continue
            running = self.state_manager.get_process(system.hostname, key[1])
            if running is None:
                continue
            if self._process_termination_recorded(system.hostname, key[1], running.start_time):
                continue
            process_user = known_users.get(username) or User(
                username=username,
                full_name=username,
                email=f"{username}@example.local",
            )
            self.generate_process_termination(
                user=process_user,
                system=system,
                time=termination_time,
                pid=key[1],
                process_name=running.image or process_name,
                logon_id=running.logon_id or logon_id,
            )

    def _generate_bounded_foreground_process_termination(
        self,
        *,
        user: User,
        system: System,
        start_time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
        lifetime: tuple[float, float],
        rng: random.Random,
    ) -> datetime:
        """Emit and track termination for a bounded foreground command process."""
        termination_time = start_time + timedelta(seconds=rng.uniform(*lifetime))
        self._remember_foreground_process_finalizer(
            system=system,
            user=user,
            pid=pid,
            process_name=process_name,
            logon_id=logon_id,
            termination_time=termination_time,
        )
        if self._is_within_scenario_window(termination_time):
            self.generate_process_termination(
                user=user,
                system=system,
                time=termination_time,
                pid=pid,
                process_name=process_name,
                logon_id=logon_id,
            )
        return termination_time

    def _is_within_scenario_window(self, event_time: datetime) -> bool:
        """Return whether source-visible generated telemetry belongs inside the scenario."""
        scenario_end = getattr(self, "_scenario_end_time", None)
        if scenario_end is None:
            return True
        return ensure_utc(event_time) < ensure_utc(scenario_end)

    def _foreground_shell_key(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
    ) -> tuple[str, str, str, int] | None:
        """Return the interactive shell key that serializes foreground Linux children."""
        proc = self.state_manager.get_process(system.hostname, parent_pid)
        if proc is None:
            return None
        image = (proc.image or "").rsplit("/", 1)[-1].lower()
        if image not in {"bash", "sh", "zsh"}:
            return None
        return (system.hostname, username, logon_id, parent_pid)

    def _reserve_foreground_shell_time(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        requested_time: datetime,
        seed_text: str,
    ) -> datetime:
        """Delay a new foreground command until the same interactive shell is free."""
        key = self._foreground_shell_key(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
        )
        if key is None:
            return requested_time
        shell_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if shell_proc is not None:
            shell_start = ensure_utc(shell_proc.start_time)
            readiness_seed = _stable_seed(
                "foreground_shell_initial_ready:"
                f"{system.hostname}:{username}:{logon_id}:{parent_pid}:"
                f"{shell_start.isoformat()}"
            )
            requested_time = max(
                requested_time,
                shell_start + timedelta(milliseconds=1800 + (readiness_seed % 5200)),
            )
        next_time = self._foreground_shell_next_time.get(key)
        if next_time is None or requested_time >= next_time:
            return requested_time
        rng = random.Random(
            _stable_seed(
                f"foreground_shell_gap:{system.hostname}:{username}:{logon_id}:"
                f"{parent_pid}:{seed_text}:{next_time.timestamp()}"
            )
        )
        return next_time + timedelta(milliseconds=rng.randint(120, 900))

    def _remember_foreground_shell_available(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        termination_time: datetime,
        seed_text: str,
    ) -> None:
        """Remember when an interactive Linux shell can plausibly accept more input."""
        rng = random.Random(
            _stable_seed(
                f"foreground_shell_release:{system.hostname}:{username}:{logon_id}:"
                f"{parent_pid}:{seed_text}:{termination_time.timestamp()}"
            )
        )
        release_time = termination_time + timedelta(milliseconds=rng.randint(180, 1400))
        bash_key = (system.hostname, username)
        self._bash_history_next_time[bash_key] = max(
            self._bash_history_next_time.get(bash_key, release_time),
            release_time,
        )
        key = self._foreground_shell_key(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
        )
        if key is None:
            return
        self._foreground_shell_next_time[key] = max(
            release_time,
            self._foreground_shell_next_time.get(key, release_time),
        )

    def reserve_linux_foreground_process_start(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        requested_time: datetime,
        process_name: str,
        command_line: str,
    ) -> datetime:
        """Return a shell-serialized start time for a Linux foreground process."""
        if _get_os_category(system.os) != "linux":
            return requested_time
        if _linux_foreground_lifetime(process_name, command_line) is None:
            return requested_time
        reserved_time = max(
            requested_time,
            self._bash_history_next_time.get((system.hostname, username), requested_time),
        )
        return self._reserve_foreground_shell_time(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            requested_time=reserved_time,
            seed_text=command_line,
        )

    def remember_linux_foreground_process_completion(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        termination_time: datetime,
        process_name: str,
        command_line: str,
    ) -> None:
        """Update shared shell availability after a Linux foreground process finishes."""
        if _get_os_category(system.os) != "linux":
            return
        if _linux_foreground_lifetime(process_name, command_line) is None:
            return
        self._remember_foreground_shell_available(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            termination_time=termination_time,
            seed_text=command_line,
        )

    def _ntp_association_profile(self, src_ip: str, dst_ip: str) -> dict[str, float | int]:
        """Return stable NTP client/server association fields."""
        key = (src_ip, dst_ip)
        profile = self._ntp_association_profiles.get(key)
        if profile is not None:
            return profile

        profile_rng = random.Random(_stable_seed(f"ntp_association:{src_ip}:{dst_ip}"))
        version = 3 if profile_rng.random() < 0.08 else 4
        poll = float(_ntp_association_poll_seconds(src_ip, dst_ip))
        profile = {
            "version": version,
            "poll": poll,
        }
        self._ntp_association_profiles[key] = profile
        return profile

    def _ntp_server_response_profile(self, dst_ip: str) -> dict[str, float]:
        """Return NTP response fields owned by the server, not by clients."""
        profile = self._ntp_server_response_profiles.get(dst_ip)
        if profile is not None:
            return profile

        profile_rng = random.Random(_stable_seed(f"ntp_server_response:{dst_ip}"))
        if _is_private_ip(dst_ip):
            root_delay = profile_rng.uniform(0.006, 0.055)
            root_disp = profile_rng.uniform(0.004, 0.028)
        else:
            root_delay = profile_rng.uniform(0.001, 0.08)
            root_disp = profile_rng.uniform(0.001, 0.04)
        precision_exponent = profile_rng.randint(-24, -19)
        profile = {
            "precision": _ntp_precision_interval_seconds(precision_exponent),
            "root_delay": root_delay,
            "root_disp": root_disp,
        }
        self._ntp_server_response_profiles[dst_ip] = profile
        return profile

    def _build_host_context(self, system: System) -> HostContext:
        """Build a HostContext from a System model object.

        Precomputes FQDN and NetBIOS domain so render methods don't have to.
        """
        ad_domain = getattr(self, "_ad_domain", "")
        hostname = system.hostname
        return HostContext(
            hostname=hostname,
            ip=system.ip,
            os=system.os,
            os_category=_get_os_category(system.os),
            system_type=system.type,
            domain=ad_domain,
            # Guard against an already-FQDN hostname so we never double the domain
            # (e.g. "cdn.example.com" -> "cdn.example.com.example.com"), mirroring
            # the guard in _system_for_hostname.
            fqdn=(hostname if "." in hostname else f"{hostname}.{ad_domain}")
            if ad_domain
            else hostname,
            netbios_domain=ad_domain.split(".")[0].upper() if ad_domain else "CORP",
            roles=list(system.roles),
        )

    def _system_for_hostname(self, hostname: str) -> Any | None:
        """Resolve a scenario system by short hostname or FQDN."""
        wanted = hostname.lower().rstrip(".")
        if not wanted:
            return None
        systems = []
        seen_hosts: set[str] = set()
        for system in getattr(self, "_ip_to_system", {}).values():
            system_host_key = str(getattr(system, "hostname", "") or "")
            if system_host_key in seen_hosts:
                continue
            seen_hosts.add(system_host_key)
            systems.append(system)
        for system in systems:
            system_host = str(getattr(system, "hostname", "") or "").lower().rstrip(".")
            ad_domain = str(getattr(self, "_ad_domain", "") or "").lower().rstrip(".")
            system_fqdn = (
                f"{system_host}.{ad_domain}"
                if system_host and ad_domain and "." not in system_host
                else system_host
            )
            if wanted in {system_host, system_fqdn}:
                return system
        return None

    def _dns_canonical_internal_hostname(self, hostname: str | None) -> str | None:
        """Return the scenario FQDN for known internal hostnames."""
        if not hostname:
            return hostname
        system = self._system_for_hostname(hostname)
        if system is None:
            return hostname
        ad_domain = str(getattr(self, "_ad_domain", "") or "").strip().rstrip(".")
        system_host = str(getattr(system, "hostname", "") or "").strip().rstrip(".")
        if not system_host or not ad_domain:
            return system_host or hostname
        if "." in system_host:
            return system_host
        return f"{system_host}.{ad_domain}"

    def _unique_environment_systems(self) -> list[Any]:
        """Return scenario systems once, preserving environment order where possible."""
        systems: list[Any] = []
        seen_hosts: set[str] = set()
        for system in getattr(self, "_ip_to_system", {}).values():
            hostname = str(getattr(system, "hostname", "") or "")
            if hostname in seen_hosts:
                continue
            seen_hosts.add(hostname)
            systems.append(system)
        return systems

    def _system_for_command_alias(self, hostname: str, service: str) -> Any | None:
        """Resolve common generic command aliases to environment systems."""
        wanted = hostname.lower().rstrip(".")
        if not wanted:
            return None
        systems = self._unique_environment_systems()
        if not systems:
            return None

        def system_matches(system: Any, markers: tuple[str, ...]) -> bool:
            haystack = " ".join(
                [
                    str(getattr(system, "hostname", "") or ""),
                    str(getattr(system, "type", "") or ""),
                    " ".join(getattr(system, "roles", []) or []),
                    " ".join(getattr(system, "services", []) or []),
                ]
            ).lower()
            return any(marker in haystack for marker in markers)

        if service == "ssh":
            if wanted.startswith("web") or "web" in wanted:
                markers = ("web", "apache", "nginx", "http")
            elif wanted.startswith("db") or "db" in wanted:
                markers = ("db", "database", "mysql", "postgres", "mssql")
            elif wanted.startswith("app") or "app" in wanted:
                markers = ("app", "api")
            elif "bastion" in wanted or "jump" in wanted:
                markers = ("bastion", "proxy", "jump")
            else:
                markers = ()
            if markers:
                candidates = [
                    system
                    for system in systems
                    if _get_os_category(getattr(system, "os", "")) == "linux"
                    and system_matches(system, markers)
                ]
                if candidates:
                    return candidates[0]
        return None

    def _resolve_command_network_target(
        self,
        target: str,
        service: str,
    ) -> tuple[str, str | None] | None:
        """Resolve a command-line network target to a destination IP and hostname hint."""
        normalized = _normalize_command_host_token(target)
        if not normalized:
            return None
        if _is_ip_literal(normalized):
            return normalized, None
        target_system = self._system_for_hostname(normalized) or self._system_for_command_alias(
            normalized, service
        )
        if target_system is None:
            return None
        return target_system.ip, normalized

    def _process_network_target_supports_service(
        self,
        target_system: Any | None,
        service: str,
        dst_port: int,
    ) -> bool:
        """Return whether a process-network side effect can succeed on a target."""
        if target_system is None:
            return False

        services = {
            str(value).lower().replace(" ", "-").replace("_", "-")
            for value in (getattr(target_system, "services", []) or [])
        }
        roles = {
            str(value).lower().replace(" ", "-").replace("_", "-")
            for value in (getattr(target_system, "roles", []) or [])
        }
        os_category = _get_os_category(str(getattr(target_system, "os", "") or ""))
        system_type = str(getattr(target_system, "type", "") or "").lower()

        if service == "smb" or dst_port == 445:
            if services & {"smb", "samba", "smbd", "lanmanserver", "ad-ds"}:
                return True
            return os_category == "windows"
        if service == "rdp" or dst_port == 3389:
            if services & {"rdp", "termservice", "terminal-services", "xrdp"}:
                return True
            return os_category == "windows" and system_type in {"server", "domain_controller"}
        if service == "ssh" or dst_port == 22:
            return os_category == "linux" or bool(services & {"ssh", "sshd", "openssh"})
        if service in {"http", "ssl"} or dst_port in {80, 443, 8080, 8443}:
            if services & {
                "http",
                "https",
                "apache",
                "apache2",
                "nginx",
                "httpd",
                "iis",
                "gunicorn",
                "tomcat",
                "squid",
            }:
                return True
            return bool(roles & {"web-server", "app-server", "forward-proxy"})
        return True

    def _process_network_target_ips(
        self,
        source_system: System,
        service: str,
        dst_port: int,
    ) -> list[str]:
        """Return internal target IPs compatible with a process-network service."""
        ips: list[str] = []
        for target in self._unique_environment_systems():
            target_ip = str(getattr(target, "ip", "") or "")
            if not target_ip or target_ip == source_system.ip:
                continue
            if self._process_network_target_supports_service(target, service, dst_port):
                ips.append(target_ip)
        return ips

    def _fallback_database_network_target(
        self,
        target: str,
        source_system: System,
    ) -> tuple[str, str | None, bool] | None:
        """Map an unresolved nonlocal DB target to a plausible failed TCP attempt."""
        normalized = _normalize_database_command_target(target)
        if not normalized or _is_local_database_instance_target(normalized):
            return None
        if _is_ip_literal(normalized):
            return normalized, None, False

        systems_by_ip = getattr(self, "_ip_to_system", {})
        anchor_ip = ""
        for db_entry in getattr(self, "_db_servers", []) or []:
            if isinstance(db_entry, dict):
                anchor_ip = str(db_entry.get("ip") or "")
            else:
                anchor_ip = str(db_entry)
            if anchor_ip:
                break
        if not anchor_ip:
            server_systems = [
                system
                for system in self._unique_environment_systems()
                if getattr(system, "ip", "") != source_system.ip
                and (
                    getattr(system, "type", "") in {"server", "domain_controller"}
                    or getattr(system, "roles", [])
                )
            ]
            if server_systems:
                anchor_ip = str(server_systems[0].ip)
        if not anchor_ip:
            anchor_ip = source_system.ip

        try:
            network = ipaddress.ip_network(f"{anchor_ip}/24", strict=False)
            host_offset = 20 + (_stable_seed(f"db_unresolved:{normalized}") % 210)
            candidate_ip = str(network.network_address + host_offset)
            if candidate_ip == source_system.ip or candidate_ip in systems_by_ip:
                candidate_ip = str(network.network_address + ((host_offset + 37) % 210 + 20))
        except ValueError:
            candidate_ip = f"10.10.2.{50 + (_stable_seed(f'db_unresolved:{normalized}') % 150)}"

        ad_domain = str(getattr(self, "_ad_domain", "") or "").strip(".")
        hostname = normalized if "." in normalized or not ad_domain else f"{normalized}.{ad_domain}"
        return candidate_ip, hostname, True

    def _pick_database_target_placeholder(
        self,
        rng: random.Random,
        command_line: str,
        source_system: System,
    ) -> str | None:
        """Choose a scenario-aware value for database command target placeholders."""
        command_lower = command_line.lower()
        service = "mssql"
        if "mysql" in command_lower:
            service = "mysql"
        elif "psql" in command_lower or "postgres" in command_lower:
            service = "postgresql"

        compatible: list[str] = []
        for db_entry in getattr(self, "_db_servers", []) or []:
            if isinstance(db_entry, dict):
                entry_service = str(db_entry.get("service") or "")
                if entry_service and entry_service != service:
                    continue
                ip = str(db_entry.get("ip") or "")
            else:
                ip = str(db_entry)
            if ip and ip != source_system.ip:
                compatible.append(ip)
        if not compatible:
            return None

        target_ip = rng.choice(compatible)
        target_system = getattr(self, "_ip_to_system", {}).get(target_ip)
        if target_system is None:
            return target_ip

        ad_domain = str(getattr(self, "_ad_domain", "") or "").strip(".")
        style = rng.random()
        if style < 0.20:
            return target_ip
        if style < 0.45 and ad_domain:
            return f"{target_system.hostname}.{ad_domain}"
        return str(target_system.hostname)

    def _pick_command_target_placeholder(
        self,
        rng: random.Random,
        command_line: str,
        source_system: System,
    ) -> str | None:
        """Choose an environment-valid replacement for command `{ssh_target}` placeholders."""
        systems = [
            system for system in self._unique_environment_systems() if system.ip != source_system.ip
        ]
        if not systems:
            return None
        command_lower = command_line.lower()
        if "ldap://" in command_lower:
            candidates = [
                system
                for system in systems
                if getattr(system, "type", "") == "domain_controller"
                or "domain_controller" in (getattr(system, "roles", []) or [])
            ]
        elif "mstsc" in command_lower:
            candidates = [
                system
                for system in systems
                if _get_os_category(getattr(system, "os", "")) == "windows"
                and getattr(system, "type", "") in {"server", "domain_controller"}
            ]
        else:
            candidates = [
                system
                for system in systems
                if _get_os_category(getattr(system, "os", "")) == "linux"
            ]
        if not candidates:
            candidates = systems
        target = rng.choice(candidates)
        ad_domain = str(getattr(self, "_ad_domain", "") or "").strip(".")
        style = rng.random()
        if style < 0.18:
            return target.ip
        if style < 0.32 and ad_domain:
            return f"{target.hostname}.{ad_domain}"
        return str(target.hostname)

    def _parameterize_command_for_system(
        self,
        rng: random.Random,
        command_line: str,
        *,
        username: str,
        system: System,
    ) -> str:
        """Parameterize command templates with environment-aware network targets."""
        if "{ssh_target}" in command_line:
            target = self._pick_command_target_placeholder(rng, command_line, system)
            if target:
                command_line = command_line.replace("{ssh_target}", target)
        if "{internal_url}" in command_line:
            internal_url_count = command_line.count("{internal_url}")
            for _ in range(internal_url_count):
                command_line = command_line.replace(
                    "{internal_url}",
                    self._pick_internal_url_placeholder(rng),
                    1,
                )
        if "{ldap_base_dn}" in command_line:
            command_line = command_line.replace(
                "{ldap_base_dn}",
                _ldap_base_dn(str(getattr(self, "_ad_domain", "") or "corp.local")),
            )
        if "{db_server}" in command_line:
            target = self._pick_database_target_placeholder(rng, command_line, system)
            if target:
                command_line = command_line.replace("{db_server}", target)
        return _parameterize_command(rng, command_line, username=username)

    def _pick_internal_url_placeholder(self, rng: random.Random) -> str:
        """Return an internal URL in the current scenario namespace."""
        domain = str(getattr(self, "_ad_domain", "") or "corp.local").strip(".").lower()
        if not domain or "{" in domain or "}" in domain:
            domain = "corp.local"
        options = [
            f"https://jira.{domain}/browse/PROJ-{rng.randint(1000, 9999)}",
            f"https://wiki.{domain}/display/ENG/Architecture",
            f"https://gitlab.{domain}/team/project/-/pipelines/{rng.randint(100, 9999)}",
            f"https://grafana.{domain}/d/system-overview",
        ]
        return rng.choice(options)

    def _active_interactive_windows_session(
        self,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest user-owned interactive Windows session on a host."""
        if _get_os_category(system.os) != "windows":
            return None

        candidates = [
            session
            for session in self.state_manager.list_active_sessions()
            if (
                session.system == system.hostname
                and session.username not in _SYSTEM_ACCOUNTS
                and not session.username.endswith("$")
                and session.logon_type in _WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES
                and session.session_kind not in {"network", "service"}
                and _session_started_by(session, time)
            )
        ]
        if not candidates:
            return None

        assigned_user = getattr(system, "assigned_user", None)
        if assigned_user:
            assigned_candidates = [
                session for session in candidates if session.username == assigned_user
            ]
            if assigned_candidates:
                candidates = assigned_candidates
        return max(candidates, key=lambda session: session.start_time)

    def _active_user_interactive_windows_session(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest active Windows interactive session for this user/host."""
        if _get_os_category(system.os) != "windows":
            return None

        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user_at(user.username, time)
            if (
                session.system == system.hostname
                and session.logon_type in _WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES
                and session.session_kind not in {"network", "service"}
                and _session_started_by(session, time)
            )
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda session: session.start_time)

    def _active_user_workstation_windows_session(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest local workstation session for this user/host."""
        if _get_os_category(system.os) != "windows":
            return None

        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user_at(user.username, time)
            if (
                session.system == system.hostname
                and _is_windows_workstation_session(session)
                and _session_started_by(session, time)
            )
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda session: session.start_time)

    def _active_user_local_linux_session(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest active local Linux session for this user/host."""
        if _get_os_category(system.os) != "linux":
            return None

        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user_at(user.username, time)
            if (
                session.system == system.hostname
                and session.logon_type in _LINUX_LOCAL_SESSION_LOGON_TYPES
                and session.session_kind not in _LINUX_REMOTE_SESSION_KINDS
                and _session_active_for_activity(session, time)
            )
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda session: ensure_utc(session.start_time))

    def _session_id_for_logon(self, logon_id: str) -> int:
        """Return the canonical source-native session ID for a LogonID."""
        if not logon_id:
            return 0
        return self.state_manager.get_session_id(logon_id)

    def _locked_user_interactive_windows_session(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> tuple[ActiveSession, datetime] | None:
        """Return the newest locked interactive Windows session for this user/host."""
        if _get_os_category(system.os) != "windows":
            return None

        lock_times = getattr(self, "_last_workstation_lock_time", {})
        candidates: list[tuple[datetime, ActiveSession]] = []
        for (hostname, username, locked_logon_id), lock_time in lock_times.items():
            if hostname != system.hostname or username != user.username:
                continue
            lock_timestamp = ensure_utc(lock_time)
            if lock_timestamp > time:
                continue
            session = self.state_manager.get_session(locked_logon_id)
            if (
                session is not None
                and session.system == system.hostname
                and session.start_time <= time
                and _is_windows_workstation_session(session)
            ):
                candidates.append((lock_timestamp, session))

        if not candidates:
            return None
        return max(candidates, key=lambda candidate: candidate[0])

    def _near_future_user_interactive_windows_session(
        self,
        user: User,
        system: System,
        time: datetime,
        *,
        max_gap: timedelta = timedelta(minutes=10),
    ) -> ActiveSession | None:
        """Return a near-future Windows session that should own shifted baseline work."""
        if _get_os_category(system.os) != "windows":
            return None

        activity_time = ensure_utc(time)
        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if (
                session.system == system.hostname
                and session.logon_type in _WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES
                and session.session_kind not in {"network", "service"}
                and activity_time < ensure_utc(session.start_time) <= activity_time + max_gap
            )
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda session: ensure_utc(session.start_time))

    def _user_model_for_username(self, username: str) -> User:
        """Resolve a known scenario user, or build a safe fallback user object."""
        known_users = getattr(self, "_users_by_username", {})
        known_user = known_users.get(username)
        if known_user is not None:
            return known_user
        return User(
            username=username,
            full_name=username,
            email=f"{username}@{self._valid_fallback_email_domain()}",
        )

    def _resolve_process_identity(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        time: datetime,
    ) -> tuple[str, str]:
        """Resolve process owner/logon before emitters render cross-source evidence."""
        if _get_os_category(system.os) != "windows":
            return username, logon_id

        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        normalized_username = username.upper().split("\\")[-1]
        if (
            normalized_username in _SYSTEM_ACCOUNT_LOGON_IDS
            and exe_name not in _WINDOWS_USER_SESSION_PROCESSES
        ):
            return normalized_username, _SYSTEM_ACCOUNT_LOGON_IDS[normalized_username]
        if (
            exe_name not in _WINDOWS_USER_SESSION_PROCESSES
            or normalized_username not in _SYSTEM_ACCOUNTS
        ):
            return username, logon_id

        session = self._active_interactive_windows_session(system, time)
        if session is None:
            return username, logon_id
        return session.username, session.logon_id

    def _remember_connection_tuple(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        duration: float | None = None,
    ) -> None:
        """Track recently allocated 5-tuples to avoid synthetic exact repeats."""
        if proto == "icmp":
            return
        ts_epoch = time.timestamp()
        self._prune_recent_connection_tuples(ts_epoch)
        active_until = ts_epoch + max(0.0, duration or 0.0)
        for key in self._connection_tuple_key_variants(src_ip, src_port, dst_ip, dst_port, proto):
            previous_seen_at = self._recent_connection_tuples.get(key)
            seen_at = max(
                active_until, previous_seen_at if previous_seen_at is not None else ts_epoch
            )
            if previous_seen_at == seen_at:
                continue
            self._recent_connection_tuples[key] = seen_at
            heapq.heappush(self._recent_connection_tuple_heap, (seen_at, key))

    def _prune_recent_connection_tuples(
        self,
        ts_epoch: float,
        *,
        reuse_window: float = _RECENT_CONNECTION_REUSE_WINDOW_SECONDS,
    ) -> None:
        """Remove tuple reservations older than the event-time reuse window."""
        if self._recent_connection_tuples and not self._recent_connection_tuple_heap:
            self._recent_connection_tuple_heap = [
                (seen_at, key) for key, seen_at in self._recent_connection_tuples.items()
            ]
            heapq.heapify(self._recent_connection_tuple_heap)
        cutoff = ts_epoch - reuse_window
        while self._recent_connection_tuple_heap:
            seen_at, key = self._recent_connection_tuple_heap[0]
            if seen_at >= cutoff:
                break
            heapq.heappop(self._recent_connection_tuple_heap)
            if self._recent_connection_tuples.get(key) == seen_at:
                del self._recent_connection_tuples[key]
        if (
            len(self._recent_connection_tuple_heap) > 100_000
            and len(self._recent_connection_tuple_heap) > len(self._recent_connection_tuples) * 4
        ):
            self._recent_connection_tuple_heap = [
                (seen_at, key) for key, seen_at in self._recent_connection_tuples.items()
            ]
            heapq.heapify(self._recent_connection_tuple_heap)

    @staticmethod
    def _connection_tuple_key_variants(
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
    ) -> tuple[tuple[str, int, str, int, str], ...]:
        """Return raw and IPv4-mapped-normalized tuple keys for reuse checks."""
        src_values = (src_ip, src_ip.removeprefix("::ffff:"))
        dst_values = (dst_ip, dst_ip.removeprefix("::ffff:"))
        variants: list[tuple[str, int, str, int, str]] = []
        seen: set[tuple[str, int, str, int, str]] = set()
        for candidate_src in src_values:
            for candidate_dst in dst_values:
                key = (candidate_src, src_port, candidate_dst, dst_port, proto)
                if key in seen:
                    continue
                variants.append(key)
                seen.add(key)
        return tuple(variants)

    def _connection_tuple_recently_used(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        *,
        reuse_window: float = _RECENT_CONNECTION_REUSE_WINDOW_SECONDS,
    ) -> bool:
        """Return whether a source port would visibly repeat a recent endpoint tuple."""
        ts_epoch = time.timestamp()
        self._prune_recent_connection_tuples(ts_epoch, reuse_window=reuse_window)
        for key in self._connection_tuple_key_variants(src_ip, src_port, dst_ip, dst_port, proto):
            seen_at = self._recent_connection_tuples.get(key)
            if seen_at is not None and abs(ts_epoch - seen_at) <= reuse_window:
                return True

        wanted_src = src_ip.removeprefix("::ffff:")
        wanted_dst = dst_ip.removeprefix("::ffff:")
        terminal_states = getattr(self.state_manager, "_TERMINAL_CONN_STATES", frozenset())
        for connection in self.state_manager.state.open_connections.values():
            if connection.state in terminal_states:
                continue
            if (
                connection.src_ip.removeprefix("::ffff:") != wanted_src
                or connection.src_port != src_port
                or connection.dst_ip.removeprefix("::ffff:") != wanted_dst
                or connection.dst_port != dst_port
                or connection.protocol != proto
            ):
                continue
            observed_times = [ensure_utc(connection.start_time)]
            if connection.close_time is not None:
                observed_times.append(ensure_utc(connection.close_time))
            if any(
                abs(ts_epoch - observed.timestamp()) <= reuse_window for observed in observed_times
            ):
                return True
        return False

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Allocate an ephemeral port while avoiding exact 5-tuple reuse."""
        rng = _get_rng()
        reuse_window = _RECENT_CONNECTION_REUSE_WINDOW_SECONDS
        for _ in range(128):
            src_port = _ephemeral_port(rng, os_category)
            if not self._connection_tuple_recently_used(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                time,
                reuse_window=reuse_window,
            ):
                self._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)
                return src_port
        src_port = _ephemeral_port(rng, os_category)
        self._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)
        return src_port

    def _last_effective_connection_source_port(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
    ) -> int | None:
        """Return the source port from the most recently emitted matching connection."""
        last_tuple = self._last_connection_effective_tuple
        if last_tuple is None:
            return None
        last_src_ip, last_src_port, last_dst_ip, last_dst_port, last_proto = last_tuple
        if (
            last_src_ip == src_ip
            and last_dst_ip == dst_ip
            and last_dst_port == dst_port
            and last_proto == proto
        ):
            return last_src_port
        return None

    @staticmethod
    def _kerberos_port_key(source_ip: str, dc_hostname: str) -> tuple[str, str]:
        """Return the source/DC key used for short Kerberos TCP exchanges."""
        return (source_ip.removeprefix("::ffff:"), dc_hostname.lower().rstrip("."))

    @staticmethod
    def _kerberos_tgt_cache_key(
        username: str,
        source_ip: str,
        dc_hostname: str,
    ) -> tuple[str, str, str]:
        """Return the source-native TGT cache identity for one client/DC account."""
        principal = username.split("@", 1)[0].upper()
        return (principal, source_ip.removeprefix("::ffff:"), dc_hostname.lower().rstrip("."))

    @staticmethod
    def _kerberos_source_time(
        time: datetime,
        *,
        event_type: str,
        username: str,
        source_ip: str,
        dc_hostname: str,
        source_port: int,
        service_name: str = "",
    ) -> datetime:
        """Return a source-native Kerberos audit timestamp with sub-ms texture."""
        seed = _stable_seed(
            "kerberos_source_time:"
            f"{event_type}:{username}:{source_ip}:{dc_hostname}:{source_port}:"
            f"{service_name}:{time.isoformat()}"
        )
        # Windows event timestamps are not obtained by adding whole milliseconds
        # to a shared base event. Add deterministic sub-ms texture so related
        # Kerberos rows do not preserve identical fractional suffixes.
        return time + timedelta(microseconds=37 + (seed % 937))

    @staticmethod
    def _kerberos_ticket_times(
        anchor_time: datetime,
        rng: random.Random,
        *,
        tgs_before_ms: tuple[int, int] = (12, 90),
        tgt_before_tgs_ms: tuple[int, int] = (35, 240),
    ) -> tuple[datetime, datetime]:
        """Return source-native-ish TGT and TGS times before an anchor event."""
        tgs_time = anchor_time - timedelta(
            milliseconds=rng.randint(*tgs_before_ms),
            microseconds=rng.randint(83, 941),
        )
        tgt_time = tgs_time - timedelta(
            milliseconds=rng.randint(*tgt_before_tgs_ms),
            microseconds=rng.randint(97, 953),
        )
        return tgt_time, tgs_time

    def _remember_kerberos_tgt_cache(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        rng: random.Random,
    ) -> None:
        """Remember that a client has a reusable TGT beyond this visible moment."""
        key = self._kerberos_tgt_cache_key(username, source_ip, dc_hostname)
        base_ttl = rng.randint(45 * 60, 8 * 60 * 60)
        if username.endswith("$"):
            base_ttl = rng.randint(60 * 60, 10 * 60 * 60)
        expires_at = ensure_utc(time) + timedelta(seconds=base_ttl)
        current = self._kerberos_tgt_cache_until.get(key)
        self._kerberos_tgt_cache_until[key] = (
            max(current, expires_at) if current is not None else expires_at
        )

    def _should_emit_visible_kerberos_tgt(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        rng: random.Random,
    ) -> bool:
        """Return whether a TGS should be preceded by a visible fresh TGT."""
        key = self._kerberos_tgt_cache_key(username, source_ip, dc_hostname)
        current_time = ensure_utc(time)
        cached_until = self._kerberos_tgt_cache_until.get(key)
        if cached_until is not None and cached_until > current_time:
            return rng.random() < 0.08

        pre_window_cache_probability = 0.55 if username.endswith("$") else 0.35
        if rng.random() < pre_window_cache_probability:
            self._remember_kerberos_tgt_cache(username, source_ip, dc_hostname, time, rng)
            return False
        return True

    def _maybe_generate_kerberos_tgt(
        self,
        *,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        rng: random.Random,
        source_port: int | None = None,
        domain: str = "",
    ) -> bool:
        """Emit a TGT only when the client should not be using a cached ticket."""
        if not self._should_emit_visible_kerberos_tgt(username, source_ip, dc_hostname, time, rng):
            return False
        self.generate_kerberos_tgt(
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=time,
            domain=domain,
            source_port=source_port,
        )
        return True

    @staticmethod
    def _is_domain_controller_system(system: Any | None) -> bool:
        """Return whether a system is a domain controller."""
        if system is None:
            return False
        roles = set(getattr(system, "roles", []) or [])
        services = set(getattr(system, "services", []) or [])
        return (
            "domain_controller" in roles
            or getattr(system, "type", "") == "domain_controller"
            or "ad-ds" in services
        )

    def _dc_system_for_ip(self, ip: str) -> Any | None:
        """Resolve a domain controller system by IP address."""
        ip_to_system = getattr(self, "_ip_to_system", {})
        system = ip_to_system.get(ip)
        if self._is_domain_controller_system(system):
            return system
        dc_systems = getattr(self, "_dc_systems", [])
        if isinstance(dc_systems, dict):
            dc_systems = dc_systems.values()
        for candidate in dc_systems:
            if getattr(candidate, "ip", "") == ip and self._is_domain_controller_system(candidate):
                return candidate
        return None

    def _dc_system_for_hostname(self, dc_hostname: str) -> Any | None:
        """Resolve a domain controller system by hostname or FQDN."""
        system = self._system_for_hostname(dc_hostname)
        if self._is_domain_controller_system(system):
            return system
        wanted = dc_hostname.lower().rstrip(".")
        dc_systems = getattr(self, "_dc_systems", [])
        if isinstance(dc_systems, dict):
            dc_systems = dc_systems.values()
        for candidate in dc_systems:
            candidate_host = str(getattr(candidate, "hostname", "") or "").lower().rstrip(".")
            ad_domain = str(getattr(self, "_ad_domain", "") or "").lower().rstrip(".")
            candidate_fqdn = (
                f"{candidate_host}.{ad_domain}"
                if candidate_host and ad_domain and "." not in candidate_host
                else candidate_host
            )
            if wanted in {candidate_host, candidate_fqdn} and self._is_domain_controller_system(
                candidate
            ):
                return candidate
        return None

    def _find_reserved_kerberos_source_port(
        self,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        *,
        dst_ip: str | None = None,
        dst_port: int = 88,
        proto: str = "tcp",
        exclude_active_tuple: bool = True,
        window_seconds: float = 2.0,
    ) -> int | None:
        """Return a nearby reserved Kerberos source port for this source/DC pair."""
        if not source_ip or source_ip == "-" or not dc_hostname:
            return None
        key = self._kerberos_port_key(source_ip, dc_hostname)
        current = time.timestamp()
        reservations = [
            (seen_at, port)
            for seen_at, port in self._kerberos_source_port_reservations.get(key, [])
            if abs(current - seen_at) <= window_seconds
        ]
        if dst_ip and exclude_active_tuple:
            filtered_reservations = []
            for seen_at, port in reservations:
                recent_connection_at = max(
                    self._recent_connection_tuples.get(
                        (source_ip, port, dst_ip, dst_port, candidate_proto),
                        self._recent_connection_tuples.get(
                            (
                                source_ip.removeprefix("::ffff:"),
                                port,
                                dst_ip,
                                dst_port,
                                candidate_proto,
                            ),
                            0.0,
                        ),
                    )
                    for candidate_proto in {proto, "tcp", "udp"}
                )
                reuse_cooldown = min(window_seconds, 2.0)
                if not recent_connection_at or current - recent_connection_at > reuse_cooldown:
                    filtered_reservations.append((seen_at, port))
            reservations = filtered_reservations
        if not reservations:
            return None
        return min(reservations, key=lambda item: abs(current - item[0]))[1]

    def _reserve_kerberos_source_port(
        self,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        source_port: int | None = None,
    ) -> int:
        """Reserve one TCP source port across nearby Kerberos audit and flow events."""
        if not source_ip or source_ip == "-" or not dc_hostname:
            return 0

        dc_system = self._dc_system_for_hostname(dc_hostname)
        dc_ip = str(getattr(dc_system, "ip", "") or "")
        reserved = self._find_reserved_kerberos_source_port(
            source_ip,
            dc_hostname,
            time,
            dst_ip=dc_ip or None,
        )
        if reserved is not None and source_port is None:
            source_port = reserved
        if source_port is None:
            if dc_ip:
                source_port = self._allocate_ephemeral_port(
                    source_ip,
                    dc_ip,
                    88,
                    "tcp",
                    time,
                    self._os_for_ip(source_ip),
                )
                for candidate_proto in ("tcp", "udp"):
                    self._recent_connection_tuples.pop(
                        (source_ip, source_port, dc_ip, 88, candidate_proto),
                        None,
                    )
                    self._recent_connection_tuples.pop(
                        (
                            source_ip.removeprefix("::ffff:"),
                            source_port,
                            dc_ip,
                            88,
                            candidate_proto,
                        ),
                        None,
                    )
            else:
                source_port = _ephemeral_port(_get_rng(), self._os_for_ip(source_ip))

        key = self._kerberos_port_key(source_ip, dc_hostname)
        current = time.timestamp()
        recent = [
            (seen_at, port)
            for seen_at, port in self._kerberos_source_port_reservations.get(key, [])
            if abs(current - seen_at) <= 30.0
        ]
        recent.append((current, source_port))
        self._kerberos_source_port_reservations[key] = recent[-16:]
        return source_port

    def _disambiguate_icmp_observation_time(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        time: datetime,
    ) -> datetime:
        """Avoid exact duplicate Zeek ICMP summaries for the same tuple and timestamp.

        ICMP scans can intentionally repeat the same source/destination pair at very high
        rates, and Zeek collapses the source/destination ports to type/code values. Track the
        next usable microsecond timestamp per rendered ICMP tuple so duplicates are assigned
        in constant time instead of linearly probing through previously emitted timestamps.
        """
        if len(self._next_icmp_observation_ts_us) > 100_000:
            self._next_icmp_observation_ts_us.clear()
        zeek_type = src_port if src_port else 8
        zeek_code = dst_port if dst_port else 0
        tuple_key = (src_ip, zeek_type, dst_ip, zeek_code)
        requested_ts_us = int(round(time.timestamp() * 1_000_000))
        adjusted_ts_us = max(
            requested_ts_us,
            self._next_icmp_observation_ts_us.get(tuple_key, requested_ts_us),
        )
        self._next_icmp_observation_ts_us[tuple_key] = adjusted_ts_us + 11_000
        if adjusted_ts_us == requested_ts_us:
            return time
        return time + timedelta(microseconds=adjusted_ts_us - requested_ts_us)

    def _infer_connection_pid(
        self,
        source_system: System | None,
        service: str | None,
        dst_port: int,
        proto: str,
    ) -> int:
        """Infer a durable system-service PID for infrastructure connections."""
        if source_system is None:
            return -1
        pids = getattr(self, "_system_pids", {}).get(source_system.hostname, {})
        if not pids:
            return -1

        service_name = (service or "").lower()
        roles = set(getattr(source_system, "roles", []) or [])
        os_category = _get_os_category(source_system.os)

        candidates: list[str] = []
        if proto == "udp" and dst_port == 53 or service_name == "dns":
            candidates = [
                "systemd_resolved",
                "svchost_local_svc",
                "svchost_netsvcs",
                "svchost_net_svc",
            ]
        elif proto == "udp" and dst_port == 123 or service_name == "ntp":
            candidates = ["timesyncd", "chronyd", "svchost_netsvcs"]
        elif service_name in ("kerberos", "ldap") or dst_port in (88, 389):
            candidates = ["lsass", "svchost_netsvcs"]
        elif service_name == "smb" or dst_port == 445:
            return 4 if os_category == "windows" else pids.get("smbd", -1)
        elif service_name == "ssh" or dst_port == 22:
            if os_category == "linux":
                return -1
            candidates = ["sshd"]
        elif "forward_proxy" in roles and service_name in ("http", "ssl"):
            candidates = ["squid", "nginx", "apache2", "httpd"]
        elif os_category == "linux" and (
            service_name in ("http", "ssl", "https") or dst_port in (80, 443, 8080, 8443)
        ):
            candidates = ["curl", "wget", "firefox", "apache2", "httpd", "nginx", "python3"]
        elif os_category == "windows" and (
            service_name in ("http", "ssl", "https") or dst_port in (80, 443, 8080, 8443)
        ):
            candidates = ["chrome", "msedge", "firefox", "powershell", "svchost_netsvcs"]

        for name in candidates:
            pid = pids.get(name)
            if pid and pid > 0:
                return pid
        return -1

    def _build_dc_host_context(self, dc_hostname: str) -> HostContext:
        """Build a HostContext for a domain controller from raw hostname string.

        DC methods receive raw strings (not System objects). Constructs a
        HostContext suitable for Windows event rendering (Computer field).
        """
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        return HostContext(
            hostname=dc_hostname,
            ip="",
            os="Windows Server 2019",
            os_category="windows",
            system_type="domain_controller",
            domain=ad_domain,
            fqdn=f"{dc_hostname}.{ad_domain}" if ad_domain else dc_hostname,
            netbios_domain=ad_domain.split(".")[0].upper() if ad_domain else "CORP",
        )

    def _proxy_fqdn(self, proxy_sys: "System") -> str:
        """Return the FQDN used to route proxy access logs."""
        proxy_fqdn = getattr(proxy_sys, "hostname", "")
        ad_domain = getattr(self, "_ad_domain", "")
        if ad_domain and "." not in proxy_fqdn:
            proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
        return proxy_fqdn

    def _proxy_username_for_source(
        self,
        *,
        source_system: Optional["System"],
        user_agent: str,
        cache_result: str,
        hostname: str | None = None,
    ) -> str:
        """Return the source-native authenticated proxy username for a client request."""
        if source_system is None or cache_result.upper() == "AUTH_REQUIRED":
            return ""

        auth_policy = getattr(self, "_proxy_auth_policy", ProxyAuthPolicyConfig())
        netbios_domain = getattr(self, "_netbios_domain", "") or "CORP"
        os_category = _get_os_category(getattr(source_system, "os", ""))
        short_hostname = str(getattr(source_system, "hostname", "") or "").split(".", 1)[0]

        def _service_principal(seed: int) -> str:
            service_accounts = list(getattr(self, "_proxy_service_accounts", []) or [])
            if not service_accounts:
                return ""
            service_account = service_accounts[seed % len(service_accounts)]
            if os_category == "windows":
                return f"{netbios_domain}\\{service_account}"
            ad_domain = getattr(self, "_ad_domain", "")
            return f"{service_account}@{ad_domain}" if ad_domain else service_account

        domain_class = get_proxy_domain_class(hostname or "") if hostname else None
        if (
            auth_policy.mode == "realistic"
            and domain_class
            and domain_class.lower() in set(auth_policy.allowlisted_domain_classes)
        ):
            if not auth_policy.non_human_principals:
                return ""
            roll_seed = _stable_seed(
                "proxy_auth_non_human:"
                f"{getattr(source_system, 'hostname', '')}:"
                f"{hostname or ''}:"
                f"{user_agent}:"
                f"{cache_result}"
            )
            roll = (roll_seed % 1_000_000) / 1_000_000.0
            machine_cutoff = auth_policy.machine_account_probability
            service_cutoff = machine_cutoff + auth_policy.service_account_probability
            if roll < machine_cutoff and os_category == "windows" and short_hostname:
                return f"{netbios_domain}\\{short_hostname}$"
            if roll < service_cutoff:
                return _service_principal(roll_seed)
            return ""

        assigned_user = getattr(source_system, "assigned_user", None)
        if not assigned_user or assigned_user in _SYSTEM_ACCOUNTS or assigned_user.endswith("$"):
            return ""

        system_type = (getattr(source_system, "type", "") or "").lower()
        if system_type != "workstation":
            return ""

        if os_category == "windows":
            if _is_machine_context_proxy_user_agent(user_agent):
                if auth_policy.mode == "realistic" and not auth_policy.non_human_principals:
                    return ""
                if auth_policy.mode == "realistic":
                    machine_roll_seed = _stable_seed(
                        "proxy_auth_machine:"
                        f"{getattr(source_system, 'hostname', '')}:"
                        f"{hostname or ''}:"
                        f"{user_agent}:"
                        f"{cache_result}"
                    )
                    machine_roll = (machine_roll_seed % 1_000_000) / 1_000_000.0
                    machine_cutoff = auth_policy.machine_account_probability
                    service_cutoff = machine_cutoff + auth_policy.service_account_probability
                    if machine_roll >= service_cutoff:
                        return ""
                    if machine_roll >= machine_cutoff:
                        return _service_principal(machine_roll_seed)
                if short_hostname:
                    return f"{netbios_domain}\\{short_hostname}$"
            return f"{netbios_domain}\\{assigned_user}"

        ad_domain = getattr(self, "_ad_domain", "")
        if ad_domain:
            return f"{assigned_user}@{ad_domain}"
        return assigned_user

    def _build_proxy_context(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str | None,
        duration: float | None,
        orig_bytes: int | None,
        resp_bytes: int | None,
        hostname: str | None,
        source_system: Optional["System"],
        proxy_sys: "System",
        http: Optional["HttpContext"] = None,
        explicit_mode: bool = False,
    ) -> ProxyContext:
        """Build a proxy access context from the logical origin request."""
        rng = _get_rng()
        proxy_hostname = hostname
        if proxy_hostname is None:
            proxy_hostname = REVERSE_DNS.get(dst_ip)
        if proxy_hostname is None:
            proxy_hostname = _generate_random_hostname(rng, dst_ip)
        if proxy_hostname == "":
            proxy_hostname = dst_ip

        from evidenceforge.generation.activity.dns_registry import get_domain_tags
        from evidenceforge.generation.activity.proxy_uri import (
            is_browser_like_proxy_domain,
            pick_proxy_uri,
            plaintext_http_redirect_status,
        )
        from evidenceforge.generation.activity.referrer import pick_referrer

        domain_tags = get_domain_tags(proxy_hostname)
        proxy_ua_override = None
        if http is not None:
            from evidenceforge.generation.activity.http_content import normalize_mime_type_for_path

            scheme = "https" if dst_port == 443 or service == "ssl" else "http"
            proxy_method = http.method
            url = f"{scheme}://{proxy_hostname}{http.uri}"
            if http.resp_mime_types or http.status_code == 304:
                proxy_content_type = normalize_mime_type_for_path(
                    http.uri,
                    http.resp_mime_types[0] if http.resp_mime_types else "text/html",
                )
            else:
                proxy_content_type = "text/html"
            user_agent = http.user_agent
            proxy_referrer = http.referrer
        elif explicit_mode and dst_port == 443:
            proxy_method = "CONNECT"
            url = f"{proxy_hostname}:443"
            proxy_content_type = ""
            proxy_referrer = ""
            user_agent = ""
        else:
            source_os = _get_os_category(source_system.os) if source_system else None
            (
                path,
                proxy_content_type,
                proxy_method,
                proxy_ua_override,
                referrer_policy,
            ) = pick_proxy_uri(
                rng,
                proxy_hostname,
                domain_tags,
                source_os=source_os,
                source_system_type=getattr(source_system, "type", None),
            )
            scheme = "https" if dst_port == 443 or service == "ssl" else "http"
            url = f"{scheme}://{proxy_hostname}{path}"
            proxy_referrer = (
                ""
                if referrer_policy == "none"
                else pick_referrer(rng, proxy_hostname, context="general", port=dst_port)
            )
            user_agent = ""

        redirect_status = plaintext_http_redirect_status(
            proxy_hostname,
            port=dst_port,
            path=http.uri if http is not None else _origin_form_uri_from_proxy_url(url),
            dst_ip=dst_ip,
        )
        if redirect_status is not None and http is None:
            proxy_content_type = "text/html"

        apply_domain_user_agent = http is None or (
            not _is_tool_http_user_agent(http.user_agent)
            and not is_browser_like_proxy_domain(proxy_hostname, domain_tags=domain_tags)
        )
        domain_user_agent = (
            pick_proxy_domain_user_agent(
                rng,
                source_system,
                hostname=proxy_hostname,
            )
            if apply_domain_user_agent
            else None
        )
        if domain_user_agent:
            user_agent = domain_user_agent
        elif not user_agent:
            if proxy_ua_override:
                user_agent = proxy_ua_override
            else:
                user_agent = pick_proxy_user_agent(
                    rng,
                    source_system,
                    hostname=proxy_hostname,
                    domain_tags=domain_tags,
                )
        user_agent = normalize_proxy_user_agent_for_os(
            rng,
            source_system,
            user_agent,
            hostname=proxy_hostname,
            domain_tags=domain_tags,
        )
        proxy_referrer = _source_native_http_referrer(
            user_agent,
            proxy_referrer,
            request_scheme="https" if dst_port == 443 or service == "ssl" else "http",
            request_port=dst_port,
        )

        proxy_cacheable = _proxy_request_allows_cache_hit(
            method=proxy_method,
            url=url,
            content_type=proxy_content_type,
            domain_tags=domain_tags,
        )
        if http is not None:
            from evidenceforge.generation.activity.http_content import infer_mime_type_from_path

            response_mime = proxy_content_type or infer_mime_type_from_path(url)
            proxy_cacheable = _proxy_request_allows_cache_hit(
                method=proxy_method,
                url=url,
                content_type=response_mime,
                domain_tags=domain_tags,
            )
        if explicit_mode and dst_port == 443:
            proxy_cacheable = False

        cache_roll = rng.random()
        if http is not None:
            # When the request already carries canonical HTTP outcome data,
            # proxy rendering should not independently invent a policy denial.
            if http.status_code == 304:
                cache_result = "REVALIDATED"
            elif proxy_cacheable and cache_roll < 0.30 and http.status_code < 400:
                cache_result = "HIT"
            else:
                cache_result = "MISS"
        elif explicit_mode and proxy_method == "CONNECT":
            if cache_roll < 0.88:
                cache_result = "NONE"
            elif cache_roll < 0.925:
                cache_result = "DENIED"
            elif cache_roll < 0.965:
                cache_result = "AUTH_REQUIRED"
            else:
                cache_result = "GATEWAY_ERROR"
        elif proxy_cacheable and cache_roll < 0.30:
            cache_result = "HIT"
        elif cache_roll < 0.95:
            cache_result = "MISS"
        else:
            cache_result = "DENIED"

        policy_status_code = (
            redirect_status
            if redirect_status is not None
            and cache_result not in {"DENIED", "AUTH_REQUIRED", "GATEWAY_ERROR"}
            else None
        )
        if policy_status_code is not None and http is None:
            from evidenceforge.generation.activity.http_content import response_size_for_status

            response_bytes = response_size_for_status(
                policy_status_code,
                proxy_hostname,
                _origin_form_uri_from_proxy_url(url),
            )
        else:
            response_bytes = http.response_body_len if http is not None else (resp_bytes or 0)
        cs_bytes = (orig_bytes or 0) + rng.randint(*_PROXY_CS_OVERHEAD)
        if cache_result == "DENIED":
            sc_bytes = rng.randint(500, 2000)
        elif cache_result == "AUTH_REQUIRED":
            sc_bytes = rng.randint(300, 1200)
        elif cache_result == "GATEWAY_ERROR":
            sc_bytes = rng.randint(250, 1800)
        elif cache_result == "HIT":
            sc_bytes = response_bytes + rng.randint(*_PROXY_SC_OVERHEAD)
        elif proxy_method == "CONNECT":
            host_len = len(proxy_hostname)
            cs_bytes = rng.randint(180 + host_len, 520 + host_len)
            sc_bytes = rng.randint(90, 260)
        else:
            sc_bytes = response_bytes + rng.randint(*_PROXY_SC_OVERHEAD)

        if (
            explicit_mode
            and proxy_method == "CONNECT"
            and cache_result
            in {
                "DENIED",
                "AUTH_REQUIRED",
                "GATEWAY_ERROR",
            }
        ):
            host_len = len(proxy_hostname)
            cs_bytes = rng.randint(180 + host_len, 520 + host_len)

        status_code = (
            http.status_code
            if http is not None
            else policy_status_code
            if policy_status_code is not None
            else {
                "DENIED": 403,
                "AUTH_REQUIRED": 407,
                "GATEWAY_ERROR": rng.choice([502, 503, 504]),
            }.get(cache_result, 200)
        )
        time_taken = _proxy_time_taken_ms(
            duration,
            rng,
            method=proxy_method,
            status_code=status_code,
            cache_result=cache_result,
        )

        return ProxyContext(
            client_ip=src_ip,
            username=self._proxy_username_for_source(
                source_system=source_system,
                user_agent=user_agent,
                cache_result=cache_result,
                hostname=proxy_hostname,
            ),
            method=proxy_method,
            url=url,
            host=proxy_hostname,
            status_code=status_code,
            tunnel_status_code=200
            if explicit_mode and dst_port == 443 and proxy_method != "CONNECT"
            else status_code,
            sc_bytes=sc_bytes,
            cs_bytes=cs_bytes,
            time_taken=time_taken,
            user_agent=user_agent,
            content_type=proxy_content_type,
            cache_result=cache_result,
            referrer=proxy_referrer,
            proxy_fqdn=self._proxy_fqdn(proxy_sys),
            proxy_action=_proxy_action_for_context(
                method=proxy_method,
                url=url,
                status_code=status_code,
                cache_result=cache_result,
                dst_port=dst_port,
                explicit_mode=explicit_mode,
            ),
        )

    def _explicit_proxy_client_process_hint(
        self,
        *,
        user_agent: str,
        hostname: str,
        dst_port: int,
        proxy_sys: System,
        source_system: System | None = None,
    ) -> tuple[str, str] | None:
        """Map user-owned proxy User-Agents to the process that owns the socket."""
        os_category = _get_os_category(source_system.os) if source_system is not None else "windows"
        server_like_source = self._is_proxy_server_like_source(source_system)
        if os_category == "windows" and not server_like_source:
            browser_hint = self._browser_http_client_process_hint(
                user_agent=user_agent,
                hostname=hostname,
                dst_port=dst_port,
            )
            if browser_hint is not None:
                return browser_hint

        ua = (user_agent or "").lower()
        if not ua:
            return None

        target_url = self._http_target_url(hostname=hostname, uri="/", dst_port=dst_port)
        proxy_url = (
            f"http://{self._proxy_fqdn(proxy_sys)}:{getattr(self, '_proxy_listener_port', 8080)}"
        )

        if os_category == "linux":
            package_hint = self._linux_package_manager_proxy_client_hint(
                user_agent=user_agent,
                source_system=source_system,
                dst_port=dst_port,
            )
            if package_hint is not None:
                return package_hint
            if server_like_source:
                if ua.startswith("go-http-client/"):
                    return "/usr/local/bin/service-healthcheck", (
                        f"service-healthcheck --url {target_url}"
                    )
                if ua.startswith("apache-httpclient/"):
                    return "/usr/bin/java", (
                        f"java -jar /opt/meridian/integration-worker.jar --check-url {target_url}"
                    )
                return None
            if "firefox/" in ua:
                return "/usr/bin/firefox", f"firefox --new-window {target_url}"
            if "edg/" in ua or "edge/" in ua:
                return "/usr/bin/microsoft-edge", f"microsoft-edge {target_url}"
            if "opr/" in ua or "opera/" in ua:
                return "/usr/bin/opera", f"opera {target_url}"
            if "chrome/" in ua and "google update" not in ua:
                return "/usr/bin/google-chrome", f"google-chrome {target_url}"
            if ua.startswith("curl/") or " curl/" in ua:
                return "/usr/bin/curl", f"curl --proxy {proxy_url} {target_url}"
            if ua.startswith("wget/") or " wget/" in ua:
                return (
                    "/usr/bin/wget",
                    f"wget -e use_proxy=yes -e http_proxy={proxy_url} {target_url}",
                )
            if ua.startswith("python-requests/"):
                return (
                    "/usr/bin/python3",
                    f"python3 -c 'import requests; requests.get(\"{target_url}\")'",
                )
            if ua.startswith("go-http-client/"):
                return "/usr/local/bin/service-healthcheck", (
                    f"service-healthcheck --url {target_url}"
                )
            if ua.startswith("apache-httpclient/"):
                return "/usr/bin/java", (
                    f"java -jar /opt/meridian/integration-worker.jar --check-url {target_url}"
                )
            if "powershell" in ua or "invoke-webrequest" in ua:
                return "/usr/bin/pwsh", f"pwsh -NoProfile -Command Invoke-WebRequest {target_url}"
            return None

        if server_like_source:
            if ua.startswith("go-http-client/"):
                image = r"C:\Program Files\Meridian\ServiceHealth\service-healthcheck.exe"
                return image, f'"{image}" --url "{target_url}"'
            if ua.startswith("apache-httpclient/"):
                image = r"C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe"
                return image, f'"{image}" -jar C:\\ProgramData\\Meridian\\integration-worker.jar'
            return None

        if ua.startswith("curl/") or " curl/" in ua:
            image = r"C:\Windows\System32\curl.exe"
            return image, f'curl.exe --proxy {proxy_url} "{target_url}"'
        if ua.startswith("wget/") or " wget/" in ua:
            image = r"C:\Program Files\GnuWin32\bin\wget.exe"
            return image, f'wget.exe -e use_proxy=yes -e http_proxy={proxy_url} "{target_url}"'
        if ua.startswith("python-requests/"):
            image = r"C:\Python311\python.exe"
            return image, f"python.exe -c \"import requests; requests.get('{target_url}')\""
        if ua.startswith("go-http-client/"):
            image = r"C:\Program Files\Meridian\ServiceHealth\service-healthcheck.exe"
            return image, f'"{image}" --url "{target_url}"'
        if ua.startswith("apache-httpclient/"):
            image = r"C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe"
            return image, f'"{image}" -jar C:\\ProgramData\\Meridian\\integration-worker.jar'
        if "powershell" in ua or "invoke-webrequest" in ua:
            image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            return image, (
                f'powershell.exe -NoProfile -Command "Invoke-WebRequest '
                f"-Proxy '{proxy_url}' -Uri '{target_url}' -UseBasicParsing\""
            )
        return None

    @staticmethod
    def _is_proxy_server_like_source(source_system: System | None) -> bool:
        """Return whether proxy client PID synthesis should avoid workstation tooling."""
        if source_system is None:
            return False
        roles = {str(role).lower() for role in (getattr(source_system, "roles", None) or [])}
        server_roles = {
            "app_server",
            "database",
            "dns_server",
            "domain_controller",
            "file_server",
            "forward_proxy",
            "log_server",
            "mail_server",
            "monitoring",
            "web_server",
        }
        if roles & server_roles:
            return True
        system_type = (getattr(source_system, "type", "") or "").lower()
        if (
            system_type == "server"
            and _get_os_category(source_system.os) == "linux"
            and getattr(source_system, "assigned_user", None)
        ):
            return False
        return system_type in {"server", "domain_controller"}

    @staticmethod
    def _linux_package_manager_proxy_client_hint(
        *,
        user_agent: str,
        source_system: System | None,
        dst_port: int,
    ) -> tuple[str, str] | None:
        """Return source-native Linux package-manager socket owner process details."""
        if source_system is None:
            return None
        ua = (user_agent or "").lower()
        if not ua:
            return None

        from evidenceforge.generation.activity.bash_commands import (
            package_manager_family_for_os,
        )

        package_family = package_manager_family_for_os(source_system.os)
        if "apt-http" in ua:
            if package_family != "debian":
                return None
            method = "https" if dst_port == 443 else "http"
            image = f"/usr/lib/apt/methods/{method}"
            return image, image
        if "libdnf" in ua:
            if package_family != "rpm":
                return None
            return "/usr/bin/dnf", "dnf makecache --timer"
        return None

    @staticmethod
    def _http_target_url(*, hostname: str, uri: str, dst_port: int) -> str:
        """Build the URL used in source-native client process command lines."""
        return ActivityGenerator._http_target_url_with_scheme(
            hostname=hostname,
            uri=uri,
            dst_port=dst_port,
            scheme=None,
        )

    @staticmethod
    def _http_target_url_with_scheme(
        *,
        hostname: str,
        uri: str,
        dst_port: int,
        scheme: str | None,
    ) -> str:
        """Build a URL while allowing CONNECT callers to preserve HTTPS semantics."""
        path = uri or "/"
        if path.startswith(("http://", "https://")):
            return path
        if not path.startswith("/"):
            path = f"/{path}"
        resolved_scheme = scheme or ("https" if dst_port == 443 else "http")
        if not hostname:
            return f"{resolved_scheme}://"
        host = hostname
        default_port = 443 if resolved_scheme == "https" else 80
        if dst_port != default_port and ":" not in host:
            host = f"{host}:{dst_port}"
        return f"{resolved_scheme}://{host}{path}"

    @staticmethod
    def _browser_launch_uri(uri: str) -> str:
        """Return the navigation URI a browser process would show at launch."""
        path = uri or "/"
        if path.startswith(("http://", "https://")):
            try:
                parsed = urlsplit(path)
            except ValueError:
                return uri or "/"
            path = parsed.path or "/"
        if not path.startswith("/"):
            path = f"/{path}"

        clean_path = path.split("?", 1)[0].split("#", 1)[0].lower()
        basename = clean_path.rsplit("/", 1)[-1]
        suffix = f".{basename.rsplit('.', 1)[-1]}" if "." in basename else ""
        static_prefixes = (
            "/assets/",
            "/asset/",
            "/static/",
            "/media/",
            "/images/",
            "/img/",
            "/css/",
            "/js/",
            "/fonts/",
        )
        static_names = {"/favicon.ico", "/robots.txt", "/sitemap.xml", "/index.html", "/index.htm"}
        static_suffixes = {
            ".avif",
            ".css",
            ".gif",
            ".ico",
            ".jpeg",
            ".jpg",
            ".js",
            ".map",
            ".png",
            ".svg",
            ".webp",
            ".woff",
            ".woff2",
        }
        if (
            clean_path in static_names
            or clean_path.startswith(static_prefixes)
            or suffix in static_suffixes
        ):
            return "/"
        return uri or "/"

    @staticmethod
    def _browser_navigation_target(
        *,
        hostname: str,
        uri: str,
        dst_port: int,
    ) -> tuple[str, int, bool]:
        """Normalize proxy CONNECT targets into a browser-visible navigation target."""
        max_port_digits = 5
        raw_uri = (uri or "").strip()
        host = (hostname or "").strip().lower().rstrip(".")
        if raw_uri and not raw_uri.startswith(("/", "http://", "https://")):
            target, separator, port = raw_uri.rpartition(":")
            if separator and port.isdigit() and target.strip().lower().rstrip(".") == host:
                if len(port) > max_port_digits:
                    return "/", dst_port, True
                parsed_port = int(port)
                if 1 <= parsed_port <= 65535:
                    return "/", parsed_port, True
                return "/", dst_port, True
        return uri, dst_port, False

    @staticmethod
    def _browser_target_allows_top_level_launch(hostname: str, uri: str = "/") -> bool:
        """Return whether a URL is plausible as a new user-visible browser launch."""
        host = (hostname or "").strip().lower().rstrip(".")
        if not host:
            return True
        if not is_browser_like_proxy_domain(host):
            return False

        label = host.split(".", 1)[0]
        resource_labels = {
            "asset",
            "assets",
            "avatars",
            "cdn",
            "crl",
            "github-releases",
            "img",
            "images",
            "media",
            "objects",
            "ocsp",
            "static",
        }
        if label in resource_labels:
            return False
        if host.endswith(".githubusercontent.com") and label in {"avatars", "objects"}:
            return False
        return True

    def _browser_http_client_process_hint(
        self,
        *,
        user_agent: str,
        hostname: str,
        dst_port: int,
        uri: str = "/",
    ) -> tuple[str, str] | None:
        """Map browser-like Windows HTTP User-Agents to their owning process."""
        ua = (user_agent or "").lower()
        if not ua:
            return None

        target_uri, target_port, is_connect_target = self._browser_navigation_target(
            hostname=hostname,
            uri=uri,
            dst_port=dst_port,
        )
        launch_uri = self._browser_launch_uri(target_uri)
        target_url = self._http_target_url_with_scheme(
            hostname=hostname,
            uri=launch_uri,
            dst_port=target_port,
            scheme="https" if is_connect_target and target_port != 80 else None,
        )
        if "firefox/" in ua:
            image = r"C:\Program Files\Mozilla Firefox\firefox.exe"
            return image, f'"{image}" -osint -url {target_url}'
        if "edg/" in ua or "edge/" in ua:
            image = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
            return image, f'"{image}" --single-argument {target_url}'
        if "opr/" in ua or "opera/" in ua:
            image = r"C:\Program Files\Opera\opera.exe"
            return image, f'"{image}" {target_url}'
        if "chrome/" in ua and "google update" not in ua:
            image = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            return image, f'"{image}" --single-argument {target_url}'
        if "trident/" in ua or "msie " in ua:
            image = r"C:\Program Files\Internet Explorer\iexplore.exe"
            return image, f'"{image}" {target_url}'
        return None

    def _claim_top_level_browser_launch_target(
        self,
        *,
        system: System,
        username: str,
        image: str,
        hostname: str,
        uri: str,
    ) -> bool:
        """Return whether an exact browser launch target should create a process."""
        if not hasattr(self, "_top_level_browser_launch_targets"):
            self._top_level_browser_launch_targets: dict[tuple[str, str, str, str, str], int] = {}
        key = (
            system.hostname,
            username,
            image.lower(),
            (hostname or "").strip().lower().rstrip("."),
            self._browser_launch_uri(uri).lower(),
        )
        previous = self._top_level_browser_launch_targets.get(key, 0)
        self._top_level_browser_launch_targets[key] = previous + 1
        return previous == 0

    def _select_explicit_proxy_client_session(
        self,
        source_system: System,
        time: datetime,
    ) -> tuple[User, Any] | None:
        """Pick the user session most likely to own a user-mode proxy request."""
        known_users = getattr(self, "_users_by_username", {})
        sessions = [
            session
            for session in self.state_manager.get_sessions_on_system(source_system.hostname)
            if session.username in known_users
            and session.username not in _SYSTEM_ACCOUNTS
            and not session.username.endswith("$")
            and session.logon_type in {2, 7, 10, 11}
            and _session_started_by(session, time)
        ]
        if not sessions:
            return None

        assigned_user = getattr(source_system, "assigned_user", None)
        if assigned_user:
            assigned_sessions = [
                session for session in sessions if session.username == assigned_user
            ]
            if assigned_sessions:
                sessions = assigned_sessions

        session = max(sessions, key=lambda candidate: candidate.start_time)
        return known_users[session.username], session

    def _ensure_explicit_proxy_client_process(
        self,
        *,
        source_system: System | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
    ) -> tuple[int, str | None]:
        """Create or reuse the process that source-natively owns a proxy client socket."""
        if source_system is None or _get_os_category(source_system.os) != "windows":
            if source_system is None or _get_os_category(source_system.os) != "linux":
                return -1, None

        hint = self._explicit_proxy_client_process_hint(
            user_agent=proxy_context.user_agent,
            hostname=proxy_context.host,
            dst_port=dst_port,
            proxy_sys=proxy_sys,
            source_system=source_system,
        )
        if hint is None:
            return -1, None

        image, command_line = hint
        session_info = self._select_explicit_proxy_client_session(source_system, time)
        if session_info is None:
            return -1, None
        user, session = session_info

        image_lower = image.lower()
        running_candidates = [
            proc
            for proc in self.state_manager.get_processes_on_system(source_system.hostname)
            if proc.username == user.username
            and proc.image.lower() == image_lower
            and proc.start_time is not None
            and proc.start_time <= time
            and not self._foreground_process_expired_for_attribution(source_system, proc, time)
        ]
        if running_candidates:
            proc = max(running_candidates, key=lambda candidate: candidate.start_time)
            self.state_manager.update_process_activity_time(
                source_system.hostname,
                proc.pid,
                time,
            )
            return proc.pid, proc.image

        os_category = _get_os_category(source_system.os)
        if os_category == "windows" and image_lower.endswith(tuple(_WINDOWS_BROWSER_EXES)):
            parsed_url = urlsplit(proxy_context.url or "")
            proxy_uri = parsed_url.path or "/"
            if not self._browser_target_allows_top_level_launch(proxy_context.host, proxy_uri):
                return -1, None
            if not self._claim_top_level_browser_launch_target(
                system=source_system,
                username=user.username,
                image=image,
                hostname=proxy_context.host,
                uri=proxy_uri,
            ):
                return -1, None

        process_rng = random.Random(
            _stable_seed(
                "explicit_proxy_client_process:"
                f"{source_system.hostname}:{user.username}:{image}:{proxy_context.host}"
            )
        )
        process_lifetime = (
            _windows_foreground_lifetime(image, command_line)
            if os_category == "windows"
            else _linux_foreground_lifetime(image, command_line)
        )
        if process_lifetime is not None:
            lead_seconds = process_rng.uniform(0.4, min(8.0, process_lifetime[1]))
        else:
            lead_seconds = process_rng.uniform(12.0, 240.0)
        process_time = time - timedelta(seconds=lead_seconds)
        min_process_time = session.start_time + timedelta(milliseconds=500)
        if process_time < min_process_time:
            process_time = min_process_time
        if process_time >= time:
            process_time = time - timedelta(milliseconds=100)

        parent_pid = self._select_parent_pid(
            source_system,
            user,
            image,
            time=process_time,
            logon_id=session.logon_id,
        )
        pid = self.generate_process(
            user=user,
            system=source_system,
            time=process_time,
            logon_id=session.logon_id,
            process_name=image,
            command_line=command_line,
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
            allow_browser_launch_spacing=False,
        )
        self._record_user_process(source_system, user, pid, image)
        self.state_manager.update_process_activity_time(source_system.hostname, pid, time)
        self.state_manager.set_current_time(time)
        return pid, image

    def _ensure_browser_http_client_process(
        self,
        *,
        source_system: System | None,
        time: datetime,
        http: HttpContext,
        dst_port: int,
    ) -> tuple[int, str | None]:
        """Create or reuse the browser process that owns a Windows HTTP socket."""
        if source_system is None or _get_os_category(source_system.os) != "windows":
            return -1, None

        hint = self._browser_http_client_process_hint(
            user_agent=http.user_agent,
            hostname=http.host,
            dst_port=dst_port,
            uri=http.uri,
        )
        if hint is None:
            return -1, None

        image, command_line = hint
        session = self._active_interactive_windows_session(source_system, time)
        if session is None:
            return -1, None
        user = self._user_model_for_username(session.username)

        image_lower = image.lower()
        running_candidates = [
            proc
            for proc in self.state_manager.get_processes_on_system(source_system.hostname)
            if proc.username == user.username
            and proc.image.lower() == image_lower
            and proc.start_time is not None
            and proc.start_time <= time
            and not self._foreground_process_expired_for_attribution(source_system, proc, time)
        ]
        if running_candidates:
            proc = max(running_candidates, key=lambda candidate: candidate.start_time)
            self.state_manager.update_process_activity_time(
                source_system.hostname,
                proc.pid,
                time,
            )
            return proc.pid, proc.image

        if not self._browser_target_allows_top_level_launch(http.host, http.uri):
            return -1, None
        if not self._claim_top_level_browser_launch_target(
            system=source_system,
            username=user.username,
            image=image,
            hostname=http.host,
            uri=http.uri,
        ):
            return -1, None

        process_rng = random.Random(
            _stable_seed(
                "browser_http_client_process:"
                f"{source_system.hostname}:{user.username}:{image}:"
                f"{http.host}:{self._browser_launch_uri(http.uri)}"
            )
        )
        lead_seconds = process_rng.uniform(0.4, 8.0)
        process_time = time - timedelta(seconds=lead_seconds)
        min_process_time = session.start_time + timedelta(milliseconds=500)
        if process_time < min_process_time:
            process_time = min_process_time
        if process_time >= time:
            process_time = time - timedelta(milliseconds=100)

        parent_pid = self._select_parent_pid(
            source_system,
            user,
            image,
            time=process_time,
            logon_id=session.logon_id,
        )
        pid = self.generate_process(
            user=user,
            system=source_system,
            time=process_time,
            logon_id=session.logon_id,
            process_name=image,
            command_line=command_line,
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
            allow_existing_browser_reuse=False,
            allow_browser_launch_spacing=False,
        )
        self._record_user_process(source_system, user, pid, image)
        self.state_manager.update_process_activity_time(source_system.hostname, pid, time)
        self.state_manager.set_current_time(time)
        running = self.state_manager.get_process(source_system.hostname, pid)
        if running is not None:
            return pid, running.image
        return pid, image

    def _set_connection_process_context(
        self,
        event: SecurityEvent,
        *,
        source_system: System,
        pid: int,
        image: str | None = None,
    ) -> None:
        """Update canonical connection process ownership from StateManager."""
        running = self.state_manager.get_process(source_system.hostname, pid)
        if running is not None:
            event.process = ProcessContext(
                pid=pid,
                parent_pid=running.parent_pid,
                image=running.image,
                command_line=running.command_line,
                username=running.username,
                logon_id=running.logon_id,
                start_time=running.start_time,
                parent_start_time=self._lookup_parent_start_time(
                    source_system.hostname,
                    running.parent_pid,
                ),
            )
        elif image:
            event.process = ProcessContext(
                pid=pid,
                parent_pid=0,
                image=image,
                command_line="",
                username="",
            )
        else:
            event.process = None
        event.network.initiating_pid = pid
        if event.edr is not None:
            event.edr.actor_id = (
                self.state_manager.get_process_object_id(source_system.hostname, pid)
                if pid > 0
                else ""
            )

    def _repair_browser_http_process_attribution(
        self,
        event: SecurityEvent,
        *,
        source_system: System | None,
        time: datetime,
    ) -> None:
        """Prevent browser-like HTTP rows from inheriting service-process ownership."""
        if (
            source_system is None
            or event.http is None
            or event.network is None
            or _get_os_category(source_system.os) != "windows"
        ):
            return

        hint = self._browser_http_client_process_hint(
            user_agent=event.http.user_agent,
            hostname=event.http.host,
            dst_port=event.network.dst_port,
            uri=event.http.uri,
        )
        if hint is None:
            return

        expected_image = hint[0].lower()
        current_pid = event.network.initiating_pid
        if current_pid > 0:
            current = self.state_manager.get_process(source_system.hostname, current_pid)
            if current is not None and not self._foreground_process_expired_for_attribution(
                source_system,
                current,
                time,
            ):
                if current.image.lower() == expected_image:
                    self._set_connection_process_context(
                        event,
                        source_system=source_system,
                        pid=current_pid,
                    )
                    self.state_manager.update_process_activity_time(
                        source_system.hostname,
                        current_pid,
                        time,
                    )
                    return
                expected_exe = ntpath.basename(expected_image).lower()
                current_exe = ntpath.basename(current.image or "").lower()
                mismatched_browser = (
                    expected_exe in _WINDOWS_BROWSER_EXES and current_exe in _WINDOWS_BROWSER_EXES
                )
                if not mismatched_browser and not self._windows_proxy_pid_should_be_replaced(
                    current
                ):
                    return

        client_pid, client_image = self._ensure_browser_http_client_process(
            source_system=source_system,
            time=time,
            http=event.http,
            dst_port=event.network.dst_port,
        )
        if client_pid > 0:
            self._set_connection_process_context(
                event,
                source_system=source_system,
                pid=client_pid,
                image=client_image,
            )
            return

        self._set_connection_process_context(
            event,
            source_system=source_system,
            pid=-1,
        )

    @staticmethod
    def _proxy_origin_port_from_http(http: HttpContext) -> int:
        """Return the origin port represented by a client-to-proxy HTTP request."""
        if (http.method or "").upper() == "CONNECT":
            target = http.uri or http.host or ""
            _host, separator, port_text = target.rpartition(":")
            if separator and port_text.isdigit() and len(port_text) <= 5:
                port = int(port_text)
                if 1 <= port <= 65535:
                    return port
            return 443
        url = http.uri or ""
        if url.startswith(("http://", "https://")):
            try:
                parsed = urlsplit(url)
                parsed_port = parsed.port
            except ValueError:
                return 443 if url.startswith("https://") else 80
            if parsed_port is not None:
                return parsed_port
            return 443 if parsed.scheme == "https" else 80
        return 80

    def _repair_explicit_proxy_listener_process_attribution(
        self,
        event: SecurityEvent,
        *,
        source_system: System | None,
        time: datetime,
    ) -> None:
        """Apply proxy client process ownership to direct client-to-proxy HTTP flows."""
        if source_system is None or event.http is None or event.network is None:
            return
        if event.network.dst_port != getattr(self, "_proxy_listener_port", 8080):
            return
        proxy_sys = getattr(self, "_ip_to_system", {}).get(event.network.dst_ip)
        if proxy_sys is None or "forward_proxy" not in (proxy_sys.roles or []):
            return

        proxy_context = ProxyContext(
            client_ip=event.network.src_ip,
            method=event.http.method,
            url=event.http.uri,
            host=event.http.host,
            status_code=event.http.status_code,
            user_agent=event.http.user_agent,
            proxy_fqdn=self._proxy_fqdn(proxy_sys),
        )
        origin_port = self._proxy_origin_port_from_http(event.http)
        current_pid = event.network.initiating_pid
        current_image = event.process.image if event.process is not None else None
        if current_pid > 0:
            caller_process_image = self._caller_explicit_proxy_process_image(
                source_system=source_system,
                pid=current_pid,
                process_image=current_image,
                time=time,
                proxy_context=proxy_context,
                proxy_sys=proxy_sys,
                dst_port=origin_port,
            )
            if caller_process_image is not None:
                self._set_connection_process_context(
                    event,
                    source_system=source_system,
                    pid=current_pid,
                    image=caller_process_image,
                )
                self.state_manager.update_process_activity_time(
                    source_system.hostname,
                    current_pid,
                    time,
                )
                return

        client_pid, client_image = self._ensure_explicit_proxy_client_process(
            source_system=source_system,
            time=time,
            proxy_context=proxy_context,
            proxy_sys=proxy_sys,
            dst_port=origin_port,
        )
        if client_pid > 0:
            self._set_connection_process_context(
                event,
                source_system=source_system,
                pid=client_pid,
                image=client_image,
            )
            return

        self._set_connection_process_context(
            event,
            source_system=source_system,
            pid=-1,
        )

    def _caller_explicit_proxy_process_image(
        self,
        *,
        source_system: System | None,
        pid: int,
        process_image: str | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
    ) -> str | None:
        """Return the caller process image when valid proxy client telemetry owns it."""
        if pid <= 0 or source_system is None:
            return None

        running = self.state_manager.get_process(source_system.hostname, pid)
        if running is None:
            return None
        if self._foreground_process_expired_for_attribution(
            source_system,
            running,
            time=time,
        ):
            return None
        candidate_image = running.image or process_image
        if not candidate_image:
            return None

        hint = self._explicit_proxy_client_process_hint(
            user_agent=proxy_context.user_agent,
            hostname=proxy_context.host,
            dst_port=dst_port,
            proxy_sys=proxy_sys,
            source_system=source_system,
        )
        if hint is None:
            os_category = _get_os_category(source_system.os)
            if os_category == "windows" and self._windows_proxy_pid_should_be_replaced(running):
                return None
            if os_category == "linux" and self._linux_proxy_pid_should_be_replaced(
                running,
                expected_exe="",
            ):
                return None
            return candidate_image

        expected_image = hint[0]
        if candidate_image.lower() == expected_image.lower():
            return candidate_image
        expected_exe = ntpath.basename(expected_image).lower()
        candidate_exe = ntpath.basename(candidate_image).lower()
        proxy_browser_exes = _WINDOWS_BROWSER_EXES | {
            "chromium",
            "chromium-browser",
            "firefox",
            "google-chrome",
            "microsoft-edge",
            "opera",
        }
        if expected_exe in proxy_browser_exes and candidate_exe in proxy_browser_exes:
            return None
        os_category = _get_os_category(source_system.os)
        if os_category == "windows" and self._windows_proxy_pid_should_be_replaced(running):
            return None
        if os_category == "linux" and self._linux_proxy_pid_should_be_replaced(
            running,
            expected_exe=expected_exe,
        ):
            return None
        return candidate_image

    @staticmethod
    def _windows_proxy_pid_should_be_replaced(process: Any) -> bool:
        """Return whether a Windows PID is known service-owned proxy attribution noise."""
        image = str(getattr(process, "image", "") or "")
        command_line = str(getattr(process, "command_line", "") or "")
        exe_name = ntpath.basename(image).lower()
        unrelated_user_app_exes = {
            "acrobat.exe",
            "devicesyncsvc.exe",
            "dropbox.exe",
            "dropboxupdate.exe",
            "excel.exe",
            "googledrivefs.exe",
            "outlook.exe",
            "onedrive.exe",
            "pangpa.exe",
            "postman.exe",
            "python.exe",
            "python3.exe",
            "selfservice.exe",
            "slack.exe",
            "teams.exe",
            "vpnui.exe",
            "webex.exe",
            "winword.exe",
            "zoom.exe",
            "zsatray.exe",
        }
        return (
            _windows_service_process_account(image, command_line) is not None
            or exe_name in _WINDOWS_SINGLETON_SERVICE_EXES
            or exe_name in unrelated_user_app_exes
        )

    @staticmethod
    def _linux_proxy_pid_should_be_replaced(process: Any, *, expected_exe: str) -> bool:
        """Return whether a Linux PID is source-native noise for a proxy client socket."""
        image = str(getattr(process, "image", "") or "")
        exe_name = image.rsplit("/", 1)[-1].lower()
        if exe_name == expected_exe:
            return False
        return exe_name in {
            "apache2",
            "bash",
            "cat",
            "cargo",
            "curl",
            "docker",
            "git",
            "grep",
            "head",
            "httpd",
            "java",
            "journalctl",
            "kubectl",
            "less",
            "ls",
            "nano",
            "nginx",
            "npm",
            "php-fpm",
            "ps",
            "python",
            "python3",
            "sed",
            "service-healthcheck",
            "sh",
            "systemctl",
            "tail",
            "vim",
            "zsh",
        }

    def _attach_ssl_context(
        self,
        event: SecurityEvent,
        *,
        hostname: str | None,
        dns: Optional["DnsContext"],
        dst_ip: str,
        rng: random.Random,
        allow_failure: bool = True,
    ) -> None:
        """Attach Zeek SSL and x509 contexts to an established TLS connection."""
        from evidenceforge.events.contexts import SslContext

        net = event.network
        if net is None or event.ssl is not None:
            return

        # Hostname is the SNI source of truth.  Do not invent SNI from a bare
        # destination IP or PTR; raw-IP TLS should either have no SNI or an
        # explicit/DNS-backed hostname.
        server_name = hostname
        if server_name is None and dns is not None and dns.query:
            server_name = dns.query
        # Suppressed hostname -> no SNI (raw-IP C2, etc.)
        if server_name == "":
            server_name = None
        if event.http is not None:
            # A visible HTTP transaction over TLS means the handshake completed.
            # Failed-handshake SSL rows cannot coexist with successful http.log,
            # web/proxy response bytes, or SF conn.log accounting for the same UID.
            allow_failure = False

        # For suppressed external hostnames (raw-IP C2), use the IP as the cert subject.
        # For internal/private endpoints without explicit SNI, use the known
        # internal hostname so x509.log does not show public-CA certificates
        # issued to private IPs. If explicit internal SNI exists, it remains
        # the certificate identity and SAN source of truth.
        internal_cert_name = ""
        if _is_private_ip(dst_ip):
            if server_name:
                internal_cert_name = server_name
            else:
                dst_host = event.dst_host
                if dst_host is None and hasattr(self, "_ip_to_system"):
                    dst_system = self._ip_to_system.get(dst_ip)
                    if dst_system is not None:
                        dst_host = self._build_host_context(dst_system)
                if dst_host is not None:
                    internal_cert_name = dst_host.fqdn or dst_host.hostname
        cert_name = server_name or internal_cert_name or dst_ip

        # Issuer-aware certificate generation from YAML config.
        from evidenceforge.generation.activity.tls_issuers import pick_issuer, pick_key_type

        cert_rng = random.Random(_stable_seed(f"tls_cert_profile:{cert_name}"))
        if internal_cert_name:
            issuer_cfg = _enterprise_tls_issuer(getattr(self, "_ad_domain", ""))
        elif _is_ip_literal(cert_name):
            issuer_cfg = _raw_ip_tls_issuer(cert_name)
        else:
            issuer_cfg = pick_issuer(cert_rng, server_name=cert_name, event_time=event.timestamp)
        key_type, key_length = pick_key_type(cert_rng, issuer_cfg)
        key_type, key_length = _tls_key_for_certificate_name(cert_name, key_type, key_length)
        is_ecdsa = key_type == "ecdsa"

        modern_tls_domain = bool(server_name) and server_name.endswith(
            (
                ".google.com",
                ".gstatic.com",
                ".googleapis.com",
                ".microsoft.com",
                ".office.com",
                ".office365.com",
                ".microsoftonline.com",
                ".windowsupdate.com",
                ".cloudfront.net",
                ".github.com",
                ".slack.com",
                ".zoom.us",
            )
        )
        _tls_rng = random.Random(_stable_seed(f"tls:{server_name or dst_ip}:{net.src_ip}"))
        if modern_tls_domain:
            tls_version = _tls_rng.choices(("TLSv12", "TLSv13"), weights=(15, 85), k=1)[0]
        else:
            tls_version = _tls_rng.choices(_TLS_VERSION_VALUES, weights=_TLS_VERSION_WEIGHTS, k=1)[
                0
            ]
        if tls_version == "TLSv13":
            cipher = _tls_rng.choices(_TLS13_CIPHER_VALUES, weights=_TLS13_CIPHER_WEIGHTS, k=1)[0]
        elif is_ecdsa:
            cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        elif modern_tls_domain:
            cipher = _tls_rng.choices(
                (
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                ),
                weights=(75, 25),
                k=1,
            )[0]
        else:
            cipher = _tls_rng.choices(
                (
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                ),
                weights=(65, 28, 7),
                k=1,
            )[0]

        ssl_established = (rng.random() > _SSL_FAILURE_RATE) if allow_failure else True
        ssl_history_roll = rng.random()
        tls_name_key = server_name or dst_ip
        first_observed_name = tls_name_key not in self._tls_seen_server_names
        pair_key = (net.src_ip, net.dst_ip, net.dst_port, tls_name_key)
        first_observed_pair = pair_key not in self._tls_seen_client_server_pairs
        resumed = (
            rng.random() < 0.45 and not first_observed_name and not first_observed_pair
            if ssl_established
            else False
        )
        self._tls_seen_server_names.add(tls_name_key)
        self._tls_seen_client_server_pairs.add(pair_key)
        ssl_hist = _choose_ssl_history_from_roll(
            ssl_history_roll,
            tls_version=tls_version,
            established=ssl_established,
            resumed=resumed,
        )

        event.ssl = SslContext(
            version=tls_version,
            cipher=cipher if ssl_established else "",
            server_name=server_name,
            resumed=resumed,
            established=ssl_established,
            ssl_history=ssl_hist,
        )
        if not ssl_established:
            net.conn_state = "S1"
            net.orig_bytes = rng.randint(90, 260)
            net.resp_bytes = rng.randint(40, 180) if rng.random() < 0.55 else 0
            net.history = "ShADd" if net.resp_bytes else "ShAD"
            net.orig_pkts, net.resp_pkts = _tcp_packet_counts_from_payload_and_history(
                net.orig_bytes,
                net.resp_bytes,
                net.history,
                rng,
            )
            net.orig_ip_bytes = _tcp_ip_byte_count(net.orig_bytes, net.orig_pkts, rng)
            net.resp_ip_bytes = _tcp_ip_byte_count(net.resp_bytes, net.resp_pkts, rng)
            if net.duration is not None:
                net.duration = rng.uniform(0.0, 0.5)
            return

        # Passive Zeek cannot extract the encrypted Certificate message from
        # ordinary TLS 1.3 handshakes. Keep ssl.log evidence but suppress
        # cert_chain_fuids plus files.log/x509.log side effects unless the
        # model grows an explicit TLS decryption context.
        if tls_version == "TLSv13":
            return

        import hashlib

        from evidenceforge.events.contexts import X509Context

        if resumed:
            return
        cert_fuid = generate_stable_zeek_uid(
            "F",
            f"cert_fuid:{cert_name}:{net.zeek_uid}:{event.timestamp.timestamp()}",
        )
        # Support validity_days_min/max ranges; fall back to scalar validity_days
        _vd_fallback = issuer_cfg.get("validity_days", 397)
        _vd_min = issuer_cfg.get("validity_days_min", _vd_fallback)
        _vd_max = issuer_cfg.get("validity_days_max", _vd_fallback)
        validity = self._tls_cert_validity.get(cert_name)
        if validity is None:
            not_before_max = issuer_cfg.get("not_before_max_days", 300)
            validity = _certificate_validity_window(
                event.timestamp,
                cert_rng,
                validity_days_min=int(_vd_min),
                validity_days_max=int(_vd_max),
                not_before_max_days=int(not_before_max),
            )
        validity = _bound_certificate_validity_to_issuer_window(
            validity,
            str(issuer_cfg["name"]),
            event.timestamp,
        )
        self._tls_cert_validity[cert_name] = validity
        if internal_cert_name:
            short_name = internal_cert_name.split(".", 1)[0]
            san_dns_list = list(dict.fromkeys([internal_cert_name, short_name]))
        else:
            san_dns_list = _tls_san_dns_names(cert_name)
        serial_seed = "|".join(
            [
                "tls_cert_serial",
                cert_name,
                issuer_cfg["name"],
                key_type,
                str(key_length),
                str(validity[0]),
                str(validity[1]),
            ]
        )
        serial_number = _tls_certificate_serial(serial_seed)
        cert_hash = hashlib.sha1(
            "|".join(
                [
                    "cert",
                    cert_name,
                    serial_number,
                    issuer_cfg["name"],
                    key_type,
                    str(key_length),
                    str(validity[0]),
                    str(validity[1]),
                ]
            ).encode(),
            usedforsecurity=False,
        ).hexdigest()
        event.x509 = X509Context(
            fuid=cert_fuid,
            fingerprint=cert_hash,
            certificate_version=3,
            certificate_serial=serial_number,
            certificate_subject=f"CN={cert_name}",
            certificate_issuer=issuer_cfg["name"],
            certificate_not_valid_before=validity[0],
            certificate_not_valid_after=validity[1],
            certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
            certificate_sig_alg=_tls_signature_algorithm_for_issuer(
                issuer_cfg["name"],
                fallback_key_type=key_type,
                fallback_key_length=key_length,
            ),
            certificate_key_type=key_type,
            certificate_key_length=key_length,
            certificate_exponent="65537" if not is_ecdsa else "",
            san_dns=san_dns_list,
            basic_constraints_ca=False,
            host_cert=True,
            client_cert=False,
        )
        event.x509_chain = self._build_tls_certificate_chain(
            leaf=event.x509,
            cert_name=cert_name,
            issuer_name=issuer_cfg["name"],
            event_time=event.timestamp,
            connection_uid=net.zeek_uid,
            rng=rng,
        )
        event.ssl.cert_chain_fuids = [cert.fuid for cert in event.x509_chain]
        self._ensure_tls_conn_covers_certificate_bytes(event)

        # OCSP response (cached/probabilistic; mostly good, with rare non-good statuses).
        # Zeek ocsp.log joins through a separate OCSP HTTP response file
        # (`ocsp.id == files.fuid`), not through the encrypted TLS connection UID.
        if rng.random() < 0.18:
            from evidenceforge.generation.activity.tls_realism import ocsp_config
            from evidenceforge.utils.ids import generate_zeek_uid as _gen_uid

            ocsp_settings = ocsp_config()
            ocsp_bucket_seconds = int(ocsp_settings.get("cache_bucket_seconds", 4 * 60 * 60))
            this_update_max_skew = int(ocsp_settings.get("this_update_max_skew_seconds", 3600))
            next_update_min = int(ocsp_settings.get("next_update_min_seconds", 8 * 3600))
            next_update_max = int(ocsp_settings.get("next_update_max_seconds", 7 * 86400))
            event_epoch = int(event.timestamp.timestamp())
            bucket_start = event_epoch - (event_epoch % ocsp_bucket_seconds)
            ocsp_window_key = (
                cert_name,
                event.x509.certificate_serial,
                bucket_start,
            )
            ocsp_window = self._tls_ocsp_windows.get(ocsp_window_key)
            if ocsp_window is None:
                ocsp_rng = random.Random(
                    _stable_seed(
                        f"ocsp_window:{cert_name}:{event.x509.certificate_serial}:{bucket_start}"
                    )
                )
                this_update = bucket_start - ocsp_rng.randint(0, max(0, this_update_max_skew))
                next_update = (
                    bucket_start
                    + ocsp_bucket_seconds
                    + ocsp_rng.randint(next_update_min, max(next_update_min, next_update_max))
                )
                ocsp_window = (this_update, next_update)
                self._tls_ocsp_windows[ocsp_window_key] = ocsp_window
            this_update, next_update = ocsp_window
            issuer_name_hash = hashlib.sha1(
                event.x509.certificate_issuer.encode(),
                usedforsecurity=False,
            ).hexdigest()
            issuer_key_hash = hashlib.sha1(
                f"key_{event.x509.certificate_issuer}".encode(),
                usedforsecurity=False,
            ).hexdigest()
            ocsp_id = _gen_uid("F")
            cert_status = _ocsp_status_for_certificate(
                cert_name,
                event.x509.certificate_serial,
                suppress_revoked=(
                    event.http is not None
                    and 200 <= int(getattr(event.http, "status_code", 0) or 0) < 400
                ),
            )
            revoketime = None
            revokereason = None
            if cert_status == "revoked":
                revocation_rng = random.Random(
                    _stable_seed(f"ocsp_revocation:{cert_name}:{event.x509.certificate_serial}")
                )
                revoketime = float(this_update - revocation_rng.randint(86400, 90 * 86400))
                revokereason = revocation_rng.choice(
                    [
                        "keyCompromise",
                        "cessationOfOperation",
                        "affiliationChanged",
                        "superseded",
                    ]
                )
            ocsp_ctx = OcspContext(
                id=ocsp_id,
                hash_algorithm="sha1",
                issuer_name_hash=issuer_name_hash,
                issuer_key_hash=issuer_key_hash,
                serial_number=event.x509.certificate_serial,
                cert_status=cert_status,
                this_update=this_update,
                next_update=next_update,
                revoketime=revoketime,
                revokereason=revokereason,
            )
            self._emit_ocsp_http_response(event, cert_name=cert_name, ocsp=ocsp_ctx, rng=rng)

    @staticmethod
    def _ensure_tls_conn_covers_certificate_bytes(event: SecurityEvent) -> None:
        """Keep Zeek SSL certificate file evidence within the same conn budget."""
        net = event.network
        if net is None or not event.x509_chain:
            return

        from evidenceforge.generation.activity.tls_realism import (
            certificate_analyzer_delay_ms,
            certificate_file_size,
        )

        cert_bytes = sum(certificate_file_size(cert) for cert in event.x509_chain)
        min_resp_bytes = cert_bytes + 280
        if (net.resp_bytes or 0) < min_resp_bytes:
            net.resp_bytes = min_resp_bytes
            if net.resp_pkts is not None:
                net.resp_pkts = max(net.resp_pkts, max(1, (net.resp_bytes // 1460) + 1))
            if net.resp_ip_bytes is not None:
                packet_count = net.resp_pkts or max(1, (net.resp_bytes // 1460) + 1)
                net.resp_ip_bytes = max(net.resp_ip_bytes, net.resp_bytes + (packet_count * 40))

        max_cert_delay = max(
            certificate_analyzer_delay_ms(
                zeek_uid=net.zeek_uid,
                event_timestamp=event.timestamp,
                fuid=cert.fuid,
                position=idx,
            )
            for idx, cert in enumerate(event.x509_chain)
        )
        min_duration = (max_cert_delay / 1000.0) + 0.005
        # Reserve room for files.log and x509.log chain rows before the conn
        # emitter applies its own source-native TLS duration floor.
        min_duration = max(min_duration, 1.05 + (0.075 * len(event.x509_chain)))
        if net.duration is None or net.duration < min_duration:
            net.duration = min_duration

    def _emit_ocsp_http_response(
        self,
        tls_event: SecurityEvent,
        *,
        cert_name: str,
        ocsp: OcspContext,
        rng: random.Random,
    ) -> None:
        """Emit Zeek-native OCSP HTTP/file evidence for an OCSP response."""
        net = tls_event.network
        if net is None:
            return

        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
        from evidenceforge.generation.activity.tls_realism import (
            ocsp_request_path,
            pick_ocsp_responder,
        )

        issuer_name = tls_event.x509.certificate_issuer if tls_event.x509 else ""
        responder = pick_ocsp_responder(
            issuer_name,
            random.Random(_stable_seed(f"ocsp_responder:{issuer_name}:{ocsp.serial_number}")),
        )
        responder_ip = resolve_domain_ip(responder, src_host=net.src_ip)
        ocsp_time = tls_event.timestamp + timedelta(
            milliseconds=random.Random(_stable_seed(f"ocsp_time:{ocsp.id}")).randint(900, 4500)
        )
        ocsp_uri = ocsp_request_path(
            responder=responder,
            issuer_name=issuer_name,
            cert_name=cert_name,
            serial_number=ocsp.serial_number,
            this_update=ocsp.this_update,
        )
        response_profile_key = (
            responder,
            ocsp_uri,
            ocsp.serial_number,
            ocsp.this_update,
            ocsp.next_update,
            ocsp.cert_status,
        )
        ocsp_size = self._tls_ocsp_response_sizes.get(response_profile_key)
        if ocsp_size is None:
            size_seed = ":".join(str(part) for part in response_profile_key)
            ocsp_size = random.Random(_stable_seed(f"ocsp_file_size:{size_seed}")).randint(
                900,
                2500,
            )
            self._tls_ocsp_response_sizes[response_profile_key] = ocsp_size
        source_system = getattr(self, "_ip_to_system", {}).get(net.src_ip)
        source_os = str(getattr(source_system, "os", "") or "")
        user_agent = pick_proxy_user_agent(
            random.Random(_stable_seed(f"ocsp_user_agent:{responder}:{net.src_ip}:{source_os}")),
            source_system,
            hostname=responder,
        )
        http_ctx = HttpContext(
            method="GET",
            host=responder,
            uri=ocsp_uri,
            version="1.1",
            user_agent=user_agent,
            request_body_len=0,
            response_body_len=ocsp_size,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["application/ocsp-response"],
            resp_fuids=[ocsp.id],
            tags=["ocsp"],
        )
        file_ctx = FileTransferContext(
            fuid=ocsp.id,
            source="HTTP",
            depth=0,
            analyzers=[],
            mime_type="application/ocsp-response",
            duration=random.Random(_stable_seed(f"ocsp_file_duration:{ocsp.id}")).uniform(
                0.001, 0.02
            ),
            local_orig=_is_private_ip(responder_ip),
            is_orig=False,
            seen_bytes=ocsp_size,
            total_bytes=ocsp_size,
            missing_bytes=0,
            overflow_bytes=0,
            timedout=False,
        )
        self.generate_connection(
            src_ip=net.src_ip,
            dst_ip=responder_ip,
            time=ocsp_time,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=random.Random(_stable_seed(f"ocsp_conn_duration:{ocsp.id}")).uniform(
                0.02, 0.35
            ),
            orig_bytes=320,
            resp_bytes=ocsp_size,
            emit_dns=True,
            pid=net.initiating_pid,
            source_system=source_system,
            conn_state="SF",
            http=http_ctx,
            file_transfer=file_ctx,
            ocsp=ocsp,
            hostname=responder,
            proxy_bypass=True,
        )

    def _pick_profiled_tls_destination(
        self,
        rng: random.Random,
        *,
        src_ip: str,
        source_system: Optional["System"] = None,
        purpose_tags: tuple[str, ...] = (),
    ) -> tuple[str, str]:
        """Pick a profile-aware TLS hostname/IP for baseline external TLS."""
        from evidenceforge.generation.activity.tls_realism import pick_tls_destination

        resolved_source = source_system
        if (
            resolved_source is None
            and hasattr(self, "_ip_to_system")
            and src_ip in self._ip_to_system
        ):
            resolved_source = self._ip_to_system[src_ip]

        source_os = _get_os_category(resolved_source.os) if resolved_source else None
        persona = None
        if resolved_source is not None and getattr(resolved_source, "assigned_user", None):
            user = getattr(self, "_users_by_username", {}).get(resolved_source.assigned_user)
            persona = getattr(user, "persona", None) if user is not None else None

        return pick_tls_destination(
            rng,
            src_host=resolved_source.hostname if resolved_source else src_ip,
            source_os=source_os,
            persona=persona,
            system_type=getattr(resolved_source, "type", None) if resolved_source else None,
            purpose_tags=purpose_tags,
        )

    def _build_tls_certificate_chain(
        self,
        *,
        leaf: Any,
        cert_name: str,
        issuer_name: str,
        event_time: datetime,
        connection_uid: str,
        rng: random.Random,
    ) -> list[Any]:
        """Build a configured leaf/intermediate certificate chain."""
        import hashlib

        from evidenceforge.events.contexts import X509Context
        from evidenceforge.generation.activity.tls_realism import (
            certificate_authority_profile,
            certificate_chain_config,
            certificate_subject_key_profile,
            chain_template_for_issuer,
            signature_algorithm_for_issuer,
        )

        chain = [leaf]
        if _is_ip_literal(cert_name):
            return chain
        config = certificate_chain_config()
        include_probability = float(config.get("include_intermediate_probability", 0.86))
        if rng.random() >= include_probability:
            return chain

        template = chain_template_for_issuer(issuer_name)
        intermediate_subjects = [
            str(subject) for subject in template.get("intermediates", []) if subject
        ]
        if not intermediate_subjects:
            return chain

        chain_rng = random.Random(_stable_seed(f"tls_chain:{cert_name}:{issuer_name}"))
        second_probability = float(config.get("include_second_intermediate_probability", 0.08))
        issuer_authority_profile = certificate_authority_profile(issuer_name)
        if issuer_authority_profile is not None:
            parent_issuer = str(issuer_authority_profile["issuer"])
        else:
            parent_issuer = chain_rng.choice(intermediate_subjects)

        selected_certificates = [(issuer_name, parent_issuer)]
        if parent_issuer != issuer_name and chain_rng.random() < second_probability:
            selected_certificates.append((parent_issuer, parent_issuer))

        for subject, certificate_issuer in selected_certificates:
            resolved_issuer = certificate_issuer
            authority_profile = certificate_authority_profile(subject)
            if authority_profile is not None:
                resolved_issuer = str(authority_profile["issuer"])
            profile_key = (subject, resolved_issuer)
            profile = self._tls_intermediate_profiles.get(profile_key)
            if profile is None:
                profile_rng = random.Random(
                    _stable_seed(f"tls_intermediate_profile:{subject}:{resolved_issuer}")
                )
                if authority_profile is not None:
                    validity = (
                        int(authority_profile["not_valid_before"]),
                        int(authority_profile["not_valid_after"]),
                    )
                    key_type = str(authority_profile["key_type"])
                    key_length = int(authority_profile["key_length"])
                else:
                    validity = self._tls_cert_validity.get(subject)
                    if validity is None:
                        min_days = int(config.get("intermediate_validity_days_min", 1825))
                        max_days = int(config.get("intermediate_validity_days_max", 3650))
                        max_not_before = int(config.get("intermediate_not_before_max_days", 1460))
                        validity = _certificate_validity_window(
                            event_time,
                            profile_rng,
                            validity_days_min=min_days,
                            validity_days_max=max_days,
                            not_before_max_days=max_not_before,
                            not_before_min_days=30,
                        )
                        self._tls_cert_validity[subject] = validity

                    key_types = config.get(
                        "key_types",
                        [{"type": "rsa", "length": 2048, "weight": 100}],
                    )
                    weights = [int(entry.get("weight", 0)) for entry in key_types]
                    selected_key = profile_rng.choices(key_types, weights=weights, k=1)[0]
                    key_type = str(selected_key.get("type", "rsa"))
                    key_length = int(selected_key.get("length", 2048))
                    key_type, key_length = certificate_subject_key_profile(
                        subject,
                        fallback_type=key_type,
                        fallback_length=key_length,
                    )
                validity = _bound_certificate_validity_to_issuer_window(
                    validity,
                    resolved_issuer,
                    event_time,
                )
                self._tls_cert_validity[subject] = validity
                key_type, key_length = _tls_key_for_certificate_name(subject, key_type, key_length)
                serial_seed = "|".join(
                    [
                        "tls_chain_serial",
                        subject,
                        resolved_issuer,
                        key_type,
                        str(key_length),
                        str(validity[0]),
                        str(validity[1]),
                    ]
                )
                serial = _tls_certificate_serial(serial_seed)
                cert_hash = hashlib.sha1(
                    "|".join(
                        [
                            "cert_chain",
                            subject,
                            serial,
                            resolved_issuer,
                            key_type,
                            str(key_length),
                            str(validity[0]),
                            str(validity[1]),
                        ]
                    ).encode(),
                    usedforsecurity=False,
                ).hexdigest()
                profile = {
                    "fingerprint": cert_hash,
                    "certificate_serial": serial,
                    "certificate_subject": subject,
                    "certificate_issuer": resolved_issuer,
                    "certificate_not_valid_before": validity[0],
                    "certificate_not_valid_after": validity[1],
                    "certificate_key_type": key_type,
                    "certificate_key_length": key_length,
                }
                self._tls_intermediate_profiles[profile_key] = profile
            key_type = str(profile["certificate_key_type"])
            key_length = int(profile["certificate_key_length"])
            is_ecdsa = key_type == "ecdsa"
            signature_alg = signature_algorithm_for_issuer(
                str(profile["certificate_issuer"]),
                fallback_type=key_type,
                fallback_length=key_length,
            )
            chain.append(
                X509Context(
                    fuid=generate_stable_zeek_uid(
                        "F",
                        f"cert_chain_fuid:{subject}:{connection_uid}:{event_time.timestamp()}",
                    ),
                    fingerprint=str(profile["fingerprint"]),
                    certificate_version=3,
                    certificate_serial=str(profile["certificate_serial"]),
                    certificate_subject=str(profile["certificate_subject"]),
                    certificate_issuer=str(profile["certificate_issuer"]),
                    certificate_not_valid_before=int(profile["certificate_not_valid_before"]),
                    certificate_not_valid_after=int(profile["certificate_not_valid_after"]),
                    certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
                    certificate_sig_alg=signature_alg,
                    certificate_key_type=key_type,
                    certificate_key_length=key_length,
                    certificate_exponent="65537" if not is_ecdsa else "",
                    san_dns=[],
                    basic_constraints_ca=True,
                    host_cert=False,
                    client_cert=False,
                )
            )
        return chain

    def _build_expansion_context(
        self,
        event_type: str,
        timestamp: datetime,
        **kwargs: Any,
    ) -> ExpansionContext:
        """Build an ExpansionContext from event parameters and engine state."""
        dns_server_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
        dc_hostnames = getattr(self, "_dc_hostnames", [])
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        if not hasattr(self, "_dns_cache"):
            self._dns_cache: dict[tuple[str, str, str, str], float] = {}
        if not hasattr(self, "_kerberos_cache"):
            self._kerberos_cache: dict[str, float] = {}

        dc_systems = getattr(self, "_dc_systems", [])
        if not hasattr(self, "_created_account_sids"):
            self._created_account_sids: dict[str, str] = {}

        return ExpansionContext(
            event_type=event_type,
            timestamp=timestamp,
            src_ip=kwargs.get("src_ip"),
            dst_ip=kwargs.get("dst_ip"),
            dst_port=kwargs.get("dst_port"),
            protocol=kwargs.get("protocol") or kwargs.get("proto"),
            service=kwargs.get("service"),
            logon_type=kwargs.get("logon_type"),
            auth_package=kwargs.get("auth_package"),
            command_line=kwargs.get("command_line"),
            process_name=kwargs.get("process_name"),
            os_category=kwargs.get("os_category"),
            hostname=kwargs.get("hostname"),
            source_system=kwargs.get("source_system"),
            target_system=kwargs.get("target_system"),
            actor=kwargs.get("actor"),
            source_pid=kwargs.get("source_pid"),
            source_image=kwargs.get("source_image"),
            target_pid=kwargs.get("target_pid"),
            target_image=kwargs.get("target_image"),
            logon_id=kwargs.get("logon_id"),
            skip_types=kwargs.get("skip_types", set()),
            dns_cache=self._dns_cache,
            kerberos_cache=self._kerberos_cache,
            dns_server_ips=dns_server_ips,
            dc_hostnames=dc_hostnames,
            dc_systems=dc_systems,
            ad_domain=ad_domain,
            sid_registry=self.sid_registry,
            created_account_sids=self._created_account_sids,
        )

    def _expand_and_emit(
        self,
        event_type: str,
        timestamp: datetime,
        **kwargs: Any,
    ) -> None:
        """Run causal expansion and emit all expanded prerequisite/consequent events.

        This is a no-op if:
        - No causal engine is configured.
        - We are already expanding the same event type (prevents same-type recursion).

        Cross-type expansion is allowed: a process_create expansion can trigger
        a connection expansion (which triggers DNS), but connection cannot
        recursively trigger another connection expansion.
        """
        if event_type in self._expanding_types:
            logger.debug("Skipping nested %s expansion (already expanding)", event_type)
            return

        ctx = self._build_expansion_context(event_type, timestamp, **kwargs)
        expanded = self._causal_engine.expand(event_type, ctx)
        if not expanded:
            return

        rng = _get_rng()
        self._expanding_types.add(event_type)
        try:
            previous_after_time: datetime | None = None
            for ev in expanded:
                offset_ms = rng.randint(ev.timing.min_ms, ev.timing.max_ms)
                offset = timedelta(milliseconds=offset_ms)
                if ev.timing.position == "before":
                    ev.kwargs["time"] = timestamp - offset
                else:
                    ev.kwargs["time"] = timestamp + offset
                    if event_type == "process_create":
                        process_system = kwargs.get("target_system") or kwargs.get("source_system")
                        source_pid = kwargs.get("source_pid")
                        if process_system is not None and isinstance(source_pid, int):
                            ev.kwargs["time"] = self._clamp_after_visible_process_create(
                                process_system,
                                source_pid,
                                ev.kwargs["time"],
                                "windows.audit_after_visible_admin_command",
                            )
                    if previous_after_time is not None and ev.kwargs["time"] <= previous_after_time:
                        ev.kwargs["time"] = previous_after_time + timedelta(milliseconds=1)
                    previous_after_time = ev.kwargs["time"]

                method = getattr(self, ev.method)
                method(**ev.kwargs)
        finally:
            self._expanding_types.discard(event_type)

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: str | None = None,
        source_system: System | None = None,
        source_port: int | None = None,
        emit_transport_syslog: bool = True,
        emit_network_evidence: bool = True,
        logon_id: str | None = None,
    ) -> str:
        """Generate logon event across all applicable log formats.

        Creates or reuses a session in StateManager, builds a SecurityEvent,
        and dispatches to matching emitters (Windows 4624 + optional 4672,
        syslog auth, eCAR).

        Args:
            user: User logging on
            system: System being logged into
            time: Logon timestamp
            logon_type: Windows logon type (2=interactive, 3=network, 10=remote interactive)
            source_ip: Source IP address for remote logons. Local logons render with no
                source address in Windows Security, but still use the host IP for DC-side
                authentication evidence when applicable.

        Returns:
            LogonID (hex string format, e.g., "0x3e7")
        """
        request = LogonRequest(
            user=user,
            system=system,
            time=time,
            logon_type=logon_type,
            source_ip=source_ip,
            source_system=source_system,
            source_port=source_port,
            emit_transport_syslog=emit_transport_syslog,
            emit_network_evidence=emit_network_evidence,
            logon_id=logon_id,
        )
        return LogonActionBundle(self, request).execute()

    def _execute_logon_bundle(self, request: LogonRequest) -> str:
        """Expand a successful logon bundle through the compatibility adapter."""
        user = request.user
        system = request.system
        time = request.time
        logon_type = request.logon_type
        source_ip = request.source_ip
        source_system = request.source_system
        source_port = request.source_port
        emit_transport_syslog = request.emit_transport_syslog
        emit_network_evidence = request.emit_network_evidence
        logon_id = request.logon_id

        self.state_manager.set_current_time(time)
        os_cat = _get_os_category(system.os)
        if logon_type == 10 and os_cat == "linux" and source_ip in (None, "", "-", system.ip):
            logon_type = 2
            source_ip = None
        if logon_type == 10 and os_cat == "windows" and source_ip in (None, "", "-", system.ip):
            logon_type = 2
            source_ip = None
        if (
            logon_type == 3
            and os_cat == "windows"
            and source_ip in (None, "", "-")
            and getattr(self, "_all_system_ips", [])
        ):
            is_service_account = user.username.endswith("$") or user.username.lower().startswith(
                "svc"
            )
            source_ip = self._baseline_type3_source_ip(
                user,
                system,
                _get_rng(),
                is_service_account=is_service_account,
            )
            if source_ip is None:
                logon_type = 2
        if logon_id is None and os_cat == "windows" and logon_type in (2, 11):
            existing_interactive = self._active_user_workstation_windows_session(
                user,
                system,
                time,
            )
            if existing_interactive is not None:
                existing_interactive.last_activity_time = time
                return existing_interactive.logon_id
        if (
            logon_id is None
            and os_cat == "linux"
            and logon_type in _LINUX_LOCAL_SESSION_LOGON_TYPES
            and source_ip in (None, "", "-", system.ip)
        ):
            existing_interactive = self._active_user_local_linux_session(
                user,
                system,
                time,
            )
            if existing_interactive is not None:
                existing_interactive.last_activity_time = time
                return existing_interactive.logon_id
        local_logon = logon_type in (2, 5, 7, 11)
        dc_source_ip = source_ip or system.ip
        if source_ip is None:
            source_ip = "-" if local_logon else system.ip
        auth_source_ip = "-" if local_logon else source_ip
        if not local_logon and source_port is None and source_ip and source_ip != "-":
            if logon_type == 3 and source_ip == system.ip:
                source_port = 0
            elif os_cat == "windows" and logon_type in (3, 10):
                source_port = self._allocate_ephemeral_port(
                    source_ip,
                    system.ip,
                    3389 if logon_type == 10 else 445,
                    "tcp",
                    time,
                    self._os_for_ip(source_ip),
                )
            else:
                source_port = _ephemeral_port(_get_rng(), self._os_for_ip(source_ip))

        # Linux type-10 remote logons are SSH, not RDP
        if logon_type == 10 and os_cat == "linux":
            session_kind = "ssh"
        else:
            session_kind = {
                3: "network",
                4: "batch",
                5: "service",
                10: "rdp",
            }.get(logon_type, "interactive")

        if (
            os_cat == "linux"
            and logon_type == 10
            and source_ip
            and source_ip not in {"-", system.ip}
        ):
            if logon_id is None:
                logon_id = self.state_manager.create_session(
                    username=user.username,
                    system=system.hostname,
                    logon_type=logon_type,
                    source_ip=auth_source_ip,
                    source_port=source_port or 0,
                    session_kind="ssh",
                )
            else:
                existing_session = self.state_manager.get_session(logon_id)
                if existing_session is None:
                    self.state_manager.register_session(
                        logon_id=logon_id,
                        username=user.username,
                        system=system.hostname,
                        logon_type=logon_type,
                        source_ip=auth_source_ip,
                        start_time=time,
                        source_port=source_port or 0,
                        session_kind="ssh",
                    )
                else:
                    self.state_manager.update_session_metadata(
                        logon_id,
                        source_ip=auth_source_ip,
                        source_port=source_port or 0,
                        session_kind="ssh",
                    )

            session_obj_id = self.state_manager.get_session_object_id(logon_id)
            source_system = (
                self._ip_to_system.get(source_ip) if hasattr(self, "_ip_to_system") else None
            )
            self.generate_ssh_session(
                user=user,
                target_system=system,
                time=time,
                source_ip=source_ip,
                source_system=source_system,
                source_port=source_port,
                logon_id=logon_id,
                session_obj_id=session_obj_id,
                source="linux_logon_compat",
            )
            session = self.state_manager.get_session(logon_id)
            if session is not None:
                session.last_activity_time = time
            logger.debug(
                "Generated Linux SSH logon via SSH bundle: %s on %s (LogonID: %s)",
                user.username,
                system.hostname,
                logon_id,
            )
            return logon_id

        # Select auth package (semantic data, not format-specific)
        auth_pkg = self._select_auth_package(logon_type)

        # Phase 1: Allocate or resolve IDs from StateManager
        if logon_id is None:
            logon_id = self.state_manager.create_session(
                username=user.username,
                system=system.hostname,
                logon_type=logon_type,
                source_ip=auth_source_ip,
                source_port=source_port or 0,
                session_kind=session_kind,
            )
        else:
            existing_session = self.state_manager.get_session(logon_id)
            if existing_session is None:
                self.state_manager.register_session(
                    logon_id=logon_id,
                    username=user.username,
                    system=system.hostname,
                    logon_type=logon_type,
                    source_ip=auth_source_ip,
                    start_time=time,
                    source_port=source_port or 0,
                    session_kind=session_kind,
                )
            else:
                self.state_manager.update_session_metadata(
                    logon_id,
                    source_ip=auth_source_ip,
                    source_port=source_port or 0,
                )
            if (
                existing_session is not None
                and logon_type != 7
                and existing_session.start_time < time
            ):
                time = existing_session.start_time
                self.state_manager.set_current_time(time)

        requires_logon_guid = auth_pkg.get("LogonGuid") != "{00000000-0000-0000-0000-000000000000}"
        auth_logon_guid = self.state_manager.get_or_create_session_logon_guid(
            logon_id,
            system.hostname,
            require_nonzero=requires_logon_guid,
        )
        session_for_guid = self.state_manager.get_session(logon_id)
        session_id = session_for_guid.session_id if session_for_guid is not None else 0
        if requires_logon_guid or not (session_for_guid and session_for_guid.logon_guid):
            self.state_manager.update_session_metadata(logon_id, logon_guid=auth_logon_guid)
        elevated = self._should_elevate(user, logon_type=logon_type, hostname=system.hostname)
        privilege_list = (
            self._select_special_privileges(user, logon_type, system.hostname) if elevated else ""
        )

        if os_cat == "linux" and logon_type in _LINUX_LOCAL_SESSION_LOGON_TYPES:
            self._emit_linux_local_logon_syslog(user, system, time, logon_id)
            session_for_guid = self.state_manager.get_session(logon_id)
            session_id = session_for_guid.session_id if session_for_guid is not None else 0

        # Phase 2: Build SecurityEvent with all contexts
        # For network logons (type 3, 10), resolve source host from source_ip
        src_host_ctx = None
        if logon_type in (3, 10) and source_ip and source_ip != "-":
            if source_system is not None:
                src_host_ctx = self._build_host_context(source_system)
            elif hasattr(self, "_ip_to_system") and source_ip in self._ip_to_system:
                src_host_ctx = self._build_host_context(self._ip_to_system[source_ip])

        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        session_actor_id = ""
        if logon_type == 7:
            # Type 7 is a workstation unlock re-auth against an existing LUID.
            # eCAR object lifecycles should still be single-login, so model the
            # re-auth as a child observation linked to the durable session.
            session_actor_id = session_obj_id
            session_obj_id = stable_uuid(
                "ecar-unlock-reauth",
                system.hostname,
                logon_id,
                time.isoformat(),
            )
        subject = self._successful_logon_subject_fields(
            user=user,
            system=system,
            logon_type=logon_type,
            time=time,
            source_ip=auth_source_ip,
            source_system=source_system,
            logon_id=logon_id,
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            src_host=src_host_ctx,
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                session_id=session_id,
                logon_type=logon_type,
                auth_package=auth_pkg.get("AuthenticationPackageName", "Negotiate"),
                source_ip=auth_source_ip,
                source_port=source_port or 0,
                elevated=elevated,
                logon_process=auth_pkg.get("LogonProcessName", ""),
                lm_package=auth_pkg.get("LmPackageName", "-"),
                logon_guid=auth_logon_guid,
                subject_sid=subject["sid"],
                subject_username=subject["username"],
                subject_domain=subject["domain"],
                subject_logon_id=subject["logon_id"],
                privilege_list=privilege_list,
                reporting_pid=self._get_system_pid(system.hostname, "lsass", 0x2E0),
            ),
            edr=EdrContext(object_id=session_obj_id, actor_id=session_actor_id),
        )

        # Attach SyslogContext for Linux SSH sessions only (not network/interactive)
        session_for_syslog = self.state_manager.get_session(logon_id) if logon_id else None
        is_ssh_session = (
            session_for_syslog and getattr(session_for_syslog, "session_kind", None) == "ssh"
        ) or logon_type == 10  # logon_type 10 = remote (SSH on Linux)
        if (
            event.dst_host
            and event.dst_host.os_category == "linux"
            and emit_transport_syslog
            and is_ssh_session
            and auth_source_ip not in {"", "-", system.ip}
        ):
            from evidenceforge.events.contexts import SyslogContext

            session = self.state_manager.get_session(logon_id)
            effective_source_port = source_port or (session.source_port if session else 0)
            sshd_pid = (
                session.transport_pid
                if session and session.transport_pid is not None
                else self.state_manager.allocate_transient_linux_pid(
                    system.hostname, time, os_category=_get_os_category(system.os)
                )
            )
            self.state_manager.update_session_metadata(
                logon_id,
                source_port=effective_source_port,
                transport_pid=sshd_pid,
            )
            event.syslog = SyslogContext(
                app_name="sshd",
                pid=sshd_pid,
                facility=10,
                severity=6,
                message=(
                    f"Accepted password for {user.username} from {auth_source_ip} "
                    f"port {effective_source_port or _ephemeral_port(_get_rng(), 'linux')} ssh2"
                ),
            )

        # Emit DC-side Kerberos events for domain logons via causal expansion.
        # The target-host 4624 renderer owns 4672 for elevated sessions because
        # that privilege assignment belongs to the host where the logon session
        # is created, not to the DC ticket request itself.
        auth_package_name = auth_pkg.get("AuthenticationPackageName", "Negotiate")
        self._expand_and_emit(
            "logon",
            time,
            actor=user,
            target_system=system,
            auth_package=auth_package_name,
            src_ip=dc_source_ip,
            os_category=_get_os_category(system.os),
        )
        if (
            auth_package_name == "NTLM"
            and logon_type in (3, 10)
            and _get_os_category(system.os) == "windows"
            and source_ip
            and source_ip != "-"
        ):
            self._emit_dc_ntlm_for_logon(user, system, time, source_ip)

        if emit_network_evidence:
            self._maybe_emit_remote_logon_network_connection(
                system=system,
                time=time,
                logon_type=logon_type,
                source_ip=source_ip,
                source_port=source_port or 0,
                auth_package=auth_package_name,
            )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        # Phase 4: Create per-session explorer.exe for interactive logons
        if logon_type in (2, 10, 11):
            session = self.state_manager.get_session(logon_id)
            if session is not None:
                os_cat = _get_os_category(system.os)
                if os_cat == "windows":
                    sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
                    parent_for_chain = None
                    for candidate in ("smss", "wininit", "winlogon", "services"):
                        pid = sys_pids.get(candidate)
                        if pid and self.state_manager.get_process(system.hostname, pid):
                            parent_for_chain = pid
                            break
                    if parent_for_chain is not None:
                        winlogon_pid = self.state_manager.create_process(
                            system.hostname,
                            parent_for_chain,
                            r"C:\Windows\System32\winlogon.exe",
                            "winlogon.exe",
                            "SYSTEM",
                            "System",
                            logon_id=logon_id,
                        )
                        session.session_winlogon_pid = winlogon_pid
                        userinit_pid = self.state_manager.create_process(
                            system.hostname,
                            winlogon_pid,
                            r"C:\Windows\System32\userinit.exe",
                            "userinit.exe",
                            user.username,
                            "Medium",
                            logon_id=logon_id,
                        )
                        explorer_pid = self.state_manager.create_process(
                            system.hostname,
                            userinit_pid,
                            r"C:\Windows\explorer.exe",
                            "explorer.exe",
                            user.username,
                            "Medium",
                            logon_id=logon_id,
                        )
                        session.explorer_pid = explorer_pid
                        session.process_tree_root = winlogon_pid
                session.last_activity_time = time

        logger.debug(f"Generated logon: {user.username} on {system.hostname} (LogonID: {logon_id})")
        return logon_id

    def _emit_linux_local_logon_syslog(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> None:
        """Emit logind open evidence for a durable local Linux session."""
        if (
            self.dispatcher is None
            or "syslog" not in self.dispatcher.emitters
            or logon_id in self._linux_local_logon_syslog_sessions
        ):
            return
        if _get_os_category(system.os) != "linux":
            return
        session = self.state_manager.get_session(logon_id)
        if (
            session is None
            or session.logon_type not in _LINUX_LOCAL_SESSION_LOGON_TYPES
            or session.session_kind in _LINUX_REMOTE_SESSION_KINDS
        ):
            return

        rng = random.Random(
            _stable_seed(f"linux_local_logon_syslog:{system.hostname}:{user.username}:{logon_id}")
        )
        logind_time = time - timedelta(milliseconds=rng.randint(20, 80))
        session_id = self.state_manager.next_linux_logind_session_id(
            system.hostname,
            rng,
            logind_time,
        )
        self._linux_local_logind_session_ids[logon_id] = session_id
        self.state_manager.update_session_metadata(logon_id, session_id=session_id)
        self.generate_syslog_event(
            system=system,
            time=logind_time,
            app_name="systemd-logind",
            message=f"New session {session_id} of user {user.username}.",
            pid=self._get_system_pid(system.hostname, "logind", 456),
            facility=10,
        )
        self._linux_local_logon_syslog_sessions.add(logon_id)

    def _emit_dc_ntlm_for_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        source_ip: str,
    ) -> None:
        """Emit DC-side 4776 validation for successful domain NTLM logons."""
        if _get_os_category(system.os) != "windows":
            return

        dc_hostnames = getattr(self, "_dc_hostnames", [])
        dc_ips = getattr(self, "_dc_ips", [])
        if not dc_hostnames:
            return
        if system.hostname in dc_hostnames or system.ip in dc_ips:
            return

        rng = _get_rng()
        dc_hostname = dc_hostnames[rng.randint(0, len(dc_hostnames) - 1)]
        workstation = self._workstation_name_for_source(source_ip)
        self.generate_ntlm_validation(
            username=user.username,
            workstation=workstation,
            dc_hostname=dc_hostname,
            time=time - timedelta(milliseconds=rng.randint(8, 120)),
            status="0x0",
        )

    def _emit_dc_kerberos_for_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        auth_package: str,
        source_ip: str,
    ) -> None:
        """Emit DC-side Kerberos evidence for a domain logon via an action bundle."""
        request = KerberosLogonTicketsRequest(
            user=user,
            system=system,
            time=time,
            auth_package=auth_package,
            source_ip=source_ip,
        )
        KerberosLogonTicketsActionBundle(self, request).execute()

    def _execute_kerberos_logon_tickets_bundle(
        self,
        request: KerberosLogonTicketsRequest,
    ) -> None:
        """Emit DC-side Kerberos TGT (4768) and service ticket (4769) for domain logons.

        In a real AD environment, when a user authenticates via Kerberos:
        1. Client requests TGT from DC (4768) ~50-200ms before logon
        2. Client requests service ticket for target host (4769) ~20-100ms after TGT
        3. Target host logs the 4624

        Only emits when:
        - Auth package is Kerberos (not NTLM)
        - Target system is Windows
        - System is not the DC itself
        - A DC is known in the scenario
        """
        user = request.user
        system = request.system
        time = request.time
        auth_package = request.auth_package
        source_ip = request.source_ip

        # Only emit for explicit Kerberos auth on Windows systems.
        # "Negotiate" can fall back to NTLM, and CredSSP (RDP) uses its own
        # auth flow — only pure "Kerberos" auth triggers DC-side TGT/TGS.
        if auth_package != "Kerberos":
            return

        os_cat = _get_os_category(system.os)
        if os_cat != "windows":
            return

        dc_hostnames = getattr(self, "_dc_hostnames", [])
        dc_ips = getattr(self, "_dc_ips", [])
        if not dc_hostnames:
            return

        # Don't emit Kerberos events when logging onto the DC itself
        if system.hostname in dc_hostnames or system.ip in dc_ips:
            return

        rng = _get_rng()
        dc_idx = rng.randint(0, len(dc_hostnames) - 1)
        dc_hostname = dc_hostnames[dc_idx]

        # TGT and service ticket requests both precede the target-host 4624.
        # Keep TGT before TGS, and TGS before member-host logon.
        tgt_time, tgs_time = self._kerberos_ticket_times(
            time,
            rng,
            tgs_before_ms=(20, 100),
            tgt_before_tgs_ms=(35, 240),
        )
        self._maybe_generate_kerberos_tgt(
            username=user.username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgt_time,
            rng=rng,
        )

        role_names = {str(role).lower() for role in (getattr(system, "roles", []) or [])}
        service_names = {
            str(service).lower() for service in (getattr(system, "services", []) or [])
        }
        hostname_lower = system.hostname.lower()
        if "file_server" in role_names or "file" in hostname_lower or "smb" in service_names:
            service_dist = (
                ("cifs/{hostname}", 70),
                ("host/{hostname}", 25),
                ("ldap/{hostname}", 5),
            )
        elif "web_server" in role_names or any("http" in service for service in service_names):
            service_dist = (
                ("http/{hostname}", 65),
                ("host/{hostname}", 30),
                ("cifs/{hostname}", 5),
            )
        elif "dns_server" in role_names or "dns" in service_names:
            service_dist = (
                ("DNS/{hostname}", 55),
                ("host/{hostname}", 35),
                ("cifs/{hostname}", 10),
            )
        else:
            service_dist = (
                ("cifs/{hostname}", 45),
                ("host/{hostname}", 35),
                ("ldap/{hostname}", 10),
                ("http/{hostname}", 5),
                ("DNS/{hostname}", 5),
            )
        _svc_template = rng.choices(
            [entry[0] for entry in service_dist],
            weights=[entry[1] for entry in service_dist],
            k=1,
        )[0]
        service_name = _svc_template.format(
            hostname=system.hostname, domain=getattr(self, "_ad_domain", "CORP.LOCAL")
        )
        self.generate_kerberos_service_ticket(
            username=user.username,
            service_name=service_name,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgs_time,
        )

    def generate_failed_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_type: int = 2,
        source_ip: str | None = None,
        target_username: str | None = None,
        dc_system: "System | None" = None,
    ) -> None:
        """Generate a failed logon event.

        Does NOT create a session in StateManager. Builds a SecurityEvent with
        result="failure" and dispatches to matching emitters (Windows 4625,
        syslog "Failed password", eCAR LOGIN with failure_reason).

        When dc_system is provided, also emits DC-side credential validation evidence
        such as 4776 and 4771. The target host owns 4625; cloning it onto the DC would
        make two machines claim the same local failed logon.

        Args:
            user: User attempting to log on (or performing the test)
            system: Target system
            time: Attempt timestamp
            logon_type: Logon type attempted
            source_ip: Source IP for remote attempts. Local failed logons render with no
                source address in Windows Security.
            target_username: If set, the logon targets this user instead of the actor
            dc_system: Domain controller to also emit 4625/4776 on (optional)
        """
        request = FailedLogonRequest(
            user=user,
            system=system,
            time=time,
            logon_type=logon_type,
            source_ip=source_ip,
            target_username=target_username,
            dc_system=dc_system,
        )
        FailedLogonActionBundle(self, request).execute()

    def _execute_failed_logon_bundle(self, request: FailedLogonRequest) -> None:
        """Expand a failed-logon bundle through the compatibility adapter."""
        user = request.user
        system = request.system
        time = request.time
        logon_type = request.logon_type
        source_ip = request.source_ip
        target_username = request.target_username
        dc_system = request.dc_system

        local_logon = logon_type in (2, 5, 7, 11)
        if source_ip == system.ip:
            source_ip = None
            local_logon = True
        if source_ip is None:
            source_ip = "-" if local_logon else system.ip
        auth_source_ip = "-" if local_logon else source_ip

        # Use target_username if provided, otherwise use the actor's username
        effective_username = target_username or user.username

        # Determine failure substatus with source-native account-state semantics.
        # Ordinary known/enabled accounts should fail as bad passwords; locked
        # or disabled states require an explicit account-state model so they do
        # not contradict later successful logons.
        rng = _get_rng()
        known_account = self._is_known_failed_logon_account(effective_username, user)
        failed_profile = self._failed_logon_profile(logon_type, system, source_ip, rng)
        validation_path = self._failed_logon_validation_path(logon_type, failed_profile, rng)
        if self._is_disabled_failed_logon_account(effective_username, user):
            substatus = "0xc0000072"  # Account disabled
            user_sid = self._get_sid(effective_username)
            failure_reason = "%%2307"
        elif not known_account:
            substatus = "0xc0000064"  # User not found: NULL SID
            user_sid = "S-1-0-0"
            failure_reason = "%%2313"
        else:
            substatus = "0xc000006a"  # Wrong password
            user_sid = self._get_sid(effective_username)
            failure_reason = "%%2313"

        remote_linux_source = (
            _get_os_category(system.os) == "linux"
            and source_ip not in (None, "-")
            and source_ip != system.ip
        )
        linux_ssh_source_port = None
        linux_ssh_responder_pid: int | None = None
        if remote_linux_source and source_ip is not None:
            linux_ssh_source_port = self._allocate_ephemeral_port(
                source_ip,
                system.ip,
                22,
                "tcp",
                time,
                self._os_for_ip(source_ip),
            )
            linux_ssh_responder_pid = self.ensure_linux_ssh_responder_process(
                target_system=system,
                time=time - timedelta(milliseconds=250),
                source_ip=source_ip,
                source_port=linux_ssh_source_port,
                target_user=effective_username if known_account else None,
            )

        event = SecurityEvent(
            timestamp=time,
            event_type="failed_logon",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=effective_username,
                user_sid=user_sid,
                logon_type=logon_type,
                result="failure",
                failure_reason=failure_reason,
                failure_status="0xc000006d",
                failure_substatus=substatus,
                source_ip=(
                    source_ip if remote_linux_source and source_ip is not None else auth_source_ip
                ),
                source_port=linux_ssh_source_port or failed_profile["source_port"],
                auth_package=failed_profile["auth_package"],
                logon_process=failed_profile["logon_process"],
                lm_package=failed_profile["lm_package"],
                process_pid=failed_profile["process_pid"],
                process_name=failed_profile["process_name"],
                workstation_name=failed_profile["workstation_name"],
                subject_sid="S-1-0-0",
                subject_username="-",
                subject_domain="-",
                subject_logon_id="0x0",
            ),
            edr=EdrContext(
                object_id=stable_uuid(
                    "failed-logon-edr",
                    system.hostname,
                    effective_username,
                    time.isoformat(),
                    source_ip,
                    linux_ssh_source_port or failed_profile["source_port"],
                )
            ),
        )

        # Attach SyslogContext for Linux hosts (sshd failed logon)
        if event.dst_host and event.dst_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            if source_ip and source_ip != "-":
                ssh_source_port = linux_ssh_source_port or _ephemeral_port(_get_rng(), "linux")
                event.syslog = SyslogContext(
                    app_name="sshd",
                    pid=linux_ssh_responder_pid
                    or self.state_manager.allocate_transient_linux_pid(
                        system.hostname, time, os_category=_get_os_category(system.os)
                    ),
                    facility=10,
                    severity=4,
                    message=(
                        f"Failed password for {effective_username} from {source_ip} "
                        f"port {ssh_source_port} ssh2"
                    ),
                )
            else:
                event.syslog = SyslogContext(
                    app_name="login",
                    pid=self.state_manager.allocate_transient_linux_pid(
                        system.hostname, time, os_category=_get_os_category(system.os)
                    ),
                    facility=10,
                    severity=4,
                    message=(
                        "pam_unix(login:auth): authentication failure; "
                        f"logname=LOGIN uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  "
                        f"user={effective_username}"
                    ),
                )

        if remote_linux_source and source_ip is not None and linux_ssh_source_port is not None:
            self._emit_failed_linux_ssh_network_connection(
                system=system,
                time=time,
                source_ip=source_ip,
                source_port=linux_ssh_source_port,
                responding_pid=linux_ssh_responder_pid,
                rng=rng,
            )

        self.dispatcher.dispatch(event)

        # Domain controller side: validation evidence only. The failed local logon
        # (4625) belongs to the target workstation/server, not the DC.
        if dc_system and dc_system.hostname != system.hostname:
            # 4776 NTLM credential validation on DC
            if validation_path.get("emit_4776", True):
                ntlm_delay_ms = rng.randint(3, 85)
                self.generate_ntlm_validation(
                    username=effective_username,
                    workstation=system.hostname,
                    dc_hostname=dc_system.hostname,
                    time=time + timedelta(milliseconds=ntlm_delay_ms),
                    status=substatus,
                )

            # 4771 Kerberos pre-authentication failure on DC
            # In real AD, Kerberos is tried first; 4771 fires before 4625/4776
            # for wrong-password failures.
            if validation_path.get("emit_4771", False) and substatus == "0xc000006a":
                krb_time = time - timedelta(milliseconds=rng.randint(40, 350))
                self.generate_kerberos_preauth_failed(
                    username=effective_username,
                    source_ip=source_ip,
                    dc_hostname=dc_system.hostname,
                    time=krb_time,
                    status="0x18",  # KDC_ERR_PREAUTH_FAILED
                    emit_connection=True,
                )

        self._maybe_emit_failed_logon_network_connection(
            system=system,
            time=time,
            logon_type=logon_type,
            source_ip=source_ip,
            profile=failed_profile,
            rng=rng,
        )

        logger.debug(f"Generated failed logon: {user.username} on {system.hostname}")

    def _account_subject_fields(
        self,
        username: str,
        system: System,
        logon_id: str | None = None,
    ) -> dict[str, str]:
        """Return coherent Windows subject identity fields for an account."""
        if username in _SYSTEM_ACCOUNT_SIDS:
            return {
                "sid": _SYSTEM_ACCOUNT_SIDS[username],
                "username": username,
                "domain": "NT AUTHORITY",
                "logon_id": logon_id or _SYSTEM_ACCOUNT_LOGON_IDS[username],
            }
        return {
            "sid": self._get_sid(username),
            "username": username,
            "domain": self._build_host_context(system).netbios_domain,
            "logon_id": logon_id or self._get_user_logon_id(username, system.hostname),
        }

    def _successful_logon_subject_fields(
        self,
        *,
        user: User,
        system: System,
        logon_type: int,
        time: datetime,
        source_ip: str,
        logon_id: str,
        source_system: System | None = None,
    ) -> dict[str, str]:
        """Return source-native Windows 4624 subject fields for successful logons."""
        system_subject = self._account_subject_fields("SYSTEM", system, logon_id="0x3e7")
        if _get_os_category(system.os) != "windows":
            return system_subject

        username = user.username
        if username in _SYSTEM_ACCOUNT_LOGON_IDS or username.endswith("$") or logon_type == 5:
            return system_subject

        if logon_type == 7:
            session = self.state_manager.get_session(logon_id)
            if (
                session is not None
                and session.system == system.hostname
                and session.username == username
            ):
                return self._account_subject_fields(username, system, logon_id=session.logon_id)
            active = self._active_user_interactive_windows_session(user, system, time)
            if active is not None:
                return self._account_subject_fields(username, system, logon_id=active.logon_id)
            return system_subject

        if logon_type in {3, 10}:
            return system_subject
        return system_subject

    def _failed_logon_profile(
        self,
        logon_type: int,
        system: System,
        source_ip: str,
        rng: random.Random,
    ) -> dict[str, Any]:
        """Return source-native Windows 4625 field values for a failed logon."""
        config = failed_logon_config()
        if logon_type in (2, 7, 11):
            local = config.get("local_interactive", {})
            process_name = str(local.get("process_name") or r"C:\Windows\System32\winlogon.exe")
            winlogon_pid = self._get_system_pid(system.hostname, "winlogon", 0)
            return {
                "auth_package": str(local.get("authentication_package_name") or "Negotiate"),
                "logon_process": str(local.get("logon_process_name") or "User32"),
                "lm_package": "-",
                "process_pid": winlogon_pid,
                "process_name": process_name,
                "workstation_name": system.hostname,
                "source_port": 0,
                "network_port": 0,
                "emit_network_probability": 0.0,
            }

        network = config.get("network", {})
        process_profiles = [
            value
            for value in (network.get("logon_process_weights") or {}).values()
            if isinstance(value, dict) and int(value.get("weight", 0)) > 0
        ]
        if process_profiles:
            weights = [int(profile.get("weight", 1)) for profile in process_profiles]
            selected = rng.choices(process_profiles, weights=weights, k=1)[0]
        else:
            selected = {
                "authentication_package_name": "NTLM",
                "logon_process_name": "NtLmSsp",
                "lm_package_name": "NTLM V2",
            }
        ports = [
            value
            for value in (network.get("network_ports") or {}).values()
            if isinstance(value, dict) and int(value.get("weight", 0)) > 0
        ]
        if ports:
            port_weights = [int(port.get("weight", 1)) for port in ports]
            network_port = int(rng.choices(ports, weights=port_weights, k=1)[0].get("port", 445))
        else:
            network_port = 445
        return {
            "auth_package": str(selected.get("authentication_package_name") or "NTLM"),
            "logon_process": str(selected.get("logon_process_name") or "NtLmSsp"),
            "lm_package": str(selected.get("lm_package_name") or "-"),
            "process_pid": self._get_system_pid(system.hostname, "lsass", 0x2E0),
            "process_name": r"C:\Windows\System32\lsass.exe",
            "workstation_name": self._workstation_name_for_source(source_ip),
            "source_port": _ephemeral_port(rng, self._os_for_ip(source_ip)),
            "network_port": network_port,
            "emit_network_probability": float(
                network.get("emit_network_connection_probability", 1.0)
            ),
        }

    @staticmethod
    def _failed_logon_validation_path(
        logon_type: int,
        profile: dict[str, Any],
        rng: random.Random,
    ) -> dict[str, bool]:
        """Choose which DC-side failed-auth validation evidence to emit."""
        if logon_type in (2, 5, 7, 11):
            return {"emit_4776": False, "emit_4771": False}
        config = failed_logon_config().get("network", {})
        paths = [
            value
            for value in (config.get("validation_path_weights") or {}).values()
            if isinstance(value, dict) and int(value.get("weight", 0)) > 0
        ]
        if paths:
            weights = [int(path.get("weight", 1)) for path in paths]
            selected = rng.choices(paths, weights=weights, k=1)[0]
            return {
                "emit_4776": bool(selected.get("emit_4776", False)),
                "emit_4771": bool(selected.get("emit_4771", False)),
            }
        auth_package = str(profile.get("auth_package") or "NTLM")
        return {
            "emit_4776": auth_package in ("NTLM", "Negotiate"),
            "emit_4771": auth_package in ("Kerberos", "Negotiate"),
        }

    @staticmethod
    def _workstation_name_for_source(source_ip: str) -> str:
        """Return a plausible WorkstationName for a failed network logon source."""
        if not source_ip or source_ip == "-":
            return "-"
        rdns = REVERSE_DNS.get(source_ip, "")
        if rdns:
            return rdns.split(".", 1)[0].upper()
        return source_ip

    def _emit_failed_linux_ssh_network_connection(
        self,
        system: System,
        time: datetime,
        source_ip: str,
        source_port: int,
        responding_pid: int | None,
        rng: random.Random,
    ) -> None:
        """Emit source-matched Zeek SSH evidence for a failed Linux sshd logon."""
        conn_time = time - timedelta(milliseconds=rng.randint(35, 450))
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=system.ip,
            time=conn_time,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=rng.uniform(0.12, 3.5),
            orig_bytes=rng.randint(260, 1800),
            resp_bytes=rng.randint(240, 2600),
            src_port=source_port,
            conn_state=rng.choices(["SF", "RSTR"], weights=[78, 22], k=1)[0],
            responding_pid=responding_pid or -1,
        )

    def _maybe_emit_failed_logon_network_connection(
        self,
        system: System,
        time: datetime,
        logon_type: int,
        source_ip: str,
        profile: dict[str, Any],
        rng: random.Random,
    ) -> None:
        """Emit visible network evidence for remote failed-auth attempts when appropriate."""
        if logon_type != 3 or not source_ip or source_ip == "-":
            return
        if _get_os_category(system.os) != "windows":
            return
        probability = float(profile.get("emit_network_probability", 0.0))
        if probability <= 0 or rng.random() > probability:
            return
        dst_port = int(profile.get("network_port", 445))
        service = "smb" if dst_port == 445 else "rdp" if dst_port == 3389 else None
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=system.ip,
            time=time - timedelta(milliseconds=rng.randint(20, 250)),
            dst_port=dst_port,
            proto="tcp",
            service=service,
            duration=rng.uniform(0.02, 1.5),
            orig_bytes=rng.randint(120, 900),
            resp_bytes=rng.randint(0, 500),
            src_port=int(
                profile.get("source_port") or _ephemeral_port(rng, self._os_for_ip(source_ip))
            ),
            conn_state=rng.choices(["SF", "RSTR"], weights=[70, 30], k=1)[0],
        )

    def _is_known_failed_logon_account(self, username: str, actor: User) -> bool:
        """Return whether a failed-logon target is a known account in this scenario."""
        normalized = username.split("@", 1)[0].lower()
        if normalized == actor.username.lower():
            return True
        if actor.email and username.lower() == actor.email.lower():
            return True
        if username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"} or username.endswith("$"):
            return True
        if username in getattr(self, "sid_registry", {}):
            return True
        return False

    @staticmethod
    def _is_disabled_failed_logon_account(username: str, actor: User) -> bool:
        """Return whether this failed-logon target is explicitly disabled."""
        if actor.enabled:
            return False
        normalized = username.split("@", 1)[0].lower()
        if normalized == actor.username.lower():
            return True
        return bool(actor.email and username.lower() == actor.email.lower())

    def generate_logoff(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        logon_type: int = 2,
        from_storyline: bool = False,
    ) -> None:
        """Generate logoff event across all applicable log formats.

        Ends session in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4634, syslog session closed, eCAR LOGOUT).

        Args:
            user: User logging off
            system: System being logged off from
            time: Logoff timestamp
            logon_id: LogonID from the logon event
            logon_type: Logon type for the session being ended
            from_storyline: When True, skip min_logoff_time clamping so the
                storyline-scheduled time is preserved unless an SSH transport
                close bounds the session lifecycle.
        """
        request = LogoffRequest(
            user=user,
            system=system,
            time=time,
            logon_id=logon_id,
            logon_type=logon_type,
            from_storyline=from_storyline,
        )
        LogoffActionBundle(self, request).execute()

    def _execute_logoff_bundle(self, request: LogoffRequest) -> None:
        """Expand a logoff bundle through the compatibility adapter."""
        user = request.user
        system = request.system
        time = request.time
        logon_id = request.logon_id
        logon_type = request.logon_type
        from_storyline = request.from_storyline

        # Terminate session-specific processes before ending session
        session = self.state_manager.get_session(logon_id)
        is_ssh_session = session and (
            session.session_kind == "ssh"
            or (_get_os_category(system.os) == "linux" and logon_type == 10)
        )
        if session:
            logon_type = session.logon_type
            ssh_transport_close_time = (
                ensure_utc(session.network_close_time)
                if is_ssh_session and session.network_close_time is not None
                else None
            )
            if (
                ssh_transport_close_time is not None
                and ensure_utc(time) >= ssh_transport_close_time
            ):
                transport_logoff_time = ssh_transport_close_time + sample_timing_delta(
                    "windows.logoff_after_last_activity",
                    seed_parts=(system.hostname, logon_id, ssh_transport_close_time),
                )
                time = transport_logoff_time
            raw_session_end_markers = (
                session.last_activity_time,
                session.network_close_time,
            )
            session_end_markers = [
                marker
                for marker in raw_session_end_markers
                if marker is not None
                and (
                    ssh_transport_close_time is None
                    or ensure_utc(marker) <= ssh_transport_close_time
                )
            ]
            session_end_markers.extend(
                marker
                for proc in self.state_manager.list_running_processes()
                if proc.system == system.hostname and proc.logon_id == logon_id
                for marker in (proc.last_activity_time or proc.start_time,)
                if marker is not None
                and (
                    ssh_transport_close_time is None
                    or ensure_utc(marker) <= ssh_transport_close_time
                )
            )
            if session_end_markers and not from_storyline:
                # Source emitters add small native delays (for example Sysmon
                # Event 1 after canonical process creation). Leave enough room
                # that final logoff/logout records do not render before those
                # same-session dependents in another source.
                latest_session_marker = max(session_end_markers)
                min_logoff_time = latest_session_marker + sample_timing_delta(
                    "windows.logoff_after_last_activity",
                    seed_parts=(system.hostname, logon_id, latest_session_marker),
                )
                if time <= min_logoff_time:
                    time = min_logoff_time
            if (
                _get_os_category(system.os) == "linux"
                and session.session_kind not in {"network", "service"}
                and session.logon_type not in {3, 5}
            ):
                self._linux_shell_last_session_close[(system.hostname, user.username)] = ensure_utc(
                    time
                )
            if session.explorer_pid is not None:
                self.state_manager.end_process(session.system, session.explorer_pid)
            # Clean up per-RDP-session winlogon chain
            if session.session_winlogon_pid is not None:
                self.state_manager.end_process(session.system, session.session_winlogon_pid)
            # Clean up per-SSH-session bash
            if session.session_shell_pid is not None:
                self.state_manager.end_process(session.system, session.session_shell_pid)

        # Build SecurityEvent (StateManager.apply() handles end_session)
        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        session_source_ip = session.source_ip if session is not None else ""
        session_source_port = session.source_port if session is not None else 0
        session_id = (
            session.session_id if session is not None else self._session_id_for_logon(logon_id)
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="logoff",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                session_id=session_id,
                logon_type=logon_type,
                source_ip=session_source_ip,
                source_port=session_source_port,
            ),
            edr=EdrContext(object_id=session_obj_id),
            storyline_origin=from_storyline,
        )

        # Attach SyslogContext for Linux SSH sessions only (sshd session closed).
        # Non-SSH sessions (interactive, network) don't produce sshd evidence.
        if event.dst_host and event.dst_host.os_category == "linux" and is_ssh_session:
            from evidenceforge.events.contexts import SyslogContext

            transport_close_consistent = True
            if session is not None and session.network_close_time is not None:
                network_close_time = ensure_utc(session.network_close_time)
                logoff_time = ensure_utc(time)
                transport_close_consistent = logoff_time <= network_close_time + timedelta(
                    seconds=90
                )
            sshd_pid = (
                session.transport_pid
                if session and session.transport_pid is not None
                else self.state_manager.allocate_transient_linux_pid(
                    system.hostname, time, os_category=_get_os_category(system.os)
                )
            )
            source_port = session.source_port if session else 0
            if (
                not source_port
                or not session
                or session.source_ip == system.ip
                or not transport_close_consistent
            ):
                event.syslog = None
            else:
                event.syslog = SyslogContext(
                    app_name="sshd",
                    pid=sshd_pid,
                    facility=10,
                    severity=6,
                    message=f"pam_unix(sshd:session): session closed for user {user.username}",
                )

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)

        logger.debug(
            f"Generated logoff: {user.username} on {system.hostname} (LogonID: {logon_id})"
        )

    @staticmethod
    def _user_profile_directory(username: str) -> str:
        """Return the Windows profile directory for a process owner."""
        account = username.split("\\")[-1]
        if account in _SYSTEM_ACCOUNTS or account.endswith("$"):
            return r"C:\Windows\System32"
        return rf"C:\Users\{account}"

    def _derive_current_directory(
        self,
        system: System,
        username: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        logon_type: int = 2,
    ) -> str:
        """Derive a source-native process working directory for Sysmon Event 1."""
        if _get_os_category(system.os) != "windows":
            account = username.split("\\")[-1]
            return (
                "/root" if account in _SYSTEM_ACCOUNTS or account == "root" else f"/home/{account}"
            )

        image = process_name.replace("/", "\\")
        image_lower = image.lower()
        exe = image_lower.rsplit("\\", 1)[-1]
        profile_dir = self._user_profile_directory(username)
        system_dir = r"C:\Windows\System32"

        if username in _SYSTEM_ACCOUNTS or username.endswith("$"):
            return system_dir + "\\"
        if logon_type == 5:
            return system_dir + "\\"

        parent_image = (
            self._lookup_process_name(system.hostname, parent_pid, _get_os_category(system.os))
            or ""
        ).lower()
        parent_dir = parent_image.rsplit("\\", 1)[0] if "\\" in parent_image else ""

        if exe in {"winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrobat.exe"}:
            if '"' in command_line:
                for candidate in command_line.split('"')[1::2]:
                    if "\\" in candidate:
                        return candidate.rsplit("\\", 1)[0] + "\\"
            return profile_dir + "\\Documents\\"

        if exe in {"onedrive.exe", "teams.exe", "outlook.exe"}:
            return profile_dir + "\\"

        if exe in {
            "cargo.exe",
            "docker.exe",
            "git.exe",
            "kubectl.exe",
            "node.exe",
            "npm.cmd",
            "npm.exe",
            "ssh.exe",
        }:
            if exe == "ssh.exe":
                return profile_dir + "\\"
            repo_names = (
                "clinical-portal",
                "integration-api",
                "ops-automation",
                "platform-services",
                "security-tools",
            )
            repo = repo_names[
                _stable_seed(
                    f"windows_project_cwd:{system.hostname}:{username}:{process_name}:"
                    f"{command_line}"
                )
                % len(repo_names)
            ]
            return profile_dir + f"\\source\\repos\\{repo}\\"

        if exe in {"chrome.exe", "msedge.exe", "firefox.exe"}:
            install_dir = image.rsplit("\\", 1)[0] if "\\" in image else ""
            if parent_dir and parent_dir == install_dir.lower():
                return install_dir + "\\"
            return profile_dir + "\\"

        if exe in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            if parent_dir and "windows\\system32" not in parent_dir:
                return parent_dir + "\\"
            return profile_dir + "\\"

        if "\\windows\\system32\\" in image_lower or "\\windows\\syswow64\\" in image_lower:
            return system_dir + "\\"

        if "\\" in image:
            return image.rsplit("\\", 1)[0] + "\\"

        return profile_dir + "\\"

    def _space_one_shot_cli_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Avoid machine-impossible bursts of repeated one-shot admin commands."""
        if _get_os_category(system.os) != "windows":
            return time

        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in _WINDOWS_ONE_SHOT_CLI_EXES:
            return time

        normalized_command = " ".join(command_line.lower().split())
        exe_key = (system.hostname, username, logon_id, exe_name)
        command_key = (*exe_key, normalized_command)
        adjusted_time = time

        command_last = self._last_one_shot_cli_launch_by_command.get(command_key)
        if command_last is not None:
            min_gap = timedelta(
                seconds=random.Random(
                    _stable_seed(
                        f"one_shot_cli_same_command:{system.hostname}:{username}:"
                        f"{exe_name}:{normalized_command}:{command_last.isoformat()}"
                    )
                ).uniform(18.0, 75.0)
            )
            if adjusted_time < command_last + min_gap:
                adjusted_time = command_last + min_gap

        exe_last = self._last_one_shot_cli_launch_by_exe.get(exe_key)
        if exe_last is not None:
            min_gap = timedelta(
                seconds=random.Random(
                    _stable_seed(
                        f"one_shot_cli_same_exe:{system.hostname}:{username}:"
                        f"{exe_name}:{exe_last.isoformat()}"
                    )
                ).uniform(2.5, 9.0)
            )
            if adjusted_time < exe_last + min_gap:
                adjusted_time = exe_last + min_gap

        self._last_one_shot_cli_launch_by_exe[exe_key] = adjusted_time
        self._last_one_shot_cli_launch_by_command[command_key] = adjusted_time
        return adjusted_time

    @staticmethod
    def _is_top_level_browser_launch(process_name: str, command_line: str) -> bool:
        """Return whether a Windows browser command represents a user-facing process."""
        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in _WINDOWS_BROWSER_EXES:
            return False
        command = f" {command_line.lower()} "
        return not any(marker in command for marker in _WINDOWS_BROWSER_CHILD_MARKERS)

    def _existing_user_browser_pid(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> int | None:
        """Reuse an open browser instead of emitting repeated top-level launches."""
        if _get_os_category(system.os) != "windows":
            return None
        if not self._is_top_level_browser_launch(process_name, command_line):
            return None

        requested_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        preferred_key = (system.hostname, username, "")
        preferred_exe = self._preferred_browser_by_session.get(preferred_key)
        candidates: list[RunningProcess] = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            if proc.username != username:
                continue
            if not self._is_pid_active_at(system, proc.pid, time):
                continue
            proc_exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if proc_exe not in _WINDOWS_BROWSER_EXES:
                continue
            if not self._is_top_level_browser_launch(proc.image, proc.command_line):
                continue
            candidates.append(proc)

        if not candidates:
            self._preferred_browser_by_session[preferred_key] = requested_exe
            return None

        if preferred_exe:
            preferred = [proc for proc in candidates if proc.image.lower().endswith(preferred_exe)]
            if preferred:
                proc = max(preferred, key=lambda candidate: candidate.start_time)
                self.state_manager.update_process_activity_time(system.hostname, proc.pid, time)
                return proc.pid

        same_exe = [
            proc
            for proc in candidates
            if proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() == requested_exe
        ]
        chosen = max(same_exe or candidates, key=lambda candidate: candidate.start_time)
        self._preferred_browser_by_session[preferred_key] = (
            chosen.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        )
        self.state_manager.update_process_activity_time(system.hostname, chosen.pid, time)
        return chosen.pid

    def _process_effect_context(
        self,
        system: System,
        pid: int,
        process_name: str,
        command_line: str,
    ) -> tuple[str, str]:
        """Return the process identity that downstream effects should use."""
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None:
            return process_name, command_line
        return proc.image, proc.command_line

    def _foreground_process_expired_for_attribution(
        self,
        system: System,
        proc: Any,
        time: datetime,
    ) -> bool:
        """Return whether a foreground process is not active for new effects."""
        if proc is None or proc.start_time is None:
            return False
        if time < proc.start_time:
            return True
        lifetime = self._foreground_process_lifetime_for_attribution(system, proc)
        if lifetime is None:
            return False
        max_process_time = proc.start_time + timedelta(seconds=lifetime[1] + 5.0)
        return time > max_process_time

    def _foreground_process_lifetime_for_attribution(
        self,
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

    def _space_browser_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Avoid rendered bursts of repeated top-level browser process creates."""
        if _get_os_category(system.os) != "windows":
            return time
        if not self._is_top_level_browser_launch(process_name, command_line):
            return time

        key = (system.hostname, username, logon_id)
        previous = self._last_browser_launch_by_session.get(key)
        adjusted_time = time
        if previous is not None:
            rng = random.Random(
                _stable_seed(
                    f"browser_launch_gap:{system.hostname}:{username}:{logon_id}:"
                    f"{previous.isoformat()}"
                )
            )
            min_gap = timedelta(seconds=rng.uniform(4.0, 18.0))
            if adjusted_time < previous + min_gap:
                adjusted_time = previous + min_gap
        self._last_browser_launch_by_session[key] = adjusted_time
        return adjusted_time

    def generate_process(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        ensure_file_event: bool = False,
        from_storyline: bool = False,
        suppress_command_file_effect: bool = False,
        allow_existing_browser_reuse: bool = True,
        allow_browser_launch_spacing: bool = True,
        concurrency_group_id: str = "",
    ) -> int:
        """Generate process creation event across all applicable log formats.

        Creates process in StateManager, builds a SecurityEvent, and dispatches
        to matching emitters (Windows 4688, eCAR PROCESS/CREATE). Also emits
        probabilistic EDR file/module/registry events.

        When ensure_file_event=True, always emits at least one FILE/CREATE for
        the process image (useful for storyline processes where FILE visibility
        is important for hunting).

        Args:
            user: User creating the process
            system: System where process is created
            time: Process creation timestamp
            logon_id: LogonID of the user's session
            process_name: Full path to executable
            command_line: Command line string
            parent_pid: Parent process PID (default 4 = System)
            suppress_command_file_effect: Caller already owns command output file artifacts.
            allow_existing_browser_reuse: Reuse an already-open browser for repeated
                navigation requests. Parent-repair paths disable this when they need
                a concrete same-family browser parent for renderer/utility children.
            allow_browser_launch_spacing: Apply anti-burst spacing to top-level browser
                launches. Causal connection-owner processes disable this so process
                creation stays before the socket evidence they own.
            concurrency_group_id: Explicit same-shell concurrency group for true pipelines.

        Returns:
            PID of the new process
        """
        request = ProcessExecutionRequest(
            user=user,
            system=system,
            time=time,
            logon_id=logon_id,
            process_name=process_name,
            command_line=command_line,
            parent_pid=parent_pid,
            ensure_file_event=ensure_file_event,
            from_storyline=from_storyline,
            suppress_command_file_effect=suppress_command_file_effect,
            allow_existing_browser_reuse=allow_existing_browser_reuse,
            allow_browser_launch_spacing=allow_browser_launch_spacing,
            concurrency_group_id=concurrency_group_id,
        )
        return ProcessExecutionActionBundle(self, request).execute()

    def _execute_process_create_bundle(self, request: ProcessExecutionRequest) -> int:
        """Expand a process-execution bundle through the compatibility adapter."""
        from evidenceforge.events.contexts import ProcessContext

        user = request.user
        system = request.system
        time = request.time
        logon_id = request.logon_id
        process_name = request.process_name
        command_line = request.command_line
        parent_pid = request.parent_pid
        ensure_file_event = request.ensure_file_event
        from_storyline = request.from_storyline
        suppress_command_file_effect = request.suppress_command_file_effect
        allow_existing_browser_reuse = request.allow_existing_browser_reuse
        allow_browser_launch_spacing = request.allow_browser_launch_spacing
        concurrency_group_id = request.concurrency_group_id

        self.state_manager.set_current_time(time)
        if _get_os_category(system.os) == "windows":
            process_name, command_line = _windows_script_host_process(
                process_name,
                command_line,
            )

        # Determine integrity level per UAC model:
        # - SYSTEM processes: "System" (handled in generate_system_process)
        # - Explicitly elevated (admin tools, installers): "High"
        # - Everything else (including admin users under UAC): "Medium"
        _HIGH_INTEGRITY_EXES = {
            "msiexec.exe",
            "regedit.exe",
            "mmc.exe",
            "dism.exe",
            "pkgmgr.exe",
            "setup.exe",
            "install.exe",
            "procdump64.exe",
            "procdump.exe",
            "mimikatz.exe",
            "psexec.exe",
            "psexesvc.exe",
        }
        _exe_lower = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if _get_os_category(system.os) == "windows" and _exe_lower == "psexesvc.exe":
            process_name = r"C:\Windows\PSEXESVC.exe"
            command_line = (
                r"C:\Windows\PSEXESVC.exe" if "accepteula" in command_line.lower() else command_line
            )
        process_name = normalize_defender_platform_path(process_name, system.hostname)
        if _exe_lower in _HIGH_INTEGRITY_EXES:
            _integrity = "High"
        elif _get_os_category(system.os) == "windows" and any(
            marker in command_line.lower()
            for marker in ("sekurlsa::", "privilege::debug", "lsadump::", "token::elevate")
        ):
            _integrity = "High"
        else:
            _integrity = "Medium"
            # Browser child processes (renderers) run at Low integrity.
            # ~65% of browser children are sandboxed renderers (Low),
            # ~35% are GPU/utility processes (Medium).
            _BROWSER_EXES = {"chrome.exe", "msedge.exe", "firefox.exe"}
            if _exe_lower in _BROWSER_EXES:
                _parent_image = (
                    self._lookup_process_name(
                        system.hostname, parent_pid, _get_os_category(system.os)
                    )
                    or ""
                )
                _parent_exe = _parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if _parent_exe in _BROWSER_EXES:
                    rng = _get_rng()
                    _integrity = "Low" if rng.random() < 0.65 else "Medium"

        process_username, process_logon_id = self._resolve_process_identity(
            system=system,
            username=user.username,
            logon_id=logon_id,
            process_name=process_name,
            time=time,
        )
        service_process_account = _windows_service_process_account(process_name, command_line)
        if _get_os_category(system.os) == "windows" and service_process_account is not None:
            process_username = service_process_account
            process_logon_id = _SYSTEM_ACCOUNT_LOGON_IDS[service_process_account]
            _integrity = "System"
        session_end_time = self.state_manager.get_session_end_time(process_logon_id)
        if (
            session_end_time is not None
            and time >= session_end_time
            and process_logon_id not in _SYSTEM_ACCOUNT_LOGON_IDS.values()
        ):
            time = session_end_time - sample_timing_delta(
                "windows.process_create_before_logoff",
                seed_parts=(system.hostname, process_logon_id, process_name, command_line),
            )
            self.state_manager.set_current_time(time)
        session = self.state_manager.get_session(process_logon_id)
        process_logon_type = session.logon_type if session is not None else 2
        if session is not None and time <= session.start_time:
            offset_ms = 100 + (
                _stable_seed(
                    f"process_after_logon:{system.hostname}:{process_logon_id}:{process_name}"
                )
                % 1400
            )
            time = session.start_time + timedelta(milliseconds=offset_ms)
            self.state_manager.set_current_time(time)
        explicit_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if explicit_parent is not None and time <= explicit_parent.start_time:
            offset_ms = 50 + (
                _stable_seed(
                    f"process_after_parent:{system.hostname}:{parent_pid}:{process_name}:"
                    f"{command_line}"
                )
                % 450
            )
            time = explicit_parent.start_time + timedelta(milliseconds=offset_ms)
            self.state_manager.set_current_time(time)
        if not from_storyline:
            spaced_time = self._space_one_shot_cli_launch(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
            )
            if spaced_time != time:
                time = spaced_time
                self.state_manager.set_current_time(time)
            if allow_browser_launch_spacing:
                spaced_time = self._space_browser_launch(
                    system=system,
                    username=process_username,
                    logon_id=process_logon_id,
                    process_name=process_name,
                    command_line=command_line,
                    time=time,
                )
                if spaced_time != time:
                    time = spaced_time
                    self.state_manager.set_current_time(time)
        if process_username != user.username and process_username not in _SYSTEM_ACCOUNTS:
            _integrity = "Medium"
        if _get_os_category(system.os) == "windows" and process_logon_type == 5:
            _integrity = "High" if _integrity == "Medium" else _integrity
        if _get_os_category(system.os) == "windows":
            _integrity, _token_elevation, _mandatory_label = _windows_token_profile(
                process_username,
                _integrity,
            )
        else:
            _token_elevation = "%%1938"
            _mandatory_label = "S-1-16-8192"

        if (
            not from_storyline
            and _get_os_category(system.os) == "windows"
            and _exe_lower == "explorer.exe"
            and process_logon_id not in _SYSTEM_ACCOUNT_LOGON_IDS.values()
        ):
            explorer_pid = self._ensure_session_explorer_pid(
                system,
                self._user_model_for_username(process_username),
                time,
                process_logon_id,
            )
            if explorer_pid is not None:
                self.state_manager.update_process_activity_time(
                    system.hostname,
                    explorer_pid,
                    time,
                )
                return explorer_pid

        singleton_pid = self._existing_windows_singleton_pid(system, process_name, time)
        if singleton_pid is not None:
            running_proc = self.state_manager.get_process(system.hostname, singleton_pid)
            if running_proc is not None:
                if (
                    running_proc.last_activity_time is None
                    or time > running_proc.last_activity_time
                ):
                    running_proc.last_activity_time = time
            return singleton_pid

        if not from_storyline and allow_existing_browser_reuse:
            browser_pid = self._existing_user_browser_pid(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
            )
            if browser_pid is not None:
                return browser_pid

        parent_pid = self._sanitize_user_parent_pid(
            system=system,
            user=user,
            time=time,
            logon_id=process_logon_id,
            process_name=process_name,
            command_line=command_line,
            parent_pid=parent_pid,
            process_username=process_username,
        )
        parent_pid = self._materialize_visible_linux_shell_parent_for_child(
            system=system,
            time=time,
            logon_id=process_logon_id,
            parent_pid=parent_pid,
            process_username=process_username,
        )
        parent_pid = self._repair_process_parent_pid(
            system=system,
            time=time,
            logon_id=process_logon_id,
            process_name=process_name,
            command_line=command_line,
            parent_pid=parent_pid,
            process_username=process_username,
        )
        repaired_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if repaired_parent is not None and time <= repaired_parent.start_time:
            time = repaired_parent.start_time + timedelta(milliseconds=50)
        if not from_storyline:
            spaced_time = self._space_interactive_shell_child_launch(
                system=system,
                process_name=process_name,
                parent_pid=parent_pid,
                time=time,
            )
            if spaced_time != time:
                time = spaced_time
        self.state_manager.set_current_time(time)
        self.state_manager.update_process_activity_time(system.hostname, parent_pid, time)

        # Phase 1: Allocate IDs from StateManager
        process_name = normalize_defender_platform_path(process_name, system.hostname)
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=process_username,
            integrity_level=_integrity,
            logon_id=process_logon_id,
        )

        # Phase 2: Build SecurityEvent
        running_proc = self.state_manager.get_process(system.hostname, pid)
        if running_proc and running_proc.logon_id:
            session = self.state_manager.get_session(running_proc.logon_id)
            if session is not None:
                session.last_activity_time = time
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        parent_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
        process_session_id = self._session_id_for_logon(process_logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_create",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=process_username,
                user_sid=self._get_sid(process_username),
                logon_id=process_logon_id,
                session_id=process_session_id,
                logon_type=process_logon_type,
                elevated=_integrity in {"High", "System"},
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=process_username,
                integrity_level=_integrity,
                logon_id=process_logon_id,
                parent_image=self._lookup_process_name(
                    system.hostname, parent_pid, _get_os_category(system.os)
                ),
                parent_command_line=self._lookup_parent_command_line(system.hostname, parent_pid),
                parent_start_time=self._lookup_parent_start_time(system.hostname, parent_pid),
                token_elevation=_token_elevation,
                mandatory_label=_mandatory_label,
                start_time=running_proc.start_time if running_proc is not None else None,
                current_directory=self._derive_current_directory(
                    system=system,
                    username=process_username,
                    process_name=process_name,
                    command_line=command_line,
                    parent_pid=parent_pid,
                    logon_type=process_logon_type,
                ),
                concurrency_group_id=concurrency_group_id,
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
            storyline_origin=from_storyline,
        )

        self._record_process_source_create_time(system.hostname, pid, event)

        # Phase 3: Dispatch to matching emitters
        self.dispatcher.dispatch(event)
        self._record_process_source_create_time(system.hostname, pid, event)
        self._emit_process_command_network_effects(
            user=user,
            system=system,
            time=time,
            pid=pid,
            process_name=process_name,
            command_line=command_line,
        )

        # Guaranteed FILE/CREATE for the process image when requested (storyline processes).
        # Skip for pre-existing binaries in System32/SysWOW64/Program Files — Event 11
        # should only fire for genuinely new files written to disk (malware drops, downloads).
        if ensure_file_event:
            _lower = process_name.lower()
            _win_path = _lower.replace("/", "\\")
            _is_windows_system_binary = (
                _win_path.startswith("c:\\windows\\system32\\")
                or _win_path.startswith("c:\\windows\\syswow64\\")
                or _win_path.startswith("c:\\program files\\")
                or _win_path.startswith("c:\\program files (x86)\\")
            )
            _linux_system_binary_prefixes = (
                "/bin/",
                "/sbin/",
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/local/bin/",
                "/usr/local/sbin/",
            )
            _is_linux_system_binary = _lower.startswith(_linux_system_binary_prefixes)
            _is_system_binary = _is_windows_system_binary or _is_linux_system_binary
            if not _is_system_binary:
                file_create_time = time + timedelta(milliseconds=120)
                file_process_pid = pid
                file_process_parent_pid = parent_pid
                file_process_image = process_name
                file_process_command_line = command_line
                file_process_username = process_username
                file_process_logon_id = process_logon_id
                file_process_start_time = (
                    running_proc.start_time if running_proc is not None else None
                )
                file_actor_obj_id = proc_obj_id
                if _exe_lower in {"psexesvc.exe", "healthmonitorsvc.exe"}:
                    file_create_time = time - timedelta(milliseconds=180)
                    parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
                    if parent_proc is not None and parent_proc.start_time < file_create_time:
                        file_process_pid = parent_proc.pid
                        file_process_parent_pid = parent_proc.parent_pid
                        file_process_image = parent_proc.image
                        file_process_command_line = parent_proc.command_line
                        file_process_username = parent_proc.username
                        file_process_logon_id = parent_proc.logon_id
                        file_process_start_time = parent_proc.start_time
                        file_actor_obj_id = parent_proc.ecar_object_id
                    elif parent_pid in {4, 0}:
                        file_process_pid = 4
                        file_process_parent_pid = 0
                        file_process_image = "System"
                        file_process_command_line = "System"
                        file_process_username = "SYSTEM"
                        file_process_logon_id = "0x3e7"
                        file_process_start_time = None
                        file_actor_obj_id = self.state_manager.get_process_object_id(
                            system.hostname,
                            4,
                        )
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=file_create_time,
                        event_type="file_create",
                        src_host=self._build_host_context(system),
                        auth=AuthContext(username=file_process_username),
                        process=ProcessContext(
                            pid=file_process_pid,
                            parent_pid=file_process_parent_pid,
                            image=file_process_image,
                            command_line=file_process_command_line,
                            username=file_process_username,
                            logon_id=file_process_logon_id,
                            start_time=file_process_start_time,
                        ),
                        file=FileContext(path=process_name, action="create", pid=file_process_pid),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "process-file-create-edr",
                                system.hostname,
                                file_process_pid,
                                process_name,
                                file_create_time.isoformat(),
                            ),
                            actor_id=file_actor_obj_id,
                        ),
                        storyline_origin=from_storyline,
                    )
                )

        # Phase 8.2: Probabilistic EDR object diversity via canonical SecurityEvent
        rng = _get_rng()
        os_category = _get_os_category(system.os)
        host_ctx = self._build_host_context(system)
        auth_ctx = AuthContext(
            username=process_username,
            user_sid=self._get_sid(process_username),
            logon_id=process_logon_id,
        )
        semantic_file_effect = None
        if not suppress_command_file_effect:
            from evidenceforge.generation.activity.edr_pools import select_command_file_side_effect

            semantic_file_effect = select_command_file_side_effect(process_name, command_line)
            if semantic_file_effect is not None:
                action, path = semantic_file_effect
                event_type = _FILE_ACTION_EVENT_TYPES[action]
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time + timedelta(milliseconds=180),
                        event_type=event_type,
                        src_host=host_ctx,
                        auth=auth_ctx,
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=process_username,
                            logon_id=process_logon_id,
                            start_time=running_proc.start_time
                            if running_proc is not None
                            else None,
                        ),
                        file=FileContext(path=path, action=action, pid=pid),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "command-file-effect-edr",
                                system.hostname,
                                pid,
                                action,
                                path,
                                time.isoformat(),
                            ),
                            actor_id=proc_obj_id,
                        ),
                        storyline_origin=from_storyline,
                    ),
                )
        if (
            not suppress_command_file_effect
            and semantic_file_effect is None
            and rng.random() < 0.40
        ):
            from evidenceforge.generation.activity.edr_pools import select_file_side_effect

            side_effect = select_file_side_effect(
                process_name=process_name,
                command_line=command_line,
                os_category=os_category,
                rng=rng,
                user=process_username,
            )
            if side_effect is not None:
                action, path = side_effect
                event_type = _FILE_ACTION_EVENT_TYPES[action]
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time + timedelta(milliseconds=rng.randint(110, 650)),
                        event_type=event_type,
                        src_host=host_ctx,
                        auth=auth_ctx,
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=process_username,
                            logon_id=process_logon_id,
                            start_time=running_proc.start_time
                            if running_proc is not None
                            else None,
                        ),
                        file=FileContext(path=path, action=action, pid=pid),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "sampled-file-effect-edr",
                                system.hostname,
                                pid,
                                action,
                                path,
                                time.isoformat(),
                            ),
                            actor_id=proc_obj_id,
                        ),
                        storyline_origin=from_storyline,
                    ),
                )
        if os_category == "windows" and rng.random() < 0.30:
            from evidenceforge.generation.activity.dll_load_profiles import get_dlls_for_process

            dll_profiles = get_dlls_for_process(_exe_lower)
            dll_profile = rng.choice(dll_profiles) if dll_profiles else {}
            dll_path = dll_profile.get("path", "")
            dll_path = _materialize_username_path(dll_path, process_username)
            module_delay_ms = rng.randint(120, 1500)
            process_start = running_proc.start_time if running_proc is not None else None
            if dll_path and self._mark_loaded_module(
                system.hostname,
                pid,
                process_start,
                dll_path,
            ):
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time + timedelta(milliseconds=module_delay_ms),
                        event_type="image_load",
                        src_host=host_ctx,
                        auth=auth_ctx,
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=process_username,
                            logon_id=process_logon_id,
                            start_time=process_start,
                        ),
                        image_load=ImageLoadContext(
                            image_loaded=dll_path,
                            signed=bool(dll_profile.get("signed", True)),
                            signature=str(dll_profile.get("signature", "Microsoft Windows")),
                            signature_status=str(dll_profile.get("signature_status", "Valid")),
                        ),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "image-load-edr",
                                system.hostname,
                                pid,
                                dll_path,
                                time.isoformat(),
                            ),
                            actor_id=proc_obj_id,
                        ),
                        storyline_origin=from_storyline,
                    )
                )
        # Only emit registry events for processes that realistically modify registry
        # (services, shells, installers) — NOT command-line recon tools like net.exe/dsquery.exe
        _REGISTRY_WRITERS = {
            "svchost.exe",
            "services.exe",
            "explorer.exe",
            "powershell.exe",
            "rundll32.exe",
            "msiexec.exe",
            "reg.exe",
            "regedit.exe",
            "taskhostw.exe",
            "usoclient.exe",
            "dllhost.exe",
        }
        _exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        _STORYLINE_REGISTRY_WRITERS = {"reg.exe", "regedit.exe", "msiexec.exe"}
        if (
            os_category == "windows"
            and _exe in _REGISTRY_WRITERS
            and (not from_storyline or _exe in _STORYLINE_REGISTRY_WRITERS)
            and rng.random() < 0.50
        ):
            # Service-level processes can write HKLM; user processes only HKCU
            _HKLM_WRITERS = {"svchost.exe", "services.exe", "reg.exe", "regedit.exe", "msiexec.exe"}
            # Emit 1-3 registry events per process (registry activity is high-volume)
            _reg_count = rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
            from evidenceforge.generation.activity.edr_pools import (
                get_registry_keys_hkcu,
                get_registry_keys_hklm,
                materialize_edr_template_group,
            )

            _pool_hkcu = get_registry_keys_hkcu()
            _pool_hklm = get_registry_keys_hklm()
            for _ in range(_reg_count):
                if process_username in _SYSTEM_ACCOUNTS:
                    _key, _vname, _details = rng.choice(_pool_hklm)
                elif _exe in _HKLM_WRITERS:
                    _key, _vname, _details = rng.choice(_pool_hklm + _pool_hkcu)
                else:
                    _key, _vname, _details = rng.choice(_pool_hkcu)
                _template_user = user.username if user else "SYSTEM"
                _key, _vname, _details = materialize_edr_template_group(
                    (_key, _vname, _details),
                    rng,
                    _template_user,
                    host_key=system.hostname,
                    host_ip=system.ip,
                    host_os=system.os,
                )
                # TargetObject = key\value_name (full path as Sysmon shows it)
                _target = f"{_key}\\{_vname}"
                # Sysmon value writes are Event 13. Key create/delete events need key-only
                # contexts, not the value-name pools used for ambient registry noise.
                reg_action = "modify"
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=time + timedelta(milliseconds=rng.randint(120, 950)),
                        event_type="registry_modify",
                        src_host=host_ctx,
                        auth=auth_ctx,
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=process_username,
                            logon_id=process_logon_id,
                            start_time=running_proc.start_time
                            if running_proc is not None
                            else None,
                        ),
                        registry=RegistryContext(
                            key=_target, value=_details, action=reg_action, pid=pid
                        ),
                        edr=EdrContext(
                            object_id=stable_uuid(
                                "registry-modify-edr",
                                system.hostname,
                                pid,
                                _target,
                                _details,
                                time.isoformat(),
                            ),
                            actor_id=proc_obj_id,
                        ),
                        storyline_origin=from_storyline,
                    )
                )

        logger.debug(f"Generated process: {process_name} (PID: {pid}) on {system.hostname}")
        return pid

    def _record_process_source_create_time(
        self,
        hostname: str,
        pid: int,
        event: SecurityEvent,
    ) -> None:
        """Remember the latest rendered source timestamp for a process create."""
        self._plan_process_source_create_times(event)
        source_timing = event.source_timing
        if source_timing is None:
            return
        source_create_times = [
            timestamp
            for key, timestamp in source_timing.source_times.items()
            if key.startswith(
                (
                    "source.windows_security_process_create|",
                    "source.sysmon_process_create|",
                    "source.ecar_process_create|",
                )
            )
        ]
        if source_create_times:
            self._process_source_create_times[(hostname, pid)] = max(source_create_times)

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        """Return the latest rendered source-create timestamp for a process."""
        return self._process_source_create_times.get((hostname, pid))

    def process_source_terminate_time(self, hostname: str, pid: int) -> datetime | None:
        """Return the rendered source-terminate timestamp for a process."""
        return self._process_source_terminate_times.get((hostname, pid))

    def _clamp_after_visible_process_create(
        self,
        system: System,
        pid: int,
        time: datetime,
        relationship_key: str,
    ) -> datetime:
        """Keep fast same-process dependents after visible Windows process creation."""
        if pid <= 0 or _get_os_category(system.os) != "windows":
            return time
        visible_create_time = self.process_source_create_time(system.hostname, pid)
        if visible_create_time is None or time > visible_create_time:
            return time
        return visible_create_time + sample_timing_delta(
            relationship_key,
            seed_parts=(system.hostname, pid, visible_create_time, time),
        )

    def _plan_process_source_create_times(self, event: SecurityEvent) -> None:
        """Precompute source-create timestamps before threaded emitters render."""
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return

        process_start_time = proc.start_time or event.timestamp

        if host.os_category == "windows":
            sysmon_not_before = event.timestamp
            if proc.parent_pid > 0:
                parent_visible_time = self.process_source_create_time(
                    host.hostname, proc.parent_pid
                )
                if parent_visible_time is not None:
                    sysmon_not_before = max(
                        sysmon_not_before,
                        parent_visible_time + timedelta(milliseconds=1),
                    )
            self._source_timing_planner.source_time(
                event,
                "source.sysmon_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=sysmon_not_before,
            )
            self._source_timing_planner.source_time(
                event,
                "source.windows_security_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=sysmon_not_before,
            )
            self._source_timing_planner.source_time(
                event,
                "source.ecar_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=process_start_time,
            )
            return
        else:
            ecar_not_before = process_start_time

        self._source_timing_planner.source_time(
            event,
            "source.ecar_process_create",
            seed_parts=(host.hostname, proc.pid, process_start_time),
            not_before=ecar_not_before,
        )

    def _record_process_source_terminate_time(
        self,
        hostname: str,
        pid: int,
        event: SecurityEvent,
    ) -> None:
        """Remember the rendered eCAR source timestamp for process termination."""
        self._plan_process_source_terminate_times(event)
        source_timing = event.source_timing
        if source_timing is None:
            return
        source_terminate_times = [
            timestamp
            for key, timestamp in source_timing.source_times.items()
            if key.startswith("source.ecar_process_terminate|")
        ]
        if source_terminate_times:
            self._process_source_terminate_times[(hostname, pid)] = max(source_terminate_times)

    def _plan_process_source_terminate_times(self, event: SecurityEvent) -> None:
        """Precompute eCAR terminate timestamps for source-visible shell ordering."""
        host = event.src_host
        proc = event.process
        if host is None or proc is None or proc.start_time is None:
            return
        self._plan_process_source_create_times(event)
        source_timing = event.source_timing
        process_create_ts = proc.start_time
        if source_timing is not None:
            ecar_create_times = [
                timestamp
                for key, timestamp in source_timing.source_times.items()
                if key.startswith("source.ecar_process_create|")
            ]
            if ecar_create_times:
                process_create_ts = max(ecar_create_times)
        canonical_lifetime = max(timedelta(milliseconds=100), event.timestamp - proc.start_time)
        self._source_timing_planner.source_time(
            event,
            "source.ecar_process_terminate",
            seed_parts=(
                host.hostname,
                proc.pid,
                proc.start_time,
                event.timestamp,
            ),
            not_before=max(event.timestamp, process_create_ts + canonical_lifetime),
        )

    def _emit_process_command_network_effects(
        self,
        *,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        command_line: str,
    ) -> None:
        """Emit direct network effects for well-known network-scanning commands."""
        NmapCommandProbeActionBundle(
            executor=self,
            request=NmapCommandProbeRequest(
                user=user,
                system=system,
                time=time,
                pid=pid,
                process_name=process_name,
                command_line=command_line,
            ),
        ).execute()

    def _execute_nmap_command_probe_bundle(self, request: NmapCommandProbeRequest) -> None:
        """Expand nmap-like process commands into scanner probe connections."""

        system = request.system
        time = request.time
        pid = request.pid
        process_name = request.process_name
        command_line = request.command_line
        command_lower = command_line.lower()
        image_lower = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if image_lower != "nmap" and " nmap " not in f" {command_lower} ":
            return
        ports = _extract_nmap_ports(command_line)
        if not ports:
            return
        targets = self._resolve_nmap_targets(command_line, system)
        if not targets:
            return

        rng = random.Random(
            _stable_seed(f"nmap_effects:{system.hostname}:{pid}:{command_line}:{time.isoformat()}")
        )
        probe_pairs = [(target_ip, port) for target_ip in targets[:32] for port in ports[:12]]
        rng.shuffle(probe_pairs)
        elapsed_ms = rng.randint(120, 260)
        for target_ip, port in probe_pairs:
            target_system = self._ip_to_system.get(target_ip)
            conn_state, service, duration, orig_bytes, resp_bytes = _nmap_probe_profile(
                port,
                target_system,
                rng,
            )
            offset = timedelta(milliseconds=elapsed_ms)
            elapsed_ms += rng.randint(35, 260) + int(rng.expovariate(1.0 / 90.0))
            self.generate_connection(
                src_ip=system.ip,
                dst_ip=target_ip,
                time=time + offset,
                dst_port=port,
                proto="tcp",
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                emit_dns=False,
                pid=pid,
                source_system=system,
                conn_state=conn_state,
                proxy_bypass=True,
                process_image=process_name,
                suppress_application_side_effects=True,
            )

    def _resolve_nmap_targets(self, command_line: str, system: System) -> list[str]:
        """Resolve nmap CIDR/IP arguments to visible scenario hosts when possible."""
        tokens = command_line.replace(",", " ").split()
        candidates: list[str] = []
        for token in tokens:
            stripped = token.strip("'\"")
            try:
                network = ipaddress.ip_network(stripped, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(stripped)
                except ValueError:
                    continue
                candidates.append(stripped)
                continue
            ip_map = getattr(self, "_ip_to_system", {})
            in_scenario = [
                ip
                for ip in sorted(ip_map)
                if ip != system.ip and ipaddress.ip_address(ip) in network
            ]
            if in_scenario:
                candidates.extend(in_scenario)
            else:
                candidates.extend(str(host) for host in itertools.islice(network.hosts(), 8))
        return list(dict.fromkeys(candidates))

    def _clamp_time_after_process_start(
        self, system: System, pid: int, time: datetime, *, offset_ms: int = 100
    ) -> datetime:
        """Ensure dependent process telemetry is not timestamped before process start."""
        process = self.state_manager.get_process(system.hostname, pid)
        if process and process.start_time and time <= process.start_time:
            return process.start_time + timedelta(milliseconds=offset_ms)
        return time

    @staticmethod
    def _ssh_responder_tuple_key(source_ip: str, source_port: int, target_ip: str) -> str:
        return f"{source_ip}:{source_port}->{target_ip}:22/tcp"

    def _remember_ssh_responder_pid(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
        pid: int,
    ) -> None:
        if pid <= 0:
            return
        if not hasattr(self, "_ssh_responder_pids"):
            self._ssh_responder_pids: dict[str, int] = {}
        self._ssh_responder_pids[
            self._ssh_responder_tuple_key(source_ip, source_port, target_ip)
        ] = pid

    def _remember_ssh_pid_alias(self, hostname: str, observed_pid: int | None, pid: int) -> None:
        if observed_pid is None or observed_pid <= 0 or pid <= 0 or observed_pid == pid:
            return
        if not hasattr(self, "_ssh_pid_aliases"):
            self._ssh_pid_aliases: dict[tuple[str, int], int] = {}
        self._ssh_pid_aliases[(hostname, observed_pid)] = pid

    def _ssh_pid_alias(self, hostname: str, pid: int | None) -> int | None:
        if pid is None or pid <= 0 or not hasattr(self, "_ssh_pid_aliases"):
            return None
        return self._ssh_pid_aliases.get((hostname, pid))

    def ssh_responder_pid_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> int | None:
        if not hasattr(self, "_ssh_responder_pids"):
            return None
        return self._ssh_responder_pids.get(
            self._ssh_responder_tuple_key(source_ip, source_port, target_ip)
        )

    def _remember_ssh_session_ready_time(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
        ready_time: datetime,
    ) -> None:
        """Remember when tuple-scoped receiver-side SSH child evidence may appear."""

        self._ssh_session_ready_times[
            self._ssh_responder_tuple_key(source_ip, source_port, target_ip)
        ] = ensure_utc(ready_time)

    def ssh_session_ready_time_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> datetime | None:
        """Return the receiver-side SSH child-evidence readiness time for a tuple."""

        return self._ssh_session_ready_times.get(
            self._ssh_responder_tuple_key(source_ip, source_port, target_ip)
        )

    def ensure_linux_ssh_responder_process(
        self,
        *,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_port: int,
        target_user: str | None = None,
    ) -> int:
        """Return the destination-side sshd process that owns one SSH 5-tuple."""
        remembered = self.ssh_responder_pid_for_tuple(source_ip, source_port, target_system.ip)
        if remembered is not None:
            running = self.state_manager.get_process(target_system.hostname, remembered)
            if running is not None:
                return remembered

        sys_pids = getattr(self, "_system_pids", {}).get(target_system.hostname, {})
        global_sshd = sys_pids.get("sshd")
        parent_pid = (
            global_sshd
            if global_sshd
            and self.state_manager.get_process(target_system.hostname, global_sshd) is not None
            else 0
        )
        sshd_seed = _stable_seed(
            "ssh_responder_pid:"
            f"{target_system.hostname}:{source_ip}:{source_port}:"
            f"{target_system.ip}:{time.isoformat()}"
        )
        process_user = target_user or "unknown"
        sshd_pid = self.generate_system_process(
            system=target_system,
            time=time + timedelta(milliseconds=8 + (sshd_seed % 72)),
            process_name="/usr/sbin/sshd",
            command_line=f"sshd: {process_user} [priv]",
            parent_pid=parent_pid,
            username="root",
            emit_linux_syslog=False,
        )
        self._remember_ssh_responder_pid(source_ip, source_port, target_system.ip, sshd_pid)
        return sshd_pid

    def _emit_generic_ssh_preauth_failure_syslog(
        self,
        *,
        target_system: System,
        target_host: HostContext | None,
        time: datetime,
        source_ip: str,
        source_port: int,
        sshd_pid: int,
        duration: float | None,
    ) -> None:
        """Emit source-native sshd auth companions for generic preauth transport."""
        if target_host is None or not source_ip or source_ip == "-" or source_port <= 0:
            return

        seed = _stable_seed(
            "generic_ssh_preauth_failure:"
            f"{target_system.hostname}:{source_ip}:{source_port}:{target_system.ip}:"
            f"{sshd_pid}:{time.isoformat()}"
        )
        connection_delta_ms = 45 + (seed % 90)
        invalid_delta_ms = connection_delta_ms + 40 + ((seed >> 8) % 180)
        failed_delta_ms = invalid_delta_ms + 120 + ((seed >> 16) % 600)
        close_delta_ms = max(
            failed_delta_ms + 40 + ((seed >> 24) % 180),
            int((duration or 0.0) * 1000) + 20,
        )
        rows = [
            (
                connection_delta_ms,
                6,
                f"Connection from {source_ip} port {source_port} on {target_system.ip} port 22",
            ),
            (
                invalid_delta_ms,
                5,
                f"Invalid user unknown from {source_ip} port {source_port}",
            ),
            (
                failed_delta_ms,
                4,
                f"Failed password for invalid user unknown from {source_ip} port {source_port} ssh2",
            ),
            (
                close_delta_ms,
                6,
                f"Connection closed by invalid user unknown {source_ip} port {source_port} [preauth]",
            ),
        ]
        for delta_ms, severity, message in rows:
            self.generate_syslog_event(
                target_system,
                time + timedelta(milliseconds=delta_ms),
                "sshd",
                message,
                pid=sshd_pid,
                facility=10,
                severity=severity,
            )

    def ensure_linux_ssh_client_process(
        self,
        *,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
        process_image: str,
        source_port: int,
    ) -> tuple[int, str] | None:
        """Return the source-side SSH client process that owns an outbound session."""
        if _get_os_category(source_system.os) != "linux":
            return None

        requested_time = ensure_utc(time)
        image = process_image or "/usr/bin/ssh"
        exe_name = image.rsplit("/", 1)[-1].lower()
        if exe_name == "sshd":
            image = "/usr/bin/ssh"
            exe_name = "ssh"
        if exe_name not in {"ssh", "scp"}:
            image = "/usr/bin/ssh"
            exe_name = "ssh"

        target_host = self._build_host_context(target_system).fqdn or target_system.hostname
        command_line = _linux_ssh_client_command_line(
            exe_name=exe_name,
            username=user.username,
            target_host=target_host,
            target_ip=target_system.ip,
            source_hostname=source_system.hostname,
            source_port=source_port,
            requested_time=requested_time,
        )

        seed = _stable_seed(
            "linux_ssh_client_process:"
            f"{source_system.hostname}:{user.username}:{target_system.hostname}:"
            f"{source_port}:{requested_time.isoformat()}:{image}"
        )
        process_time = requested_time - timedelta(milliseconds=6500 + (seed % 11500))
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        if scenario_start is not None and requested_time >= scenario_start:
            latest_with_visible_headroom = requested_time - timedelta(seconds=5)
            if process_time < scenario_start and latest_with_visible_headroom > scenario_start:
                process_time = min(
                    latest_with_visible_headroom,
                    scenario_start + timedelta(milliseconds=400 + (seed % 1800)),
                )

        strict_server_session = (
            source_system.type or "workstation"
        ).lower() == "server" and getattr(self, "_scenario_start_time", None) is not None
        session = self._active_source_linux_session(user, source_system, requested_time)
        if session is None:
            if strict_server_session:
                return None
            logon_time = process_time - timedelta(seconds=7 + (seed % 9))
            logon_id = self.generate_logon(
                user,
                source_system,
                logon_time,
                logon_type=2,
            )
            session = self.state_manager.get_session(logon_id)
        if session is None:
            return None

        logon_time = ensure_utc(session.start_time)
        parent_pid = self.ensure_linux_session_shell(
            user,
            source_system,
            session.logon_id,
            logon_time,
            process_time,
        )
        if parent_pid is None:
            parent_pid = self.ensure_linux_visible_shell_parent(
                user,
                source_system,
                process_time,
                session.logon_id,
                logon_time,
            )
        if parent_pid is None:
            parent_pid = self._linux_anchor_pid(source_system, process_time)

        process_time = self._reserve_foreground_shell_time(
            system=source_system,
            username=user.username,
            logon_id=session.logon_id,
            parent_pid=parent_pid,
            requested_time=process_time,
            seed_text=command_line,
        )
        if process_time >= requested_time:
            process_time = requested_time - timedelta(milliseconds=800)
        if not _session_active_for_activity(session, process_time, margin_seconds=0.5):
            return None

        pid = self.generate_process(
            user=user,
            system=source_system,
            time=process_time,
            logon_id=session.logon_id,
            process_name=image,
            command_line=command_line,
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
        )
        self._record_user_process(source_system, user, pid, image)
        self._emit_bash_command_event(user, source_system, process_time, command_line)
        self._remember_linux_bash_session_activity(
            user,
            source_system,
            process_time,
            requested_time,
        )
        self.state_manager.update_process_activity_time(source_system.hostname, pid, requested_time)
        self.state_manager.set_current_time(requested_time)
        return pid, image

    def _active_source_linux_session(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest active Linux session that can launch an SSH client."""
        strict_server_session = (system.type or "workstation").lower() == "server" and getattr(
            self, "_scenario_start_time", None
        ) is not None
        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user_at(user.username, time)
            if session.system == system.hostname
            and _session_active_for_activity(session, time, margin_seconds=1.5)
            and (not strict_server_session or session.session_kind == "ssh")
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda session: ensure_utc(session.start_time))

    def _normalize_sshd_syslog_pid(
        self,
        *,
        system: System,
        time: datetime,
        message: str,
        pid: int | None,
    ) -> int | None:
        alias = self._ssh_pid_alias(system.hostname, pid)
        if alias is not None:
            return alias

        source_ip = ""
        source_port = 0
        target_user = None
        conn_match = re.match(
            r"^Connection from (?P<src_ip>\S+) port (?P<src_port>\d+) "
            r"on (?P<dst_ip>\S+) port 22$",
            message,
        )
        if conn_match:
            source_ip = conn_match.group("src_ip")
            source_port = int(conn_match.group("src_port"))
        else:
            accepted_match = re.match(
                r"^Accepted \S+ for (?:invalid user )?(?P<target_user>\S+) "
                r"from (?P<src_ip>\S+) port (?P<src_port>\d+) ",
                message,
            )
            if accepted_match:
                source_ip = accepted_match.group("src_ip")
                source_port = int(accepted_match.group("src_port"))
                target_user = accepted_match.group("target_user")

        if not source_ip or source_port <= 0:
            return pid

        responder_pid = self.ensure_linux_ssh_responder_process(
            target_system=system,
            time=time,
            source_ip=source_ip,
            source_port=source_port,
            target_user=target_user,
        )
        self._remember_ssh_pid_alias(system.hostname, pid, responder_pid)
        return responder_pid

    def reserve_ssh_source_port(
        self,
        source_ip: str,
        target_ip: str,
        source_port: int | None,
        rng: random.Random,
        source_os: str,
        time: datetime | None = None,
    ) -> int:
        """Reserve a per-source/destination SSH source port for unambiguous correlation."""
        candidate = source_port or _ephemeral_port(rng, source_os)
        ts_epoch = time.timestamp() if time is not None else None
        if ts_epoch is not None:
            self._prune_recent_connection_tuples(ts_epoch)
        for _ in range(100):
            key = (source_ip, target_ip, candidate)
            recent_key = (source_ip, candidate, target_ip, 22, "tcp")
            recent_seen = self._recent_connection_tuples.get(recent_key)
            recent_is_active = (
                ts_epoch is not None
                and recent_seen is not None
                and ts_epoch - recent_seen <= _RECENT_CONNECTION_REUSE_WINDOW_SECONDS
            )
            if (
                source_port is not None
                and key in self._ssh_source_ports
                and ts_epoch is not None
                and recent_seen is not None
                and abs(ts_epoch - recent_seen) <= 1.0
            ):
                return candidate
            if key not in self._ssh_source_ports and not recent_is_active:
                self._ssh_source_ports.add(key)
                if time is not None:
                    self._remember_connection_tuple(
                        source_ip, candidate, target_ip, 22, "tcp", time
                    )
                return candidate
            candidate = _ephemeral_port(rng, source_os)
        self._ssh_source_ports.add((source_ip, target_ip, candidate))
        if time is not None:
            self._remember_connection_tuple(source_ip, candidate, target_ip, 22, "tcp", time)
        return candidate

    def generate_process_termination(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
        from_storyline: bool = False,
    ) -> None:
        """Generate process termination event across all applicable log formats.

        Builds a SecurityEvent and dispatches to matching emitters (Windows 4689,
        eCAR PROCESS/TERMINATE). StateManager.apply() handles end_process.

        Args:
            user: User who owned the process
            system: System where process ran
            time: Termination timestamp
            pid: PID of the terminated process
            process_name: Full path of the terminated process
            logon_id: LogonID of the owning session
        """
        request = ProcessTerminationRequest(
            user=user,
            system=system,
            time=time,
            pid=pid,
            process_name=process_name,
            logon_id=logon_id,
            from_storyline=from_storyline,
        )
        ProcessTerminationActionBundle(self, request).execute()

    def _execute_process_termination_bundle(self, request: ProcessTerminationRequest) -> None:
        """Expand a process-termination bundle through the compatibility adapter."""
        from evidenceforge.events.contexts import ProcessContext

        user = request.user
        system = request.system
        time = request.time
        pid = request.pid
        process_name = request.process_name
        logon_id = request.logon_id
        from_storyline = request.from_storyline

        running_proc = self.state_manager.get_process(system.hostname, pid)
        if self._process_termination_recorded(
            system.hostname,
            pid,
            running_proc.start_time if running_proc is not None else None,
        ):
            return

        if (
            running_proc is not None
            and running_proc.last_activity_time is not None
            and time <= running_proc.last_activity_time
        ):
            delay_rng = random.Random(
                _stable_seed(
                    "process_terminate_after_activity:"
                    f"{system.hostname}:{pid}:{running_proc.last_activity_time.isoformat()}"
                )
            )
            time = running_proc.last_activity_time + timedelta(seconds=delay_rng.uniform(2.0, 30.0))
        if running_proc is not None:
            process_name = running_proc.image
        process_username = running_proc.username if running_proc is not None else user.username
        process_logon_id = running_proc.logon_id if running_proc is not None else logon_id
        session_logon_type = self.state_manager.get_session_logon_type(process_logon_id)
        session_end_time = self.state_manager.get_session_end_time(process_logon_id)
        if session_end_time is not None and time >= session_end_time:
            end_margin_ms = 150 + (
                _stable_seed(
                    f"process_terminate_before_logoff:{system.hostname}:{pid}:{process_logon_id}"
                )
                % 850
            )
            latest_allowed = session_end_time - timedelta(milliseconds=end_margin_ms)
            if running_proc is not None and running_proc.start_time >= latest_allowed:
                latest_allowed = running_proc.start_time + timedelta(milliseconds=100)
            if latest_allowed < session_end_time:
                time = min(time, latest_allowed)
        if not process_logon_id:
            if process_username in _SYSTEM_ACCOUNTS:
                process_logon_id = "0x3e7"
            else:
                resolved_username, resolved_logon_id = self._resolve_process_identity(
                    system=system,
                    username=process_username,
                    logon_id=logon_id,
                    process_name=process_name,
                    time=time,
                )
                process_username = resolved_username
                process_logon_id = resolved_logon_id or logon_id
        time = self._clamp_after_visible_process_create(
            system,
            pid,
            time,
            "windows.process_exit_after_visible_create",
        )
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        process_session_id = self._session_id_for_logon(process_logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_terminate",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=process_username,
                user_sid=self._get_sid(process_username),
                logon_id=process_logon_id,
                session_id=process_session_id,
                logon_type=session_logon_type or 0,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=process_name,
                command_line="",
                username=process_username,
                logon_id=process_logon_id,
                start_time=running_proc.start_time if running_proc is not None else None,
            ),
            edr=EdrContext(object_id=proc_obj_id),
            storyline_origin=from_storyline,
        )

        self._record_process_source_terminate_time(system.hostname, pid, event)
        self.dispatcher.dispatch(event)
        termination_start_time = event.process.start_time if event.process is not None else None
        self._terminated_process_keys.add((system.hostname, pid, termination_start_time))

        logger.debug(
            f"Generated process termination: {process_name} (PID: {pid}) on {system.hostname}"
        )

    def _remember_kerberos_audit(
        self,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        *,
        source_port: int | None = None,
    ) -> None:
        """Track recently emitted DC audit so connection-layer repair does not duplicate it."""
        if not source_ip or source_ip == "-" or not dc_hostname:
            return
        cache: dict[tuple[str, str], list[float]] = getattr(
            self,
            "_kerberos_connection_audit_times",
            {},
        )
        self._kerberos_connection_audit_times = cache
        key = (source_ip.removeprefix("::ffff:"), dc_hostname.lower())
        current = time.timestamp()
        recent = [seen for seen in cache.get(key, []) if abs(current - seen) <= 30.0]
        recent.append(current)
        cache[key] = recent[-12:]
        if source_port is None or source_port <= 0:
            return
        tuple_cache = self._kerberos_audit_tuple_times
        tuple_key = (
            source_ip.removeprefix("::ffff:"),
            dc_hostname.lower().rstrip("."),
            source_port,
        )
        tuple_recent = [
            seen for seen in tuple_cache.get(tuple_key, []) if abs(current - seen) <= 30.0
        ]
        tuple_recent.append(current)
        tuple_cache[tuple_key] = tuple_recent[-16:]

    def _kerberos_audit_count_for_connection(
        self,
        source_ip: str,
        dc_hostname: str,
        source_port: int,
        time: datetime,
        *,
        window_seconds: float = 3.0,
    ) -> int:
        """Count nearby DC audit events sharing the visible Kerberos transport tuple."""
        if not source_ip or source_ip == "-" or not dc_hostname or source_port <= 0:
            return 0
        key = (source_ip.removeprefix("::ffff:"), dc_hostname.lower().rstrip("."), source_port)
        current = time.timestamp()
        return sum(
            1
            for seen in self._kerberos_audit_tuple_times.get(key, [])
            if abs(current - seen) <= window_seconds
        )

    def _has_recent_kerberos_audit(
        self,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        *,
        window_seconds: float = 10.0,
    ) -> bool:
        if not source_ip or source_ip == "-" or not dc_hostname:
            return False
        cache: dict[tuple[str, str], list[float]] = getattr(
            self,
            "_kerberos_connection_audit_times",
            {},
        )
        key = (source_ip.removeprefix("::ffff:"), dc_hostname.lower())
        current = time.timestamp()
        return any(abs(current - seen) <= window_seconds for seen in cache.get(key, []))

    def _emit_dc_audit_for_kerberos_connection(
        self,
        *,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        time: datetime,
        dst_port: int,
        proto: str,
        conn_state: str,
        service: str,
        source_system: System | None,
    ) -> None:
        """Emit DC-side Kerberos audit companions via an action bundle."""
        request = KerberosConnectionAuditRequest(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            time=time,
            dst_port=dst_port,
            proto=proto,
            conn_state=conn_state,
            service=service,
            source_system=source_system,
        )
        KerberosConnectionAuditActionBundle(self, request).execute()

    def _execute_kerberos_connection_audit_bundle(
        self,
        request: KerberosConnectionAuditRequest,
    ) -> None:
        """Ensure visible internal-to-DC Kerberos flows have nearby DC audit evidence."""
        src_ip = request.src_ip
        src_port = request.src_port
        dst_ip = request.dst_ip
        time = request.time
        dst_port = request.dst_port
        proto = request.proto
        conn_state = request.conn_state
        service = request.service
        source_system = request.source_system

        if proto not in {"tcp", "udp"} or dst_port != 88 or service != "kerberos":
            return
        if proto == "tcp" and conn_state in {"S0", "S1", "SH", "SHR", "REJ", "OTH"}:
            return
        if source_system is None:
            return

        dc_system = self._dc_system_for_ip(dst_ip)
        if dc_system is None:
            return

        dc_hostname = dc_system.hostname
        reserved_port = self._find_reserved_kerberos_source_port(
            src_ip,
            dc_hostname,
            time,
            dst_ip=dst_ip,
            proto=proto,
            exclude_active_tuple=False,
        )
        if self._has_recent_kerberos_audit(src_ip, dc_hostname, time) and reserved_port == src_port:
            return

        rng = random.Random(
            _stable_seed(
                "kerberos_connection_audit:"
                f"{src_ip}:{dst_ip}:{source_system.hostname}:{time.timestamp()}"
            )
        )
        tgt_time, tgs_time = self._kerberos_ticket_times(
            time,
            rng,
            tgs_before_ms=(12, 75),
            tgt_before_tgs_ms=(35, 260),
        )
        machine_principal = f"{source_system.hostname}$"
        self._maybe_generate_kerberos_tgt(
            username=machine_principal,
            source_ip=src_ip,
            dc_hostname=dc_hostname,
            time=tgt_time,
            rng=rng,
            source_port=src_port,
        )
        service_name = rng.choices(
            [
                f"host/{dc_hostname}",
                f"ldap/{dc_hostname}",
                f"cifs/{dc_hostname}",
                f"DNS/{dc_hostname}",
            ],
            weights=[34, 36, 20, 10],
            k=1,
        )[0]
        self.generate_kerberos_service_ticket(
            username=machine_principal,
            service_name=service_name,
            source_ip=src_ip,
            dc_hostname=dc_hostname,
            time=tgs_time,
            source_port=src_port,
        )

    def generate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        dst_port: int = 443,
        proto: str = "tcp",
        service: str | None = None,
        duration: float | None = None,
        orig_bytes: int | None = None,
        resp_bytes: int | None = None,
        src_port: int | None = None,
        emit_dns: bool = False,
        pid: int = -1,
        source_system: Optional["System"] = None,
        conn_state: str | None = None,
        dns: Optional["DnsContext"] = None,
        email: Optional["EmailContext"] = None,
        smtp: Optional["SmtpContext"] = None,
        ssl: SslContext | None = None,
        ids: Optional["IdsContext"] = None,
        http: Optional["HttpContext"] = None,
        file_transfer: FileTransferContext | None = None,
        file_transfers: list[FileTransferContext] | None = None,
        pe: PeContext | None = None,
        ocsp: OcspContext | None = None,
        proxy: Optional["ProxyContext"] = None,
        firewall: FirewallContext | None = None,
        hostname: str | None = None,
        proxy_bypass: bool = False,
        process_image: str | None = None,
        preserve_dst_ip: bool = False,
        preserve_http_outcome: bool = False,
        suppress_application_side_effects: bool = False,
        preserve_explicit_payload: bool = False,
        packet_overhead_bytes: int | None = None,
        responding_pid: int = -1,
    ) -> str:
        """Generate network connection across all applicable log formats.

        Opens connection in StateManager, builds a SecurityEvent with
        NetworkContext, and dispatches to matching emitters (Zeek conn,
        Snort, eCAR FLOW). Dispatcher handles network visibility filtering.

        Optional context overrides (ids, http) are attached to the
        SecurityEvent, enabling correlated rendering by format-specific
        emitters (e.g., Snort from IdsContext, web_access from HttpContext).

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            time: Connection start timestamp
            dst_port: Destination port
            proto: Protocol (tcp/udp/icmp)
            service: Application protocol (http, https, ssh, dns, etc.)
            duration: Connection duration in seconds
            orig_bytes: Bytes sent by originator
            resp_bytes: Bytes sent by responder
            src_port: Source port (auto-assigned ephemeral if None)
            emit_dns: If True, emit a DNS lookup for dst_ip before the connection
            ids: Optional IdsContext for IDS alert correlation (Snort emitter)
            http: Optional HttpContext override (skips auto-generation)
            preserve_dst_ip: Preserve caller-supplied dst_ip when the scenario or caller
                intentionally pairs an authored hostname with a specific address. This keeps
                static-NAT VIPs and explicit egress destinations from being re-resolved.
            packet_overhead_bytes: Optional IP packet overhead to preserve source-native
                packet accounting for canonical firewall/syslog companion events.

        Returns:
            Zeek UID (18-character string)
        """
        request = NetworkConnectionRequest(
            src_ip=src_ip,
            dst_ip=dst_ip,
            time=time,
            dst_port=dst_port,
            proto=proto,
            service=service,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            src_port=src_port,
            emit_dns=emit_dns,
            pid=pid,
            source_system=source_system,
            conn_state=conn_state,
            dns=dns,
            email=email,
            smtp=smtp,
            ssl=ssl,
            ids=ids,
            http=http,
            file_transfer=file_transfer,
            file_transfers=list(file_transfers or []),
            pe=pe,
            ocsp=ocsp,
            proxy=proxy,
            firewall=firewall,
            hostname=hostname,
            proxy_bypass=proxy_bypass,
            process_image=process_image,
            preserve_dst_ip=preserve_dst_ip,
            preserve_http_outcome=preserve_http_outcome,
            suppress_application_side_effects=suppress_application_side_effects,
            preserve_explicit_payload=preserve_explicit_payload,
            packet_overhead_bytes=packet_overhead_bytes,
            responding_pid=responding_pid,
        )
        return NetworkConnectionActionBundle(
            executor=self,
            request=request,
        ).execute()

    def generate_email_message(
        self,
        *,
        spec: EmailMessageEventSpec,
        actor: "User",
        system: "System",
        time: datetime,
        activity: str = "",
        storyline_id: str = "",
    ) -> EmailDeliveryResult:
        """Generate SMTP delivery evidence for one modeled email message."""
        request = EmailDeliveryRequest(
            spec=spec,
            actor=actor,
            system=system,
            time=time,
            activity=activity,
            storyline_id=storyline_id,
        )
        return EmailDeliveryActionBundle(executor=self, request=request).execute()

    def generate_email_read(
        self,
        *,
        spec: Any,
        actor: "User",
        system: "System",
        time: datetime,
        activity: str = "",
        storyline_id: str = "",
    ) -> dict[str, Any]:
        """Generate opaque TLS mailbox access evidence for an email_read event."""
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            raise ValueError("email_read requires environment.email to be configured")
        mailbox = (spec.mailbox or actor.email).lower()
        server_name = spec.server or self._email_server_for_user_address(mailbox)
        server_system = self._email_system_for_server_name(server_name)
        server_cfg = self._email_servers_by_name()[server_name]
        protocol = spec.protocol or ("owa" if server_cfg.platform == "exchange" else "imaps")
        uid = self.generate_email_access(
            user=actor,
            system=system,
            server=server_system,
            time=time,
            platform=server_cfg.platform,
            protocol=protocol,
            duration=spec.duration,
            user_agent=spec.user_agent or "",
            message_ids=tuple(spec.message_ids),
        )
        return {
            "mailbox": mailbox,
            "server": server_name,
            "protocol": protocol,
            "message_ids": list(spec.message_ids),
            "count": spec.count,
            "uid": uid,
        }

    def generate_email_access(
        self,
        *,
        user: "User",
        system: "System",
        server: "System",
        time: datetime,
        platform: str = "generic_smtp",
        protocol: str = "",
        duration: float | None = None,
        user_agent: str = "",
        message_ids: tuple[str, ...] = (),
    ) -> str:
        """Generate an opaque TLS mailbox access session."""
        request = EmailAccessRequest(
            user=user,
            system=system,
            server=server,
            time=time,
            platform=platform,
            protocol=protocol,
            duration=duration,
            user_agent=user_agent,
            message_ids=message_ids,
        )
        return EmailAccessActionBundle(executor=self, request=request).execute()

    def _execute_email_access_bundle(self, request: EmailAccessRequest) -> str:
        """Expand one lightweight mailbox read/access session into network evidence."""
        rng = random.Random(
            _stable_seed(
                "email_access:"
                f"{request.user.username}:{request.system.hostname}:"
                f"{request.server.hostname}:{request.time.isoformat()}"
            )
        )
        protocol = request.protocol or ("owa" if request.platform == "exchange" else "imaps")
        port = 443 if protocol == "owa" else 993
        service = "ssl"
        hostname = self._email_server_fqdn(request.server.hostname)
        return self.generate_connection(
            src_ip=request.system.ip,
            dst_ip=request.server.ip,
            time=request.time,
            dst_port=port,
            proto="tcp",
            service=service,
            duration=request.duration or rng.uniform(12.0, 180.0),
            orig_bytes=rng.randint(1200, 9000),
            resp_bytes=rng.randint(15_000, 450_000),
            conn_state="SF",
            emit_dns=True,
            source_system=request.system,
            hostname=hostname,
            process_image=self._email_access_process_image(
                request.system,
                protocol,
                request.user_agent,
                rng,
            ),
        )

    def _email_access_process_image(
        self,
        system: "System",
        protocol: str,
        user_agent: str,
        rng: random.Random,
    ) -> str:
        """Return lightweight client process attribution for mailbox reads."""
        os_category = _get_os_category(system.os)
        ua = user_agent.lower()
        if protocol == "owa":
            if os_category == "windows":
                return rng.choice(
                    [
                        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    ]
                )
            return rng.choice(["/usr/bin/firefox", "/usr/bin/chromium"])
        if "thunderbird" in ua:
            return (
                "/usr/bin/thunderbird"
                if os_category == "linux"
                else r"C:\Program Files\Mozilla Thunderbird\thunderbird.exe"
            )
        if os_category == "windows":
            return r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
        return "/usr/bin/thunderbird"

    def _load_email_corpus(self) -> dict[str, EmailCorpusEntry]:
        """Load and cache the optional scenario-created email corpus."""
        cached = getattr(self, "_email_corpus_cache", None)
        if cached is not None:
            return cached
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None or not email_config.corpus:
            self._email_corpus_cache = {}
            return {}
        corpus_path = Path(email_config.corpus)
        if not corpus_path.is_absolute():
            corpus_path = Path(getattr(self, "_scenario_root", Path.cwd())) / corpus_path
        with corpus_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        messages = raw.get("messages", raw if isinstance(raw, list) else [])
        if not isinstance(messages, list):
            raise ValueError("email_corpus.yaml must contain a top-level messages list")
        entries: dict[str, EmailCorpusEntry] = {}
        for idx, item in enumerate(messages):
            if not isinstance(item, dict):
                raise ValueError(f"email_corpus.yaml messages.{idx} must be a mapping")
            entry_id = str(item.get("id") or "").strip()
            if not entry_id:
                raise ValueError(f"email_corpus.yaml messages.{idx}.id is required")
            if entry_id in entries:
                raise ValueError(f"email_corpus.yaml duplicate message id: {entry_id}")
            subject = str(item.get("subject") or "").strip()
            body = str(item.get("body") or "")
            if not subject:
                raise ValueError(f"email_corpus.yaml message {entry_id!r} requires subject")
            if not body:
                raise ValueError(f"email_corpus.yaml message {entry_id!r} requires body")
            attachments = tuple(
                self._normalize_email_attachment(att, entry_id, index)
                for index, att in enumerate(item.get("attachments") or [])
            )
            headers_raw = item.get("headers") or {}
            if not isinstance(headers_raw, dict):
                raise ValueError(
                    f"email_corpus.yaml message {entry_id!r} headers must be a mapping"
                )
            entries[entry_id] = EmailCorpusEntry(
                entry_id=entry_id,
                subject=subject,
                body=body,
                user_agent=str(item.get("user_agent") or ""),
                headers={str(key): str(value) for key, value in headers_raw.items()},
                attachments=attachments,
                tags=tuple(str(tag) for tag in item.get("tags") or []),
                background=bool(item.get("background", False)),
                storyline=bool(item.get("storyline", True)),
            )
        self._email_corpus_cache = entries
        return entries

    def _email_corpus_entry(self, corpus_id: str | None) -> EmailCorpusEntry | None:
        """Return one corpus entry or fail clearly if the scenario references an unknown ID."""
        if not corpus_id:
            return None
        corpus = self._load_email_corpus()
        entry = corpus.get(corpus_id)
        if entry is None:
            raise ValueError(f"email_message corpus_id {corpus_id!r} was not found")
        return entry

    def _email_background_corpus_entries(self) -> list[EmailCorpusEntry]:
        """Return corpus entries eligible for deterministic background email."""
        return [entry for entry in self._load_email_corpus().values() if entry.background]

    @staticmethod
    def _normalize_email_attachment(
        attachment: Any,
        entry_id: str,
        index: int,
    ) -> dict[str, Any]:
        """Normalize one corpus attachment into EmailAttachmentSpec-compatible metadata."""
        if not isinstance(attachment, dict):
            raise ValueError(
                f"email_corpus.yaml message {entry_id!r} attachments.{index} must be a mapping"
            )
        filename = str(attachment.get("filename") or "").strip()
        if not filename:
            raise ValueError(
                f"email_corpus.yaml message {entry_id!r} attachments.{index}.filename is required"
            )
        content = attachment.get("content")
        size = attachment.get("size")
        if size is None:
            size = len(str(content or "").encode("utf-8"))
        return {
            "filename": filename,
            "content_type": str(attachment.get("content_type") or "application/octet-stream"),
            "size": int(size),
            "content": None if content is None else str(content),
        }

    def _execute_email_delivery_bundle(self, request: EmailDeliveryRequest) -> EmailDeliveryResult:
        """Expand one email message into DNS, SMTP, artifact, and manifest evidence."""
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            raise ValueError("email_message requires environment.email to be configured")

        spec = request.spec
        rng = random.Random(
            _stable_seed(
                "email_message:"
                f"{request.storyline_id}:{request.actor.username}:"
                f"{request.system.hostname}:{request.time.isoformat()}:{spec.subject or ''}"
            )
        )
        corpus_entry = self._email_corpus_entry(spec.corpus_id)
        sender = (spec.sender or request.actor.email).lower()
        recipients_all = list(dict.fromkeys([*spec.to, *spec.cc, *spec.bcc]))
        envelope_recipients = [recipient.lower() for recipient in recipients_all]
        expanded_recipients = self._expand_email_recipients(recipients_all)
        subject = (
            spec.subject
            or (corpus_entry.subject if corpus_entry is not None else "")
            or self._deterministic_email_subject(sender, expanded_recipients, rng)
        )
        body = (
            spec.body
            if spec.body is not None
            else (
                corpus_entry.body
                if corpus_entry is not None
                else self._deterministic_email_body(subject, rng)
            )
        )
        attachments = (
            [dict(attachment) for attachment in corpus_entry.attachments]
            if corpus_entry is not None
            else [att.model_dump() for att in spec.attachments]
        )
        artifact_id = spec.artifact_id or self._email_artifact_id(
            request.storyline_id,
            sender,
            expanded_recipients,
            request.time,
        )
        date_header = request.time.strftime("%a, %d %b %Y %H:%M:%S +0000")
        corpus_user_agent = (
            corpus_entry.user_agent if corpus_entry is not None and request.storyline_id else ""
        )
        user_agent = spec.user_agent or self._email_effective_user_agent(
            sender,
            corpus_user_agent or self._email_user_agent(request.system, rng),
        )
        message_id = self._email_message_id(artifact_id, sender, user_agent)
        route = self._plan_email_route(sender, expanded_recipients, request.system)
        if route and route[0].get("submission"):
            route[0]["recipients"] = envelope_recipients
        received_headers = self._received_headers_for_route(
            route=route,
            message_id=message_id,
            recipients=expanded_recipients,
            time=request.time,
        )
        email_ctx = EmailContext(
            message_id=message_id,
            artifact_id=artifact_id,
            envelope_from=sender,
            header_from=self._email_header_address(sender),
            to=[self._email_header_address(addr) for addr in spec.to],
            cc=[self._email_header_address(addr) for addr in spec.cc],
            bcc=list(spec.bcc),
            expanded_rcptto=expanded_recipients,
            subject=subject,
            date_header=date_header,
            user_agent=user_agent,
            body=body,
            body_size=len(body.encode("utf-8")),
            custom_headers=dict(corpus_entry.headers or {}) if corpus_entry is not None else {},
            attachments=attachments,
            verdict=spec.verdict,
            mail_action=spec.mail_action,
            outcome=spec.outcome,
            received_headers=received_headers,
            storyline_id=request.storyline_id,
        )
        smtp_uids: list[str] = []
        route_summary: list[dict[str, str]] = []

        self._emit_email_route_dns(route, request.time)

        for index, hop in enumerate(route):
            hop_time = request.time + timedelta(seconds=1.2 + index * rng.uniform(2.0, 8.0))
            src_system = hop["src_system"]
            dst_system = hop["dst_system"]
            tls = bool(
                hop["server_to_server"]
                and hop["src_server_attempts_starttls"]
                and hop["dst_server_allows_starttls"]
            )
            last_reply = (
                "250 2.0.0 Ok: queued"
                if spec.outcome == "delivered"
                else "550 5.7.1 Message rejected"
            )
            mime_file_transfers = (
                self._email_mime_file_transfers(
                    artifact_id=artifact_id,
                    hop_index=index,
                    body=body,
                    attachments=attachments,
                    duration=rng.uniform(0.04, 0.4),
                )
                if not tls
                else []
            )
            smtp_ctx = SmtpContext(
                helo=self._email_server_fqdn(src_system.hostname),
                mailfrom=sender,
                rcptto=hop.get("recipients")
                or (envelope_recipients if index == 0 else expanded_recipients),
                date=date_header,
                from_header=email_ctx.header_from,
                to_header=[*email_ctx.to, *[self._email_header_address(addr) for addr in spec.cc]],
                msg_id=message_id,
                subject=subject,
                last_reply=last_reply,
                path=[dst_system.ip, src_system.ip],
                user_agent=user_agent,
                tls=tls,
                encrypted_message=tls,
                fuids=[file_transfer.fuid for file_transfer in mime_file_transfers],
            )
            ssl_ctx = (
                self._smtp_starttls_ssl_context(
                    src_system=src_system,
                    dst_system=dst_system,
                    message_id=message_id,
                    hop_index=index,
                )
                if tls
                else None
            )
            uid = self.generate_connection(
                src_ip=src_system.ip,
                dst_ip=dst_system.ip,
                time=hop_time,
                dst_port=587 if hop["submission"] else 25,
                proto="tcp",
                service="smtp",
                duration=rng.uniform(0.18, 2.8),
                orig_bytes=max(180, email_ctx.body_size + rng.randint(250, 900)),
                resp_bytes=rng.randint(90, 450),
                conn_state="SF",
                emit_dns=True,
                source_system=(
                    None if "external_mail_server" in (src_system.roles or []) else src_system
                ),
                hostname=self._email_server_fqdn(dst_system.hostname),
                email=email_ctx,
                smtp=smtp_ctx,
                ssl=ssl_ctx,
                file_transfers=mime_file_transfers,
                suppress_application_side_effects=True,
            )
            if uid:
                smtp_uids.append(uid)
            route_summary.append(
                {
                    "src": src_system.hostname,
                    "dst": dst_system.hostname,
                    "port": str(587 if hop["submission"] else 25),
                    "tls": str(tls).lower(),
                    "uid": uid,
                }
            )

        artifact_path = ""
        if self._should_materialize_email_artifact(artifact_id, request.storyline_id):
            artifact_path = self._write_email_artifact(email_ctx)
            email_ctx.artifact_path = artifact_path
        self._record_email_artifact_manifest(email_ctx, route_summary, artifact_path)
        self._maybe_generate_email_recipient_reads(
            email_ctx=email_ctx,
            delivery_time=request.time,
            rng=rng,
        )
        return EmailDeliveryResult(
            artifact_id=artifact_id,
            message_id=message_id,
            sender=sender,
            recipients=expanded_recipients,
            subject=subject,
            outcome=spec.outcome,
            artifact_path=artifact_path,
            smtp_uids=smtp_uids,
            route=route_summary,
        )

    def _email_server_fqdn(self, hostname: str) -> str:
        """Return a stable mail host FQDN for DNS/SMTP headers."""
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is not None:
            for server in email_config.mail_servers:
                if (
                    server.system == hostname
                    or server.name == hostname
                    or server.hostname == hostname
                ):
                    return server.hostname
        ad_domain = getattr(self, "_ad_domain", "")
        if ad_domain and "." not in hostname:
            return f"{hostname}.{ad_domain}"
        return hostname

    @staticmethod
    def _email_domain(address: str) -> str:
        return address.rsplit("@", 1)[-1].lower().rstrip(".")

    @staticmethod
    def _email_header_address(address: str) -> str:
        return f"<{address.lower()}>"

    def _email_artifact_id(
        self,
        storyline_id: str,
        sender: str,
        recipients: list[str],
        time: datetime,
    ) -> str:
        seed = _stable_seed(
            f"email_artifact:{storyline_id}:{sender}:{','.join(recipients)}:{time.isoformat()}"
        )
        prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", storyline_id or "email").strip("-")[:40]
        return f"{prefix or 'email'}-{seed:012x}"

    def _email_message_id(self, artifact_id: str, sender: str, user_agent: str = "") -> str:
        domain = self._email_domain(sender)
        seed_hi = _stable_seed(f"email_message_id_hi:{artifact_id}:{sender}:{user_agent}")
        seed_lo = _stable_seed(f"email_message_id_lo:{artifact_id}:{sender}:{user_agent}")
        profile = self._email_mailer_profile(sender, user_agent)
        if profile == "thunderbird":
            return f"<{seed_hi}.{seed_lo % 1_000_000}.{seed_lo:08x}@{domain}>"
        if profile == "apple_mail":
            uuid_like = uuid.UUID(int=((seed_hi << 64) | seed_lo) & ((1 << 128) - 1))
            return f"<{str(uuid_like).upper()}@{domain}>"
        if profile == "service":
            token = re.sub(r"[^a-z0-9]+", "-", sender.split("@", 1)[0].lower()).strip("-")
            token = token or "notice"
            queue_fragment = seed_hi & 0xFFFFFFFF
            sequence_fragment = seed_lo % 10_000_000
            return f"<{token}-{queue_fragment:08x}-{sequence_fragment:07d}@{domain}>"
        mailbox_id = f"{seed_hi & 0xFFFF:04X}{seed_lo & 0xFFFF:04X}"
        left_fragment = seed_hi & 0xFFFFFFFF
        right_fragment = seed_lo & 0xFFFFFFFF
        return f"<{left_fragment:08x}{right_fragment:08x}@{mailbox_id}.{domain}>"

    @staticmethod
    def _email_mailer_profile(sender: str, user_agent: str) -> str:
        """Return a coarse source-native mailer profile for headers and IDs."""
        agent = user_agent.lower()
        local_part = sender.split("@", 1)[0].lower()
        domain = ActivityGenerator._email_domain(sender)
        if "thunderbird" in agent:
            return "thunderbird"
        if "apple mail" in agent:
            return "apple_mail"
        if any(marker in agent for marker in ("docflow", "mailer", "notification", "service")):
            return "service"
        if any(
            marker in local_part
            for marker in ("alert", "notice", "notification", "workspace", "billing", "support")
        ):
            return "service"
        if any(marker in domain for marker in ("service", "notify", "news", "vendor")):
            return "service"
        return "outlook"

    def _deterministic_email_subject(
        self,
        sender: str,
        recipients: list[str],
        rng: random.Random,
    ) -> str:
        verbs = [
            "Follow up",
            "Question",
            "Update",
            "Review",
            "Schedule",
            "Notes",
            "Revised",
            "Confirming",
            "Reminder",
            "Draft",
            "Closeout",
            "Heads up",
        ]
        nouns = [
            "request",
            "timeline",
            "access",
            "report",
            "meeting",
            "invoice",
            "renewal",
            "change window",
            "vendor packet",
            "forecast",
            "approval",
            "field note",
            "shipping date",
            "badge update",
            "service ticket",
            "training roster",
        ]
        qualifiers = [
            "today",
            "this week",
            "before review",
            "for closeout",
            "from yesterday",
            "for next steps",
            "after the call",
            "for the shared folder",
            "before noon",
        ]
        if recipients:
            domain = self._email_domain(recipients[0])
        else:
            domain = self._email_domain(sender)
        style = rng.randrange(4)
        if style == 0:
            return f"{rng.choice(verbs)}: {rng.choice(nouns)} for {domain.split('.')[0]}"
        if style == 1:
            return f"{rng.choice(nouns).title()} {rng.randint(1040, 9980)} {rng.choice(qualifiers)}"
        if style == 2:
            return f"{rng.choice(verbs)} {rng.choice(nouns)} - {rng.choice(qualifiers)}"
        return f"{domain.split('.')[0].title()} {rng.choice(nouns)} notes"

    def _deterministic_email_body(self, subject: str, rng: random.Random) -> str:
        openings = ["Hi,", "Hello,", "Good morning,", "Team,", "Good afternoon,", "All,"]
        closings = ["Thanks,", "Regards,", "Best,", "Thank you,", "Appreciate it,"]
        details = [
            "I added the latest notes to the shared folder.",
            "The owner list changed after this morning's sync.",
            "Please use the attached dates when you update your tracker.",
            "The vendor asked for confirmation before they close the item.",
            "I am waiting on one more answer, but the current version is usable.",
            "No action is needed if the numbers still match your copy.",
            "Please reply only if you see a mismatch in the current draft.",
            "This is mostly a reminder so the handoff does not get lost.",
        ]
        followups = [
            "I will check back after the next status call.",
            "The next update should be ready later today.",
            "We can fold any corrections into the Friday packet.",
            "I will leave the ticket open until everyone has confirmed.",
            "Please send changes directly to the group thread.",
            "I will archive the old copy once the update is approved.",
        ]
        return (
            f"{rng.choice(openings)}\n\n"
            f"Please see the note below regarding {subject.lower()}. "
            f"{rng.choice(details)} {rng.choice(followups)}\n\n"
            f"{rng.choice(closings)}\n"
        )

    def _email_user_agent(self, system: "System", rng: random.Random) -> str:
        os_category = _get_os_category(system.os)
        client_rng = random.Random(
            _stable_seed(
                "email_user_agent:"
                f"{system.hostname}:{getattr(system, 'assigned_user', '')}:{os_category}"
            )
        )
        if os_category == "windows":
            return client_rng.choice(
                [
                    "Microsoft Outlook 16.0",
                    "Microsoft Office Outlook 12.0",
                    "Microsoft Outlook 15.0",
                ]
            )
        return client_rng.choice(
            ["Thunderbird 115.0", "Evolution 3.44", "Apple Mail (2.3608.120.23.2.7)"]
        )

    def _email_effective_user_agent(self, sender: str, user_agent: str) -> str:
        """Return a profile-compatible mailer fingerprint for generated/corpus mail."""
        profile = self._email_mailer_profile(sender, user_agent)
        if profile != "service":
            return user_agent
        agent = user_agent.lower()
        if not any(marker in agent for marker in ("outlook", "thunderbird", "apple mail")):
            return user_agent
        local_part = sender.split("@", 1)[0].lower()
        domain_label = self._email_domain(sender).split(".", 1)[0]
        label = re.sub(r"[^A-Za-z0-9]+", " ", local_part or domain_label).strip().title()
        label = label or "Notification"
        seed = _stable_seed(f"email_service_user_agent:{sender}")
        return f"{label} Mailer {2 + seed % 4}.{seed % 10}"

    def _smtp_starttls_ssl_context(
        self,
        *,
        src_system: "System",
        dst_system: "System",
        message_id: str,
        hop_index: int,
    ) -> SslContext:
        """Return Zeek SSL metadata for a successful SMTP STARTTLS upgrade."""
        rng = random.Random(
            _stable_seed(
                "smtp_starttls:"
                f"{src_system.hostname}:{dst_system.hostname}:{message_id}:{hop_index}"
            )
        )
        version = rng.choices(_TLS_VERSION_VALUES, weights=(70, 30), k=1)[0]
        if version == "TLSv13":
            cipher = rng.choices(_TLS13_CIPHER_VALUES, weights=_TLS13_CIPHER_WEIGHTS, k=1)[0]
        else:
            cipher = rng.choices(_TLS12_CIPHER_VALUES, weights=_TLS12_CIPHER_WEIGHTS, k=1)[0]
        resumed = rng.random() < 0.12
        return SslContext(
            version=version,
            cipher=cipher,
            server_name=self._email_server_fqdn(dst_system.hostname),
            resumed=resumed,
            established=True,
            ssl_history=_choose_ssl_history(
                rng,
                tls_version=version,
                established=True,
                resumed=resumed,
            ),
        )

    def _email_servers_by_name(self) -> dict[str, Any]:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            return {}
        return {server.name: server for server in email_config.mail_servers}

    def _email_system_for_server_name(self, server_name: str) -> "System":
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        servers = self._email_servers_by_name()
        if server_name == "default" and email_config is not None:
            server_name = email_config.default_mailbox_servers[0]
        server = servers[server_name]
        for system in self._scenario_environment.systems:
            if system.hostname == server.system:
                return system
        raise ValueError(
            f"Email server {server_name!r} references unknown system {server.system!r}"
        )

    def _email_server_for_user_address(self, address: str) -> str:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            raise ValueError("environment.email is not configured")
        user = next(
            (
                candidate
                for candidate in self._scenario_environment.users
                if candidate.email.lower() == address.lower()
            ),
            None,
        )
        if user is not None:
            user_groups = set(user.groups or [])
            for override in email_config.mailbox_overrides:
                if override.group in user_groups:
                    return override.server
        seed = _stable_seed(f"email_mailbox_server:{address}")
        return email_config.default_mailbox_servers[
            seed % len(email_config.default_mailbox_servers)
        ]

    def _expand_email_recipients(self, recipients: list[str]) -> list[str]:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            return recipients
        groups = {group.address.lower(): group for group in email_config.distribution_groups}
        expanded: list[str] = []
        for recipient in recipients:
            group = groups.get(recipient.lower())
            if group is None:
                expanded.append(recipient.lower())
            else:
                expanded.extend(member.lower() for member in group.members)
        return list(dict.fromkeys(expanded))

    def _plan_email_route(
        self,
        sender: str,
        recipients: list[str],
        client_system: "System",
    ) -> list[dict[str, Any]]:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            raise ValueError("environment.email is not configured")
        accepted_domains = set(email_config.accepted_domains)
        internal_recipients = [
            address for address in recipients if self._email_domain(address) in accepted_domains
        ]
        external_recipients = [
            address for address in recipients if self._email_domain(address) not in accepted_domains
        ]
        sender_is_internal = self._email_domain(sender) in accepted_domains
        if not sender_is_internal:
            inbound_server_name = (
                email_config.inbound_route[0]
                if email_config.inbound_route
                else self._email_server_for_user_address(internal_recipients[0])
            )
            inbound_system = self._email_system_for_server_name(inbound_server_name)
            external_mx = self._external_source_mail_system(sender)
            route = [
                self._email_hop(
                    external_mx,
                    inbound_system,
                    submission=False,
                    server_to_server=True,
                    src_server_name="",
                    dst_server_name=inbound_server_name,
                    recipients=internal_recipients,
                )
            ]
            sender_server_name = inbound_server_name
            sender_server_system = inbound_system
        else:
            sender_server_name = self._email_server_for_user_address(sender)
            sender_server_system = self._email_system_for_server_name(sender_server_name)
            route: list[dict[str, Any]] = [
                self._email_hop(
                    client_system,
                    sender_server_system,
                    submission=True,
                    server_to_server=False,
                    src_server_name="",
                    dst_server_name=sender_server_name,
                    recipients=recipients,
                )
            ]
        for server_name in sorted(
            {self._email_server_for_user_address(addr) for addr in internal_recipients}
        ):
            dst_system = self._email_system_for_server_name(server_name)
            if dst_system.ip != sender_server_system.ip:
                route.append(
                    self._email_hop(
                        sender_server_system,
                        dst_system,
                        submission=False,
                        server_to_server=True,
                        src_server_name=sender_server_name,
                        dst_server_name=server_name,
                        recipients=[
                            address
                            for address in internal_recipients
                            if self._email_server_for_user_address(address) == server_name
                        ],
                    )
                )
        if external_recipients:
            outbound_server_name = self._select_outbound_email_server(sender)
            outbound_system = self._email_system_for_server_name(outbound_server_name)
            if outbound_system.ip != sender_server_system.ip:
                route.append(
                    self._email_hop(
                        sender_server_system,
                        outbound_system,
                        submission=False,
                        server_to_server=True,
                        src_server_name=sender_server_name,
                        dst_server_name=outbound_server_name,
                        recipients=external_recipients,
                    )
                )
            if email_config.isp_relays:
                relay_host = email_config.isp_relays[
                    _stable_seed(f"email_isp_relay:{sender}") % len(email_config.isp_relays)
                ]
                route.append(
                    self._external_email_hop(
                        outbound_system,
                        relay_host,
                        outbound_server_name,
                        recipients=external_recipients,
                    )
                )
            else:
                mx_host = self._external_mx_for_domain(self._email_domain(external_recipients[0]))
                route.append(
                    self._external_email_hop(
                        outbound_system,
                        mx_host,
                        outbound_server_name,
                        recipients=external_recipients,
                    )
                )
        return route

    def _email_hop(
        self,
        src_system: "System",
        dst_system: "System",
        *,
        submission: bool,
        server_to_server: bool,
        src_server_name: str,
        dst_server_name: str,
        recipients: list[str],
    ) -> dict[str, Any]:
        servers = self._email_servers_by_name()
        src_cfg = servers.get(src_server_name)
        dst_cfg = servers.get(dst_server_name)
        return {
            "src_system": src_system,
            "dst_system": dst_system,
            "submission": submission,
            "server_to_server": server_to_server,
            "src_server_attempts_starttls": bool(
                src_cfg is not None and src_cfg.attempt_outbound_starttls
            ),
            "dst_server_allows_starttls": bool(
                dst_cfg is not None and dst_cfg.allow_inbound_starttls
            ),
            "external_hostname": "",
            "recipients": list(dict.fromkeys(address.lower() for address in recipients)),
        }

    def _external_email_hop(
        self,
        src_system: "System",
        dst_hostname: str,
        src_server_name: str,
        recipients: list[str],
    ) -> dict[str, Any]:
        servers = self._email_servers_by_name()
        src_cfg = servers.get(src_server_name)
        seed = _stable_seed(f"email_external_mx:{dst_hostname}")
        dst_ip = _generate_random_external_ip(random.Random(seed))
        dst_system = type(src_system)(
            hostname=dst_hostname,
            ip=dst_ip,
            os="Internet SMTP Server",
            type="server",
            services=["smtp"],
            roles=["external_mail_server"],
        )
        return {
            "src_system": src_system,
            "dst_system": dst_system,
            "submission": False,
            "server_to_server": True,
            "src_server_attempts_starttls": bool(
                src_cfg is not None and src_cfg.attempt_outbound_starttls
            ),
            "dst_server_allows_starttls": True,
            "external_hostname": dst_hostname,
            "recipients": list(dict.fromkeys(address.lower() for address in recipients)),
        }

    def _external_source_mail_system(self, sender: str) -> "System":
        domain = self._email_domain(sender)
        hostname = self._external_mx_for_domain(domain)
        seed = _stable_seed(f"email_external_sender:{sender}")
        return type(next(iter(self._scenario_environment.systems)))(
            hostname=hostname,
            ip=_generate_random_external_ip(random.Random(seed)),
            os="Internet SMTP Server",
            type="server",
            services=["smtp"],
            roles=["external_mail_server"],
        )

    def _select_outbound_email_server(self, sender: str) -> str:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            raise ValueError("environment.email is not configured")
        user = next(
            (
                candidate
                for candidate in self._scenario_environment.users
                if candidate.email.lower() == sender.lower()
            ),
            None,
        )
        user_groups = set(user.groups if user is not None else [])
        selected = email_config.outbound_routes[0]
        for route in email_config.outbound_routes:
            if route.sender_groups and user_groups.intersection(route.sender_groups):
                selected = route
                break
            if route.name == "default" and not selected.sender_groups:
                selected = route
        servers = selected.servers
        if servers == ["default"]:
            servers = email_config.default_mailbox_servers
        return servers[_stable_seed(f"email_outbound:{sender}") % len(servers)]

    @staticmethod
    def _external_mx_for_domain(domain: str) -> str:
        safe = re.sub(r"[^a-z0-9.-]+", "", domain.lower()).strip(".")
        return f"mx1.{safe}"

    def _received_headers_for_route(
        self,
        *,
        route: list[dict[str, Any]],
        message_id: str,
        recipients: list[str],
        time: datetime,
    ) -> list[str]:
        headers: list[str] = []
        recipient_clause = f" for <{recipients[0]}>" if len(recipients) == 1 else ""
        for index, hop in enumerate(route):
            by_host = self._email_server_fqdn(hop["dst_system"].hostname)
            from_host = self._email_server_fqdn(hop["src_system"].hostname)
            hop_time = time + timedelta(seconds=index * 4)
            headers.insert(
                0,
                (
                    f"from {from_host} ({hop['src_system'].ip}) by {by_host} "
                    f"with ESMTP id {_stable_seed(f'received:{message_id}:{index}'):08x} "
                    f"{recipient_clause}; {hop_time.strftime('%a, %d %b %Y %H:%M:%S +0000')}"
                ),
            )
        return headers

    def _emit_email_route_dns(
        self,
        route: list[dict[str, Any]],
        time: datetime,
    ) -> None:
        resolver_ips = getattr(self, "_dns_server_ips", []) or ["10.0.0.1"]
        resolver_ip = resolver_ips[0]
        for index, hop in enumerate(route):
            source_system = hop["src_system"]
            if not _is_modeled_local_ip(self, source_system.ip):
                continue
            dst_host = hop.get("external_hostname") or self._email_server_fqdn(
                hop["dst_system"].hostname
            )
            qtype = "MX" if hop.get("external_hostname") else "A"
            answer = dst_host if qtype == "MX" else hop["dst_system"].ip
            dns_ctx = DnsContext(
                query=self._email_domain(dst_host) if qtype == "MX" else dst_host,
                query_type=qtype,
                qtype=15 if qtype == "MX" else 1,
                rcode="NOERROR",
                rcode_num=0,
                answers=[f"10 {answer}" if qtype == "MX" else answer],
                TTLs=[300.0],
                rtt=0.003 + index * 0.0005,
            )
            self.generate_connection(
                src_ip=source_system.ip,
                dst_ip=resolver_ip,
                time=time - timedelta(seconds=max(0.1, 2.0 - index * 0.1)),
                dst_port=53,
                proto="udp",
                service="dns",
                duration=dns_ctx.rtt,
                orig_bytes=60,
                resp_bytes=120,
                conn_state="SF",
                dns=dns_ctx,
                source_system=source_system,
                suppress_application_side_effects=True,
            )
            if qtype == "MX":
                a_ctx = DnsContext(
                    query=answer,
                    query_type="A",
                    qtype=1,
                    rcode="NOERROR",
                    rcode_num=0,
                    answers=[hop["dst_system"].ip],
                    TTLs=[300.0],
                    rtt=0.004 + index * 0.0005,
                )
                self.generate_connection(
                    src_ip=source_system.ip,
                    dst_ip=resolver_ip,
                    time=time - timedelta(seconds=max(0.05, 1.0 - index * 0.1)),
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    duration=a_ctx.rtt,
                    orig_bytes=60,
                    resp_bytes=120,
                    conn_state="SF",
                    dns=a_ctx,
                    source_system=source_system,
                    suppress_application_side_effects=True,
                )

    def _email_mime_file_transfers(
        self,
        *,
        artifact_id: str,
        hop_index: int,
        body: str,
        attachments: list[dict[str, Any]],
        duration: float,
    ) -> list[FileTransferContext]:
        """Return Zeek files.log metadata for all visible SMTP MIME parts."""
        parts: list[dict[str, Any]] = [
            {
                "name": "",
                "mime_type": "text/plain",
                "content": body,
                "size": len(body.encode("utf-8")),
            }
        ]
        for attachment in attachments:
            payload = self._email_attachment_payload_bytes(attachment, artifact_id)
            parts.append(
                {
                    "name": str(attachment.get("filename") or "attachment.bin"),
                    "mime_type": str(attachment.get("content_type") or "application/octet-stream"),
                    "payload": payload,
                    "size": len(payload),
                }
            )
        transfers: list[FileTransferContext] = []
        for depth, part in enumerate(parts):
            content_seed = f"email-mime:{artifact_id}:{depth}:{part['name']}:{part['mime_type']}"
            observation_seed = f"{content_seed}:hop:{hop_index}"
            payload = part.get("payload")
            if payload is None:
                payload = str(part.get("content") or "").encode("utf-8")
            size = max(0, int(part["size"]))
            analyzers = ["MD5", "SHA1", "SHA256"]
            transfers.append(
                FileTransferContext(
                    fuid=f"F{_stable_seed(observation_seed):017x}"[:18],
                    source="SMTP",
                    depth=depth,
                    filename=str(part["name"]),
                    analyzers=analyzers,
                    mime_type=str(part["mime_type"]),
                    duration=max(0.001, duration * (1.0 + depth * 0.15)),
                    local_orig=True,
                    is_orig=True,
                    seen_bytes=size,
                    total_bytes=size,
                    missing_bytes=0,
                    overflow_bytes=0,
                    timedout=False,
                    md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                    sha1=hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
        return transfers

    @staticmethod
    def _email_attachment_payload_bytes(
        attachment: dict[str, Any],
        artifact_id: str,
    ) -> bytes:
        """Return the canonical bytes for an email attachment payload."""
        content = attachment.get("content")
        if content is not None:
            return str(content).encode("utf-8")
        size = max(0, int(attachment.get("size") or 0))
        if size == 0:
            return b""
        seed = (
            f"email-attachment:{artifact_id}:"
            f"{attachment.get('filename') or 'attachment.bin'}:"
            f"{attachment.get('content_type') or 'application/octet-stream'}"
        ).encode()
        repeats = (size // len(seed)) + 1
        return (seed * repeats)[:size]

    def _maybe_generate_email_recipient_reads(
        self,
        *,
        email_ctx: EmailContext,
        delivery_time: datetime,
        rng: random.Random,
    ) -> None:
        """Generate low-rate opaque mailbox reads after delivered internal mail."""
        if email_ctx.outcome != "delivered":
            return
        users_by_email = {
            user.email.lower(): user for user in self._scenario_environment.users if user.email
        }
        for recipient in email_ctx.expanded_rcptto[:8]:
            user = users_by_email.get(recipient.lower())
            if user is None:
                continue
            if rng.random() > 0.72:
                continue
            system = self._system_for_email_user(user)
            if system is None:
                continue
            server_name = self._email_server_for_user_address(recipient)
            server_system = self._email_system_for_server_name(server_name)
            server_cfg = self._email_servers_by_name()[server_name]
            read_delay = timedelta(seconds=rng.uniform(90.0, 2700.0))
            read_time = delivery_time + read_delay
            if not self._is_within_scenario_window(read_time):
                continue
            protocol = "owa" if server_cfg.platform == "exchange" else "imaps"
            self.generate_email_access(
                user=user,
                system=system,
                server=server_system,
                time=read_time,
                platform=server_cfg.platform,
                protocol=protocol,
                user_agent=email_ctx.user_agent,
                message_ids=(email_ctx.message_id, email_ctx.artifact_id),
            )

    def _system_for_email_user(self, user: "User") -> "System | None":
        """Return a user's likely mailbox client system."""
        if user.primary_system:
            system = next(
                (
                    candidate
                    for candidate in self._scenario_environment.systems
                    if candidate.hostname == user.primary_system
                ),
                None,
            )
            if system is not None:
                return system
        return next(
            (
                candidate
                for candidate in self._scenario_environment.systems
                if candidate.assigned_user == user.username
            ),
            None,
        )

    def _should_materialize_email_artifact(self, artifact_id: str, storyline_id: str) -> bool:
        email_config = getattr(getattr(self, "_scenario_environment", None), "email", None)
        if email_config is None:
            return False
        mode = email_config.artifacts.mode
        if mode == "none":
            return False
        if mode in {"storyline", "all"}:
            return bool(storyline_id) or mode == "all"
        return artifact_id in set(email_config.artifacts.selected_ids) or storyline_id in set(
            email_config.artifacts.selected_ids
        )

    def _write_email_artifact(self, email_ctx: EmailContext) -> str:
        artifact_dir = getattr(self, "_email_artifact_dir", None)
        if artifact_dir is None:
            return ""
        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / f"{email_ctx.artifact_id}.eml"
        path.write_bytes(self._render_email_artifact(email_ctx).encode("utf-8"))
        return path.relative_to(artifact_dir.parent.parent).as_posix()

    def _render_email_artifact(self, email_ctx: EmailContext) -> str:
        """Render a deterministic MIME message with profile-specific header texture."""
        profile = self._email_mailer_profile(email_ctx.envelope_from, email_ctx.user_agent)
        has_attachments = bool(email_ctx.attachments)
        boundary = self._email_mime_boundary(email_ctx.artifact_id, profile)
        header_lines = self._email_artifact_header_lines(
            email_ctx,
            profile=profile,
            boundary=boundary,
            has_attachments=has_attachments,
        )
        if not has_attachments:
            body = self._quoted_printable_text(email_ctx.body or "")
            return "\r\n".join([*header_lines, "", body, ""])

        parts = [
            f"--{boundary}",
            'Content-Type: text/plain; charset="utf-8"',
            "Content-Transfer-Encoding: quoted-printable",
            "",
            self._quoted_printable_text(email_ctx.body or ""),
            "",
        ]
        for attachment in email_ctx.attachments:
            payload = self._email_attachment_payload_bytes(attachment, email_ctx.artifact_id)
            content_type = str(attachment.get("content_type") or "application/octet-stream")
            filename = self._sanitize_email_header_value(
                str(attachment.get("filename") or "attachment.bin")
            )
            parts.extend(
                [
                    f"--{boundary}",
                    f'Content-Type: {content_type}; name="{filename}"',
                    "Content-Transfer-Encoding: base64",
                    f'Content-Disposition: attachment; filename="{filename}"',
                    "",
                    *self._base64_mime_lines(payload),
                    "",
                ]
            )
        parts.append(f"--{boundary}--")
        parts.append("")
        return "\r\n".join([*header_lines, "", *parts])

    def _email_artifact_header_lines(
        self,
        email_ctx: EmailContext,
        *,
        profile: str,
        boundary: str,
        has_attachments: bool,
    ) -> list[str]:
        """Return source-native-ish ordered message headers for one mailer profile."""
        header_values = {
            "Return-Path": email_ctx.header_from,
            "Date": email_ctx.date_header,
            "From": email_ctx.header_from,
            "To": ", ".join(email_ctx.to),
            "Cc": ", ".join(email_ctx.cc),
            "Subject": email_ctx.subject,
            "Message-ID": email_ctx.message_id,
            "MIME-Version": "1.0",
            "Content-Type": (
                f'multipart/mixed; boundary="{boundary}"'
                if has_attachments
                else 'text/plain; charset="utf-8"'
            ),
            "Content-Transfer-Encoding": "" if has_attachments else "quoted-printable",
        }
        generated_mailer_header = self._email_profile_mailer_header(
            profile,
            email_ctx.user_agent,
        )
        if generated_mailer_header is not None:
            header_values[generated_mailer_header[0]] = generated_mailer_header[1]
        if profile == "outlook":
            header_values["Thread-Topic"] = email_ctx.subject
            if has_attachments:
                header_values["X-MS-Has-Attach"] = "yes"
        if profile == "service":
            header_values["Auto-Submitted"] = "auto-generated"
            header_values["X-Auto-Response-Suppress"] = "All"

        owned_headers = {
            "return-path",
            "received",
            "date",
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "message-id",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
            "thread-topic",
            "x-ms-has-attach",
            "user-agent",
            "x-mailer",
            "auto-submitted",
            "x-auto-response-suppress",
        }
        custom_headers = [
            (str(header), str(value))
            for header, value in email_ctx.custom_headers.items()
            if str(header).lower() not in owned_headers
        ]
        custom_header_names = {header.lower() for header, _ in custom_headers}

        lines = [
            self._format_email_header("Received", received)
            for received in email_ctx.received_headers
        ]
        order = self._email_profile_header_order(profile, has_attachments)
        custom_inserted = False
        for header in order:
            if header == "_CUSTOM":
                lines.extend(
                    self._format_email_header(custom_header, custom_value)
                    for custom_header, custom_value in custom_headers
                )
                custom_inserted = True
                continue
            if header in {"X-Mailer", "User-Agent"} and header.lower() in custom_header_names:
                continue
            value = header_values.get(header, "")
            if value:
                lines.append(self._format_email_header(header, value))
        if not custom_inserted:
            for header, value in custom_headers:
                lines.append(self._format_email_header(header, value))
        return lines

    @staticmethod
    def _email_profile_header_order(profile: str, has_attachments: bool) -> list[str]:
        """Return the deterministic header order for a coarse mailer profile."""
        if profile == "thunderbird":
            return [
                "Return-Path",
                "Date",
                "From",
                "To",
                "Cc",
                "Subject",
                "Message-ID",
                "User-Agent",
                "_CUSTOM",
                "MIME-Version",
                "Content-Type",
                "Content-Transfer-Encoding",
            ]
        if profile == "apple_mail":
            return [
                "Return-Path",
                "From",
                "To",
                "Cc",
                "Subject",
                "Date",
                "Message-ID",
                "X-Mailer",
                "_CUSTOM",
                "MIME-Version",
                "Content-Type",
                "Content-Transfer-Encoding",
            ]
        if profile == "service":
            return [
                "Return-Path",
                "Date",
                "From",
                "To",
                "Cc",
                "Message-ID",
                "Subject",
                "Auto-Submitted",
                "X-Auto-Response-Suppress",
                "X-Mailer",
                "_CUSTOM",
                "MIME-Version",
                "Content-Type",
                "Content-Transfer-Encoding",
            ]
        return [
            "Return-Path",
            "From",
            "To",
            "Cc",
            "Subject",
            "Date",
            "Message-ID",
            "Thread-Topic",
            "X-MS-Has-Attach",
            "X-Mailer",
            "_CUSTOM",
            "MIME-Version",
            "Content-Type",
            "Content-Transfer-Encoding",
        ]

    @staticmethod
    def _email_profile_mailer_header(
        profile: str,
        user_agent: str,
    ) -> tuple[str, str] | None:
        """Return the profile-appropriate visible mailer header."""
        if not user_agent:
            return None
        if profile == "thunderbird":
            return "User-Agent", user_agent
        return "X-Mailer", user_agent

    @staticmethod
    def _email_mime_boundary(artifact_id: str, profile: str) -> str:
        seed_hi = _stable_seed(f"email_mime_boundary:{profile}:{artifact_id}:hi")
        seed_lo = _stable_seed(f"email_mime_boundary:{profile}:{artifact_id}:lo")
        if profile == "outlook":
            return f"_004_{seed_hi:016X}{seed_lo:016X}_"
        if profile == "thunderbird":
            return f"------------{seed_hi:012x}{seed_lo & 0xFFFFFF:06x}"
        if profile == "apple_mail":
            return f"Apple-Mail=_${seed_hi:08X}-{seed_lo:08X}"
        return f"----=_Part_{seed_hi % 1000000}_{seed_lo}"

    @staticmethod
    def _sanitize_email_header_value(value: str) -> str:
        return " ".join(value.replace("\r", " ").replace("\n", " ").split())

    def _format_email_header(self, header: str, value: str) -> str:
        safe_header = re.sub(r"[^A-Za-z0-9-]+", "-", header).strip("-") or "X-Header"
        return f"{safe_header}: {self._sanitize_email_header_value(str(value))}"

    @staticmethod
    def _quoted_printable_text(text: str) -> str:
        encoded = quopri.encodestring(text.encode("utf-8"), quotetabs=False).decode("ascii")
        return encoded.replace("\n", "\r\n").rstrip("\r\n")

    @staticmethod
    def _base64_mime_lines(payload: bytes) -> list[str]:
        if not payload:
            return [""]
        return [
            base64.b64encode(payload[index : index + 57]).decode("ascii")
            for index in range(0, len(payload), 57)
        ]

    def _record_email_artifact_manifest(
        self,
        email_ctx: EmailContext,
        route: list[dict[str, str]],
        artifact_path: str,
    ) -> None:
        manifest = getattr(self, "_email_artifact_manifest", None)
        if manifest is None:
            self._email_artifact_manifest = []
            manifest = self._email_artifact_manifest
        manifest.append(
            {
                "artifact_id": email_ctx.artifact_id,
                "message_id": email_ctx.message_id,
                "sender": email_ctx.envelope_from,
                "to": email_ctx.to,
                "cc": email_ctx.cc,
                "bcc": email_ctx.bcc,
                "expanded_rcptto": email_ctx.expanded_rcptto,
                "subject": email_ctx.subject,
                "date": email_ctx.date_header,
                "outcome": email_ctx.outcome,
                "verdict": email_ctx.verdict,
                "mail_action": email_ctx.mail_action,
                "artifact_path": artifact_path,
                "route": route,
                "received_headers": email_ctx.received_headers,
                "storyline_id": email_ctx.storyline_id,
            }
        )

    def write_email_artifact_manifest(self) -> None:
        """Write EMAIL_ARTIFACTS.json when email artifact metadata exists."""
        manifest = getattr(self, "_email_artifact_manifest", None)
        artifact_dir = getattr(self, "_email_artifact_dir", None)
        if artifact_dir is None or manifest is None:
            return
        import json

        artifact_dir.mkdir(parents=True, exist_ok=True)
        path = artifact_dir / "EMAIL_ARTIFACTS.json"
        payload = {
            "schema_version": "1.0",
            "messages": sorted(
                manifest,
                key=lambda item: (item.get("storyline_id") or "", item.get("artifact_id") or ""),
            ),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _execute_network_connection_bundle(self, request: NetworkConnectionRequest) -> str:
        """Expand one network connection request into canonical evidence."""
        src_ip = request.src_ip
        dst_ip = request.dst_ip
        time = request.time
        dst_port = request.dst_port
        proto = request.proto
        service = request.service
        duration = request.duration
        orig_bytes = request.orig_bytes
        resp_bytes = request.resp_bytes
        explicit_orig_bytes = request.orig_bytes
        explicit_resp_bytes = request.resp_bytes
        src_port = request.src_port
        emit_dns = request.emit_dns
        pid = request.pid
        source_system = request.source_system
        conn_state = request.conn_state
        dns = request.dns
        email = request.email
        smtp = request.smtp
        ids = request.ids
        http = request.http
        caller_supplied_http = http is not None
        file_transfer = request.file_transfer
        file_transfers = request.file_transfers
        pe = request.pe
        ocsp = request.ocsp
        proxy = request.proxy
        firewall = request.firewall
        hostname = request.hostname
        proxy_bypass = request.proxy_bypass
        process_image = request.process_image
        preserve_dst_ip = request.preserve_dst_ip
        preserve_http_outcome = request.preserve_http_outcome
        suppress_application_side_effects = request.suppress_application_side_effects
        preserve_explicit_payload = request.preserve_explicit_payload
        packet_overhead_bytes = request.packet_overhead_bytes
        responding_pid = request.responding_pid

        from evidenceforge.events.contexts import NetworkContext

        self._last_connection_effective_tuple = None
        self._last_connection_effective_time = None

        if http is not None:
            http = _normalize_http_context_for_source_native_response(http)

        caller_provided_duration = duration is not None
        caller_provided_conn_state = conn_state is not None
        caller_provided_payload = (
            service is not None
            and duration is not None
            and (orig_bytes or 0) > 0
            and (resp_bytes or 0) > 0
        )
        if http is not None and proto == "tcp" and conn_state is None:
            conn_state = "SF"
        process_exe = (process_image or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        is_tcp_probe = process_exe in {"nmap", "nmap.exe"}
        if source_system is None and hasattr(self, "_ip_to_system"):
            source_system = self._ip_to_system.get(src_ip)
        if service == "kerberos" and dst_port == 88 and proto == "tcp":
            from evidenceforge.generation.activity.kerberos_realism import (
                pick_kerberos_transport,
            )

            proto = pick_kerberos_transport(
                random.Random(
                    _stable_seed(
                        "kerberos_transport:"
                        f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                    )
                )
            )
        if service == "kerberos" and dst_port == 88 and proto == "udp":
            udp_kerberos_rng = random.Random(
                _stable_seed(
                    "kerberos_udp_shape:"
                    f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                )
            )
            duration = min(
                duration if duration is not None else udp_kerberos_rng.uniform(0.003, 0.075),
                udp_kerberos_rng.uniform(0.035, 0.16),
            )
            orig_bytes = min(
                max(orig_bytes or udp_kerberos_rng.randint(180, 900), 160),
                udp_kerberos_rng.randint(700, 1300),
            )
            resp_bytes = min(
                max(resp_bytes or udp_kerberos_rng.randint(120, 1200), 80),
                udp_kerberos_rng.randint(600, 1400),
            )
            if conn_state not in {None, "SF", "S0", "REJ", "OTH"}:
                conn_state = "SF" if resp_bytes else "S0"

        if (
            http is None
            and pid > 0
            and source_system is not None
            and proto == "tcp"
            and (dst_port in {80, 443, 8080} or service is None or service in {"http", "ssl"})
        ):
            proc = self.state_manager.get_process(source_system.hostname, pid)
            if proc is not None:
                command_http = _http_context_from_process_command(
                    proc.image,
                    proc.command_line,
                    response_body_len=resp_bytes or _get_rng().randint(500, 50000),
                )
                if command_http is not None:
                    command_http_context, command_host, command_port, command_service = command_http
                    command_target = self._system_for_hostname(command_host)
                    host_lower = command_host.lower().rstrip(".")
                    ad_domain_for_command = (
                        str(
                            getattr(self, "_ad_domain", "") or "",
                        )
                        .lower()
                        .rstrip(".")
                    )
                    command_is_unknown_internal = command_target is None and (
                        host_lower.endswith(".local")
                        or (
                            ad_domain_for_command
                            and host_lower.endswith(f".{ad_domain_for_command}")
                        )
                    )
                    if not command_is_unknown_internal:
                        http = command_http_context
                        hostname = command_host
                        dst_port = command_port
                        service = command_service
                        if command_target is not None:
                            dst_ip = command_target.ip
                            emit_dns = True

        # Resolve hostname ONCE for DNS/proxy consistency.
        # All downstream uses (causal DNS expansion, proxy hostname)
        # share this single resolved value instead of doing independent lookups.
        #
        # hostname semantics (preserved through all downstream builders):
        #   None  → auto-resolve from REVERSE_DNS or generate random
        #   ""    → suppress resolution (raw-IP C2, exposed hosts w/o public_hostnames)
        #   "x.y" → use this hostname explicitly
        hostname_was_explicit = hostname not in (None, "")
        hostname_from_reverse_dns = False
        if hostname is None:
            reverse_hostname = REVERSE_DNS.get(dst_ip)
            if reverse_hostname is not None:
                hostname = reverse_hostname
                hostname_from_reverse_dns = True
            elif emit_dns and proto == "tcp" and dst_port not in (53,) and _is_private_ip(dst_ip):
                hostname = _generate_internal_hostname(
                    _get_rng(), dst_ip, getattr(self, "_ad_domain", "corp.local")
                )
            else:
                hostname = None
        if hostname is None and emit_dns and proto == "tcp" and dst_port not in (53,):
            if not _is_private_ip(dst_ip):
                hostname = _generate_random_hostname(_get_rng(), dst_ip)

        proxy_routes = getattr(self, "_proxy_routes", {})
        proxy_chain = proxy_routes.get(src_ip)
        preserve_explicit_proxy_dst_ip = (
            preserve_dst_ip
            and hostname_was_explicit
            and not proxy_bypass
            and getattr(self, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and dst_port in (80, 443)
        )

        if (
            hostname
            and hostname_was_explicit
            and not preserve_dst_ip
            and not preserve_explicit_proxy_dst_ip
            and not (service == "dns" and proto in ("udp", "tcp") and dst_port == 53)
        ):
            from evidenceforge.generation.activity.dns_registry import get_domain_ips

            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(self, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if (
                resolved is not None
                and resolved.source == "scenario_identity"
                and resolved.ip
                and dst_ip != resolved.ip
            ):
                dst_ip = resolved.ip
            elif resolved is not None and resolved.source == "stable_fallback":
                pass
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                domain_ips = get_domain_ips(hostname)
                if domain_ips and dst_ip not in domain_ips:
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)
                elif not domain_ips and emit_dns and not _is_private_ip(dst_ip):
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        ad_domain = getattr(self, "_ad_domain", "corp.local")
        hostname_is_external = (
            bool(hostname)
            and "." in hostname
            and not hostname.endswith(f".{ad_domain}")
            and not hostname.endswith(".local")
        )
        proxyable_external_destination = hostname_is_external or not _is_private_ip(dst_ip)
        dns_server_ips = set(getattr(self, "_dns_server_ips", []))
        if (
            proto == "tcp"
            and dst_port in (80, 443)
            and hostname_is_external
            and dst_ip in dns_server_ips
        ):
            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(self, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if resolved is not None and resolved.ip:
                dst_ip = resolved.ip
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        # Infer common payload service from destination port before proxy
        # routing and DNS expansion. Some callers provide only port/protocol or
        # source-common aliases (for example "https"); explicit proxy semantics
        # still need to catch 80/443 before a client-side origin DNS lookup is
        # emitted. Keep the empty-string raw-TCP sentinel unchanged.
        if proto == "tcp" and dst_port in (80, 443) and service != "" and not is_tcp_probe:
            service = "http" if dst_port == 80 else "ssl"
        if proto == "udp" and dst_port == 123 and (service != "" or (resp_bytes or 0) > 0):
            service = "ntp"
            if not _is_private_ip(dst_ip):
                from evidenceforge.generation.activity.network_params import public_ntp_ips

                configured_ntp_ips = set(public_ntp_ips())
                if configured_ntp_ips and dst_ip not in configured_ntp_ips:
                    selected_ntp_ip = _select_public_ntp_ip(src_ip, dst_ip, time)
                    if selected_ntp_ip:
                        dst_ip = selected_ntp_ip

        if (
            proto == "tcp"
            and service == "ssl"
            and dst_port == 443
            and emit_dns
            and dns is None
            and http is None
            and not hostname_was_explicit
            and _is_private_ip(src_ip)
            and not _is_private_ip(dst_ip)
        ):
            hostname, dst_ip = self._pick_profiled_tls_destination(
                rng=_get_rng(),
                src_ip=src_ip,
                source_system=source_system,
                purpose_tags=("web", "saas", "background"),
            )

        self._last_connection_effective_dst_ip = dst_ip

        tls_hostname = hostname
        if hostname_from_reverse_dns and not emit_dns and dns is None and http is None:
            # A PTR/reverse-DNS-style fallback is useful for proxy URL rendering
            # but should not become TLS SNI unless the client actually resolved
            # or was explicitly configured to use that hostname.
            tls_hostname = ""

        will_route_explicit_proxy = (
            not proxy_bypass
            and getattr(self, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and proxyable_external_destination
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        )

        if http is not None and not preserve_http_outcome and not will_route_explicit_proxy:
            http = _apply_plaintext_http_policy(
                http,
                hostname=hostname,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

        explicit_proxy = will_route_explicit_proxy
        if explicit_proxy:
            proxy_request = ProxyTransactionRequest(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                src_port=src_port,
                pid=pid,
                source_system=source_system,
                conn_state=conn_state,
                dns=dns,
                ids=ids,
                http=http,
                file_transfer=file_transfer,
                ocsp=ocsp,
                proxy=proxy,
                firewall=firewall,
                hostname=hostname,
                process_image=process_image,
                proxy_chain=list(proxy_chain),
                preserve_explicit_proxy_dst_ip=preserve_explicit_proxy_dst_ip,
                caller_provided_conn_state=caller_provided_conn_state,
                ad_domain=ad_domain,
            )
            return ProxyTransactionActionBundle(
                request=proxy_request,
                executor=self,
            ).execute()

        # Emit DNS lookup before connection via causal expansion.
        # The DnsBeforeConnection rule handles caching, SERVFAIL, multi-answer, etc.
        # Only internal hosts generate DNS lookups — external source IPs (e.g.,
        # attacker IPs in storylines) don't query the victim's internal resolver.
        src_ip_is_local = _is_modeled_local_ip(self, src_ip)
        dst_ip_is_local = _is_modeled_local_ip(self, dst_ip)
        force_visible_prereq_dns = (
            source_system is not None
            and "forward_proxy" in (source_system.roles or [])
            and hostname_is_external
            and proto == "tcp"
            and dst_port in (80, 443)
            and src_ip_is_local
        )
        if force_visible_prereq_dns:
            self._emit_dns_lookup(
                src_ip,
                dst_ip,
                time,
                hostname=hostname,
                force_address=True,
            )
        elif emit_dns and proto == "tcp" and dst_port not in (53,) and src_ip_is_local:
            self._expand_and_emit(
                "connection",
                time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                service=service,
                hostname=hostname,
            )

        # Same-host connections are valid for host-based logs (eCAR FLOW)
        # but invisible to network sensors (Zeek/Snort)
        local_only = src_ip == dst_ip

        # Validate connection is not fundamentally invalid (localhost, link-local, multicast)
        is_invalid, reason = _is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            logger.warning(
                "Skipping invalid network connection: %s:%s -> %s:%s proto=%s. "
                "Reason: %s. Check that all systems have routable IPs in the scenario.",
                src_ip,
                src_port or "?",
                dst_ip,
                dst_port,
                proto,
                reason,
            )
            return ""

        is_fw_deny = firewall is not None and firewall.action == "deny"

        resolved_source_system = source_system
        if (
            resolved_source_system is None
            and hasattr(self, "_ip_to_system")
            and src_ip in self._ip_to_system
        ):
            resolved_source_system = self._ip_to_system[src_ip]

        http_application_layer_only = False
        reused_http_uid = ""
        http_persistent_key: tuple[str, str, int, str, str] | None = None
        if http is not None and proto == "tcp" and service == "http" and dst_port > 0:
            http_host_key = (http.host or hostname or dst_ip).lower().rstrip(".")
            http_user_agent_key = (http.user_agent or "").lower()
            http_persistent_key = (
                src_ip,
                dst_ip,
                dst_port,
                http_host_key,
                http_user_agent_key,
            )
            if http.trans_depth > 1:
                cached = self._http_persistent_connections.get(http_persistent_key)
                if cached is not None:
                    reuse_deadline = cached.close_deadline - _HTTP_PERSISTENT_REUSE_GUARD
                    elapsed = (time - reuse_deadline).total_seconds()
                    request_body = http.request_body_len or 0
                    response_body = http.response_body_len or 0
                    fits_parent_flow = (
                        cached.used_orig + request_body <= cached.orig_budget
                        and cached.used_resp + response_body <= cached.resp_budget
                    )
                    if elapsed <= 0 and fits_parent_flow:
                        src_port = cached.src_port
                        reused_http_uid = cached.uid
                        http_application_layer_only = True
                        http = replace(http, trans_depth=cached.next_trans_depth)
                        cached.next_trans_depth += 1
                        cached.used_orig += request_body
                        cached.used_resp += response_body
                    else:
                        self._http_persistent_connections.pop(http_persistent_key, None)
                if not http_application_layer_only:
                    http = replace(http, trans_depth=1)

        kerberos_dc_hostname = None
        if proto in {"tcp", "udp"} and dst_port == 88:
            kerberos_dc = self._dc_system_for_ip(dst_ip)
            if kerberos_dc is not None:
                kerberos_dc_hostname = str(getattr(kerberos_dc, "hostname", "") or "")

        if proto == "icmp":
            src_port = 0
            dst_port = 0
        elif src_port is None:
            if kerberos_dc_hostname:
                src_port = self._find_reserved_kerberos_source_port(
                    src_ip,
                    kerberos_dc_hostname,
                    time,
                    dst_ip=dst_ip,
                )
                if src_port is not None:
                    self._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)
            if src_port is None:
                # Determine source OS for correct ephemeral port range
                _src_os = "windows"
                if resolved_source_system:
                    _src_os = _get_os_category(resolved_source_system.os)
                src_port = self._allocate_ephemeral_port(
                    src_ip, dst_ip, dst_port, proto, time, _src_os
                )
        else:
            self._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)
        if kerberos_dc_hostname and src_port is not None and src_port > 0:
            self._reserve_kerberos_source_port(src_ip, kerberos_dc_hostname, time, src_port)

        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            dns_pid = self._infer_connection_pid(resolved_source_system, service, dst_port, proto)
            if dns_pid > 0:
                pid = dns_pid
        elif pid <= 0:
            pid = self._infer_connection_pid(resolved_source_system, service, dst_port, proto)

        resolved_process = None
        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            query_len = len(dns.query) if dns is not None and dns.query else 12
            query_type = (dns.query_type if dns is not None else "").upper()
            min_query_payload = max(40, query_len + 16)
            if query_type in {"TXT", "NULL"}:
                min_query_payload += 18
            elif query_type == "SRV":
                min_query_payload += 10
            if orig_bytes is None or orig_bytes < min_query_payload:
                orig_bytes = min_query_payload
            if dns is not None and dns.rtt is not None:
                duration = max(duration or 0.001, dns.rtt)

        if pid > 0 and resolved_source_system:
            resolved_process = self.state_manager.get_process(resolved_source_system.hostname, pid)
            if (
                resolved_process
                and resolved_process.start_time
                and time < resolved_process.start_time
            ):
                logger.debug(
                    "Dropping future connection PID attribution: "
                    "host=%s pid=%s process_start=%s connection_time=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.start_time,
                    time,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
            elif (
                resolved_process
                and resolved_process.start_time
                and self._foreground_process_expired_for_attribution(
                    resolved_source_system,
                    resolved_process,
                    time,
                )
            ):
                logger.debug(
                    "Dropping expired foreground process attribution: "
                    "host=%s pid=%s image=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.image,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
            elif resolved_process is None and pid != 4:
                logger.debug(
                    "Dropping stale connection PID attribution: host=%s pid=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    dst_ip,
                    dst_port,
                )
                pid = -1

        if pid > 0 and resolved_source_system is not None and resolved_process is not None:
            time = self._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                time,
                "source.windows_wfp_connection",
            )

        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53 and dns is not None:
            ad_domain = getattr(self, "_ad_domain", "corp.local")
            dns.AA = _dns_is_internal_name(dns.query or "", ad_domain)
            if not is_fw_deny:
                duration, orig_bytes, resp_bytes = _dns_payload_accounting(
                    dns=dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
        elif service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            if hostname and resp_bytes is not None and resp_bytes > 0:
                dns_query = (
                    hostname or REVERSE_DNS.get(dst_ip) or f"host-{dst_ip.replace('.', '-')}"
                )
                fallback_dns = DnsContext(
                    query=dns_query,
                    trans_id=0,
                    qtype=1,
                    query_type="A",
                    rcode="NOERROR",
                    rcode_num=0,
                    answers=[dst_ip],
                    rtt=duration,
                )
                duration, orig_bytes, resp_bytes = _dns_payload_accounting(
                    dns=fallback_dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
            else:
                duration = min(
                    duration
                    or _jitter_default_connection_duration(
                        0.02,
                        caller_provided_duration=False,
                        seed_parts=(src_ip, dst_ip, dst_port, time, "dns_default"),
                    ),
                    0.08,
                )
                orig_bytes = min(max(orig_bytes or 40, 40), 260)
                if resp_bytes is None:
                    resp_bytes = 120
                elif resp_bytes <= 0:
                    resp_bytes = 0
                else:
                    resp_bytes = min(max(resp_bytes, 70), 512)

        if (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is None
            and hostname
        ):
            ad_domain = getattr(self, "_ad_domain", "corp.local")
            dns_cache_key = (src_ip, dst_ip, hostname, "A")
            ts_epoch = time.timestamp()
            cache_ttl = _dns_base_ttl(hostname, _dns_is_internal_name(hostname, ad_domain))
            cached_until = self._dns_cache.get(dns_cache_key, 0)
            if cached_until and cached_until > ts_epoch:
                self._last_connection_effective_dst_ip = dst_ip
                return ""
            self._dns_cache[dns_cache_key] = ts_epoch + cache_ttl

        state_source_system = resolved_source_system.hostname if resolved_source_system else ""
        state_source_hostname = ""
        if resolved_source_system:
            state_source_hostname = self._build_host_context(resolved_source_system).fqdn
        close_time = time + timedelta(seconds=duration) if duration is not None else None

        self._last_connection_effective_dst_ip = dst_ip

        # Phase 1: Allocate IDs from StateManager
        conn_id = self.state_manager.open_connection(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto,
            source_system=state_source_system,
            source_hostname=state_source_hostname,
            hostname=hostname or "",
            initiating_pid=pid,
            close_time=close_time,
        )
        uid = self.state_manager.get_zeek_uid(conn_id)
        if reused_http_uid:
            uid = reused_http_uid
        if orig_bytes is not None and resp_bytes is not None:
            self.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Protocol-aware connection state selection
        rng = _get_rng()

        dns_has_response = (
            proto == "udp"
            and service == "dns"
            and dns is not None
            and (
                dns.rtt is not None
                or bool(dns.answers)
                or dns.rcode.upper() in {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
            )
        )

        # ICMP is connectionless — always OTH regardless of what the caller passed
        if proto == "icmp":
            conn_state = "OTH"
            history = "-"
            src_port = 0  # ICMP has no ports; Zeek emits 0
            dst_port = 0
            if resp_bytes and resp_bytes > 0:
                request_size = _icmp_echo_payload_size(rng, orig_bytes)
                response_size = request_size
                orig_bytes = request_size
                resp_bytes = response_size
                duration = _icmp_echo_duration(rng, duration)
            else:
                orig_bytes = _icmp_echo_payload_size(rng, orig_bytes)
                resp_bytes = 0
                duration = _icmp_echo_duration(rng, duration)
        elif dns_has_response:
            conn_state = "SF"
            history = "Dd"
            orig_bytes = max(orig_bytes or 0, 28)
            resp_bytes = max(resp_bytes or 0, 40)
            if dns.rtt is not None and (duration is None or duration < dns.rtt):
                duration = dns.rtt
        elif conn_state is not None:
            # Explicit conn_state for TCP/UDP (e.g., UFW BLOCK → REJ)
            if proto == "udp":
                history = {
                    "SF": "Dd" if resp_bytes else "D",
                    "S0": "D",
                    "REJ": "D",
                    "OTH": "D",
                }.get(conn_state, "Dd" if resp_bytes else "D")
            else:
                if conn_state == "SF":
                    history = _tcp_success_history(rng)
                else:
                    history = {
                        "REJ": "Sr",
                        "S0": "S",
                        "OTH": "Cc",
                        "S2": "ShADadF",
                        "S3": "ShADadf",
                        "RSTO": "ShADaR",
                        "RSTR": "ShADadR",
                        "S1": "ShR",
                    }.get(conn_state, _tcp_success_history(rng))
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                if service == "dns" and proto == "udp" and dst_port == 53:
                    orig_bytes = max(orig_bytes or 0, 40)
                else:
                    orig_bytes = 0
            elif conn_state in ("S2", "S3"):
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
        elif proto == "udp":
            # DNS connections with responses must not be S0 (no-response)
            if service == "kerberos" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            elif service == "dns" and resp_bytes and resp_bytes > 0:
                # ~5% retransmissions, ~2% multi-packet responses (large TXT/DNSSEC)
                dns_roll = rng.random()
                if dns_roll < 0.05:
                    conn_state, history = "SF", "DDd"  # Retransmitted query
                elif dns_roll < 0.07:
                    conn_state, history = "SF", "Ddd"  # Multi-packet response
                else:
                    conn_state, history = "SF", "Dd"
            elif service == "ntp" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            else:
                entry = rng.choices(_UDP_CONN_ENTRIES, weights=_UDP_CONN_WEIGHTS, k=1)[0]
                conn_state, _, history = entry
            if conn_state == "S0":
                duration = None
                resp_bytes = 0
        else:
            if duration is not None:
                tcp_entries = _TCP_CONN_ENTRIES
                tcp_weights = _TCP_CONN_WEIGHTS
                if caller_provided_payload:
                    candidates = [
                        entry
                        for entry in _TCP_CONN_ENTRIES
                        if entry[0] not in {"S0", "S1", "SH", "SHR", "REJ"}
                    ]
                    if candidates:
                        tcp_entries = candidates
                        tcp_weights = [entry[1] for entry in candidates]
                entry = rng.choices(tcp_entries, weights=tcp_weights, k=1)[0]
                conn_state, _, history = entry
            else:
                conn_state = "S0"
                history = "S"
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                # S0/REJ: Zeek orig_bytes/resp_bytes are payload (application
                # data), not packet overhead.  No handshake completed → zero payload.
                orig_bytes = 0
            elif conn_state in ("S1", "SH", "SHR"):
                # S1/SH/SHR = partial handshake, no application data transferred.
                # Zeek orig_bytes/resp_bytes are payload bytes (always 0 for
                # handshake-only states); IP-byte totals are computed from packet
                # counts + header overhead downstream.
                orig_bytes = 0
                resp_bytes = 0
                if duration is not None:
                    duration = rng.uniform(0.0, 0.5)
            elif conn_state in ("S2", "S3"):
                # S2/S3 = half-closed: connection established, one side sent FIN
                # but the other never replied. Some data transferred before close.
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
            elif conn_state == "OTH":
                # OTH/Cc = midstream capture fragment — minimal data visible
                orig_bytes = rng.randint(0, 200)
                resp_bytes = rng.randint(0, 200)
                if duration is not None:
                    duration = rng.uniform(0.001, 0.5)

        if (
            not suppress_application_side_effects
            and proto == "tcp"
            and dst_port == 443
            and conn_state == "SF"
        ):
            # A completed TLS session with ssl.log/SNI evidence must include
            # at least a ClientHello and server handshake payload at conn.log
            # accounting level, even when the logical request body is empty.
            if http is not None:
                request_body_len = _http_context_flow_body_len(http, "request")
                response_body_len = _http_context_flow_body_len(http, "response")
                request_records = max(1, (request_body_len + 16_383) // 16_384)
                response_records = max(1, (response_body_len + 16_383) // 16_384)
                orig_bytes = (
                    request_body_len + rng.randint(350, 950) + request_records * rng.randint(22, 38)
                )
                resp_bytes = (
                    response_body_len
                    + rng.randint(1200, 5200)
                    + response_records * rng.randint(22, 38)
                )
            else:
                orig_bytes = max(orig_bytes or 0, rng.randint(180, 900))
                resp_bytes = max(resp_bytes or 0, rng.randint(900, 4500))
            tls_min_window = get_timing_window(
                "network.tls_completed_min_duration",
                default_min_ms=800,
                default_max_ms=2500,
                default_position="after",
                default_class="same_observation",
            )
            tls_min_duration = tls_min_window.min_ms / 1000
            if duration is None or duration < tls_min_duration:
                max_extra = max(
                    0.016, min(0.65, (tls_min_window.max_ms - tls_min_window.min_ms) / 1000)
                )
                duration = tls_min_duration + rng.uniform(0.015, max_extra)
            else:
                duration += rng.expovariate(1.0 / 0.35)
                if rng.random() < 0.08:
                    duration += rng.uniform(1.5, 8.0)

        if not suppress_application_side_effects and http is not None and conn_state == "SF":
            http_timing = get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if duration is None or duration < http_min_duration:
                duration = http_min_duration + rng.uniform(0.0, 0.025)

        kerberos_has_response = conn_state not in {"S0", "S1", "SH", "SHR", "REJ", "OTH"} and (
            (resp_bytes or 0) > 0 or conn_state == "SF"
        )
        if kerberos_has_response and not suppress_application_side_effects:
            self._emit_dc_audit_for_kerberos_connection(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                conn_state=conn_state,
                service=service or "",
                source_system=resolved_source_system,
            )

        duration_locked_to_dns_rtt = (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is not None
            and dns.rtt is not None
            and duration is not None
            and math.isclose(duration, dns.rtt, rel_tol=0.0, abs_tol=1e-9)
        )
        duration = _jitter_default_connection_duration(
            duration,
            caller_provided_duration=caller_provided_duration or duration_locked_to_dns_rtt,
            seed_parts=(src_ip, src_port, dst_ip, dst_port, proto, service or "", time),
        )
        kerberos_audit_count = 0
        if (
            not suppress_application_side_effects
            and service == "kerberos"
            and dst_port == 88
            and proto in {"tcp", "udp"}
            and kerberos_dc_hostname
            and src_port is not None
            and src_port > 0
            and not (proto == "tcp" and conn_state in {"S0", "S1", "SH", "SHR", "REJ", "OTH"})
        ):
            kerberos_audit_count = self._kerberos_audit_count_for_connection(
                src_ip,
                kerberos_dc_hostname,
                src_port,
                time,
            )
            if kerberos_audit_count > 0:
                conn_state = "SF"
                min_orig_bytes = kerberos_audit_count * rng.randint(260, 520)
                min_resp_bytes = kerberos_audit_count * rng.randint(320, 760)
                orig_bytes = max(orig_bytes or 0, min_orig_bytes)
                resp_bytes = max(resp_bytes or 0, min_resp_bytes)
                min_duration = kerberos_audit_count * rng.uniform(0.006, 0.022)
                duration = max(duration or 0.0, min_duration)
                if proto == "udp":
                    history = "Dd" * kerberos_audit_count
                else:
                    history = _tcp_success_history(rng)

        if proto == "tcp":
            orig_bytes, resp_bytes = _tcp_payload_bytes_consistent_with_history(
                orig_bytes,
                resp_bytes,
                history,
            )
            self.state_manager.update_connection_bytes(
                conn_id,
                orig_bytes or 0,
                resp_bytes or 0,
            )

        # Calculate packet counts — enforce consistency with history
        if proto == "udp" and history:
            orig_pkts = max(history.count("D"), math.ceil((orig_bytes or 0) / 1232))
            resp_pkts = max(history.count("d"), math.ceil((resp_bytes or 0) / 1232))
            if orig_pkts > 0 and orig_bytes:
                orig_bytes = max(orig_bytes, orig_pkts * 28)
            if resp_pkts > 0 and resp_bytes:
                resp_bytes = max(resp_bytes, resp_pkts * 28)
            elif resp_pkts == 0:
                resp_bytes = 0
        elif proto == "tcp" and history and history != "-":
            orig_pkts, resp_pkts = _tcp_packet_counts_from_payload_and_history(
                orig_bytes,
                resp_bytes,
                history,
                rng,
            )
            if dst_port == 443 and conn_state == "SF":
                orig_pkts += rng.choices([0, 1, 2, 3, 5], weights=[45, 25, 15, 10, 5], k=1)[0]
                resp_pkts += rng.choices([0, 1, 2, 4, 8], weights=[35, 25, 20, 15, 5], k=1)[0]
        elif proto == "icmp":
            orig_pkts = 1
            resp_pkts = 1 if resp_bytes and resp_bytes > 0 else 0
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0
        if kerberos_audit_count > 0:
            orig_pkts = max(orig_pkts, kerberos_audit_count)
            resp_pkts = max(resp_pkts, kerberos_audit_count)

        if proto == "udp" and dst_port == 123:
            orig_bytes, resp_bytes, duration = _ntp_payload_accounting(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                conn_state=conn_state,
                history=history,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                duration=duration,
            )
            orig_pkts = max(1, (history or "").count("D"))
            resp_pkts = (history or "").count("d") if (resp_bytes or 0) > 0 else 0

        if packet_overhead_bytes is not None:
            overhead = packet_overhead_bytes
        elif proto == "udp":
            overhead = rng.choices(_UDP_OVERHEAD_VALUES, weights=_UDP_OVERHEAD_WEIGHTS, k=1)[0]
        elif proto == "icmp":
            overhead = 28
        else:
            overhead = rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
        # Zeek count fields are source-observed IP payload totals. TCP gets
        # per-side header/control texture; UDP/ICMP keeps protocol-specific
        # fixed accounting for source-native packet sizes.
        if proto == "tcp":
            orig_ip_bytes = _tcp_ip_byte_count(
                orig_bytes,
                orig_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
            resp_ip_bytes = _tcp_ip_byte_count(
                resp_bytes,
                resp_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
        else:
            orig_ip_bytes = (orig_bytes or 0) + orig_pkts * overhead
            resp_ip_bytes = (resp_bytes or 0) + resp_pkts * overhead

        ip_proto = 6 if proto == "tcp" else 17 if proto == "udp" else 1

        # Probabilistic missed_bytes for long TCP connections (~3% chance, more for bulk transfers)
        missed_bytes = 0
        if proto == "tcp" and duration and duration > 10.0 and rng.random() < 0.03:
            missed_bytes = rng.randint(500, 50000)

        time = _zeek_conn_observation_time(
            time,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            service or "",
        )
        if proto == "icmp":
            time = self._disambiguate_icmp_observation_time(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                time,
            )
        else:
            self._remember_connection_tuple(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                time,
                duration=duration,
            )
        self.state_manager.update_connection_interval(
            conn_id,
            time,
            time + timedelta(seconds=duration) if duration is not None else None,
        )

        if pid > 0 and resolved_source_system:
            activity_time = time
            if duration is not None:
                activity_time = time + timedelta(seconds=max(0.0, duration))
            self.state_manager.update_process_activity_time(
                resolved_source_system.hostname,
                pid,
                activity_time,
            )

        # Port-based service correction (Zeek detects service from payload, not scenario labels)
        _PORT_SERVICE = {
            80: "http",
            443: "ssl",
            22: "ssh",
            53: "dns",
            25: "smtp",
            587: "smtp",
            88: "kerberos",
            389: "ldap",
            445: "smb",
        }
        if (
            service
            and dst_port in _PORT_SERVICE
            and service != _PORT_SERVICE[dst_port]
            and not is_tcp_probe
        ):
            service = _PORT_SERVICE[dst_port]
        if (
            proto == "tcp"
            and conn_state in {"S0", "REJ", "S1", "SH", "SHR"}
            and service != "dns"
            and http is None
        ):
            service = ""
        if (
            proto == "udp"
            and conn_state in {"S0", "REJ", "OTH"}
            and (orig_bytes or 0) == 0
            and (resp_bytes or 0) == 0
            and service != "dns"
        ):
            service = ""

        # Phase 2: Build SecurityEvent with NetworkContext + HostContext
        # Resolve source system for src_host (needed by eCAR emitter for hostname/routing)
        src_host_ctx = None
        if resolved_source_system:
            src_host_ctx = self._build_host_context(resolved_source_system)

        # Resolve destination system for dst_host
        dst_host_ctx = None
        if hasattr(self, "_ip_to_system") and dst_ip in self._ip_to_system:
            dst_host_ctx = self._build_host_context(self._ip_to_system[dst_ip])
        elif self.dispatcher and self.dispatcher.visibility_engine:
            real_dst_ip = self.dispatcher.visibility_engine._vip_to_real_ip.get(dst_ip)
            if real_dst_ip and real_dst_ip in self._ip_to_system:
                dst_host_ctx = self._build_host_context(self._ip_to_system[real_dst_ip])

        # Resolve eCAR actor_id from initiating process (if pid is known)
        conn_actor_id = ""
        process_ctx = None
        if pid > 0 and resolved_source_system:
            conn_actor_id = self.state_manager.get_process_object_id(
                resolved_source_system.hostname, pid
            )
            running = resolved_process or self.state_manager.get_process(
                resolved_source_system.hostname, pid
            )
            if running is not None:
                process_ctx = ProcessContext(
                    pid=pid,
                    parent_pid=running.parent_pid,
                    image=running.image,
                    command_line=running.command_line,
                    username=running.username,
                    logon_id=running.logon_id,
                    start_time=running.start_time,
                    parent_start_time=self._lookup_parent_start_time(
                        resolved_source_system.hostname, running.parent_pid
                    ),
                )
            elif process_image:
                process_ctx = ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image=process_image,
                    command_line="",
                    username="",
                )

        target_system = None
        if dst_host_ctx is not None and hasattr(self, "_ip_to_system"):
            target_system = self._ip_to_system.get(dst_host_ctx.ip)
        target_has_ssh = target_system is not None and "ssh" in {
            str(service_name).lower() for service_name in (target_system.services or [])
        }
        generic_ssh_preauth_pid: int | None = None
        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and responding_pid <= 0
        ):
            responding_pid = self._resolve_windows_inbound_service_pid(
                target_system,
                dst_port,
                time,
            )
        if (
            dst_host_ctx is not None
            and dst_host_ctx.os_category == "linux"
            and target_system is not None
            and proto == "tcp"
            and dst_port == 22
            and conn_state == "SF"
            and (service in {"", "ssh"} or target_has_ssh)
        ):
            if responding_pid <= 0:
                responding_pid = self.ensure_linux_ssh_responder_process(
                    target_system=target_system,
                    time=time,
                    source_ip=src_ip,
                    source_port=src_port,
                )
                generic_ssh_preauth_pid = responding_pid
            else:
                self._remember_ssh_responder_pid(src_ip, src_port, target_system.ip, responding_pid)

        event = SecurityEvent(
            timestamp=time,
            event_type="connection",
            src_host=src_host_ctx,
            dst_host=dst_host_ctx,
            local_only=local_only,
            process=process_ctx,
            network=NetworkContext(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=service or "",
                zeek_uid=uid,
                conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes,
                resp_ip_bytes=resp_ip_bytes,
                conn_state=conn_state,
                history=history,
                local_orig=src_ip_is_local,
                local_resp=dst_ip_is_local,
                ip_proto=ip_proto,
                missed_bytes=missed_bytes,
                initiating_pid=pid,
                responding_pid=responding_pid,
                application_layer_only=http_application_layer_only,
            ),
            edr=EdrContext(
                object_id=stable_uuid(
                    "connection-edr",
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    proto,
                    time.isoformat(),
                ),
                actor_id=conn_actor_id,
            ),
        )

        # Caller-provided context overrides
        if ids is not None:
            event.ids = ids
        if email is not None:
            event.email = email
        if smtp is not None:
            event.smtp = smtp
        if request.ssl is not None:
            event.ssl = request.ssl
        if http is not None:
            event.http = http
        if file_transfer is not None:
            event.file_transfer = file_transfer
        if file_transfers:
            event.file_transfers = list(file_transfers)
        if pe is not None:
            event.pe = pe
        if ocsp is not None:
            event.ocsp = ocsp
        if proxy is not None:
            event.proxy = proxy
        if firewall is not None:
            event.firewall = firewall

        # DNS context for Zeek dns.log fan-out
        if dns is not None:
            event.dns = dns
            if (
                event.firewall is not None
                and event.firewall.action == "deny"
                and proto in ("udp", "tcp")
                and dst_port == 53
            ):
                event.dns.rcode = "NOERROR"
                event.dns.rcode_num = 0
                event.dns.answers = []
                event.dns.TTLs = []
                event.dns.rtt = None
                event.network.conn_state = "S0"
                event.network.history = "D" if proto == "udp" else "S"
                event.network.duration = None
                event.network.resp_bytes = 0
                event.network.resp_pkts = 0
                event.network.resp_ip_bytes = None
            else:
                self._normalize_dns_context_for_resolver(
                    event.dns,
                    resolver_ip=dst_ip,
                    time=time,
                )
        elif (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and hostname
            and (hostname_was_explicit or dst_ip in dns_server_ips)
            and not is_fw_deny
        ):
            dns_query = hostname or REVERSE_DNS.get(dst_ip) or f"host-{dst_ip.replace('.', '-')}"
            dns_is_internal = _dns_is_internal_name(
                dns_query,
                getattr(self, "_ad_domain", ""),
            )
            dns_answers = [dst_ip] if resp_bytes else []
            event.dns = DnsContext(
                query=dns_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NOERROR" if resp_bytes else "SERVFAIL",
                rcode_num=0 if resp_bytes else 2,
                answers=dns_answers,
                TTLs=self._dns_observed_ttls(
                    resolver_ip=dst_ip,
                    query=dns_query,
                    qtype_name="A",
                    answers=dns_answers,
                    is_internal=dns_is_internal,
                    base_ttl=_dns_base_ttl(dns_query, dns_is_internal),
                    time=time,
                ),
                rtt=_dns_rtt(rng, dst_ip) if resp_bytes else None,
                AA=dns_is_internal,
            )
            if not resp_bytes:
                event.network.conn_state = "SF"
                event.network.history = "Dd"
                event.network.duration = rng.uniform(0.001, 0.03)
                event.network.resp_bytes = rng.randint(80, 220)
                if proto == "udp":
                    event.network.orig_pkts = event.network.history.count("D")
                    event.network.resp_pkts = event.network.history.count("d")
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        event.network.orig_pkts * 28,
                    )
                    event.network.orig_ip_bytes = (
                        event.network.orig_bytes + event.network.orig_pkts * overhead
                    )
                    event.network.resp_ip_bytes = (
                        event.network.resp_bytes + event.network.resp_pkts * overhead
                    )
                else:
                    event.network.resp_pkts = max(event.network.resp_pkts or 0, 1)
                    event.network.resp_ip_bytes = event.network.resp_bytes + overhead
                self.state_manager.update_connection_bytes(
                    event.network.conn_id,
                    event.network.orig_bytes or 0,
                    event.network.resp_bytes or 0,
                )
            if event.dns.rtt is not None:
                event.network.duration = event.dns.rtt

        # Proxy context: attach only for established outbound internet traffic.
        # Forward proxies only see egress that completes (not blocked/denied flows).
        if (
            not local_only
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and event.proxy is None
            and not _is_private_ip(dst_ip)
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        ):
            proxy_routes = getattr(self, "_proxy_routes", {})
            chain = proxy_routes.get(src_ip)
            if chain:
                from evidenceforge.events.contexts import ProxyContext

                proxy_sys = chain[0]
                proxy_fqdn = getattr(proxy_sys, "hostname", "")
                # Build proxy FQDN from hostname + domain
                ad_domain = getattr(self, "_ad_domain", "")
                if ad_domain and "." not in proxy_fqdn:
                    proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
                # Hostname was resolved once at the top of generate_connection().
                proxy_hostname = hostname
                if proxy_hostname is None and dns is not None and dns.query:
                    proxy_hostname = dns.query
                if proxy_hostname is None:
                    proxy_hostname = REVERSE_DNS.get(dst_ip)
                if proxy_hostname is None:
                    proxy_hostname = _generate_random_hostname(_get_rng(), dst_ip)
                # Suppressed hostname → use raw IP for proxy logging
                if proxy_hostname == "":
                    proxy_hostname = dst_ip
                from evidenceforge.generation.activity.dns_registry import get_domain_tags
                from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

                domain_tags = get_domain_tags(proxy_hostname)

                # When a pre-built HttpContext exists (from browsing session
                # generator), derive proxy fields from it.  The proxy emitter
                # handles CONNECT tunnel deduplication automatically.
                if event.http is not None:
                    from evidenceforge.generation.activity.http_content import (
                        normalize_mime_type_for_path,
                    )

                    scheme = "https" if dst_port == 443 else "http"
                    proxy_method = event.http.method
                    url = f"{scheme}://{proxy_hostname}{event.http.uri}"
                    if event.http.resp_mime_types or event.http.status_code == 304:
                        proxy_content_type = normalize_mime_type_for_path(
                            event.http.uri,
                            (
                                event.http.resp_mime_types[0]
                                if event.http.resp_mime_types
                                else "text/html"
                            ),
                        )
                    else:
                        proxy_content_type = "text/html"
                    proxy_ua_override = None  # session UA is already on HttpContext
                    user_agent = event.http.user_agent
                    proxy_referrer = event.http.referrer
                elif dst_port == 443:
                    # Legacy single-connection HTTPS path
                    _src_os = _get_os_category(source_system.os) if source_system else None
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        _get_rng(),
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                    )
                    url = f"https://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=443)
                    )
                else:
                    _src_os = _get_os_category(source_system.os) if source_system else None
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        _get_rng(),
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                    )
                    url = f"http://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=80)
                    )
                # OS-aware proxy User-Agent selection (skip when session set it)
                if event.http is None:
                    if proxy_ua_override:
                        user_agent = proxy_ua_override
                    else:
                        user_agent = pick_proxy_user_agent(
                            rng,
                            source_system,
                            hostname=proxy_hostname,
                            domain_tags=domain_tags,
                        )
                from evidenceforge.generation.activity.proxy_uri import is_browser_like_proxy_domain

                apply_domain_user_agent = event.http is None or (
                    not _is_tool_http_user_agent(event.http.user_agent)
                    and not is_browser_like_proxy_domain(proxy_hostname, domain_tags=domain_tags)
                )
                domain_user_agent = (
                    pick_proxy_domain_user_agent(
                        rng,
                        source_system,
                        hostname=proxy_hostname,
                    )
                    if apply_domain_user_agent
                    else None
                )
                if domain_user_agent:
                    user_agent = domain_user_agent
                user_agent = normalize_proxy_user_agent_for_os(
                    rng,
                    source_system,
                    user_agent,
                    hostname=proxy_hostname,
                    domain_tags=domain_tags,
                )
                proxy_referrer = _source_native_http_referrer(
                    user_agent,
                    proxy_referrer,
                    request_scheme="https" if dst_port == 443 else "http",
                    request_port=dst_port,
                )
                cache_roll = rng.random()
                proxy_cacheable = _proxy_request_allows_cache_hit(
                    method=proxy_method,
                    url=url,
                    content_type=proxy_content_type,
                    domain_tags=domain_tags,
                )
                if event.http is not None:
                    if event.http.status_code == 304:
                        cache_result = "REVALIDATED"
                    elif proxy_cacheable and cache_roll < 0.30 and event.http.status_code < 400:
                        cache_result = "HIT"
                    else:
                        cache_result = "MISS"
                elif proxy_cacheable and cache_roll < 0.30:
                    cache_result = "HIT"
                elif cache_roll < 0.91:
                    cache_result = "MISS"
                elif cache_roll < 0.945:
                    cache_result = "DENIED"
                elif cache_roll < 0.975:
                    cache_result = "AUTH_REQUIRED"
                else:
                    cache_result = "GATEWAY_ERROR"
                # Proxy sc_bytes/cs_bytes are source-side accounting fields:
                # payload plus HTTP/proxy headers for allowed responses,
                # or proxy-generated error pages for failures.
                _cs = (orig_bytes or 0) + rng.randint(*_PROXY_CS_OVERHEAD)
                _response_bytes = (
                    event.http.response_body_len if event.http is not None else (resp_bytes or 0)
                )
                if cache_result == "DENIED":
                    _sc = rng.randint(500, 2000)  # proxy error page
                elif cache_result == "AUTH_REQUIRED":
                    _sc = rng.randint(300, 1200)
                elif cache_result == "GATEWAY_ERROR":
                    _sc = rng.randint(250, 1800)
                elif cache_result == "HIT":
                    _sc = _response_bytes + rng.randint(*_PROXY_SC_OVERHEAD)
                else:
                    _sc = _response_bytes + rng.randint(*_PROXY_SC_OVERHEAD)
                proxy_status_code = (
                    event.http.status_code
                    if event.http is not None
                    else {
                        "DENIED": 403,
                        "AUTH_REQUIRED": 407,
                        "GATEWAY_ERROR": rng.choice([502, 503, 504]),
                    }.get(cache_result, 200)
                )
                event.proxy = ProxyContext(
                    client_ip=src_ip,
                    username=self._proxy_username_for_source(
                        source_system=source_system,
                        user_agent=user_agent,
                        cache_result=cache_result,
                        hostname=proxy_hostname,
                    ),
                    method=proxy_method,
                    url=url,
                    host=proxy_hostname,
                    status_code=proxy_status_code,
                    sc_bytes=_sc,
                    cs_bytes=_cs,
                    time_taken=_proxy_time_taken_ms(
                        duration,
                        rng,
                        method=proxy_method,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                    ),
                    user_agent=user_agent,
                    content_type=proxy_content_type,
                    cache_result=cache_result,
                    referrer=proxy_referrer,
                    proxy_fqdn=proxy_fqdn,
                    proxy_action=_proxy_action_for_context(
                        method=proxy_method,
                        url=url,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                        dst_port=dst_port,
                    ),
                )

        # Zeek protocol-layer contexts: populate SSL/HTTP/files for fan-out
        # Skip for local-only events (no network sensor will see them)
        rng = _get_rng()
        if (
            not suppress_application_side_effects
            and not local_only
            and service == "ssl"
            and proto == "tcp"
            and conn_state == "SF"
        ):
            self._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=not caller_provided_conn_state,
            )
        if (
            proto == "tcp"
            and event.network.conn_state in {"S0", "REJ", "SH", "SHR"}
            and event.network.service in {"http", "ssl"}
            and event.http is None
            and event.ssl is None
        ):
            event.network.service = ""

        elif (
            not local_only
            and not suppress_application_side_effects
            and service == "http"
            and proto == "tcp"
            and conn_state == "SF"
            and event.http is None  # Skip auto-generation if caller provided HttpContext
        ):
            _USER_AGENTS_WINDOWS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            ]
            _USER_AGENTS_LINUX = [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "curl/7.88.1",
                "python-requests/2.31.0",
                "Wget/1.21.3",
            ]
            if source_system and _get_os_category(source_system.os) == "linux":
                ua = rng.choice(_USER_AGENTS_LINUX)
            else:
                ua = rng.choice(_USER_AGENTS_WINDOWS)
            # Use the already-resolved hostname for HTTP Host header and URI templates.
            # Honor hostname="" (suppressed) — use raw IP instead of REVERSE_DNS.
            host = hostname if hostname is not None else REVERSE_DNS.get(dst_ip, dst_ip)
            if host == "":
                host = dst_ip
            if dst_port not in (80, 443):
                host = f"{host}:{dst_port}"
            from evidenceforge.generation.activity.dns_registry import get_domain_tags
            from evidenceforge.generation.activity.http_content import (
                apply_transfer_size_variance,
                coerce_response_size_for_mime,
                http_status_message,
                is_stable_resource_path,
                response_mime_types_for_status,
                response_size_for_status,
            )
            from evidenceforge.generation.activity.proxy_uri import (
                is_browser_like_proxy_domain,
                pick_proxy_uri,
                plaintext_http_redirect_status,
            )

            web_host = hostname if hostname is not None else REVERSE_DNS.get(dst_ip, dst_ip)
            if web_host == "":
                web_host = dst_ip
            web_domain_tags = get_domain_tags(web_host)
            _src_os_http = _get_os_category(source_system.os) if source_system else None
            uri, mime_type, http_method, http_ua_override, http_referrer_policy = pick_proxy_uri(
                rng,
                web_host,
                web_domain_tags,
                source_os=_src_os_http,
                source_system_type=getattr(source_system, "type", None),
            )
            domain_user_agent = pick_proxy_domain_user_agent(
                rng,
                source_system,
                hostname=web_host,
            )
            if domain_user_agent:
                ua = domain_user_agent
            elif http_ua_override:
                ua = http_ua_override
            elif self._is_proxy_server_like_source(
                source_system
            ) or not is_browser_like_proxy_domain(web_host, domain_tags=web_domain_tags):
                ua = pick_proxy_user_agent(
                    rng,
                    source_system,
                    hostname=web_host,
                    domain_tags=web_domain_tags,
                )
            redirect_status = plaintext_http_redirect_status(
                web_host,
                port=dst_port,
                path=uri,
                dst_ip=dst_ip,
            )
            if redirect_status is not None:
                status_code = redirect_status
                status_msg = http_status_message(status_code)
            else:
                status_code, status_msg = _get_http_status(dst_ip, uri)

            if status_code in {204, 304}:
                resp_body_len = 0
            else:
                if status_code >= 300 or is_stable_resource_path(uri):
                    resp_body_len = apply_transfer_size_variance(
                        response_size_for_status(status_code, host, uri),
                        status_code=status_code,
                        host=host,
                        uri=uri,
                        content_type=mime_type,
                        variant_key=f"{src_ip}:{ua}",
                    )
                else:
                    resp_body_len = coerce_response_size_for_mime(rng, mime_type, resp_bytes)
            if event.network.conn_state == "SF" and resp_body_len > (event.network.resp_bytes or 0):
                event.network.resp_bytes = resp_body_len
                min_resp_pkts = max(1, math.ceil(resp_body_len / 1460))
                event.network.resp_pkts = max(event.network.resp_pkts or 0, min_resp_pkts)
                min_resp_ip_bytes = resp_body_len + event.network.resp_pkts * 40
                event.network.resp_ip_bytes = max(
                    event.network.resp_ip_bytes or 0,
                    min_resp_ip_bytes,
                )
            from evidenceforge.generation.activity.referrer import pick_referrer

            _http_referer = (
                ""
                if http_referrer_policy == "none"
                else pick_referrer(rng, host, context="general", port=dst_port)
            )
            _http_referer = _source_native_http_referrer(
                ua,
                _http_referer,
                request_scheme="https" if dst_port == 443 else "http",
                request_port=dst_port,
            )
            event.http = HttpContext(
                method=http_method,
                host=host,
                uri=uri,
                version="1.1",
                user_agent=ua,
                request_body_len=rng.randint(50, 2000) if http_method == "POST" else 0,
                response_body_len=resp_body_len,
                status_code=status_code,
                status_msg=status_msg,
                referrer=_http_referer,
                resp_mime_types=response_mime_types_for_status(
                    status_code,
                    mime_type,
                    resp_body_len,
                    method=http_method,
                ),
                tags=[],
            )

        if not suppress_application_side_effects:
            _attach_http_response_file_transfer(
                event,
                dst_ip=dst_ip,
                rng=rng,
                probabilistic_file_analysis=not caller_supplied_http,
            )

        if (
            not suppress_application_side_effects
            and event.file_transfer is None
            and service == "smb"
            and proto == "tcp"
            and dst_port == 445
            and event.network.conn_state == "SF"
        ):
            transfer_bytes = max(event.network.orig_bytes or 0, event.network.resp_bytes or 0)
            smb_server = ""
            if event.dst_host is not None:
                smb_server = event.dst_host.hostname or event.dst_host.fqdn
            if not smb_server:
                smb_server = REVERSE_DNS.get(event.network.dst_ip, event.network.dst_ip)
            smb_user = getattr(resolved_source_system, "assigned_user", "") or "Public"
            event.file_transfer = SmbFileTransferMetadataActionBundle(
                SmbFileTransferMetadataRequest(
                    src_ip=event.network.src_ip,
                    dst_ip=event.network.dst_ip,
                    transfer_bytes=transfer_bytes,
                    duration=event.network.duration or 0.0,
                    server=smb_server,
                    user=smb_user,
                    is_orig=(event.network.orig_bytes or 0) >= (event.network.resp_bytes or 0),
                ),
                rng,
            ).execute()

        # NTP context for Zeek ntp.log fan-out. Zeek ntp.log records server response
        # fields, so only attach the context when the matching conn.log row has a
        # responder payload.
        if (
            not local_only
            and service == "ntp"
            and proto == "udp"
            and event.network.conn_state == "SF"
            and (event.network.resp_pkts or 0) > 0
            and (event.network.resp_bytes or 0) > 0
        ):
            from evidenceforge.events.contexts import NtpContext

            ntp_rng = _get_rng()
            ntp_epoch = time.timestamp()
            # Stratum-aware timing via log-normal distribution
            stratum, ref_id = _ntp_stratum_and_ref_id(dst_ip)
            association = self._ntp_association_profile(event.network.src_ip, dst_ip)
            poll_seconds = float(association["poll"])
            last_parser_time = self._ntp_last_parser_times.get((event.network.src_ip, dst_ip))
            parser_gap = (
                None
                if last_parser_time is None
                else (event.timestamp - last_parser_time).total_seconds()
            )
            if parser_gap is None or parser_gap >= _ntp_parser_min_gap_seconds(poll_seconds):
                self._ntp_last_parser_times[(event.network.src_ip, dst_ip)] = event.timestamp
                server_response = self._ntp_server_response_profile(dst_ip)
                observed_response = _ntp_observed_response_fields(
                    server_response,
                    dst_ip=dst_ip,
                    event_time=event.timestamp,
                )
                _ntp_mean_ms, _ntp_sigma = _NTP_STRATUM_TIMING.get(stratum, (10.0, 0.7))
                _ntp_mu = math.log(_ntp_mean_ms) - (_ntp_sigma**2) / 2
                rtt_sec = ntp_rng.lognormvariate(_ntp_mu, _ntp_sigma) / 1000.0
                proc_sec = ntp_rng.lognormvariate(math.log(0.5) - 0.3**2 / 2, 0.3) / 1000.0
                ntp_jitter = ntp_rng.uniform(-0.005, 0.005)
                ntp_duration = max(0.001, rtt_sec + proc_sec + ntp_rng.uniform(0.001, 0.008))
                if event.network.duration is None or event.network.duration < ntp_duration:
                    event.network.duration = ntp_duration
                event.ntp = NtpContext(
                    version=int(association["version"]),
                    mode=4,  # server response
                    stratum=stratum,
                    poll=poll_seconds,
                    precision=observed_response["precision"],
                    root_delay=observed_response["root_delay"],
                    root_disp=observed_response["root_disp"],
                    ref_id=ref_id,
                    ref_ts=round(ntp_epoch - ntp_rng.uniform(30, 300), 6),
                    org_ts=round(ntp_epoch + ntp_jitter, 6),
                    rec_ts=round(ntp_epoch + ntp_jitter + rtt_sec, 6),
                    xmt_ts=round(ntp_epoch + ntp_jitter + rtt_sec + proc_sec, 6),
                )
            else:
                event.network.service = ""

        # Enforce conn_state/HTTP consistency: if HTTP context exists,
        # the connection must have completed successfully (SF). A connection
        # with a handshake-only, reset, or half-close state cannot have served
        # a Zeek HTTP transaction with request/response body accounting.
        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state != "SF"
        ):
            event.network.conn_state = "SF"
            event.network.history = _tcp_success_history(rng)
            if event.network.duration is None:
                event.network.duration = rng.uniform(0.01, 2.0)

        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state == "SF"
        ):
            http_timing = get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if event.network.duration is None or event.network.duration < http_min_duration:
                event.network.duration = http_min_duration + rng.uniform(0.0, 0.025)

        if event.network.protocol == "tcp" and event.network.conn_state == "SF":
            if event.http is not None:
                method = (event.http.method or "GET").upper()
                if event.network.service == "http" and method != "CONNECT":
                    event.network.orig_bytes, event.network.resp_bytes = _http_flow_payload_bytes(
                        event.http
                    )
                else:
                    request_body_len = _http_context_flow_body_len(event.http, "request")
                    response_body_len = _http_context_flow_body_len(event.http, "response")
                    request_overhead = rng.randint(180, 620)
                    response_overhead = rng.randint(180, 900)
                    if event.http.status_code in {204, 304} or method == "HEAD":
                        response_overhead = rng.randint(90, 360)
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        request_body_len + request_overhead,
                        rng.randint(180, 520),
                    )
                    event.network.resp_bytes = max(
                        event.network.resp_bytes or 0,
                        response_body_len + response_overhead,
                        rng.randint(90, 450),
                    )
            if event.network.service == "ssl" and not suppress_application_side_effects:
                event.network.orig_bytes = max(event.network.orig_bytes or 0, rng.randint(180, 900))
                event.network.resp_bytes = max(
                    event.network.resp_bytes or 0, rng.randint(900, 4500)
                )
            event.network.orig_pkts, event.network.resp_pkts = (
                _tcp_packet_counts_from_payload_and_history(
                    event.network.orig_bytes,
                    event.network.resp_bytes,
                    event.network.history,
                    rng,
                )
            )
            if event.network.service == "ssl" and not suppress_application_side_effects:
                event.network.orig_pkts += rng.choices(
                    [0, 1, 2, 3, 5],
                    weights=[45, 25, 15, 10, 5],
                    k=1,
                )[0]
                event.network.resp_pkts += rng.choices(
                    [0, 1, 2, 4, 8],
                    weights=[35, 25, 20, 15, 5],
                    k=1,
                )[0]
            event.network.orig_ip_bytes = _tcp_ip_byte_count(
                event.network.orig_bytes,
                event.network.orig_pkts,
                rng,
            )
            event.network.resp_ip_bytes = _tcp_ip_byte_count(
                event.network.resp_bytes,
                event.network.resp_pkts,
                rng,
            )
            self.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )

        if (
            not suppress_application_side_effects
            and not local_only
            and event.network.service == "ssl"
            and event.network.conn_state == "SF"
            and event.ssl is None
        ):
            self._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=False,
            )

        if _align_tcp_network_payload_with_history(event.network, rng):
            self.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )
        if preserve_explicit_payload and _preserve_explicit_tcp_payload_overrides(
            event.network,
            explicit_orig_bytes=explicit_orig_bytes,
            explicit_resp_bytes=explicit_resp_bytes,
            rng=rng,
        ):
            self.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )

        self._repair_explicit_proxy_listener_process_attribution(
            event,
            source_system=resolved_source_system,
            time=time,
        )
        self._repair_browser_http_process_attribution(
            event,
            source_system=resolved_source_system,
            time=time,
        )
        pid = event.network.initiating_pid
        process_ctx = event.process
        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            adjusted_time = self._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                event.timestamp,
                "source.windows_wfp_connection",
            )
            if adjusted_time > event.timestamp:
                event.timestamp = adjusted_time
                time = adjusted_time

        # Automatic weird.log synthesis is intentionally disabled for now. The
        # Zeek weird type space is broad and state-sensitive; poorly matched
        # weird rows are more damaging than sparse weird.log output. Explicit
        # WeirdContext events still render through ZeekWeirdEmitter. Keep one
        # RNG draw to avoid reshaping unrelated deterministic traffic choices.
        if not _AUTO_WEIRD_ENABLED:
            rng.random()

        if (
            http_persistent_key is not None
            and event.http is not None
            and event.network.conn_state == "SF"
            and not event.network.application_layer_only
            and event.network.duration is not None
        ):
            self._http_persistent_connections[http_persistent_key] = _HttpPersistentConnection(
                close_deadline=event.timestamp + timedelta(seconds=event.network.duration),
                uid=uid,
                src_port=src_port,
                next_trans_depth=max(2, event.http.trans_depth + 1),
                orig_budget=max(event.network.orig_bytes or 0, event.http.request_body_len or 0),
                resp_budget=max(event.network.resp_bytes or 0, event.http.response_body_len or 0),
                used_orig=event.http.request_body_len or 0,
                used_resp=event.http.response_body_len or 0,
            )

        # Phase 3: Dispatch to matching emitters (visibility handled by dispatcher)
        if not event.network.application_layer_only and event.network.src_port > 0:
            self._last_connection_effective_tuple = (
                event.network.src_ip,
                event.network.src_port,
                event.network.dst_ip,
                event.network.dst_port,
                event.network.protocol,
            )
            self._last_connection_effective_time = event.timestamp
        self.dispatcher.dispatch(event)
        if generic_ssh_preauth_pid is not None and target_system is not None:
            self._emit_generic_ssh_preauth_failure_syslog(
                target_system=target_system,
                target_host=dst_host_ctx,
                time=event.timestamp,
                source_ip=src_ip,
                source_port=src_port,
                sshd_pid=generic_ssh_preauth_pid,
                duration=event.network.duration,
            )
        logger.debug(f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})")

        # Emit 5156 (WFP connection) on Windows source hosts when process ownership is known.
        # Unknown ownership is not PID 4 by default; rendering it as System makes ordinary
        # user/proxy flows look kernel-originated.
        wfp_system = resolved_source_system or source_system
        wfp_application = event.process.image if event.process is not None else None
        if (
            wfp_system
            and _get_os_category(wfp_system.os) == "windows"
            and (pid > 0 or wfp_application is not None)
            and not event.network.application_layer_only
        ):
            self.generate_wfp_connection(
                system=wfp_system,
                time=time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                pid=pid,
                application=wfp_application,
            )

        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and not event.network.application_layer_only
            and self._should_emit_windows_inbound_wfp(event, target_system)
        ):
            inbound_pid = event.network.responding_pid
            inbound_application = self._lookup_process_name(
                target_system.hostname,
                inbound_pid,
                "windows",
            )
            self.generate_wfp_connection(
                system=target_system,
                time=time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=target_system.ip,
                dst_port=dst_port,
                protocol=proto,
                pid=inbound_pid,
                application=inbound_application,
            )

        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            running = self.state_manager.get_process(resolved_source_system.hostname, pid)
            if self._process_termination_recorded(
                resolved_source_system.hostname,
                pid,
                running.start_time if running is not None else None,
            ):
                return uid
            lifetime = (
                self._foreground_process_lifetime_for_attribution(resolved_source_system, running)
                if running is not None
                else None
            )
            if lifetime is not None and re.match(r"^[a-zA-Z0-9._$-]+$", running.username):
                known_users = getattr(self, "_users_by_username", {})
                process_user = known_users.get(running.username) or User(
                    username=running.username,
                    full_name=running.username,
                    email=f"{running.username}@example.local",
                )
                term_rng = random.Random(
                    _stable_seed(
                        "connection_owned_foreground_termination:"
                        f"{resolved_source_system.hostname}:{pid}:{time.isoformat()}"
                    )
                )
                min_delay = min(max(lifetime[0], 0.5), 4.0)
                max_delay = max(min_delay + 0.5, min(lifetime[1] + 8.0, 45.0))
                self.generate_process_termination(
                    user=process_user,
                    system=resolved_source_system,
                    time=time + timedelta(seconds=term_rng.uniform(min_delay, max_delay)),
                    pid=pid,
                    process_name=running.image,
                    logon_id=running.logon_id,
                )

        return uid

    def generate_ssh_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_system: Optional["System"] = None,
        source_port: int | None = None,
        source_pid: int = -1,
        source_process_image: str = "",
        sshd_pid: int | None = None,
        logon_id: str = "",
        session_obj_id: str = "",
        min_duration: float | None = None,
        duration: float | None = None,
        orig_bytes: int | None = None,
        resp_bytes: int | None = None,
        auth_method: str = "password",
        public_key_type: str = "",
        public_key_hash: str = "",
        emit_session_close: bool = False,
        source: str = "activity_generator",
    ) -> str:
        """Generate an SSH session through the SSH action-bundle adapter.

        Args:
            user: User initiating the SSH connection
            target_system: Target Linux system
            time: Connection timestamp
            source_ip: Source IP of the SSH client

        Returns:
            Zeek UID for the connection
        """
        request = SshSessionRequest(
            user=user,
            target_system=target_system,
            time=time,
            source_ip=source_ip,
            source_system=source_system,
            source_port=source_port,
            source_pid=source_pid,
            source_process_image=source_process_image,
            sshd_pid=sshd_pid,
            logon_id=logon_id,
            session_obj_id=session_obj_id,
            min_duration=min_duration,
            duration=duration,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            auth_method=auth_method,
            public_key_type=public_key_type,
            public_key_hash=public_key_hash,
            emit_session_close=emit_session_close,
            source=source,
        )
        return SshSessionActionBundle(request=request, executor=self).execute()

    @staticmethod
    def _ssh_tcp_success_history(rng: random.Random) -> str:
        """Choose a plausible Zeek TCP history string for SSH bundle expansion."""
        return _tcp_success_history(rng)

    @staticmethod
    def _ssh_tcp_packet_counts_from_payload_and_history(
        orig_bytes: int | None,
        resp_bytes: int | None,
        history: str | None,
        rng: random.Random,
    ) -> tuple[int, int]:
        """Return TCP packet counts for SSH bundle expansion."""
        return _tcp_packet_counts_from_payload_and_history(orig_bytes, resp_bytes, history, rng)

    @staticmethod
    def _ssh_tcp_ip_byte_count(
        payload_bytes: int | None,
        packet_count: int,
        rng: random.Random,
    ) -> int:
        """Return TCP IP byte accounting for SSH bundle expansion."""
        return _tcp_ip_byte_count(payload_bytes, packet_count, rng)

    def ensure_linux_ssh_session_shell(
        self,
        user: User,
        target_system: System,
        logon_id: str,
        logon_time: datetime,
        activity_time: datetime,
    ) -> int | None:
        """Create visible per-session sshd and login shell process state for SSH."""
        session = self.state_manager.get_session(logon_id)
        if session is None or session.system != target_system.hostname:
            return None
        logon_time = ensure_utc(logon_time)
        activity_time = ensure_utc(activity_time)
        if not _session_active_for_activity(session, activity_time, margin_seconds=1.5):
            return None
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        if session.session_shell_pid is not None:
            shell_proc = self.state_manager.get_process(
                target_system.hostname,
                session.session_shell_pid,
            )
            if shell_proc is not None and self._is_pid_active_at(
                target_system,
                session.session_shell_pid,
                activity_time,
            ):
                shell_start = ensure_utc(shell_proc.start_time)
                source_ready_time = _session_source_ready_time(session)
                if (
                    scenario_start is None
                    or activity_time < scenario_start
                    or shell_start >= scenario_start
                ) and (source_ready_time is None or shell_start >= source_ready_time):
                    return session.session_shell_pid

        sys_pids = getattr(self, "_system_pids", {}).get(target_system.hostname, {})
        global_sshd = sys_pids.get("sshd")
        if (
            not global_sshd
            or self.state_manager.get_process(target_system.hostname, global_sshd) is None
        ):
            return None

        shell_seed = _stable_seed(
            "linux_ssh_session_shell:"
            f"{target_system.hostname}:{user.username}:{logon_id}:{logon_time.isoformat()}"
        )
        source_ready_time = _session_source_ready_time(session)
        source_floor = logon_time + timedelta(milliseconds=150)
        if source_ready_time is not None:
            source_floor = max(source_floor, source_ready_time + timedelta(milliseconds=50))
        sshd_delay_ms = 900 + (shell_seed % 1400)
        sshd_time = max(logon_time + timedelta(milliseconds=sshd_delay_ms), source_floor)
        if (
            scenario_start is not None
            and activity_time >= scenario_start
            and sshd_time < scenario_start
        ):
            pre_command_gap = timedelta(seconds=5 + (shell_seed % 95))
            scenario_floor = scenario_start + timedelta(milliseconds=500 + (shell_seed % 3000))
            sshd_time = max(scenario_floor, activity_time - pre_command_gap)
        effective_activity_time = max(activity_time, sshd_time + timedelta(milliseconds=700))
        latest_parent_time = effective_activity_time - timedelta(milliseconds=500)
        if sshd_time > latest_parent_time and latest_parent_time >= source_floor:
            sshd_time = max(logon_time + timedelta(milliseconds=150), latest_parent_time)

        session_sshd_pid = self.generate_system_process(
            system=target_system,
            time=sshd_time,
            process_name="/usr/sbin/sshd",
            command_line=f"sshd: {user.username} [priv]",
            parent_pid=global_sshd,
            username="root",
            emit_linux_syslog=False,
        )

        bash_time = sshd_time + timedelta(milliseconds=120 + (shell_seed % 180))
        effective_activity_time = max(activity_time, bash_time + timedelta(milliseconds=260))
        latest_bash_time = effective_activity_time - timedelta(milliseconds=120)
        if bash_time > latest_bash_time and latest_bash_time >= sshd_time + timedelta(
            milliseconds=20
        ):
            bash_time = max(sshd_time + timedelta(milliseconds=20), latest_bash_time)

        bash_pid = self.generate_process(
            user=user,
            system=target_system,
            time=bash_time,
            logon_id=logon_id,
            process_name="/bin/bash",
            command_line="-bash",
            parent_pid=session_sshd_pid,
            suppress_command_file_effect=True,
        )
        session.session_shell_pid = bash_pid
        session.process_tree_root = session_sshd_pid
        return bash_pid

    def _ensure_linux_local_session_shell_parent(
        self,
        *,
        user: User,
        target_system: System,
        logon_id: str,
        logon_time: datetime,
        bash_time: datetime,
        root_parent_pid: int,
        shell_seed: int,
    ) -> tuple[int, datetime]:
        """Create a visible local-session parent chain before a login shell."""

        system_type = (getattr(target_system, "type", "") or "").lower()
        workstation_like = system_type in {
            "workstation",
            "laptop",
        } or target_system.hostname.upper().startswith(("WS-", "LT-"))
        user_systemd_time = max(
            logon_time + timedelta(milliseconds=90),
            bash_time - timedelta(milliseconds=900 + (shell_seed % 320)),
        )
        if user_systemd_time >= bash_time:
            user_systemd_time = logon_time + timedelta(milliseconds=90)

        user_systemd_pid = self.generate_process(
            user=user,
            system=target_system,
            time=user_systemd_time,
            logon_id=logon_id,
            process_name="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --user",
            parent_pid=root_parent_pid,
            suppress_command_file_effect=True,
        )
        user_systemd_proc = self.state_manager.get_process(target_system.hostname, user_systemd_pid)
        if user_systemd_proc is not None:
            user_systemd_time = ensure_utc(user_systemd_proc.start_time)

        if workstation_like:
            parent_image = "/usr/libexec/gnome-terminal-server"
            parent_command = "/usr/libexec/gnome-terminal-server"
        else:
            parent_image = "/bin/login"
            parent_command = f"login -- {user.username}"

        terminal_time = max(
            user_systemd_time + timedelta(milliseconds=120),
            bash_time - timedelta(milliseconds=260 + (shell_seed % 170)),
        )
        terminal_pid = self.generate_process(
            user=user,
            system=target_system,
            time=terminal_time,
            logon_id=logon_id,
            process_name=parent_image,
            command_line=parent_command,
            parent_pid=user_systemd_pid,
            suppress_command_file_effect=True,
        )
        terminal_proc = self.state_manager.get_process(target_system.hostname, terminal_pid)
        if terminal_proc is not None:
            terminal_time = ensure_utc(terminal_proc.start_time)
        return terminal_pid, terminal_time

    def ensure_linux_session_shell(
        self,
        user: User,
        target_system: System,
        logon_id: str,
        logon_time: datetime,
        activity_time: datetime,
    ) -> int | None:
        """Create or return a visible Linux shell that owns session child processes."""
        session = self.state_manager.get_session(logon_id)
        if session is None or session.system != target_system.hostname:
            return None
        if not _session_active_for_activity(session, activity_time, margin_seconds=1.5):
            return None
        if session.session_kind == "ssh":
            return self.ensure_linux_ssh_session_shell(
                user=user,
                target_system=target_system,
                logon_id=logon_id,
                logon_time=logon_time,
                activity_time=activity_time,
            )

        logon_time = ensure_utc(logon_time)
        activity_time = ensure_utc(activity_time)
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        if session.session_shell_pid is not None:
            shell_proc = self.state_manager.get_process(
                target_system.hostname,
                session.session_shell_pid,
            )
            if shell_proc is not None and self._is_pid_active_at(
                target_system,
                session.session_shell_pid,
                activity_time,
            ):
                shell_start = ensure_utc(shell_proc.start_time)
                if (
                    scenario_start is None
                    or activity_time < scenario_start
                    or shell_start >= scenario_start
                ):
                    return session.session_shell_pid

        sys_pids = getattr(self, "_system_pids", {}).get(target_system.hostname, {})
        parent_pid = sys_pids.get("systemd") or sys_pids.get("init")
        if (
            not parent_pid
            or self.state_manager.get_process(target_system.hostname, parent_pid) is None
        ):
            parent_pid = self._linux_anchor_pid(target_system, activity_time)

        shell_seed = _stable_seed(
            "linux_session_shell:"
            f"{target_system.hostname}:{user.username}:{logon_id}:{logon_time.isoformat()}"
        )
        bash_time = logon_time + timedelta(milliseconds=180 + (shell_seed % 1200))
        if (
            scenario_start is not None
            and activity_time >= scenario_start
            and bash_time < scenario_start
        ):
            scenario_floor = scenario_start + timedelta(milliseconds=400 + (shell_seed % 2500))
            pre_command_gap = timedelta(seconds=4 + (shell_seed % 75))
            bash_time = max(scenario_floor, activity_time - pre_command_gap)
        readiness_gap = timedelta(milliseconds=2200 + (shell_seed % 5200))
        latest_bash_time = activity_time - readiness_gap
        if bash_time > latest_bash_time and latest_bash_time > logon_time:
            bash_time = latest_bash_time

        parent_pid, parent_time = self._ensure_linux_local_session_shell_parent(
            user=user,
            target_system=target_system,
            logon_id=logon_id,
            logon_time=logon_time,
            bash_time=bash_time,
            root_parent_pid=parent_pid,
            shell_seed=shell_seed,
        )
        if parent_time >= bash_time:
            bash_time = parent_time + timedelta(milliseconds=120)

        bash_pid = self.generate_process(
            user=user,
            system=target_system,
            time=bash_time,
            logon_id=logon_id,
            process_name="/bin/bash",
            command_line="-bash",
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
        )
        session.session_shell_pid = bash_pid
        session.process_tree_root = parent_pid
        return bash_pid

    def _active_visible_linux_shell_pid(
        self,
        system: System,
        username: str,
        time: datetime,
        logon_id: str = "",
    ) -> int | None:
        """Return a visible user shell that can own Linux child process telemetry."""
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        activity_time = ensure_utc(time)
        candidates = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_exe = proc.image.rsplit("/", 1)[-1].lower()
            if proc_exe not in {"bash", "sh", "zsh"}:
                continue
            if proc.username != username:
                continue
            if logon_id and proc.logon_id and proc.logon_id != logon_id:
                continue
            if proc.logon_id:
                session = self.state_manager.get_session(proc.logon_id)
                if session is not None and not _session_active_for_activity(
                    session,
                    activity_time,
                    margin_seconds=1.5,
                ):
                    continue
            if not self._is_pid_active_at(system, proc.pid, activity_time):
                continue
            shell_start = ensure_utc(proc.start_time)
            if (
                scenario_start is not None
                and activity_time >= scenario_start
                and shell_start < scenario_start
            ):
                continue
            candidates.append(proc)
        if not candidates:
            return None
        candidates.sort(key=lambda proc: ensure_utc(proc.start_time), reverse=True)
        return candidates[0].pid

    def ensure_linux_visible_shell_parent(
        self,
        user: User,
        target_system: System,
        activity_time: datetime,
        logon_id: str = "",
        logon_time: datetime | None = None,
    ) -> int | None:
        """Create or return a source-visible Linux shell parent for loose user work."""
        activity_time = ensure_utc(activity_time)
        if logon_id:
            session = self.state_manager.get_session(logon_id)
            if session is not None and not _session_active_for_activity(
                session,
                activity_time,
                margin_seconds=1.5,
            ):
                return None
        existing = self._active_visible_linux_shell_pid(
            target_system,
            user.username,
            activity_time,
            logon_id,
        )
        if existing is not None:
            return existing

        sys_pids = getattr(self, "_system_pids", {}).get(target_system.hostname, {})
        parent_pid = sys_pids.get("systemd") or sys_pids.get("init")
        if (
            not parent_pid
            or self.state_manager.get_process(target_system.hostname, parent_pid) is None
        ):
            parent_pid = self._linux_anchor_pid(target_system, activity_time)

        base_time = ensure_utc(logon_time) if logon_time is not None else activity_time
        shell_seed = _stable_seed(
            "linux_visible_shell_parent:"
            f"{target_system.hostname}:{user.username}:{logon_id}:{activity_time.isoformat()}"
        )
        shell_time = base_time + timedelta(milliseconds=160 + (shell_seed % 1100))
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        if (
            scenario_start is not None
            and activity_time >= scenario_start
            and shell_time < scenario_start
        ):
            scenario_floor = scenario_start + timedelta(milliseconds=350 + (shell_seed % 2200))
            pre_command_gap = timedelta(seconds=3 + (shell_seed % 60))
            shell_time = max(scenario_floor, activity_time - pre_command_gap)
        readiness_gap = timedelta(milliseconds=2000 + (shell_seed % 5000))
        latest_shell_time = activity_time - readiness_gap
        if shell_time > latest_shell_time and latest_shell_time > base_time:
            shell_time = latest_shell_time

        return self.generate_process(
            user=user,
            system=target_system,
            time=shell_time,
            logon_id=logon_id,
            process_name="/bin/bash",
            command_line="-bash",
            parent_pid=parent_pid,
            suppress_command_file_effect=True,
        )

    def generate_bash_command(
        self,
        user: User,
        system: System,
        time: datetime,
        activity_type_or_command: str = "default",
        *,
        emit_process_telemetry: bool = True,
    ) -> datetime | None:
        """Generate bash command history entry via dispatch.

        Builds a SecurityEvent with ShellContext and dispatches.
        BashHistoryEmitter.can_handle() filters for Linux-only.

        Args:
            user: User executing command
            system: Linux system
            time: Command execution time
            activity_type_or_command: Either an activity type key (process_code, etc.)
                or a direct command string (if it contains spaces or '/')
            emit_process_telemetry: Whether direct shell commands may emit correlated
                process lifecycle telemetry. Storyline process events set this to False
                because the typed process event already owns the canonical process.
        """
        return LinuxShellCommandActionBundle(
            self,
            LinuxShellCommandRequest(
                user=user,
                system=system,
                time=time,
                activity_type_or_command=activity_type_or_command,
                emit_process_telemetry=emit_process_telemetry,
            ),
        ).execute()

    def _resolve_bash_command(
        self,
        user: User,
        system: System,
        activity_type_or_command: str,
    ) -> str:
        """Return the concrete bash command for an activity key or literal command."""

        _activity_type_commands = {
            "process_code": [
                "vim script.py",
                "nano config.conf",
                "code .",
                "git status",
                "git diff",
                "python3 -m pytest",
                "cat README.md",
            ],
            "process_build": [
                "make",
                "gcc -o output source.c",
                "npm run build",
                "docker build -t app .",
                "cargo build --release",
            ],
            "connection_web": [
                "curl https://example.com",
                "wget https://github.com/repo/file.tar.gz",
                "curl -I https://api.example.com/health",
            ],
            "process_query": [
                "mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'",
                "psql -c '\\l'",
                "redis-cli info",
                "mysql --defaults-extra-file=~/.my.cnf -e 'SHOW PROCESSLIST'",
                "psql -c 'SELECT pg_size_pretty(pg_database_size(current_database()))'",
                "sqlite3 /var/lib/app/data.db '.tables'",
            ],
            "process_system": [
                "systemctl status sshd",
                "journalctl -u cron --since '1 hour ago'",
                "top -bn1 | head -20",
                "ss -tulnp",
                "df -h",
                "free -m",
                "dmesg | tail -20",
                "last -10",
            ],
            "process_user_apps": [
                "ls -la",
                "cd /var/www/html",
                "tail -f /var/log/syslog",
                'grep -r "error" /var/log/',
                "systemctl status apache2",
                "free -m",
                "uptime",
                "cat /etc/hostname",
                "netstat -tlnp",
                "du -sh /var/log/*",
                "w",
                'journalctl -u apache2 --since "1 hour ago"',
                "htop",
                "ss -tulnp",
                "ip -o addr show scope global",
            ],
            "default": [
                "ls -la",
                "ps aux",
                "top",
                "df -h",
                "whoami",
                "pwd",
                "cat /etc/os-release",
                "uptime",
                "free -m",
                "w",
                "tail -20 /var/log/syslog",
                "history | tail -20",
                "date",
                "ls /tmp",
                "mount | grep -v tmpfs",
            ],
        }

        if activity_type_or_command in _activity_type_commands:
            command_list = _activity_type_commands[activity_type_or_command]
            if activity_type_or_command == "process_user_apps":
                from evidenceforge.generation.activity.bash_commands import _resolve_server_role

                server_role = _resolve_server_role(
                    system.hostname,
                    list(getattr(system, "services", []) or []),
                )
                if server_role == "db":
                    command_list = [
                        "ls -la",
                        "tail -f /var/log/mysql/error.log",
                        "mysql --defaults-extra-file=~/.my.cnf -e 'SHOW PROCESSLIST'",
                        "pg_isready",
                        "du -sh /var/lib/mysql/*",
                        "systemctl status mysql",
                        "free -m",
                        "uptime",
                        "cat /etc/hostname",
                        "ss -tulnp",
                        "w",
                        "htop",
                        "ip -4 addr show scope global",
                    ]
                elif server_role != "web":
                    web_markers = (
                        "apache",
                        "nginx",
                        "certbot",
                        "/var/www",
                        "ab -n",
                    )
                    command_list = [
                        command
                        for command in command_list
                        if not any(marker in command for marker in web_markers)
                    ]
            from evidenceforge.generation.activity.bash_commands import (
                _choose_template_with_memory,
            )

            command = _choose_template_with_memory(
                _get_rng(),
                command_list,
                {},
                list(getattr(system, "services", []) or []),
                system.hostname,
                user.username,
            )
        else:
            command = activity_type_or_command
        return command

    @staticmethod
    def _should_skip_bash_history(user: User, system: System) -> bool:
        """Return true when bash-history evidence should be suppressed."""

        _ = system
        return _is_noninteractive_bash_user(user)

    @staticmethod
    def _prepare_bash_history_command(system: System, command: str) -> str:
        """Return a source-native command suitable for bash history."""

        if _get_os_category(system.os) == "linux":
            return _background_linux_shell_command_if_needed(command)
        return command

    def _emit_bash_command_event(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Dispatch a bash-history event at an already scheduled command time."""
        if _is_noninteractive_bash_user(user):
            logger.debug(
                "Skipping bash_history for noninteractive web service user %s on %s",
                user.username,
                system.hostname,
            )
            return

        from evidenceforge.events.contexts import ShellContext

        event = SecurityEvent(
            timestamp=time,
            event_type="bash_command",
            src_host=self._build_host_context(system),
            auth=AuthContext(username=user.username),
            shell=ShellContext(command=command),
        )

        self.dispatcher.dispatch(event)

    def _maybe_emit_bash_process_telemetry(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Emit process telemetry for interactive Linux shell commands when state supports it."""
        if _get_os_category(system.os) != "linux":
            return
        processes = _linux_command_processes_from_shell(
            command,
            max_processes=_LINUX_SHELL_MAX_INFERRED_PROCESSES,
            username=user.username,
        )
        if not processes:
            return

        sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if session.system == system.hostname
            and _session_active_for_activity(session, time, margin_seconds=1.5)
        ]
        if not sessions:
            return
        session = max(sessions, key=lambda candidate: candidate.start_time)

        rng = random.Random(
            _stable_seed(
                f"bash_process_telemetry:{system.hostname}:{user.username}:{time}:{command}"
            )
        )

        shell_release_times: list[tuple[int, datetime, str]] = []
        base_process_time: datetime | None = None
        concurrency_group_id = ""
        if len(processes) > 1 and _contains_unquoted_shell_pipe(command):
            pipeline_seed = _stable_seed(
                "linux_shell_pipeline:"
                f"{system.hostname}:{user.username}:{session.logon_id}:"
                f"{time.isoformat()}:{command}"
            )
            concurrency_group_id = f"linux-shell-pipeline-{pipeline_seed:016x}"
        for index, (image, process_command_line) in enumerate(processes):
            parent_pid = self._resolve_parent(system, user, time, session.logon_id, image)
            if base_process_time is None:
                base_process_time = self._reserve_foreground_shell_time(
                    system=system,
                    username=user.username,
                    logon_id=session.logon_id,
                    parent_pid=parent_pid,
                    requested_time=time + timedelta(milliseconds=rng.randint(20, 180)),
                    seed_text=command,
                )
            process_time = base_process_time + timedelta(milliseconds=index * 35)
            if not self._is_within_scenario_window(process_time):
                continue
            network_close_time = getattr(session, "network_close_time", None)
            if network_close_time is not None:
                if network_close_time.tzinfo is None:
                    network_close_time = network_close_time.replace(tzinfo=UTC)
                else:
                    network_close_time = network_close_time.astimezone(UTC)
                if process_time >= network_close_time - timedelta(milliseconds=750):
                    continue
            pid = self.generate_process(
                user=user,
                system=system,
                time=process_time,
                logon_id=session.logon_id,
                process_name=image,
                command_line=process_command_line,
                parent_pid=parent_pid,
                suppress_command_file_effect=True,
                concurrency_group_id=concurrency_group_id,
            )
            running_proc = self.state_manager.get_process(system.hostname, pid)
            actual_process_start = (
                running_proc.start_time if running_proc is not None else process_time
            )
            self._record_user_process(system, user, pid, image)
            lifetime = _linux_foreground_lifetime(image, process_command_line)
            if lifetime is not None:
                termination_time = self._generate_bounded_foreground_process_termination(
                    user=user,
                    system=system,
                    start_time=actual_process_start,
                    pid=pid,
                    process_name=image,
                    logon_id=session.logon_id,
                    lifetime=lifetime,
                    rng=rng,
                )
                shell_release_times.append((parent_pid, termination_time, process_command_line))
        for parent_pid, termination_time, process_command_line in shell_release_times:
            self._remember_foreground_shell_available(
                system=system,
                username=user.username,
                logon_id=session.logon_id,
                parent_pid=parent_pid,
                termination_time=termination_time,
                seed_text=process_command_line,
            )

    def _prepare_bash_process_session(
        self,
        user: User,
        system: System,
        requested_time: datetime,
        command: str,
    ) -> None:
        """Ensure assigned Linux workstation shell commands have session ownership."""
        if _get_os_category(system.os) != "linux":
            return
        if (system.type or "workstation").lower() != "workstation":
            return
        if system.assigned_user != user.username:
            return
        if not _linux_command_processes_from_shell(
            command,
            max_processes=_LINUX_SHELL_MAX_INFERRED_PROCESSES,
            username=user.username,
        ):
            return

        requested_time = ensure_utc(requested_time)
        sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if session.system == system.hostname
            and session.session_kind not in {"network", "service"}
            and session.logon_type not in {3, 5}
            and _session_active_for_activity(session, requested_time, margin_seconds=1.5)
        ]
        if sessions:
            return

        seed = _stable_seed(
            "linux_workstation_bash_session:"
            f"{system.hostname}:{user.username}:{requested_time.isoformat()}:{command}"
        )
        logon_time = requested_time - timedelta(minutes=5 + (seed % 11), seconds=seed % 47)
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
            if requested_time >= scenario_start and logon_time < scenario_start:
                logon_time = scenario_start + timedelta(milliseconds=350 + (seed % 3200))
        if logon_time >= requested_time:
            logon_time = requested_time - timedelta(seconds=2, milliseconds=seed % 500)
        if not self._is_within_scenario_window(logon_time):
            return

        self.generate_logon(
            user=user,
            system=system,
            time=logon_time,
            logon_type=2,
            source_ip="-",
            emit_network_evidence=False,
        )

    def _schedule_bash_history_time(
        self,
        user: User,
        system: System,
        requested_time: datetime,
        command: str,
    ) -> datetime | None:
        """Preserve foreground command dwell time for one user's shell history."""
        requested_time = self._align_linux_bash_after_session_ready(
            user,
            system,
            requested_time,
            command,
        )
        key = (system.hostname, user.username)
        scheduled_time = max(requested_time, self._bash_history_next_time.get(key, requested_time))
        scheduled_time = self._fit_bash_history_time_to_linux_session(
            user,
            system,
            scheduled_time,
        )
        if scheduled_time is None:
            return None
        scheduled_time = self._reserve_bash_history_second(user, system, scheduled_time, command)
        scheduled_time = self._fit_bash_history_time_to_linux_session(
            user,
            system,
            scheduled_time,
        )
        if scheduled_time is None:
            return None
        dwell_seconds = _bash_command_dwell_seconds(command)
        jitter_rng = random.Random(
            _stable_seed(
                f"bash_dwell:{system.hostname}:{user.username}:{scheduled_time.timestamp()}:{command}"
            )
        )
        if dwell_seconds <= 2.0:
            command_count = self._bash_history_command_counts.get(key, 0)
            quick_streak = self._bash_history_quick_streaks.get(key, 0)
            roll = jitter_rng.random()
            if command_count == 0:
                extra_delay = jitter_rng.uniform(4.0, 18.0)
            elif roll < 0.16 and quick_streak == 0:
                extra_delay = jitter_rng.uniform(4.0, 12.0)
            elif roll < 0.68:
                extra_delay = jitter_rng.uniform(18.0, 95.0)
            elif roll < 0.93:
                extra_delay = jitter_rng.uniform(95.0, 420.0)
            else:
                extra_delay = jitter_rng.uniform(420.0, 1500.0)
            dwell_seconds += extra_delay
            self._bash_history_quick_streaks[key] = quick_streak + 1 if extra_delay < 14.0 else 0
        elif dwell_seconds < 45.0:
            dwell_seconds = dwell_seconds * jitter_rng.uniform(1.0, 2.2) + jitter_rng.uniform(
                4.0, 18.0
            )
        else:
            dwell_seconds = max(dwell_seconds, dwell_seconds * jitter_rng.uniform(0.95, 1.35))
            self._bash_history_quick_streaks[key] = 0
        completion_time = scheduled_time + timedelta(seconds=dwell_seconds)
        self._bash_history_command_counts[key] = self._bash_history_command_counts.get(key, 0) + 1
        self._bash_history_next_time[key] = completion_time
        self._remember_linux_bash_session_activity(
            user,
            system,
            scheduled_time,
            completion_time,
        )
        return scheduled_time

    def _remember_linux_bash_session_activity(
        self,
        user: User,
        system: System,
        scheduled_time: datetime,
        completion_time: datetime,
    ) -> None:
        """Record shell-history activity on the concrete session that owns it."""
        if _get_os_category(system.os) != "linux":
            return
        activity_time = ensure_utc(scheduled_time)
        sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if session.system == system.hostname
            and session.session_kind not in {"network", "service"}
            and session.logon_type not in {3, 5}
            and _session_started_by(session, activity_time)
        ]
        if not sessions:
            return
        session = max(sessions, key=lambda candidate: ensure_utc(candidate.start_time))
        marker = ensure_utc(completion_time)
        if session.network_close_time is not None:
            network_close_time = ensure_utc(session.network_close_time)
            marker = min(marker, network_close_time - timedelta(milliseconds=900))
        if session.last_activity_time is None or marker > ensure_utc(session.last_activity_time):
            session.last_activity_time = marker

    def _fit_bash_history_time_to_linux_session(
        self,
        user: User,
        system: System,
        scheduled_time: datetime,
    ) -> datetime | None:
        """Return a concrete session-owned bash timestamp for Linux shell history."""
        if _get_os_category(system.os) != "linux":
            return scheduled_time
        sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if session.system == system.hostname
            and session.session_kind not in {"network", "service"}
            and session.logon_type not in {3, 5}
        ]
        strict_server_session = (system.type or "workstation").lower() == "server" and getattr(
            self, "_scenario_start_time", None
        ) is not None
        if not sessions:
            if strict_server_session:
                return None
            last_close = self._linux_shell_last_session_close.get((system.hostname, user.username))
            if last_close is not None and ensure_utc(scheduled_time) >= ensure_utc(last_close):
                return None
            return scheduled_time

        activity_time = ensure_utc(scheduled_time)
        sessions.sort(key=lambda session: ensure_utc(session.start_time))
        for session in sessions:
            window_start = _session_source_ready_time(session) or ensure_utc(session.start_time)
            window_end = getattr(session, "network_close_time", None)
            if window_end is not None:
                window_end = ensure_utc(window_end) - timedelta(milliseconds=900)
            candidate_time = max(activity_time, window_start)
            if window_end is None or candidate_time < window_end:
                return candidate_time
        return None

    def _align_linux_bash_after_session_ready(
        self,
        user: User,
        system: System,
        requested_time: datetime,
        command: str,
    ) -> datetime:
        """Shift visible Linux shell commands after SSH auth/PAM/eCAR session readiness."""
        if _get_os_category(system.os) != "linux":
            return requested_time
        activity_time = ensure_utc(requested_time)
        sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(user.username)
            if session.system == system.hostname
            and session.session_kind == "ssh"
            and _session_active_for_activity(session, activity_time)
        ]
        if not sessions:
            return requested_time
        session = max(sessions, key=lambda candidate: ensure_utc(candidate.start_time))
        ready_time = _session_source_ready_time(session)
        if ready_time is None or activity_time >= ready_time:
            return requested_time
        ready_seed = _stable_seed(
            "linux_bash_after_ssh_ready:"
            f"{system.hostname}:{user.username}:{session.logon_id}:{command}:{activity_time}"
        )
        return ready_time + timedelta(milliseconds=180 + (ready_seed % 420))

    def _reserve_bash_history_second(
        self,
        user: User,
        system: System,
        scheduled_time: datetime,
        command: str,
    ) -> datetime:
        """Avoid exact same-user bash-history seconds across different hosts."""
        username_key = user.username.lower()
        candidate = scheduled_time
        for attempt in range(8):
            second_key = (username_key, int(candidate.timestamp()))
            if second_key not in self._bash_history_user_seconds:
                self._bash_history_user_seconds[second_key] = 1
                return candidate
            collision_count = self._bash_history_user_seconds[second_key]
            self._bash_history_user_seconds[second_key] = collision_count + 1
            delay_rng = random.Random(
                _stable_seed(
                    "bash_user_second_collision:"
                    f"{username_key}:{system.hostname}:{command}:"
                    f"{candidate.timestamp()}:{attempt}:{collision_count}"
                )
            )
            candidate += timedelta(seconds=delay_rng.randint(1, 23))

        second_key = (username_key, int(candidate.timestamp()))
        self._bash_history_user_seconds[second_key] = (
            self._bash_history_user_seconds.get(second_key, 0) + 1
        )
        return candidate

    def generate_bash_command_with_noise(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Generate a bash command with organic noise commands around it.

        Emits the primary command plus 0-3 organic noise commands at
        slight time offsets, simulating an attacker or admin who types
        ls, pwd, id etc. between deliberate actions.
        """
        # Emit the primary command
        self.generate_bash_command(user, system, time, command)

        # Probabilistically emit 0-3 noise commands (role-aware)
        from evidenceforge.generation.activity.bash_commands import pick_bash_command_entry

        rng = _get_rng()
        n_noise = rng.choices([0, 1, 1, 2, 2, 3], k=1)[0]
        typo_count = 0
        # Complexity-aware inter-command delays
        _COMPLEX_PREFIXES = ("nmap", "find ", "tar ", "rsync", "make", "docker", "ansible")
        _MEDIUM_PREFIXES = ("curl", "wget", "scp", "ssh ", "mysql", "psql", "pip", "apt", "yum")
        cumulative_delay = 0.0
        prev_cmd = command
        for _ in range(n_noise):
            # Delay based on complexity of previous command
            if any(prev_cmd.startswith(p) for p in _COMPLEX_PREFIXES):
                delay = rng.uniform(20.0, 120.0)
            elif any(prev_cmd.startswith(p) for p in _MEDIUM_PREFIXES):
                delay = rng.uniform(8.0, 45.0)
            else:
                delay = rng.choice(
                    [
                        rng.uniform(4.0, 14.0),
                        rng.uniform(18.0, 90.0),
                        rng.uniform(90.0, 240.0),
                    ]
                )
            cumulative_delay += delay
            noise_time = time + timedelta(seconds=cumulative_delay)
            noise_cmd, is_typo = pick_bash_command_entry(
                rng,
                user.persona or "",
                system.hostname,
                system.services,
                username=user.username,
                session_command_count=n_noise + 1,
                prior_typo_count=typo_count,
                system_os=system.os,
            )
            if is_typo:
                typo_count += 1
            self.generate_bash_command(user, system, noise_time, noise_cmd)
            prev_cmd = noise_cmd

    def generate_system_process(
        self,
        system: System,
        time: datetime,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        username: str = "SYSTEM",
        syslog_message: str | None = None,
        *,
        emit_linux_syslog: bool = True,
        concurrency_group_id: str = "",
    ) -> int:
        """Generate a system process creation event (no user session required).

        Used for scheduled tasks, service spawns, and other system-initiated
        processes that don't have an associated user logon session.

        Args:
            system: System where process is created
            time: Process creation timestamp
            process_name: Full path to executable
            command_line: Command line string
            parent_pid: Parent process PID
            username: System account name (SYSTEM, root, etc.)
            syslog_message: Custom syslog message (overrides auto-generated message)
            emit_linux_syslog: Whether to attach a Linux syslog record to this process event.
            concurrency_group_id: Optional source-local process group for related
                foreground children such as cron shell/workload pairs.

        Returns:
            PID of the new process
        """
        from evidenceforge.events.contexts import ProcessContext

        self.state_manager.set_current_time(time)
        if _get_os_category(system.os) == "windows":
            process_name, command_line = _windows_script_host_process(
                process_name,
                command_line,
            )

        exe_name = ntpath.basename(process_name).lower()
        if (
            _get_os_category(system.os) == "windows"
            and exe_name in _WINDOWS_SHELL_UWP_USER_PROCESS_EXES
        ):
            session = self._active_interactive_windows_session(system, time)
            if session is None:
                return 0
            session_user = self._user_model_for_username(session.username)
            if self.state_manager.get_process(system.hostname, parent_pid) is None:
                parent_pid = self._resolve_parent(
                    system,
                    session_user,
                    time,
                    session.logon_id,
                    process_name,
                )
            return self.generate_process(
                user=session_user,
                system=system,
                time=time,
                logon_id=session.logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                allow_existing_browser_reuse=False,
            )

        singleton_service_pid = self._existing_windows_singleton_service_pid(
            system=system,
            process_name=process_name,
            time=time,
            username=username,
        )
        if singleton_service_pid is not None:
            return singleton_service_pid

        parent_pid = self._repair_process_parent_pid(
            system=system,
            time=time,
            logon_id={
                "SYSTEM": "0x3e7",
                "LOCAL SERVICE": "0x3e5",
                "NETWORK SERVICE": "0x3e4",
            }.get(username, "0x3e7"),
            process_name=process_name,
            command_line=command_line,
            parent_pid=parent_pid,
            process_username=username,
        )
        repaired_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if repaired_parent is not None and time <= repaired_parent.start_time:
            time = repaired_parent.start_time + timedelta(milliseconds=50)
        self.state_manager.set_current_time(time)
        self.state_manager.update_process_activity_time(system.hostname, parent_pid, time)
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=username,
            integrity_level="System",
        )

        # Determine system-level SID and logon ID
        sid = self.sid_registry.get(username, "S-1-5-18") if self.sid_registry else "S-1-5-18"
        system_logon_ids = {"SYSTEM": "0x3e7", "LOCAL SERVICE": "0x3e5", "NETWORK SERVICE": "0x3e4"}
        logon_id = system_logon_ids.get(username, "0x3e7")

        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        parent_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="system_process_create",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=username,
                user_sid=sid,
                logon_id=logon_id,
                subject_sid=sid,
                subject_username=username,
                subject_domain="NT AUTHORITY",
                subject_logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=username,
                integrity_level="System",
                logon_id=logon_id,
                parent_image=self._lookup_parent_image(system.hostname, parent_pid),
                parent_command_line=self._lookup_parent_command_line(system.hostname, parent_pid),
                parent_start_time=self._lookup_parent_start_time(system.hostname, parent_pid),
                token_elevation="%%1936",
                mandatory_label="S-1-16-16384",
                start_time=self._lookup_parent_start_time(system.hostname, pid),
                current_directory=self._derive_current_directory(
                    system=system,
                    username=username,
                    process_name=process_name,
                    command_line=command_line,
                    parent_pid=parent_pid,
                ),
                concurrency_group_id=concurrency_group_id,
            ),
            edr=EdrContext(object_id=proc_obj_id, actor_id=parent_obj_id),
        )

        self._record_process_source_create_time(system.hostname, pid, event)
        # Attach SyslogContext for Linux hosts
        if emit_linux_syslog and event.src_host and event.src_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            if syslog_message:
                event.syslog = SyslogContext(
                    app_name="systemd",
                    pid=1,
                    facility=3,
                    severity=6,
                    message=syslog_message,
                )
            elif "cron" in (process_name or "").lower():
                event.syslog = SyslogContext(
                    app_name="CRON",
                    pid=pid,
                    facility=9,
                    severity=6,
                    message=f"({username}) CMD ({command_line})",
                )
            else:
                app_name = process_name.split("/")[-1]
                event.syslog = SyslogContext(
                    app_name=app_name,
                    pid=pid,
                    facility=3,
                    severity=6,
                    message=f"started: {command_line}",
                )

        self.dispatcher.dispatch(event)
        self._record_process_source_create_time(system.hostname, pid, event)

        return pid

    def generate_system_process_termination(
        self,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        parent_pid: int = 0,
        username: str = "root",
        syslog_message: str | None = None,
        *,
        concurrency_group_id: str = "",
    ) -> None:
        """Terminate a system process, emitting eCAR PROCESS/TERMINATE + optional syslog.

        Unlike generate_process_termination(), this doesn't require a user session.
        Used for short-lived system service processes (systemd units, etc.).
        """
        from evidenceforge.events.contexts import ProcessContext

        if self._is_protected_windows_system_pid(system, pid):
            self.state_manager.update_process_activity_time(system.hostname, pid, time)
            return

        running_proc = self.state_manager.get_process(system.hostname, pid)
        if running_proc is not None:
            process_name = running_proc.image
            username = running_proc.username or username
            if (
                running_proc.last_activity_time is not None
                and time <= running_proc.last_activity_time
            ):
                delay_ms = 20 + (
                    _stable_seed(
                        "system_process_terminate_after_activity:"
                        f"{system.hostname}:{pid}:{running_proc.last_activity_time.isoformat()}"
                    )
                    % 480
                )
                time = running_proc.last_activity_time + timedelta(milliseconds=delay_ms)
        process_logon_id = (
            running_proc.logon_id
            if running_proc is not None and running_proc.logon_id
            else {"SYSTEM": "0x3e7", "LOCAL SERVICE": "0x3e5", "NETWORK SERVICE": "0x3e4"}.get(
                username, "0x3e7"
            )
        )
        if parent_pid not in (0, pid):
            self.state_manager.update_process_activity_time(system.hostname, parent_pid, time)
        time = self._clamp_after_visible_process_create(
            system,
            pid,
            time,
            "windows.process_exit_after_visible_create",
        )
        sid = self.sid_registry.get(username, "S-1-5-18") if self.sid_registry else "S-1-5-18"
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="process_terminate",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=username,
                user_sid=sid,
                logon_id=process_logon_id,
                subject_sid=sid,
                subject_username=username,
                subject_domain="NT AUTHORITY",
                subject_logon_id=process_logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line="",
                username=username,
                logon_id=process_logon_id,
                start_time=running_proc.start_time if running_proc is not None else None,
                concurrency_group_id=concurrency_group_id,
            ),
            edr=EdrContext(object_id=proc_obj_id),
        )

        if syslog_message and event.src_host and event.src_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            event.syslog = SyslogContext(
                app_name="systemd",
                pid=1,
                facility=3,
                severity=6,
                message=syslog_message,
            )

        self.dispatcher.dispatch(event)

    def _is_protected_windows_system_pid(self, system: System, pid: int) -> bool:
        """Return whether a PID belongs to the durable seeded Windows process tree."""
        if _get_os_category(system.os) != "windows":
            return False
        system_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        return pid in set(system_pids.values())

    def _dns_observed_ttls(
        self,
        *,
        resolver_ip: str,
        query: str,
        qtype_name: str,
        answers: list[str],
        is_internal: bool,
        base_ttl: int,
        time: datetime,
    ) -> list[float]:
        """Return resolver-consistent TTLs for a DNS RRset observation."""
        if not answers:
            return []
        bounded_ttl = max(1, int(base_ttl))
        if is_internal:
            return [float(bounded_ttl)] * len(answers)

        ts_epoch = time.timestamp()
        normalized_query = query.rstrip(".").lower()
        normalized_answers = tuple(sorted(str(answer) for answer in answers))
        cache_key = (resolver_ip, normalized_query, qtype_name.upper(), normalized_answers)
        offset = _stable_seed(f"dns_rrset_cache_cycle:{cache_key}") % bounded_ttl
        cycle_start = math.floor((ts_epoch - offset) / bounded_ttl) * bounded_ttl + offset
        age = max(0.0, ts_epoch - cycle_start)
        remaining = max(1, int(bounded_ttl - age))
        return [float(remaining)] * len(answers)

    def _normalize_dns_context_for_resolver(
        self,
        dns: DnsContext,
        *,
        resolver_ip: str,
        time: datetime,
    ) -> None:
        """Normalize caller-provided DNS context through shared resolver semantics."""
        ad_domain = getattr(self, "_ad_domain", "corp.local")
        qtype_name = (dns.query_type or "").upper()
        if qtype_name in {"A", "AAAA", "PTR", "MX", "NS", "SOA"}:
            dns.query = self._dns_canonical_internal_hostname(dns.query) or dns.query
        is_internal = qtype_name == "SRV" or _dns_is_internal_name(dns.query, ad_domain)
        if is_internal:
            dns.AA = True
        elif qtype_name != "TXT":
            dns.AA = False

        if dns.rcode != "NOERROR" or not dns.answers:
            return
        if dns.preserve_ttls and len(dns.TTLs) == len(dns.answers):
            return
        if not is_internal and qtype_name == "TXT" and len(dns.TTLs) == len(dns.answers):
            base_ttl = max(1, int(min(dns.TTLs)))
        else:
            base_ttl = _dns_base_ttl(dns.query, is_internal)
        dns.TTLs = self._dns_observed_ttls(
            resolver_ip=resolver_ip,
            query=dns.query,
            qtype_name=qtype_name or str(dns.qtype),
            answers=dns.answers,
            is_internal=is_internal,
            base_ttl=base_ttl,
            time=time,
        )

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        hostname: str | None = None,
        force_address: bool = False,
        bypass_cache: bool = False,
    ) -> None:
        """Emit a DNS lookup preceding a TCP connection.

        Generates both a Zeek conn.log UDP/53 record and a Zeek dns.log record
        with consistent fields. The dns.log answers field contains the dst_ip
        that the subsequent TCP connection will use.

        Args:
            src_ip: IP of the system making the query
            dst_ip: IP that will be resolved (the "answer")
            time: Timestamp of the DNS query (should precede TCP connection)
            hostname: Explicit domain name to use (bypasses REVERSE_DNS lookup)
            force_address: Force an A/AAAA lookup for connection prerequisites.
            bypass_cache: Emit a lookup even when the generator cache has a valid entry.
        """
        request = DnsLookupRequest(
            src_ip=src_ip,
            dst_ip=dst_ip,
            time=time,
            hostname=hostname,
            force_address=force_address,
            bypass_cache=bypass_cache,
        )
        DnsLookupActionBundle(executor=self, request=request).execute()

    def _execute_dns_lookup_bundle(self, request: DnsLookupRequest) -> None:
        """Expand one DNS lookup request into canonical evidence."""
        src_ip = request.src_ip
        dst_ip = request.dst_ip
        time = request.time
        hostname = request.hostname
        force_address = request.force_address

        rng = _get_rng()

        # Use explicit hostname if provided (domain-first selection),
        # otherwise fall back to REVERSE_DNS lookup
        if not hostname:
            hostname = REVERSE_DNS.get(dst_ip)
        if not hostname:
            if _is_private_ip(dst_ip):
                hostname = _generate_internal_hostname(
                    rng, dst_ip, getattr(self, "_ad_domain", "corp.local")
                )
            else:
                hostname = _generate_random_hostname(rng, dst_ip)
        hostname = self._dns_canonical_internal_hostname(hostname) or hostname

        # DNS caching: skip re-emission if this source/resolver/hostname tuple
        # still has a client-visible address answer. Values are expiration
        # epochs derived from the TTL actually returned in dns.log, not the
        # authoritative TTL, so later TCP evidence does not depend on visibly
        # expired DNS answers.
        if not hasattr(self, "_dns_cache"):
            self._dns_cache: dict[tuple[str, str, str, str], float] = {}
        if not hasattr(self, "_dns_cache_last_prune"):
            self._dns_cache_last_prune = 0.0

        ts_epoch = time.timestamp()

        # Keep the cache bounded: drop entries older than the max TTL horizon,
        # and enforce a hard cap under high-cardinality/adversarial inputs.
        if ts_epoch - self._dns_cache_last_prune >= 60 or len(self._dns_cache) > 50_000:
            cutoff = ts_epoch
            self._dns_cache = {
                key: cached_until
                for key, cached_until in self._dns_cache.items()
                if cached_until >= cutoff
            }
            if len(self._dns_cache) > 50_000:
                sorted_items = sorted(
                    self._dns_cache.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
                self._dns_cache = dict(sorted_items[:50_000])
            self._dns_cache_last_prune = ts_epoch

        ad_domain = getattr(self, "_ad_domain", "corp.local")
        is_internal = _dns_is_internal_name(hostname, ad_domain)

        # Determine DNS server IP from network visibility or use default. Forward
        # proxies use a sticky configured resolver policy instead of rotating
        # evenly across unrelated public DNS providers.
        dns_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
        src_system = getattr(self, "_ip_to_system", {}).get(src_ip)
        if src_system and "forward_proxy" in (src_system.roles or []) and not is_internal:
            resolver_pool = [ip for ip in dns_ips if _is_private_ip(ip)] or [
                "1.1.1.1",
                "8.8.8.8",
                "9.9.9.9",
            ]
            resolver_rng = random.Random(_stable_seed(f"proxy_dns_policy:{src_ip}"))
            primary_index = resolver_rng.randrange(len(resolver_pool))
            secondary_index = (
                primary_index + 1 + resolver_rng.randrange(max(1, len(resolver_pool) - 1))
            ) % len(resolver_pool)
            primary_resolver = resolver_pool[primary_index]
            secondary_resolver = resolver_pool[secondary_index]
            resolver_roll = random.Random(
                _stable_seed(f"proxy_dns_roll:{src_ip}:{hostname}:{int(ts_epoch // 300)}")
            ).random()
            dns_server_ip = primary_resolver if resolver_roll < 0.92 else secondary_resolver
        else:
            dns_server_ip = _get_rng().choice(dns_ips)

        cache_key = (src_ip, dns_server_ip, hostname, "ADDR")
        cached_until = self._dns_cache.get(cache_key, 0)
        if force_address and not request.bypass_cache and cached_until and cached_until > ts_epoch:
            return  # Cache hit — skip DNS emission

        _src_os = "windows"
        if src_system is not None:
            _src_os = _get_os_category(src_system.os)
        dns_time = time - timedelta(milliseconds=rng.randint(900, 1400))
        src_port = self._allocate_ephemeral_port(
            src_ip, dns_server_ip, 53, "udp", dns_time, _src_os
        )

        from evidenceforge.events.contexts import DnsContext

        # Phase 6.3: 0.2% chance of SERVFAIL (transient failures).
        # Known internal names are served by authoritative internal DNS and
        # should not randomly fail unless a scenario explicitly models DNS trouble.
        if not force_address and not is_internal and rng.random() < 0.002:
            dns_ctx = DnsContext(
                query=hostname,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="SERVFAIL",
                rcode_num=2,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=dns_server_ip,
                time=dns_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.03),
                orig_bytes=rng.randint(40, 100),
                resp_bytes=rng.randint(80, 400),
                src_port=src_port,
                dns=dns_ctx,
            )
            return

        # Determine query type, query string, and answer
        qtype_roll = 0.0 if force_address else rng.random()
        txt_ttl: int | None = None

        if ":" in dst_ip and force_address:
            qtype, qtype_name = 28, "AAAA"
            query = hostname
            answers = [dst_ip]
        elif qtype_roll < 0.65:
            # A record: hostname → IPv4
            qtype, qtype_name = 1, "A"
            query = hostname
            answers = _dns_address_rrset(hostname, dst_ip, is_internal=is_internal)
        elif qtype_roll < 0.85:
            # AAAA record: hostname → IPv6
            qtype, qtype_name = 28, "AAAA"
            query = hostname
            answers = _public_dns_aaaa_answers(hostname, dst_ip, is_internal=is_internal)
        elif qtype_roll < 0.93:
            # PTR record: reversed IP → rDNS name
            qtype, qtype_name = 12, "PTR"
            query = _dns_reverse_query(dst_ip)
            if _is_private_ip(dst_ip):
                answers = [hostname]
            else:
                answers = [_generate_rdns_name(rng, dst_ip, hostname)]
        elif qtype_roll < 0.98:
            # SRV record: AD service discovery — must resolve to DCs only
            qtype, qtype_name = 33, "SRV"
            domain = ad_domain
            query = rng.choice(_AD_SRV_QUERIES).format(domain=domain)
            dc_systems = getattr(self, "_dc_systems", [])
            if dc_systems:
                dc_sys = _get_rng().choice(dc_systems)
                dc_ip = dc_sys.ip
            else:
                dc_ips = getattr(self, "_dns_server_ips", ["10.0.0.1"])
                dc_ip = _get_rng().choice(dc_ips)
            dc_hostname = REVERSE_DNS.get(dc_ip, f"dc-01.{domain}")
            svc_prefix = query.split(".")[0]
            port = _SRV_PORT_MAP.get(svc_prefix, 389)
            answers = [f"0 100 {port} {dc_hostname}"]
            is_internal = True
        elif qtype_roll < 0.995:
            # TXT record: SPF/DKIM/DMARC-style mail/authentication lookups.
            qtype, qtype_name = 16, "TXT"
            query, txt_answer, txt_ttl = _dns_txt_query_and_answer(rng, hostname)
            answers = [txt_answer]
        else:
            # MX record: domain → mail server
            if _dns_hostname_allows_mx(hostname):
                qtype, qtype_name = 15, "MX"
                query = _dns_registrable_domain(hostname)
                if _dns_is_internal_name(query, ad_domain):
                    answers = [f"10 mail.{query}"]
                else:
                    answers = _public_dns_mx_answers(query)
            else:
                qtype, qtype_name = 16, "TXT"
                query, txt_answer, txt_ttl = _dns_txt_query_and_answer(rng, hostname)
                answers = [txt_answer]

        query_is_internal = qtype_name == "SRV" or _dns_is_internal_name(query, ad_domain)
        if query_is_internal and not _is_private_ip(dns_server_ip):
            dns_server_ip = _get_rng().choice(dns_ips)
            src_port = self._allocate_ephemeral_port(
                src_ip, dns_server_ip, 53, "udp", dns_time, _src_os
            )
        is_internal = query_is_internal

        if force_address and qtype in (1, 28) and query_is_internal and _is_private_ip(src_ip):
            self._emit_ad_srv_discovery(
                src_ip=src_ip,
                dns_server_ip=dns_server_ip,
                time=dns_time - timedelta(seconds=2, milliseconds=rng.randint(180, 420)),
                src_os=_src_os,
                domain=ad_domain,
                rng=rng,
            )

        # Internal authoritative names use stable TTLs. External answers may be
        # observed through a resolver cache, so expose realistic countdown TTLs.
        base_ttl = txt_ttl if txt_ttl is not None else _dns_base_ttl(query, is_internal)
        ttls = self._dns_observed_ttls(
            resolver_ip=dns_server_ip,
            query=query,
            qtype_name=qtype_name,
            answers=answers,
            is_internal=is_internal,
            base_ttl=base_ttl,
            time=dns_time,
        )
        if force_address and qtype in (1, 28) and not is_internal and ttls:
            min_client_ttl = max(30, math.ceil((time - dns_time).total_seconds()) + 1)
            ttls = [max(float(min_client_ttl), ttl) for ttl in ttls]

        # Only address lookups for the requested hostname populate the client
        # DNS cache. PTR/SRV/MX companions should not hide future A/AAAA
        # evidence for high-volume proxy or browser destinations.
        if query == hostname and qtype in (1, 28):
            client_ttl = max(1.0, min(ttls) if ttls else float(base_ttl))
            self._dns_cache[cache_key] = dns_time.timestamp() + client_ttl

        # Build DnsContext and emit connection + dns.log via fan-out
        dns_ctx = DnsContext(
            query=query,
            trans_id=rng.randint(1, 65535),
            qtype=qtype,
            query_type=qtype_name,
            rcode="NOERROR",
            rcode_num=0,
            answers=answers,
            TTLs=ttls,
            rtt=_dns_rtt(rng, dns_server_ip),
            AA=is_internal,
            RD=True,
            RA=True,
            preserve_ttls=True,
        )
        self.generate_connection(
            src_ip=src_ip,
            dst_ip=dns_server_ip,
            time=dns_time,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(40, 100),
            resp_bytes=rng.randint(80, 400),
            src_port=src_port,
            dns=dns_ctx,
        )

        # Address lookups that are prerequisites for TCP still occur in a
        # resolver ecosystem. Add low-volume companion questions so Zeek DNS
        # does not collapse to only A/TXT/SRV in generated enterprise slices.
        if force_address and rng.random() < 0.25:
            companion_time = dns_time + timedelta(milliseconds=rng.randint(1, 30))
            companion_src_port = self._allocate_ephemeral_port(
                src_ip, dns_server_ip, 53, "udp", companion_time, _src_os
            )
            companion_kind = rng.choices(
                ["AAAA", "PTR", "NS", "MX", "SOA"],
                weights=[45, 30, 10, 10, 5],
                k=1,
            )[0]
            companion_query = hostname
            companion_answers: list[str] = []
            companion_rcode = "NOERROR"
            companion_rcode_num = 0
            companion_qtype = 28
            if companion_kind == "AAAA":
                companion_qtype = 28
                companion_answers = _public_dns_aaaa_answers(
                    hostname,
                    dst_ip,
                    is_internal=is_internal,
                )
            elif companion_kind == "PTR":
                companion_qtype = 12
                companion_query = _dns_reverse_query(dst_ip)
                if _is_private_ip(dst_ip):
                    companion_answers = [hostname]
                else:
                    (
                        companion_rcode,
                        companion_rcode_num,
                        companion_answers,
                    ) = _public_dns_ptr_response(dst_ip, hostname)
            elif companion_kind == "NS":
                companion_qtype = 2
                companion_query = _dns_registrable_domain(hostname)
                if _dns_is_internal_name(companion_query, ad_domain):
                    companion_answers = [f"ns1.{companion_query}", f"ns2.{companion_query}"]
                else:
                    companion_answers = _public_dns_ns_answers(companion_query)
            elif companion_kind == "MX" and _dns_hostname_allows_mx(hostname):
                companion_qtype = 15
                companion_query = _dns_registrable_domain(hostname)
                if _dns_is_internal_name(companion_query, ad_domain):
                    companion_answers = [f"10 mail.{companion_query}"]
                else:
                    companion_answers = _public_dns_mx_answers(companion_query)
            else:
                companion_kind = "SOA"
                companion_qtype = 6
                companion_query = _dns_registrable_domain(hostname)
                if _dns_is_internal_name(companion_query, ad_domain):
                    companion_answers = [
                        _dns_soa_answer(
                            companion_query,
                            f"ns1.{companion_query}",
                            f"hostmaster.{companion_query}",
                            "internal",
                        )
                    ]
                else:
                    companion_answers = _public_dns_soa_answers(companion_query)
            companion_is_internal = _dns_is_internal_name(companion_query, ad_domain) or (
                companion_kind == "PTR" and _is_private_ip(dst_ip)
            )
            companion_ttls = self._dns_observed_ttls(
                resolver_ip=dns_server_ip,
                query=companion_query,
                qtype_name=companion_kind,
                answers=companion_answers,
                is_internal=companion_is_internal,
                base_ttl=_dns_base_ttl(companion_query, companion_is_internal),
                time=companion_time,
            )
            companion_ctx = DnsContext(
                query=companion_query,
                trans_id=rng.randint(1, 65535),
                qtype=companion_qtype,
                query_type=companion_kind,
                rcode=companion_rcode,
                rcode_num=companion_rcode_num,
                answers=companion_answers,
                TTLs=companion_ttls,
                rtt=_dns_rtt(rng, dns_server_ip),
                AA=companion_is_internal,
                RD=True,
                RA=True,
                preserve_ttls=True,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=dns_server_ip,
                time=companion_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.02),
                orig_bytes=rng.randint(40, 100),
                resp_bytes=rng.randint(80, 500),
                src_port=companion_src_port,
                dns=companion_ctx,
            )

        # Occasional resolver search-suffix mistakes/background discovery probes.
        # Keep this low-volume and avoid doubling an already-qualified internal name.
        if rng.random() < 0.05:
            nxdomain_queries = _dns_nxdomain_companion_queries(hostname, ad_domain)
            nx_query = rng.choice(nxdomain_queries)
            nx_time = dns_time - timedelta(milliseconds=rng.randint(1, 10))
            nx_is_internal = _dns_is_internal_name(nx_query, ad_domain) or nx_query in {
                "wpad",
                "wpad.local",
                "isatap",
            }
            nx_dns_server_ip = dns_server_ip
            if nx_is_internal and not _is_private_ip(nx_dns_server_ip):
                nx_dns_server_ip = _get_rng().choice(dns_ips)
            nx_src_port = self._allocate_ephemeral_port(
                src_ip, nx_dns_server_ip, 53, "udp", nx_time, _src_os
            )
            nx_qtype = 33 if nx_query.startswith("_") else 1
            nx_qtype_name = "SRV" if nx_qtype == 33 else "A"
            nx_ctx = DnsContext(
                query=nx_query,
                trans_id=rng.randint(1, 65535),
                qtype=nx_qtype,
                query_type=nx_qtype_name,
                rcode="NXDOMAIN",
                rcode_num=3,
                rtt=_dns_rtt(rng, nx_dns_server_ip),
                AA=nx_is_internal,
                RD=True,
                RA=True,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=nx_dns_server_ip,
                time=nx_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.01),
                orig_bytes=rng.randint(40, 80),
                resp_bytes=rng.randint(80, 200),
                src_port=nx_src_port,
                dns=nx_ctx,
            )

    def _emit_ad_srv_discovery(
        self,
        *,
        src_ip: str,
        dns_server_ip: str,
        time: datetime,
        src_os: str,
        domain: str,
        rng: random.Random,
    ) -> None:
        """Emit low-volume AD SRV service-discovery DNS for domain clients."""
        dc_systems = list(getattr(self, "_dc_systems", []) or [])
        if not dc_systems:
            return

        if not hasattr(self, "_ad_srv_discovery_cache"):
            self._ad_srv_discovery_cache: set[tuple[str, str, int]] = set()
        cache_key = (src_ip, domain.lower(), int((time + timedelta(seconds=5)).timestamp() // 3600))
        if cache_key in self._ad_srv_discovery_cache:
            return
        self._ad_srv_discovery_cache.add(cache_key)

        from evidenceforge.events.contexts import DnsContext

        query_templates = [
            "_ldap._tcp.dc._msdcs.{domain}",
            "_kerberos._tcp.{domain}",
            "_ldap._tcp.{domain}",
            "_kerberos._tcp.dc._msdcs.{domain}",
        ]
        start_index = _stable_seed(f"ad_srv_query:{src_ip}:{domain}") % len(query_templates)
        query_count = 1 + (_stable_seed(f"ad_srv_query_count:{src_ip}:{domain}") % 2)
        selected_queries = [
            query_templates[(start_index + index) % len(query_templates)]
            for index in range(query_count)
        ]
        dc_hosts = sorted(
            (
                (dc.hostname if "." in dc.hostname else f"{dc.hostname}.{domain}".rstrip("."))
                for dc in dc_systems
            ),
            key=str.lower,
        )
        for index, query_template in enumerate(selected_queries):
            query = query_template.format(domain=domain)
            service_prefix = query.split(".", 1)[0]
            port = _SRV_PORT_MAP.get(service_prefix, 389)
            answers = [f"0 100 {port} {hostname}" for hostname in dc_hosts[:2]]
            srv_time = time + timedelta(milliseconds=index * rng.randint(35, 95))
            src_port = self._allocate_ephemeral_port(
                src_ip,
                dns_server_ip,
                53,
                "udp",
                srv_time,
                src_os,
            )
            srv_ctx = DnsContext(
                query=query,
                trans_id=rng.randint(1, 65535),
                qtype=33,
                query_type="SRV",
                rcode="NOERROR",
                rcode_num=0,
                answers=answers,
                TTLs=[float(_dns_base_ttl(query, True))] * len(answers),
                rtt=_dns_rtt(rng, dns_server_ip),
                AA=True,
                RD=True,
                RA=True,
            )
            self.generate_connection(
                src_ip=src_ip,
                dst_ip=dns_server_ip,
                time=srv_time,
                dst_port=53,
                proto="udp",
                service="dns",
                duration=rng.uniform(0.001, 0.02),
                orig_bytes=rng.randint(48, 110),
                resp_bytes=rng.randint(140, 520),
                src_port=src_port,
                dns=srv_ctx,
            )

    def get_baseline_pattern(
        self,
        persona_name: str | None,
        persona=None,
    ) -> list[tuple[str, float]]:
        """Get baseline activity pattern for persona.

        Phase 2.6: If persona has activity_intensity overrides, builds
        dynamic pattern from those. Otherwise falls back to hardcoded patterns.

        Args:
            persona_name: Persona name string (or None for default)
            persona: Optional resolved Persona object for dynamic patterns

        Returns:
            List of (activity_type, probability) tuples
        """
        # Phase 2.6: Use activity_intensity overrides if provided
        if persona and persona.activity_intensity:
            return self._build_pattern_from_intensity(persona.activity_intensity)

        # Fall back to hardcoded patterns (Phase 1 behavior)
        if persona_name and persona_name.lower() in BASELINE_PATTERNS:
            return BASELINE_PATTERNS[persona_name.lower()]
        return BASELINE_PATTERNS["default"]

    def _build_pattern_from_intensity(self, intensity: dict[str, int]) -> list[tuple[str, float]]:
        """Convert activity_intensity dict to baseline pattern.

        Maps intensity values to probabilities. Higher intensity = higher probability.

        Args:
            intensity: Dict mapping activity_type to events/hour intensity

        Returns:
            List of (activity_type, probability) tuples
        """
        # Always include logon
        pattern: list[tuple[str, float]] = [("logon", 0.9)]

        if not intensity:
            return pattern

        # Normalize intensities to probabilities (cap at 0.95).
        # Ignore non-positive values when determining the denominator so an
        # all-zero (or all-negative) map cannot trigger divide-by-zero.
        positive_values = [
            value for activity, value in intensity.items() if activity != "logon" and value > 0
        ]
        if not positive_values:
            for activity, _ in intensity.items():
                if activity == "logon":
                    continue  # Already added
                pattern.append((activity, 0.1))
            return pattern

        max_val = max(positive_values)
        for activity, value in intensity.items():
            if activity == "logon":
                continue  # Already added
            normalized = max(value, 0) / max_val
            prob = min(0.95, normalized * 0.8 + 0.1)
            pattern.append((activity, prob))

        return pattern

    # Process→network correlation loaded from config/activity/process_network_map.yaml.
    # See generation/activity/process_network.py for the loader.

    def _emit_process_network_correlation(
        self,
        system: Any,
        process_name: str,
        command_line: str,
        time: datetime,
        pid: int,
        rng: random.Random,
    ) -> None:
        """Emit network connections correlated with a process creation.

        When a baseline process is one that normally generates network
        traffic (browsers, Office apps, dev tools, DB clients), emit
        a corresponding connection shortly after process creation.
        """
        # Extract executable basename
        exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        # Strip .exe for Linux lookups
        exe_base = exe.replace(".exe", "") if exe.endswith(".exe") else exe

        from evidenceforge.generation.activity.process_network import get_exe_to_service

        _exe_map = get_exe_to_service()
        conn_info = _exe_map.get(exe) or _exe_map.get(exe_base)
        if conn_info is None:
            return

        dst_port = conn_info["dst_port"]
        service = conn_info["service"]
        command_target = _extract_network_command_target(command_line, service)
        command_http_url = _extract_http_url_from_command(command_line)

        # Only emit ~60% of ambient app launches. Commands that name a concrete
        # remote endpoint should leave a matching socket attempt every time.
        if not command_target and not command_http_url and rng.random() > 0.60:
            return

        conn_time = time + timedelta(milliseconds=rng.randint(50, 500))
        ext_hostname = None
        http_context = None
        resp_bytes = rng.randint(500, 50000)
        emit_dns = bool(conn_info["external"])
        failure_conn_state = None

        if conn_info["external"]:
            # External connection: domain-first selection. App-specific mappings
            # can constrain destinations via DNS registry tags (e.g., Teams →
            # Teams/M365 endpoints instead of arbitrary web/CDN domains).
            from evidenceforge.generation.activity.dns_registry import (
                _domain_to_ip as _d2ip,
            )
            from evidenceforge.generation.activity.dns_registry import (
                generate_long_tail_domain as _gen_lt_domain,
            )
            from evidenceforge.generation.activity.dns_registry import (
                pick_domain_and_ip as _pick_domain_and_ip,
            )
            from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

            dns_tags = conn_info.get("dns_tags") or []
            process_http = _http_context_from_process_command(
                process_name,
                command_line,
                response_body_len=resp_bytes,
            )
            if process_http is not None:
                http_context, ext_hostname, dst_port, service = process_http
                command_target = self._system_for_hostname(ext_hostname)
                if command_target is not None:
                    dst_ip = command_target.ip
                else:
                    host_lower = ext_hostname.lower().rstrip(".")
                    ad_domain = str(getattr(self, "_ad_domain", "") or "").lower().rstrip(".")
                    if host_lower.endswith(".local") or (
                        ad_domain and host_lower.endswith(f".{ad_domain}")
                    ):
                        return
                    dst_ip = resolve_domain_ip(ext_hostname, src_host=system.hostname)
            elif service == "ssl":
                if hasattr(self, "_pick_profiled_tls_destination"):
                    ext_hostname, dst_ip = self._pick_profiled_tls_destination(
                        rng,
                        src_ip=system.ip,
                        source_system=system,
                        purpose_tags=tuple(dns_tags) if dns_tags else ("web", "saas"),
                    )
                elif dns_tags:
                    tag = rng.choice(dns_tags)
                    ext_hostname, dst_ip = _pick_domain_and_ip(
                        rng,
                        tag,
                        src_host=system.hostname,
                        include_os=_get_os_category(system.os),
                    )
                else:
                    ext_hostname = _gen_lt_domain(rng)
                    dst_ip = _d2ip(ext_hostname)
            elif dns_tags:
                tag = rng.choice(dns_tags)
                ext_hostname, dst_ip = _pick_domain_and_ip(
                    rng,
                    tag,
                    src_host=system.hostname,
                    include_os=_get_os_category(system.os),
                )
            else:
                ext_hostname = _gen_lt_domain(rng)
                dst_ip = _d2ip(ext_hostname)
        else:
            # Internal connection: use DB server or any internal server
            db_servers = getattr(self, "_db_servers", [])
            all_ips = getattr(self, "_all_system_ips", [])
            resolved_command_target = (
                self._resolve_command_network_target(command_target, service)
                if command_target
                else None
            )
            if resolved_command_target is not None:
                dst_ip, command_hostname = resolved_command_target
                if command_hostname:
                    ext_hostname = command_hostname
                    emit_dns = True
                target_system = getattr(self, "_ip_to_system", {}).get(dst_ip)
                if not self._process_network_target_supports_service(
                    target_system,
                    service,
                    dst_port,
                ):
                    failure_conn_state = "S0"
                    service = ""
                    resp_bytes = 0
            elif command_target:
                fallback_target = (
                    self._fallback_database_network_target(command_target, system)
                    if service in {"mssql", "mysql", "postgresql"}
                    else None
                )
                if fallback_target is None:
                    logger.debug(
                        "Skipping %s process network effect with unresolved command target %s",
                        service,
                        command_target,
                    )
                    return
                dst_ip, command_hostname, emit_dns = fallback_target
                if command_hostname:
                    ext_hostname = command_hostname
                failure_conn_state = "S0"
                service = ""
                resp_bytes = 0
            elif service in ("mssql", "mysql", "postgresql") and db_servers:
                # Filter to DB servers that match the requested service
                svc = service
                compatible = [
                    e
                    for e in db_servers
                    if (isinstance(e, dict) and e.get("service") == svc) or not isinstance(e, dict)
                ]
                if not compatible:
                    return  # No service-compatible DB host — skip
                db_entry = rng.choice(compatible)
                dst_ip = db_entry["ip"] if isinstance(db_entry, dict) else db_entry
            elif all_ips:
                compatible_ips = self._process_network_target_ips(system, service, dst_port)
                if compatible_ips:
                    dst_ip = rng.choice(compatible_ips)
                elif service in {"smb", "rdp", "ssh"} or dst_port in {22, 445, 3389}:
                    return
                else:
                    dst_ip = rng.choice([ip for ip in all_ips if ip != system.ip] or all_ips)
            else:
                return  # No internal targets available

        self.generate_connection(
            src_ip=system.ip,
            dst_ip=dst_ip,
            time=conn_time,
            dst_port=dst_port,
            proto="tcp",
            service=service,
            duration=rng.uniform(0.3, 15.0),
            orig_bytes=rng.randint(48, 140) if failure_conn_state else rng.randint(200, 5000),
            resp_bytes=resp_bytes,
            emit_dns=emit_dns,
            pid=pid,
            http=http_context,
            hostname=ext_hostname,
            source_system=system,
            conn_state=failure_conn_state,
        )

    def _baseline_type3_source_ip(
        self,
        user: User,
        system: System,
        rng: random.Random,
        *,
        is_service_account: bool,
    ) -> str | None:
        """Choose a source host for ambient baseline Type 3 logons.

        Human workstation users should not create self-sourced network logons;
        those are local-service semantics and otherwise collide with outbound
        SMB evidence whose real Type 3 record belongs on the file server.
        """
        all_ips = [str(ip) for ip in getattr(self, "_all_system_ips", []) if str(ip)]
        other_ips = [ip for ip in all_ips if ip != system.ip]

        username = user.username
        service_identity = (
            is_service_account
            or username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
            or username.endswith("$")
        )
        if service_identity and rng.random() < 0.30:
            return system.ip
        if other_ips:
            return rng.choice(other_ips)
        if service_identity:
            return system.ip
        return None

    def execute_baseline_activity(
        self, user: User, system: System, time: datetime, activity_type: str
    ) -> None:
        """Execute a specific baseline activity type.

        Args:
            user: User performing the activity
            system: System where activity occurs
            time: Activity timestamp
            activity_type: Type of activity to execute
        """
        # Logon activity (10% chance of failure — bad password)
        if activity_type == "logon":
            if _get_rng().random() < 0.10:
                self.generate_failed_logon(user, system, time)
                return

            # Phase 6.2: Realistic logon type distribution by system type
            # Type 3 (network) should dominate in AD; Type 5 only for service accounts
            rng = _get_rng()
            sys_type = (system.type or "workstation").lower()
            os_category = _get_os_category(system.os)
            is_service_account = user.username.endswith("$") or user.username.lower().startswith(
                "svc"
            )

            if os_category == "linux":
                # SSH is a modeled remote-session bundle on Linux. Generic
                # baseline logon activity should not create successful
                # non-SSH "remote" endpoint sessions.
                if is_service_account:
                    logon_type = 5
                else:
                    logon_type = 2
            elif sys_type in ("server", "domain_controller"):
                # Servers/DCs: Type 3 (network) dominates
                logon_type = rng.choices(
                    [3, 5, 10, 4, 2, 8, 9], weights=[70, 15, 8, 4, 1, 1, 1], k=1
                )[0]
            elif is_service_account:
                # Service accounts on workstations: network + service logons
                logon_type = rng.choices([3, 5, 10], weights=[70, 25, 5], k=1)[0]
            else:
                # Regular users on workstations: Type 3 dominant, no Type 5
                logon_type = rng.choices([3, 2, 7, 11, 10], weights=[55, 20, 10, 10, 5], k=1)[0]

            active_interactive = None
            if (
                logon_type in (2, 7, 11)
                and not is_service_account
                and sys_type not in ("server", "domain_controller")
            ):
                active_interactive = self._active_user_workstation_windows_session(
                    user,
                    system,
                    time,
                )
            if active_interactive is not None and logon_type in (2, 7, 11):
                # A baseline "logon" activity while the same user's console
                # session is already active is continued use, not a new
                # same-user Type 2/11 session.  If the session is visibly
                # locked, render the re-authentication as a Type 7 unlock;
                # otherwise just advance activity time and keep the durable
                # workstation session.
                lock_key = (system.hostname, user.username, active_interactive.logon_id)
                if logon_type == 7 and lock_key in getattr(self, "_last_workstation_lock_time", {}):
                    self.generate_workstation_unlock(
                        user,
                        system,
                        time,
                        active_interactive.logon_id,
                    )
                else:
                    active_interactive.last_activity_time = time
                return

            if active_interactive is None and logon_type == 7:
                # Type 7 is an unlock of an existing session, not a fresh
                # session-establishing event.
                logon_type = 2

            network_source_ip = None
            if logon_type == 3:
                network_source_ip = self._baseline_type3_source_ip(
                    user,
                    system,
                    rng,
                    is_service_account=is_service_account,
                )
                if network_source_ip is None:
                    logon_type = 2

            # Type 3 (network) logons are standalone events, not interactive sessions
            if logon_type in (3, 4, 5, 8, 9):
                # Pick a source IP from another system for network logons
                source_ip = network_source_ip
                logon_id = self.generate_logon(
                    user,
                    system,
                    time,
                    logon_type=logon_type,
                    source_ip=source_ip if source_ip else system.ip,
                )
                # Type 3/5 are short-lived — generate paired logoff after brief delay
                logoff_delay = _get_rng().uniform(1.0, 60.0)
                logoff_time = time + timedelta(seconds=logoff_delay)
                self.generate_logoff(user, system, logoff_time, logon_id, logon_type)
                return

            # Interactive logon types (2, 7, 10, 11) — create sessions
            if logon_type == 7:
                source_ip = "127.0.0.1"
            elif logon_type in (10, 11):
                # Remote interactive (RDP/VNC) — pick a realistic remote IP
                other_ips = getattr(self, "_all_system_ips", [])
                remote_ips = [ip for ip in other_ips if ip != system.ip]
                source_ip = _get_rng().choice(remote_ips) if remote_ips else system.ip
            else:
                source_ip = None  # Local console on Windows — defaults to system.ip

            # Linux remote interactive logons are SSH sessions. Let the SSH
            # compatibility path own transport, auth/PAM, endpoint session, and
            # session state so eCAR does not see a duplicate generic login.
            if (
                _get_os_category(system.os) == "linux"
                and logon_type in (2, 10)
                and source_ip
                and source_ip != system.ip
            ):
                self.generate_logon(
                    user,
                    system,
                    time,
                    logon_type=10,
                    source_ip=source_ip,
                )
                return
            elif (
                _get_os_category(system.os) == "windows"
                and logon_type == 10
                and source_ip
                and source_ip != system.ip
            ):
                rdp_time = time - timedelta(milliseconds=_get_rng().randint(80, 400))
                rdp_source_system = self._resolve_direct_rdp_source_system(
                    user,
                    system,
                    source_ip,
                    _get_rng(),
                )
                if rdp_source_system is not None:
                    source_ip = rdp_source_system.ip
                source_process_time = (
                    rdp_time - timedelta(milliseconds=_get_rng().randint(1800, 3200))
                    if rdp_source_system is not None
                    else None
                )
                self.generate_rdp_session(
                    user=user,
                    target_system=system,
                    time=rdp_time,
                    source_ip=source_ip,
                    source_system=rdp_source_system,
                    source_process_time=source_process_time,
                    source_process_factory=(
                        self._direct_rdp_source_process_factory(_get_rng())
                        if rdp_source_system is not None
                        else None
                    ),
                )
                return

            self.generate_logon(
                user,
                system,
                time,
                logon_type=logon_type,
                source_ip=source_ip,
            )

        # Process activities
        elif activity_type in PROCESS_TEMPLATES:
            os_category = _get_os_category(system.os)
            # Get or create session for this user (with login cooldown)
            if os_category == "windows":
                active_session = self._active_user_interactive_windows_session(
                    user,
                    system,
                    time,
                )
            else:
                sessions = self.state_manager.get_sessions_for_user(user.username)
                active_session = (
                    next(
                        (
                            s
                            for s in sessions
                            if s.system == system.hostname
                            and _session_active_for_activity(s, time)
                            and s.logon_type in (2, 10, 11)
                        ),
                        None,
                    )
                    if sessions
                    else None
                )

            if active_session:
                logon_id = active_session.logon_id
                active_session.last_activity_time = time
            else:
                future_session = (
                    self._near_future_user_interactive_windows_session(user, system, time)
                    if os_category == "windows"
                    else None
                )
                if future_session is not None:
                    time = ensure_utc(future_session.start_time) + timedelta(
                        seconds=_get_rng().uniform(20.0, 90.0)
                    )
                    logon_id = future_session.logon_id
                    future_session.last_activity_time = time
                else:
                    # No active session on this system — create logon slightly before
                    # the process to maintain causal ordering
                    if os_category == "linux":
                        logon_time = time - timedelta(seconds=_get_rng().uniform(7.0, 15.0))
                    else:
                        logon_time = time - timedelta(seconds=_get_rng().uniform(0.5, 2.0))
                    logon_id = self.generate_logon(user, system, logon_time)

            # Phase 2.10: OS-aware process template selection
            # Map activity_type to catalog category
            _CATEGORY_MAP = {
                "process_user_apps": "user_app",
                "process_code": "code",
                "process_build": "build",
                "process_query": "query",
            }
            catalog_category = _CATEGORY_MAP.get(activity_type)

            if catalog_category in ("user_app", "browser", "office") and system.type in (
                "server",
                "domain_controller",
            ):
                return

            # Try unified application catalog first (persona-aware, PE-metadata-rich)
            if catalog_category:
                from evidenceforge.generation.activity.application_catalog import (
                    pick_app_and_command,
                )

                rng = _get_rng()
                result = pick_app_and_command(
                    rng,
                    user.persona or "default",
                    os_category,
                    catalog_category,
                    username=user.username,
                    system_type=system.type,
                )
                if result:
                    process_name, command_line = result
                    command_line = self._parameterize_command_for_system(
                        rng,
                        command_line,
                        username=user.username,
                        system=system,
                    )
                    process_time = time
                    shell_command_line = command_line
                    source_processes = [(process_name, command_line)]
                    if os_category == "linux":
                        shell_command_line = _background_linux_shell_command_if_needed(command_line)
                        process_time = self._schedule_bash_history_time(
                            user, system, time, shell_command_line
                        )
                        if process_time is None or not self._is_within_scenario_window(
                            process_time
                        ):
                            return
                        source_processes = _linux_catalog_processes_from_shell_command(
                            process_name,
                            shell_command_line,
                            username=user.username,
                        )
                        process_name, command_line = source_processes[0]
                    parent_pid = self._resolve_parent(
                        system, user, process_time, logon_id, process_name
                    )
                    if os_category == "linux":
                        process_time = self._reserve_foreground_shell_time(
                            system=system,
                            username=user.username,
                            logon_id=logon_id,
                            parent_pid=parent_pid,
                            requested_time=process_time,
                            seed_text=shell_command_line,
                        )
                        if not self._is_within_scenario_window(process_time):
                            return
                    pid = -1
                    created_processes: list[tuple[int, str, str, datetime]] = []
                    for process_index, (
                        source_process_name,
                        source_command_line,
                    ) in enumerate(source_processes):
                        source_process_time = process_time + timedelta(
                            milliseconds=process_index * 35
                        )
                        if not self._is_within_scenario_window(source_process_time):
                            continue
                        source_pid = self.generate_process(
                            user,
                            system,
                            source_process_time,
                            logon_id,
                            source_process_name,
                            source_command_line,
                            parent_pid=parent_pid,
                        )
                        if pid < 0:
                            pid = source_pid
                            process_name = source_process_name
                            command_line = source_command_line
                            process_time = source_process_time
                        created_processes.append(
                            (
                                source_pid,
                                source_process_name,
                                source_command_line,
                                source_process_time,
                            )
                        )
                        self._record_user_process(system, user, source_pid, source_process_name)
                    if not created_processes:
                        return
                    if active_session:
                        active_session.last_activity_time = process_time
                    effect_process_name, effect_command_line = self._process_effect_context(
                        system,
                        pid,
                        process_name,
                        command_line,
                    )
                    network_process_name, network_command_line = (
                        _network_effect_context_for_process(
                            process_name,
                            command_line,
                            effect_process_name,
                            effect_command_line,
                        )
                    )

                    # Spawn child/utility processes for apps that have them
                    if activity_type == "process_user_apps":
                        from evidenceforge.generation.activity.application_catalog import (
                            get_child_processes,
                        )

                        exe_lower = effect_process_name.rsplit("\\", 1)[-1].lower()
                        if "/" in effect_process_name:
                            exe_lower = effect_process_name.rsplit("/", 1)[-1].lower()
                        child_entries = get_child_processes(os_category, exe_lower)
                        if child_entries:
                            num_children = rng.randint(1, min(3, len(child_entries)))
                            for entry in rng.sample(child_entries, num_children):
                                child_time = process_time + timedelta(seconds=rng.uniform(0.5, 3.0))
                                child_image = entry["image"]
                                child_cmd = entry["command_line"]
                                if "{username}" in child_image:
                                    child_image = child_image.replace("{username}", user.username)
                                if "{username}" in child_cmd:
                                    child_cmd = child_cmd.replace("{username}", user.username)
                                self.generate_process(
                                    user,
                                    system,
                                    child_time,
                                    logon_id,
                                    child_image,
                                    child_cmd,
                                    parent_pid=pid,
                                )

                    # Emit correlated network connection for network-active apps
                    # (tight PID+timestamp coupling alongside profile-driven volume)
                    self._emit_process_network_correlation(
                        system,
                        network_process_name,
                        network_command_line,
                        process_time,
                        pid,
                        rng,
                    )

                    # Also generate bash history for Linux processes from the same
                    # canonical command so eCAR and shell artifacts do not diverge.
                    if os_category == "windows":
                        lifetime = _windows_foreground_lifetime(
                            effect_process_name,
                            effect_command_line,
                        )
                        if lifetime is not None:
                            self._generate_bounded_foreground_process_termination(
                                user=user,
                                system=system,
                                start_time=process_time,
                                pid=pid,
                                process_name=effect_process_name,
                                logon_id=logon_id,
                                lifetime=lifetime,
                                rng=rng,
                            )
                    elif os_category == "linux":
                        self._emit_bash_command_event(
                            user,
                            system,
                            process_time,
                            shell_command_line,
                        )
                        for (
                            source_pid,
                            source_process_name,
                            source_command_line,
                            source_process_time,
                        ) in created_processes:
                            lifetime = _linux_foreground_lifetime(
                                source_process_name,
                                source_command_line,
                            )
                            if lifetime is None:
                                continue
                            running_proc = self.state_manager.get_process(
                                system.hostname, source_pid
                            )
                            actual_process_start = (
                                running_proc.start_time
                                if running_proc is not None
                                else source_process_time
                            )
                            termination_time = (
                                self._generate_bounded_foreground_process_termination(
                                    user=user,
                                    system=system,
                                    start_time=actual_process_start,
                                    pid=source_pid,
                                    process_name=source_process_name,
                                    logon_id=logon_id,
                                    lifetime=lifetime,
                                    rng=rng,
                                )
                            )
                            self._remember_foreground_shell_available(
                                system=system,
                                username=user.username,
                                logon_id=logon_id,
                                parent_pid=parent_pid,
                                termination_time=termination_time,
                                seed_text=source_command_line,
                            )

            # Legacy PROCESS_TEMPLATES only for process_system (not user apps/code/build/query)
            elif activity_type == "process_system":
                if os_category == "windows" and activity_type in PROCESS_TEMPLATES:
                    rng = _get_rng()
                    process_name, command_line = rng.choice(PROCESS_TEMPLATES[activity_type])
                    process_name = process_name.replace("{username}", user.username)
                    command_line = self._parameterize_command_for_system(
                        rng,
                        command_line,
                        username=user.username,
                        system=system,
                    )
                    parent_pid = self._resolve_parent(system, user, time, logon_id, process_name)
                    pid = self.generate_process(
                        user,
                        system,
                        time,
                        logon_id,
                        process_name,
                        command_line,
                        parent_pid=parent_pid,
                    )
                    self._record_user_process(system, user, pid, process_name)
                    lifetime = _windows_foreground_lifetime(process_name, command_line)
                    if lifetime is not None:
                        self._generate_bounded_foreground_process_termination(
                            user=user,
                            system=system,
                            start_time=time,
                            pid=pid,
                            process_name=process_name,
                            logon_id=logon_id,
                            lifetime=lifetime,
                            rng=rng,
                        )
                elif os_category == "linux" and activity_type in PROCESS_TEMPLATES_LINUX:
                    rng = _get_rng()
                    process_name, command_line = rng.choice(PROCESS_TEMPLATES_LINUX[activity_type])
                    command_line = self._parameterize_command_for_system(
                        rng,
                        command_line,
                        username=user.username,
                        system=system,
                    )
                    command_line = _background_linux_shell_command_if_needed(command_line)
                    process_time = self._schedule_bash_history_time(
                        user, system, time, command_line
                    )
                    if process_time is None or not self._is_within_scenario_window(process_time):
                        return
                    parent_pid = self._resolve_parent(
                        system, user, process_time, logon_id, process_name
                    )
                    process_time = self._reserve_foreground_shell_time(
                        system=system,
                        username=user.username,
                        logon_id=logon_id,
                        parent_pid=parent_pid,
                        requested_time=process_time,
                        seed_text=command_line,
                    )
                    if not self._is_within_scenario_window(process_time):
                        return
                    pid = self.generate_process(
                        user,
                        system,
                        process_time,
                        logon_id,
                        process_name,
                        command_line,
                        parent_pid=parent_pid,
                    )
                    self._record_user_process(system, user, pid, process_name)
                    if active_session:
                        active_session.last_activity_time = process_time
                    self._emit_bash_command_event(user, system, process_time, command_line)
                    lifetime = _linux_foreground_lifetime(process_name, command_line)
                    if lifetime is not None:
                        running_proc = self.state_manager.get_process(system.hostname, pid)
                        actual_process_start = (
                            running_proc.start_time if running_proc is not None else process_time
                        )
                        termination_time = self._generate_bounded_foreground_process_termination(
                            user=user,
                            system=system,
                            start_time=actual_process_start,
                            pid=pid,
                            process_name=process_name,
                            logon_id=logon_id,
                            lifetime=lifetime,
                            rng=rng,
                        )
                        self._remember_foreground_shell_available(
                            system=system,
                            username=user.username,
                            logon_id=logon_id,
                            parent_pid=parent_pid,
                            termination_time=termination_time,
                            seed_text=command_line,
                        )

        # Connection activities
        elif activity_type in EXTERNAL_IPS:
            rng = _get_rng()
            conn_hostname = None  # Domain name for DNS/SNI consistency

            # Domain-first selection: pick a domain, resolve to its IP.
            # Uses pick_domain_and_ip() which maintains correct per-domain IP
            # pools and per-host deterministic selection (simulates DNS cache).
            from evidenceforge.generation.activity.dns_registry import (
                _domain_to_ip,
                generate_long_tail_domain,
                pick_domain_and_ip,
            )

            _tag_for_activity = {
                "connection_web": "web",
                "connection_saas": "saas",
                "connection_email": "email",
                "connection_git": "git",
                "connection_db": "internal",
            }
            tag = _tag_for_activity.get(activity_type, "web")

            if activity_type in ("connection_web", "connection_saas") and rng.random() < 0.30:
                # 30% chance: long-tail domain for CDN/SaaS/analytics diversity
                conn_hostname = generate_long_tail_domain(rng)
                dst_ip = _domain_to_ip(conn_hostname)
            else:
                # Known domain with correct per-domain IP pairing
                conn_hostname, dst_ip = pick_domain_and_ip(rng, tag, src_host=system.hostname)
                if dst_ip == system.ip:
                    return  # Skip self-connections

            # Set service and port based on activity type
            if activity_type in ("connection_web", "connection_saas"):
                service = rng.choice(["http", "ssl"])
                dst_port = 443 if service == "ssl" else 80
                if service == "ssl":
                    conn_hostname, dst_ip = self._pick_profiled_tls_destination(
                        rng,
                        src_ip=system.ip,
                        source_system=system,
                        purpose_tags=(tag,),
                    )
            elif activity_type == "connection_email":
                if getattr(getattr(self, "_scenario_environment", None), "email", None) is not None:
                    return
                service = "smtp"
                # Route through internal Exchange if detected (P1-15)
                exchange_ip = getattr(self, "_exchange_ip", None)
                if exchange_ip:
                    dst_ip = exchange_ip
                    dst_port = 25  # Internal SMTP relay uses port 25
                else:
                    dst_port = 587
            elif activity_type == "connection_git":
                service = "ssl"
                dst_port = 443
            elif activity_type == "connection_db":
                db_servers = getattr(self, "_db_servers", [])
                if db_servers:
                    db = _get_rng().choice(db_servers)
                    dst_ip = db["ip"]
                    service = db["service"]
                    dst_port = db["port"]
                    conn_hostname = None
                else:
                    # No DB servers detected from scenario; skip DB connection
                    return
            else:
                service = None
                dst_port = 443

            # Generate realistic traffic sizes
            orig_bytes = rng.randint(500, 5000)
            resp_bytes = rng.randint(1000, 50000)
            duration = rng.uniform(0.1, 5.0)

            self.generate_connection(
                src_ip=system.ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                service=service,
                emit_dns=True,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                hostname=conn_hostname,
            )

    def generate_machine_account_logon(
        self,
        hostname: str,
        machine_username: str,
        dc_hostname: str,
        source_ip: str,
        dc_ip: str,
        time: datetime,
        domain: str = "",
    ) -> None:
        """Generate machine account logon event (4624 type 3) on the DC.

        Machine accounts (COMPUTERNAME$) authenticate to DCs constantly for
        GPO updates, Kerberos renewal, LDAP queries, etc. The event is logged
        on the DC, not on the source machine.
        """
        request = MachineAccountLogonRequest(
            hostname=hostname,
            machine_username=machine_username,
            dc_hostname=dc_hostname,
            source_ip=source_ip,
            dc_ip=dc_ip,
            time=time,
            domain=domain,
        )
        MachineAccountLogonActionBundle(self, request).execute()

    def _execute_machine_account_logon_bundle(
        self,
        request: MachineAccountLogonRequest,
    ) -> None:
        """Generate machine account logon event (4624 type 3) on the DC."""
        machine_username = request.machine_username
        dc_hostname = request.dc_hostname
        source_ip = request.source_ip
        dc_ip = request.dc_ip
        time = request.time
        domain = request.domain

        domain = domain or getattr(self, "_netbios_domain", "CORP")
        rng = _get_rng()
        logon_id = self.state_manager.allocate_logon_id(dc_hostname, time)
        tgt_time, tgs_time = self._kerberos_ticket_times(
            time,
            rng,
            tgs_before_ms=(8, 65),
            tgt_before_tgs_ms=(35, 220),
        )
        source_port = self._reserve_kerberos_source_port(source_ip, dc_hostname, tgt_time)
        self.generate_kerberos_tgt(
            username=machine_username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgt_time,
            source_port=source_port,
        )
        service_name = rng.choices(
            [
                f"host/{dc_hostname}",
                f"ldap/{dc_hostname}",
                f"cifs/{dc_hostname}",
                f"DNS/{dc_hostname}",
            ],
            weights=[35, 35, 20, 10],
            k=1,
        )[0]
        self.generate_kerberos_service_ticket(
            username=machine_username,
            service_name=service_name,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=tgs_time,
            source_port=source_port,
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="machine_logon",
            dst_host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=logon_id,
                logon_type=3,
                auth_package="Kerberos",
                source_ip=source_ip,
                source_port=source_port,
                logon_process="Kerberos",
                lm_package="-",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid=self._get_sid("SYSTEM"),
                subject_username="SYSTEM",
                subject_domain="NT AUTHORITY",
                subject_logon_id="0x3e7",
            ),
        )
        self.dispatcher.dispatch(event)

        # Paired logoff for short-lived type 3 machine logon (1-30 seconds)
        logoff_delay = rng.uniform(1.0, 30.0)
        logoff_event = SecurityEvent(
            timestamp=time + timedelta(seconds=logoff_delay),
            event_type="logoff",
            dst_host=self._build_dc_host_context(dc_hostname),
            auth=AuthContext(
                username=machine_username,
                user_sid=self._get_sid(machine_username),
                logon_id=logon_id,
                logon_type=3,
            ),
        )
        self.dispatcher.dispatch(logoff_event)

        # Also generate the Kerberos network connection to DC
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=dc_ip,
            time=time,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=rng.uniform(0.001, 0.03),
            orig_bytes=rng.randint(200, 1000),
            resp_bytes=rng.randint(200, 1500),
            src_port=source_port,
        )

    def generate_kerberos_tgt(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
        source_port: int | None = None,
    ) -> None:
        """Generate Kerberos TGT request event (4768) on the DC."""
        request = KerberosTgtRequest(
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=time,
            domain=domain,
            source_port=source_port,
        )
        KerberosTgtActionBundle(self, request).execute()

    def _execute_kerberos_tgt_bundle(self, request: KerberosTgtRequest) -> None:
        """Generate Kerberos TGT request event (4768) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        username = request.username
        source_ip = request.source_ip
        dc_hostname = request.dc_hostname
        time = request.time
        domain = request.domain
        source_port = request.source_port

        # Kerberos realm is always the DNS FQDN in uppercase, never NetBIOS short name
        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()
        from evidenceforge.generation.activity.kerberos_realism import pick_tgt_success_fields

        tgt_fields = pick_tgt_success_fields(rng, domain.lower())
        source_port = self._reserve_kerberos_source_port(
            source_ip,
            dc_hostname,
            time,
            source_port,
        )
        time = self._kerberos_source_time(
            time,
            event_type="kerberos_tgt",
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            source_port=source_port,
        )

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options=tgt_fields["ticket_options"],
                encryption_type=tgt_fields["encryption_type"],
                pre_auth_type=tgt_fields["pre_auth_type"],
                cert_issuer_name=tgt_fields["cert_issuer_name"],
                cert_serial_number=tgt_fields["cert_serial_number"],
                cert_thumbprint=tgt_fields["cert_thumbprint"],
                source_ip=f"::ffff:{source_ip}",
                source_port=source_port,
            ),
        )

        self._remember_kerberos_audit(
            source_ip,
            dc_hostname,
            time,
            source_port=source_port,
        )
        self._remember_kerberos_tgt_cache(username, source_ip, dc_hostname, time, rng)
        self.dispatcher.dispatch(event)

    def generate_kerberos_tgt_renewal(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
        source_port: int | None = None,
    ) -> None:
        """Generate Kerberos TGT renewal event (4770) on the DC."""
        request = KerberosTgtRenewalRequest(
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=time,
            domain=domain,
            source_port=source_port,
        )
        KerberosTgtRenewalActionBundle(self, request).execute()

    def _execute_kerberos_tgt_renewal_bundle(
        self,
        request: KerberosTgtRenewalRequest,
    ) -> None:
        """Generate Kerberos TGT renewal event (4770) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        username = request.username
        source_ip = request.source_ip
        dc_hostname = request.dc_hostname
        time = request.time
        domain = request.domain
        source_port = request.source_port

        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()
        source_port = self._reserve_kerberos_source_port(
            source_ip,
            dc_hostname,
            time,
            source_port,
        )
        time = self._kerberos_source_time(
            time,
            event_type="kerberos_tgt_renewal",
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            source_port=source_port,
        )

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_tgt_renewal",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username,
                target_domain=domain,
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                service_sid=self._get_sid("krbtgt"),
                ticket_options=rng.choices(["0x2", "0x60810010"], weights=[80, 20], k=1)[0],
                encryption_type=rng.choices(["0x12", "0x11", "0x17"], weights=[70, 15, 15], k=1)[0],
                source_ip=f"::ffff:{source_ip}",
                source_port=source_port,
            ),
        )

        self._remember_kerberos_audit(
            source_ip,
            dc_hostname,
            time,
            source_port=source_port,
        )
        self._remember_kerberos_tgt_cache(username, source_ip, dc_hostname, time, rng)
        self.dispatcher.dispatch(event)

    def generate_kerberos_service_ticket(
        self,
        username: str,
        service_name: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        domain: str = "",
        source_port: int | None = None,
    ) -> None:
        """Generate Kerberos service ticket request event (4769) on the DC."""
        request = KerberosServiceTicketRequest(
            username=username,
            service_name=service_name,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=time,
            domain=domain,
            source_port=source_port,
        )
        KerberosServiceTicketActionBundle(self, request).execute()

    def _execute_kerberos_service_ticket_bundle(
        self,
        request: KerberosServiceTicketRequest,
    ) -> None:
        """Generate Kerberos service ticket request event (4769) on the DC."""
        from evidenceforge.events.contexts import KerberosContext

        username = request.username
        service_name = request.service_name
        source_ip = request.source_ip
        dc_hostname = request.dc_hostname
        time = request.time
        domain = request.domain
        source_port = request.source_port

        domain = domain or getattr(self, "_ad_domain", "corp.local").upper()
        rng = _get_rng()
        source_port = self._reserve_kerberos_source_port(
            source_ip,
            dc_hostname,
            time,
            source_port,
        )
        time = self._kerberos_source_time(
            time,
            event_type="kerberos_service",
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            source_port=source_port,
            service_name=service_name,
        )

        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_service",
            dst_host=self._build_dc_host_context(dc_hostname),
            kerberos=KerberosContext(
                target_username=username.split("@", 1)[0],
                target_domain=domain,
                service_name=service_name,
                service_sid=(
                    self._get_sid("krbtgt")
                    if service_name.lower().startswith("krbtgt/")
                    else self._get_sid(
                        f"{service_name.split('/')[1]}$" if "/" in service_name else service_name
                    )
                ),
                ticket_options=rng.choices(
                    ["0x40810000", "0x40810010", "0x40000000", "0x10"],
                    weights=[50, 25, 15, 10],
                    k=1,
                )[0],
                encryption_type=rng.choices(["0x12", "0x11", "0x17"], weights=[70, 15, 15], k=1)[0],
                source_ip=f"::ffff:{source_ip}",
                source_port=source_port,
            ),
        )

        self._remember_kerberos_audit(
            source_ip,
            dc_hostname,
            time,
            source_port=source_port,
        )
        self.dispatcher.dispatch(event)

    def generate_ntlm_validation(
        self,
        username: str,
        workstation: str,
        dc_hostname: str,
        time: datetime,
        status: str = "0x0",
    ) -> None:
        """Generate NTLM credential validation event (4776) on the DC."""
        request = NtlmValidationRequest(
            username=username,
            workstation=workstation,
            dc_hostname=dc_hostname,
            time=time,
            status=status,
        )
        NtlmValidationActionBundle(self, request).execute()

    def _execute_ntlm_validation_bundle(self, request: NtlmValidationRequest) -> None:
        """Generate NTLM credential validation event (4776) on the DC."""
        event = SecurityEvent(
            timestamp=request.time,
            event_type="ntlm_validation",
            dst_host=self._build_dc_host_context(request.dc_hostname),
            auth=AuthContext(
                username=request.username,
                source_ip=request.workstation,  # SourceWorkstation stored in source_ip
                failure_status=request.status,
            ),
        )

        self.dispatcher.dispatch(event)

    def generate_explicit_credentials(
        self,
        user: User,
        system: System,
        time: datetime,
        target_username: str,
        target_server: str,
        process_name: str,
        process_pid: int | None,
        source_ip: str = "",
        source_port: int = 0,
    ) -> None:
        """Generate explicit credentials event (4648) on source system.

        Fires when a process uses RunAs, scheduled tasks, PsExec, WMIC,
        or other explicit credential usage.
        """
        bundle = ExplicitCredentialUseActionBundle(
            self,
            ExplicitCredentialUseRequest(
                user=user,
                system=system,
                time=time,
                target_username=target_username,
                target_server=target_server,
                process_name=process_name,
                process_pid=process_pid,
                source_ip=source_ip,
                source_port=source_port,
            ),
        )
        bundle.execute()

    def _coerce_windows_explicit_credentials_subject(
        self,
        user: User,
        system: System,
        target_username: str,
    ) -> User:
        """Return a Windows-native subject for 4648 when the narrative actor is Unix-local."""
        if _get_os_category(system.os) != "windows":
            return user
        if user.username.lower() not in _LINUX_LOCAL_ACCOUNTS:
            return user

        candidate = target_username.split("\\")[-1].split("@", 1)[0]
        known_users = getattr(self, "_users_by_username", {})
        if candidate and candidate.lower() not in _LINUX_LOCAL_ACCOUNTS:
            if candidate in known_users:
                return known_users[candidate]
            if _USER_MODEL_USERNAME_RE.fullmatch(candidate):
                return User(
                    username=candidate,
                    full_name=candidate,
                    email=f"{candidate}@{self._valid_fallback_email_domain()}",
                )

        assigned_user = getattr(system, "assigned_user", "")
        if assigned_user:
            assigned = known_users.get(assigned_user)
            if assigned is not None:
                return assigned
            if _USER_MODEL_USERNAME_RE.fullmatch(assigned_user):
                return User(
                    username=assigned_user,
                    full_name=assigned_user,
                    email=f"{assigned_user}@{self._valid_fallback_email_domain()}",
                )
        return User(
            username="Administrator",
            full_name="Administrator",
            email=f"administrator@{self._valid_fallback_email_domain()}",
        )

    def _explicit_credentials_source_ip(
        self,
        system: System,
        target_server: str,
        source_ip: str = "",
    ) -> str:
        """Return source network metadata for explicit-credential use."""
        target = target_server.strip().lower()
        system_domain = getattr(system, "domain", "")
        local_names = {
            system.hostname.lower(),
            f"{system.hostname}.{system_domain}".lower() if system_domain else "",
            system.ip,
        }
        if target in {"", "-", "localhost", "127.0.0.1", "::1"}:
            return "-"
        target_host = target.split(".", 1)[0]
        if target in local_names or target_host == system.hostname.lower():
            return "-"

        explicit_source_ip = source_ip.strip()
        if explicit_source_ip in {"", "-"}:
            return "-"

        normalized_source_ip = explicit_source_ip.removeprefix("::ffff:")
        if normalized_source_ip.lower() in local_names or explicit_source_ip.lower() in local_names:
            return "-"

        source_system = getattr(self, "_ip_to_system", {}).get(normalized_source_ip)
        if source_system is None:
            return "-"
        if (
            source_system.ip == system.ip
            or source_system.hostname.lower() == system.hostname.lower()
        ):
            return "-"
        return normalized_source_ip

    def _ensure_explicit_credentials_subject_logon(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> str:
        """Return a visible subject session for a Windows 4648 event."""
        existing = self._get_user_logon_id(user.username, system.hostname, time)
        if existing != "0x0":
            return existing
        if user.username in _SYSTEM_ACCOUNT_LOGON_IDS:
            return _SYSTEM_ACCOUNT_LOGON_IDS[user.username]

        logon_time = time - timedelta(seconds=2)
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
            if ensure_utc(logon_time) < scenario_start:
                logon_time = time - timedelta(milliseconds=500)
        return self.generate_logon(user, system, logon_time, logon_type=2, source_ip="-")

    def _explicit_credentials_target_domain(
        self,
        target_username: str,
        target_server: str,
        source_system: System,
    ) -> str:
        """Return a source-native TargetDomainName for explicit credentials."""
        if "\\" in target_username:
            return target_username.split("\\", 1)[0]
        if "@" in target_username:
            return target_username.rsplit("@", 1)[1].upper()

        netbios_domain = self._build_host_context(source_system).netbios_domain
        if target_username in _SYSTEM_ACCOUNT_LOGON_IDS:
            return "NT AUTHORITY"
        if target_username in getattr(self, "_users_by_username", {}):
            return netbios_domain
        if target_username in self.sid_registry and target_username.lower() not in {
            "root",
            "apache",
        }:
            return netbios_domain

        target_host = target_server.split(".", 1)[0].upper() if target_server else ""
        world_model = getattr(self, "_world_model", None)
        target_system = None
        if world_model is not None:
            target_system = world_model.systems_by_hostname.get(target_server) or (
                world_model.systems_by_hostname.get(target_server.split(".", 1)[0])
                if target_server
                else None
            )
        if target_system is not None and _get_os_category(target_system.os) != "windows":
            return target_host or netbios_domain
        if target_username.lower() in {"root", "apache"}:
            return target_host or "-"
        return netbios_domain

    def generate_workstation_lock(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> None:
        """Generate workstation lock event (4800)."""
        request = WorkstationLockRequest(
            user=user,
            system=system,
            time=time,
            logon_id=logon_id,
        )
        WorkstationLockActionBundle(self, request).execute()

    def _execute_workstation_lock_bundle(self, request: WorkstationLockRequest) -> None:
        """Generate workstation lock event (4800)."""
        user = request.user
        system = request.system
        time = request.time
        logon_id = request.logon_id

        session = self.state_manager.get_session(logon_id)
        if (
            session is None
            or session.system != system.hostname
            or session.start_time > time
            or not _is_windows_workstation_session(session)
        ):
            return
        if not hasattr(self, "_last_workstation_lock_time"):
            self._last_workstation_lock_time = {}
        if self._locked_user_interactive_windows_session(user, system, time) is not None:
            return
        lock_key = (system.hostname, user.username, logon_id)
        if lock_key in self._last_workstation_lock_time:
            return
        self._last_workstation_lock_time[lock_key] = time
        session = self.state_manager.get_session(logon_id)
        if session is not None:
            session.last_activity_time = time
        event = SecurityEvent(
            timestamp=time,
            event_type="workstation_locked",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                session_id=session.session_id,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_workstation_unlock(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> None:
        """Generate workstation unlock event (4801 + 4624 type 7)."""
        request = WorkstationUnlockRequest(
            user=user,
            system=system,
            time=time,
            logon_id=logon_id,
        )
        WorkstationUnlockActionBundle(self, request).execute()

    def _execute_workstation_unlock_bundle(self, request: WorkstationUnlockRequest) -> None:
        """Generate workstation unlock event (4801 + 4624 type 7)."""
        user = request.user
        system = request.system
        time = request.time
        logon_id = request.logon_id

        session = self.state_manager.get_session(logon_id)
        lock_times = getattr(self, "_last_workstation_lock_time", {})
        lock_key = (system.hostname, user.username, logon_id)
        lock_time = lock_times.get(lock_key)
        if lock_time is None:
            locked = self._locked_user_interactive_windows_session(user, system, time)
            if locked is not None:
                lock_time, session = locked
                logon_id = session.logon_id
                lock_key = (system.hostname, user.username, logon_id)
        if (
            session is None
            or session.system != system.hostname
            or session.start_time > time
            or not _is_windows_workstation_session(session)
        ):
            return
        reauth_gap = self._workstation_unlock_reauth_gap(user, system, time, logon_id)
        reauth_not_before = session.start_time
        if lock_time is not None:
            min_reauth_time = lock_time + timedelta(seconds=min_unlock_gap_seconds())
            reauth_not_before = max(reauth_not_before, min_reauth_time)
            self._last_workstation_lock_time.pop(lock_key, None)
        timing_graph = TemporalConstraintGraph()
        timing_graph.add_node(
            "reauth",
            time - reauth_gap,
            not_before=reauth_not_before,
        )
        timing_graph.add_node("unlock", time)
        timing_graph.constrain_after("unlock", "reauth", min_gap=reauth_gap)
        resolved_times = timing_graph.resolve()
        reauth_time = resolved_times["reauth"]
        unlock_time = resolved_times["unlock"]

        session = self.state_manager.get_session(logon_id)
        if session is not None:
            session.last_activity_time = unlock_time
        # Unlock is a re-authentication: Windows records the Type 7 4624 before
        # the workstation-unlocked audit event for the same terminal session.
        self.generate_logon(
            user=user,
            system=system,
            time=reauth_time,
            logon_type=7,
            source_ip="-",
            logon_id=logon_id,
        )
        event = SecurityEvent(
            timestamp=unlock_time,
            event_type="workstation_unlocked",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                user_sid=self._get_sid(user.username),
                logon_id=logon_id,
                session_id=session.session_id,
            ),
        )
        self.dispatcher.dispatch(event)

    @staticmethod
    def _workstation_unlock_reauth_gap(
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
    ) -> timedelta:
        """Return source-native spacing from unlock re-auth to 4801 audit."""

        seed = _stable_seed(
            "workstation_unlock_reauth_gap:"
            f"{system.hostname}:{user.username}:{logon_id}:{time.isoformat()}"
        )
        return timedelta(milliseconds=80 + (seed % 571))

    def _resolve_windows_inbound_service_pid(
        self,
        system: System,
        dst_port: int,
        time: datetime,
    ) -> int:
        """Return a destination-local Windows service PID for inbound audit rows."""

        if _get_os_category(system.os) != "windows":
            return -1

        system_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for role in _WINDOWS_INBOUND_SERVICE_PID_CANDIDATES.get(dst_port, ()):
            pid = int(system_pids.get(role, -1) or -1)
            if pid > 0 and self._is_pid_active_at(system, pid, time):
                return pid
        return -1

    @staticmethod
    def _should_emit_windows_inbound_wfp(event: SecurityEvent, target_system: System) -> bool:
        """Return whether a canonical connection should create target-side 5156 evidence."""

        net = event.network
        if net is None or net.responding_pid <= 0:
            return False
        if net.dst_ip == net.src_ip or net.dst_ip != target_system.ip:
            return False
        if event.firewall is not None and event.firewall.action == "deny":
            return False
        proto = net.protocol.lower()
        if proto == "tcp":
            if net.conn_state in {"S0", "REJ", "S1", "SH", "SHR", "OTH"}:
                return False
            history = net.history or ""
            if not net.conn_state and not history:
                return True
            return any(marker in history for marker in ("h", "a", "d", "r", "f"))
        if proto in {"udp", "icmp"}:
            return net.conn_state not in {"S0", "REJ", "OTH"}
        return False

    def generate_wfp_connection(
        self,
        system: System,
        time: datetime,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        pid: int = 4,
        application: str | None = None,
    ) -> None:
        """Generate WFP connection permitted event (5156) on Windows host.

        Records the Windows Filtering Platform firewall allow decision.
        """
        from evidenceforge.events.contexts import NetworkContext, ProcessContext

        ip_proto = 6 if protocol == "tcp" else 17 if protocol == "udp" else 1
        process = None
        if pid > 0:
            running = self.state_manager.get_process(system.hostname, pid)
            if running is not None:
                process = ProcessContext(
                    pid=pid,
                    parent_pid=running.parent_pid,
                    image=running.image,
                    command_line=running.command_line,
                    username=running.username,
                    logon_id=running.logon_id,
                    start_time=running.start_time,
                    parent_start_time=self._lookup_parent_start_time(
                        system.hostname,
                        running.parent_pid,
                    ),
                )
        if process is None and application and pid <= 0:
            process = ProcessContext(
                pid=pid,
                parent_pid=0,
                image=application,
                command_line="",
                username="",
            )
        if process is None and pid > 0 and pid != 4:
            logger.debug(
                "Skipping WFP 5156 for unresolved process image: host=%s pid=%s",
                system.hostname,
                pid,
            )
            return
        if process is not None:
            time = self._clamp_after_visible_process_create(
                system,
                pid,
                time,
                "source.windows_wfp_connection",
            )
        event = SecurityEvent(
            timestamp=time,
            event_type="wfp_connection",
            src_host=self._build_host_context(system),
            network=NetworkContext(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                ip_proto=ip_proto,
                initiating_pid=pid,
            ),
            process=process,
        )
        self.dispatcher.dispatch(event)

    def generate_rdp_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_system: Optional["System"] = None,
        source_pid: int = -1,
        logon_id: str | None = None,
        source_process_time: datetime | None = None,
        source_process_factory: RdpSourceProcessFactory | None = None,
    ) -> str:
        """Generate RDP session: Zeek conn + 4624 type 10 + eCAR on target.

        Compound event ensuring network and host evidence are always paired.
        Returns Zeek UID.
        """
        bundle = RdpSessionActionBundle(
            executor=self,
            request=RdpSessionRequest(
                user=user,
                target_system=target_system,
                time=time,
                source_ip=source_ip,
                source_system=source_system,
                source_pid=source_pid,
                source_process_time=source_process_time,
                logon_id=logon_id or "",
            ),
            source_process_factory=source_process_factory,
        )
        return bundle.execute()

    def _resolve_direct_rdp_source_system(
        self,
        user: User,
        target_system: System,
        source_ip: str,
        rng: random.Random,
    ) -> System | None:
        """Return a modeled Windows source host for direct Type 10 compatibility calls."""

        source_system = self._ip_to_system.get(source_ip)
        if (
            source_system is not None
            and source_system.ip != target_system.ip
            and _get_os_category(source_system.os) == "windows"
        ):
            return source_system

        candidates = sorted(
            {
                system.hostname: system
                for system in self._ip_to_system.values()
                if system.ip != target_system.ip and _get_os_category(system.os) == "windows"
            }.values(),
            key=lambda system: system.hostname,
        )
        workstations = [
            system
            for system in candidates
            if (system.type or "workstation").lower() == "workstation"
        ]
        preferred = [
            system for system in workstations or candidates if system.assigned_user == user.username
        ]
        return rng.choice(preferred or workstations or candidates) if candidates else None

    def _direct_rdp_source_process_factory(
        self,
        rng: random.Random,
    ) -> RdpSourceProcessFactory:
        """Return a source-process factory for direct RDP compatibility generation."""

        def _factory(
            *,
            user: User,
            source_system: System,
            target_system: System,
            time: datetime,
        ) -> int:
            source_session = self._active_user_interactive_windows_session(
                user,
                source_system,
                time,
            )
            if source_session is None:
                logon_time = time - timedelta(seconds=rng.uniform(30.0, 180.0))
                logon_id = self.generate_logon(
                    user,
                    source_system,
                    logon_time,
                    logon_type=2,
                )
                source_session = self.state_manager.get_session(logon_id)
            if source_session is None:
                return -1

            parent_pid = source_session.explorer_pid or source_session.process_tree_root
            if parent_pid is None:
                sys_pids = getattr(self, "_system_pids", {}).get(source_system.hostname, {})
                parent_pid = sys_pids.get(
                    "explorer",
                    sys_pids.get("winlogon", sys_pids.get("services", 4)),
                )

            self.state_manager.set_current_time(time)
            pid = self.generate_process(
                user=user,
                system=source_system,
                time=time,
                logon_id=source_session.logon_id,
                process_name=r"C:\Windows\System32\mstsc.exe",
                command_line=f"mstsc.exe /v:{target_system.hostname}",
                parent_pid=parent_pid,
            )
            self._record_user_process(
                source_system,
                user,
                pid,
                r"C:\Windows\System32\mstsc.exe",
            )
            return pid

        return _factory

    def _coerce_windows_rdp_user_from_existing_session(
        self,
        user: User,
        target_system: System,
        source_ip: str,
    ) -> User:
        """Use a recent successful Windows credential instead of a Unix local actor."""
        if _get_os_category(target_system.os) != "windows":
            return user
        if user.username.lower() not in _LINUX_LOCAL_ACCOUNTS:
            return user
        sessions = [
            session
            for session in self.state_manager.get_sessions_on_system(target_system.hostname)
            if session.source_ip == source_ip
            and session.username.lower() not in _LINUX_LOCAL_ACCOUNTS
            and session.username not in _SYSTEM_ACCOUNT_LOGON_IDS
        ]
        if not sessions:
            return user
        selected = max(sessions, key=lambda session: session.start_time)
        known_users = getattr(self, "_users_by_username", {})
        if selected.username in known_users:
            return known_users[selected.username]
        ad_domain = self._valid_fallback_email_domain()
        return User(
            username=selected.username,
            full_name=selected.username,
            email=f"{selected.username}@{ad_domain}",
        )

    def _valid_fallback_email_domain(self) -> str:
        """Return a safe domain for synthetic fallback users."""
        ad_domain = str(getattr(self, "_ad_domain", "corp.local")).strip().lower()
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
        labels = ad_domain.split(".")
        if (
            len(labels) >= 2
            and all(labels)
            and all(
                set(label) <= allowed and not label.startswith("-") and not label.endswith("-")
                for label in labels
            )
            and labels[-1].isalpha()
            and len(labels[-1]) >= 2
        ):
            return ad_domain
        return "corp.local"

    def generate_service_logon(
        self,
        system: System,
        time: datetime,
        service_account: str = "SYSTEM",
    ) -> str:
        """Generate a service logon (type 5) for system accounts.

        Unlike generate_logon(), does not require a User object.
        Emits 4624 (type 5) + 4672 (special privileges) via normal pipeline.
        Each call gets a unique LogonID (real Windows allocates new sessions for service restarts).
        """
        request = ServiceLogonRequest(
            system=system,
            time=time,
            service_account=service_account,
        )
        return ServiceLogonActionBundle(self, request).execute()

    def _execute_service_logon_bundle(self, request: ServiceLogonRequest) -> str:
        """Generate a service logon (type 5) for system accounts."""
        system = request.system
        time = request.time
        service_account = request.service_account

        sid = _SYSTEM_ACCOUNT_SIDS.get(service_account, self._get_sid(service_account))
        logon_id = self.state_manager.create_session(
            username=service_account,
            system=system.hostname,
            logon_type=5,
            source_ip="-",
            start_time=time,
            session_kind="service",
        )
        host = self._build_host_context(system)
        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject = self._account_subject_fields("SYSTEM", system, logon_id="0x3e7")

        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            dst_host=host,
            auth=AuthContext(
                username=service_account,
                user_sid=sid,
                logon_id=logon_id,
                logon_type=5,
                auth_package="Negotiate",
                source_ip="-",
                elevated=True,
                logon_process="Advapi",
                lm_package="-",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid=subject["sid"],
                subject_username=subject["username"],
                subject_domain=subject["domain"],
                subject_logon_id=subject["logon_id"],
                reporting_pid=reporting_pid,
            ),
        )
        self.dispatcher.dispatch(event)
        return logon_id

    def generate_kerberos_preauth_failed(
        self,
        username: str,
        source_ip: str,
        dc_hostname: str,
        time: datetime,
        status: str = "0x18",
        source_port: int | None = None,
        emit_connection: bool = False,
    ) -> None:
        """Generate Kerberos pre-authentication failed event (4771) on DC."""
        request = KerberosPreauthFailureRequest(
            username=username,
            source_ip=source_ip,
            dc_hostname=dc_hostname,
            time=time,
            status=status,
            source_port=source_port,
            emit_connection=emit_connection,
        )
        KerberosPreauthFailureActionBundle(self, request).execute()

    def _execute_kerberos_preauth_failure_bundle(
        self,
        request: KerberosPreauthFailureRequest,
    ) -> None:
        """Generate Kerberos pre-authentication failed event (4771) on DC."""
        username = request.username
        source_ip = request.source_ip
        dc_hostname = request.dc_hostname
        time = request.time
        status = request.status
        source_port = request.source_port
        emit_connection = request.emit_connection

        rng = _get_rng()
        from evidenceforge.generation.activity.kerberos_realism import pick_tgt_failure_fields

        failure_fields = pick_tgt_failure_fields(rng)
        dc_host = self._build_dc_host_context(dc_hostname)
        reporting_pid = self._get_system_pid(dc_hostname, "lsass", 0x2E0)
        has_source_ip = source_ip not in {"", "-"}
        normalized_source_ip = (
            f"::ffff:{source_ip}" if has_source_ip and ":" not in source_ip else source_ip
        )
        source_port = (
            self._reserve_kerberos_source_port(source_ip, dc_hostname, time, source_port)
            if has_source_ip
            else 0
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="kerberos_preauth_failed",
            dst_host=dc_host,
            kerberos=KerberosContext(
                target_username=username,
                target_domain=getattr(self, "_ad_domain", "corp.local").upper(),
                target_sid=self._get_sid(username),
                service_name="krbtgt",
                ticket_options=failure_fields["ticket_options"],
                ticket_status=status,
                pre_auth_type=failure_fields["pre_auth_type"],
                source_ip=normalized_source_ip or "-",
                source_port=source_port,
                reporting_pid=reporting_pid,
            ),
        )
        self._remember_kerberos_audit(
            source_ip,
            dc_hostname,
            time,
            source_port=source_port,
        )
        self.dispatcher.dispatch(event)

        if not emit_connection or not has_source_ip:
            return
        dc_system = self._dc_system_for_hostname(dc_hostname)
        dc_ip = str(getattr(dc_system, "ip", "") or "")
        if not dc_ip:
            return
        source_system = getattr(self, "_ip_to_system", {}).get(source_ip)
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=dc_ip,
            time=time,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=rng.uniform(0.001, 0.04),
            orig_bytes=rng.randint(180, 900),
            resp_bytes=rng.randint(80, 500),
            src_port=source_port,
            source_system=source_system,
            conn_state=rng.choices(["SF", "RSTR"], weights=[82, 18], k=1)[0],
            emit_dns=False,
        )

    def _get_user_logon_id(
        self,
        username: str,
        hostname: str,
        at_time: datetime | None = None,
    ) -> str:
        """Look up the user's active session LogonID on the given host.

        Returns the session LogonID if found. Well-known service identities use
        their canonical logon IDs. Human/domain accounts without an active
        session fall back to 0x0 rather than SYSTEM's 0x3e7.
        """
        canonical_logon_ids = {
            "SYSTEM": "0x3e7",
            "LOCAL SERVICE": "0x3e5",
            "NETWORK SERVICE": "0x3e4",
        }
        if username in canonical_logon_ids:
            return canonical_logon_ids[username]

        sessions = self.state_manager.get_sessions_for_user(username)
        if sessions:
            host_sessions = [s for s in sessions if s.system == hostname]
            if at_time is not None:
                host_sessions = [s for s in host_sessions if _session_started_by(s, at_time)]
            active = max(host_sessions, key=lambda s: s.start_time) if host_sessions else None
            if active:
                return active.logon_id
        return "0x0"

    def _get_subject_logon_id(
        self,
        username: str,
        hostname: str,
        at_time: datetime | None = None,
    ) -> str:
        """Look up the visible subject session, including service-account sessions."""
        sessions = self.state_manager.get_sessions_for_user(username)
        if sessions:
            host_sessions = [s for s in sessions if s.system == hostname]
            if at_time is not None:
                host_sessions = [s for s in host_sessions if _session_started_by(s, at_time)]
            active = max(host_sessions, key=lambda s: s.start_time) if host_sessions else None
            if active:
                return active.logon_id
        return self._get_user_logon_id(username, hostname, at_time)

    def _ensure_account_management_subject_logon(
        self,
        actor: User,
        system: System,
        time: datetime,
    ) -> str:
        """Return an active subject LogonID for account-management audit events."""
        existing = self._get_user_logon_id(actor.username, system.hostname, time)
        if existing != "0x0":
            return existing

        source_ip = system.ip
        world_model = getattr(self, "_world_model", None)
        primary_system_name = getattr(actor, "primary_system", None)
        if world_model is not None and primary_system_name:
            primary_system = world_model.systems_by_hostname.get(primary_system_name)
            if primary_system is not None:
                source_ip = primary_system.ip

        logon_time = time - timedelta(milliseconds=500)
        return self.generate_logon(
            actor,
            system,
            logon_time,
            logon_type=3 if source_ip != system.ip else 2,
            source_ip=source_ip,
        )

    def generate_log_cleared(
        self,
        user: User,
        system: System,
        time: datetime,
        from_storyline: bool = False,
        subject_logon_id: str | None = None,
    ) -> None:
        """Generate security log cleared event (1102) on target system."""
        request = LogClearedRequest(
            user=user,
            system=system,
            time=time,
            from_storyline=from_storyline,
            subject_logon_id=subject_logon_id,
        )
        LogClearedActionBundle(self, request).execute()

    def _execute_log_cleared_bundle(self, request: LogClearedRequest) -> None:
        """Generate security log cleared event (1102) on target system."""
        user = request.user
        system = request.system
        time = request.time
        from_storyline = request.from_storyline
        subject_logon_id = request.subject_logon_id

        if user.username in _SYSTEM_ACCOUNT_LOGON_IDS:
            subject_logon_id = _SYSTEM_ACCOUNT_LOGON_IDS[user.username]
        subject_logon_id = subject_logon_id or self._get_subject_logon_id(
            user.username, system.hostname, time
        )
        subject = self._account_subject_fields(user.username, system, logon_id=subject_logon_id)
        event = SecurityEvent(
            timestamp=time,
            event_type="log_cleared",
            src_host=self._build_host_context(system),
            auth=AuthContext(
                username=user.username,
                subject_sid=subject["sid"],
                subject_username=subject["username"],
                subject_domain=subject["domain"],
                subject_logon_id=subject["logon_id"],
            ),
            storyline_origin=from_storyline,
        )
        self.dispatcher.dispatch(event)

    def generate_service_installed(
        self,
        user: User,
        system: System,
        time: datetime,
        service_name: str,
        service_file_name: str,
        service_type: str = "0x10",
        service_start_type: str = "3",
        service_account: str = "LocalSystem",
    ) -> None:
        """Generate service installed event (4697) on target system."""
        bundle = WindowsServiceInstallActionBundle(
            self,
            WindowsServiceInstallRequest(
                user=user,
                system=system,
                time=time,
                service_name=service_name,
                service_file_name=service_file_name,
                service_type=service_type,
                service_start_type=service_start_type,
                service_account=service_account,
            ),
        )
        bundle.execute()

    def _emit_remote_service_control_network_evidence(
        self,
        user: User,
        target_system: System,
        time: datetime,
    ) -> None:
        """Emit SMB/RPC flows that usually precede remote Windows service creation."""
        world_model = getattr(self, "_world_model", None)
        source_system = None
        primary_system_name = getattr(user, "primary_system", None)
        if world_model is not None and primary_system_name:
            source_system = world_model.systems_by_hostname.get(primary_system_name)
        if source_system is None:
            sessions = [
                session
                for session in self.state_manager.get_sessions_for_user(user.username)
                if session.system != target_system.hostname
            ]
            if sessions and world_model is not None:
                newest = max(sessions, key=lambda session: session.start_time)
                source_system = world_model.systems_by_hostname.get(newest.system)
        if source_system is None or source_system.ip == target_system.ip:
            return
        if _get_os_category(target_system.os) != "windows":
            return
        rng = _get_rng()
        flow_specs = (
            (445, "smb", time - timedelta(milliseconds=rng.randint(1100, 1800))),
            (135, "dce_rpc", time - timedelta(milliseconds=rng.randint(350, 900))),
        )
        source_os = _get_os_category(source_system.os)
        max_ephemeral_port = 60999 if source_os == "linux" else 65535
        base_src_port = min(
            _ephemeral_port(rng, source_os),
            max_ephemeral_port - len(flow_specs) + 1,
        )
        for idx, (dst_port, service, flow_time) in enumerate(flow_specs):
            self.generate_connection(
                src_ip=source_system.ip,
                dst_ip=target_system.ip,
                time=flow_time,
                dst_port=dst_port,
                proto="tcp",
                service=service,
                duration=rng.uniform(0.08, 0.9),
                orig_bytes=rng.randint(45_000, 160_000)
                if dst_port == 445
                else rng.randint(450, 1800),
                resp_bytes=rng.randint(1500, 7000) if dst_port == 445 else rng.randint(350, 2200),
                src_port=base_src_port + idx,
                emit_dns=False,
                source_system=source_system,
                conn_state="SF",
            )

    def generate_scheduled_task(
        self,
        user: User,
        system: System,
        time: datetime,
        task_name: str,
        action: str = "created",
        task_content: str = "",
        source_command_line: str = "",
    ) -> None:
        """Generate scheduled task event (4698/4699/4700/4701) on target system."""
        request = ScheduledTaskRequest(
            user=user,
            system=system,
            time=time,
            task_name=task_name,
            action=action,
            task_content=task_content,
            source_command_line=source_command_line,
        )
        ScheduledTaskActionBundle(self, request).execute()

    def _execute_scheduled_task_bundle(self, request: ScheduledTaskRequest) -> None:
        """Generate scheduled task event (4698/4699/4700/4701) on target system."""
        from evidenceforge.events.contexts import ScheduledTaskContext

        user = request.user
        system = request.system
        time = request.time
        task_name = request.task_name
        action = request.action
        task_content = request.task_content
        source_command_line = request.source_command_line

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        task_content = self._normalize_scheduled_task_content(
            task_name=task_name,
            task_content=task_content,
            actor=user,
            host=host,
            time=time,
            source_command_line=source_command_line,
        )
        event = SecurityEvent(
            timestamp=time,
            event_type=f"scheduled_task_{action}",
            src_host=host,
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname, time),
                reporting_pid=reporting_pid,
            ),
            scheduled_task=ScheduledTaskContext(
                task_name=task_name,
                task_content=task_content,
            ),
        )
        self.dispatcher.dispatch(event)

    def _normalize_scheduled_task_content(
        self,
        *,
        task_name: str,
        task_content: str,
        actor: User,
        host: HostContext,
        time: datetime,
        source_command_line: str = "",
    ) -> str:
        """Return a full Task Scheduler XML definition for Security 4698 events."""
        if self._is_complete_task_xml(task_content):
            return task_content

        command, arguments = self._extract_scheduled_task_command(
            task_content,
            task_name,
            source_command_line=source_command_line,
        )
        return self._build_scheduled_task_xml(
            task_name=task_name,
            command=command,
            arguments=arguments,
            actor=actor,
            host=host,
            time=time,
            schedule=self._extract_schtasks_schedule(source_command_line),
            principal_name=self._extract_schtasks_option(source_command_line, "ru"),
        )

    @staticmethod
    def _is_complete_task_xml(task_content: str) -> bool:
        """Detect user-supplied full Task Scheduler XML that should be preserved."""
        stripped = task_content.lstrip()
        if not stripped.startswith(("<?xml", "<Task")):
            return False
        return all(
            marker in task_content
            for marker in (
                "<RegistrationInfo>",
                "<Principals>",
                "<Settings>",
                "<Actions",
            )
        )

    @classmethod
    def _extract_scheduled_task_command(
        cls,
        task_content: str,
        task_name: str,
        *,
        source_command_line: str = "",
    ) -> tuple[str, str]:
        """Extract a command/arguments pair from command text or minimal task XML."""
        import re
        from html import unescape

        command = ""
        arguments = ""
        source_action = cls._extract_schtasks_option(source_command_line, "tr")
        command_match = re.search(
            r"<Command>(?P<command>.*?)</Command>", task_content, flags=re.IGNORECASE | re.DOTALL
        )
        args_match = re.search(
            r"<Arguments>(?P<args>.*?)</Arguments>", task_content, flags=re.IGNORECASE | re.DOTALL
        )
        if source_action:
            command = source_action
        elif command_match:
            command = unescape(command_match.group("command")).strip()
        else:
            command = task_content.strip()
        if args_match:
            arguments = unescape(args_match.group("args")).strip()

        if not command:
            task_label = task_name.rsplit("\\", 1)[-1] or task_name
            return r"C:\Windows\System32\cmd.exe", f'/c "{task_label}"'

        split_command, split_args = cls._split_scheduled_task_command(command)
        if split_args and not arguments:
            arguments = split_args
        return split_command, arguments

    @staticmethod
    def _split_scheduled_task_command(command: str) -> tuple[str, str]:
        """Split a Task Scheduler command line into Command and Arguments fields."""
        import re

        stripped = command.strip()
        quoted = re.match(r'^"(?P<exe>[^"]+?\.exe)"\s*(?P<args>.*)$', stripped, re.IGNORECASE)
        if quoted:
            return quoted.group("exe"), quoted.group("args").strip()

        windows_path = re.match(
            r"^(?P<exe>[A-Za-z]:\\.*?\.exe)\s*(?P<args>.*)$", stripped, re.IGNORECASE
        )
        if windows_path:
            return windows_path.group("exe"), windows_path.group("args").strip()

        executable = re.match(r"^(?P<exe>\S+?\.exe)\s*(?P<args>.*)$", stripped, re.IGNORECASE)
        if executable:
            return executable.group("exe"), executable.group("args").strip()

        return stripped, ""

    @staticmethod
    def _extract_schtasks_option(command_line: str, option: str) -> str:
        """Extract a quoted or bare schtasks.exe option value."""
        import re

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

    @classmethod
    def _extract_schtasks_schedule(cls, command_line: str) -> dict[str, str]:
        """Extract the subset of schtasks schedule options represented in task XML."""
        schedule = cls._extract_schtasks_option(command_line, "sc").upper()
        if not schedule:
            return {}
        details = {"sc": schedule}
        for option in ("mo", "st", "sd"):
            value = cls._extract_schtasks_option(command_line, option)
            if value:
                details[option] = value
        return details

    @staticmethod
    def _schedule_modifier(schedule: dict[str, str], default: int = 1) -> int:
        """Return a safe positive `/MO` schedule modifier."""
        try:
            modifier = int(schedule.get("mo", ""))
        except ValueError:
            return default
        return max(1, min(modifier, 365))

    @classmethod
    def _scheduled_task_trigger_xml(cls, start_boundary: str, schedule: dict[str, str]) -> str:
        """Render the trigger XML implied by common schtasks schedule options."""
        schedule_type = schedule.get("sc", "").upper()
        modifier = cls._schedule_modifier(schedule)
        if schedule_type == "HOURLY":
            interval = f"PT{modifier}H"
            return (
                "  <Triggers>\n"
                "    <TimeTrigger>\n"
                f"      <StartBoundary>{start_boundary}</StartBoundary>\n"
                "      <Enabled>true</Enabled>\n"
                "      <Repetition>\n"
                f"        <Interval>{interval}</Interval>\n"
                "        <StopAtDurationEnd>false</StopAtDurationEnd>\n"
                "      </Repetition>\n"
                "    </TimeTrigger>\n"
                "  </Triggers>\n"
            )
        if schedule_type == "MINUTE":
            interval = f"PT{modifier}M"
            return (
                "  <Triggers>\n"
                "    <TimeTrigger>\n"
                f"      <StartBoundary>{start_boundary}</StartBoundary>\n"
                "      <Enabled>true</Enabled>\n"
                "      <Repetition>\n"
                f"        <Interval>{interval}</Interval>\n"
                "        <StopAtDurationEnd>false</StopAtDurationEnd>\n"
                "      </Repetition>\n"
                "    </TimeTrigger>\n"
                "  </Triggers>\n"
            )
        if schedule_type == "DAILY":
            return (
                "  <Triggers>\n"
                "    <CalendarTrigger>\n"
                f"      <StartBoundary>{start_boundary}</StartBoundary>\n"
                "      <Enabled>true</Enabled>\n"
                "      <ScheduleByDay>\n"
                f"        <DaysInterval>{modifier}</DaysInterval>\n"
                "      </ScheduleByDay>\n"
                "    </CalendarTrigger>\n"
                "  </Triggers>\n"
            )
        return (
            "  <Triggers>\n"
            "    <TimeTrigger>\n"
            f"      <StartBoundary>{start_boundary}</StartBoundary>\n"
            "      <Enabled>true</Enabled>\n"
            "    </TimeTrigger>\n"
            "  </Triggers>\n"
        )

    @staticmethod
    def _build_scheduled_task_xml(
        *,
        task_name: str,
        command: str,
        arguments: str,
        actor: User,
        host: HostContext,
        time: datetime,
        schedule: dict[str, str] | None = None,
        principal_name: str = "",
    ) -> str:
        """Build source-native Task Scheduler XML for Windows Security 4698."""
        from xml.sax.saxutils import escape as xml_escape

        task_path = task_name if task_name.startswith("\\") else f"\\{task_name}"
        author = ActivityGenerator._scheduled_task_principal(principal_name or actor.username, host)
        start_boundary = (
            time.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        command_xml = xml_escape(command)
        arguments_xml = xml_escape(arguments)
        arguments_line = f"\n      <Arguments>{arguments_xml}</Arguments>" if arguments else ""
        logon_type = "ServiceAccount" if author.upper().startswith("NT AUTHORITY\\") else "Password"
        run_level = (
            "HighestAvailable" if author.upper() == "NT AUTHORITY\\SYSTEM" else "LeastPrivilege"
        )
        trigger_xml = ActivityGenerator._scheduled_task_trigger_xml(start_boundary, schedule or {})
        return (
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            "  <RegistrationInfo>\n"
            f"    <Date>{start_boundary}</Date>\n"
            f"    <Author>{xml_escape(author)}</Author>\n"
            f"    <URI>{xml_escape(task_path)}</URI>\n"
            "  </RegistrationInfo>\n"
            f"{trigger_xml}"
            "  <Principals>\n"
            '    <Principal id="Author">\n'
            f"      <UserId>{xml_escape(author)}</UserId>\n"
            f"      <LogonType>{logon_type}</LogonType>\n"
            f"      <RunLevel>{run_level}</RunLevel>\n"
            "    </Principal>\n"
            "  </Principals>\n"
            "  <Settings>\n"
            "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
            "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
            "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
            "    <AllowHardTerminate>true</AllowHardTerminate>\n"
            "    <StartWhenAvailable>false</StartWhenAvailable>\n"
            "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
            "    <Enabled>true</Enabled>\n"
            "    <Hidden>false</Hidden>\n"
            "    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\n"
            "    <Priority>7</Priority>\n"
            "  </Settings>\n"
            '  <Actions Context="Author">\n'
            "    <Exec>\n"
            f"      <Command>{command_xml}</Command>{arguments_line}\n"
            "    </Exec>\n"
            "  </Actions>\n"
            "</Task>"
        )

    @staticmethod
    def _scheduled_task_principal(username: str, host: HostContext) -> str:
        """Return a source-native Task Scheduler principal for local and domain users."""
        normalized = username.strip()
        upper = normalized.upper()
        if "\\" in normalized:
            return normalized
        if upper in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}:
            return f"NT AUTHORITY\\{upper}"
        if normalized.endswith("$"):
            return normalized
        if host.netbios_domain:
            return f"{host.netbios_domain}\\{normalized}"
        return normalized

    def generate_group_membership_change(
        self,
        actor: User,
        system: System,
        time: datetime,
        action: str,
        scope: str,
        group_name: str,
        group_sid: str,
        member_username: str,
        member_sid: str,
    ) -> None:
        """Generate group membership change event on DC."""
        request = GroupMembershipChangeRequest(
            actor=actor,
            system=system,
            time=time,
            action=action,
            scope=scope,
            group_name=group_name,
            group_sid=group_sid,
            member_username=member_username,
            member_sid=member_sid,
        )
        GroupMembershipChangeActionBundle(self, request).execute()

    def _execute_group_membership_change_bundle(
        self,
        request: GroupMembershipChangeRequest,
    ) -> None:
        """Generate group membership change event on DC.

        Args:
            action: "add" or "remove"
            scope: "global", "local", or "universal"
        """
        from evidenceforge.events.contexts import GroupMembershipContext

        actor = request.actor
        system = request.system
        time = request.time
        action = request.action
        scope = request.scope
        group_name = request.group_name
        group_sid = request.group_sid
        member_username = request.member_username
        member_sid = request.member_sid

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject_logon_id = self._ensure_account_management_subject_logon(actor, system, time)
        host = self._build_host_context(system)
        event_type = f"group_member_{'added' if action == 'add' else 'removed'}_{scope}"
        event = SecurityEvent(
            timestamp=time,
            event_type=event_type,
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=subject_logon_id,
                reporting_pid=reporting_pid,
            ),
            group_membership=GroupMembershipContext(
                member_name=self._distinguished_name_for_account(
                    member_username,
                    host.fqdn,
                    getattr(system, "domain", ""),
                    host.netbios_domain,
                ),
                member_sid=member_sid,
                group_name=group_name,
                group_domain=host.netbios_domain,
                group_sid=group_sid,
            ),
        )
        self.dispatcher.dispatch(event)

    @staticmethod
    def _distinguished_name_for_account(
        username: str,
        host_fqdn: str,
        domain: str = "",
        netbios_domain: str = "",
    ) -> str:
        """Build a realistic Active Directory DN for group-member audit fields."""
        dns_domain = host_fqdn.split(".", 1)[1] if "." in host_fqdn else domain
        if not dns_domain and netbios_domain:
            dns_domain = f"{netbios_domain.lower()}.local"
        domain_parts = ",".join(f"DC={part}" for part in dns_domain.split(".") if part)
        escaped_username = username.replace("\\", "\\5c").replace(",", "\\,")
        return f"CN={escaped_username},CN=Users,{domain_parts}" if domain_parts else username

    def generate_account_created(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate user account created event (4720) on DC."""
        request = AccountCreatedRequest(
            actor=actor,
            system=system,
            time=time,
            target_username=target_username,
            target_sid=target_sid,
        )
        AccountCreatedActionBundle(self, request).execute()

    def _execute_account_created_bundle(self, request: AccountCreatedRequest) -> None:
        """Generate user account created event (4720) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        actor = request.actor
        system = request.system
        time = request.time
        target_username = request.target_username
        target_sid = request.target_sid

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject_logon_id = self._ensure_account_management_subject_logon(actor, system, time)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="account_created",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=subject_logon_id,
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
                sam_account_name=target_username,
                password_last_set="%%1794",
                new_uac_value="0x15",
                user_account_control="\n\t\t\t%%2080\n\t\t\t%%2082\n\t\t\t%%2084",
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_account_deleted(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
        from_storyline: bool = False,
    ) -> None:
        """Generate user account deleted event (4726) on DC."""
        request = AccountDeletedRequest(
            actor=actor,
            system=system,
            time=time,
            target_username=target_username,
            target_sid=target_sid,
            from_storyline=from_storyline,
        )
        AccountDeletedActionBundle(self, request).execute()

    def _execute_account_deleted_bundle(self, request: AccountDeletedRequest) -> None:
        """Generate user account deleted event (4726) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        actor = request.actor
        system = request.system
        time = request.time
        target_username = request.target_username
        target_sid = request.target_sid
        from_storyline = request.from_storyline

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject_logon_id = self._ensure_account_management_subject_logon(actor, system, time)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="account_deleted",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=subject_logon_id,
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
            ),
            storyline_origin=from_storyline,
        )
        self.dispatcher.dispatch(event)

    def generate_password_reset(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
    ) -> None:
        """Generate password reset event (4724) on DC."""
        request = PasswordResetRequest(
            actor=actor,
            system=system,
            time=time,
            target_username=target_username,
            target_sid=target_sid,
        )
        PasswordResetActionBundle(self, request).execute()

    def _execute_password_reset_bundle(self, request: PasswordResetRequest) -> None:
        """Generate password reset event (4724) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        actor = request.actor
        system = request.system
        time = request.time
        target_username = request.target_username
        target_sid = request.target_sid

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject_logon_id = self._ensure_account_management_subject_logon(actor, system, time)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="password_reset",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=subject_logon_id,
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_password_change(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> None:
        """Generate password change event (4723) on DC."""
        request = PasswordChangeRequest(user=user, system=system, time=time)
        PasswordChangeActionBundle(self, request).execute()

    def _execute_password_change_bundle(self, request: PasswordChangeRequest) -> None:
        """Generate password change event (4723) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        user = request.user
        system = request.system
        time = request.time

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        host = self._build_host_context(system)
        event = SecurityEvent(
            timestamp=time,
            event_type="password_change",
            dst_host=host,
            auth=AuthContext(
                username=user.username,
                subject_sid=self._get_sid(user.username),
                subject_username=user.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._get_user_logon_id(user.username, system.hostname, time),
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=user.username,
                target_domain=host.netbios_domain,
                target_sid=self._get_sid(user.username),
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_create_remote_thread(
        self,
        user: User,
        system: System,
        time: datetime,
        source_pid: int,
        source_image: str,
        target_pid: int,
        target_image: str,
    ) -> bool:
        """Generate Sysmon Event 8 (CreateRemoteThread) for process injection."""
        request = CreateRemoteThreadRequest(
            user=user,
            system=system,
            time=time,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=target_image,
        )
        return CreateRemoteThreadActionBundle(self, request).execute()

    def _execute_create_remote_thread_bundle(
        self,
        request: CreateRemoteThreadRequest,
    ) -> bool:
        """Generate Sysmon Event 8 (CreateRemoteThread) for process injection.

        Returns:
            True when evidence was emitted, False when lifecycle validation skipped it.
        """
        user = request.user
        system = request.system
        time = request.time
        source_pid = request.source_pid
        source_image = request.source_image
        target_pid = request.target_pid
        target_image = request.target_image

        # Entity lifecycle: validate target PID exists
        if not self.state_manager.validate_target_pid(system.hostname, target_pid):
            logger.debug(
                "Skipping remote thread for non-running target process: %s source_pid=%s target_pid=%s",
                system.hostname,
                source_pid,
                target_pid,
            )
            return False

        from evidenceforge.events.contexts import ProcessContext

        time = self._clamp_time_after_process_start(system, source_pid, time)
        rng = random.Random(
            _stable_seed(
                "remote_thread:"
                f"{system.hostname}:{source_pid}:{target_pid}:{time.isoformat()}:{target_image}"
            )
        )
        from evidenceforge.generation.activity.create_remote_thread_patterns import (
            pick_remote_thread_start,
        )

        start_module, start_function = pick_remote_thread_start(source_image, target_image, rng)
        source_proc = self.state_manager.get_process(system.hostname, source_pid)
        if source_proc is None:
            logger.debug(
                "Skipping remote thread for non-running source process: %s pid=%s target=%s",
                system.hostname,
                source_pid,
                target_image,
            )
            return False
        target_proc = self.state_manager.get_process(system.hostname, target_pid)
        source_image = normalize_defender_platform_path(
            source_proc.image or source_image, system.hostname
        )
        if target_proc is not None:
            target_image = normalize_defender_platform_path(
                target_proc.image or target_image, system.hostname
            )
        else:
            target_image = normalize_defender_platform_path(target_image, system.hostname)
        module_key = (start_module or target_image).rsplit("\\", 1)[-1].lower()
        module_base = (
            0x00007FF600000000 + (_stable_seed(f"module_base:{module_key}") % 0x700000) * 0x1000
        )
        start_address = module_base + rng.randrange(0x1000, 0x1F000, 0x10)
        self.state_manager.update_process_activity_time(system.hostname, source_pid, time)
        source_obj_id = self.state_manager.get_process_object_id(system.hostname, source_pid)
        target_obj_id = self.state_manager.get_process_object_id(system.hostname, target_pid)
        thread_obj_id = stable_uuid(
            "ecar-remote-thread",
            system.hostname,
            source_pid,
            target_pid,
            time.isoformat(),
            start_address,
        )
        stack_base = 0x000000C0000000 + (rng.randint(0, 0x7FFF) << 12)
        user_stack_base = stack_base
        event = SecurityEvent(
            timestamp=time,
            event_type="create_remote_thread",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=source_pid,
                parent_pid=source_proc.parent_pid if source_proc is not None else 0,
                image=source_image,
                command_line=source_proc.command_line if source_proc is not None else "",
                username=source_proc.username if source_proc is not None else user.username,
                logon_id=source_proc.logon_id if source_proc is not None else "",
                start_time=source_proc.start_time if source_proc is not None else None,
            ),
            auth=AuthContext(
                username=source_proc.username if source_proc is not None else user.username,
                target_server=target_image,
                source_port=target_pid,  # Pack target PID into source_port for emitter
            ),
            remote_thread=RemoteThreadContext(
                target_pid=target_pid,
                target_image=target_image,
                new_thread_id=windows_id_randint(rng, 100, 9999),
                start_address=start_address,
                start_module=start_module,
                start_function=start_function,
                source_thread_id=windows_id_randint(rng, 1000, 9999),
                target_thread_id=windows_id_randint(rng, 1000, 9999),
                target_process_object_id=target_obj_id,
                thread_object_id=thread_obj_id,
                stack_base=stack_base,
                stack_limit=stack_base - 0x6000,
                user_stack_base=user_stack_base,
                user_stack_limit=user_stack_base - 0x100000,
            ),
            edr=EdrContext(object_id=thread_obj_id, actor_id=source_obj_id),
        )
        self.dispatcher.dispatch(event)
        return True

    def generate_process_access(
        self,
        user: User,
        system: System,
        time: datetime,
        source_pid: int,
        source_image: str,
        target_pid: int,
        target_image: str = r"C:\Windows\System32\lsass.exe",
        granted_access: str = "0x1010",
    ) -> bool:
        """Generate Sysmon Event 10 (ProcessAccess) for credential dumping detection."""
        request = ProcessAccessRequest(
            user=user,
            system=system,
            time=time,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=target_image,
            granted_access=granted_access,
        )
        return ProcessAccessActionBundle(self, request).execute()

    def _execute_process_access_bundle(self, request: ProcessAccessRequest) -> bool:
        """Generate Sysmon Event 10 (ProcessAccess) for credential dumping detection.

        Emits when a process accesses another process's memory (e.g., mimikatz
        reading lsass.exe for credential extraction).

        Args:
            user: User running the source process
            system: System where the access occurs
            time: Event timestamp
            source_pid: PID of the process doing the access
            source_image: Full path of the source process image
            target_pid: PID of the target process (typically lsass.exe)
            target_image: Full path of the target process image
            granted_access: Access mask (0x1010=VM_READ, 0x1FFFFF=ALL_ACCESS)

        Returns:
            True when evidence was emitted, False when lifecycle validation skipped it.
        """
        user = request.user
        system = request.system
        time = request.time
        source_pid = request.source_pid
        source_image = request.source_image
        target_pid = request.target_pid
        target_image = request.target_image
        granted_access = request.granted_access

        # Entity lifecycle: validate target PID exists
        if not self.state_manager.validate_target_pid(system.hostname, target_pid):
            logger.debug(
                "Skipping process access for non-running target process: %s source_pid=%s target_pid=%s",
                system.hostname,
                source_pid,
                target_pid,
            )
            return False

        time = self._clamp_time_after_process_start(system, source_pid, time)
        source_proc = self.state_manager.get_process(system.hostname, source_pid)
        if source_proc is None:
            logger.debug(
                "Skipping process access for non-running source process: %s pid=%s target=%s",
                system.hostname,
                source_pid,
                target_image,
            )
            return False
        target_proc = self.state_manager.get_process(system.hostname, target_pid)
        source_image = normalize_defender_platform_path(
            source_proc.image or source_image, system.hostname
        )
        if target_proc is not None:
            target_image = normalize_defender_platform_path(
                target_proc.image or target_image, system.hostname
            )
        else:
            target_image = normalize_defender_platform_path(target_image, system.hostname)
        self.state_manager.update_process_activity_time(system.hostname, source_pid, time)
        source_obj_id = self.state_manager.get_process_object_id(system.hostname, source_pid)
        target_obj_id = self.state_manager.get_process_object_id(system.hostname, target_pid)
        source_thread_id = -1
        if source_proc is not None:
            source_thread_rng = random.Random(
                _stable_seed(f"process_access_thread:{system.hostname}:{source_pid}:{time}")
            )
            source_thread_id = windows_id_randint(source_thread_rng, 1000, 9999)
        from evidenceforge.generation.activity.calltrace_patterns import (
            render_call_trace_for_source,
        )

        call_trace = render_call_trace_for_source(
            source_image,
            system.hostname,
            seed_parts=(source_pid, target_pid, time.isoformat(), granted_access),
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="process_access",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=source_pid,
                parent_pid=source_proc.parent_pid if source_proc is not None else 0,
                image=source_image,
                command_line=source_proc.command_line if source_proc is not None else "",
                username=source_proc.username if source_proc is not None else user.username,
                logon_id=source_proc.logon_id if source_proc is not None else "",
                start_time=source_proc.start_time if source_proc is not None else None,
            ),
            auth=AuthContext(
                username=source_proc.username if source_proc is not None else user.username,
            ),
            process_access=ProcessAccessContext(
                source_pid=source_pid,
                source_image=source_image,
                source_thread_id=source_thread_id,
                target_pid=target_pid,
                target_image=target_image,
                target_user=target_proc.username
                if target_proc is not None and target_proc.username
                else "NT AUTHORITY\\SYSTEM",
                target_process_object_id=target_obj_id,
                granted_access=granted_access,
                call_trace=call_trace,
            ),
            edr=EdrContext(object_id=target_obj_id, actor_id=source_obj_id),
        )
        self.dispatcher.dispatch(event)
        return True

    def generate_image_load(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        image: str,
        dll_path: str,
        signed: bool = True,
        signature: str = "Microsoft Windows",
        signature_status: str = "Valid",
    ) -> None:
        """Generate Sysmon Event 7 (ImageLoaded) for DLL/module loading.

        Args:
            user: User running the process that loaded the DLL
            system: System where the load occurs
            time: Event timestamp
            pid: PID of the process loading the DLL
            image: Full path of the process image
            dll_path: Full path of the loaded DLL
            signed: Whether the DLL is signed
            signature: Signer name (e.g., "Microsoft Windows")
            signature_status: Signature validation status (Valid, Expired, etc.)
        """
        from evidenceforge.events.contexts import ImageLoadContext, ProcessContext

        image = normalize_defender_platform_path(image, system.hostname)
        dll_path = _materialize_username_path(dll_path, user.username)
        dll_path = normalize_defender_platform_path(dll_path, system.hostname)
        time = self._clamp_time_after_process_start(system, pid, time)
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None:
            logger.debug(
                "Skipping image load for non-running process: %s pid=%s image=%s dll=%s",
                system.hostname,
                pid,
                image,
                dll_path,
            )
            return
        session_end_time = (
            self.state_manager.get_session_end_time(proc.logon_id) if proc.logon_id else None
        )
        if session_end_time is not None and ensure_utc(time) >= ensure_utc(session_end_time):
            logger.debug(
                "Skipping image load after owning session ended: %s pid=%s logon_id=%s dll=%s",
                system.hostname,
                pid,
                proc.logon_id,
                dll_path,
            )
            return
        if not self._mark_loaded_module(system.hostname, pid, proc.start_time, dll_path):
            logger.debug(
                "Skipping duplicate image load for process instance: %s pid=%s dll=%s",
                system.hostname,
                pid,
                dll_path,
            )
            return
        self.state_manager.update_process_activity_time(system.hostname, pid, time)
        proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
        event = SecurityEvent(
            timestamp=time,
            event_type="image_load",
            src_host=self._build_host_context(system),
            process=ProcessContext(
                pid=pid,
                parent_pid=proc.parent_pid,
                image=image,
                command_line=proc.command_line,
                username=proc.username,
                logon_id=proc.logon_id,
                start_time=proc.start_time,
            ),
            image_load=ImageLoadContext(
                image_loaded=dll_path,
                signed=signed,
                signature=signature,
                signature_status=signature_status,
            ),
            edr=EdrContext(
                object_id=stable_uuid(
                    "manual-image-load-edr",
                    system.hostname,
                    pid,
                    dll_path,
                    time.isoformat(),
                ),
                actor_id=proc_obj_id,
            ),
        )
        self.dispatcher.dispatch(event)

    def _mark_loaded_module(
        self,
        hostname: str,
        pid: int,
        process_start: datetime | None,
        dll_path: str,
    ) -> bool:
        """Return False when this process instance already loaded the module."""
        process_start_key = process_start.isoformat() if process_start is not None else ""
        module_key = (hostname, pid, process_start_key, dll_path.lower())
        if module_key in self._loaded_modules_by_process:
            return False
        self._loaded_modules_by_process.add(module_key)
        return True

    def generate_account_changed(
        self,
        actor: User,
        system: System,
        time: datetime,
        target_username: str,
        target_sid: str,
        password_last_set_to_event_time: bool = False,
        old_uac_value: str | None = None,
        new_uac_value: str | None = None,
        user_account_control: str | None = None,
        primary_group_id: str | None = None,
    ) -> None:
        """Generate user account changed event (4738) on DC."""
        request = AccountChangedRequest(
            actor=actor,
            system=system,
            time=time,
            target_username=target_username,
            target_sid=target_sid,
            password_last_set_to_event_time=password_last_set_to_event_time,
            old_uac_value=old_uac_value,
            new_uac_value=new_uac_value,
            user_account_control=user_account_control,
            primary_group_id=primary_group_id,
        )
        AccountChangedActionBundle(self, request).execute()

    def _execute_account_changed_bundle(self, request: AccountChangedRequest) -> None:
        """Generate user account changed event (4738) on DC."""
        from evidenceforge.events.contexts import AccountManagementContext

        actor = request.actor
        system = request.system
        time = request.time
        target_username = request.target_username
        target_sid = request.target_sid
        password_last_set_to_event_time = request.password_last_set_to_event_time
        old_uac_value = request.old_uac_value
        new_uac_value = request.new_uac_value
        user_account_control = request.user_account_control
        primary_group_id = request.primary_group_id

        reporting_pid = self._get_system_pid(system.hostname, "lsass", 0x2E0)
        subject_logon_id = self._ensure_account_management_subject_logon(actor, system, time)
        host = self._build_host_context(system)
        password_last_set = (
            _format_windows_account_attribute_time(time) if password_last_set_to_event_time else "-"
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="account_changed",
            dst_host=host,
            auth=AuthContext(
                username=actor.username,
                subject_sid=self._get_sid(actor.username),
                subject_username=actor.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=subject_logon_id,
                reporting_pid=reporting_pid,
            ),
            account_management=AccountManagementContext(
                target_username=target_username,
                target_domain=host.netbios_domain,
                target_sid=target_sid,
                sam_account_name=target_username,
                old_uac_value=old_uac_value or "0x0",
                new_uac_value=new_uac_value or "0x15",
                user_account_control=user_account_control or "-",
                password_last_set=password_last_set,
                primary_group_id=primary_group_id or "513",
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_dhcp_lease(
        self,
        system: "System",
        time: datetime,
        mac: str,
        server_addr: str = "10.0.0.1",
        lease_time: float = 3600.0,
        uid: str = "",
        msg_types: list[str] | None = None,
        domain: str | None = None,
    ) -> None:
        """Generate a DHCP lease event via canonical SecurityEvent dispatch."""
        request = DhcpLeaseRequest(
            system=system,
            time=time,
            mac=mac,
            server_addr=server_addr,
            lease_time=lease_time,
            uid=uid,
            msg_types=msg_types,
            domain=domain,
        )
        DhcpLeaseActionBundle(executor=self, request=request).execute()

    def _execute_dhcp_lease_bundle(self, request: DhcpLeaseRequest) -> None:
        """Expand one DHCP lease request into canonical evidence."""
        system = request.system
        time = request.time
        mac = request.mac
        server_addr = request.server_addr
        lease_time = request.lease_time
        uid = request.uid
        msg_types = request.msg_types
        domain = request.domain

        from evidenceforge.events.contexts import DhcpContext

        if msg_types is None:
            msg_types = ["DISCOVER", "OFFER", "REQUEST", "ACK"]
        if domain is None:
            domain = getattr(self, "_ad_domain", "") or ""

        from evidenceforge.events.contexts import NetworkContext

        is_initial_acquisition = "DISCOVER" in msg_types
        dhcp_duration = _get_rng().uniform(0.01, 0.5)
        (
            orig_bytes,
            resp_bytes,
            orig_pkts,
            resp_pkts,
            orig_ip_bytes,
            resp_ip_bytes,
        ) = _dhcp_payload_accounting(
            hostname=system.hostname,
            mac=mac,
            server_addr=server_addr,
            time=time,
            msg_types=msg_types,
        )
        event = SecurityEvent(
            timestamp=time,
            event_type="dhcp_lease",
            src_host=self._build_host_context(system),
            network=NetworkContext(
                src_ip=system.ip,
                dst_ip=server_addr,
                src_port=68,
                dst_port=67,
                protocol="udp",
                service="dhcp",
                zeek_uid=uid,
                duration=dhcp_duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes,
                resp_ip_bytes=resp_ip_bytes,
                conn_state="SF",
                history="DdDd" if "DISCOVER" in msg_types else "Dd",
                local_orig=True,
                local_resp=True,
                ip_proto=17,
                link_local=True,
            ),
            dhcp=DhcpContext(
                client_addr="0.0.0.0" if is_initial_acquisition else system.ip,
                server_addr=server_addr,
                mac=mac,
                host_name=system.hostname,
                domain=domain,
                assigned_addr=system.ip,
                lease_time=lease_time,
                uids=[uid] if uid else [],
                msg_types=msg_types,
                duration=dhcp_duration,
            ),
        )
        self.dispatcher.dispatch(event)
        dispatcher_emitters = getattr(self.dispatcher, "emitters", {})
        if "syslog" in dispatcher_emitters and _get_os_category(system.os) == "linux":
            dhclient_pid = 500 + (_stable_seed(f"dhclient:{system.hostname}") % 59000)
            interface = linux_primary_interface(system)
            renewal = max(60, int(lease_time / 2))
            if is_initial_acquisition:
                messages = [
                    f"DHCPDISCOVER on {interface} to 255.255.255.255 port 67 interval 3",
                    f"DHCPOFFER of {system.ip} from {server_addr}",
                    f"DHCPREQUEST for {system.ip} on {interface} to {server_addr} port 67",
                    f"DHCPACK of {system.ip} from {server_addr}",
                    f"bound to {system.ip} -- renewal in {renewal} seconds.",
                ]
            else:
                messages = [
                    f"DHCPREQUEST for {system.ip} on {interface} to {server_addr} port 67",
                    f"DHCPACK of {system.ip} from {server_addr}",
                    f"bound to {system.ip} -- renewal in {renewal} seconds.",
                ]
            for idx, message in enumerate(messages):
                self.generate_syslog_event(
                    system=system,
                    time=time + timedelta(milliseconds=idx * 1500),
                    app_name="dhclient",
                    message=message,
                    pid=dhclient_pid,
                )

    def generate_anonymous_logon(
        self,
        system: "System",
        time: datetime,
    ) -> None:
        """Generate an anonymous logon event (4624 type 3) without creating a session.

        Used for Windows server/DC background SMB enumeration traffic.
        """
        request = AnonymousLogonRequest(system=system, time=time)
        AnonymousLogonActionBundle(self, request).execute()

    def _execute_anonymous_logon_bundle(self, request: AnonymousLogonRequest) -> None:
        """Generate an anonymous logon event (4624 type 3) without creating a session."""
        system = request.system
        time = request.time

        rng = _get_rng()
        source_ip = "-"
        workstation_name = "-"
        source_port = 0
        candidate_ips = [
            ip
            for ip in getattr(self, "_all_system_ips", [])
            if ip != system.ip and _is_private_ip(ip)
        ]
        source_system = None
        if candidate_ips:
            source_ip = rng.choice(candidate_ips)
            source_port = _ephemeral_port(rng, "windows")
            source_system = getattr(self, "_ip_to_system", {}).get(source_ip)
            workstation_name = source_system.hostname if source_system else "-"
            self.generate_connection(
                src_ip=source_ip,
                dst_ip=system.ip,
                time=time - timedelta(milliseconds=rng.randint(150, 900)),
                dst_port=445,
                proto="tcp",
                service="smb",
                duration=rng.uniform(0.2, 4.0),
                orig_bytes=rng.randint(250, 2600),
                resp_bytes=rng.randint(350, 4200),
                src_port=source_port,
                conn_state="SF",
                source_system=source_system,
            )
        event = SecurityEvent(
            timestamp=time,
            event_type="logon",
            dst_host=self._build_host_context(system),
            auth=AuthContext(
                username="ANONYMOUS LOGON",
                user_sid="S-1-5-7",
                logon_id=self.state_manager.allocate_logon_id(system.hostname, time),
                logon_type=3,
                auth_package="NTLM",
                logon_process="NtLmSsp",
                lm_package="NTLM V2",
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                subject_sid="S-1-0-0",
                subject_username="-",
                subject_domain="-",
                subject_logon_id="0x0",
                source_ip=source_ip,
                source_port=source_port,
                workstation_name=workstation_name,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_syslog_event(
        self,
        system: "System",
        time: datetime,
        app_name: str,
        message: str,
        pid: int | None = None,
        facility: int = 3,
        severity: int = 6,
    ) -> None:
        """Generate a standalone syslog event via canonical SecurityEvent dispatch.

        For daemon status messages, kernel logs, and other syslog-only entries
        that don't correlate with other event types. The SecurityEvent carries
        HostContext + SyslogContext and dispatches to the syslog emitter.
        """
        from evidenceforge.events.contexts import SyslogContext

        if app_name == "sshd" and _get_os_category(system.os) == "linux":
            pid = self._normalize_sshd_syslog_pid(
                system=system,
                time=time,
                message=message,
                pid=pid,
            )

        event = SecurityEvent(
            timestamp=time,
            event_type="syslog",
            src_host=self._build_host_context(system),
            syslog=SyslogContext(
                app_name=app_name,
                message=message,
                pid=pid,
                facility=facility,
                severity=severity,
            ),
        )
        self.dispatcher.dispatch(event)

    def generate_raw(
        self,
        time: datetime,
        target_format: str,
        fields: dict,
        system: "System | None" = None,
    ) -> None:
        """Emit a raw event through the SecurityEvent pipeline.

        Unlike dispatch_raw(), this goes through state management,
        visibility filtering, and local_only checks.
        Automatically injects _host_fqdn for host-based emitter routing.
        """
        from evidenceforge.events.contexts import RawContext

        fields = dict(fields)
        host_ctx = self._build_host_context(system) if system else None
        if target_format == "syslog" and str(fields.get("app_name", "")).startswith("apache"):
            fields = self._normalize_apache_raw_syslog(time, fields, system)
        # Inject timestamp if not provided (format templates need it for rendering)
        if "timestamp" not in fields:
            fields["timestamp"] = time
        # Inject host FQDN for HostMultiplexEmitter routing
        if host_ctx and "_host_fqdn" not in fields:
            fields["_host_fqdn"] = (
                host_ctx.fqdn if hasattr(host_ctx, "fqdn") and host_ctx.fqdn else host_ctx.hostname
            )
        if host_ctx and "hostname" not in fields:
            fields["hostname"] = host_ctx.hostname
        event = SecurityEvent(
            timestamp=time,
            event_type="raw",
            src_host=host_ctx,
            raw=RawContext(target_format=target_format, fields=fields),
        )
        self.dispatcher.dispatch(event)

    def generate_spillage(
        self,
        *,
        user: "User",
        system: "System",
        time: datetime,
        surface: str,
        family: str | None,
        value: str | None,
        seed_key: str,
        scheme: str | None = None,
        logon_id: str | None = None,
        target_system: "System | None" = None,
    ) -> dict[str, Any]:
        """Emit one synthetic credential into a semantic surface.

        Resolves a single safety-checked canonical value (synthesized from a
        family or supplied literally), renders it with surface-appropriate
        encoding, and routes it through the canonical modeled generation path
        for that surface. ``target_system`` is the destination web server for the
        http_* surfaces (whose access log records the credential). Returns a dict
        of ground-truth fields.
        """
        from evidenceforge.generation.spillage import (
            HTTP_SURFACES,
            choose_web_spillage_scheme,
            render_for_surface,
            resolve_value,
        )

        canonical, resolved_family = resolve_value(family, value, seed_key=seed_key)
        os_category = _get_os_category(system.os)
        render = render_for_surface(
            canonical, surface, resolved_family, seed_key, os_category=os_category
        )

        emitted_time = time
        target_fqdn: str | None = None
        effective_scheme: str | None = None
        if surface == "shell_history":
            # bash history dwell/session scheduling can shift the visible time;
            # use the actual emitted time so ground truth matches the log line.
            # This surface is the bash-history-FILE exposure (the credential left in
            # history); v1 does not also emit correlated process/network telemetry
            # for the carrier — use process_command_line for the EDR-correlated form.
            result_time = self.generate_bash_command(
                user=user,
                system=system,
                time=time,
                activity_type_or_command=render.command,
                emit_process_telemetry=False,
            )
            if result_time is None:
                # The bash command was suppressed (dwell-shifted past the scenario
                # window, or a non-interactive user) — nothing landed on disk, so
                # do NOT label it. Signal suppression; the caller skips the record.
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            emitted_time = result_time
        elif surface == "process_command_line":
            # The credential rides on a process command line (T1552.001), captured
            # by EDR/process telemetry via the canonical process-execution bundle as
            # a standalone process with a durable unique PID. Carriers are LOCAL
            # commands only (aws configure set, git config, os.environ[...]=, …),
            # so this live in-window process record is self-consistent and never
            # implies an outbound connection it doesn't model — see docs/reference/
            # spillage.md "Correlation scope (v1)". OS-aware: a Windows host renders
            # a cmd/PowerShell/.exe carrier (not a Linux /usr/bin command line).
            default_proc = (
                r"C:\Windows\System32\cmd.exe" if os_category == "windows" else "/usr/bin/sh"
            )
            parent_pid = 4
            if os_category == "linux" and logon_id:
                parent_pid = self._spillage_process_parent_pid(
                    system=system,
                    time=time,
                    logon_id=logon_id,
                )
            pid = self.generate_process(
                user=user,
                system=system,
                time=time,
                logon_id=logon_id or "0x0",
                process_name=render.process_name or default_proc,
                command_line=render.command,
                parent_pid=parent_pid,
                from_storyline=True,
            )
            if not pid:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
        elif surface == "syslog_message":
            self.generate_syslog_event(
                system=system,
                time=time,
                app_name=render.syslog_app,
                message=render.syslog_message,
            )
        elif surface in HTTP_SURFACES:
            # The credential rides in an outbound HTTP/S request (URL query or
            # Referer header) from the actor's host to a web server, captured by
            # that server's access log. Route through the canonical connection
            # path so the web emitter renders it natively.
            if target_system is None:
                # No web server to receive the request — nothing lands on disk, so
                # do NOT label it (validation flags this case before generation).
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            effective_scheme = choose_web_spillage_scheme(target_system, scheme)
            if effective_scheme is None:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            # Record the destination's FQDN exactly as the web emitter names the
            # access-log directory, so the sidecar's target_system points a scorer
            # (and the eval record search) at the right host even for dotted/FQDN
            # hostnames or external servers.
            target_fqdn = self._build_host_context(target_system).fqdn or target_system.hostname
            ua_rng = random.Random(_stable_seed(f"{seed_key}:ua"))
            if surface == "http_referrer":
                # A Referer header is sent by browsers, not CLI/library clients; a
                # browser-class UA keeps the request realistic and source-coherent
                # (a tool UA would make downstream normalization drop the Referer).
                # Use an OS-matched browser pool so a Linux/Windows actor gets a
                # Linux/Windows UA (AGENTS.md rule 3: OS-aware defaults).
                from evidenceforge.generation.activity.web_session_profiles import (
                    pick_web_user_agent,
                )

                user_agent = pick_web_user_agent(
                    ua_rng,
                    {
                        "user_agent_pool": "browser_any",
                        "user_agent_pool_by_os": {
                            "windows": "browser_windows",
                            "linux": "browser_linux",
                        },
                    },
                    source_os=_get_os_category(system.os),
                )
            else:
                user_agent = pick_proxy_user_agent(ua_rng, system, hostname=target_system.hostname)
            resp_len = random.Random(_stable_seed(f"{seed_key}:bytes")).randint(256, 8192)
            http_ctx = HttpContext(
                method=render.http_method or "GET",
                host=target_system.hostname,
                uri=render.http_uri or "/",
                version="1.1",
                user_agent=user_agent,
                request_body_len=0,
                response_body_len=resp_len,
                status_code=200,
                status_msg="OK",
                referrer=render.http_referrer or "",
            )
            # Direct request to the web server (proxy_bypass): the spillage contract
            # is that the credential lands in the target's access log with
            # client_ip = the actor's host. Routing through an explicit proxy would
            # rewrite client_ip to the proxy and can scrub the Referer for an
            # external target, which would mislabel the (unwritten) credential as
            # landed. Going direct keeps the surface source-coherent.
            uid = self.generate_connection(
                src_ip=system.ip,
                dst_ip=target_system.ip,
                time=time,
                dst_port=80 if effective_scheme == "http" else 443,
                proto="tcp",
                service=effective_scheme,
                source_system=system,
                http=http_ctx,
                hostname=target_system.hostname,
                preserve_dst_ip=True,
                proxy_bypass=True,
            )
            if not uid:
                # The connection was filtered out (e.g. no sensor observes the
                # actor->web-server path), so nothing landed on disk — do NOT label
                # it, mirroring the suppressed shell_history case above.
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
        else:  # pragma: no cover - guarded by render_for_surface/model Literal
            raise ValueError(f"unsupported spillage surface: {surface!r}")

        return {
            "surface": surface,
            "family": resolved_family,
            "value": canonical,
            "rendered_value": render.encoded_value,
            "expected_sources": list(render.expected_sources),
            "time": emitted_time,
            "target_system": target_fqdn,
            "scheme": effective_scheme,
        }

    def _spillage_process_parent_pid(
        self,
        *,
        system: "System",
        time: datetime,
        logon_id: str,
    ) -> int:
        """Choose a non-shell parent for session-bound Linux process spillage."""
        if _get_os_category(system.os) != "linux" or not logon_id:
            return 4

        session = self.state_manager.get_session(logon_id)
        if session is not None:
            for candidate in (session.transport_pid, session.process_tree_root):
                if (
                    candidate
                    and self.state_manager.get_process(system.hostname, candidate) is not None
                    and self._is_pid_active_at(system, candidate, time)
                ):
                    parent_proc = self.state_manager.get_process(system.hostname, candidate)
                    parent_exe = (
                        parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                        if parent_proc is not None
                        else ""
                    )
                    if parent_exe not in {"bash", "sh", "zsh"}:
                        return candidate

        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for role in ("sshd", "systemd", "init"):
            candidate = sys_pids.get(role)
            if (
                candidate
                and self.state_manager.get_process(system.hostname, candidate) is not None
                and self._is_pid_active_at(system, candidate, time)
            ):
                return candidate
        return 4

    def generate_adversarial_payload(
        self,
        *,
        user: "User",
        system: "System",
        time: datetime,
        surface: str,
        family: str | None,
        value: str | None,
        seed_key: str,
        scheme: str | None = None,
        logon_id: str | None = None,
        target_system: "System | None" = None,
    ) -> dict[str, Any]:
        """Emit one adversarial payload into a semantic surface.

        The counterpart to ``generate_spillage``: resolves a single safety-checked
        canonical payload (synthesized from a family or supplied literally), renders
        it with surface-appropriate encoding that PRESERVES the injection, and routes
        it through the canonical modeled generation path for that surface. For http_*
        surfaces ``scheme`` is the destination web server's resolved transport
        (http/https), chosen by the caller from the server's supported schemes.
        Returns a dict of ground-truth fields (including ``encoding`` and ``scheme``).
        """
        from evidenceforge.config.payload_families import get_family
        from evidenceforge.generation.adversarial_payload import (
            HTTP_SURFACES,
            _raw_surfaces_for,
            ids_signature_for_payload,
            render_for_surface,
            resolve_value,
        )

        # Live-callback opt-in (off by default): operator-registered OOB host(s) from
        # `eforge generate --oob-host`. When set, a family's {canary} resolves to the
        # first and all are accepted by the host allowlist, so the payload calls back to
        # the operator's Collaborator/sinkhole and a fuzzer's own value: payload passes.
        oob_hosts: tuple[str, ...] = tuple(getattr(self, "_oob_hosts", ()) or ())
        canonical, resolved_family = resolve_value(
            family, value, seed_key=seed_key, oob_hosts=oob_hosts
        )
        os_category = _get_os_category(system.os)
        render = render_for_surface(
            canonical,
            surface,
            resolved_family or None,
            seed_key,
            os_category=os_category,
            oob_hosts=oob_hosts,
        )

        emitted_time = time
        target_fqdn: str | None = None
        effective_scheme: str | None = None
        ids_alert_meta: dict[str, Any] | None = None
        # Pivot anchors: faithful identifiers that let an analyst jump from the payload
        # record to the exact evidence row — dst tuple for http (grep zeek/web by ip:port),
        # pid for process (the eCAR PROCESS record). The connection UID is intentionally
        # omitted: the rendered Zeek row carries a sensor-derived UID, so a raw UID here
        # would mislead rather than pivot.
        pivot: dict[str, Any] = {}
        if surface == "syslog_message":
            # Carry a realistic procid so the injected line isn't the only NILVALUE-pid
            # line in the file (a statistical fingerprint a reviewer could grep for).
            syslog_pid = random.Random(_stable_seed(f"{seed_key}:syslog_pid")).randint(300, 32000)
            self.generate_syslog_event(
                system=system,
                time=time,
                app_name=render.syslog_app,
                message=render.syslog_message,
                pid=syslog_pid,
            )
        elif surface == "process_command_line":
            # The payload rides on a process command line, captured by EDR/process
            # telemetry as a standalone process. Control bytes are escaped by the
            # surface encoder before they reach command_line, so the eCAR record is
            # not corrupted (the modeled raw-injection surface is syslog_message).
            default_proc = (
                r"C:\Windows\System32\cmd.exe" if os_category == "windows" else "/usr/bin/sh"
            )
            # Canonical session/parent ownership for a session-bound Linux spill: pick a
            # non-shell parent so the live in-window process record is self-consistent.
            parent_pid = 4
            if os_category == "linux" and logon_id:
                parent_pid = self._spillage_process_parent_pid(
                    system=system,
                    time=time,
                    logon_id=logon_id,
                )
            pid = self.generate_process(
                user=user,
                system=system,
                time=time,
                logon_id=logon_id or "0x0",
                process_name=render.process_name or default_proc,
                command_line=render.command,
                parent_pid=parent_pid,
                from_storyline=True,
            )
            if not pid:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            pivot["pid"] = pid
        elif surface in HTTP_SURFACES:
            # The payload rides in an outbound HTTP/S request field (User-Agent, URL,
            # or Referer) from the actor's host to a web server, captured by that
            # server's access log. Route through the canonical connection path so the
            # web emitter renders it natively.
            if target_system is None:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            from evidenceforge.generation.spillage import choose_web_spillage_scheme

            effective_scheme = choose_web_spillage_scheme(target_system, scheme)
            if effective_scheme is None:
                # The chosen web server does not serve a compatible scheme.
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            target_fqdn = self._build_host_context(target_system).fqdn or target_system.hostname
            if surface == "http_user_agent":
                # The payload IS the User-Agent header (the classic Log4Shell/UA
                # vector); the request path is benign.
                user_agent = render.user_agent or render.encoded_value
            elif surface == "http_referrer":
                from evidenceforge.generation.activity.web_session_profiles import (
                    pick_web_user_agent,
                )

                ua_rng = random.Random(_stable_seed(f"{seed_key}:ua"))
                user_agent = pick_web_user_agent(
                    ua_rng,
                    {
                        "user_agent_pool": "browser_any",
                        "user_agent_pool_by_os": {
                            "windows": "browser_windows",
                            "linux": "browser_linux",
                        },
                    },
                    source_os=_get_os_category(system.os),
                )
            else:
                ua_rng = random.Random(_stable_seed(f"{seed_key}:ua"))
                user_agent = pick_proxy_user_agent(ua_rng, system, hostname=target_system.hostname)
            resp_len = random.Random(_stable_seed(f"{seed_key}:bytes")).randint(256, 8192)
            http_ctx = HttpContext(
                method=render.http_method or "GET",
                host=target_system.hostname,
                uri=render.http_uri or "/",
                version="1.1",
                user_agent=user_agent,
                request_body_len=0,
                response_body_len=resp_len,
                status_code=200,
                status_msg="OK",
                referrer=render.http_referrer or "",
            )
            conn_dst_port = 80 if effective_scheme == "http" else 443
            # On-wire IDS detection: a cleartext http payload mapped to a Snort/Suricata
            # signature fires the network alert — the "does my IDS catch this?" test. The
            # alert fires ONLY when the rendered payload still contains the signature's flat
            # content token, so an evasion variant (obfuscated JNDI lookup, UNION/**/SELECT,
            # a CR-only forge) correctly produces NO alert — modeling the real rule's blind
            # spot, which is the detection-gap the evasion variants exist to exercise.
            # Encrypted (https) traffic is opaque to the sensor. Built through the IDS alert
            # action bundle so (gid, sid, rev)/message/priority are owned canonically; the
            # Snort emitter only renders the resulting IdsContext.
            ids_ctx: IdsContext | None = None
            fire_sid = (
                ids_signature_for_payload(resolved_family, canonical)
                if effective_scheme == "http"
                else None
            )
            if fire_sid:
                from evidenceforge.generation.actions import (
                    IdsAlertActionBundle,
                    IdsAlertRequest,
                )
                from evidenceforge.generation.activity.ids_signatures import signature_by_sid

                signature = signature_by_sid(fire_sid)
                if signature:
                    ids_ctx = IdsAlertActionBundle(
                        IdsAlertRequest(
                            signature=signature,
                            time=time,
                            src_ip=system.ip,
                            dst_ip=target_system.ip,
                            dst_port=conn_dst_port,
                            proto="tcp",
                            rng=random.Random(_stable_seed(f"{seed_key}:ids")),
                            source="adversarial_payload",
                            direction="in",
                        )
                    ).execute()
                    # Record the alert in ground truth ONLY when an IDS sensor on the path
                    # actually observes this cleartext connection — mirroring the exact
                    # decision the dispatcher uses to render snort_alert. East-west traffic a
                    # TAP sensor cannot see (intra-segment), or a scenario with no IDS sensor,
                    # renders NO snort line, so it must record no ids_alert (else ground truth
                    # would claim an alert that is absent from snort_alert.log). The IdsContext
                    # is still attached; the dispatcher is the single render authority.
                    visibility = self._network_visibility or (
                        self.dispatcher.visibility_engine
                        if getattr(self, "dispatcher", None)
                        else None
                    )
                    snort_observes = visibility is None or (
                        "snort_alert"
                        in visibility.get_log_formats_for_connection(system.ip, target_system.ip)
                    )
                    if snort_observes:
                        ids_alert_meta = {
                            "sid": int(signature["sid"]),
                            "rev": int(signature.get("rev", 1)),
                            "message": str(signature["message"]),
                        }
            uid = self.generate_connection(
                src_ip=system.ip,
                dst_ip=target_system.ip,
                time=time,
                dst_port=conn_dst_port,
                proto="tcp",
                service=effective_scheme,
                source_system=system,
                http=http_ctx,
                hostname=target_system.hostname,
                preserve_dst_ip=True,
                proxy_bypass=True,
                ids=ids_ctx,
            )
            if not uid:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            pivot["dst_ip"] = target_system.ip
            pivot["dst_port"] = conn_dst_port
        elif surface == "dns_qname":
            # The payload rides in a DNS query NAME the actor's host looks up, captured by
            # the network sensor's Zeek dns.log. A non-resolving .invalid canary QNAME
            # yields NXDOMAIN (no answer, no follow-on TCP). Route through the canonical
            # connection path (UDP/53, service=dns) so the zeek_dns emitter renders it
            # natively. zeek_dns is the ONLY source for this surface, so if no network
            # sensor observes the lookup, nothing lands and the payload is not_emitted —
            # never a ground-truth label without bytes on disk.
            qname = render.dns_query or render.encoded_value
            dns_server_ips = getattr(self, "_dns_server_ips", None) or ["10.0.0.1"]
            dns_rng = random.Random(_stable_seed(f"{seed_key}:dns"))
            dns_server_ip = dns_rng.choice(sorted(dns_server_ips))
            dns_ctx = DnsContext(
                query=qname,
                query_type="A",
                qtype=1,
                rcode="NXDOMAIN",
                rcode_num=3,
                answers=[],
                TTLs=[],
                trans_id=dns_rng.randint(1, 65535),
                AA=False,
                RD=True,
                RA=True,
                rejected=False,
                rtt=_dns_rtt(dns_rng, dns_server_ip),
            )
            uid = self.generate_connection(
                src_ip=system.ip,
                dst_ip=dns_server_ip,
                time=time,
                dst_port=53,
                proto="udp",
                service="dns",
                source_system=system,
                dns=dns_ctx,
                emit_dns=False,
                orig_bytes=dns_rng.randint(40, 100),
                resp_bytes=dns_rng.randint(40, 80),
                conn_state="SF",
                duration=dns_rng.uniform(0.001, 0.05),
            )
            # zeek_dns is the ONLY source for this surface (a Linux host keeps no DNS log
            # of its own), and it renders ONLY when a network sensor on the path observes
            # the UDP/53 lookup. generate_connection allocates a uid regardless of
            # visibility, so uid alone is NOT proof of emission — gate on actual zeek_dns
            # observation, mirroring the http_user_agent → zeek_http check, so ground truth
            # never claims a row that no sensor wrote.
            dispatcher = getattr(self, "dispatcher", None)
            visibility = self._network_visibility or (
                dispatcher.visibility_engine if dispatcher else None
            )
            zeek_dns_observed = bool(
                uid
                and dispatcher is not None
                and "zeek_dns" in dispatcher.emitters
                and visibility is not None
                and visibility.enabled
                and "zeek_dns"
                in visibility.get_log_formats_for_connection(system.ip, dns_server_ip)
            )
            if not zeek_dns_observed:
                return {
                    "surface": surface,
                    "family": resolved_family,
                    "skipped_reason": "not_emitted",
                }
            pivot["dst_ip"] = dns_server_ip
            pivot["dst_port"] = 53
        elif surface == "auth_user":
            # The payload rides in a failed-logon USERNAME, captured by the host's auth.log
            # (sshd "Failed password for <user> from <ip>"). A remote SSH attempt with an
            # injected username is the realistic vector a copilot reads. Linux-only (the
            # validator gates non-Linux), so the syslog auth line is the rendered surface.
            username = render.auth_username or render.encoded_value
            attacker_octet = random.Random(_stable_seed(f"{seed_key}:authsrc")).randint(2, 254)
            attacker_ip = f"203.0.113.{attacker_octet}"
            self.generate_failed_logon(
                user=user,
                system=system,
                time=time,
                logon_type=3,
                source_ip=attacker_ip,
                target_username=username,
            )
        else:  # pragma: no cover - guarded by render_for_surface/model Literal
            raise ValueError(f"unsupported adversarial payload surface: {surface!r}")

        # Label the transform by what actually happened: when the encoder was a no-op
        # for this value (e.g. csv_formula has no control bytes to escape; a printable
        # log4shell UA needs no percent-encoding) the on-disk form equals the canonical
        # value, so report "raw" rather than a transform that did nothing.
        unchanged = render.encoded_value == canonical
        if surface in ("http_request_url", "http_referrer", "http_user_agent"):
            encoding = "raw" if unchanged else "percent"
        elif surface == "process_command_line":
            encoding = "raw" if unchanged else "shell_quote"
        elif surface == "dns_qname":
            encoding = "qname"  # LDH-encoded into a DNS query name under the canary domain
        elif surface == "auth_user":
            encoding = "raw" if unchanged else "escaped"  # control bytes escaped in the username
        else:  # syslog_message — use the SAME family resolution the encoder used
            raw_here = surface in _raw_surfaces_for(resolved_family or None)
            encoding = "raw" if (raw_here or unchanged) else "escaped"

        # A plaintext-http payload MAY also be visible on the wire in Zeek http.log — but only
        # claim it as an expected source when it will ACTUALLY land in this dataset: the
        # zeek_http emitter must be configured AND a network sensor on the path must observe Zeek
        # for this connection (with no sensor there is no Zeek output, and an unconfigured format
        # is never written). expected_sources must mean "exists in this dataset", not
        # "theoretically visible there". https is encrypted, so web_access only.
        expected_sources = list(render.expected_sources)
        if surface in HTTP_SURFACES and effective_scheme == "http":
            dispatcher = getattr(self, "dispatcher", None)
            visibility = self._network_visibility or (
                dispatcher.visibility_engine if dispatcher else None
            )
            zeek_configured = dispatcher is not None and "zeek_http" in dispatcher.emitters
            zeek_observed = (
                visibility is not None
                and visibility.enabled
                and "zeek_http"
                in visibility.get_log_formats_for_connection(system.ip, target_system.ip)
            )
            if zeek_configured and zeek_observed:
                expected_sources.append("zeek_http")

        # Surface the live-callback host when this payload actually embeds it, so an
        # operator knows exactly which OOB record to watch on their Collaborator.
        callback_host = next((h for h in oob_hosts if h and h in canonical), None)
        # Carry the family's weakness class + pass criterion into ground truth so an
        # analyst can score the payload without re-reading the family config.
        fam_meta = get_family(resolved_family) if resolved_family else None
        weakness_class = (fam_meta or {}).get("weakness_class", "").strip() or None
        expected_signal = (fam_meta or {}).get("expected_defender_signal", "").strip() or None
        return {
            "surface": surface,
            "family": resolved_family,
            "value": canonical,
            "rendered_value": render.encoded_value,
            "expected_sources": expected_sources,
            "encoding": encoding,
            "scheme": effective_scheme,
            "time": emitted_time,
            "target_system": target_fqdn,
            **({"callback_host": callback_host} if callback_host else {}),
            **({"weakness_class": weakness_class} if weakness_class else {}),
            **({"expected_defender_signal": expected_signal} if expected_signal else {}),
            **({"ids_alert": ids_alert_meta} if ids_alert_meta else {}),
            **pivot,
        }

    def _normalize_apache_raw_syslog(
        self,
        time: datetime,
        fields: dict[str, Any],
        system: "System | None",
    ) -> dict[str, Any]:
        """Align Apache raw syslog fragments with canonical event time/tuple context."""
        message = str(fields.get("message", ""))
        if not message:
            return fields

        apache_time = ensure_utc(time).strftime("%a %b %d %H:%M:%S.%f %Y")
        message = _APACHE_EMBEDDED_TS_RE.sub(f"[{apache_time}]", message, count=1)

        listener_pid = self._apache_listener_pid(system, time)
        if listener_pid is not None:
            fields["pid"] = listener_pid
            message = _APACHE_PID_RE.sub(f"[pid {listener_pid}]", message, count=1)

        client_match = _APACHE_CLIENT_RE.search(message)
        if client_match and system is not None:
            client_ip = client_match.group("ip")
            recent_port = self._recent_apache_client_port(client_ip, system, time)
            if recent_port is not None:
                message = _APACHE_CLIENT_RE.sub(
                    f"[client {client_ip}:{recent_port}]",
                    message,
                    count=1,
                )

        fields["message"] = message
        return fields

    def _apache_listener_pid(self, system: "System | None", time: datetime) -> int | None:
        """Return the live Apache listener PID for source-native Apache log fragments."""
        if system is None:
            return None
        system_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for key in ("apache2", "httpd", "nginx"):
            pid = int(system_pids.get(key, 0) or 0)
            if pid > 0 and self._is_pid_active_at(system, pid, time):
                return pid
        return None

    def _recent_apache_client_port(
        self,
        client_ip: str,
        system: "System",
        reference_time: datetime,
    ) -> int | None:
        """Return a recent canonical web-request source port for Apache raw logs."""
        candidate_dst_ips = [system.ip]
        visibility = getattr(getattr(self, "dispatcher", None), "visibility_engine", None)
        real_to_vip = getattr(visibility, "_real_ip_to_vip", {}) if visibility is not None else {}
        vip_ip = real_to_vip.get(system.ip)
        if vip_ip and vip_ip not in candidate_dst_ips:
            candidate_dst_ips.append(vip_ip)

        for dst_ip in candidate_dst_ips:
            recent_port = self._recent_source_port_for_connection(
                client_ip,
                dst_ip,
                dst_port=443,
                proto="tcp",
                reference_time=reference_time,
            )
            if recent_port is not None:
                return recent_port
        return None

    def _recent_source_port_for_connection(
        self,
        src_ip: str,
        dst_ip: str,
        *,
        dst_port: int,
        proto: str,
        reference_time: datetime,
    ) -> int | None:
        """Return a recent remembered source port for a canonical network tuple."""
        ref_epoch = reference_time.timestamp()
        candidates: list[tuple[float, int]] = []
        for (
            remembered_src,
            remembered_port,
            remembered_dst,
            remembered_dst_port,
            remembered_proto,
        ), seen_at in self._recent_connection_tuples.items():
            if (
                remembered_src == src_ip
                and remembered_dst == dst_ip
                and remembered_dst_port == dst_port
                and remembered_proto == proto
                and abs(ref_epoch - seen_at) <= 1800
            ):
                candidates.append((abs(ref_epoch - seen_at), remembered_port))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][1]

    def generate_sensor_startup(
        self,
        sensor_hostname: str,
        time: datetime,
        reporter_messages: list[tuple[str, str]] | None = None,
    ) -> None:
        """Generate sensor startup events (packet_filter.log + reporter.log).

        Emits a SecurityEvent with event_type="sensor_startup" that routes
        to ZeekPacketFilterEmitter and ZeekReporterEmitter.

        Args:
            sensor_hostname: Hostname of the sensor
            time: Startup timestamp
            reporter_messages: Optional list of (level, message) tuples for reporter.log
        """
        from evidenceforge.events.contexts import ShellContext

        # Packet filter startup
        event = SecurityEvent(
            timestamp=time,
            event_type="sensor_startup",
            src_host=HostContext(
                hostname=sensor_hostname,
                ip="",
                os="",
                os_category="",
                system_type="sensor",
            ),
        )
        self.dispatcher.dispatch(event)

        # Reporter startup messages
        if reporter_messages:
            for i, (level, msg) in enumerate(reporter_messages):
                reporter_event = SecurityEvent(
                    timestamp=time + timedelta(milliseconds=i * 50),
                    event_type="sensor_startup",
                    src_host=HostContext(
                        hostname=sensor_hostname,
                        ip="",
                        os="",
                        os_category="",
                        system_type="sensor",
                    ),
                    shell=ShellContext(command=f"{level}|{msg}"),
                )
                self.dispatcher.dispatch(reporter_event)

    def _get_next_event_record_id(self, hostname: str = "") -> int:
        """Get next EventRecordID for a specific computer (thread-safe).

        Real Windows event logs have per-computer sequential IDs. Each host
        starts at a random offset (1000-50000) to simulate uptime history.

        Args:
            hostname: Computer hostname for per-machine counter
        """
        with self._counter_lock:
            if hostname not in self._event_record_counters:
                rng = random.Random(_stable_seed(f"erid_{hostname}"))
                self._event_record_counters[hostname] = rng.randint(1000, 50000)
            self._event_record_counters[hostname] += 1
            return self._event_record_counters[hostname]

    # Well-known Windows SIDs (always available regardless of registry)
    _WELL_KNOWN_SIDS = {
        "SYSTEM": "S-1-5-18",
        "LOCAL SERVICE": "S-1-5-19",
        "NETWORK SERVICE": "S-1-5-20",
    }

    # Personas that imply privileged Windows tokens without explicit group data.
    # Help desk and security analyst roles often have delegated tools but should
    # not automatically receive SeDebug/backup-style 4672 privileges on every
    # routine workstation logon unless scenario groups mark them as admins.
    _ADMIN_PERSONAS = {"sysadmin"}

    def _special_privilege_profile_name(
        self,
        user: User,
        logon_type: int,
        hostname: str,
    ) -> str:
        """Classify a logon for 4672 emission and privilege-list selection."""
        username = user.username
        if username in ("LOCAL SERVICE", "NETWORK SERVICE"):
            return "service_account"
        if username == "SYSTEM":
            return "system_account"
        if username.endswith("$"):
            return "machine_account"
        if logon_type == 5:
            return "service_account"

        persona = str(getattr(user, "persona", "") or "")
        admin_group_terms = ("admin", "operator", "account operator", "server operator")
        groups = [str(group).lower() for group in getattr(user, "groups", [])]
        is_admin = persona in self._ADMIN_PERSONAS or any(
            any(term in group for term in admin_group_terms) for group in groups
        )
        if is_admin:
            return "domain_admin" if "dc" in hostname.lower() else "workstation_admin"
        return "regular_user"

    def _should_elevate(
        self,
        user: User,
        logon_type: int = 0,
        hostname: str = "",
    ) -> bool:
        """Determine if a logon should generate 4672 (Special Privileges).

        Role-based and data-driven: privileged accounts receive 4672 according
        to source-native account-class probabilities. Regular users do not
        randomly receive 4672 unless the scenario marks them as privileged via
        persona or group membership.
        """
        rng = _get_rng()
        profile_name = self._special_privilege_profile_name(user, logon_type, hostname)
        if profile_name == "regular_user":
            return False
        config = special_privileges_config().get("emission_probabilities", {})
        probabilities = config if isinstance(config, dict) else {}
        default_probability = 0.0 if profile_name == "regular_user" else 0.5
        try:
            probability = float(probabilities.get(profile_name, default_probability))
        except (TypeError, ValueError):
            probability = default_probability
        probability = max(0.0, min(probability, 1.0))
        return rng.random() < probability

    def _select_auth_package(self, logon_type: int) -> dict[str, str]:
        """Select auth package, LogonProcessName, and LogonGuid based on logon type.

        In real AD: Kerberos dominates for network logons, NTLM as fallback,
        Negotiate for interactive logons.
        """
        rng = _get_rng()
        if logon_type == 2:
            # Interactive: Negotiate (local login)
            return {
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "LmPackageName": "-",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }
        elif logon_type in (3, 4, 5, 8, 9):
            # Network/batch/service: Kerberos dominates in AD
            roll = rng.random()
            if roll < 0.70:
                return {
                    "LogonProcessName": "Kerberos",
                    "AuthenticationPackageName": "Kerberos",
                    "LmPackageName": "-",
                    "LogonGuid": "generate",
                }
            return {
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": "NTLM",
                "LmPackageName": "NTLM V2",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }
        elif logon_type == 10:
            # RemoteInteractive/RDP 4624 records use the workstation logon process;
            # CredSSP is the transport/SSP layer, not a native 4624 auth package.
            auth_package = rng.choices(
                ["Negotiate", "Kerberos", "NTLM"], weights=[55, 35, 10], k=1
            )[0]
            return {
                "LogonProcessName": "User32",
                "AuthenticationPackageName": auth_package,
                "LmPackageName": "NTLM V2" if auth_package == "NTLM" else "-",
                "LogonGuid": "generate"
                if auth_package == "Kerberos"
                else "{00000000-0000-0000-0000-000000000000}",
            }
        else:
            # Type 7 (unlock), 11 (cached interactive), etc. are local interactive
            # workstation logons. User32 is the logon process; Negotiate is the
            # auth package.
            return {
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "LmPackageName": "-",
                "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            }

    def _select_special_privileges(
        self,
        user: User,
        logon_type: int,
        hostname: str,
    ) -> str:
        """Return a source-native 4672 privilege list for this elevated session."""
        profile_name = self._special_privilege_profile_name(user, logon_type, hostname)
        if profile_name == "service_account":
            profile_name = "service_account"
        elif profile_name in {"system_account", "machine_account"}:
            profile_name = "domain_admin"
        elif profile_name == "regular_user":
            profile_name = "uac_elevated_user"

        profiles = special_privileges_config().get("profiles", {})
        profile = profiles.get(profile_name, {}) if isinstance(profiles, dict) else {}
        privileges = profile.get("privileges") if isinstance(profile, dict) else None
        if not isinstance(privileges, list) or not privileges:
            privileges = ["SeChangeNotifyPrivilege"]
        return "\n\t\t\t".join(str(privilege) for privilege in privileges)

    def _maybe_emit_remote_logon_network_connection(
        self,
        system: System,
        time: datetime,
        logon_type: int,
        source_ip: str | None,
        source_port: int,
        auth_package: str,
    ) -> None:
        """Emit established network evidence for remote Windows logons when needed."""
        if logon_type not in (3, 10):
            return
        if not source_ip or source_ip == "-" or source_port <= 0:
            return
        source_ip = source_ip.removeprefix("::ffff:")
        if source_ip == system.ip:
            return
        if _get_os_category(system.os) != "windows":
            return
        rng = _get_rng()
        dst_port = 3389 if logon_type == 10 else 445
        service = "rdp" if dst_port == 3389 else "smb"
        self.generate_connection(
            src_ip=source_ip,
            dst_ip=system.ip,
            time=time - timedelta(milliseconds=rng.randint(150, 900)),
            dst_port=dst_port,
            proto="tcp",
            service=service,
            duration=rng.uniform(1.5, 45.0) if auth_package != "NTLM" else rng.uniform(0.4, 8.0),
            orig_bytes=rng.randint(700, 6500),
            resp_bytes=rng.randint(900, 12000),
            src_port=source_port,
            conn_state="SF",
        )

    def _get_system_pid(self, hostname: str, role: str, fallback: int) -> int:
        """Get a seeded system process PID by role name."""
        pids = getattr(self, "_system_pids", {}).get(hostname, {})
        return pids.get(role, fallback)

    def _existing_windows_singleton_service_pid(
        self,
        system: System,
        process_name: str,
        time: datetime,
        username: str,
    ) -> int | None:
        """Return an active canonical Windows service singleton PID when one exists."""
        if _get_os_category(system.os) != "windows":
            return None

        normalized_path = ntpath.normpath(process_name.replace("/", "\\")).lower()
        exe_name = normalized_path.rsplit("\\", 1)[-1]
        if exe_name not in _WINDOWS_SINGLETON_SERVICE_EXES:
            return None

        canonical_path = f"c:\\windows\\system32\\{exe_name}"
        if "\\" in normalized_path and normalized_path != canonical_path:
            return None

        normalized_username = username.upper()
        candidates: list[RunningProcess] = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_path = ntpath.normpath(proc.image.replace("/", "\\")).lower()
            if proc_path != canonical_path:
                continue
            if proc.username.upper() != normalized_username:
                continue
            if proc.start_time > time:
                continue
            parent = self.state_manager.get_process(system.hostname, proc.parent_pid)
            parent_image = parent.image if parent else ""
            if ntpath.basename(parent_image).lower() != "services.exe":
                continue
            candidates.append(proc)

        if not candidates:
            return None
        return max(candidates, key=lambda proc: proc.start_time).pid

    def _existing_windows_singleton_pid(
        self,
        system: System,
        process_name: str,
        time: datetime,
    ) -> int | None:
        """Return a seeded Windows singleton PID instead of creating a duplicate."""
        if _get_os_category(system.os) != "windows":
            return None
        normalized_path = ntpath.normpath(process_name.replace("/", "\\")).lower()
        exe_name = normalized_path.rsplit("\\", 1)[-1]
        role = _WINDOWS_SINGLETON_SYSTEM_PROCESSES.get(exe_name)
        if role is None:
            return None
        if "\\" in normalized_path and normalized_path != f"c:\\windows\\system32\\{exe_name}":
            return None
        pid = getattr(self, "_system_pids", {}).get(system.hostname, {}).get(role)
        if pid is None or not self._is_pid_active_at(system, pid, time):
            return None
        return pid

    def _lookup_process_name(self, hostname: str, pid: int, os_category: str = "windows") -> str:
        """Look up the image path of a running process by PID.

        PID 4 is always the Windows System process (ntoskrnl.exe). Unknown
        Linux PIDs have no safe parent image: returning a shell there fabricates
        impossible eCAR parent relationships such as bash with ppid=4.
        """
        if pid == 4 and os_category == "windows":
            return r"C:\Windows\System32\ntoskrnl.exe"
        key = (hostname, pid)
        proc = self.state_manager.state.running_processes.get(key)
        if proc:
            return proc.image
        if os_category == "linux":
            return "-"
        return r"C:\Windows\explorer.exe"

    # Process names that can spawn child processes
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
    # GUI apps that users launch from Start Menu / desktop — always parent=explorer.exe
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
    _LINUX_SHELLS = {"/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/bash", "/usr/bin/zsh"}
    _LINUX_SERVICE_USERS = {"apache", "www-data", "nginx", "httpd"}
    _LINUX_SERVICE_PARENT_KEYS = ("apache2", "httpd", "nginx", "php-fpm")

    @staticmethod
    def _is_one_shot_shell_command(process_name: str, command_line: str) -> bool:
        """Return whether a shell command is a short-lived command wrapper."""
        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            return False
        return _windows_foreground_lifetime(process_name, command_line) is not None

    def _is_one_shot_shell_parent(self, system: System, pid: int) -> bool:
        """Return whether PID is a short-lived shell unsuitable as a later parent."""
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None:
            return False
        return self._is_one_shot_shell_command(proc.image, proc.command_line)

    def _is_bare_interactive_windows_shell(self, process_name: str, command_line: str) -> bool:
        """Return whether a shell is an interactive prompt rather than an inline command."""
        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            return False
        return not self._is_one_shot_shell_command(process_name, command_line)

    def _space_interactive_shell_child_launch(
        self,
        *,
        system: System,
        process_name: str,
        parent_pid: int,
        time: datetime,
    ) -> datetime:
        """Add human-scale dwell time before visible children of bare shells."""
        if _get_os_category(system.os) != "windows":
            return time
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if process_exe in self._WINDOWS_SHELL_NAMES or process_exe == "conhost.exe":
            return time
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None or parent_proc.start_time is None:
            return time
        if not self._is_bare_interactive_windows_shell(parent_proc.image, parent_proc.command_line):
            return time
        rng = random.Random(
            _stable_seed(
                f"interactive_shell_child_gap:{system.hostname}:{parent_pid}:"
                f"{process_exe}:{parent_proc.start_time.isoformat()}"
            )
        )
        minimum_child_time = parent_proc.start_time + timedelta(seconds=rng.uniform(8.0, 45.0))
        if time < minimum_child_time:
            return minimum_child_time
        return time

    def _windows_remote_command_owner_pid(
        self,
        *,
        system: System,
        time: datetime,
        child_exe: str,
        child_command_line: str,
    ) -> int:
        """Return a concrete service-family owner for a remote/admin shell."""
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        exe = child_exe.lower()
        command = child_command_line.lower()
        owner_keys: tuple[str, ...]

        if exe == "schtasks.exe" or "schtasks" in command:
            owner_keys = ("taskhostw", "svchost_local_system", "services")
        elif exe in {"wmic.exe", "wmic"} or "wmic " in command:
            owner_keys = ("wmiprvse", "svchost_dcom", "services")
        elif exe in {"sc.exe", "sc"} or "sc.exe create" in command or " sc create" in command:
            owner_keys = ("services", "svchost_dcom", "wmiprvse")
        elif exe in {"wevtutil.exe", "wevtutil", "net.exe", "net1.exe", "net", "net1"}:
            owner_keys = ("wmiprvse", "taskhostw", "services")
        elif "powershell" in command or "winrm" in command or "invoke-command" in command:
            owner_keys = ("wmiprvse", "svchost_dcom", "services")
        else:
            seed = _stable_seed(
                f"windows_remote_owner:{system.hostname}:{exe}:{child_command_line}"
            )
            owner_keys = (
                ("wmiprvse", "taskhostw", "services")
                if seed % 2
                else ("taskhostw", "wmiprvse", "services")
            )

        for key in owner_keys:
            pid = sys_pids.get(key)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        return sys_pids.get("services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4)))

    def _ensure_windows_service_shell_parent(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        child_exe: str,
        child_command_line: str = "",
    ) -> int | None:
        """Create a short-lived SYSTEM shell for service-context admin utilities."""
        if _get_os_category(system.os) != "windows":
            return None
        if child_exe not in self._WINDOWS_SERVICE_SHELL_CHILDREN:
            return None

        parent_pid = self._windows_remote_command_owner_pid(
            system=system,
            time=time,
            child_exe=child_exe,
            child_command_line=child_command_line,
        )
        shell_time = time - timedelta(
            milliseconds=120
            + (_stable_seed(f"windows-service-shell:{system.hostname}:{child_exe}:{time}") % 90)
        )
        session = self.state_manager.get_session(logon_id)
        if session is not None and shell_time <= session.start_time:
            shell_time = session.start_time + timedelta(milliseconds=40)
        if shell_time >= time:
            shell_time = time - timedelta(milliseconds=40)

        rendered_child = child_command_line.strip() or child_exe
        shell_command = f"C:\\Windows\\System32\\cmd.exe /c {rendered_child}"
        shell_pid = self.generate_process(
            user=user,
            system=system,
            time=shell_time,
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line=shell_command,
            parent_pid=parent_pid,
            ensure_file_event=False,
            from_storyline=True,
            suppress_command_file_effect=True,
            allow_existing_browser_reuse=False,
            allow_browser_launch_spacing=False,
        )
        self._record_user_process(system, user, shell_pid, r"C:\Windows\System32\cmd.exe")
        return shell_pid

    def _linux_anchor_pid(self, system: System, time: datetime) -> int:
        """Return a tracked Linux init/systemd process for parent-chain fallbacks."""
        sys_pids = getattr(self, "_system_pids", {}).setdefault(system.hostname, {})
        for role in ("systemd", "init"):
            pid = sys_pids.get(role)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_exe = proc.image.rsplit("/", 1)[-1].lower()
            if proc_exe in {"systemd", "init"} and proc.start_time <= time:
                sys_pids.setdefault("systemd", proc.pid)
                return proc.pid

        current_time = time - timedelta(minutes=5)
        self.state_manager.set_current_time(current_time)
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd",
            username="root",
            integrity_level="System",
            logon_id="",
        )
        sys_pids["systemd"] = pid
        return pid

    def _active_session_shell_pid(
        self,
        system: System,
        user: User,
        time: datetime | None,
        logon_id: str = "",
    ) -> int | None:
        """Return the actor's live per-session shell when one owns the command."""
        sessions = (
            self.state_manager.get_sessions_for_user_at(user.username, time)
            if time is not None
            else self.state_manager.get_sessions_for_user(user.username)
        )
        if logon_id:
            sessions = [sess for sess in sessions if sess.logon_id == logon_id]
        for sess in sessions:
            if sess.system != system.hostname or sess.session_shell_pid is None:
                continue
            if time is not None and not _session_active_for_activity(
                sess,
                time,
                margin_seconds=1.5,
            ):
                continue
            is_active = (
                self._is_pid_active_at(system, sess.session_shell_pid, time)
                if time is not None
                else self._is_pid_alive(system, sess.session_shell_pid)
            )
            if is_active:
                return sess.session_shell_pid
        return None

    def _linux_service_parent_pid(
        self,
        system: System,
        username: str,
        time: datetime,
        possible_parents: list[str] | None = None,
    ) -> int | None:
        """Return a live Linux service daemon parent for service-account commands."""
        if username not in self._LINUX_SERVICE_USERS:
            return None
        parent_names = {parent.lower() for parent in possible_parents or []}
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for key in self._LINUX_SERVICE_PARENT_KEYS:
            if parent_names and key not in parent_names:
                continue
            pid = sys_pids.get(key)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        return None

    def _is_pid_alive(self, system: System, pid: int) -> bool:
        """Check if a PID is still running in state manager."""
        return self.state_manager.get_process(system.hostname, pid) is not None

    def _is_pid_active_at(self, system: System, pid: int, time: datetime) -> bool:
        """Check whether a PID exists and has started by the requested time."""
        if pid == 4 and _get_os_category(system.os) == "windows":
            return True
        proc = self.state_manager.get_process(system.hostname, pid)
        return proc is not None and proc.start_time <= time

    def _is_valid_process_parent_at(
        self,
        *,
        system: System,
        parent_pid: int,
        time: datetime,
    ) -> bool:
        """Return whether a PID can be passed to StateManager.create_process()."""
        if parent_pid == 0:
            return True
        if parent_pid == 4 and _get_os_category(system.os) == "windows":
            return True
        return self._is_pid_active_at(system, parent_pid, time)

    def _prune_user_process_history(
        self,
        *,
        system: System,
        username: str,
        time: datetime,
        logon_id: str = "",
    ) -> list[tuple[int, str]]:
        """Drop ended process PIDs from recent parent-selection history."""
        key = (system.hostname, username)
        history = self._user_process_history.get(key, [])
        if not history:
            return []

        os_category = _get_os_category(system.os)
        pruned = [
            (pid, image)
            for pid, image in history
            if self._is_pid_active_at(system, pid, time)
            and self._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_category,
            )
        ]
        self._user_process_history[key] = pruned[-10:]
        return self._user_process_history[key]

    def _windows_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Windows service ancestry fallback for system processes."""
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for role in ("services", "svchost_netsvcs", "svchost_dcom", "wininit"):
            pid = sys_pids.get(role)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        return 4

    def _linux_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Linux service ancestry fallback for system processes."""
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for role in ("systemd", "init", "sshd", "bash"):
            pid = sys_pids.get(role)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        return self._linux_anchor_pid(system, time)

    def _repair_process_parent_pid(
        self,
        *,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Resolve a live parent PID before process state allocation."""
        os_category = _get_os_category(system.os)
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        user_context = process_username not in _SYSTEM_ACCOUNTS and not process_username.endswith(
            "$"
        )

        if os_category == "windows":
            if user_context:
                repair_user = self._user_model_for_username(process_username)
                if self._is_windows_same_exe_gui_child(process_name, command_line):
                    same_exe_parent = self._windows_same_exe_gui_parent_pid(
                        system=system,
                        user=repair_user,
                        time=time,
                        logon_id=logon_id,
                        process_name=process_name,
                        parent_pid=parent_pid,
                        process_username=process_username,
                    )
                    if (
                        same_exe_parent is not None
                        and self.state_manager.get_process(system.hostname, same_exe_parent)
                        is not None
                    ):
                        return same_exe_parent
                if self._is_valid_process_parent_at(
                    system=system,
                    parent_pid=parent_pid,
                    time=time,
                ):
                    return parent_pid
                if process_exe in self._WINDOWS_GUI_APPS or process_exe == "explorer.exe":
                    explorer_pid = self._ensure_session_explorer_pid(
                        system,
                        repair_user,
                        time,
                        logon_id,
                    )
                    if explorer_pid is not None and self._is_valid_process_parent_at(
                        system=system,
                        parent_pid=explorer_pid,
                        time=time,
                    ):
                        return explorer_pid
                resolved = self._resolve_parent(
                    system,
                    repair_user,
                    time,
                    logon_id,
                    process_name,
                    command_line,
                )
                if self._is_valid_process_parent_at(
                    system=system,
                    parent_pid=resolved,
                    time=time,
                ):
                    return resolved
            if self._is_valid_process_parent_at(system=system, parent_pid=parent_pid, time=time):
                return parent_pid
            return self._windows_system_parent_fallback(system, time)

        if user_context:
            repair_user = self._user_model_for_username(process_username)
            materialized_parent = self._materialize_visible_linux_shell_parent_for_child(
                system=system,
                time=time,
                logon_id=logon_id,
                parent_pid=parent_pid,
                process_username=process_username,
            )
            if materialized_parent != parent_pid and self._is_valid_process_parent_at(
                system=system, parent_pid=materialized_parent, time=time
            ):
                return materialized_parent
            if (
                materialized_parent != parent_pid
                and self.state_manager.get_process(system.hostname, materialized_parent) is not None
            ):
                return materialized_parent
            parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
            if parent_proc is not None and ensure_utc(parent_proc.start_time) > ensure_utc(time):
                return parent_pid
            if self._is_valid_process_parent_at(system=system, parent_pid=parent_pid, time=time):
                return parent_pid
            session_shell = self._active_session_shell_pid(system, repair_user, time, logon_id)
            if session_shell is not None:
                return session_shell
            resolved = self._resolve_parent(
                system,
                repair_user,
                time,
                logon_id,
                process_name,
                command_line,
            )
            if self._is_valid_process_parent_at(system=system, parent_pid=resolved, time=time):
                return resolved
        if self._is_valid_process_parent_at(system=system, parent_pid=parent_pid, time=time):
            return parent_pid
        return self._linux_system_parent_fallback(system, time)

    def _lookup_parent_image(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process image from StateManager, with fallback."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.image
        return "-"

    def _lookup_parent_command_line(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process command line from StateManager."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.command_line
        return "-"

    def _lookup_parent_start_time(self, hostname: str, parent_pid: int) -> datetime | None:
        """Look up parent process start time at event construction time."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        return proc.start_time if proc else None

    def _parent_process_matches_logon(
        self,
        *,
        hostname: str,
        parent_pid: int,
        logon_id: str,
        os_category: str,
    ) -> bool:
        """Return whether a parent process can source-native spawn this session's child."""
        if os_category != "windows" or not logon_id:
            return True
        parent_proc = self.state_manager.get_process(hostname, parent_pid)
        if parent_proc is None or not parent_proc.logon_id:
            if parent_proc is not None:
                parent_exe = parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if (
                    parent_exe == "explorer.exe"
                    and parent_proc.username not in _SYSTEM_ACCOUNTS
                    and not parent_proc.username.endswith("$")
                ):
                    return False
            return True
        if parent_proc.username in _SYSTEM_ACCOUNTS or parent_proc.username.endswith("$"):
            return True
        return parent_proc.logon_id == logon_id

    def _get_session_explorer_pid(
        self,
        system: System,
        user: User,
        time: datetime | None = None,
        logon_id: str = "",
    ) -> int | None:
        """Get the explorer.exe PID for the user's active interactive session.

        Returns None if no interactive session exists or explorer PID not set.
        """
        sessions = (
            self.state_manager.get_sessions_for_user_at(user.username, time)
            if time is not None
            else self.state_manager.get_sessions_for_user(user.username)
        )
        candidates = [
            session
            for session in sessions
            if session.system == system.hostname
            and session.explorer_pid is not None
            and (not logon_id or session.logon_id == logon_id)
        ]
        candidates.sort(key=lambda session: session.start_time, reverse=True)
        for session in candidates:
            if session.explorer_pid is None:
                continue
            if time is not None and not self._is_pid_active_at(system, session.explorer_pid, time):
                continue
            if self._is_pid_alive(system, session.explorer_pid):
                return session.explorer_pid
        return None

    def _ensure_session_explorer_pid(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
    ) -> int | None:
        """Return or create the per-session Explorer state for GUI children."""
        existing = self._get_session_explorer_pid(system, user, time=time, logon_id=logon_id)
        if existing is not None:
            return existing

        session = self.state_manager.get_session(logon_id)
        if session is None:
            return None
        if session.system != system.hostname or session.username != user.username:
            return None
        if session.logon_type in {3, 5} or session.session_kind in {"network", "service"}:
            return None

        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        parent_for_chain = None
        for candidate in ("smss", "wininit", "winlogon", "services"):
            pid = sys_pids.get(candidate)
            if pid and self._is_pid_active_at(system, pid, time):
                parent_for_chain = pid
                break
        if parent_for_chain is None:
            return None

        original_time = self.state_manager.state.current_time
        chain_time = max(session.start_time, time - timedelta(milliseconds=250))
        self.state_manager.set_current_time(chain_time)
        try:
            winlogon_pid = session.session_winlogon_pid
            if winlogon_pid is None or not self._is_pid_active_at(system, winlogon_pid, time):
                winlogon_pid = self.state_manager.create_process(
                    system.hostname,
                    parent_for_chain,
                    r"C:\Windows\System32\winlogon.exe",
                    "winlogon.exe",
                    "SYSTEM",
                    "System",
                    logon_id=logon_id,
                )
                session.session_winlogon_pid = winlogon_pid
                session.process_tree_root = winlogon_pid

            userinit_pid = self.state_manager.create_process(
                system.hostname,
                winlogon_pid,
                r"C:\Windows\System32\userinit.exe",
                "userinit.exe",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
            explorer_pid = self.state_manager.create_process(
                system.hostname,
                userinit_pid,
                r"C:\Windows\explorer.exe",
                "explorer.exe",
                user.username,
                "Medium",
                logon_id=logon_id,
            )
            session.explorer_pid = explorer_pid
            return explorer_pid
        finally:
            if original_time is not None:
                self.state_manager.set_current_time(original_time)

    def _windows_explorer_parent_pid(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str = "",
    ) -> int:
        """Return the Windows logon-chain parent for explorer.exe.

        Explorer is the interactive shell. It is created by userinit/winlogon,
        not by arbitrary user applications that happen to be alive in the same
        session.
        """
        sessions = self.state_manager.get_sessions_for_user_at(user.username, time)
        for session in sessions:
            if session.system != system.hostname:
                continue
            if logon_id and session.logon_id != logon_id:
                continue
            if session.explorer_pid is None:
                continue
            explorer = self.state_manager.get_process(system.hostname, session.explorer_pid)
            if explorer is None:
                continue
            parent_pid = explorer.parent_pid
            if parent_pid and self._is_pid_active_at(system, parent_pid, time):
                return parent_pid
            if session.session_winlogon_pid and self._is_pid_active_at(
                system, session.session_winlogon_pid, time
            ):
                return session.session_winlogon_pid

        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        for role in ("userinit", "winlogon", "services", "wininit"):
            pid = sys_pids.get(role)
            if pid and self._is_pid_active_at(system, pid, time):
                return pid
        return sys_pids.get("winlogon", sys_pids.get("services", 4))

    def _select_parent_pid(
        self,
        system: System,
        user: User,
        process_name: str,
        time: datetime | None = None,
        logon_id: str = "",
    ) -> int:
        """Select a realistic parent PID based on process type and history.

        Builds process trees with depth by tracking recent user processes.
        Windows GUI apps always spawn from explorer.exe.
        CLI/script processes can spawn from shells.
        Linux user processes typically spawn from login shells.

        Only returns PIDs that are still alive in the state manager.
        """
        rng = _get_rng()
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        os_cat = _get_os_category(system.os)
        history = self._prune_user_process_history(
            system=system,
            username=user.username,
            time=time or self.state_manager.state.current_time or datetime.now(UTC),
            logon_id=logon_id,
        )
        # Filter history to only include still-running processes
        alive_history = []
        for pid, name in history:
            if not self._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_cat,
            ):
                continue
            if time is not None:
                if self._is_pid_active_at(system, pid, time):
                    alive_history.append((pid, name))
            elif self._is_pid_alive(system, pid):
                alive_history.append((pid, name))

        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
            effective_time = time or self.state_manager.state.current_time

            # Check if the user's active session on this system is a network
            # logon (type 3). Network logons never spawn explorer.exe — processes
            # are parented by svchost.exe or services.exe instead.
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if logon_id and sessions:
                active_session = next(
                    (s for s in sessions if s.system == system.hostname and s.logon_id == logon_id),
                    None,
                )
            else:
                active_session = (
                    next((s for s in sessions if s.system == system.hostname), None)
                    if sessions
                    else None
                )
            is_network_logon = active_session and active_session.logon_type == 3
            is_service_logon = active_session and active_session.logon_type == 5

            if is_network_logon:
                # Network logon: parent is services.exe or svchost.exe
                # (processes arrive via PsExec, WMI, or SMB)
                # CLI/script processes: check for a running shell as parent first
                shells = [
                    (pid, name)
                    for pid, name in alive_history
                    if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SHELL_NAMES
                    and not self._is_one_shot_shell_parent(system, pid)
                ]
                if shells and rng.random() < 0.6:
                    return shells[-1][0]
                return sys_pids.get(
                    "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            if is_service_logon:
                if exe_name in self._WINDOWS_SHELLS:
                    return sys_pids.get(
                        "svchost_netsvcs",
                        sys_pids.get("svchost_dcom", sys_pids.get("services", 4)),
                    )
                return sys_pids.get(
                    "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )

            if exe_name == "explorer.exe":
                return self._windows_explorer_parent_pid(
                    system, user, effective_time, active_session.logon_id if active_session else ""
                )

            # Prefer session-specific explorer PID over system-wide default
            session_explorer = self._ensure_session_explorer_pid(
                system, user, time=time, logon_id=logon_id
            )
            fallback_explorer = sys_pids.get("explorer")
            if fallback_explorer:
                fallback_proc = self.state_manager.get_process(system.hostname, fallback_explorer)
                fallback_exe = (
                    fallback_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                    if fallback_proc is not None
                    else ""
                )
                if fallback_exe != "explorer.exe" or not self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=fallback_explorer,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    fallback_explorer = None
            explorer_pid = (
                session_explorer
                or fallback_explorer
                or sys_pids.get("winlogon", sys_pids.get("services", 4))
            )

            # Shells and terminals spawn from explorer.exe
            if exe_name in self._WINDOWS_SHELLS:
                return explorer_pid

            # GUI apps always spawn from explorer.exe (user launches via Start Menu/desktop)
            if exe_name in self._WINDOWS_GUI_APPS:
                return explorer_pid

            # CLI/script processes: check for a running shell as parent
            shells = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SHELL_NAMES
                and not self._is_one_shot_shell_parent(system, pid)
            ]
            if shells and rng.random() < 0.6:
                return shells[-1][0]

            # Check for a browser/app that could spawn this process (e.g. download+run)
            spawners = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in self._WINDOWS_SPAWNERS
            ]
            if spawners and rng.random() < 0.3:
                return spawners[-1][0]

            # Default: session-specific or system-wide explorer.exe
            return explorer_pid
        else:
            # Linux: most user commands spawn from a shell
            session_shell_pid = self._active_session_shell_pid(system, user, time)
            if session_shell_pid is not None:
                return session_shell_pid
            shells = [(pid, name) for pid, name in alive_history if name in self._LINUX_SHELLS]
            if shells:
                return shells[-1][0]
            return sys_pids.get("bash", sys_pids.get("sshd", 1))

    def _resolve_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str = "",
    ) -> int:
        """Resolve the parent PID for a process using spawn rules.

        Transparently finds an existing valid parent or auto-creates the
        parent chain (with realistic timing) using the spawn rules YAML.
        Falls back to the legacy _select_parent_pid() for unknown processes.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        os_cat = _get_os_category(system.os)
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})

        # Extract basename for rule lookup
        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
        else:
            exe_name = (
                process_name.rsplit("/", 1)[-1].lower()
                if "/" in process_name
                else process_name.lower()
            )

        # Special override: SYSTEM user or network logon → svchost (not services.exe directly)
        # Real Windows: services.exe → svchost.exe → cmd.exe (never services.exe → cmd.exe)
        _SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe"}
        is_shell = exe_name in _SHELLS
        remote_wrapper_pid = self._active_remote_execution_wrapper_pid(system, time)
        if user.username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            if remote_wrapper_pid is not None:
                return remote_wrapper_pid
            if is_shell:
                # Shells get svchost as parent (realistic: service host spawns shell)
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        sessions = self.state_manager.get_sessions_for_user_at(user.username, time)
        # Match by logon_id when available to avoid picking the wrong session
        # when a user has both interactive (type 2) and network (type 3) sessions
        # on the same host.
        if logon_id and sessions:
            active_session = next(
                (s for s in sessions if s.system == system.hostname and s.logon_id == logon_id),
                None,
            )
        else:
            active_session = (
                next((s for s in sessions if s.system == system.hostname), None)
                if sessions
                else None
            )
        is_network_logon = active_session and active_session.logon_type == 3
        is_service_logon = active_session and active_session.logon_type == 5
        if is_network_logon:
            if remote_wrapper_pid is not None:
                return remote_wrapper_pid
            history = self._prune_user_process_history(
                system=system,
                username=user.username,
                time=time,
                logon_id=logon_id,
            )
            remote_wrappers = []
            shells = []
            for pid, name in history:
                if not self._is_pid_active_at(system, pid, time):
                    continue
                if not self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                hist_exe = (
                    name.rsplit("\\", 1)[-1].lower()
                    if "\\" in name
                    else name.rsplit("/", 1)[-1].lower()
                )
                if hist_exe in {"psexesvc.exe", "wmiprvse.exe", "healthmonitorsvc.exe"}:
                    remote_wrappers.append(pid)
                elif hist_exe in self._WINDOWS_SHELL_NAMES and not (
                    self._is_one_shot_shell_parent(system, pid)
                ):
                    shells.append(pid)
            if remote_wrappers:
                return remote_wrappers[-1]
            if shells:
                return shells[-1]
            if is_shell:
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )
        if is_service_logon:
            if is_shell:
                return sys_pids.get(
                    "svchost_netsvcs",
                    sys_pids.get("svchost_dcom", sys_pids.get("services", 4)),
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        if os_cat == "windows" and exe_name == "explorer.exe":
            return self._windows_explorer_parent_pid(system, user, time, logon_id)

        # Look up valid parents from spawn rules
        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        possible_parents = reverse.get(exe_name, [])
        if os_cat == "linux":
            service_parent = self._linux_service_parent_pid(
                system, user.username, time, possible_parents
            )
            if service_parent is not None:
                return service_parent
            shell_parent_allowed = not possible_parents or any(
                parent in {"bash", "sh", "zsh"} for parent in possible_parents
            )
            if shell_parent_allowed:
                if active_session is not None:
                    session_shell_pid = self.ensure_linux_session_shell(
                        user=user,
                        target_system=system,
                        logon_id=active_session.logon_id,
                        logon_time=active_session.start_time,
                        activity_time=time,
                    )
                    if session_shell_pid is not None:
                        return session_shell_pid
                visible_shell_pid = self.ensure_linux_visible_shell_parent(
                    user=user,
                    target_system=system,
                    activity_time=time,
                    logon_id=logon_id,
                    logon_time=active_session.start_time if active_session is not None else None,
                )
                if visible_shell_pid is not None:
                    return visible_shell_pid
            session_shell_pid = self._active_session_shell_pid(system, user, time, logon_id)
            if session_shell_pid is not None and any(
                parent in {"bash", "sh", "zsh"} for parent in possible_parents
            ):
                return session_shell_pid

        if not possible_parents:
            # No rules for this exe — fall back to legacy logic
            return self._select_parent_pid(system, user, process_name, time=time, logon_id=logon_id)

        # Check alive_history for a matching parent
        history = self._prune_user_process_history(
            system=system,
            username=user.username,
            time=time,
            logon_id=logon_id,
        )
        alive_parents = []
        for pid, name in history:
            if not self._is_pid_active_at(system, pid, time):
                continue
            if not self._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_cat,
            ):
                continue
            hist_exe = (
                name.rsplit("\\", 1)[-1].lower()
                if "\\" in name
                else name.rsplit("/", 1)[-1].lower()
            )
            if (
                os_cat == "windows"
                and hist_exe in self._WINDOWS_SHELL_NAMES
                and self._is_one_shot_shell_parent(system, pid)
            ):
                continue
            if hist_exe in possible_parents:
                alive_parents.append((pid, name))

        # Also check seeded system processes as potential parents
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc and proc.start_time <= time:
                if not self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe in possible_parents:
                    alive_parents.append((pid, proc.image))

        if alive_parents:
            # Deduplicate by PID
            seen = set()
            unique = []
            for pid, name in alive_parents:
                if pid not in seen:
                    seen.add(pid)
                    unique.append((pid, name))
            return rng.choice(unique)[0]

        # No valid parent alive — auto-create the chain
        return self._ensure_parent_chain(system, user, time, logon_id, exe_name, os_cat, depth=0)

    def _active_remote_execution_wrapper_pid(self, system: System, time: datetime) -> int | None:
        """Return a live explicit remote-execution service wrapper, if one exists."""
        wrappers = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if exe not in {"psexesvc.exe", "healthmonitorsvc.exe"}:
                continue
            if not self._is_pid_active_at(system, proc.pid, time):
                continue
            wrappers.append(proc)
        if not wrappers:
            return None
        wrappers.sort(key=lambda proc: proc.start_time or time)
        return wrappers[-1].pid

    def _sanitize_user_parent_pid(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Prevent user-context processes from being parented by impossible fallbacks."""
        os_category = _get_os_category(system.os)
        if os_category not in {"windows", "linux"}:
            return parent_pid
        if process_username in _SYSTEM_ACCOUNTS or process_username.endswith("$"):
            return parent_pid
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        parent_image = (parent_proc.image if parent_proc is not None else "").lower()
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        session = self.state_manager.get_session(logon_id)
        if (
            os_category == "windows"
            and session is not None
            and session.logon_type == 5
            and parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] == "explorer.exe"
        ):
            sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
            if process_exe in self._WINDOWS_SHELLS:
                return sys_pids.get(
                    "svchost_netsvcs",
                    sys_pids.get("svchost_dcom", sys_pids.get("services", parent_pid)),
                )
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", parent_pid))
            )
        is_browser_child = process_exe in _WINDOWS_BROWSER_EXES and not (
            self._is_top_level_browser_launch(process_name, command_line)
        )
        is_same_exe_gui_child = self._is_windows_same_exe_gui_child(
            process_name,
            command_line,
        )
        if os_category == "windows" and process_exe == "explorer.exe":
            return self._windows_explorer_parent_pid(system, user, time, logon_id)

        if os_category == "windows":
            if is_same_exe_gui_child:
                same_exe_parent = self._windows_same_exe_gui_parent_pid(
                    system=system,
                    user=user,
                    time=time,
                    logon_id=logon_id,
                    process_name=process_name,
                    parent_pid=parent_pid,
                    process_username=process_username,
                )
                if same_exe_parent is not None:
                    return same_exe_parent
            if process_exe in self._WINDOWS_GUI_APPS and not is_browser_child:
                explorer_pid = self._ensure_session_explorer_pid(system, user, time, logon_id)
                if explorer_pid is not None:
                    return explorer_pid
            if (
                parent_pid != 4
                and parent_image not in {"system", "ntoskrnl.exe"}
                and parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                not in {"winlogon.exe", "userinit.exe"}
                and self._is_pid_active_at(system, parent_pid, time)
                and self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=parent_pid,
                    logon_id=logon_id,
                    os_category=os_category,
                )
                and not self._is_one_shot_shell_parent(system, parent_pid)
            ):
                return parent_pid
        elif parent_proc is not None and self._is_pid_active_at(system, parent_pid, time):
            parent_exe = parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if parent_exe in {"bash", "sh", "zsh"}:
                session = self.state_manager.get_session(logon_id)
                if session is not None:
                    session_shell_pid = self.ensure_linux_session_shell(
                        user=self._user_model_for_username(process_username),
                        target_system=system,
                        logon_id=logon_id,
                        logon_time=session.start_time,
                        activity_time=time,
                    )
                    if session_shell_pid is not None:
                        return session_shell_pid
                visible_shell_pid = self.ensure_linux_visible_shell_parent(
                    user=self._user_model_for_username(process_username),
                    target_system=system,
                    activity_time=time,
                    logon_id=logon_id,
                    logon_time=session.start_time if session is not None else None,
                )
                if visible_shell_pid is not None:
                    return visible_shell_pid
            return parent_pid

        resolved = self._resolve_parent(system, user, time, logon_id, process_name)
        resolved_proc = self.state_manager.get_process(system.hostname, resolved)
        resolved_image = (resolved_proc.image if resolved_proc is not None else "").lower()
        if os_category == "windows":
            if (
                resolved != 4
                and resolved_image not in {"system", "ntoskrnl.exe"}
                and self._is_pid_active_at(system, resolved, time)
            ):
                return resolved
        elif resolved_proc is not None and self._is_pid_active_at(system, resolved, time):
            return resolved

        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})
        if os_category == "linux":
            for role in ("bash", "sshd", "systemd"):
                candidate = sys_pids.get(role)
                if candidate and self._is_pid_active_at(system, candidate, time):
                    return candidate
            return parent_pid
        for role in ("explorer", "winlogon", "services", "svchost_dcom"):
            candidate = sys_pids.get(role)
            candidate_proc = self.state_manager.get_process(system.hostname, candidate or -1)
            candidate_exe = (
                candidate_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if candidate_proc is not None
                else ""
            )
            if process_exe in self._WINDOWS_GUI_APPS and candidate_exe != "explorer.exe":
                continue
            if (
                candidate
                and candidate != 4
                and self._is_pid_active_at(system, candidate, time)
                and self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=candidate,
                    logon_id=logon_id,
                    os_category=os_category,
                )
            ):
                return candidate
        return parent_pid

    def _materialize_visible_linux_shell_parent_for_child(
        self,
        *,
        system: System,
        time: datetime,
        logon_id: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Ensure post-window Linux shell parents are source-visible."""
        if _get_os_category(system.os) != "linux":
            return parent_pid
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None or not self._is_pid_active_at(system, parent_pid, time):
            return parent_pid

        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if parent_exe not in {"bash", "sh", "zsh"}:
            return parent_pid

        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is None:
            return parent_pid
        scenario_start = ensure_utc(scenario_start)
        activity_time = ensure_utc(time)
        if activity_time < scenario_start:
            return parent_pid
        if ensure_utc(parent_proc.start_time) >= scenario_start:
            return parent_pid

        user = self._user_model_for_username(process_username)
        session = self.state_manager.get_session(logon_id)
        if session is not None:
            session_shell_pid = self.ensure_linux_session_shell(
                user=user,
                target_system=system,
                logon_id=logon_id,
                logon_time=session.start_time,
                activity_time=activity_time,
            )
            if session_shell_pid is not None:
                return session_shell_pid

        visible_shell_pid = self.ensure_linux_visible_shell_parent(
            user=user,
            target_system=system,
            activity_time=activity_time,
            logon_id=logon_id,
            logon_time=session.start_time if session is not None else None,
        )
        return visible_shell_pid if visible_shell_pid is not None else parent_pid

    def _is_windows_same_exe_gui_child(self, process_name: str, command_line: str) -> bool:
        """Return whether a Windows GUI command should be parented by its own executable."""
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        command = f" {command_line.lower()} "
        if process_exe in _WINDOWS_BROWSER_EXES:
            return not self._is_top_level_browser_launch(process_name, command_line)
        if process_exe in _WINDOWS_ELECTRON_CHILD_EXES:
            return any(marker in command for marker in _WINDOWS_ELECTRON_CHILD_MARKERS)
        return False

    def _windows_same_exe_gui_parent_pid(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        parent_pid: int,
        process_username: str,
    ) -> int | None:
        """Return or create a same-family parent for browser/Electron child processes."""
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if (
            parent_proc is not None
            and parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() == process_exe
            and not self._is_windows_same_exe_gui_child(parent_proc.image, parent_proc.command_line)
            and self._is_pid_active_at(system, parent_pid, time)
            and self._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=parent_pid,
                logon_id=logon_id,
                os_category="windows",
            )
        ):
            return parent_pid

        candidates = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if proc_exe != process_exe:
                continue
            if self._is_windows_same_exe_gui_child(proc.image, proc.command_line):
                continue
            if proc.username != process_username:
                continue
            if proc.logon_id and proc.logon_id != logon_id:
                continue
            if not self._is_pid_active_at(system, proc.pid, time):
                continue
            candidates.append(proc)
        if candidates:
            return max(candidates, key=lambda candidate: candidate.start_time or time).pid

        from evidenceforge.generation.activity.application_catalog import resolve_image_path
        from evidenceforge.generation.activity.spawn_rules import get_parent_config

        parent_time = time - timedelta(
            milliseconds=150
            + (_stable_seed(f"same_exe_gui_parent:{system.hostname}:{process_exe}:{time}") % 850)
        )
        session = self.state_manager.get_session(logon_id)
        if session is not None and parent_time <= session.start_time:
            parent_time = session.start_time + timedelta(milliseconds=120)

        explorer_pid = self._ensure_session_explorer_pid(system, user, parent_time, logon_id)
        if explorer_pid is None:
            return None

        config = get_parent_config("windows", process_exe)
        templates = config.get("command_templates", [])
        parent_command = templates[0] if templates else ""
        parent_command = parent_command.replace("{username}", user.username)
        parent_image = resolve_image_path(process_exe, "windows", username=user.username)
        if not parent_image:
            parent_image = _extract_image_from_command(parent_command) or process_name
        parent_image = parent_image.replace("{username}", user.username)
        if not parent_command:
            parent_command = f'"{parent_image}"'

        return self.generate_process(
            user=user,
            system=system,
            time=parent_time,
            logon_id=logon_id,
            process_name=parent_image,
            command_line=parent_command,
            parent_pid=explorer_pid,
            allow_existing_browser_reuse=False,
        )

    def _ensure_parent_chain(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        child_exe: str,
        os_cat: str,
        depth: int = 0,
    ) -> int:
        """Recursively create parent processes needed for child_exe.

        Builds the chain up to the nearest seeded system process (explorer,
        services, sshd, systemd). Depth-limited to 3 to prevent infinite
        recursion.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_parent_config,
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        sys_pids = getattr(self, "_system_pids", {}).get(system.hostname, {})

        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        # Safety limit
        if depth > 3:
            if os_cat == "windows":
                session_explorer = self._ensure_session_explorer_pid(
                    system, user, time=time, logon_id=logon_id
                )
                if session_explorer is not None:
                    return session_explorer
                return sys_pids.get("services", sys_pids.get("wininit", 4))
            return (
                sys_pids.get("bash") or sys_pids.get("sshd") or self._linux_anchor_pid(system, time)
            )

        # Pick a parent for child_exe from the rules
        possible_parents = reverse.get(child_exe, [])
        if not possible_parents:
            if os_cat == "windows":
                session_explorer = self._ensure_session_explorer_pid(
                    system, user, time=time, logon_id=logon_id
                )
                if session_explorer is not None:
                    return session_explorer
                return sys_pids.get("services", sys_pids.get("wininit", 4))
            return (
                sys_pids.get("bash") or sys_pids.get("sshd") or self._linux_anchor_pid(system, time)
            )

        # Auto-created parent chains should not fabricate a fresh parent with
        # the same executable as the child when another valid parent exists.
        # Existing same-exe parents are still honored in _resolve_parent().
        child_exe_lower = child_exe.lower()
        nonself_parents = [
            parent for parent in possible_parents if parent.lower() != child_exe_lower
        ]
        if nonself_parents:
            possible_parents = nonself_parents

        if (
            os_cat == "windows"
            and child_exe_lower in {"cmd.exe", "powershell.exe", "pwsh.exe"}
            and "explorer.exe" in {parent.lower() for parent in possible_parents}
        ):
            possible_parents = ["explorer.exe"]

        # Fresh CLI parent chains should start from a shell when the rules
        # allow it. Existing IDE/editor parents are still honored in
        # _resolve_parent(), but auto-creating a new Code.exe just to launch a
        # command-line tool looks less like a normal interactive session.
        if os_cat == "windows":
            shell_parents = [
                parent
                for parent in possible_parents
                if parent.lower() in {"cmd.exe", "powershell.exe", "pwsh.exe"}
            ]
            if shell_parents:
                possible_parents = shell_parents

        # Prefer shells for CLI tools on Windows, sshd→bash for Linux
        chosen_parent = rng.choice(possible_parents)
        if os_cat == "windows" and chosen_parent.lower() == "explorer.exe":
            session_explorer = self._ensure_session_explorer_pid(
                system, user, time=time, logon_id=logon_id
            )
            if session_explorer is not None:
                return session_explorer

        # Check if chosen parent is already a seeded system process
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc and proc.start_time <= time:
                if not self._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe == chosen_parent:
                    return pid

        # Not a seeded process — need to create it, but first ensure ITS parent
        grandparent_pid = self._ensure_parent_chain(
            system, user, time, logon_id, chosen_parent, os_cat, depth=depth + 1
        )

        # Get command template for the parent we're creating
        config = get_parent_config(os_cat, chosen_parent)
        cmd_templates = config.get("command_templates", [chosen_parent])
        cmd_line = rng.choice(cmd_templates)

        # Derive image path from command_templates (which have correct full paths)
        # rather than blindly prefixing C:\Windows\System32\
        image = None
        from evidenceforge.generation.activity.application_catalog import resolve_image_path

        if os_cat == "windows":
            for tmpl in cmd_templates:
                if "\\" in tmpl:
                    image = _extract_image_from_command(tmpl)
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "windows", username=user.username)
        else:
            for tmpl in cmd_templates:
                if "/" in tmpl:
                    image = _extract_image_from_command(tmpl)
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "linux")
                if chosen_parent in ("bash", "sh", "zsh"):
                    image = f"/bin/{chosen_parent}"

        # Timing: parent is created before child
        spawn_delay = config.get("spawn_delay", [0.5, 3.0])
        delay_sec = rng.uniform(spawn_delay[0], spawn_delay[1])
        parent_time = time - timedelta(seconds=delay_sec * (depth + 1))
        session = self.state_manager.get_session(logon_id)
        if session is not None and parent_time <= session.start_time:
            parent_time = session.start_time + timedelta(milliseconds=10 * (4 - depth))

        # Create the parent process
        self.state_manager.set_current_time(parent_time)
        parent_pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=grandparent_pid,
            image=image,
            command_line=cmd_line,
            username=user.username,
            integrity_level="System" if user.username == "SYSTEM" else "Medium",
            logon_id=logon_id,
        )

        # Determine if this is a pre-existing process (no creation event)
        # Long-lived parents early in the scenario were "already running"
        lifetime = config.get("lifetime", "long")
        scenario_start = getattr(self, "_scenario_start_time", None)
        is_pre_existing = False
        if lifetime == "long" and scenario_start:
            elapsed = (time - scenario_start).total_seconds()
            if elapsed < 1800 and rng.random() < 0.7:  # First 30 min, 70% chance
                is_pre_existing = True
        # Parents created before the output window are always pre-existing
        # (their creation events would be suppressed by the warm-up filter anyway)
        if not is_pre_existing and scenario_start and parent_time < scenario_start:
            is_pre_existing = True

        if not is_pre_existing:
            # Emit a process creation event
            from evidenceforge.events.base import SecurityEvent

            proc_obj_id = self.state_manager.get_process_object_id(system.hostname, parent_pid)
            actor_obj_id = self.state_manager.get_process_object_id(
                system.hostname,
                grandparent_pid,
            )

            event = SecurityEvent(
                timestamp=parent_time,
                event_type="process_create",
                src_host=self._build_host_context(system),
                auth=AuthContext(
                    username=user.username,
                    user_sid=self._get_sid(user.username),
                    logon_id=logon_id,
                ),
                process=ProcessContext(
                    pid=parent_pid,
                    parent_pid=grandparent_pid,
                    image=image,
                    command_line=cmd_line,
                    username=user.username,
                    integrity_level="Medium",
                    logon_id=logon_id,
                    parent_image=self._lookup_process_name(
                        system.hostname, grandparent_pid, _get_os_category(system.os)
                    ),
                    parent_command_line=self._lookup_parent_command_line(
                        system.hostname, grandparent_pid
                    ),
                    parent_start_time=self._lookup_parent_start_time(
                        system.hostname, grandparent_pid
                    ),
                    token_elevation="%%1938",
                    mandatory_label="S-1-16-8192",
                    start_time=self._lookup_parent_start_time(system.hostname, parent_pid),
                ),
                edr=EdrContext(object_id=proc_obj_id, actor_id=actor_obj_id),
            )
            self.dispatcher.dispatch(event)

        # Record in user process history
        self._record_user_process(system, user, parent_pid, image)
        return parent_pid

    def _record_user_process(self, system: System, user: User, pid: int, process_name: str) -> None:
        """Record a user process in history for future parent selection."""
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is not None:
            process_name = proc.image
        key = (system.hostname, user.username)
        self._user_process_history.setdefault(key, []).append((pid, process_name))
        # Keep only last 10 processes per user/system
        if len(self._user_process_history[key]) > 10:
            self._user_process_history[key] = self._user_process_history[key][-10:]

    def _os_for_ip(self, ip: str) -> str:
        """Look up OS category for an IP address. Defaults to 'windows'."""
        if hasattr(self, "_ip_to_system") and ip in self._ip_to_system:
            return _get_os_category(self._ip_to_system[ip].os)
        return "windows"

    def _get_sid(self, username: str) -> str:
        """Look up Windows SID for a username.

        For unknown principals (stale accounts, attacker-created accounts),
        generates a deterministic synthetic SID using the domain prefix from
        the existing registry and a stable RID derived from the username.

        Args:
            username: Username to look up

        Returns:
            SID string — from registry, well-known, or deterministic synthetic
        """
        if username in self.sid_registry:
            return self.sid_registry[username]
        if username in self._WELL_KNOWN_SIDS:
            return self._WELL_KNOWN_SIDS[username]
        # Generate deterministic synthetic SID for unknown principals.
        # Allocate from max existing RID + offset (not hardcoded 7000 range)
        # to avoid unrealistic gaps in the RID sequence.
        if not hasattr(self, "_domain_sid_prefix"):
            self._domain_sid_prefix: str | None = None
            self._max_rid: int = 1100
            for sid in self.sid_registry.values():
                if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                    self._domain_sid_prefix = "-".join(sid.split("-")[:7])
                    try:
                        rid_val = int(sid.rsplit("-", 1)[1])
                        if rid_val > self._max_rid:
                            self._max_rid = rid_val
                    except ValueError:
                        pass
        if self._domain_sid_prefix:
            from evidenceforge.utils.rng import _stable_seed

            rid = self._max_rid + 1 + (_stable_seed(f"unknown_sid_{username}") % 50)
            self._max_rid = max(self._max_rid, rid)
            synthetic = f"{self._domain_sid_prefix}-{rid}"
            self.sid_registry[username] = synthetic  # Cache for consistency
            return synthetic
        return "S-1-0-0"

    # Phase 5.2: EDR object type diversity data pools
    # EDR file/registry/DLL pools moved to edr_pools.yaml (data-driven config).
    # Access via: from evidenceforge.generation.activity.edr_pools import get_file_paths, etc.

    # _emit_ecar_file_event and _emit_ecar_registry_event removed in Phase 8.2
    # FILE/REGISTRY events now dispatched via SecurityEvent canonical model

    # _emit_ecar_flow_event removed in Phase 8.1 — eCAR FLOW now dispatched
    # via SecurityEvent "connection" type through the canonical event model

    # _emit_ecar_module_event removed in Phase 8.2
    # MODULE events now dispatched via SecurityEvent canonical model
