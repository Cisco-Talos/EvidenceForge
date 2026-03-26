"""Composable context dataclasses for the canonical event model.

Each context represents a domain-specific facet of a security event.
ActivityGenerator populates contexts; emitters and StateManager read from them.
All use @dataclass(slots=True) for memory efficiency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class HostContext:
    """The system where this event occurs."""

    hostname: str
    ip: str
    os: str  # e.g., "Windows Server 2019", "Ubuntu 22.04"
    os_category: str  # "windows" | "linux"
    system_type: str  # "workstation" | "server" | "domain_controller"
    domain: str = ""
    fqdn: str = ""  # Precomputed: hostname.domain (Windows Computer field)
    netbios_domain: str = ""  # Precomputed: domain.split('.')[0].upper()


@dataclass(slots=True)
class AuthContext:
    """Authentication/session details."""

    username: str
    full_name: str = ""
    user_sid: str = ""
    logon_id: str = ""  # Allocated by StateManager.create_session()
    logon_type: int = 2
    auth_package: str = "Negotiate"
    result: str = "success"  # "success" | "failure"
    failure_reason: str = ""  # Windows FailureReason (%%2313, %%2304, %%2307)
    failure_status: str = ""  # Windows Status (0xc000006d)
    failure_substatus: str = ""  # Windows SubStatus (0xc000006a, 0xc0000064, etc.)
    source_ip: str = ""
    source_port: int = 0
    elevated: bool = False
    logon_process: str = ""  # LogonProcessName (User32, Kerberos, NtLmSsp)
    lm_package: str = ""  # LmPackageName (-, NTLM V2)
    logon_guid: str = ""  # LogonGuid ({uuid} or null GUID)
    subject_sid: str = ""  # SubjectUserSid (usually SYSTEM S-1-5-18)
    subject_username: str = ""  # SubjectUserName (usually SYSTEM)
    subject_domain: str = ""  # SubjectDomainName (usually NT AUTHORITY)
    subject_logon_id: str = ""  # SubjectLogonId (usually 0x3e7)
    reporting_pid: int = 0  # PID of the process reporting this event (e.g., lsass for logons)
    target_server: str = ""  # 4648 TargetServerName (e.g., "fileserver01", "localhost")
    process_name: str = ""  # 4648 ProcessName (process using explicit creds)


@dataclass(slots=True)
class ProcessContext:
    """Process creation/termination details."""

    pid: int  # Allocated by StateManager.create_process()
    parent_pid: int
    image: str  # Full path
    command_line: str
    username: str
    integrity_level: str = "Medium"
    logon_id: str = ""  # For 4688/4689 SubjectLogonId + TargetLogonId
    parent_image: str = ""  # ParentProcessName (4688)
    token_elevation: str = ""  # TokenElevationType (%%1936/%%1938)
    mandatory_label: str = ""  # MandatoryLabel SID


@dataclass(slots=True)
class NetworkContext:
    """Network connection details -- shared across Zeek, eCAR, Snort."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp"
    service: str = ""
    zeek_uid: str = ""  # From StateManager.open_connection()
    conn_id: str = ""  # From StateManager.open_connection()
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_ip_bytes: int | None = None
    resp_ip_bytes: int | None = None
    conn_state: str = ""
    history: str = ""
    local_orig: bool = True
    local_resp: bool = False
    ip_proto: int = 6  # TCP=6, UDP=17, ICMP=1
    missed_bytes: int = 0
    initiating_pid: int = -1  # PID of process that opened this connection (-1 = unknown)


@dataclass(slots=True)
class DnsContext:
    """DNS query/response details for Zeek dns.log fan-out."""

    query: str
    query_type: str = "A"  # qtype_name: "A", "AAAA", "PTR", "CNAME", "SOA", "SRV", "MX"
    response_ip: str = ""
    rcode: str = "NOERROR"  # rcode_name: "NOERROR", "NXDOMAIN", "SERVFAIL"

    # Zeek dns.log fields
    trans_id: int = 0
    qclass: int = 1
    qclass_name: str = "C_INTERNET"
    qtype: int = 1  # Numeric: 1=A, 28=AAAA, 12=PTR, 5=CNAME, 6=SOA, 33=SRV, 15=MX
    rcode_num: int = 0  # Numeric: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN
    answers: list[str] = field(default_factory=list)
    TTLs: list[float] = field(default_factory=list)
    AA: bool = False
    TC: bool = False
    RD: bool = True
    RA: bool = True
    rejected: bool = False
    rtt: float | None = None
    opcode: int = 0
    opcode_name: str = "query"
    Z: int = 0


@dataclass(slots=True)
class FileContext:
    """File operation details."""

    path: str
    action: str  # "create" | "modify" | "delete" | "read"
    pid: int = 0


@dataclass(slots=True)
class RegistryContext:
    """Windows registry operation details."""

    key: str
    value: str = ""
    action: str = ""  # "create" | "modify" | "delete"
    pid: int = 0


@dataclass(slots=True)
class IdsContext:
    """IDS/IPS alert details for Snort."""

    sid: int
    message: str
    classification: str
    priority: int = 2


@dataclass(slots=True)
class SyslogContext:
    """Syslog message fields for Linux system/daemon/kernel logs.

    Used by the syslog emitter to render syslog-format log entries.
    Callers provide the exact app_name, message, facility, and severity.
    """

    app_name: str  # "sshd", "kernel", "systemd", "snapd", etc.
    message: str  # The syslog message body
    pid: int | None = None  # None for kernel messages
    facility: int = 3  # 3=daemon, 0=kernel, 10=auth/security
    severity: int = 6  # 6=info, 5=notice, 4=warning


@dataclass(slots=True)
class WeirdContext:
    """Zeek weird.log anomaly details."""

    name: str  # e.g., "truncated_header", "bad_TCP_checksum"
    notice: bool = False
    peer: str = ""
    source: str = "TCP"  # "TCP", "UDP"


@dataclass(slots=True)
class KerberosContext:
    """Kerberos protocol details for DC events (4768 TGT, 4769 service ticket)."""

    target_username: str
    target_domain: str
    target_sid: str = ""
    service_name: str = ""  # "krbtgt" for TGT, SPN for service ticket
    service_sid: str = ""
    ticket_options: str = ""
    ticket_status: str = "0x0"
    encryption_type: str = ""  # e.g., "0x12" (AES-256)
    pre_auth_type: int = 0  # 4768 only
    source_ip: str = ""  # IPv6-mapped: "::ffff:x.x.x.x"
    source_port: int = 0
    reporting_pid: int = 0  # PID of lsass.exe that wrote this event


@dataclass(slots=True)
class ServiceContext:
    """Windows service installation details (4697)."""

    service_name: str
    service_file_name: str  # Full command line / binary path
    service_type: str = "0x10"  # 0x10=Own Process, 0x20=Share Process
    service_start_type: str = "2"  # 2=Auto, 3=Manual, 4=Disabled
    service_account: str = "LocalSystem"


@dataclass(slots=True)
class ScheduledTaskContext:
    """Windows scheduled task details (4698/4699/4700/4701)."""

    task_name: str  # e.g., "\MyTask"
    task_content: str = ""  # XML task definition (HTML-escaped in output)


@dataclass(slots=True)
class GroupMembershipContext:
    """Windows group membership change details (4728/4729/4732/4733/4756/4757)."""

    member_name: str = "-"  # DN format or "-"
    member_sid: str = ""
    group_name: str = ""  # TargetUserName (the group)
    group_domain: str = ""  # TargetDomainName
    group_sid: str = ""  # TargetSid


@dataclass(slots=True)
class AccountManagementContext:
    """Windows account management details (4720/4723/4724/4726/4738)."""

    target_username: str = ""
    target_domain: str = ""
    target_sid: str = ""
    sam_account_name: str = ""
    display_name: str = "-"
    user_principal_name: str = "-"
    old_uac_value: str = "0x0"
    new_uac_value: str = "0x15"
    user_account_control: str = "-"
    password_last_set: str = "-"
    primary_group_id: str = "513"


@dataclass(slots=True)
class ShellContext:
    """Shell command execution details (bash_history)."""

    command: str
    exit_code: int = 0


# --- Zeek protocol-layer contexts (Phase: Zeek expansion) ---


@dataclass(slots=True)
class SslContext:
    """SSL/TLS handshake details for Zeek ssl.log."""

    version: str = ""  # "TLSv12", "TLSv13"
    cipher: str = ""  # "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    server_name: str = ""  # SNI hostname
    resumed: bool = False
    established: bool = True
    ssl_history: str = ""  # e.g., "CsiI"


@dataclass(slots=True)
class HttpContext:
    """HTTP request/response details for Zeek http.log."""

    method: str = "GET"
    host: str = ""  # Host header value
    uri: str = "/"
    version: str = "1.1"
    user_agent: str = ""
    request_body_len: int = 0
    response_body_len: int = 0
    status_code: int = 200
    status_msg: str = "OK"
    referrer: str = ""
    trans_depth: int = 1
    tags: list[str] = field(default_factory=list)
    resp_fuids: list[str] = field(default_factory=list)
    resp_mime_types: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FileTransferContext:
    """File transfer metadata for Zeek files.log.

    Distinct from FileContext (file-system operations). This tracks
    network file transfers observed by Zeek.
    """

    fuid: str = ""  # F-prefix Zeek file UID
    source: str = ""  # "HTTP", "SSL", "SMTP"
    depth: int = 0
    analyzers: list[str] = field(default_factory=list)
    mime_type: str = ""
    duration: float = 0.0
    local_orig: bool = False
    is_orig: bool = False
    seen_bytes: int = 0
    total_bytes: int | None = None
    missing_bytes: int = 0
    overflow_bytes: int = 0
    timedout: bool = False


@dataclass(slots=True)
class X509Context:
    """X.509 certificate details for Zeek x509.log."""

    fingerprint: str = ""  # SHA256 hex
    certificate_version: int = 3
    certificate_serial: str = ""
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_not_valid_before: float = 0.0
    certificate_not_valid_after: float = 0.0
    certificate_key_alg: str = "rsaEncryption"
    certificate_sig_alg: str = "sha256WithRSAEncryption"
    certificate_key_type: str = "rsa"
    certificate_key_length: int = 2048
    certificate_exponent: str = "65537"
    san_dns: list[str] = field(default_factory=list)
    basic_constraints_ca: bool = False
    host_cert: bool = True
    client_cert: bool = False


@dataclass(slots=True)
class DhcpContext:
    """DHCP transaction details for Zeek dhcp.log."""

    client_addr: str = ""
    server_addr: str = ""
    mac: str = ""
    host_name: str = ""
    domain: str = ""
    assigned_addr: str = ""
    lease_time: float = 0.0
    uids: list[str] = field(default_factory=list)
    msg_types: list[str] = field(default_factory=list)  # ["DISCOVER", "OFFER", "REQUEST", "ACK"]
    duration: float = 0.0


@dataclass(slots=True)
class NtpContext:
    """NTP protocol details for Zeek ntp.log."""

    version: int = 3
    mode: int = 3  # 3=client, 4=server
    stratum: int = 2
    poll: float = 512.0
    precision: float = 0.0
    root_delay: float = 0.0
    root_disp: float = 0.0
    ref_id: str = ""
    ref_ts: float = 0.0
    org_ts: float = 0.0
    rec_ts: float = 0.0
    xmt_ts: float = 0.0
    num_exts: int = 0


@dataclass(slots=True)
class OcspContext:
    """OCSP response details for Zeek ocsp.log."""

    id: str = ""  # F-prefix file ID
    hash_algorithm: str = "sha256"
    issuer_name_hash: str = ""
    issuer_key_hash: str = ""
    serial_number: str = ""
    cert_status: str = "good"  # "good", "revoked", "unknown"
    this_update: float = 0.0
    next_update: float = 0.0


@dataclass(slots=True)
class PeContext:
    """PE (Portable Executable) analysis for Zeek pe.log."""

    id: str = ""  # F-prefix file ID from files.log
    machine: str = "AMD64"
    compile_ts: float = 0.0
    os: str = "WINDOWS_NT"
    subsystem: str = "WINDOWS_GUI"
    is_exe: bool = True
    is_64bit: bool = True
    uses_aslr: bool = True
    uses_dep: bool = True
    uses_code_integrity: bool = False
    uses_seh: bool = True
    has_import_table: bool = True
    has_export_table: bool = False
    has_cert_table: bool = False
    has_debug_data: bool = False
    section_names: list[str] = field(default_factory=lambda: [".text", ".rdata", ".data", ".rsrc"])


@dataclass(slots=True)
class ProxyContext:
    """HTTP proxy transaction details for proxy_access.log fan-out."""

    client_ip: str
    username: str = ""
    method: str = "GET"
    url: str = ""  # Full destination URL or host:port for CONNECT
    host: str = ""  # Destination hostname
    status_code: int = 200
    sc_bytes: int = 0  # Server→client bytes
    cs_bytes: int = 0  # Client→server bytes
    time_taken: int = 0  # Request duration in ms
    user_agent: str = ""
    content_type: str = ""
    cache_result: str = "MISS"  # HIT, MISS, NONE, DENIED
    proxy_fqdn: str = ""  # FQDN of proxy system for routing


@dataclass(slots=True)
class RawContext:
    """Carries arbitrary fields destined for one specific emitter.

    Use when an event needs pipeline benefits (state management, visibility,
    local_only) but doesn't have a dedicated context model.
    """

    target_format: str  # Emitter key, e.g. "syslog", "windows_event_security"
    fields: dict[str, Any]
