"""Composable context dataclasses for the canonical event model.

Each context represents a domain-specific facet of a security event.
ActivityGenerator populates contexts; emitters and StateManager read from them.
All use @dataclass(slots=True) for memory efficiency.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
    """DNS query/response details."""

    query: str
    query_type: str = "A"
    response_ip: str = ""
    rcode: str = "NOERROR"


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
    mac: str = ""
    host_name: str = ""
    domain: str = ""
    msg_types: list[str] = field(default_factory=list)  # ["REQUEST", "ACK"]
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
