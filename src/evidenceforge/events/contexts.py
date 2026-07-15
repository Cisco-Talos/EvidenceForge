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

"""Composable context dataclasses for the canonical event model.

Each context represents a domain-specific facet of a security event.
ActivityGenerator populates contexts; emitters and StateManager read from them.
All use @dataclass(slots=True) for memory efficiency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionOutcome,
    NetworkTransactionPlan,
)
from evidenceforge.events.proxy import ProxyTransactionPlan


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
    roles: list[str] = field(default_factory=list)  # Scenario roles: web_server, dns_server, etc.


@dataclass(slots=True)
class AuthContext:
    """Authentication/session details."""

    username: str
    full_name: str = ""
    user_sid: str = ""
    logon_id: str = ""  # Allocated by StateManager.create_session()
    session_id: int = 0  # Windows terminal/session ID for interactive sources
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
    privilege_list: str = ""  # Newline-separated Windows 4672 PrivilegeList
    reporting_pid: int = 0  # PID of the process reporting this event (e.g., lsass for logons)
    process_pid: int = 0  # PID of process using explicit credentials (4648 ProcessId)
    target_server: str = ""  # 4648 TargetServerName (e.g., "fileserver01", "localhost")
    target_domain: str = ""  # 4648 TargetDomainName for target credentials
    process_name: str = ""  # 4648 ProcessName (process using explicit creds)
    workstation_name: str = ""  # Windows WorkstationName for logon/failure events


@dataclass(slots=True)
class ProcessTargetSecurityContext:
    """Optional alternate security context used to create a process."""

    user_sid: str
    username: str
    domain: str
    logon_id: str


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
    parent_command_line: str = ""  # ParentCommandLine (Sysmon Event 1)
    parent_start_time: datetime | None = None  # Parent creation time for stable GUIDs
    token_elevation: str = ""  # TokenElevationType (%%1936/%%1938)
    mandatory_label: str = ""  # MandatoryLabel SID
    start_time: datetime | None = None  # Process creation time for stable cross-event GUIDs
    current_directory: str = ""  # Sysmon Event 1 CurrentDirectory / process working dir
    concurrency_group_id: str = ""  # Explicit same-shell concurrency group (for pipelines)
    target_security_context: ProcessTargetSecurityContext | None = None


@dataclass(slots=True)
class RemoteThreadContext:
    """Cross-source details for remote thread creation."""

    target_pid: int
    target_image: str
    new_thread_id: int
    start_address: int
    start_module: str = ""
    start_function: str = ""
    source_thread_id: int = 0
    target_thread_id: int = 0
    target_process_object_id: str = ""
    thread_object_id: str = ""
    stack_base: int = 0
    stack_limit: int = 0
    user_stack_base: int = 0
    user_stack_limit: int = 0


@dataclass(slots=True)
class ProcessAccessContext:
    """Cross-source details for one process opening another process."""

    source_pid: int
    source_image: str
    target_pid: int
    target_image: str
    granted_access: str
    source_thread_id: int = -1
    target_user: str = "NT AUTHORITY\\SYSTEM"
    target_process_object_id: str = ""
    call_trace: str = ""


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
    source_visible_start_time: datetime | None = None
    source_visible_close_time: datetime | None = None
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
    responding_pid: int = -1  # Destination-side PID that accepted/owned the connection
    link_local: bool = False  # True for same-broadcast-domain traffic such as DHCP
    application_layer_only: bool = False  # Additional protocol transaction on an existing flow
    transaction: NetworkTransactionPlan | None = None

    @property
    def traffic_ledger(self) -> NetworkTrafficLedger:
        """Return finalized traffic truth or a compatibility projection."""

        if self.transaction is not None:
            return self.transaction.traffic
        return self._project_traffic_ledger()

    def finalize_transaction(
        self,
        stable_id: str,
        *,
        hostname: str = "",
        outcome: NetworkTransactionOutcome = "success",
        phase_times: tuple[tuple[str, datetime], ...] = (),
    ) -> NetworkTransactionPlan:
        """Freeze the final canonical transaction after all planning adjustments."""

        started_at = self.source_visible_start_time
        if started_at is None:
            raise ValueError("Cannot finalize a network transaction without a visible start")
        closed_at = self.source_visible_close_time
        transaction = NetworkTransactionPlan(
            stable_id=stable_id,
            hostname=hostname,
            outcome=outcome,
            phase_times=phase_times or (("transport_start", started_at),),
            started_at=started_at,
            closed_at=closed_at,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
            service=self.service,
            zeek_uid=self.zeek_uid,
            conn_id=self.conn_id,
            duration=self.duration,
            conn_state=self.conn_state,
            history=self.history,
            traffic=self._project_traffic_ledger(),
            initiating_pid=self.initiating_pid,
            responding_pid=self.responding_pid,
        )
        self.transaction = transaction
        return transaction

    def validate_finalized_transaction(self) -> None:
        """Fail if compatibility fields drift from finalized canonical truth."""

        transaction = self.transaction
        if transaction is None:
            return
        projection = (
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol,
            self.service,
            self.zeek_uid,
            self.conn_id,
            self.duration,
            self.conn_state,
            self.history,
            self.initiating_pid,
            self.responding_pid,
            self.source_visible_start_time,
            self.source_visible_close_time,
            self._project_traffic_ledger(),
        )
        canonical = (
            transaction.src_ip,
            transaction.src_port,
            transaction.dst_ip,
            transaction.dst_port,
            transaction.protocol,
            transaction.service,
            transaction.zeek_uid,
            transaction.conn_id,
            transaction.duration,
            transaction.conn_state,
            transaction.history,
            transaction.initiating_pid,
            transaction.responding_pid,
            transaction.started_at,
            transaction.closed_at,
            transaction.traffic,
        )
        if projection != canonical:
            raise ValueError("NetworkContext changed after canonical transaction finalization")

    def _project_traffic_ledger(self) -> NetworkTrafficLedger:
        """Build immutable accounting from legacy flat context fields."""

        orig_payload = max(0, self.orig_bytes or 0)
        resp_payload = max(0, self.resp_bytes or 0)
        orig_packets = max(0, self.orig_pkts)
        resp_packets = max(0, self.resp_pkts)
        orig_ip_bytes = max(orig_payload, self.orig_ip_bytes or 0)
        resp_ip_bytes = max(resp_payload, self.resp_ip_bytes or 0)
        if orig_ip_bytes > 0 and orig_packets == 0:
            orig_packets = 1
        if resp_ip_bytes > 0 and resp_packets == 0:
            resp_packets = 1
        return NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(orig_payload, orig_packets, orig_ip_bytes),
            resp=DirectionalTrafficLedger(resp_payload, resp_packets, resp_ip_bytes),
            missed_orig_bytes=max(0, self.missed_bytes),
        )


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
    preserve_ttls: bool = False
    AA: bool = False
    TC: bool = False
    RD: bool = True
    RA: bool = True
    rejected: bool = False
    rtt: float | None = None
    opcode: int = 0
    opcode_name: str = "query"
    Z: int = 0
    query_process: ProcessContext | None = None


@dataclass(slots=True)
class EmailContext:
    """Message-level email identity shared across SMTP hops and artifacts."""

    message_id: str
    artifact_id: str
    envelope_from: str
    header_from: str
    to: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    expanded_rcptto: list[str] = field(default_factory=list)
    subject: str = ""
    date_header: str = ""
    user_agent: str = ""
    body: str = ""
    body_size: int = 0
    custom_headers: dict[str, str] = field(default_factory=dict)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    verdict: str = "clean"
    mail_action: str = "deliver"
    outcome: str = "delivered"
    received_headers: list[str] = field(default_factory=list)
    artifact_path: str = ""
    storyline_id: str = ""


@dataclass(slots=True)
class SmtpContext:
    """One SMTP transaction/hop visible to Zeek smtp.log."""

    helo: str
    mailfrom: str
    rcptto: list[str]
    date: str
    from_header: str
    to_header: list[str]
    msg_id: str
    subject: str
    last_reply: str
    path: list[str] = field(default_factory=list)
    cc_header: list[str] = field(default_factory=list)
    user_agent: str = ""
    tls: bool = False
    trans_depth: int = 1
    fuids: list[str] = field(default_factory=list)
    encrypted_message: bool = False


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
class ImageLoadContext:
    """DLL/module load details for Sysmon Event 7."""

    image_loaded: str  # Full path to loaded DLL
    signed: bool = True
    signature: str = "Microsoft Windows"
    signature_status: str = "Valid"  # Valid, Expired, Revoked, Unavailable


@dataclass(slots=True)
class IdsContext:
    """IDS/IPS alert details for Snort."""

    sid: int
    message: str
    classification: str
    priority: int = 2
    rev: int = 1
    gid: int = 1


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
    service_name: str = ""  # "krbtgt" for TGT, requested SPN for service ticket
    service_account_name: str = ""  # AD account ticketed for the requested service
    service_sid: str = ""
    ticket_options: str = ""
    ticket_status: str = "0x0"
    encryption_type: str = ""  # e.g., "0x12" (AES-256)
    pre_auth_type: int = 0  # 4768 only
    cert_issuer_name: str = ""  # 4768 PKINIT only
    cert_serial_number: str = ""  # 4768 PKINIT only
    cert_thumbprint: str = ""  # 4768 PKINIT only
    source_ip: str = ""  # IPv6-mapped: "::ffff:x.x.x.x"
    source_port: int = 0
    reporting_pid: int = 0  # PID of lsass.exe that wrote this event


@dataclass(slots=True)
class ServiceContext:
    """Windows service installation details (4697)."""

    service_name: str
    service_file_name: str  # Full command line / binary path
    service_type: str = "0x10"  # 0x10=Own Process, 0x20=Share Process
    service_start_type: str = "3"  # 2=Auto, 3=Manual/Demand, 4=Disabled
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


# --- Zeek protocol-layer contexts (Phase: Zeek expansion) ---


@dataclass(slots=True)
class SslContext:
    """SSL/TLS handshake details for Zeek ssl.log."""

    version: str = ""  # "TLSv12", "TLSv13"
    cipher: str = ""  # "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    server_name: str = ""  # SNI hostname
    resumed: bool = False
    established: bool = True
    ssl_history: str = ""  # e.g., "CSOXYFFD"
    cert_chain_fuids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class HttpContext:
    """HTTP request/response details for Zeek http.log."""

    method: str = "GET"
    host: str = ""  # Host header value
    uri: str = "/"
    version: str = "1.1"
    user_agent: str = ""
    user_agent_known_absent: bool = False
    request_body_len: int = 0
    response_body_len: int = 0
    canonical_request_time: datetime | None = None
    flow_request_body_len: int | None = None
    flow_response_body_len: int | None = None
    flow_transaction_count: int = 1
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
    filename: str = ""
    analyzers: list[str] = field(default_factory=list)
    mime_type: str = ""
    duration: float = 0.0
    observation_not_before: datetime | None = None
    local_orig: bool = False
    is_orig: bool = False
    seen_bytes: int = 0
    total_bytes: int | None = None
    missing_bytes: int = 0
    overflow_bytes: int = 0
    timedout: bool = False
    md5: str = ""
    sha1: str = ""
    sha256: str = ""


@dataclass(slots=True)
class X509Context:
    """X.509 certificate details for Zeek x509.log."""

    fuid: str = ""  # Zeek file UID referenced by ssl.cert_chain_fuids
    fingerprint: str = ""  # SHA1 hex as rendered by Zeek x509.log
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
    hash_algorithm: str = "sha1"
    issuer_name_hash: str = ""
    issuer_key_hash: str = ""
    serial_number: str = ""
    cert_status: str = "good"  # "good", "revoked", "unknown"
    this_update: float = 0.0
    next_update: float = 0.0
    revoketime: float | None = None
    revokereason: str | None = None


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
    tunnel_status_code: int | None = None
    sc_bytes: int = 0  # Server→client bytes
    cs_bytes: int = 0  # Client→server bytes
    time_taken: int = 0  # Request duration in ms
    request_body_bytes: int = 0  # HTTP entity body only, excluding headers/framing
    response_body_bytes: int = 0  # HTTP entity body only, excluding headers/framing
    user_agent: str = ""
    content_type: str = ""
    cache_result: str = "MISS"  # HIT, MISS, REVALIDATED, NONE, DENIED
    referrer: str = ""  # HTTP Referer header
    proxy_fqdn: str = ""  # FQDN of proxy system for routing
    proxy_action: str = ""  # forward, tunnel, tunnel-setup, ssl-inspect, deny, auth-required
    transaction: ProxyTransactionPlan | None = None


@dataclass(slots=True)
class EdrContext:
    """EDR-specific entity tracking for eCAR format.

    Carries persistent object/actor UUIDs that form the eCAR object graph.
    object_id persists across an entity's lifecycle (e.g., same UUID for
    PROCESS/CREATE and PROCESS/TERMINATE).  actor_id links to the objectID
    of the entity that performed the action (e.g., parent process UUID on
    a PROCESS/CREATE, or initiating process UUID on a FILE/CREATE).
    """

    object_id: str = ""
    actor_id: str = ""
    tid: int = -1

    def validate_identity_plan(self, plan: EventIdentityPlan) -> None:
        """Validate populated compatibility fields against canonical identity truth."""

        if self.object_id and self.object_id != plan.object_id:
            raise ValueError("EdrContext object_id contradicts the canonical identity subject")
        if self.actor_id and self.actor_id != plan.actor_id:
            raise ValueError("EdrContext actor_id contradicts the canonical identity actor")
        if self.tid >= 0 and self.tid != plan.canonical_tid:
            raise ValueError("EdrContext tid contradicts the canonical identity thread")


@dataclass(slots=True)
class FirewallContext:
    """Cisco ASA firewall decision context.

    Carries the firewall action (permit/deny), ASA message ID, connection
    counter, and interface names for rendering ASA syslog records.
    """

    action: str  # "permit" | "deny"
    msg_id: int  # ASA message ID (302013, 106023, etc.)
    connection_id: int  # ASA connection counter
    src_interface: str  # "inside", "outside", "dmz"
    dst_interface: str
    access_group: str = ""  # ACL name for deny logs
    bytes_sent: int = 0  # For teardown records
    duration: str = ""  # "H:MM:SS" for teardown
    deny_hash_a: str = "0x0"  # ASA deny metadata hash field
    deny_hash_b: str = "0x0"  # ASA deny metadata hash field


@dataclass(slots=True)
class NatContext:
    """NAT translation applied to a connection by a firewall.

    Carries the mapped (post-NAT) addresses for rendering by emitters.
    For dynamic PAT, the source port is translated. For static NAT,
    ports are preserved. Emitters use these to render different IPs
    depending on which side of the NAT boundary they sit.
    """

    nat_type: str  # "dynamic_pat" | "static"
    mapped_src_ip: str  # post-NAT source IP
    mapped_src_port: int  # post-NAT source port (PAT changes this; static keeps it)
    mapped_dst_ip: str  # post-NAT dest IP (for inbound static NAT)
    mapped_dst_port: int  # post-NAT dest port
    pre_nat_dst_ip: str = ""  # original public dest when canonical tuple is already post-NAT
    pre_nat_dst_port: int = 0  # original public dest port when canonical tuple is already post-NAT


@dataclass(slots=True)
class RawContext:
    """Carries arbitrary fields destined for one specific emitter.

    Use when an event needs pipeline benefits (state management, visibility,
    local_only) but doesn't have a dedicated context model.
    """

    target_format: str  # Emitter key, e.g. "syslog", "windows_event_security"
    fields: dict[str, Any]
