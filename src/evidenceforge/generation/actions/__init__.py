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

"""Action-bundle interfaces for coordinated evidence generation."""

from evidenceforge.generation.actions.auth_session import (
    AnonymousLogonActionBundle,
    AnonymousLogonRequest,
    FailedLogonActionBundle,
    FailedLogonRequest,
    LogoffActionBundle,
    LogoffRequest,
    LogonActionBundle,
    LogonRequest,
    MachineAccountLogonActionBundle,
    MachineAccountLogonRequest,
    NtlmValidationActionBundle,
    NtlmValidationRequest,
    ServiceLogonActionBundle,
    ServiceLogonRequest,
    WorkstationLockActionBundle,
    WorkstationLockRequest,
    WorkstationUnlockActionBundle,
    WorkstationUnlockRequest,
)
from evidenceforge.generation.actions.base import ActionAnchor, ActionBundle
from evidenceforge.generation.actions.browser_session import (
    BrowserSessionActionBundle,
    BrowserSessionRequest,
    BrowserSessionResult,
)
from evidenceforge.generation.actions.dhcp_lease import (
    DhcpLeaseActionBundle,
    DhcpLeaseRequest,
)
from evidenceforge.generation.actions.dns_lookup import (
    DnsLookupActionBundle,
    DnsLookupRequest,
)
from evidenceforge.generation.actions.file_transfer import (
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
    HttpResponseFileTransferResult,
    ScpReceiverFileActionBundle,
    ScpReceiverFileRequest,
    SmbFileTransferMetadataActionBundle,
    SmbFileTransferMetadataRequest,
    StagedArchiveSmbReadActionBundle,
    StagedArchiveSmbReadRequest,
    file_transfer_hashes,
)
from evidenceforge.generation.actions.ids_alert import (
    IdsAlertActionBundle,
    IdsAlertRequest,
    IdsAlertResult,
)
from evidenceforge.generation.actions.kerberos_dc import (
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
)
from evidenceforge.generation.actions.linux_shell_command import (
    LinuxShellCommandActionBundle,
    LinuxShellCommandRequest,
)
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionActionBundle,
    NetworkConnectionRequest,
)
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
    ProcessTerminationActionBundle,
    ProcessTerminationRequest,
)
from evidenceforge.generation.actions.proxy_transaction import (
    ProxyTransactionActionBundle,
    ProxyTransactionRequest,
)
from evidenceforge.generation.actions.rdp_session import (
    RdpSessionActionBundle,
    RdpSessionRequest,
    RdpSourceProcessFactory,
)
from evidenceforge.generation.actions.scanner_probe import (
    NmapCommandProbeActionBundle,
    NmapCommandProbeRequest,
    PortScanActionBundle,
    PortScanRequest,
    ScheduledScanOverlapActionBundle,
    ScheduledScanOverlapRequest,
    WebScanActionBundle,
    WebScanRequest,
)
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
)
from evidenceforge.generation.actions.windows_audit import (
    AccountChangedActionBundle,
    AccountChangedRequest,
    AccountCreatedActionBundle,
    AccountCreatedRequest,
    AccountDeletedActionBundle,
    AccountDeletedRequest,
    CreateRemoteThreadActionBundle,
    CreateRemoteThreadRequest,
    GroupMembershipChangeActionBundle,
    GroupMembershipChangeRequest,
    LogClearedActionBundle,
    LogClearedRequest,
    PasswordChangeActionBundle,
    PasswordChangeRequest,
    PasswordResetActionBundle,
    PasswordResetRequest,
    ProcessAccessActionBundle,
    ProcessAccessRequest,
    ScheduledTaskActionBundle,
    ScheduledTaskRequest,
)
from evidenceforge.generation.actions.windows_remote_admin import (
    ExplicitCredentialUseActionBundle,
    ExplicitCredentialUseRequest,
    WindowsServiceInstallActionBundle,
    WindowsServiceInstallRequest,
)

__all__ = [
    "AccountChangedActionBundle",
    "AccountChangedRequest",
    "AccountCreatedActionBundle",
    "AccountCreatedRequest",
    "AccountDeletedActionBundle",
    "AccountDeletedRequest",
    "ActionAnchor",
    "ActionBundle",
    "AnonymousLogonActionBundle",
    "AnonymousLogonRequest",
    "BrowserSessionActionBundle",
    "BrowserSessionRequest",
    "BrowserSessionResult",
    "CreateRemoteThreadActionBundle",
    "CreateRemoteThreadRequest",
    "DhcpLeaseActionBundle",
    "DhcpLeaseRequest",
    "DnsLookupActionBundle",
    "DnsLookupRequest",
    "FailedLogonActionBundle",
    "FailedLogonRequest",
    "HttpResponseFileTransferActionBundle",
    "HttpResponseFileTransferRequest",
    "HttpResponseFileTransferResult",
    "IdsAlertActionBundle",
    "IdsAlertRequest",
    "IdsAlertResult",
    "GroupMembershipChangeActionBundle",
    "GroupMembershipChangeRequest",
    "KerberosConnectionAuditActionBundle",
    "KerberosConnectionAuditRequest",
    "KerberosLogonTicketsActionBundle",
    "KerberosLogonTicketsRequest",
    "KerberosPreauthFailureActionBundle",
    "KerberosPreauthFailureRequest",
    "KerberosServiceTicketActionBundle",
    "KerberosServiceTicketRequest",
    "KerberosTgtActionBundle",
    "KerberosTgtRenewalActionBundle",
    "KerberosTgtRenewalRequest",
    "KerberosTgtRequest",
    "LogoffActionBundle",
    "LogoffRequest",
    "LogClearedActionBundle",
    "LogClearedRequest",
    "LogonActionBundle",
    "LogonRequest",
    "MachineAccountLogonActionBundle",
    "MachineAccountLogonRequest",
    "ScpReceiverFileActionBundle",
    "ScpReceiverFileRequest",
    "SmbFileTransferMetadataActionBundle",
    "SmbFileTransferMetadataRequest",
    "StagedArchiveSmbReadActionBundle",
    "StagedArchiveSmbReadRequest",
    "file_transfer_hashes",
    "LinuxShellCommandActionBundle",
    "LinuxShellCommandRequest",
    "NetworkConnectionActionBundle",
    "NetworkConnectionRequest",
    "NmapCommandProbeActionBundle",
    "NmapCommandProbeRequest",
    "NtlmValidationActionBundle",
    "NtlmValidationRequest",
    "PasswordChangeActionBundle",
    "PasswordChangeRequest",
    "PasswordResetActionBundle",
    "PasswordResetRequest",
    "ProcessExecutionActionBundle",
    "ProcessExecutionRequest",
    "ProcessAccessActionBundle",
    "ProcessAccessRequest",
    "ProcessTerminationActionBundle",
    "ProcessTerminationRequest",
    "PortScanActionBundle",
    "PortScanRequest",
    "ProxyTransactionActionBundle",
    "ProxyTransactionRequest",
    "RdpSessionActionBundle",
    "RdpSessionRequest",
    "RdpSourceProcessFactory",
    "ScheduledScanOverlapActionBundle",
    "ScheduledScanOverlapRequest",
    "ScheduledTaskActionBundle",
    "ScheduledTaskRequest",
    "ServiceLogonActionBundle",
    "ServiceLogonRequest",
    "WebScanActionBundle",
    "WebScanRequest",
    "SshSessionActionBundle",
    "SshSessionRequest",
    "ExplicitCredentialUseActionBundle",
    "ExplicitCredentialUseRequest",
    "WindowsServiceInstallActionBundle",
    "WindowsServiceInstallRequest",
    "WorkstationLockActionBundle",
    "WorkstationLockRequest",
    "WorkstationUnlockActionBundle",
    "WorkstationUnlockRequest",
]
