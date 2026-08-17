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

"""Canonical event model for cross-log consistency by construction.

This package provides the intermediate representation layer between
ActivityGenerator (which builds events) and emitters (which render them).
"""

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.authentication import (
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
)
from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder, RawProjectionRequest
from evidenceforge.events.collection_policy import (
    CollectionBatchingPolicy,
    CollectionCapability,
    CollectionWindow,
    ProjectionAdmission,
    ProjectionEnvelope,
    ProjectionRole,
    SourceCollectionOverride,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
    normalize_source_collection_policy,
)
from evidenceforge.events.content_identity import (
    ApplicationProfileIdentity,
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    CompiledServiceDeploymentIdentity,
    CompiledTaskDeploymentIdentity,
    ContentDigests,
    FileContentIdentity,
    InstalledSoftwareReleaseIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
    PeVersionInfo,
    ProcessBinaryIdentity,
    RuntimeServiceDeploymentIdentity,
    ServiceDeploymentIdentity,
    SoftwareInstallationIdentity,
    UnresolvedBinaryIdentity,
    UserProfileIdentity,
    VirtualKernelBinaryIdentity,
)
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    EmailContext,
    FileContext,
    HostContext,
    IdsAlertPlan,
    ImageLoadContext,
    KerberosContext,
    ProcessAccessContext,
    ProcessContext,
    ProcessTargetSecurityContext,
    RegistryContext,
    ShellContext,
    SmtpContext,
)
from evidenceforge.events.contracts import (
    EVENT_KIND_CONTRACTS,
    CanonicalOccurrenceSnapshot,
    ContextKind,
    EventKind,
    EventKindContract,
    OccurrenceRole,
    SemanticOccurrenceKey,
    ShadowSealResult,
    shadow_seal,
)
from evidenceforge.events.network import (
    NatSensorObservation,
    NetworkTransactionPlan,
    SignaturePredicate,
)
from evidenceforge.events.protocol import ProtocolTransactionPlan
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpOperationAdmission,
    RdpReconnectCensus,
    RdpRetentionLease,
    RdpSessionAffinity,
    RdpSessionClosure,
    RdpSessionSnapshot,
    RdpSessionState,
    RdpTransportGeneration,
    RdpTransportPlan,
    RdpWatermarkResult,
)

__all__ = [
    "OccurrenceBuilder",
    "CanonicalOccurrence",
    "RawProjectionRequest",
    "ApplicationChannelBudget",
    "ApplicationChannelCensus",
    "ApplicationChannelIdentity",
    "ApplicationChannelSnapshot",
    "ApplicationOperationReservation",
    "ApplicationTransportBinding",
    "RdpLogicalSessionIdentity",
    "RdpOperationAdmission",
    "RdpReconnectCensus",
    "RdpRetentionLease",
    "RdpSessionClosure",
    "RdpSessionAffinity",
    "RdpSessionSnapshot",
    "RdpSessionState",
    "RdpTransportGeneration",
    "RdpTransportPlan",
    "RdpWatermarkResult",
    "CollectionBatchingPolicy",
    "CollectionCapability",
    "CollectionWindow",
    "ProjectionAdmission",
    "ProjectionEnvelope",
    "ProjectionRole",
    "SourceCollectionOverride",
    "SourceCollectionPolicy",
    "SourceInstanceIdentity",
    "normalize_source_collection_policy",
    "ApplicationProfileIdentity",
    "BinaryReleaseIdentity",
    "BinaryReleaseKey",
    "CompiledServiceDeploymentIdentity",
    "CompiledTaskDeploymentIdentity",
    "ContentDigests",
    "FileContentIdentity",
    "InstalledSoftwareReleaseIdentity",
    "LocalArtifactBinaryIdentity",
    "LocalArtifactIdentity",
    "LocalArtifactVersionRecord",
    "PeVersionInfo",
    "ProcessBinaryIdentity",
    "RuntimeServiceDeploymentIdentity",
    "ServiceDeploymentIdentity",
    "SoftwareInstallationIdentity",
    "UnresolvedBinaryIdentity",
    "UserProfileIdentity",
    "VirtualKernelBinaryIdentity",
    "EventKind",
    "ContextKind",
    "EventKindContract",
    "EVENT_KIND_CONTRACTS",
    "OccurrenceRole",
    "SemanticOccurrenceKey",
    "CanonicalOccurrenceSnapshot",
    "ShadowSealResult",
    "shadow_seal",
    "RemoteAuthenticationPlan",
    "RemoteAuthenticationTransportPlan",
    "HostContext",
    "AuthContext",
    "ProcessContext",
    "ProcessTargetSecurityContext",
    "ProcessAccessContext",
    "NetworkTransactionPlan",
    "ProtocolTransactionPlan",
    "DnsContext",
    "EmailContext",
    "FileContext",
    "RegistryContext",
    "IdsAlertPlan",
    "NatSensorObservation",
    "SignaturePredicate",
    "ImageLoadContext",
    "KerberosContext",
    "ShellContext",
    "SmtpContext",
]
