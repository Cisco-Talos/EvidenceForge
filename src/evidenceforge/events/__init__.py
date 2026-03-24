"""Canonical event model for cross-log consistency by construction.

This package provides the intermediate representation layer between
ActivityGenerator (which builds events) and emitters (which render them).
"""

from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    IdsContext,
    KerberosContext,
    NetworkContext,
    ProcessContext,
    RawContext,
    RegistryContext,
    ShellContext,
)

__all__ = [
    "SecurityEvent",
    "RawLogEntry",
    "HostContext",
    "AuthContext",
    "ProcessContext",
    "NetworkContext",
    "DnsContext",
    "FileContext",
    "RegistryContext",
    "IdsContext",
    "KerberosContext",
    "ShellContext",
    "RawContext",
]
