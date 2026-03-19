"""Core event model types for the canonical event system.

SecurityEvent is the intermediate representation between ActivityGenerator
and emitters. RawLogEntry is the escape hatch for single-format entries.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    IdsContext,
    KerberosContext,
    NetworkContext,
    ProcessContext,
    RegistryContext,
    ShellContext,
)


@dataclass(slots=True)
class SecurityEvent:
    """Canonical event carrying all shared metadata for a single logical event.

    Composable contexts are populated as needed by ActivityGenerator.
    Emitters render their format-specific view from these contexts.
    """

    timestamp: datetime
    event_type: str

    host: HostContext | None = None
    auth: AuthContext | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None
    dns: DnsContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    ids: IdsContext | None = None
    kerberos: KerberosContext | None = None
    shell: ShellContext | None = None


@dataclass(slots=True)
class RawLogEntry:
    """Escape hatch -- bypass the event model for simple, single-format entries.

    Use for: background noise that only appears in one format, simple heartbeats,
    or events that don't yet fit the context model.
    """

    timestamp: datetime
    target_emitter: str  # Emitter dict key (e.g., "syslog", "zeek_conn")
    data: dict[str, Any]
