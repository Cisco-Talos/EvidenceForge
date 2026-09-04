"""Bounded incremental head for proxy-emitter tunnel summaries."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.emitters.proxy import ProxyEmitter, _PendingTunnelSummary

from .errors import CheckpointCorruptionError, CheckpointError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _ProxyEmitterHead(BaseModel):
    """Validated envelope for incomplete proxy CONNECT summaries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    pending_tunnels: list[list[object]] = Field(default_factory=list)


def _parse_utc(value: object, *, field: str) -> datetime:
    if type(value) is not str:
        raise CheckpointCorruptionError(f"proxy emitter checkpoint {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CheckpointCorruptionError(f"proxy emitter checkpoint {field} is invalid") from error
    if parsed.tzinfo is not UTC:
        raise CheckpointCorruptionError(f"proxy emitter checkpoint {field} must be UTC")
    return parsed


class ProxyEmitterParticipant:
    """Persist only tunnel summaries still inside the proxy reuse window."""

    checkpoint_owner = "proxy-emitter-runtime"
    checkpoint_restore_priority = 43
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("_observed_tunnel_children", "transient-empty-at-barrier"),
        OwnerStateField("_pending_tunnels", "bounded-live-head"),
    )

    def __init__(self, emitter: ProxyEmitter) -> None:
        self.emitter = emitter

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture the bounded set of tunnels that may accept future children."""

        del sequence
        if self.emitter._observed_tunnel_children:
            raise CheckpointError("proxy emitter checkpoint retained unfurled tunnel children")
        rows: list[list[object]] = []
        for key, pending in sorted(self.emitter._pending_tunnels.items()):
            rows.append(
                [
                    key[0],
                    key[1],
                    encode_state_value(pending.connect_data),
                    pending.opened_at.isoformat(),
                    pending.last_activity_at.isoformat(),
                    pending.tunnel_cs_bytes,
                    pending.tunnel_sc_bytes,
                    (
                        None
                        if pending.latest_child_end is None
                        else pending.latest_child_end.isoformat()
                    ),
                    pending.transport_duration_ms,
                ]
            )
        document = _ProxyEmitterHead(
            schema_version=self.checkpoint_schema_version,
            pending_tunnels=rows,
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore incomplete proxy summaries into the fresh emitter."""

        if segments:
            raise CheckpointCorruptionError("proxy emitter checkpoint cannot own segments")
        try:
            document = _ProxyEmitterHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("proxy emitter checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("proxy emitter checkpoint schema is unsupported")
        restored: dict[tuple[str, str], _PendingTunnelSummary] = {}
        for row in document.pending_tunnels:
            if (
                type(row) is not list
                or len(row) != 9
                or type(row[0]) is not str
                or not row[0]
                or type(row[1]) is not str
                or not row[1]
                or type(row[5]) is not int
                or row[5] < 0
                or type(row[6]) is not int
                or row[6] < 0
                or (row[8] is not None and (type(row[8]) is not int or row[8] < 0))
            ):
                raise CheckpointCorruptionError("proxy emitter checkpoint row is invalid")
            key = (row[0], row[1])
            if key in restored:
                raise CheckpointCorruptionError("proxy emitter checkpoint has a duplicate tunnel")
            connect_data = decode_state_value(row[2])
            if (
                type(connect_data) is not dict
                or type(connect_data.get("timestamp")) is not datetime
                or connect_data["timestamp"].tzinfo is not UTC
                or type(connect_data.get("_host_fqdn")) is not str
                or not connect_data["_host_fqdn"]
            ):
                raise CheckpointCorruptionError("proxy emitter checkpoint CONNECT data is invalid")
            latest_child_end = (
                None if row[7] is None else _parse_utc(row[7], field="latest child timestamp")
            )
            restored[key] = _PendingTunnelSummary(
                connect_data=connect_data,
                opened_at=_parse_utc(row[3], field="open timestamp"),
                last_activity_at=_parse_utc(row[4], field="activity timestamp"),
                tunnel_cs_bytes=row[5],
                tunnel_sc_bytes=row[6],
                latest_child_end=latest_child_end,
                transport_duration_ms=row[8],
            )
        self.emitter._observed_tunnel_children.clear()
        self.emitter._pending_tunnels = restored
