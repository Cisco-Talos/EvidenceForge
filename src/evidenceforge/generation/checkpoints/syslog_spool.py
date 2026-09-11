"""Incremental adapter for the Syslog emitter's anonymous journal."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from evidenceforge.generation.emitters.base import ExactPublicationError
from evidenceforge.generation.emitters.syslog import SyslogEmitter

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "1"
_MAGIC = b"EFORGE-SYSLOG-SPOOL-1\n"
_EMPTY_CHAIN = "0" * 64
_CHUNK_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class _CommittedState:
    length: int = 0
    chunks: int = 0
    chain: str = _EMPTY_CHAIN


@dataclass(frozen=True)
class _PreparedState:
    sequence: int
    committed: _CommittedState
    seal: ParticipantSeal


def _chain(previous: str, *, offset: int, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(previous))
    digest.update(offset.to_bytes(8, "big"))
    digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _encode_chunk(*, offset: int, payload: bytes) -> bytes:
    metadata = dumps(
        {
            "offset": offset,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    )
    return _MAGIC + len(metadata).to_bytes(8, "big") + metadata + payload


def _decode_chunk(encoded: bytes) -> tuple[int, bytes]:
    prefix = len(_MAGIC)
    if not encoded.startswith(_MAGIC) or len(encoded) < prefix + 8:
        raise CheckpointCorruptionError("syslog spool segment header is unsupported")
    metadata_size = int.from_bytes(encoded[prefix : prefix + 8], "big")
    metadata_end = prefix + 8 + metadata_size
    if metadata_end > len(encoded):
        raise CheckpointCorruptionError("syslog spool segment header is truncated")
    metadata = loads(encoded[prefix + 8 : metadata_end])
    payload = encoded[metadata_end:]
    if (
        type(metadata) is not dict
        or type(metadata.get("offset")) is not int
        or metadata["offset"] < 0
        or metadata.get("size") != len(payload)
        or metadata.get("sha256") != hashlib.sha256(payload).hexdigest()
    ):
        raise CheckpointCorruptionError("syslog spool segment metadata changed")
    return metadata["offset"], payload


class SyslogSpoolParticipant:
    """Seal new Syslog journal bytes and rebuild a protected anonymous spool."""

    checkpoint_owner = "syslog-spool"
    checkpoint_restore_priority = 44
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("journal_head", "bounded-live-head"),
        OwnerStateField("journal_suffix", "immutable-incremental-segments"),
        OwnerStateField("descriptor_owner", "deterministically-rebuilt"),
        OwnerStateField("prepared_append", "transient-empty-at-barrier"),
    )

    def __init__(self, emitter: SyslogEmitter) -> None:
        if type(emitter) is not SyslogEmitter:
            raise TypeError("syslog checkpoint participant requires the production emitter")
        self.emitter = emitter
        self._committed = _CommittedState()
        self._prepared: _PreparedState | None = None
        self.last_bytes_read = 0

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture only journal bytes appended since the prior checkpoint."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("syslog spool participant already prepared another sequence")
            return self._prepared.seal
        suffix, live_state = self.emitter.checkpoint_spool_export(self._committed.length)
        segments: list[SegmentDraft] = []
        cursor = self._committed.length
        chain = self._committed.chain
        chunks = self._committed.chunks
        self.last_bytes_read = len(suffix)
        for start in range(0, len(suffix), _CHUNK_BYTES):
            payload = suffix[start : start + _CHUNK_BYTES]
            segments.append(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=_encode_chunk(offset=cursor, payload=payload),
                    record_count=1,
                )
            )
            chain = _chain(chain, offset=cursor, payload=payload)
            chunks += 1
            cursor += len(payload)
        committed = _CommittedState(length=cursor, chunks=chunks, chain=chain)
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(
                    {
                        "chain": committed.chain,
                        "chunks": committed.chunks,
                        "length": committed.length,
                        "live_state": live_state,
                        "schema_version": self.checkpoint_schema_version,
                    }
                ),
            ),
            segments=tuple(segments),
        )
        self._prepared = _PreparedState(sequence=sequence, committed=committed, seal=seal)
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the journal watermark only after durable manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("syslog spool commit does not match its prepared sequence")
        self._committed = self._prepared.committed
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retry the same suffix after a failed manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("syslog spool abort does not match its prepared sequence")
        self._prepared = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Validate the immutable chain and recreate the anonymous journal."""

        document = loads(head)
        if (
            type(document) is not dict
            or set(document)
            != {
                "chain",
                "chunks",
                "length",
                "live_state",
                "schema_version",
            }
            or document["schema_version"] != self.checkpoint_schema_version
            or type(document["length"]) is not int
            or document["length"] < 0
            or type(document["chunks"]) is not int
            or document["chunks"] < 0
            or type(document["chain"]) is not str
            or len(document["chain"]) != 64
        ):
            raise CheckpointCorruptionError("syslog spool head schema is unsupported")
        payloads: list[bytes] = []
        cursor = 0
        chain = _EMPTY_CHAIN
        for encoded in segments:
            offset, payload = _decode_chunk(encoded)
            if offset != cursor:
                raise CheckpointCorruptionError("syslog spool segment offset changed")
            payloads.append(payload)
            chain = _chain(chain, offset=offset, payload=payload)
            cursor += len(payload)
        if (cursor, len(payloads), chain) != (
            document["length"],
            document["chunks"],
            document["chain"],
        ):
            raise CheckpointCorruptionError("syslog spool head does not match its segments")
        try:
            self.emitter.checkpoint_spool_restore(
                b"".join(payloads),
                document["live_state"],
            )
        except (ExactPublicationError, OSError, ValueError) as error:
            raise CheckpointCorruptionError("syslog spool hydration failed") from error
        self._committed = _CommittedState(
            length=document["length"],
            chunks=document["chunks"],
            chain=document["chain"],
        )
        self._prepared = None


__all__ = ["SyslogSpoolParticipant"]
