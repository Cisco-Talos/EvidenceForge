"""Incremental checkpoint adapters for append-only emitter spools."""

from __future__ import annotations

import hashlib
import os
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import CheckpointCorruptionError, CheckpointFilesystemError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft, SegmentDraft

_APPEND_SPOOL_SCHEMA = "1"
_CHUNK_MAGIC = b"EFORGE-APPEND-SPOOL-1\n"
_IMMUTABLE_FILE_MAGIC = b"EFORGE-IMMUTABLE-SPOOL-1\n"
_EMPTY_CHAIN = "0" * 64


@dataclass(frozen=True)
class _CommittedFile:
    length: int = 0
    chunk_count: int = 0
    chain_sha256: str = _EMPTY_CHAIN
    device: int | None = None
    inode: int | None = None


@dataclass(frozen=True)
class _PreparedAppendSpool:
    sequence: int
    files: dict[str, _CommittedFile]
    seal: ParticipantSeal


@dataclass(frozen=True)
class _ImmutableFile:
    size: int
    sha256: str


@dataclass(frozen=True)
class _PreparedImmutableFiles:
    sequence: int
    files: dict[str, _ImmutableFile]
    seal: ParticipantSeal


def _hash_chain(previous: str, *, offset: int, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(previous))
    digest.update(offset.to_bytes(8, "big"))
    digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _encode_chunk(*, name: str, offset: int, previous: str, payload: bytes) -> bytes:
    header = dumps(
        {
            "chain_sha256": _hash_chain(previous, offset=offset, payload=payload),
            "name": name,
            "offset": offset,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    )
    return _CHUNK_MAGIC + len(header).to_bytes(8, "big") + header + payload


def _decode_chunk(payload: bytes) -> tuple[str, int, str, bytes]:
    prefix = len(_CHUNK_MAGIC)
    if not payload.startswith(_CHUNK_MAGIC) or len(payload) < prefix + 8:
        raise CheckpointCorruptionError("append-spool segment header is unsupported")
    header_length = int.from_bytes(payload[prefix : prefix + 8], "big")
    header_end = prefix + 8 + header_length
    if header_end > len(payload):
        raise CheckpointCorruptionError("append-spool segment header is truncated")
    header = loads(payload[prefix + 8 : header_end])
    if type(header) is not dict:
        raise CheckpointCorruptionError("append-spool segment metadata is invalid")
    name = header.get("name")
    offset = header.get("offset")
    size = header.get("size")
    payload_sha256 = header.get("payload_sha256")
    chain_sha256 = header.get("chain_sha256")
    body = payload[header_end:]
    if (
        type(name) is not str
        or not name
        or "/" in name
        or "\\" in name
        or type(offset) is not int
        or offset < 0
        or type(size) is not int
        or size != len(body)
        or type(payload_sha256) is not str
        or hashlib.sha256(body).hexdigest() != payload_sha256
        or type(chain_sha256) is not str
        or len(chain_sha256) != 64
    ):
        raise CheckpointCorruptionError("append-spool segment metadata changed")
    return name, offset, chain_sha256, body


def _encode_immutable_file(*, name: str, payload: bytes) -> bytes:
    header = dumps(
        {
            "name": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    )
    return _IMMUTABLE_FILE_MAGIC + len(header).to_bytes(8, "big") + header + payload


def _decode_immutable_file(payload: bytes) -> tuple[str, str, bytes]:
    prefix = len(_IMMUTABLE_FILE_MAGIC)
    if not payload.startswith(_IMMUTABLE_FILE_MAGIC) or len(payload) < prefix + 8:
        raise CheckpointCorruptionError("immutable-spool segment header is unsupported")
    header_length = int.from_bytes(payload[prefix : prefix + 8], "big")
    header_end = prefix + 8 + header_length
    if header_end > len(payload):
        raise CheckpointCorruptionError("immutable-spool segment header is truncated")
    header = loads(payload[prefix + 8 : header_end])
    body = payload[header_end:]
    if type(header) is not dict:
        raise CheckpointCorruptionError("immutable-spool segment metadata is invalid")
    name = header.get("name")
    size = header.get("size")
    digest = header.get("sha256")
    if (
        type(name) is not str
        or not name
        or "/" in name
        or "\\" in name
        or type(size) is not int
        or size != len(body)
        or type(digest) is not str
        or hashlib.sha256(body).hexdigest() != digest
    ):
        raise CheckpointCorruptionError("immutable-spool segment metadata changed")
    return name, digest, body


class AppendOnlySpoolParticipant:
    """Seal only bytes appended since the prior durable checkpoint.

    The caller owns the append-only contract and must invoke this participant only
    after its emitter barrier. Paths are deliberately absent from the durable head;
    logical names resolve fresh protected spool locations after moved-root recovery.
    """

    checkpoint_schema_version = _APPEND_SPOOL_SCHEMA
    checkpoint_state_fields = (
        OwnerStateField("committed_lengths", "bounded-live-head"),
        OwnerStateField("sealed_chunks", "immutable-incremental-segments"),
        OwnerStateField("paths", "deterministically-rebuilt"),
        OwnerStateField("open_writes", "transient-empty-at-barrier"),
    )

    def __init__(
        self,
        *,
        owner: str,
        files: dict[str, Path],
        chunk_size: int = 4 * 1024 * 1024,
    ) -> None:
        if not owner:
            raise ValueError("append-spool checkpoint owner cannot be empty")
        if not files:
            raise ValueError("append-spool participant requires at least one logical file")
        if chunk_size <= 0:
            raise ValueError("append-spool chunk_size must be positive")
        if any(not name or "/" in name or "\\" in name for name in files):
            raise ValueError("append-spool logical names must be safe path components")
        self.checkpoint_owner = owner
        self._files = {name: Path(path) for name, path in sorted(files.items())}
        self._chunk_size = chunk_size
        self._committed = {name: _CommittedFile() for name in self._files}
        self._prepared: _PreparedAppendSpool | None = None
        self.last_bytes_read = 0

    @staticmethod
    def _open_append_source(path: Path, prior: _CommittedFile) -> tuple[int, os.stat_result]:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CheckpointFilesystemError(f"append-only spool is not a regular file: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CheckpointFilesystemError(f"append-only spool has an unsafe owner: {path}")
        if info.st_size < prior.length:
            raise CheckpointFilesystemError(f"append-only spool was truncated: {path}")
        if prior.device is not None and (info.st_dev, info.st_ino) != (prior.device, prior.inode):
            raise CheckpointFilesystemError(f"append-only spool identity changed: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            os.close(descriptor)
            raise CheckpointFilesystemError(f"append-only spool changed while opening: {path}")
        return descriptor, opened

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Read each spool strictly from its prior committed length."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("append-spool participant already prepared another sequence")
            return self._prepared.seal
        segments: list[SegmentDraft] = []
        projected: dict[str, _CommittedFile] = {}
        self.last_bytes_read = 0
        for name, path in self._files.items():
            prior = self._committed[name]
            descriptor, opened = self._open_append_source(path, prior)
            offset = prior.length
            chunk_count = prior.chunk_count
            chain = prior.chain_sha256
            try:
                while offset < opened.st_size:
                    body = os.pread(
                        descriptor, min(self._chunk_size, opened.st_size - offset), offset
                    )
                    if not body:
                        raise CheckpointFilesystemError(
                            f"append-only spool read made no progress: {path}"
                        )
                    encoded = _encode_chunk(name=name, offset=offset, previous=chain, payload=body)
                    chain = _hash_chain(chain, offset=offset, payload=body)
                    segments.append(
                        SegmentDraft(
                            owner=self.checkpoint_owner,
                            schema_version=self.checkpoint_schema_version,
                            payload=encoded,
                            record_count=1,
                        )
                    )
                    offset += len(body)
                    chunk_count += 1
                    self.last_bytes_read += len(body)
                if os.fstat(descriptor).st_size != opened.st_size:
                    raise CheckpointFilesystemError(
                        f"append-only spool changed during checkpoint capture: {path}"
                    )
            finally:
                os.close(descriptor)
            projected[name] = _CommittedFile(
                length=offset,
                chunk_count=chunk_count,
                chain_sha256=chain,
                device=opened.st_dev,
                inode=opened.st_ino,
            )
        head = HeadDraft(
            owner=self.checkpoint_owner,
            schema_version=self.checkpoint_schema_version,
            payload=dumps(
                {
                    "files": [
                        {
                            "chain_sha256": state.chain_sha256,
                            "chunk_count": state.chunk_count,
                            "length": state.length,
                            "name": name,
                        }
                        for name, state in projected.items()
                    ],
                    "schema_version": self.checkpoint_schema_version,
                }
            ),
        )
        seal = ParticipantSeal(head=head, segments=tuple(segments))
        self._prepared = _PreparedAppendSpool(sequence=sequence, files=projected, seal=seal)
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance committed byte watermarks after manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("append-spool commit does not match its prepared sequence")
        self._committed = self._prepared.files
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Keep the prior byte watermarks so the full delta is retried."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("append-spool abort does not match its prepared sequence")
        self._prepared = None

    @staticmethod
    def _replace_file(path: Path, payloads: list[bytes]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            raise CheckpointFilesystemError(f"append-spool restore parent is unsafe: {path.parent}")
        temporary = path.with_name(f".{path.name}.checkpoint-{uuid.uuid4().hex}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            for payload in payloads:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:  # pragma: no cover - os.write contract
                        raise OSError("append-spool restore write made no progress")
                    view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            parent_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Validate the hash chain and recreate each configured spool."""

        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
        ):
            raise CheckpointCorruptionError("append-spool head schema is unsupported")
        raw_files = document.get("files")
        if type(raw_files) is not list:
            raise CheckpointCorruptionError("append-spool head file table is invalid")
        expected: dict[str, _CommittedFile] = {}
        for raw in raw_files:
            if type(raw) is not dict:
                raise CheckpointCorruptionError("append-spool head file entry is invalid")
            name = raw.get("name")
            length = raw.get("length")
            chunk_count = raw.get("chunk_count")
            chain = raw.get("chain_sha256")
            if (
                type(name) is not str
                or name not in self._files
                or name in expected
                or type(length) is not int
                or length < 0
                or type(chunk_count) is not int
                or chunk_count < 0
                or type(chain) is not str
                or len(chain) != 64
            ):
                raise CheckpointCorruptionError("append-spool head file entry changed")
            expected[name] = _CommittedFile(
                length=length,
                chunk_count=chunk_count,
                chain_sha256=chain,
            )
        if set(expected) != set(self._files):
            raise CheckpointCorruptionError("append-spool logical file set changed")

        bodies: dict[str, list[bytes]] = {name: [] for name in self._files}
        offsets = {name: 0 for name in self._files}
        chains = {name: _EMPTY_CHAIN for name in self._files}
        counts = {name: 0 for name in self._files}
        for encoded in segments:
            name, offset, stored_chain, body = _decode_chunk(encoded)
            if name not in bodies or offset != offsets[name]:
                raise CheckpointCorruptionError("append-spool segment order or offset changed")
            computed_chain = _hash_chain(chains[name], offset=offset, payload=body)
            if stored_chain != computed_chain:
                raise CheckpointCorruptionError("append-spool segment hash chain changed")
            bodies[name].append(body)
            offsets[name] += len(body)
            chains[name] = computed_chain
            counts[name] += 1
        for name, state in expected.items():
            if (offsets[name], counts[name], chains[name]) != (
                state.length,
                state.chunk_count,
                state.chain_sha256,
            ):
                raise CheckpointCorruptionError("append-spool head does not match its segments")
        restored: dict[str, _CommittedFile] = {}
        for name, path in self._files.items():
            self._replace_file(path, bodies[name])
            info = path.lstat()
            state = expected[name]
            restored[name] = _CommittedFile(
                length=state.length,
                chunk_count=state.chunk_count,
                chain_sha256=state.chain_sha256,
                device=info.st_dev,
                inode=info.st_ino,
            )
        self._committed = restored
        self._prepared = None


class ImmutableSpoolFilesParticipant:
    """Import each immutable spool file once and recreate it on recovery."""

    checkpoint_schema_version = _APPEND_SPOOL_SCHEMA
    checkpoint_state_fields = (
        OwnerStateField("imported_files", "immutable-incremental-segments"),
        OwnerStateField("file_index", "bounded-live-head"),
        OwnerStateField("paths", "deterministically-rebuilt"),
        OwnerStateField("pending_writes", "transient-empty-at-barrier"),
    )

    def __init__(
        self,
        *,
        owner: str,
        source_files: Callable[[], dict[str, Path]],
        restore_path: Callable[[str], Path],
    ) -> None:
        if not owner:
            raise ValueError("immutable-spool checkpoint owner cannot be empty")
        self.checkpoint_owner = owner
        self._source_files = source_files
        self._restore_path = restore_path
        self._committed: dict[str, _ImmutableFile] = {}
        self._prepared: _PreparedImmutableFiles | None = None
        self.last_bytes_read = 0

    @staticmethod
    def _read_immutable(path: Path) -> bytes:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise CheckpointFilesystemError(f"immutable spool is not a regular file: {path}")
        if hasattr(os, "getuid") and before.st_uid != os.getuid():
            raise CheckpointFilesystemError(f"immutable spool has an unsafe owner: {path}")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise CheckpointFilesystemError(f"immutable spool changed while opening: {path}")
            chunks: list[bytes] = []
            offset = 0
            while offset < opened.st_size:
                chunk = os.pread(descriptor, min(4 * 1024 * 1024, opened.st_size - offset), offset)
                if not chunk:
                    raise CheckpointFilesystemError(
                        f"immutable spool read made no progress: {path}"
                    )
                chunks.append(chunk)
                offset += len(chunk)
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                raise CheckpointFilesystemError(f"immutable spool changed during capture: {path}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_name(name: object) -> str:
        if type(name) is not str or not name or "/" in name or "\\" in name:
            raise CheckpointCorruptionError("immutable-spool logical name is unsafe")
        return name

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Read only files whose logical identities have not been imported."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("immutable-spool participant already prepared another sequence")
            return self._prepared.seal
        sources = self._source_files()
        if any(type(name) is not str for name in sources):
            raise ValueError("immutable-spool logical names must be strings")
        projected = dict(self._committed)
        segments: list[SegmentDraft] = []
        self.last_bytes_read = 0
        for name, path in sorted(sources.items()):
            self._validate_name(name)
            if name in projected:
                continue
            body = self._read_immutable(Path(path))
            digest = hashlib.sha256(body).hexdigest()
            projected[name] = _ImmutableFile(size=len(body), sha256=digest)
            self.last_bytes_read += len(body)
            segments.append(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=_encode_immutable_file(name=name, payload=body),
                    record_count=1,
                )
            )
        head = HeadDraft(
            owner=self.checkpoint_owner,
            schema_version=self.checkpoint_schema_version,
            payload=dumps(
                {
                    "files": [
                        {"name": name, "sha256": item.sha256, "size": item.size}
                        for name, item in sorted(projected.items())
                    ],
                    "schema_version": self.checkpoint_schema_version,
                }
            ),
        )
        seal = ParticipantSeal(head=head, segments=tuple(segments))
        self._prepared = _PreparedImmutableFiles(sequence=sequence, files=projected, seal=seal)
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Remember imported logical identities after durable publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("immutable-spool commit does not match its prepared sequence")
        self._committed = self._prepared.files
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retry every newly observed file after failed publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("immutable-spool abort does not match its prepared sequence")
        self._prepared = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Validate the immutable index and recreate each file at a fresh path."""

        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
            or type(document.get("files")) is not list
        ):
            raise CheckpointCorruptionError("immutable-spool head schema is unsupported")
        expected: dict[str, _ImmutableFile] = {}
        for raw in document["files"]:
            if type(raw) is not dict:
                raise CheckpointCorruptionError("immutable-spool head file entry is invalid")
            name = self._validate_name(raw.get("name"))
            size = raw.get("size")
            digest = raw.get("sha256")
            if (
                name in expected
                or type(size) is not int
                or size < 0
                or type(digest) is not str
                or len(digest) != 64
            ):
                raise CheckpointCorruptionError("immutable-spool head file entry changed")
            expected[name] = _ImmutableFile(size=size, sha256=digest)
        recovered: dict[str, bytes] = {}
        for segment in segments:
            name, digest, body = _decode_immutable_file(segment)
            if name in recovered or expected.get(name) != _ImmutableFile(
                size=len(body), sha256=digest
            ):
                raise CheckpointCorruptionError("immutable-spool segment set changed")
            recovered[name] = body
        if set(recovered) != set(expected):
            raise CheckpointCorruptionError("immutable-spool head does not match its segments")
        for name, body in sorted(recovered.items()):
            AppendOnlySpoolParticipant._replace_file(Path(self._restore_path(name)), [body])
        self._committed = expected
        self._prepared = None
