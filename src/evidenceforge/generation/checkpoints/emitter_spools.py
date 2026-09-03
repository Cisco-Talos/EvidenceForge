"""Incremental adapters for production emitter output and external-sort runs."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

from .errors import CheckpointCorruptionError, CheckpointFilesystemError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .spools import AppendOnlySpoolParticipant
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "2"
_BLOB_MAGIC = b"EFORGE-EMITTER-SPOOL-2\n"
_EMPTY_CHAIN = "0" * 64


@dataclass(frozen=True)
class _FileState:
    length: int
    chunks: int
    chain: str
    device: int
    inode: int


@dataclass(frozen=True)
class _RunState:
    size: int
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class _SortedWriterState:
    event_count: int
    run_sequence: int
    runs: tuple[_RunState, ...]


@dataclass(frozen=True)
class _PreparedState:
    sequence: int
    append_files: dict[str, _FileState]
    sorted_writers: dict[tuple[str, str], _SortedWriterState]
    writers: tuple[ExternalSortedLineWriter, ...]
    declared_emitters: tuple[object, ...]
    seal: ParticipantSeal


def _chain(previous: str, *, offset: int, payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(previous))
    digest.update(offset.to_bytes(8, "big"))
    digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _encode_blob(*, kind: str, key: str, offset: int, payload: bytes) -> bytes:
    metadata = dumps(
        {
            "key": key,
            "kind": kind,
            "offset": offset,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    )
    return _BLOB_MAGIC + len(metadata).to_bytes(8, "big") + metadata + payload


def _decode_blob(encoded: bytes) -> tuple[str, str, int, bytes]:
    prefix = len(_BLOB_MAGIC)
    if not encoded.startswith(_BLOB_MAGIC) or len(encoded) < prefix + 8:
        raise CheckpointCorruptionError("emitter spool segment header is unsupported")
    metadata_size = int.from_bytes(encoded[prefix : prefix + 8], "big")
    metadata_end = prefix + 8 + metadata_size
    if metadata_end > len(encoded):
        raise CheckpointCorruptionError("emitter spool segment header is truncated")
    metadata = loads(encoded[prefix + 8 : metadata_end])
    body = encoded[metadata_end:]
    if type(metadata) is not dict:
        raise CheckpointCorruptionError("emitter spool segment metadata is invalid")
    kind = metadata.get("kind")
    key = metadata.get("key")
    offset = metadata.get("offset")
    if (
        kind not in {"append", "replace", "sorted-run"}
        or type(key) is not str
        or not key
        or type(offset) is not int
        or offset < 0
        or metadata.get("size") != len(body)
        or metadata.get("sha256") != hashlib.sha256(body).hexdigest()
        or (kind == "replace" and offset != 0)
    ):
        raise CheckpointCorruptionError("emitter spool segment metadata changed")
    return kind, key, offset, body


def _safe_relative(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise CheckpointCorruptionError("emitter spool path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CheckpointCorruptionError("emitter spool path is unsafe")
    return path.as_posix()


def _read_file(path: Path, *, offset: int = 0) -> tuple[bytes, os.stat_result]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise CheckpointFilesystemError(f"emitter spool is not a regular file: {path}")
    if hasattr(os, "getuid") and before.st_uid != os.getuid():
        raise CheckpointFilesystemError(f"emitter spool has an unsafe owner: {path}")
    if before.st_size < offset:
        raise CheckpointFilesystemError(f"emitter spool was truncated: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise CheckpointFilesystemError(f"emitter spool changed while opening: {path}")
        chunks: list[bytes] = []
        cursor = offset
        while cursor < opened.st_size:
            payload = os.pread(descriptor, min(4 * 1024 * 1024, opened.st_size - cursor), cursor)
            if not payload:
                raise CheckpointFilesystemError(f"emitter spool read made no progress: {path}")
            chunks.append(payload)
            cursor += len(payload)
        if os.fstat(descriptor).st_size != opened.st_size:
            raise CheckpointFilesystemError(f"emitter spool changed during capture: {path}")
        return b"".join(chunks), opened
    finally:
        os.close(descriptor)


class EmitterSpoolParticipant:
    """Seal new append bytes and immutable external-sort runs after emitter barriers."""

    checkpoint_owner = "emitter-spools"
    checkpoint_restore_priority = 45
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("committed_lengths", "bounded-live-head"),
        OwnerStateField("append_chunks", "immutable-incremental-segments"),
        OwnerStateField("replace_chunks", "immutable-incremental-segments"),
        OwnerStateField("external_sort_runs", "immutable-incremental-segments"),
        OwnerStateField("writer_locks_and_paths", "deterministically-rebuilt"),
        OwnerStateField("queued_or_buffered_rows", "transient-empty-at-barrier"),
    )

    def __init__(self, *, emitters: dict[str, object], output_root: Path) -> None:
        self.emitters = emitters
        self.output_root = Path(output_root).resolve()
        self._committed_append: dict[str, _FileState] = {}
        self._committed_sorted: dict[tuple[str, str], _SortedWriterState] = {}
        self._prepared: _PreparedState | None = None
        self.last_bytes_read = 0

    def _relative_output(self, path: Path) -> str:
        try:
            relative = path.resolve().relative_to(self.output_root)
        except ValueError as error:
            raise CheckpointFilesystemError(
                f"emitter output escaped the staged bundle: {path}"
            ) from error
        return _safe_relative(relative.as_posix())

    def _writers(self) -> tuple[tuple[str, str, object], ...]:
        discovered: list[tuple[str, str, object]] = []
        for format_name, emitter in sorted(self.emitters.items()):
            routes = getattr(emitter, "_writers", None)
            if type(routes) is not dict:
                continue
            for route, writer in sorted(routes.items(), key=lambda item: str(item[0])):
                if type(route) is not str:
                    continue
                discovered.append((format_name, route, writer))
        return tuple(discovered)

    def _declared_output_files(self) -> tuple[tuple[object, Path, bool], ...]:
        """Return multiplexed outputs whose route writers may already be reclaimed."""

        discovered: list[tuple[object, Path, bool]] = []
        for _format_name, emitter in sorted(self.emitters.items()):
            snapshot = getattr(emitter, "checkpoint_output_files", None)
            if not callable(snapshot):
                continue
            rows = snapshot()
            if type(rows) is not tuple:
                raise RuntimeError("emitter checkpoint output inventory is malformed")
            for row in rows:
                if (
                    type(row) is not tuple
                    or len(row) != 2
                    or not isinstance(row[0], Path)
                    or type(row[1]) is not bool
                ):
                    raise RuntimeError("emitter checkpoint output inventory is malformed")
                discovered.append((emitter, row[0], row[1]))
        return tuple(discovered)

    def _capture_append_file(
        self,
        *,
        path: Path,
        replace: bool,
        require_same_identity: bool,
        projected_append: dict[str, _FileState],
        segments: list[SegmentDraft],
    ) -> None:
        """Capture one public spool as a suffix or explicit replacement generation."""

        relative = self._relative_output(path)
        previous = projected_append.get(relative)
        if replace:
            offset = 0
            chain = _EMPTY_CHAIN
            chunks = 0
            kind = "replace"
        else:
            offset = 0 if previous is None else previous.length
            chain = _EMPTY_CHAIN if previous is None else previous.chain
            chunks = 0 if previous is None else previous.chunks
            kind = "append"
        body, info = _read_file(path, offset=offset)
        if (
            previous is not None
            and not replace
            and require_same_identity
            and (info.st_dev, info.st_ino) != (previous.device, previous.inode)
        ):
            raise CheckpointFilesystemError(f"committed append output changed: {path}")
        cursor = offset
        if replace and not body:
            segments.append(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=_encode_blob(kind=kind, key=relative, offset=0, payload=b""),
                    record_count=1,
                )
            )
            chain = _chain(chain, offset=0, payload=b"")
            chunks += 1
        for chunk_offset in range(0, len(body), 4 * 1024 * 1024):
            chunk = body[chunk_offset : chunk_offset + 4 * 1024 * 1024]
            segment_kind = kind if chunk_offset == 0 else "append"
            segments.append(
                SegmentDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=_encode_blob(
                        kind=segment_kind,
                        key=relative,
                        offset=cursor,
                        payload=chunk,
                    ),
                    record_count=1,
                )
            )
            chain = _chain(chain, offset=cursor, payload=chunk)
            chunks += 1
            cursor += len(chunk)
        self.last_bytes_read += len(body)
        projected_append[relative] = _FileState(
            length=cursor,
            chunks=chunks,
            chain=chain,
            device=info.st_dev,
            inode=info.st_ino,
        )

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture only content created since the previous manifest."""

        if self._prepared is not None:
            if self._prepared.sequence != sequence:
                raise RuntimeError("emitter spool participant already prepared another sequence")
            return self._prepared.seal
        segments: list[SegmentDraft] = []
        projected_append = dict(self._committed_append)
        projected_sorted: dict[tuple[str, str], _SortedWriterState] = {}
        checkpoint_writers: list[ExternalSortedLineWriter] = []
        self.last_bytes_read = 0
        sorted_documents: list[dict[str, object]] = []
        append_documents: list[dict[str, object]] = []
        captured_paths: set[str] = set()

        for format_name, route, writer in self._writers():
            sorted_writer = getattr(writer, "_sorted_writer", None)
            output_path = getattr(writer, "output_path", None)
            if isinstance(sorted_writer, ExternalSortedLineWriter):
                event_count, run_sequence, paths = sorted_writer.checkpoint_snapshot()
                prior = self._committed_sorted.get((format_name, route))
                prior_runs = () if prior is None else prior.runs
                runs: list[_RunState] = []
                run_documents: list[dict[str, object]] = []
                for index, path in enumerate(paths):
                    key = f"{format_name}\n{route}\n{index}"
                    if index < len(prior_runs):
                        retained = prior_runs[index]
                        info = path.lstat()
                        if (info.st_size, info.st_dev, info.st_ino) != (
                            retained.size,
                            retained.device,
                            retained.inode,
                        ):
                            raise CheckpointFilesystemError(
                                f"committed external-sort run changed: {path}"
                            )
                        state = retained
                    else:
                        body, info = _read_file(path)
                        state = _RunState(
                            size=len(body),
                            sha256=hashlib.sha256(body).hexdigest(),
                            device=info.st_dev,
                            inode=info.st_ino,
                        )
                        self.last_bytes_read += len(body)
                        segments.append(
                            SegmentDraft(
                                owner=self.checkpoint_owner,
                                schema_version=self.checkpoint_schema_version,
                                payload=_encode_blob(
                                    kind="sorted-run", key=key, offset=0, payload=body
                                ),
                                record_count=1,
                            )
                        )
                    runs.append(state)
                    run_documents.append({"key": key, "sha256": state.sha256, "size": state.size})
                state = _SortedWriterState(
                    event_count=event_count,
                    run_sequence=run_sequence,
                    runs=tuple(runs),
                )
                projected_sorted[(format_name, route)] = state
                checkpoint_writers.append(sorted_writer)
                sorted_documents.append(
                    {
                        "event_count": event_count,
                        "format": format_name,
                        "route": route,
                        "run_sequence": run_sequence,
                        "runs": run_documents,
                    }
                )
                continue
            if not isinstance(output_path, Path) or not output_path.exists():
                continue
            relative = self._relative_output(output_path)
            self._capture_append_file(
                path=output_path,
                replace=False,
                require_same_identity=True,
                projected_append=projected_append,
                segments=segments,
            )
            captured_paths.add(relative)

        declared_emitters: list[object] = []
        for emitter, output_path, replace in self._declared_output_files():
            if not output_path.exists():
                continue
            relative = self._relative_output(output_path)
            if relative in captured_paths:
                raise RuntimeError(f"emitter checkpoint output has duplicate ownership: {relative}")
            self._capture_append_file(
                path=output_path,
                replace=replace,
                require_same_identity=False,
                projected_append=projected_append,
                segments=segments,
            )
            captured_paths.add(relative)
            if emitter not in declared_emitters:
                declared_emitters.append(emitter)

        for relative, state in sorted(projected_append.items()):
            append_documents.append(
                {
                    "chain": state.chain,
                    "chunks": state.chunks,
                    "length": state.length,
                    "path": relative,
                }
            )
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(
                    {
                        "append": append_documents,
                        "schema_version": self.checkpoint_schema_version,
                        "sorted": sorted_documents,
                    }
                ),
            ),
            segments=tuple(segments),
        )
        self._prepared = _PreparedState(
            sequence=sequence,
            append_files=projected_append,
            sorted_writers=projected_sorted,
            writers=tuple(checkpoint_writers),
            declared_emitters=tuple(declared_emitters),
            seal=seal,
        )
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance file watermarks only after the recovery manifest is durable."""

        prepared = self._prepared
        if prepared is None or prepared.sequence != sequence:
            raise RuntimeError("emitter spool commit does not match its prepared sequence")
        for writer in prepared.writers:
            writer.checkpoint_committed()
        for emitter in prepared.declared_emitters:
            committed = getattr(emitter, "checkpoint_outputs_committed", None)
            if not callable(committed):
                raise RuntimeError("emitter checkpoint output owner lost its commit hook")
            committed()
        self._committed_append = prepared.append_files
        self._committed_sorted = prepared.sorted_writers
        self._prepared = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retry the same physical delta after a failed manifest publication."""

        if self._prepared is None or self._prepared.sequence != sequence:
            raise RuntimeError("emitter spool abort does not match its prepared sequence")
        self._prepared = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Recreate append files and fresh protected external-sort run spools."""

        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
            or type(document.get("append")) is not list
            or type(document.get("sorted")) is not list
        ):
            raise CheckpointCorruptionError("emitter spool head schema is unsupported")
        append_bodies: dict[str, list[tuple[int, bytes]]] = {}
        sorted_bodies: dict[str, bytes] = {}
        for encoded in segments:
            kind, key, offset, body = _decode_blob(encoded)
            if kind in {"append", "replace"}:
                retained = append_bodies.setdefault(key, [])
                if kind == "replace":
                    retained.clear()
                retained.append((offset, body))
            elif key in sorted_bodies or offset != 0:
                raise CheckpointCorruptionError("external-sort run segment set changed")
            else:
                sorted_bodies[key] = body

        restored_append: dict[str, _FileState] = {}
        for raw in document["append"]:
            if type(raw) is not dict:
                raise CheckpointCorruptionError("emitter append head entry is invalid")
            relative = _safe_relative(raw.get("path"))
            length = raw.get("length")
            chunks = raw.get("chunks")
            expected_chain = raw.get("chain")
            if (
                type(length) is not int
                or length < 0
                or type(chunks) is not int
                or chunks < 0
                or type(expected_chain) is not str
                or len(expected_chain) != 64
                or relative in restored_append
            ):
                raise CheckpointCorruptionError("emitter append head entry changed")
            ordered = sorted(append_bodies.pop(relative, []), key=lambda item: item[0])
            cursor = 0
            chain = _EMPTY_CHAIN
            payloads: list[bytes] = []
            for offset, body in ordered:
                if offset != cursor:
                    raise CheckpointCorruptionError("emitter append segment offset changed")
                payloads.append(body)
                chain = _chain(chain, offset=offset, payload=body)
                cursor += len(body)
            if (cursor, len(ordered), chain) != (length, chunks, expected_chain):
                raise CheckpointCorruptionError("emitter append head does not match its segments")
            path = self.output_root.joinpath(*PurePosixPath(relative).parts)
            AppendOnlySpoolParticipant._replace_file(path, payloads)
            info = path.lstat()
            restored_append[relative] = _FileState(
                length=length,
                chunks=chunks,
                chain=chain,
                device=info.st_dev,
                inode=info.st_ino,
            )
        if append_bodies:
            raise CheckpointCorruptionError("checkpoint contains an unknown append output")

        restored_sorted: dict[tuple[str, str], _SortedWriterState] = {}
        for raw in document["sorted"]:
            if type(raw) is not dict or type(raw.get("runs")) is not list:
                raise CheckpointCorruptionError("emitter sorted head entry is invalid")
            format_name = raw.get("format")
            route = raw.get("route")
            event_count = raw.get("event_count")
            run_sequence = raw.get("run_sequence")
            if (
                type(format_name) is not str
                or format_name not in self.emitters
                or type(route) is not str
                or type(event_count) is not int
                or event_count < 0
                or type(run_sequence) is not int
                or run_sequence < 0
                or (format_name, route) in restored_sorted
            ):
                raise CheckpointCorruptionError("emitter sorted head entry changed")
            emitter = self.emitters[format_name]
            get_writer = getattr(emitter, "_get_writer", None)
            if not callable(get_writer):
                raise CheckpointCorruptionError("checkpoint emitter cannot rebuild its writer")
            writer = get_writer(route)
            sorted_writer = getattr(writer, "_sorted_writer", None)
            if not isinstance(sorted_writer, ExternalSortedLineWriter):
                raise CheckpointCorruptionError("checkpoint emitter sorting strategy changed")
            spool_dir = sorted_writer._ensure_spool_dir_unlocked()
            paths: list[Path] = []
            run_states: list[_RunState] = []
            for index, run in enumerate(raw["runs"]):
                if type(run) is not dict:
                    raise CheckpointCorruptionError("external-sort run head is invalid")
                key = run.get("key")
                size = run.get("size")
                digest = run.get("sha256")
                body = sorted_bodies.pop(key, None) if type(key) is str else None
                if (
                    key != f"{format_name}\n{route}\n{index}"
                    or type(size) is not int
                    or size < 0
                    or type(digest) is not str
                    or body is None
                    or len(body) != size
                    or hashlib.sha256(body).hexdigest() != digest
                ):
                    raise CheckpointCorruptionError("external-sort run head changed")
                path = spool_dir / f"checkpoint-{index:08d}.ndjson"
                AppendOnlySpoolParticipant._replace_file(path, [body])
                info = path.lstat()
                paths.append(path)
                run_states.append(
                    _RunState(
                        size=size,
                        sha256=digest,
                        device=info.st_dev,
                        inode=info.st_ino,
                    )
                )
            sorted_writer.restore_checkpoint_runs(
                paths=tuple(paths),
                event_count=event_count,
                run_sequence=run_sequence,
            )
            writer.event_count = event_count
            restored_sorted[(format_name, route)] = _SortedWriterState(
                event_count=event_count,
                run_sequence=run_sequence,
                runs=tuple(run_states),
            )
        if sorted_bodies:
            raise CheckpointCorruptionError("checkpoint contains an unknown external-sort run")
        self._committed_append = restored_append
        self._committed_sorted = restored_sorted
        self._prepared = None
        restored_paths = tuple(
            self.output_root.joinpath(*PurePosixPath(relative).parts)
            for relative in sorted(restored_append)
        )
        for emitter in self.emitters.values():
            restored = getattr(emitter, "checkpoint_outputs_restored", None)
            if callable(restored):
                restored(restored_paths)


__all__ = ["EmitterSpoolParticipant"]
