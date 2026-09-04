"""Content-addressed storage and atomic publication for incremental checkpoints."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import socket
import stat
import time
import uuid
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import ValidationError

from .errors import (
    CheckpointCompatibilityError,
    CheckpointCorruptionError,
    CheckpointFilesystemError,
    CheckpointLockError,
)
from .models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointRecovery,
    ParticipantHead,
    SegmentCatalogNode,
    SegmentCatalogReference,
    SegmentReference,
)

_SEGMENT_MAGIC = b"EFORGE-SEGMENT\x00\x01"
_WORKSPACE_NAME = ".eforge-generation"
_MANIFEST_NAME = "manifest.json"
_INDEX_NAME = "CURRENT.json"
_LOCK_NAME = "run.lock"
_MAX_LOCK_BYTES = 64 * 1024

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SegmentDraft:
    """New immutable records sealed by one explicit participant."""

    owner: str
    schema_version: str
    payload: bytes
    record_count: int
    compression: str = "none"


@dataclass(frozen=True)
class HeadDraft:
    """Bounded live participant state for the new recovery point."""

    owner: str
    schema_version: str
    payload: bytes
    referenced_segments: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunLockInspection:
    """Read-only ownership assessment for one generation run lock."""

    state: str
    owner: dict[str, object] | None = None
    detail: str | None = None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise CheckpointCorruptionError(f"unsafe checkpoint relative path: {value!r}")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise CheckpointCorruptionError(f"unsafe checkpoint relative path: {value!r}")
    return relative


def _sync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - os.write contract
                raise OSError("checkpoint write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_replace(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.pending-{uuid.uuid4().hex}")
    try:
        _write_new_file(temporary, payload)
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class RunLock:
    """Exclusive generation ownership for one output root."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.path = self.workspace / _LOCK_NAME
        self._owned = False

    def acquire(self) -> None:
        """Acquire the run lock, reclaiming only a demonstrably dead local owner."""

        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = _canonical_json(
            {
                "hostname": socket.gethostname(),
                "pid": os.getpid(),
                "started_ns": time.time_ns(),
            }
        )
        while True:
            try:
                _write_new_file(self.path, payload)
                _sync_directory(self.workspace)
                self._owned = True
                return
            except FileExistsError:
                owner = self._read_owner()
                if owner.get("hostname") != socket.gethostname():
                    raise CheckpointLockError(
                        "generation output is locked by another host; remove the lock only after "
                        "confirming that owner is no longer running"
                    ) from None
                pid = owner.get("pid")
                if not isinstance(pid, int) or _process_is_alive(pid):
                    raise CheckpointLockError(
                        f"generation output is already locked by live process {pid!r}"
                    ) from None
                stale = self.path.with_name(f".{_LOCK_NAME}.stale-{uuid.uuid4().hex}")
                try:
                    os.replace(self.path, stale)
                except FileNotFoundError:
                    continue
                stale.unlink(missing_ok=True)
                _sync_directory(self.workspace)

    def _read_owner(self) -> dict[str, object]:
        try:
            descriptor = os.open(
                self.path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise CheckpointLockError("generation output lock is not a regular file")
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    raise CheckpointLockError("generation output lock has an unsafe owner")
                if info.st_mode & 0o022:
                    raise CheckpointLockError("generation output lock is externally writable")
                raw = os.read(descriptor, _MAX_LOCK_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(raw) > _MAX_LOCK_BYTES:
                raise CheckpointLockError("generation output lock is too large")
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as error:
            raise CheckpointLockError(
                "generation output has an unreadable lock; inspect it before reclaiming"
            ) from error
        if not isinstance(value, dict):
            raise CheckpointLockError("generation output lock has an invalid owner record")
        return value

    def inspect(self) -> RunLockInspection:
        """Inspect lock ownership without creating, reclaiming, or deleting anything."""

        try:
            owner = self._read_owner()
        except CheckpointLockError as error:
            if not self.path.exists() and not self.path.is_symlink():
                return RunLockInspection(state="absent")
            return RunLockInspection(state="invalid", detail=str(error))
        hostname = owner.get("hostname")
        pid = owner.get("pid")
        if type(hostname) is not str or type(pid) is not int:
            return RunLockInspection(
                state="invalid",
                owner=owner,
                detail="generation output lock has an invalid owner record",
            )
        if hostname != socket.gethostname():
            return RunLockInspection(
                state="remote",
                owner=owner,
                detail="lock belongs to another host and cannot be locally probed",
            )
        if _process_is_alive(pid):
            return RunLockInspection(state="active", owner=owner)
        return RunLockInspection(
            state="stale",
            owner=owner,
            detail="local lock owner is no longer running and can be reclaimed by resume",
        )

    def release(self) -> None:
        """Release this process's lock without deleting another owner's replacement."""

        if not self._owned:
            return
        try:
            owner = self._read_owner()
        except CheckpointLockError:
            self._owned = False
            raise
        if owner.get("hostname") != socket.gethostname() or owner.get("pid") != os.getpid():
            self._owned = False
            raise CheckpointLockError("generation lock ownership changed before release")
        self.path.unlink()
        _sync_directory(self.workspace)
        self._owned = False

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class IncrementalCheckpointStore:
    """Publish two recovery manifests over shared immutable content objects."""

    def __init__(
        self,
        output_root: Path,
        *,
        publication_synchronization_hook: Callable[[str, int], None] | None = None,
    ) -> None:
        self.output_root = Path(output_root).resolve()
        self.workspace = self.output_root / _WORKSPACE_NAME
        self.objects = self.workspace / "objects"
        self.recovery = self.workspace / "recovery"
        self.index_path = self.workspace / _INDEX_NAME
        self.lock = RunLock(self.workspace)
        self._initialized = False
        self._publication_synchronization_hook = publication_synchronization_hook

    def _synchronize_publication(self, stage: str, sequence: int) -> None:
        """Invoke an explicitly installed test barrier at a publication seam."""

        if self._publication_synchronization_hook is not None:
            self._publication_synchronization_hook(stage, sequence)

    @property
    def staged_bundle(self) -> Path:
        """Return the stable hidden bundle root used by resumable generation."""

        return self.workspace / "staged"

    def initialize(self) -> None:
        """Create and validate the protected checkpoint workspace."""

        if self._initialized:
            return
        self._validate_output_root()
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.objects.mkdir(mode=0o700, exist_ok=True)
        self.recovery.mkdir(mode=0o700, exist_ok=True)
        self._validate_protected_directory(self.workspace)
        self._validate_protected_directory(self.objects)
        self._validate_protected_directory(self.recovery)
        self._probe_filesystem()
        self._initialized = True

    def validate_existing_workspace(self) -> None:
        """Validate an existing workspace without creating or probing any path."""

        if not self.output_root.exists():
            raise CheckpointFilesystemError(f"generation output does not exist: {self.output_root}")
        self._validate_output_ancestry(create=False)
        if not self.workspace.exists():
            raise CheckpointFilesystemError(
                f"generation checkpoint workspace does not exist: {self.workspace}"
            )
        self._validate_protected_directory(self.workspace)
        for directory in (self.objects, self.recovery):
            if directory.exists():
                self._validate_protected_directory(directory)

    def _validate_output_root(self) -> None:
        self._validate_output_ancestry(create=True)

    def _validate_output_ancestry(self, *, create: bool) -> None:
        current = self.output_root
        existing: list[Path] = []
        while not current.exists():
            if current == current.parent:
                break
            current = current.parent
        while True:
            existing.append(current)
            if current == current.parent:
                break
            current = current.parent
        for path in reversed(existing):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise CheckpointFilesystemError(
                    f"checkpoint output ancestry cannot contain symlinks: {path}"
                )
        if create:
            self.output_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_protected_directory(path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CheckpointFilesystemError(f"checkpoint path is not a real directory: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CheckpointFilesystemError(f"checkpoint directory has an unsafe owner: {path}")
        if info.st_mode & 0o022:
            raise CheckpointFilesystemError(f"checkpoint directory is group/world writable: {path}")

    def _probe_filesystem(self) -> None:
        probe = self.workspace / f".probe-{uuid.uuid4().hex}"
        replacement = self.workspace / f".probe-replaced-{uuid.uuid4().hex}"
        try:
            _write_new_file(probe, b"checkpoint-probe")
            os.replace(probe, replacement)
            _sync_file(replacement)
            _sync_directory(self.workspace)
        except OSError as error:
            raise CheckpointFilesystemError(
                "checkpoint filesystem cannot guarantee atomic rename and durable file/directory "
                "sync; use another filesystem or --checkpoint-hours 0"
            ) from error
        finally:
            probe.unlink(missing_ok=True)
            replacement.unlink(missing_ok=True)

    @staticmethod
    def _encode_segment(draft: SegmentDraft) -> tuple[bytes, str]:
        if draft.record_count < 0:
            raise ValueError("segment record_count cannot be negative")
        if draft.compression == "none":
            body = draft.payload
        elif draft.compression == "zlib-1":
            body = zlib.compress(draft.payload, level=1)
        else:
            raise ValueError(f"unsupported segment compression: {draft.compression!r}")
        payload_digest = _sha256(draft.payload)
        metadata = _canonical_json(
            {
                "codec": "stdlib-packed-v1",
                "compression": draft.compression,
                "owner": draft.owner,
                "payload_sha256": payload_digest,
                "record_count": draft.record_count,
                "schema_version": draft.schema_version,
                "uncompressed_size": len(draft.payload),
            }
        )
        encoded = _SEGMENT_MAGIC + len(metadata).to_bytes(8, "big") + metadata + body
        digest = _sha256(encoded)
        return encoded, digest

    def persist_resolved_scenario(self, payload: bytes) -> tuple[str, str]:
        """Write the authoritative resolved input once, outside checkpoint pauses."""

        self.initialize()
        digest = _sha256(payload)
        relative_path, _created = self._write_content_object(
            category="resolved",
            digest=digest,
            suffix=".yaml",
            payload=payload,
        )
        return digest, relative_path

    def _write_content_object(
        self,
        *,
        category: str,
        digest: str,
        suffix: str,
        payload: bytes,
    ) -> tuple[str, bool]:
        directory = self.objects / category / digest[:2]
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = directory / f"{digest}{suffix}"
        relative = path.relative_to(self.workspace).as_posix()
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise CheckpointFilesystemError(f"checkpoint object path is unsafe: {path}")
            if info.st_size != len(payload):
                raise CheckpointCorruptionError(
                    f"checkpoint object digest collision or tampering detected: {relative}"
                )
            return relative, False
        temporary = directory / f".{digest}.pending-{uuid.uuid4().hex}"
        try:
            _write_new_file(temporary, payload)
            if path.exists():
                if path.lstat().st_size != len(payload):
                    raise CheckpointCorruptionError(
                        f"checkpoint object changed during publication: {relative}"
                    )
            else:
                os.replace(temporary, path)
            _sync_directory(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return relative, True

    @staticmethod
    def _catalog_totals(
        references: tuple[SegmentReference, ...],
    ) -> tuple[int, int, dict[str, int]]:
        owner_counts: dict[str, int] = {}
        for reference in references:
            owner_counts[reference.owner] = owner_counts.get(reference.owner, 0) + 1
        return len(references), sum(reference.size for reference in references), owner_counts

    def _write_catalog_node(
        self,
        node: SegmentCatalogNode,
        *,
        segment_count: int,
        segment_bytes: int,
        owner_counts: dict[str, int],
    ) -> SegmentCatalogReference:
        payload = _canonical_json(node.model_dump(mode="json"))
        digest = _sha256(payload)
        relative, _created = self._write_content_object(
            category="catalogs",
            digest=digest,
            suffix=".json",
            payload=payload,
        )
        return SegmentCatalogReference(
            level=node.level,
            sha256=digest,
            relative_path=relative,
            size=len(payload),
            segment_count=segment_count,
            segment_bytes=segment_bytes,
            owner_counts=owner_counts,
        )

    def _extend_catalogs(
        self,
        inherited: tuple[SegmentCatalogReference, ...],
        segments: tuple[SegmentReference, ...],
    ) -> tuple[SegmentCatalogReference, ...]:
        """Append one delta through a persistent binary size-tiered catalog forest."""

        if not segments:
            return inherited
        count, size, owners = self._catalog_totals(segments)
        carry = self._write_catalog_node(
            SegmentCatalogNode(kind="leaf", level=0, segments=segments),
            segment_count=count,
            segment_bytes=size,
            owner_counts=owners,
        )
        by_level = {reference.level: reference for reference in inherited}
        while carry.level in by_level:
            left = by_level.pop(carry.level)
            combined_owners = dict(left.owner_counts)
            for owner, owner_count in carry.owner_counts.items():
                combined_owners[owner] = combined_owners.get(owner, 0) + owner_count
            carry = self._write_catalog_node(
                SegmentCatalogNode(
                    kind="branch",
                    level=carry.level + 1,
                    children=(left, carry),
                ),
                segment_count=left.segment_count + carry.segment_count,
                segment_bytes=left.segment_bytes + carry.segment_bytes,
                owner_counts=combined_owners,
            )
        by_level[carry.level] = carry
        return tuple(sorted(by_level.values(), key=lambda reference: reference.level, reverse=True))

    def _read_catalog(
        self,
        reference: SegmentCatalogReference,
        *,
        retained_paths: set[str] | None = None,
        visited: set[str] | None = None,
    ) -> tuple[SegmentReference, ...]:
        seen = set() if visited is None else visited
        if reference.sha256 in seen:
            raise CheckpointCorruptionError("checkpoint segment catalog contains a cycle")
        seen.add(reference.sha256)
        if retained_paths is not None:
            retained_paths.add(reference.relative_path)
        payload = self._validate_file(reference.relative_path, reference.size, reference.sha256)
        try:
            node = SegmentCatalogNode.model_validate_json(payload)
        except ValidationError as error:
            raise CheckpointCorruptionError("checkpoint segment catalog is corrupt") from error
        if node.level != reference.level:
            raise CheckpointCorruptionError("checkpoint segment catalog level changed")
        if node.kind == "leaf":
            segments = node.segments
        else:
            segments = tuple(
                segment
                for child in node.children
                for segment in self._read_catalog(
                    child,
                    retained_paths=retained_paths,
                    visited=seen,
                )
            )
        count, size, owners = self._catalog_totals(segments)
        if (
            count != reference.segment_count
            or size != reference.segment_bytes
            or owners != reference.owner_counts
        ):
            raise CheckpointCorruptionError("checkpoint segment catalog totals changed")
        return segments

    def segment_references(
        self,
        manifest: CheckpointManifest,
        *,
        retained_paths: set[str] | None = None,
    ) -> tuple[SegmentReference, ...]:
        """Expand and validate the immutable catalog forest in chronological order."""

        visited: set[str] = set()
        segments = tuple(
            segment
            for catalog in manifest.segment_catalogs
            for segment in self._read_catalog(
                catalog,
                retained_paths=retained_paths,
                visited=visited,
            )
        )
        owner_ordinals: dict[str, list[int]] = {}
        for segment in segments:
            owner_ordinals.setdefault(segment.owner, []).append(segment.owner_ordinal)
        for owner, ordinals in owner_ordinals.items():
            if ordinals != list(range(len(ordinals))):
                raise CheckpointCorruptionError(
                    f"checkpoint participant {owner!r} has invalid segment ordinals"
                )
        known = {segment.sha256 for segment in segments}
        for head in manifest.participant_heads:
            missing = set(head.referenced_segments) - known
            if missing:
                raise CheckpointCorruptionError(
                    f"participant {head.owner!r} references unknown segments: {sorted(missing)}"
                )
        return segments

    def commit(
        self,
        *,
        sequence: int,
        run_id: str,
        run_fingerprint: str,
        checkpoint_hours: int,
        cursor: CheckpointCursor,
        resolved_scenario: bytes,
        resolved_scenario_reference: tuple[str, str] | None = None,
        inherited_catalogs: tuple[SegmentCatalogReference, ...],
        new_segments: tuple[SegmentDraft, ...],
        heads: tuple[HeadDraft, ...],
        metadata: dict[str, Any] | None = None,
    ) -> CheckpointManifest:
        """Atomically publish one recovery manifest over shared immutable objects."""

        if checkpoint_hours <= 0:
            raise ValueError("checkpoint publication requires a positive cadence")
        self.initialize()
        next_owner_ordinal: dict[str, int] = {}
        for catalog in inherited_catalogs:
            for owner, count in catalog.owner_counts.items():
                next_owner_ordinal[owner] = next_owner_ordinal.get(owner, 0) + count
        segment_refs: list[SegmentReference] = []
        for draft in new_segments:
            encoded, digest = self._encode_segment(draft)
            relative, _created = self._write_content_object(
                category="segments",
                digest=digest,
                suffix=".seg",
                payload=encoded,
            )
            segment_refs.append(
                SegmentReference(
                    owner=draft.owner,
                    schema_version=draft.schema_version,
                    owner_ordinal=next_owner_ordinal.get(draft.owner, 0),
                    sha256=digest,
                    relative_path=relative,
                    size=len(encoded),
                    record_count=draft.record_count,
                    compression=draft.compression,
                )
            )
            next_owner_ordinal[draft.owner] = next_owner_ordinal.get(draft.owner, 0) + 1
        segment_catalogs = self._extend_catalogs(
            inherited_catalogs,
            tuple(segment_refs),
        )

        if resolved_scenario_reference is None:
            resolved_digest = _sha256(resolved_scenario)
            resolved_path, _ = self._write_content_object(
                category="resolved",
                digest=resolved_digest,
                suffix=".yaml",
                payload=resolved_scenario,
            )
        else:
            resolved_digest, resolved_path = resolved_scenario_reference

        pending = self.recovery / f".pending-{sequence:020d}-{uuid.uuid4().hex}"
        final = self.recovery / f"{sequence:020d}"
        if final.exists():
            indexed_sequences = {item_sequence for item_sequence, _ in self._read_index()}
            if sequence in indexed_sequences:
                raise CheckpointFilesystemError(f"checkpoint sequence already exists: {sequence}")
            self._validate_protected_directory(final)
            shutil.rmtree(final)
            _sync_directory(self.recovery)
        pending.mkdir(mode=0o700)
        head_refs: list[ParticipantHead] = []
        try:
            heads_directory = pending / "heads"
            heads_directory.mkdir(mode=0o700)
            for head in sorted(heads, key=lambda item: item.owner):
                filename = f"{head.owner}.bin"
                path = heads_directory / filename
                digest = _sha256(head.payload)
                _write_new_file(path, head.payload)
                head_refs.append(
                    ParticipantHead(
                        owner=head.owner,
                        schema_version=head.schema_version,
                        relative_path=f"recovery/{sequence:020d}/heads/{filename}",
                        size=len(head.payload),
                        sha256=digest,
                        referenced_segments=head.referenced_segments,
                    )
                )
            _sync_directory(heads_directory)
            self._synchronize_publication("heads_durable", sequence)
            manifest = CheckpointManifest(
                sequence=sequence,
                run_id=run_id,
                run_fingerprint=run_fingerprint,
                checkpoint_hours=checkpoint_hours,
                cursor=cursor,
                resolved_scenario_sha256=resolved_digest,
                resolved_scenario_relative_path=resolved_path,
                segment_catalogs=segment_catalogs,
                participant_heads=tuple(head_refs),
                metadata={} if metadata is None else metadata,
            )
            manifest_payload = _canonical_json(manifest.model_dump(mode="json"))
            _write_new_file(pending / _MANIFEST_NAME, manifest_payload)
            _sync_directory(pending)
            os.replace(pending, final)
            _sync_directory(self.recovery)
            self._synchronize_publication("recovery_published", sequence)
            self._publish_index(manifest, manifest_payload)
            self._synchronize_publication("index_published", sequence)
            try:
                self._rotate_recoveries()
            except OSError as error:
                # CURRENT.json is the atomic commit point. Once it names this recovery,
                # participant watermarks must advance even if best-effort cleanup of an
                # older, now-unreferenced directory fails. A later checkpoint retries it.
                logger.warning("Deferred checkpoint recovery rotation after failure: %s", error)
            return manifest
        finally:
            if pending.exists():
                shutil.rmtree(pending)

    def _publish_index(self, manifest: CheckpointManifest, payload: bytes) -> None:
        entries: list[dict[str, object]] = [
            {"manifest_sha256": _sha256(payload), "sequence": manifest.sequence}
        ]
        if self.index_path.exists():
            for sequence, manifest_sha256 in self._read_index():
                if sequence == manifest.sequence:
                    continue
                entries.append({"manifest_sha256": manifest_sha256, "sequence": sequence})
                if len(entries) == 2:
                    break
        _atomic_replace(self.index_path, _canonical_json({"recoveries": entries}))

    def _read_index(self) -> list[tuple[int, str]]:
        """Read the authoritative ordered recovery pointer without following links."""

        try:
            info = self.index_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise CheckpointCorruptionError("checkpoint recovery index is not a regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise CheckpointCorruptionError("checkpoint recovery index has an unsafe owner")
            if info.st_mode & 0o022:
                raise CheckpointCorruptionError("checkpoint recovery index is externally writable")
            document = json.loads(self.index_path.read_bytes())
        except FileNotFoundError:
            return []
        except (OSError, json.JSONDecodeError) as error:
            raise CheckpointCorruptionError("checkpoint recovery index is corrupt") from error
        if type(document) is not dict or set(document) != {"recoveries"}:
            raise CheckpointCorruptionError("checkpoint recovery index has an invalid schema")
        raw_entries = document["recoveries"]
        if type(raw_entries) is not list or not 1 <= len(raw_entries) <= 2:
            raise CheckpointCorruptionError("checkpoint recovery index has an invalid entry set")
        entries: list[tuple[int, str]] = []
        for raw in raw_entries:
            if type(raw) is not dict or set(raw) != {"manifest_sha256", "sequence"}:
                raise CheckpointCorruptionError("checkpoint recovery index entry is invalid")
            sequence = raw["sequence"]
            digest = raw["manifest_sha256"]
            if (
                type(sequence) is not int
                or sequence < 0
                or type(digest) is not str
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise CheckpointCorruptionError("checkpoint recovery index entry changed")
            entries.append((sequence, digest))
        sequences = [sequence for sequence, _ in entries]
        if len(sequences) != len(set(sequences)) or sequences != sorted(sequences, reverse=True):
            raise CheckpointCorruptionError("checkpoint recovery index order changed")
        return entries

    def recovery_index_entries(self, *, read_only: bool = False) -> tuple[tuple[int, str], ...]:
        """Return authoritative recovery entries without selecting or mutating them."""

        if read_only:
            self.validate_existing_workspace()
        else:
            self.initialize()
        return tuple(self._read_index())

    def _rotate_recoveries(self) -> None:
        directories = self._recovery_directories()
        for stale in directories[2:]:
            shutil.rmtree(stale)
        _sync_directory(self.recovery)

    def collect_garbage(self) -> None:
        """Remove objects unreferenced by either recovery outside checkpoint pauses."""

        self.initialize()
        directories = self._recovery_directories()
        retained_paths: set[str] = set()
        for directory in directories[:2]:
            try:
                manifest = self._load_manifest(directory)
            except CheckpointCorruptionError:
                continue
            retained_paths.add(manifest.resolved_scenario_relative_path)
            try:
                segments = self.segment_references(manifest, retained_paths=retained_paths)
            except CheckpointCorruptionError:
                continue
            retained_paths.update(segment.relative_path for segment in segments)
        if not self.objects.exists():
            return
        for path in self.objects.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(self.workspace).as_posix()
            if relative not in retained_paths:
                path.unlink()
        for directory in sorted(
            (path for path in self.objects.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except OSError:
                pass

    def _recovery_directories(self) -> list[Path]:
        if not self.recovery.exists():
            return []
        directories = [
            path
            for path in self.recovery.iterdir()
            if path.is_dir() and not path.name.startswith(".") and path.name.isdigit()
        ]
        return sorted(directories, key=lambda path: int(path.name), reverse=True)

    def _load_manifest(
        self,
        directory: Path,
        *,
        expected_sha256: str | None = None,
    ) -> CheckpointManifest:
        manifest_path = directory / _MANIFEST_NAME
        try:
            info = manifest_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise CheckpointCorruptionError("checkpoint manifest is not a regular file")
            payload = manifest_path.read_bytes()
            if expected_sha256 is not None and _sha256(payload) != expected_sha256:
                raise CheckpointCorruptionError("checkpoint manifest failed index validation")
            value = json.loads(payload)
            manifest = CheckpointManifest.model_validate(value)
        except (OSError, json.JSONDecodeError, ValidationError) as error:
            raise CheckpointCorruptionError(
                f"checkpoint manifest is corrupt: {manifest_path}"
            ) from error
        if manifest.sequence != int(directory.name):
            raise CheckpointCorruptionError("checkpoint directory and manifest sequence disagree")
        return manifest

    def _object_path(self, relative_path: str) -> Path:
        relative = _safe_relative_path(relative_path)
        path = self.workspace.joinpath(*relative.parts)
        try:
            path.relative_to(self.workspace)
        except ValueError as error:  # pragma: no cover - PurePosixPath guard
            raise CheckpointCorruptionError("checkpoint object escaped its workspace") from error
        current = self.workspace
        try:
            for part in relative.parts:
                current = current / part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise CheckpointCorruptionError(
                        f"checkpoint object traverses a symlink: {current}"
                    )
        except FileNotFoundError as error:
            raise CheckpointCorruptionError(
                f"checkpoint object is missing: {relative_path}"
            ) from error
        return path

    def _validate_file(self, relative_path: str, expected_size: int, expected_hash: str) -> bytes:
        path = self._object_path(relative_path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise CheckpointCorruptionError(f"checkpoint object is not a regular file: {path}")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CheckpointCorruptionError(f"checkpoint object has an unsafe owner: {path}")
        if info.st_mode & 0o022:
            raise CheckpointCorruptionError(f"checkpoint object is externally writable: {path}")
        payload = path.read_bytes()
        if len(payload) != expected_size or _sha256(payload) != expected_hash:
            raise CheckpointCorruptionError(
                f"checkpoint object failed integrity validation: {path}"
            )
        return payload

    def recover(
        self,
        *,
        expected_fingerprint: str | None = None,
        read_only: bool = False,
    ) -> CheckpointRecovery:
        """Return the newest valid recovery point, falling back once on corruption.

        When ``read_only`` is true, validate only paths that already exist and skip the
        durability probe so inspection cannot alter the output root.
        """

        if read_only:
            self.validate_existing_workspace()
        else:
            self.initialize()
        failures: list[str] = []
        entries = self._read_index()
        for index, (sequence, manifest_sha256) in enumerate(entries):
            try:
                recovery = self.validate_recovery_entry(
                    sequence,
                    manifest_sha256,
                    expected_fingerprint=expected_fingerprint,
                )
                warning = None
                if failures:
                    warning = (
                        "newest generation checkpoint was corrupt; using previous recovery point: "
                        + "; ".join(failures)
                    )
                return CheckpointRecovery(
                    checkpoint_directory=recovery.checkpoint_directory,
                    manifest=recovery.manifest,
                    segments=recovery.segments,
                    used_fallback=index > 0,
                    warning=warning,
                )
            except CheckpointCompatibilityError:
                raise
            except CheckpointCorruptionError as error:
                failures.append(str(error))
        if failures:
            raise CheckpointCorruptionError(
                "no valid generation checkpoint remains: " + "; ".join(failures)
            )
        raise CheckpointCorruptionError("no generation checkpoint exists")

    def validate_recovery_entry(
        self,
        sequence: int,
        manifest_sha256: str,
        *,
        expected_fingerprint: str | None = None,
    ) -> CheckpointRecovery:
        """Thoroughly validate one indexed recovery without changing the workspace."""

        directory = self.recovery / f"{sequence:020d}"
        manifest = self._load_manifest(directory, expected_sha256=manifest_sha256)
        if expected_fingerprint is not None and manifest.run_fingerprint != expected_fingerprint:
            raise CheckpointCompatibilityError(
                "checkpoint fingerprint does not match the resolved scenario and runtime"
            )
        resolved_path = self._object_path(manifest.resolved_scenario_relative_path)
        self._validate_file(
            manifest.resolved_scenario_relative_path,
            resolved_path.stat().st_size,
            manifest.resolved_scenario_sha256,
        )
        segments = self.segment_references(manifest)
        for segment in segments:
            self._validate_file(segment.relative_path, segment.size, segment.sha256)
        for head in manifest.participant_heads:
            self._validate_file(head.relative_path, head.size, head.sha256)
        return CheckpointRecovery(
            checkpoint_directory=directory.relative_to(self.workspace).as_posix(),
            manifest=manifest,
            segments=segments,
        )

    def read_head(self, recovery: CheckpointRecovery, owner: str) -> bytes:
        """Read and revalidate one bounded participant head."""

        head = next(
            (item for item in recovery.manifest.participant_heads if item.owner == owner),
            None,
        )
        if head is None:
            raise CheckpointCorruptionError(f"checkpoint has no participant head for {owner!r}")
        return self._validate_file(head.relative_path, head.size, head.sha256)

    def read_segment(self, reference: SegmentReference) -> bytes:
        """Read, validate, and decode one immutable participant segment payload."""

        encoded = self._validate_file(reference.relative_path, reference.size, reference.sha256)
        if not encoded.startswith(_SEGMENT_MAGIC):
            raise CheckpointCorruptionError("checkpoint segment magic is invalid")
        offset = len(_SEGMENT_MAGIC)
        metadata_size = int.from_bytes(encoded[offset : offset + 8], "big")
        offset += 8
        metadata_end = offset + metadata_size
        if metadata_end > len(encoded):
            raise CheckpointCorruptionError("checkpoint segment metadata is truncated")
        try:
            metadata = json.loads(encoded[offset:metadata_end])
        except json.JSONDecodeError as error:
            raise CheckpointCorruptionError("checkpoint segment metadata is invalid") from error
        if not isinstance(metadata, dict):
            raise CheckpointCorruptionError("checkpoint segment metadata must be an object")
        expected = {
            "codec": reference.codec,
            "compression": reference.compression,
            "owner": reference.owner,
            "record_count": reference.record_count,
            "schema_version": reference.schema_version,
        }
        for key, value in expected.items():
            if metadata.get(key) != value:
                raise CheckpointCorruptionError(f"checkpoint segment {key} changed")
        body = encoded[metadata_end:]
        try:
            payload = body if reference.compression == "none" else zlib.decompress(body)
        except zlib.error as error:
            raise CheckpointCorruptionError("checkpoint segment compression is corrupt") from error
        if len(payload) != metadata.get("uncompressed_size") or _sha256(payload) != metadata.get(
            "payload_sha256"
        ):
            raise CheckpointCorruptionError("checkpoint segment payload failed validation")
        return payload

    def read_resolved_scenario(self, recovery: CheckpointRecovery) -> bytes:
        """Read the authoritative self-contained resolved input."""

        path = self._object_path(recovery.manifest.resolved_scenario_relative_path)
        return self._validate_file(
            recovery.manifest.resolved_scenario_relative_path,
            path.stat().st_size,
            recovery.manifest.resolved_scenario_sha256,
        )

    def resolved_scenario_path(self, recovery: CheckpointRecovery) -> Path:
        """Return the validated authoritative resolved input path for checkpoint-only resume."""

        self.read_resolved_scenario(recovery)
        return self._object_path(recovery.manifest.resolved_scenario_relative_path)

    def remove_workspace(self) -> None:
        """Remove checkpoint infrastructure after successful bundle publication."""

        if not self.workspace.exists():
            return
        self._validate_protected_directory(self.workspace)
        shutil.rmtree(self.workspace)
