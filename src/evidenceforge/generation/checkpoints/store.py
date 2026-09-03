"""Content-addressed storage and atomic publication for incremental checkpoints."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import time
import uuid
import zlib
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
    CheckpointStoreMetrics,
    ParticipantHead,
    SegmentReference,
)

_SEGMENT_MAGIC = b"EFORGE-SEGMENT\x00\x01"
_WORKSPACE_NAME = ".eforge-generation"
_MANIFEST_NAME = "manifest.json"
_INDEX_NAME = "CURRENT.json"
_LOCK_NAME = "run.lock"


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
            raw = self.path.read_bytes()
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as error:
            raise CheckpointLockError(
                "generation output has an unreadable lock; inspect it before reclaiming"
            ) from error
        if not isinstance(value, dict):
            raise CheckpointLockError("generation output lock has an invalid owner record")
        return value

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

    def __init__(self, output_root: Path) -> None:
        self.output_root = Path(output_root).resolve()
        self.workspace = self.output_root / _WORKSPACE_NAME
        self.objects = self.workspace / "objects"
        self.recovery = self.workspace / "recovery"
        self.index_path = self.workspace / _INDEX_NAME
        self.lock = RunLock(self.workspace)
        self._initialized = False

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

    def _validate_output_root(self) -> None:
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
    def _encode_segment(
        draft: SegmentDraft,
        metrics: CheckpointStoreMetrics | None = None,
    ) -> tuple[bytes, str]:
        if draft.record_count < 0:
            raise ValueError("segment record_count cannot be negative")
        encode_started = time.perf_counter()
        compression_seconds = 0.0
        hashing_seconds = 0.0
        if draft.compression == "none":
            body = draft.payload
        elif draft.compression == "zlib-1":
            compression_started = time.perf_counter()
            body = zlib.compress(draft.payload, level=1)
            compression_seconds = time.perf_counter() - compression_started
            if metrics is not None:
                metrics.compression_seconds += compression_seconds
        else:
            raise ValueError(f"unsupported segment compression: {draft.compression!r}")
        payload_hash_started = time.perf_counter()
        payload_digest = _sha256(draft.payload)
        hashing_seconds += time.perf_counter() - payload_hash_started
        if metrics is not None:
            metrics.bytes_hashed += len(draft.payload)
            metrics.hashing_seconds += hashing_seconds
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
        encoded_hash_started = time.perf_counter()
        digest = _sha256(encoded)
        encoded_hash_seconds = time.perf_counter() - encoded_hash_started
        hashing_seconds += encoded_hash_seconds
        if metrics is not None:
            metrics.bytes_hashed += len(encoded)
            metrics.hashing_seconds += encoded_hash_seconds
            metrics.segment_encode_seconds += max(
                0.0,
                time.perf_counter() - encode_started - compression_seconds - hashing_seconds,
            )
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
        inherited_segments: tuple[SegmentReference, ...],
        new_segments: tuple[SegmentDraft, ...],
        heads: tuple[HeadDraft, ...],
        metadata: dict[str, Any] | None = None,
        metrics: CheckpointStoreMetrics | None = None,
    ) -> CheckpointManifest:
        """Atomically publish one recovery manifest over shared immutable objects."""

        if checkpoint_hours <= 0:
            raise ValueError("checkpoint publication requires a positive cadence")
        self.initialize()
        store_started = time.perf_counter()
        accounting = metrics or CheckpointStoreMetrics()
        inherited_by_digest = {segment.sha256: segment for segment in inherited_segments}
        segment_refs = list(inherited_segments)
        next_owner_ordinal: dict[str, int] = {}
        for segment in inherited_segments:
            next_owner_ordinal[segment.owner] = max(
                next_owner_ordinal.get(segment.owner, 0),
                segment.owner_ordinal + 1,
            )
        accounting.reused_segment_bytes = sum(segment.size for segment in inherited_segments)
        segment_started = time.perf_counter()
        for draft in new_segments:
            encoded, digest = self._encode_segment(draft, accounting)
            if digest in inherited_by_digest:
                raise ValueError(
                    f"participant {draft.owner!r} attempted to reseal an inherited segment"
                )
            relative, created = self._write_content_object(
                category="segments",
                digest=digest,
                suffix=".seg",
                payload=encoded,
            )
            if created:
                accounting.new_segment_bytes += len(encoded)
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
        accounting.segment_write_seconds = time.perf_counter() - segment_started

        if resolved_scenario_reference is None:
            resolved_hash_started = time.perf_counter()
            resolved_digest = _sha256(resolved_scenario)
            accounting.bytes_hashed += len(resolved_scenario)
            accounting.hashing_seconds += time.perf_counter() - resolved_hash_started
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
            raise CheckpointFilesystemError(f"checkpoint sequence already exists: {sequence}")
        pending.mkdir(mode=0o700)
        head_refs: list[ParticipantHead] = []
        try:
            heads_directory = pending / "heads"
            heads_directory.mkdir(mode=0o700)
            head_started = time.perf_counter()
            for head in sorted(heads, key=lambda item: item.owner):
                filename = f"{head.owner}.bin"
                path = heads_directory / filename
                head_hash_started = time.perf_counter()
                digest = _sha256(head.payload)
                accounting.bytes_hashed += len(head.payload)
                accounting.hashing_seconds += time.perf_counter() - head_hash_started
                accounting.head_bytes += len(head.payload)
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
            accounting.head_write_seconds = time.perf_counter() - head_started
            manifest = CheckpointManifest(
                sequence=sequence,
                run_id=run_id,
                run_fingerprint=run_fingerprint,
                checkpoint_hours=checkpoint_hours,
                cursor=cursor,
                resolved_scenario_sha256=resolved_digest,
                resolved_scenario_relative_path=resolved_path,
                segments=tuple(segment_refs),
                participant_heads=tuple(head_refs),
                metadata={} if metadata is None else metadata,
            )
            manifest_payload = _canonical_json(manifest.model_dump(mode="json"))
            accounting.manifest_bytes = len(manifest_payload)
            manifest_started = time.perf_counter()
            _write_new_file(pending / _MANIFEST_NAME, manifest_payload)
            _sync_directory(pending)
            accounting.manifest_write_seconds = time.perf_counter() - manifest_started
            publish_started = time.perf_counter()
            os.replace(pending, final)
            _sync_directory(self.recovery)
            accounting.atomic_publish_seconds = time.perf_counter() - publish_started
            index_started = time.perf_counter()
            self._publish_index(manifest, manifest_payload)
            accounting.index_publish_seconds = time.perf_counter() - index_started
            rotation_started = time.perf_counter()
            self._rotate_recoveries()
            accounting.rotation_seconds = time.perf_counter() - rotation_started
            accounting.commit_seconds = time.perf_counter() - store_started
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
            retained_paths.update(segment.relative_path for segment in manifest.segments)
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

    def recover(self, *, expected_fingerprint: str | None = None) -> CheckpointRecovery:
        """Return the newest valid recovery point, falling back once on corruption."""

        self.initialize()
        failures: list[str] = []
        entries = self._read_index()
        for index, (sequence, manifest_sha256) in enumerate(entries):
            directory = self.recovery / f"{sequence:020d}"
            try:
                manifest = self._load_manifest(
                    directory,
                    expected_sha256=manifest_sha256,
                )
                if expected_fingerprint is not None and (
                    manifest.run_fingerprint != expected_fingerprint
                ):
                    raise CheckpointCompatibilityError(
                        "checkpoint fingerprint does not match the resolved scenario and runtime"
                    )
                self._validate_file(
                    manifest.resolved_scenario_relative_path,
                    self._object_path(manifest.resolved_scenario_relative_path).stat().st_size,
                    manifest.resolved_scenario_sha256,
                )
                for segment in manifest.segments:
                    self._validate_file(segment.relative_path, segment.size, segment.sha256)
                for head in manifest.participant_heads:
                    self._validate_file(head.relative_path, head.size, head.sha256)
                warning = None
                if failures:
                    warning = (
                        "newest generation checkpoint was corrupt; using previous recovery point: "
                        + "; ".join(failures)
                    )
                return CheckpointRecovery(
                    checkpoint_directory=directory.relative_to(self.workspace).as_posix(),
                    manifest=manifest,
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
