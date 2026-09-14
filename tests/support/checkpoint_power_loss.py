"""Test-only file/namespace persistence model, independent of checkpoint schemas.

Directory entries are keyed by parent object identity, not by pathname. Moving a
directory therefore cannot accidentally flush its children's dirty entries. A
file flush makes bytes durable; an NTFS write-through rename makes only the
affected namespace mutation durable. Storage is assumed to honor those requests.
"""

from __future__ import annotations

import base64
import json
import random
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal


@dataclass(frozen=True)
class StorageEvent:
    operation: Literal["create", "mkdir", "write", "flush", "rename", "unlink", "ack", "stage"]
    path: str = ""
    target: str = ""
    payload: bytes = b""
    write_through: bool = False
    sequence: int = -1
    stage: str = ""
    elapsed_seconds: float = 0.0

    def document(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "path": self.path,
            "target": self.target,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "write_through": self.write_through,
            "sequence": self.sequence,
            "stage": self.stage,
            "elapsed_seconds": self.elapsed_seconds,
        }

    @classmethod
    def from_document(cls, value: dict) -> StorageEvent:
        return cls(**(value | {"payload": base64.b64decode(value["payload"])}))


@dataclass(frozen=True)
class CrashImage:
    files: dict[str, bytes]
    directories: tuple[str, ...]
    acknowledged_sequence: int

    def materialize(self, root: Path) -> None:
        """Create a new storage image; never restore in a running writer's tree."""
        import os

        if os.name == "nt":
            from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO

            operations = WindowsCheckpointIO()
            operations.mkdir(root, parents=True, exist_ok=True)
        else:
            root.mkdir(parents=True, exist_ok=True)
        # This synthesizes the model's surviving disk state, not a second
        # publication protocol. Windows children inherit the private root ACL.
        for name in self.directories:
            (root / name).mkdir(parents=True, exist_ok=True)
        for name, payload in self.files.items():
            (root / name).write_bytes(payload)


@dataclass
class PowerLossModel:
    """Replay actual I/O requests into separate volatile and stable storage state."""

    namespace: dict[tuple[int, str], int] = field(default_factory=dict)
    durable_namespace: dict[tuple[int, str], int] = field(default_factory=dict)
    data: dict[int, bytes] = field(default_factory=dict)
    durable_data: dict[int, bytes] = field(default_factory=dict)
    directories: set[int] = field(default_factory=lambda: {0})
    pending_namespace: list[dict[tuple[int, str], int | None]] = field(default_factory=list)
    acknowledged_sequence: int = -1
    next_id: int = 1

    @classmethod
    def from_image(cls, image: CrashImage) -> PowerLossModel:
        """Start a second crash experiment from the first one's surviving state."""
        model = cls()
        for path in image.directories:
            model.apply(StorageEvent("mkdir", path))
        for path, payload in image.files.items():
            model.apply(StorageEvent("create", path))
            model.apply(StorageEvent("write", path, payload=payload))
            model.apply(StorageEvent("flush", path))
        model.durable_namespace = model.namespace.copy()
        model.pending_namespace.clear()
        model.acknowledged_sequence = image.acknowledged_sequence
        return model

    def _key(self, path: str) -> tuple[int, str]:
        parts = PurePosixPath(path).parts
        assert parts and not PurePosixPath(path).is_absolute() and ".." not in parts
        parent = 0
        for part in parts[:-1]:
            parent = self.namespace[parent, part]
            assert parent in self.directories
        return parent, parts[-1]

    @staticmethod
    def _change(
        namespace: dict[tuple[int, str], int], changes: dict[tuple[int, str], int | None]
    ) -> None:
        for key, value in changes.items():
            if value is None:
                namespace.pop(key, None)
            else:
                namespace[key] = value

    def apply(self, event: StorageEvent) -> None:
        if event.operation == "ack":
            assert event.sequence > self.acknowledged_sequence
            self.acknowledged_sequence = event.sequence
            return
        if event.operation == "stage":
            return
        key = self._key(event.path)
        if event.operation in {"create", "mkdir"}:
            assert key not in self.namespace
            identity = self.next_id
            self.next_id += 1
            if event.operation == "mkdir":
                self.directories.add(identity)
            else:
                self.data[identity] = b""
            changes = {key: identity}
        elif event.operation == "write":
            identity = self.namespace[key]
            self.data[identity] += event.payload
            return
        elif event.operation == "flush":
            identity = self.namespace[key]
            self.durable_data[identity] = self.data[identity]
            return
        elif event.operation == "rename":
            changes = {key: None, self._key(event.target): self.namespace[key]}
        elif event.operation == "unlink":
            changes = {key: None}
        else:
            raise AssertionError(event.operation)
        self._change(self.namespace, changes)
        if event.operation == "rename" and event.write_through:
            self._change(self.durable_namespace, changes)
            # The synchronous mutation supersedes older dirty operations on
            # these same entries, but never flushes descendants or file data.
            self.pending_namespace = [
                remaining
                for pending in self.pending_namespace
                if (
                    remaining := {
                        key: value for key, value in pending.items() if key not in changes
                    }
                )
            ]
        else:
            self.pending_namespace.append(changes)

    def crash(self, profile: str = "drop", *, sector_size: int = 512) -> CrashImage:
        """Lose volatile state, optionally persisting reordered or torn dirty writes."""
        assert profile in {"drop", "all", "reverse", "partial", "torn"}
        namespace = self.durable_namespace.copy()
        contents = self.durable_data.copy()
        pending = list(self.pending_namespace)
        rng = random.Random(415)
        if profile == "reverse":
            pending.reverse()
        elif profile in {"partial", "torn"}:
            rng.shuffle(pending)
            pending = [change for change in pending if rng.getrandbits(1)]
        if profile != "drop":
            for change in pending:
                self._change(namespace, change)
            for identity, volatile in self.data.items():
                durable = contents.get(identity, b"")
                if volatile == durable:
                    continue
                if profile in {"all", "reverse"}:
                    contents[identity] = volatile
                elif profile == "partial":
                    if rng.getrandbits(1):
                        contents[identity] = volatile
                else:
                    result = bytearray(durable.ljust(len(volatile), b"\x00"))
                    for offset in range(0, len(volatile), sector_size):
                        if (offset // sector_size) % 2 == 0:
                            result[offset : offset + sector_size] = volatile[
                                offset : offset + sector_size
                            ]
                    contents[identity] = bytes(result)
        files: dict[str, bytes] = {}
        directories: list[str] = []

        def visit(parent: int, path: str, ancestors: frozenset[int]) -> None:
            assert parent not in ancestors, "namespace cycle"
            children = sorted(
                (name, node) for (owner, name), node in namespace.items() if owner == parent
            )
            for name, node in children:
                child = f"{path}/{name}" if path else name
                if node in self.directories:
                    directories.append(child)
                    visit(node, child, ancestors | {parent})
                else:
                    files[child] = contents.get(node, b"")

        visit(0, "", frozenset())
        return CrashImage(files, tuple(directories), self.acknowledged_sequence)


def read_trace(path: Path) -> list[StorageEvent]:
    return [StorageEvent.from_document(json.loads(line)) for line in path.read_text().splitlines()]
