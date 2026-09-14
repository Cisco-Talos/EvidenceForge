"""Observe real Windows checkpoint I/O without substituting its implementation."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import local
from typing import Any

import pytest

from tests.support.checkpoint_power_loss import StorageEvent


@contextmanager
def trace_checkpoint_io(
    root: Path, destination: Path, *, on_event: Callable[[StorageEvent], None] | None = None
) -> Iterator[list[StorageEvent]]:
    from evidenceforge.generation.checkpoints.store import IncrementalCheckpointStore
    from evidenceforge.generation.checkpoints.windows_io import WindowsCheckpointIO
    from evidenceforge.utils import windows_filesystem as filesystem

    events: list[StorageEvent] = []
    descriptors: dict[int, str] = {}
    rename_context = local()
    root = root.resolve()
    known_paths = {path.relative_to(root).as_posix() for path in root.rglob("*")}
    with destination.open("w", encoding="utf-8") as trace, pytest.MonkeyPatch.context() as patches:

        def relative(path: Path) -> str | None:
            try:
                return path.resolve().relative_to(root).as_posix()
            except ValueError:
                return None

        def record(event: StorageEvent) -> None:
            if event.operation in {"mkdir", "create"}:
                known_paths.add(event.path)
            elif event.operation == "rename":
                moved = {
                    name
                    for name in known_paths
                    if name == event.path or name.startswith(event.path + "/")
                }
                known_paths.difference_update(moved)
                known_paths.update(event.target + name[len(event.path) :] for name in moved)
            elif event.operation == "unlink":
                known_paths.discard(event.path)
            events.append(event)
            trace.write(json.dumps(event.document(), sort_keys=True) + "\n")
            trace.flush()
            if on_event is not None:
                on_event(event)

        create = WindowsCheckpointIO._create_file
        mkdir = WindowsCheckpointIO._create_directory
        write = WindowsCheckpointIO._write
        flush = WindowsCheckpointIO._flush
        rename = WindowsCheckpointIO._rename
        native_rename = filesystem.replace_child
        unlink = WindowsCheckpointIO.unlink
        commit = IncrementalCheckpointStore.commit
        synchronize = IncrementalCheckpointStore._synchronize_publication

        def observed_create(operations: WindowsCheckpointIO, path: Path, mode: int) -> int:
            descriptor = create(operations, path, mode)
            name = relative(path)
            if name is not None:
                # The CLI recreates disposable staging directories outside the
                # durable checkpoint writer. Record observed new ancestry as
                # volatile; never grant it an invented persistence barrier.
                for parent in reversed(Path(name).parents):
                    parent_name = parent.as_posix()
                    if parent_name != "." and parent_name not in known_paths:
                        record(StorageEvent("mkdir", parent_name))
                descriptors[descriptor] = name
                record(StorageEvent("create", name))
            else:
                descriptors.pop(descriptor, None)
            return descriptor

        def observed_mkdir(operations: WindowsCheckpointIO, path: Path, **kwargs: Any) -> None:
            mkdir(operations, path, **kwargs)
            name = relative(path)
            if name is not None:
                record(StorageEvent("mkdir", name))

        def observed_write(
            operations: WindowsCheckpointIO, descriptor: int, payload: memoryview
        ) -> int:
            count = write(operations, descriptor, payload)
            if descriptor in descriptors:
                record(
                    StorageEvent("write", descriptors[descriptor], payload=bytes(payload[:count]))
                )
            return count

        def observed_flush(operations: WindowsCheckpointIO, descriptor: int) -> None:
            flush(operations, descriptor)
            if descriptor in descriptors:
                record(StorageEvent("flush", descriptors[descriptor]))

        def observed_native_rename(*args: Any, **kwargs: Any) -> None:
            native_rename(*args, **kwargs)
            if getattr(rename_context, "flags", None) is not None:
                rename_context.flags.append(kwargs.get("write_through", False))

        def observed_rename(
            operations: WindowsCheckpointIO, source: Path, target: Path, **kwargs: Any
        ) -> None:
            rename_context.flags = []
            try:
                rename(operations, source, target, **kwargs)
                flags = rename_context.flags
                assert len(flags) == 1
                first, second = relative(source), relative(target)
                if first is not None and second is not None:
                    record(StorageEvent("rename", first, second, write_through=flags[0]))
            finally:
                rename_context.flags = None

        def observed_unlink(operations: WindowsCheckpointIO, path: Path, **kwargs: Any) -> None:
            existed = path.exists()
            unlink(operations, path, **kwargs)
            name = relative(path)
            if existed and name is not None:
                record(StorageEvent("unlink", name))

        def observed_commit(store: IncrementalCheckpointStore, **kwargs: Any) -> Any:
            started = time.monotonic()
            manifest = commit(store, **kwargs)
            if relative(store.output_root) is not None:
                record(
                    StorageEvent(
                        "ack",
                        sequence=manifest.sequence,
                        elapsed_seconds=time.monotonic() - started,
                    )
                )
            return manifest

        def observed_stage(store: IncrementalCheckpointStore, stage: str, sequence: int) -> None:
            record(StorageEvent("stage", stage=stage, sequence=sequence))
            synchronize(store, stage, sequence)

        patches.setattr(WindowsCheckpointIO, "_create_file", observed_create)
        patches.setattr(WindowsCheckpointIO, "_create_directory", observed_mkdir)
        patches.setattr(WindowsCheckpointIO, "_write", observed_write)
        patches.setattr(WindowsCheckpointIO, "_flush", observed_flush)
        patches.setattr(WindowsCheckpointIO, "_rename", observed_rename)
        patches.setattr(filesystem, "replace_child", observed_native_rename)
        patches.setattr(WindowsCheckpointIO, "unlink", observed_unlink)
        patches.setattr(IncrementalCheckpointStore, "commit", observed_commit)
        patches.setattr(IncrementalCheckpointStore, "_synchronize_publication", observed_stage)
        yield events
