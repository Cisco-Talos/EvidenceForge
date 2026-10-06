"""Replay actual publication calls into a separate file/namespace durability model."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.studio import state_io
from tests.support.checkpoint_power_loss import PowerLossModel, StorageEvent


@pytest.mark.parametrize("defect", ["none", "missing-file-flush", "missing-namespace-flush"])
@pytest.mark.parametrize("publication", ["write", "copy"])
def test_actual_atomic_publication_has_durable_bytes_before_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
    publication: str,
) -> None:
    model = PowerLossModel()
    target = tmp_path / "state.json"
    old, new = b"original-state", b"verified-new-state"
    target.write_bytes(old)
    source = tmp_path / "source.json"
    source.write_bytes(new)
    for event in (
        StorageEvent("create", "state.json"),
        StorageEvent("write", "state.json", payload=old),
        StorageEvent("flush", "state.json"),
    ):
        model.apply(event)
    model.durable_namespace = model.namespace.copy()
    model.pending_namespace.clear()
    files: dict[int, str] = {}
    captured: list[dict[str, bytes]] = []

    def capture() -> None:
        for profile in ("drop", "all", "reverse", "partial", "torn"):
            captured.append(model.crash(profile).files)

    original_write = os.write

    def write(descriptor: int, content: Any) -> int:
        written = original_write(descriptor, content)
        if descriptor in files:
            model.apply(StorageEvent("write", files[descriptor], payload=bytes(content[:written])))
            capture()
        return written

    monkeypatch.setattr(os, "write", write)

    if os.name == "nt":
        from evidenceforge.utils import windows_filesystem as filesystem

        original_open = filesystem.open_child
        original_flush = filesystem.flush_file
        original_replace = filesystem.replace_child

        def open_child(parent: int, name: str, flags: int, *args: Any, **kwargs: Any) -> int:
            descriptor = original_open(parent, name, flags, *args, **kwargs)
            if flags & os.O_CREAT and not kwargs.get("directory"):
                files[descriptor] = name
                model.apply(StorageEvent("create", name))
                capture()
            return descriptor

        def flush(descriptor: int) -> None:
            original_flush(descriptor)
            if descriptor in files and defect != "missing-file-flush":
                model.apply(StorageEvent("flush", files[descriptor]))
                capture()

        def replace(first: int, source: str, second: int, destination: str, **kwargs: Any) -> None:
            original_replace(first, source, second, destination, **kwargs)
            model.apply(
                StorageEvent(
                    "rename", source, destination, write_through=defect != "missing-namespace-flush"
                )
            )
            capture()

        monkeypatch.setattr(filesystem, "open_child", open_child)
        monkeypatch.setattr(filesystem, "flush_file", flush)
        monkeypatch.setattr(filesystem, "replace_child", replace)
    else:
        original_open = os.open
        original_flush = os.fsync
        original_replace = os.replace

        def open_file(name: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            descriptor = original_open(name, flags, *args, **kwargs)
            if flags & os.O_CREAT:
                files[descriptor] = str(name)
                model.apply(StorageEvent("create", str(name)))
                capture()
            return descriptor

        def flush(descriptor: int) -> None:
            original_flush(descriptor)
            if descriptor in files:
                if defect != "missing-file-flush":
                    model.apply(StorageEvent("flush", files[descriptor]))
            elif defect != "missing-namespace-flush":
                model.durable_namespace = model.namespace.copy()
                model.pending_namespace.clear()
            capture()

        def replace(source: Any, destination: Any, **kwargs: Any) -> None:
            original_replace(source, destination, **kwargs)
            model.apply(StorageEvent("rename", str(source), str(destination)))
            capture()

        monkeypatch.setattr(os, "open", open_file)
        monkeypatch.setattr(os, "fsync", flush)
        monkeypatch.setattr(os, "replace", replace)
    if publication == "write":
        state_io.atomic_write(target, new)
    else:
        state_io.atomic_copy(target, source)

    def assert_protocol() -> None:
        assert all(image.get("state.json") in (old, new) for image in captured)
        assert model.crash().files["state.json"] == new

    if defect == "none":
        assert_protocol()
    else:
        with pytest.raises(AssertionError):
            assert_protocol()  # Prove the oracle catches weakened durability, not only happy paths.
