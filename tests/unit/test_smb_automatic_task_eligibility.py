# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Ordinary task policy selects compatible files without restricting explicit intent."""

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import SmbProcessProfile
from evidenceforge.generation.actions.smb_activity import (
    SmbActivityActionBundle,
    SmbActivityRequest,
)
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.storage_world import (
    CompiledStorageFile,
    CompiledStorageMapping,
    StorageWorldModel,
)
from evidenceforge.models.scenario import (
    SmbActivityEventSpec,
    SmbFileSelector,
    SmbShareLocation,
    System,
    User,
)


def _process(extensions: tuple[str, ...] | None = (".txt", ".csv")) -> SmbProcessProfile:
    return SmbProcessProfile(
        key_template="reader",
        image="/bin/cat",
        command_line_template='cat "{client_path}"',
        username_template="{username}",
        lifecycle="operation",
        automatic_file_extensions=extensions,
    )


def _bundle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    extensions: tuple[str, ...] | None = (".txt", ".csv"),
    **updates: Any,
) -> tuple[SmbActivityActionBundle, Mock]:
    files = tuple(
        CompiledStorageFile(
            file_id=str(i),
            share="FS.team",
            path=path,
            size_bytes=size,
            mime_type="application/octet-stream",
            tags=("review",),
        )
        for i, (path, size) in enumerate(
            [
                ("Reports\\plan.txt", 900),
                ("Reports\\plan.docx", 2000),
                ("Archive\\metrics.csv", 400),
            ]
        )
    )
    share = SimpleNamespace(
        ref="FS.team", name="Team", system="FS", preset="collaboration", files=files
    )
    mapping = CompiledStorageMapping(
        id="team",
        share="FS.team",
        users={"alice"},
        systems={"MAC"},
        mount="/Volumes/team",
        lifecycle="persistent",
    )
    world = StorageWorldModel(volumes=(), shares=(share,), mappings=(mapping,))
    server = System(hostname="FS", ip="10.0.0.20", os="Windows Server 2022", type="server")
    available = Mock(return_value=True)
    executor = SimpleNamespace(
        _storage_world=world,
        state_manager=SimpleNamespace(smb_file_is_available=available),
        _system_for_hostname=lambda _name: server,
    )
    spec = SmbActivityEventSpec(
        type="smb_activity", operation="read", target=SmbShareLocation(share="FS.team"), **updates
    )
    request = SmbActivityRequest(
        spec=spec,
        actor=User(username="alice", full_name="Alice", email="alice@example.test"),
        parent_system=System(hostname="MAC", ip="10.0.0.10", os="macOS 27", type="workstation"),
        time=datetime(2026, 11, 2, 13, tzinfo=UTC),
        activity_source="baseline",
    )
    bundle = SmbActivityActionBundle(executor, request)
    profile = SimpleNamespace(automatic_file_extensions=extensions)
    monkeypatch.setattr(bundle, "_client_operation_profile", Mock(return_value=(object(), profile)))
    return bundle, available


def test_policy_intersects_existing_selector_and_preserves_other_criteria(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, available = _bundle(monkeypatch)
    location = bundle.request.spec.target.model_copy(
        update={
            "selector": SmbFileSelector(
                extensions=["txt", "docx"],
                path_glob="Reports/*",
                tags_any=["review"],
                min_size_bytes=500,
            )
        }
    )
    bundle.request = replace(
        bundle.request, spec=bundle.request.spec.model_copy(update={"target": location})
    )
    refined = bundle.automatic_task_spec()
    assert refined is not None and refined.target.selector.extensions == [".txt"]
    assert refined.target.selector.path_glob == "Reports/*"
    assert refined.target.selector.tags_any == ["review"]
    assert refined.target.selector.min_size_bytes == 500
    assert [
        file.path for file in bundle.world.select("FS.team", selector=refined.target.selector)
    ] == ["Reports\\plan.txt"]
    assert available.call_count == 1


def test_empty_intersection_and_unavailable_files_skip_without_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, available = _bundle(monkeypatch, extensions=(".pdf",))
    assert bundle.automatic_task_spec() is None
    available.assert_not_called()
    bundle, available = _bundle(monkeypatch)
    available.return_value = False
    assert bundle.automatic_task_spec() is None
    assert available.call_count == 2


@pytest.mark.parametrize("explicit", ["path", "file_ref", "storyline", "override", "legacy"])
def test_explicit_binary_and_legacy_requests_remain_authoritative(
    monkeypatch: pytest.MonkeyPatch, explicit: str
) -> None:
    bundle, available = _bundle(monkeypatch, extensions=None if explicit == "legacy" else (".txt",))
    if explicit in {"path", "file_ref"}:
        location = bundle.request.spec.target.model_copy(
            update={explicit: "Reports\\plan.docx" if explicit == "path" else "binary"}
        )
        bundle.request = replace(
            bundle.request, spec=bundle.request.spec.model_copy(update={"target": location})
        )
    elif explicit == "storyline":
        bundle.request = replace(bundle.request, activity_source="storyline")
    elif explicit == "override":
        bundle.request = replace(
            bundle.request, files_override=(bundle.world.share("FS.team").files[1],)
        )
    assert bundle.automatic_task_spec() is bundle.request.spec
    available.assert_not_called()


def test_eligible_share_filter_precedes_dc_preference_and_preserves_write_policy() -> None:
    actor = User(username="alice", full_name="Alice", email="alice@example.test")
    client = System(hostname="MAC", ip="10.0.0.10", os="macOS 27", type="workstation")
    shares = [
        SimpleNamespace(ref="DC.policy", preset="dc_policy"),
        SimpleNamespace(ref="FS.binary", preset="collaboration"),
        SimpleNamespace(ref="FS.text", preset="collaboration"),
    ]
    calls: list[tuple[str, str]] = []

    def admit(**kwargs: Any) -> SmbActivityEventSpec | None:
        spec = kwargs["spec"]
        calls.append((spec.target.share, spec.operation))
        return spec if spec.target.share == "FS.text" else None

    baseline = SimpleNamespace(activity_generator=SimpleNamespace(automatic_smb_task_spec=admit))
    tasks = BaselineMixin._eligible_baseline_smb_tasks(
        baseline,
        shares=shares,
        actor=actor,
        system=client,
        time=datetime(2026, 11, 2, 13, tzinfo=UTC),
        operation_profile="write",
    )
    assert [(share.ref, spec.operation) for share, spec in tasks] == [("FS.text", "update")]
    assert calls == [("DC.policy", "read"), ("FS.binary", "update"), ("FS.text", "update")]


@pytest.mark.parametrize("extensions", [(), ("txt",), (".txt", ".TXT"), (".bad/path",), ("",)])
def test_malformed_task_extensions_are_rejected(extensions: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError, match="automatic_file_extensions"):
        _process(extensions)


def test_task_extensions_normalize_and_missing_field_is_unrestricted() -> None:
    assert _process((".TXT", ".Csv")).automatic_file_extensions == (".txt", ".csv")
    data = _process().model_dump()
    data.pop("automatic_file_extensions")
    assert SmbProcessProfile.model_validate(data).automatic_file_extensions is None
