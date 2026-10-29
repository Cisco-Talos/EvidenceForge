# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented Finder intents qualify relationships without inventing native exec inputs."""

from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.config.schemas import MacosExecutionMetadataProfile
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.activity.macos_execution_metadata import (
    load_macos_execution_metadata_profile,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import resolve_time_window
from tests.unit.test_macos_installed_provisioning import _scenario

_APP = "/Applications/InventedReference.app/Contents/MacOS/InventedReference"


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[GenerationEngine]:
    instance = GenerationEngine(_scenario(), tmp_path / "run", generation_seed=345)
    try:
        instance._initialize()
        yield instance
    finally:
        instance._close_emitters()


def _request(engine: GenerationEngine | None = None) -> ProcessExecutionRequest:
    scenario = engine.scenario if engine is not None else _scenario()
    system = next(s for s in scenario.environment.systems if s.hostname == "MAC-01")
    user = next(u for u in scenario.environment.users if u.username == "alex")
    start = (
        engine.start_time if engine is not None else resolve_time_window(scenario.time_window)[0]
    )
    at = start + timedelta(minutes=10)
    logon = (
        engine.activity_generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        if engine is not None
        else "invented-login"
    )
    return ProcessExecutionRequest(
        user=user,
        system=system,
        time=at + timedelta(seconds=5),
        logon_id=logon,
        process_name=_APP,
        command_line=_APP,
        parent_pid=1,
        require_exact_parent=True,
        arguments=(_APP,),
        macos_launch_kind="finder",
        allow_existing_browser_reuse=False,
        allow_browser_launch_spacing=False,
        from_storyline=True,
    )


def test_relationship_producer_consumes_exact_gui_and_boot_owners_without_mutation(
    engine: GenerationEngine,
) -> None:
    request = _request(engine)
    state = engine.state_manager
    before = state.materialization_digest()
    relationship = engine.macos_execution_metadata.finder_launch_relationships(
        state,
        request.system.hostname,
        request.user.username,
        parent_pid=1,
        logon_id=request.logon_id,
        at=request.time,
        credentials=PosixProcessCredentials(501, 501, 20, 20),
    )
    assert relationship.parent == state.get_process_identity_at("MAC-01", 1, request.time)
    assert relationship.parent.image == "/sbin/launchd"
    assert relationship.responsibility.responsible is None
    origin = state.get_session(request.logon_id).audit_origin
    assert relationship.credentials.audit_uid == origin.audit_uid
    assert relationship.credentials.audit_session_id == origin.audit_session_id
    assert state.materialization_digest() == before


@pytest.mark.parametrize(
    "damage", ["profile", "audit_profile", "parent", "session", "time", "credentials", "foreign"]
)
def test_unqualified_relationships_fail_before_allocation(
    engine: GenerationEngine, damage: str
) -> None:
    request = _request(engine)
    state = engine.state_manager
    provider = engine.macos_execution_metadata
    if damage in {"profile", "audit_profile"}:
        key = "finder_launch_relationships" if damage == "profile" else "gui_audit_origin"
        provider.profile = provider.profile.model_copy(update={key: None})
    credentials = PosixProcessCredentials(501, 501, 20, 20)
    if damage == "foreign":
        credentials = replace(credentials, audit_uid=501, audit_session_id=2**32 - 1)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="Finder launch|foreign audit"):
        provider.finder_launch_relationships(
            state,
            request.system.hostname,
            request.user.username,
            parent_pid=404 if damage == "parent" else 1,
            logon_id="missing-session" if damage == "session" else request.logon_id,
            at=engine.end_time if damage == "time" else request.time,
            credentials=None if damage == "credentials" else credentials,
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize(
    "changes",
    [
        {"parent_pid": 2},
        {"parent_pid": True},
        {"process_name": _APP.lstrip("/")},
        {"process_name": _APP + "/helper"},
        {"arguments": ("arbitrary-argv-zero",), "command_line": "arbitrary-argv-zero"},
        {
            "process_name": "/usr/bin/id",
            "command_line": "/usr/bin/id",
            "arguments": ("/usr/bin/id",),
        },
        {"macos_standard_io": "null"},
        {"macos_terminal": "absent", "new_posix_session": True},
        {"arguments": None},
        {"require_exact_parent": False},
    ],
)
def test_finder_selector_requires_a_fresh_literal_bundle_and_separate_unknowns(
    changes: dict[str, object],
) -> None:
    request = _request()
    with pytest.raises(ValueError, match="Finder relationship|Modeled Mac launch"):
        replace(request, **changes)


def test_explicit_finder_process_uses_canonical_relationships_and_preserves_unknowns(
    engine: GenerationEngine,
) -> None:
    request = _request(engine)
    provider = engine.macos_execution_metadata
    provider.profile = provider.profile.model_copy(update={"finder_launch_execution": None})
    generator = engine.activity_generator
    pid = generator.generate_process(
        request.user,
        request.system,
        request.time,
        request.logon_id,
        request.process_name,
        request.command_line,
        parent_pid=request.parent_pid,
        require_exact_parent=True,
        arguments=request.arguments,
        macos_launch_kind="finder",
        allow_existing_browser_reuse=False,
        allow_browser_launch_spacing=False,
        from_storyline=True,
    )
    assert pid > 1
    state = engine.state_manager
    process = state.get_process_identity("MAC-01", pid)
    origin = state.get_session(request.logon_id).audit_origin
    assert process.parent_pid == process.parentage.original_pid == 1
    assert process.responsibility is not None and process.responsibility.responsible is None
    assert process.credentials.audit_uid == origin.audit_uid
    assert process.credentials.audit_session_id == origin.audit_session_id
    assert process.arguments == (_APP,)
    # No exec vector is reconstructed from a display command or runtime snapshot.
    assert process.environment is process.execution_directory is process.exec_image is None
    assert process.exec_script is process.image_security is None
    assert state.process_descriptors_at(process, event_time=request.time) is None
    # This slice has aggregate canonical birth semantics, not a fabricated fork/exec.
    assert process.execution_ordinal == 0
    assert process.executed_at is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity("MAC-01", pid) == process
    assert restored.get_session(request.logon_id).audit_origin == origin


def test_generic_user_launch_does_not_acquire_finder_responsibility(
    engine: GenerationEngine,
) -> None:
    request = _request(engine)
    pid = engine.activity_generator.generate_process(
        request.user,
        request.system,
        request.time,
        request.logon_id,
        request.process_name,
        request.command_line,
        parent_pid=1,
        require_exact_parent=True,
        arguments=request.arguments,
        macos_launch_kind="user",
        allow_existing_browser_reuse=False,
        allow_browser_launch_spacing=False,
    )
    process = engine.state_manager.get_process_identity("MAC-01", pid)
    assert process.responsibility is None
    assert process.environment is not None  # Existing explicit clean-launch semantics.


def test_finder_intent_has_distinct_identity_and_legacy_profiles_remain_unknown() -> None:
    request = _request()
    assert request.stable_id != replace(request, macos_launch_kind="user").stable_id
    profile = load_macos_execution_metadata_profile().model_dump(mode="json")
    profile.pop("finder_launch_relationships")
    restored = MacosExecutionMetadataProfile.model_validate(profile)
    assert restored.finder_launch_relationships is None
