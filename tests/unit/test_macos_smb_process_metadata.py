# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbClientProcessPreparation,
)


def _recipe() -> PersistentSmbClientProcessPreparation:
    return PersistentSmbClientProcessPreparation(
        disposition="materialize",
        hostname="MAC-TEST",
        process_object_id="",
        pid=0,
        parent_pid=1,
        parent_object_id="parent-test",
        image="/usr/bin/head",
        command_line="/usr/bin/head /Volumes/team/plan.txt",
        username="alex",
        logon_id="session-test",
        session_object_id="session-object-test",
        session_id=7,
        logon_type=2,
        started_at=datetime(2026, 10, 16, tzinfo=UTC),
        lifecycle_group_id="smb-group-test",
        os_category="macos",
        integrity_level="Medium",
        access_mode="mounted",
        path_style="posix",
        transport_attribution="none",
        lifecycle="operation",
    )


@pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
def test_legacy_smb_process_recipe_retains_21_field_identity(platform: str) -> None:
    recipe = replace(_recipe(), os_category=platform)
    snapshot = recipe.identity_snapshot()
    assert len(snapshot) == 21
    assert snapshot == tuple(getattr(recipe, field) for field in recipe.__dataclass_fields__)[:21]
    assert PersistentSmbClientProcessPreparation.from_identity_snapshot(snapshot) == recipe


@pytest.mark.parametrize("kind", ["credentials", "installed", "runtime", "both"])
def test_mac_smb_process_facts_roundtrip_as_scalar_retry_identity(kind: str) -> None:
    recipe = _recipe()
    if kind in {"credentials", "both"}:
        recipe = replace(recipe, credentials=PosixProcessCredentials(501, 501, 20, 20, 501, 17))
    if kind in {"installed", "both"}:
        recipe = replace(
            recipe, executable_version=ProcessExecutableVersion("macos", "installed_release", "c1")
        )
    if kind == "runtime":
        recipe = replace(
            recipe,
            executable_version=ProcessExecutableVersion("macos", "local_artifact", "c1", "v1"),
        )
    snapshot = recipe.identity_snapshot()
    assert len(snapshot) == 23
    assert all(item is None or type(item) is tuple for item in snapshot[21:])
    assert PersistentSmbClientProcessPreparation.from_identity_snapshot(snapshot) == recipe
    assert snapshot != _recipe().identity_snapshot()


@pytest.mark.parametrize(
    "tail",
    [
        (None, None),
        ((501, 501, 20), None),
        ((True, 501, 20, 20, None, None), None),
        (None, ("macos", "installed_release", "c1")),
        (None, ("linux", "installed_release", "c1", None)),
        (None, ("macos", "local_artifact", "c1", None)),
    ],
)
def test_mac_smb_rejects_malformed_metadata_snapshot(tail: tuple[object, ...]) -> None:
    with pytest.raises((TypeError, ValueError)):
        PersistentSmbClientProcessPreparation.from_identity_snapshot(
            _recipe().identity_snapshot() + tail
        )


def test_smb_metadata_cannot_attach_to_actorless_or_other_platform_recipe() -> None:
    credentials = PosixProcessCredentials(501, 501, 20, 20)
    with pytest.raises(ValueError):
        replace(PersistentSmbClientProcessPreparation.none(), credentials=credentials)
    with pytest.raises(ValueError):
        replace(_recipe(), os_category="linux", credentials=credentials)
    with pytest.raises(ValueError):
        replace(
            _recipe(),
            os_category="windows",
            executable_version=ProcessExecutableVersion("windows", "installed_release", "c1"),
        )


def test_mac_smb_root_stages_loaded_facts_and_rejects_changed_retry() -> None:
    from datetime import timedelta

    from evidenceforge.generation.actions.network_connection import PersistentSmbRootIntent
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.exceptions import StateError
    from tests.unit.test_smb_channels import _plan

    recipe = _recipe()
    state = StateManager()
    at = recipe.started_at
    assert at is not None
    state.set_current_time(at - timedelta(minutes=1))
    parent = state.plan_process_materialization(
        system=recipe.hostname,
        fixed_pid=1,
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
    )
    state.materialize_process(parent)
    logon = state.create_session(
        username=recipe.username,
        system=recipe.hostname,
        logon_type=2,
        source_ip="192.0.2.10",
    )
    session = state.get_session_identity(logon)
    assert session is not None
    credentials = PosixProcessCredentials(501, 501, 20, 20)
    version = ProcessExecutableVersion("macos", "installed_release", "test-release-1")
    recipe = replace(
        recipe,
        parent_object_id=parent.identity.object_id,
        logon_id=logon,
        session_object_id=session.object_id,
        session_id=session.session_id,
        credentials=credentials,
        executable_version=version,
    )
    transport = _plan(opened_at=at + timedelta(seconds=1))
    intent = PersistentSmbRootIntent(
        username=recipe.username,
        system=transport.hostname,
        auth_time=at + timedelta(seconds=2),
        lifecycle_group_id="smb-root-test",
        auth_protocol="ntlm",
        smb_principal="alex",
        account_scope="local",
        auth_session_ref="smb-auth-test",
        client_process=recipe,
    )
    batch = intent.prepare(state, transport)
    identity = intent.client_process_identity(state, batch)
    assert identity is not None
    assert identity.credentials == credentials and identity.executable_version == version
    for changed in (
        replace(recipe, credentials=PosixProcessCredentials(502, 502, 20, 20)),
        replace(recipe, executable_version=replace(version, content_id="test-release-2")),
    ):
        with pytest.raises(StateError, match="frozen client actor"):
            replace(intent, client_process=changed).client_process_identity(state, batch)
