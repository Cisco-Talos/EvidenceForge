# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Receiver preparation consumes modeled accounts/catalogs through real SSH owners."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.identity import IdentityDirectory, MacAccount
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_macos_ssh_startup import _descriptor
from tests.unit.test_ssh_deferred_production import _START, _fixture, _RealSshFixture


def _mac_fixture(tmp_path: Path, shell: str = "/bin/zsh") -> _RealSshFixture:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path, production_timing_runtime=True)
    fixture.target.os = "macOS 26 arm64"
    fixture.target.type = "workstation"
    fixture.generator.identity_directory = IdentityDirectory(
        windows_domain="",
        domain_sid_base="",
        has_windows_domain=False,
        macos_accounts={
            ("analyst", "db-01"): MacAccount(
                "analyst", "analyst", 501, 20, "DB-01", "/Users/analyst", shell
            ),
            ("_sshd", "db-01"): MacAccount(
                "_sshd", "_sshd", 75, 75, "DB-01", "/var/empty", "/usr/bin/false", "well_known"
            ),
        },
    )
    fixture.generator.dispatcher.deployment_registry = DeploymentContentRegistry(
        application_descriptors=tuple(
            _descriptor(application)
            for application in (
                "macos-launchd",
                "macos-sshd-keygen-wrapper",
                "macos-sshd",
                "macos-sshd-session",
                "macos-sshd-auth",
                "macos-zsh",
                "macos-bash",
            )
        )
    )
    bootstrap = fixture.state.plan_process_materialization(
        system=fixture.target.hostname,
        fixed_pid=1,
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START - timedelta(minutes=1),
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    fixture.state.materialize_process(bootstrap)
    fixture.generator._lifecycle_authority.ensure_process(fixture.target.hostname, 1)
    return fixture


@pytest.mark.parametrize("shell", ["/bin/zsh", "/bin/bash"])
@pytest.mark.parametrize("collection", ["all", "network", "endpoint", "none"])
def test_mac_receiver_preparation_transport_startup_and_close(
    tmp_path: Path, shell: str, collection: str
) -> None:
    fixture = _mac_fixture(tmp_path, shell)
    if collection in {"network", "none"}:
        fixture.generator.dispatcher.emitters.pop("ecar")
    if collection in {"endpoint", "none"}:
        fixture.generator.dispatcher.emitters.pop("zeek_conn")
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    before = fixture.state.materialization_digest()
    prepared = bundle._prepare_deferred_open(transport)
    assert fixture.state.materialization_digest() == before
    assert not fixture.state._linux_logind_session_counters
    assert (
        prepared.close_continuation.startup_request.phase_times
        == prepared.authority.ssh_timing_intent.macos_startup_times
    )
    transaction = bundle._open_deferred_transport(transport, prepared)
    continuation = bundle._bind_deferred_close_continuation(prepared, transaction)
    fixture.generator._defer_ssh_session_close(continuation)
    continuation.prepared.drain_receiver_startup(fixture.generator)
    session = fixture.state.get_session(prepared.session_plan.identity.logon_id)
    assert session.audit_origin.audit_uid == 501
    shell_process = fixture.state.get_process(fixture.target.hostname, session.session_shell_pid)
    assert shell_process.image == shell and shell_process.credentials.effective_uid == 501
    fixture.generator._finalize_exact_ssh_close_continuation(continuation)
    assert fixture.state.get_session(prepared.session_plan.identity.logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, 1) is not None
    rows, flows = fixture.close_and_read()
    assert bool(rows) == (collection in {"all", "endpoint"})
    assert len(flows) == (1 if collection in {"all", "network"} else 0)
    assert (
        fixture.generator.timing_runtime.audit.snapshot().sample_counts["macos.ssh_receiver_stage"]
        == 11
    )


@pytest.mark.parametrize("damage", ["account", "service", "shell", "catalog", "parent", "close"])
def test_mac_receiver_preparation_rejects_missing_owners_before_state_mutation(
    tmp_path: Path, damage: str
) -> None:
    fixture = _mac_fixture(tmp_path)
    request = replace(fixture.request(), emit_session_close=True)
    accounts = fixture.generator.identity_directory.macos_accounts
    if damage == "account":
        accounts.pop(("analyst", "db-01"))
    elif damage == "service":
        accounts.pop(("_sshd", "db-01"))
    elif damage == "shell":
        accounts[("analyst", "db-01")] = replace(accounts[("analyst", "db-01")], shell="/bin/fish")
    elif damage == "catalog":
        fixture.generator.dispatcher.deployment_registry = None
    elif damage == "parent":
        fixture.state.get_process(fixture.target.hostname, 1).image = "/usr/sbin/sshd"
    else:
        request = replace(request, emit_session_close=False)
    bundle = SshSessionActionBundle(request, fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    before = fixture.state.materialization_digest()
    with pytest.raises(StateError):
        bundle._prepare_deferred_open(transport)
    assert fixture.state.materialization_digest() == before
    fixture.close_and_read()


@pytest.mark.parametrize("collection", ["network", "none"])
@pytest.mark.parametrize("failure_mode", ["fail-before", "lost-return"])
def test_mac_receiver_omitted_projection_release_recovers_without_repeating_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collection: str, failure_mode: str
) -> None:
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    fixture = _mac_fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    if collection == "none":
        fixture.generator.dispatcher.emitters.pop("zeek_conn")
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    original = ExactPublicationBatch.release_no_fail
    attempts = 0

    def inject(batch: ExactPublicationBatch) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(batch)
            raise OSError("injected Mac projection release")
        original(batch)

    monkeypatch.setattr(ExactPublicationBatch, "release_no_fail", inject)
    if failure_mode == "fail-before":
        with pytest.raises(OSError, match="Mac projection release"):
            bundle._open_deferred_transport(transport, prepared)
        before = fixture.state.materialization_digest()
        fixture.generator.dispatcher.drain_exact_projection_recoveries()
        assert fixture.state.materialization_digest() == before
        transaction = bundle._adopt_deferred_transport_identity(transport, prepared)
    else:
        transaction = bundle._open_deferred_transport(transport, prepared)
    assert attempts == (2 if failure_mode == "fail-before" else 1)
    continuation = bundle._bind_deferred_close_continuation(prepared, transaction)
    fixture.generator._defer_ssh_session_close(continuation)
    continuation.prepared.drain_receiver_startup(fixture.generator)
    fixture.generator._finalize_exact_ssh_close_continuation(continuation)
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    fixture.close_and_read()


def test_mac_receiver_visible_sink_cannot_omit_its_positive_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.models.exceptions import EventContractError

    fixture = _mac_fixture(tmp_path)
    monkeypatch.setattr(fixture.ecar, "emit", lambda _event: None)
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    before = fixture.state.materialization_digest()
    with pytest.raises(EventContractError, match="staged no durable row"):
        bundle._open_deferred_transport(transport, prepared)
    assert fixture.state.materialization_digest() == before
    fixture.generator._cancel_exact_ssh_close_continuation_reservation(prepared.close_continuation)
    assert fixture.close_and_read() == ([], [])


def test_mac_receiver_changed_timing_preview_aborts_before_state(tmp_path: Path) -> None:
    fixture = _mac_fixture(tmp_path)
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    intent = prepared.authority.ssh_timing_intent
    times = intent.macos_startup_times
    object.__setattr__(
        intent, "macos_startup_times", (times[0] + timedelta(microseconds=1),) + times[1:]
    )
    before = fixture.state.materialization_digest()
    audit_before = fixture.generator.timing_runtime.audit.snapshot()
    with pytest.raises(StateError, match="timing replay disagrees"):
        bundle._open_deferred_transport(transport, prepared)
    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.audit.snapshot() == audit_before
    fixture.generator._cancel_exact_ssh_close_continuation_reservation(prepared.close_continuation)
    fixture.close_and_read()


@pytest.mark.parametrize("gap_ms", [0, 1_000])
def test_mac_receiver_invalid_stage_overlay_rejects_before_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gap_ms: int
) -> None:
    from evidenceforge.generation.activity import timing_profiles

    fixture = _mac_fixture(tmp_path)
    original = timing_profiles.get_timing_window

    def overlay(key: str, **kwargs: object) -> timing_profiles.TimingWindow:
        if key == "macos.ssh_receiver_stage":
            return timing_profiles.TimingWindow(min_ms=gap_ms, max_ms=gap_ms, position="after")
        return original(key, **kwargs)

    monkeypatch.setattr(timing_profiles, "get_timing_window", overlay)
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    before = fixture.state.materialization_digest()
    with pytest.raises(ValueError, match="Mac SSH receiver stage"):
        bundle._prepare_deferred_open(transport)
    assert fixture.state.materialization_digest() == before
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    fixture.close_and_read()
