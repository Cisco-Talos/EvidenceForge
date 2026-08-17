# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Production integration tests for prepared canonical network publication."""

import ast
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import DnsContext, HttpContext
from evidenceforge.events.contracts import (
    EffectOccurrenceProvenance,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedDispatch,
    PreparedDispatchStateIntent,
    PreparedNetworkDependentBatch,
)
from evidenceforge.generation.actions import network_transaction_planner as planner_module
from evidenceforge.generation.actions.command_effects import (
    PreparedExecutionEffectAuditCommit,
)
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionIdentityCapture,
    NetworkConnectionPublicationOutcome,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.http_multipart import build_http_multipart_context
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.http import HttpMultipartEntitySpec
from evidenceforge.models.scenario import System, User

_START = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def _generator() -> tuple[ActivityGenerator, StateManager, Mock]:
    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(hours=1),
    )
    return generator, state, emitter


def _generate(
    generator: ActivityGenerator,
    capture: NetworkConnectionIdentityCapture,
) -> str:
    return generator.generate_connection(
        src_ip="10.0.0.10",
        src_port=50_001,
        dst_ip="203.0.113.20",
        time=_START,
        dst_port=8443,
        proto="tcp",
        service="",
        duration=0.25,
        orig_bytes=64,
        resp_bytes=128,
        conn_state="SF",
        hostname="",
        preserve_start_time=True,
        suppress_application_side_effects=True,
        suppress_source_pid_inference=True,
        preserve_explicit_payload=True,
        identity_capture=capture,
    )


def _multipart_environment() -> tuple[
    ActivityGenerator,
    StateManager,
    dict[str, Mock],
    System,
    int,
    int,
    HttpContext,
]:
    """Return exact live client/server actors and four ordered multipart local reads."""

    state = StateManager()
    state.set_current_time(_START)
    emitters = {"zeek_conn": Mock(), "ecar": Mock()}
    emitters["zeek_conn"].can_handle.side_effect = lambda event: event.network is not None
    emitters["ecar"].can_handle.side_effect = lambda event: event.file is not None
    generator = ActivityGenerator(
        state,
        emitters,
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(hours=1),
    )
    source = System(
        hostname="MULTIPART-CLIENT",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        type="workstation",
    )
    target = System(
        hostname="MULTIPART-SERVER",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["app_server"],
        services=["http"],
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    generator._all_system_ips = [source.ip, target.ip]
    client_pid = generator.generate_process(
        user=User(username="analyst", full_name="Analyst", email="analyst@example.test"),
        system=source,
        time=_START,
        logon_id="",
        process_name="/usr/bin/curl",
        command_line="curl -F left=@/tmp/left.bin -F right=@/tmp/right.bin server/upload",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    server_pid = generator.generate_process(
        user=User(username="www-data", full_name="Web Service", email="www@example.test"),
        system=target,
        time=_START,
        logon_id="",
        process_name="/usr/sbin/nginx",
        command_line="nginx: worker process",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    for emitter in emitters.values():
        emitter.reset_mock()
    request_multipart = build_http_multipart_context(
        HttpMultipartEntitySpec.model_validate(
            {
                "media_type": "multipart/form-data",
                "parts": [
                    {"name": "left", "body_len": 11, "local_source_path": "/tmp/left.bin"},
                    {"name": "right", "body_len": 13, "local_source_path": "/tmp/right.bin"},
                ],
            }
        ),
        stable_key="prepared-request-multipart",
    )
    response_multipart = build_http_multipart_context(
        HttpMultipartEntitySpec.model_validate(
            {
                "media_type": "multipart/mixed",
                "parts": [
                    {"body_len": 17, "local_source_path": "/srv/first.bin"},
                    {"body_len": 19, "local_source_path": "/srv/second.bin"},
                ],
            }
        ),
        stable_key="prepared-response-multipart",
    )
    http = HttpContext(
        method="POST",
        host="multipart.example.test",
        uri="/upload",
        request_body_len=request_multipart.body_len,
        request_multipart=request_multipart,
        response_body_len=response_multipart.body_len,
        response_multipart=response_multipart,
        status_code=200,
        status_msg="OK",
    )
    return generator, state, emitters, source, client_pid, server_pid, http


def _generate_multipart(
    generator: ActivityGenerator,
    source: System,
    client_pid: int,
    server_pid: int,
    http: HttpContext,
    capture: NetworkConnectionIdentityCapture,
    *,
    time: datetime = _START,
    src_port: int = 50_020,
    dns: DnsContext | None = None,
) -> str:
    """Publish the exact prepared multipart transaction used by focused tests."""

    return generator.generate_connection(
        src_ip=source.ip,
        src_port=src_port,
        dst_ip="10.0.0.20",
        time=time,
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=700,
        conn_state="SF",
        hostname="multipart.example.test",
        pid=client_pid,
        responding_pid=server_pid,
        source_system=source,
        dns=dns,
        http=http,
        preserve_start_time=True,
        preserve_explicit_payload=True,
        suppress_prereq_dns=True,
        identity_capture=capture,
    )


def _ssh_generator() -> tuple[ActivityGenerator, StateManager, Mock, System]:
    """Return one generator with a modeled Linux SSH receiver."""

    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"ecar": emitter, "syslog": emitter, "zeek_conn": emitter},
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(hours=1),
    )
    target = System(
        hostname="APP-SSH-01",
        ip="10.0.2.30",
        os="Ubuntu 24.04",
        type="server",
        roles=["app_server"],
        services=["ssh"],
    )
    generator._ip_to_system = {target.ip: target}
    generator._all_system_ips = ["10.0.1.10", target.ip]
    return generator, state, emitter, target


def _generate_ssh(
    generator: ActivityGenerator,
    target: System,
    capture: NetworkConnectionIdentityCapture,
    *,
    time: datetime = _START,
    suppress_prereq_dns: bool = False,
) -> str:
    """Generate one successful generic SSH transport with an auto source port."""

    return generator.generate_connection(
        src_ip="10.0.1.10",
        dst_ip=target.ip,
        time=time,
        dst_port=22,
        proto="tcp",
        service="ssh",
        duration=1.2,
        orig_bytes=500,
        resp_bytes=900,
        conn_state="SF",
        hostname=target.hostname,
        preserve_start_time=True,
        suppress_source_pid_inference=True,
        preserve_explicit_payload=True,
        suppress_prereq_dns=suppress_prereq_dns,
        identity_capture=capture,
    )


def test_normal_network_root_commits_one_authenticated_prepared_receipt() -> None:
    """The production entrypoint owns State/lifecycle/runtime/timing and one publish."""

    generator, state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()

    uid = _generate(generator, capture)

    root = capture.require_prepared_root()
    receipt = capture.require_receipt()
    transaction = capture.require()
    assert uid == transaction.zeek_uid
    assert root.transaction == transaction
    assert capture.require_outcome() is NetworkConnectionPublicationOutcome.PUBLISHED
    assert generator._lifecycle_authority.authenticates_prepared_network_receipt(root, receipt)
    assert state.get_connection_by_transaction_id(transaction.stable_id) is not None
    assert generator._network_transaction_runtime.census().has_last_result
    emitter.emit.assert_called_once()


def test_failed_transport_keeps_internal_close_but_source_native_duration_missing() -> None:
    """S0 remains source-native durationless while State/lifecycle receive a closed root."""

    generator, state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()

    result = generator.generate_connection(
        src_ip="10.0.0.10",
        src_port=50_019,
        dst_ip="203.0.113.20",
        time=_START,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=0.25,
        orig_bytes=0,
        resp_bytes=0,
        conn_state="S0",
        suppress_prereq_dns=True,
        identity_capture=capture,
    )

    canonical = capture.require()
    assert result == canonical.zeek_uid
    assert canonical.conn_state == "S0"
    assert canonical.duration == pytest.approx(0.25)
    assert canonical.closed_at == canonical.started_at + timedelta(seconds=0.25)
    assert state.get_connection_by_transaction_id(canonical.stable_id) is not None
    assert generator._lifecycle_authority.authenticates_prepared_network_receipt(
        capture.require_prepared_root(),
        capture.require_receipt(),
    )
    projected = emitter.emit.call_args.args[0]
    assert projected.network.conn_state == "S0"
    assert projected.network.duration is None
    assert projected.network.closed_at is None


def test_network_process_activity_and_hold_require_live_lifecycle_identity() -> None:
    """Compatibility State-only actors omit holds; production actors retain them."""

    system = System(
        hostname="NETWORK-HOLD-CLIENT",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        type="workstation",
    )

    legacy_generator, legacy_state, legacy_emitter = _generator()
    legacy_generator._ip_to_system = {system.ip: system}
    legacy_pid = legacy_state.create_process(
        system=system.hostname,
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl https://example.test/",
        username="analyst",
        integrity_level="Medium",
    )
    legacy_capture = NetworkConnectionIdentityCapture()
    legacy_generator.generate_connection(
        src_ip=system.ip,
        src_port=50_017,
        dst_ip="203.0.113.20",
        time=_START,
        dst_port=8443,
        proto="tcp",
        service="",
        duration=0.25,
        orig_bytes=100,
        resp_bytes=200,
        conn_state="SF",
        pid=legacy_pid,
        source_system=system,
        suppress_prereq_dns=True,
        identity_capture=legacy_capture,
    )
    assert legacy_capture.require_prepared_root().state_plan.process_activity == ()
    assert legacy_capture.require_receipt().connection_receipt.process_holds == ()
    assert legacy_emitter.emit.call_args.args[0].process.pid == legacy_pid

    generator, state, emitter = _generator()
    generator._ip_to_system = {system.ip: system}
    pid = generator.generate_process(
        user=User(username="analyst", full_name="Analyst", email="analyst@example.test"),
        system=system,
        time=_START,
        logon_id="",
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    emitter.reset_mock()
    capture = NetworkConnectionIdentityCapture()
    generator.generate_connection(
        src_ip=system.ip,
        src_port=50_018,
        dst_ip="203.0.113.20",
        time=_START,
        dst_port=8443,
        proto="tcp",
        service="",
        duration=0.25,
        orig_bytes=100,
        resp_bytes=200,
        conn_state="SF",
        pid=pid,
        source_system=system,
        suppress_prereq_dns=True,
        identity_capture=capture,
    )
    process_identity = state.get_process_identity(system.hostname, pid)
    assert process_identity is not None
    root = capture.require_prepared_root()
    assert tuple(patch.identity for patch in root.state_plan.process_activity) == (
        process_identity,
    )
    holds = capture.require_receipt().connection_receipt.process_holds
    assert tuple(hold.subject.object_id for hold in holds) == (process_identity.object_id,)
    assert emitter.emit.call_args.args[0].process.pid == pid


def test_http_multipart_reads_publish_one_exact_owned_projection_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Request then response leaves consume one bounded plan with exact ordered ordinals."""

    generator, state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    capture = NetworkConnectionIdentityCapture()
    state_apply = Mock(side_effect=AssertionError("multipart projection reapplied State"))
    monkeypatch.setattr(state, "apply", state_apply)
    audit_counter = generator._execution_effect_audit
    prepare_audit = audit_counter.prepare_action_cohort
    prepared_audits: list[
        tuple[
            PreparedExecutionEffectAuditCommit,
            str,
            tuple[object, ...],
            tuple[OwnedEffectOccurrencePlan, ...],
            tuple[EffectOccurrenceProvenance, ...],
        ]
    ] = []

    def capture_audit_preparation(
        _audit: object,
        root_action_id: str,
        entries: tuple[object, ...],
        *,
        owned_plans: tuple[OwnedEffectOccurrencePlan, ...] = (),
        published_provenances: tuple[EffectOccurrenceProvenance, ...] = (),
    ) -> PreparedExecutionEffectAuditCommit:
        preparation = prepare_audit(
            root_action_id,
            entries,
            owned_plans=owned_plans,
            published_provenances=published_provenances,
        )
        prepared_audits.append(
            (
                preparation,
                root_action_id,
                entries,
                owned_plans,
                published_provenances,
            )
        )
        return preparation

    monkeypatch.setattr(
        type(audit_counter),
        "prepare_action_cohort",
        capture_audit_preparation,
    )
    root_committed = False
    materialize = generator._lifecycle_authority.materialize_prepared_network_transaction
    validate_prepared = generator.dispatcher.validate_prepared
    publish_batch = generator.dispatcher.publish_prepared_network_dependent_batch
    published_batches: list[tuple[PreparedNetworkDependentBatch, object]] = []

    def commit_then_forbid_dependent_revalidation(*args: object, **kwargs: object) -> object:
        nonlocal root_committed
        result = materialize(*args, **kwargs)
        root_committed = True
        return result

    def reject_post_root_dependent_validation(
        prepared: PreparedDispatch,
        **kwargs: object,
    ) -> None:
        if (
            root_committed
            and prepared._state_intent is PreparedDispatchStateIntent.EXTERNAL_NETWORK_DEPENDENT
        ):
            raise AssertionError("multipart member was revalidated after root commit")
        validate_prepared(prepared, **kwargs)

    def capture_batch_publication(
        batch: PreparedNetworkDependentBatch,
        *,
        materialization_receipt: object,
    ) -> tuple[dict[str, str], ...]:
        published_batches.append((batch, materialization_receipt))
        return publish_batch(
            batch,
            materialization_receipt=materialization_receipt,
        )

    monkeypatch.setattr(
        generator._lifecycle_authority,
        "materialize_prepared_network_transaction",
        commit_then_forbid_dependent_revalidation,
    )
    monkeypatch.setattr(
        generator.dispatcher,
        "validate_prepared",
        reject_post_root_dependent_validation,
    )
    monkeypatch.setattr(
        generator.dispatcher,
        "publish_prepared_network_dependent_batch",
        capture_batch_publication,
    )

    _generate_multipart(
        generator,
        source,
        client_pid,
        server_pid,
        http,
        capture,
    )

    file_reads = [call.args[0] for call in emitters["ecar"].emit.call_args_list]
    assert [event.file.path for event in file_reads] == [
        "/tmp/left.bin",
        "/tmp/right.bin",
        "/srv/first.bin",
        "/srv/second.bin",
    ]
    provenances = [event.effect_provenance for event in file_reads]
    assert [provenance.occurrence_ordinal for provenance in provenances] == [0, 1, 2, 3]
    assert len({provenance.plan_action_id for provenance in provenances}) == 1
    assert len({provenance.node_id for provenance in provenances}) == 1
    assert {provenance.root_action_id for provenance in provenances} == {
        capture.require().stable_id
    }
    audit = generator.execution_effect_audit_snapshot()
    assert audit.owned_effect_plan_count == 1
    assert audit.owned_effect_expected_occurrence_count == 4
    assert audit.owned_effect_published_occurrence_count == 4
    assert audit.exempt_effect_occurrence_count == 0
    assert audit.effect_publication_mismatch_count == 0
    assert audit.complete
    assert len(prepared_audits) == 1
    audit_preparation, root_action_id, entries, owned_plans, provenances = prepared_audits[0]
    audit_receipt = audit_preparation.receipt
    assert audit_counter.authenticates_action_cohort_receipt(
        audit_receipt,
        preparation=audit_preparation,
        root_action_id=root_action_id,
        entries=entries,
        owned_plans=owned_plans,
        published_provenances=provenances,
    )
    assert audit_counter.action_cohort_preparation_census().active == 0
    assert generator.dispatcher._network_dependent_batches == {}
    state_apply.assert_not_called()
    assert len(published_batches) == 1
    batch, materialization_receipt = published_batches[0]
    audit_after = generator.execution_effect_audit_snapshot()
    with pytest.raises(EventContractError, match="lacks its final precommit authentication"):
        publish_batch(
            batch,
            materialization_receipt=materialization_receipt,
        )
    assert generator.execution_effect_audit_snapshot() == audit_after


def test_committed_suppressed_http_multipart_publishes_claimed_read_batch() -> None:
    """A duplicate DNS observation suppresses only the root projection, not owned reads."""

    generator, _state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    dns = DnsContext(
        query="multipart.example.test",
        query_type="A",
        answers=["10.0.0.20"],
        TTLs=[300],
        rtt=0.002,
    )
    first_capture = NetworkConnectionIdentityCapture()
    second_capture = NetworkConnectionIdentityCapture()

    first_result = _generate_multipart(
        generator,
        source,
        client_pid,
        server_pid,
        http,
        first_capture,
        dns=dns,
    )
    second_result = _generate_multipart(
        generator,
        source,
        client_pid,
        server_pid,
        http,
        second_capture,
        time=_START + timedelta(seconds=1),
        src_port=50_021,
        dns=dns,
    )

    assert first_result == first_capture.require().zeek_uid
    assert second_result == ""
    assert (
        second_capture.require_outcome() is NetworkConnectionPublicationOutcome.COMMITTED_SUPPRESSED
    )
    assert emitters["zeek_conn"].emit.call_count == 1
    file_reads = [call.args[0] for call in emitters["ecar"].emit.call_args_list]
    assert len(file_reads) == 8
    assert [event.effect_provenance.occurrence_ordinal for event in file_reads] == [
        0,
        1,
        2,
        3,
        0,
        1,
        2,
        3,
    ]
    audit = generator.execution_effect_audit_snapshot()
    assert audit.owned_effect_plan_count == 2
    assert audit.owned_effect_expected_occurrence_count == 8
    assert audit.owned_effect_published_occurrence_count == 8
    assert audit.complete
    assert generator._execution_effect_audit.action_cohort_preparation_census().active == 0
    assert generator.dispatcher._network_dependent_batches == {}


def test_http_multipart_tampered_batch_owner_rejects_and_releases_every_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A locally tampered owner field cannot strand the trusted batch capability."""

    generator, state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    timing_before = generator._source_timing_planner.state_digest()
    audit_before = generator.execution_effect_audit_snapshot()
    authenticate = generator.dispatcher.authenticates_prepared_network_dependent_batch
    claimed_members: list[PreparedDispatch] = []

    def tamper_owner(batch: PreparedNetworkDependentBatch) -> bool:
        claimed_members.extend(batch._dispatches)
        batch._dispatcher_token = -1
        return authenticate(batch)

    monkeypatch.setattr(
        generator.dispatcher,
        "authenticates_prepared_network_dependent_batch",
        tamper_owner,
    )

    with pytest.raises(StateError, match="batch changed before publication"):
        _generate_multipart(
            generator,
            source,
            client_pid,
            server_pid,
            http,
            capture,
        )

    assert claimed_members
    assert generator.dispatcher._network_dependent_batches == {}
    assert all(
        member._network_dependent_batch_id is None and not member._consumed
        for member in claimed_members
    )
    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator.execution_effect_audit_snapshot() == audit_before
    assert generator._execution_effect_audit.action_cohort_preparation_census().active == 0
    assert capture.transaction is None
    assert all(emitter.emit.call_count == 0 for emitter in emitters.values())


def test_http_multipart_member_content_tamper_rejects_before_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Batch authentication recomputes the full member projection preimage."""

    generator, state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    capture = NetworkConnectionIdentityCapture()
    authenticate = generator.dispatcher.authenticates_prepared_network_dependent_batch
    materialize = Mock(side_effect=AssertionError("multipart root committed after member tamper"))
    monkeypatch.setattr(
        generator._lifecycle_authority,
        "materialize_prepared_network_transaction",
        materialize,
    )

    def tamper_projection(batch: PreparedNetworkDependentBatch) -> bool:
        member = batch._dispatches[0]
        member._projection = replace(
            member._projection,
            initial_statuses=(*member._projection.initial_statuses, ("ecar", "filtered")),
        )
        return authenticate(batch)

    monkeypatch.setattr(
        generator.dispatcher,
        "authenticates_prepared_network_dependent_batch",
        tamper_projection,
    )

    with pytest.raises(StateError, match="batch changed before publication"):
        _generate_multipart(
            generator,
            source,
            client_pid,
            server_pid,
            http,
            capture,
        )

    materialize.assert_not_called()
    assert generator.dispatcher._network_dependent_batches == {}
    assert generator.execution_effect_audit_snapshot().owned_effect_plan_count == 0
    assert generator._execution_effect_audit.action_cohort_preparation_census().active == 0
    assert capture.transaction is None
    assert all(emitter.emit.call_count == 0 for emitter in emitters.values())


def test_http_multipart_copied_audit_binding_rejects_and_releases_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied audit token cannot authenticate or strand the trusted preparation."""

    generator, state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    capture = NetworkConnectionIdentityCapture()
    authenticate = generator.dispatcher.authenticates_prepared_network_dependent_batch
    materialize = Mock(side_effect=AssertionError("multipart root committed after audit tamper"))
    state_before = state.materialization_digest()
    audit_before = generator.execution_effect_audit_snapshot()
    monkeypatch.setattr(
        generator._lifecycle_authority,
        "materialize_prepared_network_transaction",
        materialize,
    )

    def replace_audit_binding(batch: PreparedNetworkDependentBatch) -> bool:
        batch._audit_binding_token = copy.copy(batch._audit_binding_token)
        return authenticate(batch)

    monkeypatch.setattr(
        generator.dispatcher,
        "authenticates_prepared_network_dependent_batch",
        replace_audit_binding,
    )

    with pytest.raises(StateError, match="batch changed before publication"):
        _generate_multipart(
            generator,
            source,
            client_pid,
            server_pid,
            http,
            capture,
        )

    materialize.assert_not_called()
    assert state.materialization_digest() == state_before
    assert generator.execution_effect_audit_snapshot() == audit_before
    assert generator._execution_effect_audit.action_cohort_preparation_census().active == 0
    assert generator.dispatcher._network_dependent_batches == {}
    assert capture.transaction is None
    assert all(emitter.emit.call_count == 0 for emitter in emitters.values())


def test_http_multipart_last_precommit_rejection_is_globally_neutral() -> None:
    """A claimed four-read batch leaves no State, timing, audit, or output residue on reject."""

    generator, state, emitters, source, client_pid, server_pid, http = _multipart_environment()
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    timing_before = generator._source_timing_planner.state_digest()
    audit_before = generator.execution_effect_audit_snapshot()

    def reject_after_all_preparation() -> None:
        assert len(generator.dispatcher._network_dependent_batches) == 1
        raise StateError("injected multipart last-precommit rejection")

    generator._lifecycle_authority._materialization_precommit_hook = reject_after_all_preparation
    with pytest.raises(StateError, match="injected multipart last-precommit rejection"):
        _generate_multipart(
            generator,
            source,
            client_pid,
            server_pid,
            http,
            capture,
        )

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator.execution_effect_audit_snapshot() == audit_before
    assert generator._execution_effect_audit.action_cohort_preparation_census().active == 0
    assert generator.dispatcher._network_dependent_batches == {}
    assert capture.transaction is None
    assert all(emitter.emit.call_count == 0 for emitter in emitters.values())


def test_rejected_network_preparation_is_globally_neutral() -> None:
    """A last-precommit rejection leaves no State, RNG, timing, channel, or output residue."""

    generator, state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    runtime_census_before = generator._network_transaction_runtime.census()
    timing_before = generator._source_timing_planner.state_digest()
    lifecycle_before = generator._lifecycle_authority.registry.stats()
    application_before = generator._application_channel_registry.census()
    http_before = generator._http_channel_manager.census()
    proxy_before = generator._proxy_channel_manager.census()

    def _reject() -> None:
        raise StateError("injected prepared network rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected prepared network rejection"):
        _generate(generator, capture)

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._network_transaction_runtime.census() == runtime_census_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator._lifecycle_authority.registry.stats() == lifecycle_before
    assert generator._application_channel_registry.census() == application_before
    assert generator._http_channel_manager.census() == http_before
    assert generator._proxy_channel_manager.census() == proxy_before
    assert capture.transaction is None
    assert capture.receipt is None
    assert capture.outcome is None
    assert generator.dispatcher.source_evidence_status == {}
    emitter.emit.assert_not_called()

    generator._lifecycle_authority._materialization_precommit_hook = None
    uid = _generate(generator, capture)
    assert uid == capture.require().zeek_uid
    assert capture._claim is None


def test_network_identity_capture_preflight_is_exact_one_shot_and_retryable() -> None:
    """Wrong, copied, tampered, claimed, and reused handoffs fail before planning effects."""

    generator, state, emitter = _generator()
    owner_rng = generator_module._get_rng()

    class DerivedCapture(NetworkConnectionIdentityCapture):
        pass

    def assert_neutral_rejection(capture: object, message: str) -> None:
        state_before = state.materialization_digest()
        rng_before = owner_rng.getstate()
        runtime_before = generator._network_transaction_runtime.state_digest()
        timing_before = generator._source_timing_planner.state_digest()
        output_before = emitter.emit.call_count
        with pytest.raises((TypeError, ValueError), match=message):
            _generate(generator, capture)  # type: ignore[arg-type]
        assert state.materialization_digest() == state_before
        assert owner_rng.getstate() == rng_before
        assert generator._network_transaction_runtime.state_digest() == runtime_before
        assert generator._source_timing_planner.state_digest() == timing_before
        assert emitter.emit.call_count == output_before

    assert_neutral_rejection(DerivedCapture(), "exact carrier type")

    capture = NetworkConnectionIdentityCapture()
    claim = capture._claim_empty()
    copied_claim = copy.copy(claim)
    assert not capture._authenticates_claim(copied_claim)
    assert capture._authenticates_claim(claim)
    object.__setattr__(copied_claim, "_active", False)
    assert capture._authenticates_claim(claim)
    assert_neutral_rejection(capture, "already claimed")
    capture._release_claim(claim)

    tampered_claim = capture._claim_empty()
    object.__setattr__(tampered_claim, "_active", False)
    assert not capture._authenticates_claim(tampered_claim)
    assert_neutral_rejection(capture, "already claimed")
    capture._release_claim(tampered_claim)

    uid = _generate(generator, capture)
    assert uid == capture.require().zeek_uid
    assert capture._claim is None
    assert_neutral_rejection(capture, "already published")


def test_rejected_http_file_identity_draw_uses_the_prepared_rng() -> None:
    """HTTP FUID allocation cannot advance the owner RNG before root acceptance."""

    generator, state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    timing_before = generator._source_timing_planner.state_digest()
    http_before = generator._http_channel_manager.census()

    def _reject() -> None:
        raise StateError("injected HTTP FUID rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected HTTP FUID rejection"):
        generator.generate_connection(
            src_ip="10.0.0.10",
            src_port=50_002,
            dst_ip="203.0.113.20",
            time=_START,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=300,
            resp_bytes=2_000,
            conn_state="SF",
            hostname="",
            http=HttpContext(
                method="GET",
                host="example.test",
                uri="/payload.bin",
                response_body_len=1_500,
                resp_mime_types=["application/octet-stream"],
                status_code=200,
                status_msg="OK",
            ),
            suppress_prereq_dns=True,
            identity_capture=capture,
        )

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator._http_channel_manager.census() == http_before
    assert capture.transaction is None
    emitter.emit.assert_not_called()


def test_rejected_dns_normalization_does_not_mutate_the_caller_context() -> None:
    """Resolver normalization stays on the canceled prepared occurrence copy."""

    generator, _state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()
    dns = DnsContext(
        query="downloads.example.test",
        query_type="A",
        answers=["203.0.113.20"],
        TTLs=[],
    )
    caller_value = (dns.query, tuple(dns.answers), tuple(dns.TTLs), dns.AA)

    def _reject() -> None:
        raise StateError("injected DNS normalization rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected DNS normalization rejection"):
        generator.generate_connection(
            src_ip="10.0.0.10",
            src_port=50_003,
            dst_ip="203.0.113.53",
            time=_START,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.05,
            orig_bytes=64,
            resp_bytes=160,
            conn_state="SF",
            dns=dns,
            suppress_prereq_dns=True,
            identity_capture=capture,
        )

    assert (dns.query, tuple(dns.answers), tuple(dns.TTLs), dns.AA) == caller_value
    assert capture.transaction is None
    emitter.emit.assert_not_called()


def test_rejected_windows_process_visibility_clamp_uses_only_staged_timing() -> None:
    """The pre-transport Windows visibility repair cannot advance base timing."""

    generator, state, emitter = _generator()
    source = System(
        hostname="CLIENT-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    process_plan = state.plan_process_materialization(
        system=source.hostname,
        parent_pid=0,
        image=r"C:\Program Files\Browser\browser.exe",
        command_line="browser.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id="0x1001",
        start_time=_START - timedelta(seconds=1),
        auth_session_id=0x1001,
        auth_logon_type=2,
    )
    state.materialize_process(process_plan)
    generator._ip_to_system = {source.ip: source}
    generator.process_source_create_time = Mock(return_value=_START + timedelta(milliseconds=10))
    timing_before = generator._source_timing_planner.state_digest()

    def _reject() -> None:
        raise StateError("injected process visibility rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected process visibility rejection"):
        generator.generate_connection(
            src_ip=source.ip,
            src_port=50_004,
            dst_ip="203.0.113.20",
            time=_START,
            dst_port=8443,
            proto="tcp",
            service="",
            duration=0.25,
            orig_bytes=64,
            resp_bytes=128,
            pid=process_plan.identity.pid,
            source_system=source,
            conn_state="SF",
            hostname="",
            suppress_application_side_effects=True,
            suppress_prereq_dns=True,
            preserve_explicit_payload=True,
        )

    assert generator._source_timing_planner.state_digest() == timing_before
    generator.process_source_create_time.assert_called()
    emitter.emit.assert_not_called()


def test_post_begin_network_inventory_has_no_eager_publish_or_owner_runtime_calls() -> None:
    """The prepared region uses only revocable capabilities before authority commit."""

    tree = ast.parse(Path(planner_module.__file__).read_text(encoding="utf-8"))
    execute = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_execute"
    )

    def call_name(call: ast.Call) -> str:
        def expression_name(expression: ast.expr) -> str:
            if isinstance(expression, ast.Name):
                return expression.id
            if isinstance(expression, ast.Attribute):
                return f"{expression_name(expression.value)}.{expression.attr}"
            return ""

        return expression_name(call.func)

    calls = [node for node in ast.walk(execute) if isinstance(node, ast.Call)]
    begin_line = next(node.lineno for node in calls if call_name(node) == "boundary.begin")
    commit_line = next(
        node.lineno
        for node in calls
        if call_name(node)
        == "executor._lifecycle_authority.materialize_prepared_network_transaction"
    )
    prepared_calls = [node for node in calls if begin_line < node.lineno < commit_line]
    prepared_names = {call_name(node) for node in prepared_calls}
    forbidden = {
        "executor.dispatcher.dispatch_builder",
        "executor._http_channel_manager.open_transport",
        "executor._http_channel_manager.reserve_request",
        "executor._proxy_channel_manager.open_tunnel",
        "executor._proxy_channel_manager.reserve_request",
        "executor.state_manager.add_connection",
        "executor.state_manager.materialize_connection_composite",
        "executor.state_manager.set_current_time",
        "executor.state_manager.update_process_activity_time",
        "executor.state_manager.update_session_activity_time",
        "generator_module._get_rng",
    }
    assert prepared_names.isdisjoint(forbidden)

    clamp_calls = [
        node
        for node in prepared_calls
        if call_name(node) == "executor._clamp_after_visible_process_create"
    ]
    assert len(clamp_calls) == 2
    for call in clamp_calls:
        runtime_keyword = next(
            keyword for keyword in call.keywords if keyword.arg == "timing_runtime"
        )
        assert isinstance(runtime_keyword.value, ast.Attribute)
        assert runtime_keyword.value.attr == "_timing_runtime"

    status_call = next(
        node for node in prepared_calls if call_name(node) == "generator_module._get_http_status"
    )
    cache_keyword = next(
        keyword for keyword in status_call.keywords if keyword.arg == "publish_cache"
    )
    assert isinstance(cache_keyword.value, ast.Constant)
    assert cache_keyword.value.value is False


def test_auto_port_ssh_responder_commits_inside_the_network_root() -> None:
    """The responder process, tuple claim, timing, and transport publish as one root."""

    generator, state, _emitter, target = _ssh_generator()
    capture = NetworkConnectionIdentityCapture()

    uid = _generate_ssh(generator, target, capture)

    root = capture.require_prepared_root()
    receipt = capture.require_receipt()
    batch = root.state_plan.batch
    assert batch is not None
    assert len(batch.processes) == 1
    responder_plan = batch.processes[0]
    transaction = capture.require()
    assert uid == transaction.zeek_uid
    assert transaction.src_port > 0
    assert transaction.responding_pid == responder_plan.identity.pid
    assert state.get_process(target.hostname, responder_plan.identity.pid) is not None
    assert (
        generator.ssh_responder_pid_for_tuple(
            transaction.src_ip,
            transaction.src_port,
            transaction.dst_ip,
        )
        == responder_plan.identity.pid
    )
    assert generator._lifecycle_authority.authenticates_materialization_receipt(
        responder_plan,
        receipt,
    )


def test_rejected_auto_port_ssh_responder_is_state_runtime_and_output_neutral() -> None:
    """A rejected root cannot leak its planned responder process or tuple binding."""

    generator, state, emitter, target = _ssh_generator()
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    timing_before = generator._source_timing_planner.state_digest()
    lifecycle_before = generator._lifecycle_authority.registry.stats()

    def _reject() -> None:
        raise StateError("injected responder root rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected responder root rejection"):
        _generate_ssh(generator, target, capture, suppress_prereq_dns=True)

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator._lifecycle_authority.registry.stats() == lifecycle_before
    assert state.get_processes_on_system(target.hostname) == []
    assert capture.transaction is None
    assert emitter.emit.call_count == 0


def test_network_receipt_authenticates_only_its_exact_responder_members() -> None:
    """Cross-root, non-member, and tampered outer receipts cannot publish a responder."""

    generator, state, _emitter, target = _ssh_generator()
    unrelated = state.plan_process_materialization(
        system=target.hostname,
        parent_pid=0,
        image="/usr/bin/unrelated",
        command_line="unrelated --idle",
        username="root",
        integrity_level="System",
        os_category="linux",
        logon_id="0x3e7",
        start_time=_START,
        auth_session_id=0,
        auth_logon_type=2,
    )
    first_capture = NetworkConnectionIdentityCapture()
    _generate_ssh(generator, target, first_capture)
    first_root = first_capture.require_prepared_root()
    first_receipt = first_capture.require_receipt()
    assert first_root.state_plan.batch is not None
    first_responder = first_root.state_plan.batch.processes[-1]

    second_capture = NetworkConnectionIdentityCapture()
    _generate_ssh(
        generator,
        target,
        second_capture,
        time=_START + timedelta(seconds=5),
    )
    second_receipt = second_capture.require_receipt()
    authority = generator._lifecycle_authority

    assert authority.authenticates_materialization_receipt(first_responder, first_receipt)
    assert not authority.authenticates_materialization_receipt(unrelated, first_receipt)
    assert not authority.authenticates_materialization_receipt(first_responder, second_receipt)
    tampered = replace(first_receipt, _integrity_token="0" * 64)
    assert not authority.authenticates_materialization_receipt(first_responder, tampered)


def test_network_runtime_sentinel_preserves_exact_end_and_rejects_after_end_neutrally() -> None:
    """Only the invisible exact-end compatibility call enters the runtime sentinel."""

    window_end = _START + timedelta(minutes=5)
    state = StateManager()
    state.set_current_time(window_end)
    emitter = Mock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters={"zeek_conn": emitter, "zeek_http": emitter},
        output_start_time=_START,
        output_end_time=window_end,
    )
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter, "zeek_http": emitter},
        dispatcher=dispatcher,
        generation_window_start=_START,
        generation_window_end=window_end,
    )
    capture = NetworkConnectionIdentityCapture()
    uid = generator.generate_connection(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.20",
        time=window_end,
        dst_port=80,
        proto="tcp",
        service="http",
        duration=0.2,
        orig_bytes=300,
        resp_bytes=1_100,
        conn_state="SF",
        hostname="",
        http=HttpContext(
            method="GET",
            host="example.test",
            uri="/outside",
            response_body_len=1_000,
            resp_mime_types=["application/octet-stream"],
            status_code=200,
            status_msg="OK",
        ),
        suppress_prereq_dns=True,
        identity_capture=capture,
    )

    transaction = capture.require()
    assert uid == transaction.zeek_uid
    assert transaction.started_at == window_end
    assert transaction.closed_at == generator._network_transaction_runtime.window_end
    assert state.get_connection_by_transaction_id(transaction.stable_id) is not None
    assert generator._http_channel_manager.census().open_transport_views == 0
    emitter.emit.assert_not_called()

    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    runtime_before = generator._network_transaction_runtime.state_digest()
    timing_before = generator._source_timing_planner.state_digest()
    lifecycle_before = generator._lifecycle_authority.registry.stats()
    after_capture = NetworkConnectionIdentityCapture()
    with pytest.raises(StateError, match="at or after the runtime window end"):
        generator.generate_connection(
            src_ip="10.0.0.10",
            dst_ip="203.0.113.20",
            time=window_end + timedelta(microseconds=1),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.2,
            orig_bytes=300,
            resp_bytes=1_100,
            conn_state="SF",
            hostname="",
            http=HttpContext(
                method="GET",
                host="example.test",
                uri="/after-window",
                response_body_len=1_000,
                status_code=200,
                status_msg="OK",
            ),
            suppress_prereq_dns=True,
            identity_capture=after_capture,
        )
    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator._lifecycle_authority.registry.stats() == lifecycle_before
    assert after_capture.transaction is None
    emitter.emit.assert_not_called()

    generator.advance_application_channel_watermark(
        generator._network_transaction_runtime.window_end
    )
    census = generator._network_transaction_runtime.census()
    assert census.live_points == 0
    assert census.tombstone_points == 0
    assert census.open_preparations == 0
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert census.preparation_fences == 0
    assert census.reserved_deadlines == 0
    assert census.active_deadlines == 0
    assert census.expiry_backing == 0


def test_committed_suppressed_dns_duplicate_keeps_public_empty_string_contract() -> None:
    """The typed capture exposes the commit while the public API reports no emission."""

    generator, state, emitter = _generator()
    first_capture = NetworkConnectionIdentityCapture()
    first_uid = generator.generate_connection(
        src_ip="10.0.0.10",
        src_port=53_001,
        dst_ip="203.0.113.53",
        time=_START,
        dst_port=53,
        proto="udp",
        service="dns",
        duration=0.02,
        orig_bytes=64,
        resp_bytes=160,
        conn_state="SF",
        hostname="cached.example.test",
        preserve_dst_ip=True,
        preserve_explicit_payload=True,
        suppress_application_side_effects=True,
        suppress_source_pid_inference=True,
        suppress_prereq_dns=True,
        identity_capture=first_capture,
    )
    second_capture = NetworkConnectionIdentityCapture()
    second_result = generator.generate_connection(
        src_ip="10.0.0.10",
        src_port=53_002,
        dst_ip="203.0.113.53",
        time=_START + timedelta(seconds=1),
        dst_port=53,
        proto="udp",
        service="dns",
        duration=0.02,
        orig_bytes=64,
        resp_bytes=160,
        conn_state="SF",
        hostname="cached.example.test",
        preserve_dst_ip=True,
        preserve_explicit_payload=True,
        suppress_application_side_effects=True,
        suppress_source_pid_inference=True,
        suppress_prereq_dns=True,
        identity_capture=second_capture,
    )

    assert first_uid == first_capture.require().zeek_uid
    assert second_result == ""
    assert (
        second_capture.require_outcome() is NetworkConnectionPublicationOutcome.COMMITTED_SUPPRESSED
    )
    suppressed = second_capture.require()
    assert suppressed.zeek_uid
    assert state.get_connection_by_transaction_id(suppressed.stable_id) is not None
    assert generator._lifecycle_authority.authenticates_prepared_network_receipt(
        second_capture.require_prepared_root(),
        second_capture.require_receipt(),
    )
    assert emitter.emit.call_count == 1


def test_rejected_command_http_root_without_prerequisite_is_owner_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root-only command HTTP sizing is prepared, not a pre-begin owner mutation."""

    state = StateManager()
    state.set_current_time(_START)
    source = System(
        hostname="CLIENT-LINUX-01",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        type="workstation",
    )
    process_plan = state.plan_process_materialization(
        system=source.hostname,
        parent_pid=0,
        image="/usr/bin/curl",
        command_line="curl https://downloads.example.test/payload.bin",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        logon_id="0x1001",
        start_time=_START - timedelta(seconds=1),
        auth_session_id=0x1001,
        auth_logon_type=2,
    )
    state.materialize_process(process_plan)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(hours=1),
    )
    generator._ip_to_system = {source.ip: source}
    command_parser = Mock(wraps=generator_module._http_context_from_process_command)
    monkeypatch.setattr(generator_module, "_http_context_from_process_command", command_parser)
    capture = NetworkConnectionIdentityCapture()
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    timing_before = generator._source_timing_planner.state_digest()
    runtime_before = generator._network_transaction_runtime.state_digest()
    http_before = generator._http_channel_manager.census()

    def _reject() -> None:
        raise StateError("injected command HTTP root rejection")

    generator._lifecycle_authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected command HTTP root rejection"):
        generator.generate_connection(
            src_ip=source.ip,
            src_port=50_010,
            dst_ip="203.0.113.20",
            time=_START,
            dst_port=443,
            proto="tcp",
            service=None,
            pid=process_plan.identity.pid,
            source_system=source,
            conn_state="SF",
            preserve_dst_ip=True,
            suppress_prereq_dns=True,
            identity_capture=capture,
        )

    command_parser.assert_called_once()
    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert generator._source_timing_planner.state_digest() == timing_before
    assert generator._network_transaction_runtime.state_digest() == runtime_before
    assert generator._http_channel_manager.census() == http_before
    assert capture.transaction is None
    emitter.emit.assert_not_called()


def test_committed_dns_prerequisite_survives_later_root_rejection_without_orphan_claim() -> None:
    """A DNS prerequisite is independent truth; only the later outer root rolls back."""

    generator, state, emitter = _generator()
    capture = NetworkConnectionIdentityCapture()
    state_before = state.materialization_digest()
    timing_before = generator._source_timing_planner.state_digest()
    precommit_calls = 0

    def _accept_prerequisite_then_reject_root() -> None:
        nonlocal precommit_calls
        precommit_calls += 1
        if precommit_calls == 2:
            raise StateError("injected post-prerequisite root rejection")

    generator._lifecycle_authority._materialization_precommit_hook = (
        _accept_prerequisite_then_reject_root
    )
    with pytest.raises(StateError, match="injected post-prerequisite root rejection"):
        generator.generate_connection(
            src_ip="10.0.0.10",
            src_port=50_011,
            dst_ip="203.0.113.20",
            time=_START,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=0.25,
            orig_bytes=200,
            resp_bytes=1_200,
            conn_state="SF",
            hostname="updates.example.test",
            emit_dns=True,
            preserve_dst_ip=True,
            suppress_source_pid_inference=True,
            identity_capture=capture,
        )

    assert precommit_calls == 2
    assert state.materialization_digest() != state_before
    assert generator._source_timing_planner.state_digest() != timing_before
    committed = state.list_open_connections()
    assert len(committed) == 1
    assert committed[0].dst_port == 53
    assert capture.transaction is None
    census = generator._network_transaction_runtime.census()
    assert census.open_preparations == 0
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert census.preparation_fences == 0
    assert census.reserved_deadlines == 0
    assert emitter.emit.call_count == 1
