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
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import DnsContext, HttpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions import network_transaction_planner as planner_module
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionIdentityCapture,
    NetworkConnectionPublicationOutcome,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System

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
