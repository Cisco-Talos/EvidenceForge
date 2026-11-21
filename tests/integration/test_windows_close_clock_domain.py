# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Observer clock headroom must not become elapsed Windows process work."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.scenario import System, User

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _process(
    profile: str, entry: str
) -> tuple[ActivityGenerator, StateManager, System, User, str, int]:
    state = StateManager()
    emitters = {name: Mock() for name in ("ecar", "windows_event_sysmon", "windows_event_security")}
    for emitter in emitters.values():
        emitter.can_handle.return_value = True
    runtime = TimingRuntime(
        reference_time=T0 - timedelta(hours=2),
        namespace="shared-timing-v1",
        generation_seed=42,
    )
    dispatcher = EventDispatcher(
        state,
        emitters,
        observation_policy=ObservationPolicy(profile),
        timing_runtime=runtime,
    )
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    generator._scenario_start_time = T0
    generator._scenario_end_time = T0 + timedelta(hours=6)
    system = System(hostname="WIN-CLOCK", ip="10.0.0.55", os="Windows 11", type="workstation")
    user = User(
        username="duration-user", full_name="Duration User", email="duration-user@example.test"
    )
    at = T0 + timedelta(minutes=10)
    logon_id = "0x3e7"
    if entry == "user":
        logon_id = generator.generate_logon(
            user, system, at - timedelta(minutes=1), emit_network_evidence=False
        )
        pid = generator.generate_process(
            user,
            system,
            at,
            logon_id,
            process_name=r"C:\Windows\System32\whoami.exe",
            command_line="whoami.exe",
            suppress_command_file_effect=True,
        )
    else:
        pid = generator.generate_system_process(
            system,
            at,
            r"C:\Windows\System32\conhost.exe",
            "conhost.exe 0x4",
            username="SYSTEM",
        )
    return generator, state, system, user, logon_id, pid


@pytest.mark.parametrize("profile", ["complete", "enterprise_standard"])
@pytest.mark.parametrize("entry", ["user", "system"])
def test_observation_headroom_does_not_extend_canonical_process_runtime(
    profile: str, entry: str
) -> None:
    generator, state, system, user, logon_id, pid = _process(profile, entry)
    process = state.get_process(system.hostname, pid)
    assert process is not None
    requested = process.start_time + timedelta(milliseconds=500)
    assert process.last_activity_time is None or process.last_activity_time < requested
    bound = generator.process_source_create_bound(system, pid)
    assert bound is not None and bound > requested
    identity = state.get_process_identity(system.hostname, pid)
    assert identity is not None
    if entry == "user":
        generator.generate_process_termination(
            user, system, requested, pid, process.image, logon_id
        )
    else:
        generator.generate_system_process_termination(
            system, requested, pid, process.image, username="SYSTEM"
        )
    lifetime = generator._lifecycle_authority.registry.get_process(identity.object_id)
    assert lifetime is not None and lifetime.closed_at == requested
    termination = next(
        call.args[0]
        for emitter in generator.dispatcher.emitters.values()
        for call in emitter.emit.call_args_list
        if call.args[0].event_type == "process_terminate" and call.args[0].process.pid == pid
    )
    assert termination.source_timing is not None
    times = termination.source_timing.finalized_times
    paired = 0
    for create, close in (
        ("ecar.process.create.WIN-CLOCK", "ecar.process.terminate.WIN-CLOCK"),
        ("sysmon.process.create.native.WIN-CLOCK", "sysmon.process.terminate.native.WIN-CLOCK"),
        (
            "windows_security.event.process_create.native.WIN-CLOCK",
            "windows_security.event.process_terminate.native.WIN-CLOCK",
        ),
    ):
        if create in times and close in times:
            elapsed = times[close] - times[create]
            assert timedelta(milliseconds=500) <= elapsed < timedelta(seconds=2)
            paired += 1
    assert paired > 0


@pytest.mark.parametrize("profile", ["complete", "enterprise_standard"])
@pytest.mark.parametrize("entry", ["user", "system"])
def test_clock_correction_keeps_real_canonical_activity_floor(profile: str, entry: str) -> None:
    generator, state, system, user, logon_id, pid = _process(profile, entry)
    process = state.get_process(system.hostname, pid)
    assert process is not None
    identity = state.get_process_identity(system.hostname, pid)
    assert identity is not None
    activity = process.start_time + timedelta(seconds=7)
    state.update_process_activity_time(system.hostname, pid, activity)
    requested = process.start_time + timedelta(milliseconds=500)
    if entry == "user":
        generator.generate_process_termination(
            user, system, requested, pid, process.image, logon_id
        )
    else:
        generator.generate_system_process_termination(
            system, requested, pid, process.image, username="SYSTEM"
        )
    closed = generator._lifecycle_authority.registry.get_process(identity.object_id)
    assert closed is not None and closed.closed_at > activity


def test_clock_correction_keeps_process_owned_transport_hold() -> None:
    generator, state, system, user, logon_id, pid = _process("enterprise_standard", "user")
    process = state.get_process(system.hostname, pid)
    assert process is not None
    identity = state.get_process_identity(system.hostname, pid)
    assert identity is not None
    hold = process.start_time + timedelta(seconds=5)
    generator._process_connection_hold_until[(system.hostname, pid, process.start_time)] = hold
    generator.generate_process_termination(
        user,
        system,
        process.start_time + timedelta(milliseconds=500),
        pid,
        process.image,
        logon_id,
    )
    closed = generator._lifecycle_authority.registry.get_process(identity.object_id)
    assert closed is not None and closed.closed_at > hold


def test_clock_correction_preserves_authoritative_session_end() -> None:
    from evidenceforge.events.lifecycle import SessionEndPlan

    generator, state, system, user, logon_id, pid = _process("enterprise_standard", "user")
    process = state.get_process(system.hostname, pid)
    assert process is not None
    identity = state.get_process_identity(system.hostname, pid)
    assert identity is not None
    end = SessionEndPlan(
        canonical_end=process.start_time + timedelta(seconds=1),
        authority="explicit_storyline",
        storyline_event_id="bounded-clock-fixture",
    )
    assert state.plan_session_end(logon_id, end)
    requested = process.start_time + timedelta(milliseconds=500)
    generator.generate_process_termination(
        user,
        system,
        requested,
        pid,
        process.image,
        logon_id,
        session_end_plan=end,
    )
    closed = generator._lifecycle_authority.registry.get_process(identity.object_id)
    assert closed is not None and closed.closed_at == requested < end.canonical_end
