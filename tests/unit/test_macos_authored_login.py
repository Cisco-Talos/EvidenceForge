# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authored Mac logins own an occurrence; implicit bootstrap may reuse a GUI."""

import random
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.actions.auth_session import LogonRequest
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.typed_handlers.authentication import (
    handle_failed_logon,
    handle_logon,
)
from evidenceforge.generation.engine.typed_handlers.context import TypedEventContext
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import FailedLogonEventSpec, LogonEventSpec, System
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user


def _context(system: System) -> TypedEventContext:
    return TypedEventContext(
        actor=_user(),
        system=system,
        time=_TIME + timedelta(minutes=2),
        activity="Authored login",
        explicit_types={"logon"},
        future_specs=(),
        authored_time_shift=timedelta(0),
        session_required_until=None,
        rng=random.Random(17),
        dispatcher=None,
        malicious_event={},
        _ground_truth_uid=Mock(),
    )


@pytest.mark.parametrize("source_ip", [None, "-", "192.0.2.10"])
def test_authored_mac_login_keeps_new_occurrence_and_exact_close(source_ip: str | None) -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    implicit = generator.generate_logon(user, system, _TIME)
    assert generator.generate_logon(user, system, _TIME + timedelta(seconds=30)) == implicit
    end_plan = SessionEndPlan(_TIME + timedelta(hours=1), "storyline", "authored-close")
    owner = SimpleNamespace(
        activity_generator=generator,
        state_manager=state,
        public_identity_registry=Mock(),
        _session_end_plan_for_current_start=lambda: end_plan,
        _record_storyline_logon=Mock(),
    )
    context = _context(system)
    handle_logon(owner, LogonEventSpec(type="logon", logon_type=2, source_ip=source_ip), context)
    authored = context.malicious_event["logon_id"]
    assert authored != implicit
    assert state.get_session_identity(authored).started_at == context.time
    session = state.get_session(authored)
    assert session.storyline_protected and session.end_plan == end_plan
    assert state.get_session(implicit).end_plan is None
    assert not state.get_session(implicit).storyline_protected
    owner.public_identity_registry.bind.assert_not_called()
    assert context.malicious_event["source_ip"] == (source_ip or "-")
    owner._record_storyline_logon.assert_called_once_with(
        user, system, authored, source_ip=source_ip or "-"
    )


@pytest.mark.parametrize("failed", [False, True])
@pytest.mark.parametrize(
    "os_name,logon_type,source_ip,expected",
    [
        ("macOS 26", 2, None, "-"),
        ("Darwin 25", 2, None, "-"),
        ("macOS 26", 2, "192.0.2.55", "192.0.2.55"),
        ("macOS 26", 3, None, "198.51.100.44"),
        ("Windows 11", 2, None, "198.51.100.44"),
        ("Ubuntu 24.04", 2, None, "198.51.100.44"),
    ],
)
def test_authored_origin_defaults_are_mac_local_only(
    failed: bool, os_name: str, logon_type: int, source_ip: str | None, expected: str
) -> None:
    system = _system(os_name)
    generator = Mock()
    state = Mock()
    state.get_session.return_value = None
    registry = Mock()
    registry.bind.return_value = SimpleNamespace(ip="198.51.100.44")
    owner = SimpleNamespace(
        activity_generator=generator,
        state_manager=state,
        public_identity_registry=registry,
        scenario=SimpleNamespace(environment=SimpleNamespace(systems=[system])),
        _session_end_plan_for_current_start=lambda: None,
        _record_storyline_logon=Mock(),
    )
    context = _context(system)
    if failed:
        spec = FailedLogonEventSpec(type="failed_logon", logon_type=logon_type, source_ip=source_ip)
        handle_failed_logon(owner, spec, context)
        call = generator.generate_failed_logon.call_args
        assert "allow_local_session_reuse" not in call.kwargs
    else:
        spec = LogonEventSpec(type="logon", logon_type=logon_type, source_ip=source_ip)
        handle_logon(owner, spec, context)
        call = generator.generate_logon.call_args
        if os_name in {"macOS 26", "Darwin 25"} and logon_type == 2:
            assert call.kwargs["allow_local_session_reuse"] is False
        else:
            assert "allow_local_session_reuse" not in call.kwargs
    assert call.kwargs["source_ip"] == expected
    assert context.malicious_event["source_ip"] == expected
    assert registry.bind.call_count == int(expected == "198.51.100.44")


def test_authored_occurrence_and_reusable_intent_have_distinct_ids() -> None:
    kwargs = {"user": _user(), "system": _system(), "time": _TIME}
    implicit = LogonRequest(**kwargs)
    assert implicit.stable_id == LogonRequest(**kwargs, allow_local_session_reuse=True).stable_id
    assert implicit.stable_id != LogonRequest(**kwargs, allow_local_session_reuse=False).stable_id
