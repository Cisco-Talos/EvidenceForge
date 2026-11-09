# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.generation.actions.process_policy import record_failed_process_exec
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.engine.typed_handlers.process import handle_process
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import ProcessEventSpec, Scenario
from evidenceforge.validation.schema import ScenarioValidator
from tests.unit.test_macos_authored_login import _context
from tests.unit.test_macos_foundations import _system
from tests.unit.test_process_execution_state import _START, _process


@pytest.mark.parametrize("restored", [False, True])
def test_authored_exec_failure_preserves_exact_caller_and_has_no_success_effects(
    restored: bool,
) -> None:
    state, caller = _process()
    if restored:
        previous = state
        state = StateManager()
        _restore_head(state, _capture_head(previous))
    context = replace(
        _context(_system().model_copy(update={"hostname": caller.hostname})),
        time=_START + timedelta(seconds=2),
        malicious_event={},
    )
    runtime = SimpleNamespace(
        state_manager=state,
        _storyline_process_refs={
            (caller.hostname, context.actor.username, "caller"): (
                caller.pid,
                caller.image,
                caller.object_id,
            ),
        },
    )
    before_counters = dict(state._pid_counters)
    result = handle_process(
        runtime,
        ProcessEventSpec(
            process_name="/usr/bin/curl",
            command_line="curl https://not-requested.example.test/attempt",
            parent_ref="caller",
            outcome="exec_failed",
        ),
        context,
    )
    assert result["outcome"] == "exec_failed"
    assert result["skipped_reason"] == "exec_failed_caller_preserved"
    assert result["expected_sources"] == [] and "pid" not in result
    assert state.get_process_identity(caller.hostname, caller.pid) == caller
    assert state._pid_counters == before_counters
    assert len(state.list_running_processes()) == 1
    assert state.get_process(caller.hostname, caller.pid).last_activity_time == context.time
    # No generator/dispatcher exists on this harness. The failure cannot run successful effects.
    later = state.begin_action_cohort_materialization()
    after = later.execute_process(
        caller,
        image="/usr/bin/true",
        command_line="true",
        executed_at=context.time + timedelta(seconds=1),
    )
    state.materialize_action_cohort(later.seal())
    assert after.execution_ordinal == caller.execution_ordinal + 1


def test_unknown_errno_stays_unknown_without_replacing_image() -> None:
    state, caller = _process()
    result = record_failed_process_exec(
        state,
        actor=caller,
        attempted_at=_START + timedelta(seconds=1),
        image="/usr/bin/missing",
        command_line="missing",
    )
    assert result.error_number is None
    assert state.get_process_identity(caller.hostname, caller.pid) == caller


@pytest.mark.parametrize(
    "changes",
    [
        {"parent_ref": None},
        {"process_ref": "nonexistent-execution"},
        {"process_name": "relative"},
        {"outcome": "failed"},
    ],
)
def test_failed_exec_schema_requires_an_exact_existing_caller(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ProcessEventSpec.model_validate(
            dict(process_name="/bin/false", parent_ref="caller", outcome="exec_failed") | changes
        )


@pytest.mark.parametrize("damage", [None, "linux", "windows", "caller"])
def test_failed_exec_validation_checks_platform_and_prior_reference(damage: str | None) -> None:
    data = yaml.safe_load(Path("scenarios/macos-denied-launch-example/scenario.yaml").read_text())
    for section in data["storyline"]:
        for event in section["events"]:
            if event.get("outcome") == "denied":
                event["outcome"] = "exec_failed"
    if damage in {"linux", "windows"}:
        data["environment"]["systems"][0]["os"] = (
            "Ubuntu 24.04" if damage == "linux" else "Windows 11"
        )
    elif damage == "caller":
        data["storyline"] = data["storyline"][1:]
    validator = ScenarioValidator(Scenario.model_validate(data))
    validator._validate_event_sequences()
    errors = [issue for issue in validator.issues if issue.severity == "error"]
    if damage:
        assert any(
            issue.field_path.endswith("parent_ref" if damage == "caller" else "outcome")
            for issue in errors
        )
    else:
        assert not errors
        validator._validate_process_network_pairing()
        validator._validate_evidence_reachability()
        assert not any(
            "PROCESS_CREATE" in issue.message or "connection" in issue.message.lower()
            for issue in validator.issues
        )


@pytest.mark.parametrize("damage", ["missing", "legacy", "reused", "linux", "closed"])
def test_failed_exec_runtime_rejects_unproven_caller_before_mutation(damage: str) -> None:
    state, caller = _process("linux" if damage == "linux" else "macos")
    system = _system().model_copy(
        update={
            "hostname": caller.hostname,
            "os": "Ubuntu 24.04" if damage == "linux" else "macOS 26",
        }
    )
    context = replace(_context(system), time=_START + timedelta(seconds=2), malicious_event={})
    reference = (
        (caller.pid, caller.image)
        if damage == "legacy"
        else (caller.pid, caller.image, "old-object" if damage == "reused" else caller.object_id)
    )
    refs = (
        {}
        if damage == "missing"
        else {(caller.hostname, context.actor.username, "caller"): reference}
    )
    if damage == "closed":
        builder = state.begin_action_cohort_materialization()
        builder.terminate_process(caller, end_time=_START + timedelta(seconds=1))
        state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    with pytest.raises(StateError):
        handle_process(
            SimpleNamespace(state_manager=state, _storyline_process_refs=refs),
            ProcessEventSpec(process_name="/bin/false", parent_ref="caller", outcome="exec_failed"),
            context,
        )
    assert state.materialization_digest() == before


def test_installed_authoring_references_include_both_bounded_failure_outcomes(
    tmp_path: Path,
) -> None:
    from evidenceforge.cli.install_skills import install_chatgpt_skills

    installed, _ = install_chatgpt_skills(tmp_path)
    for name in ("scenario-events-endpoint.md", "evidence-endpoint-macos.md"):
        relative = f"eforge-scenario/references/{name}"
        assert relative in installed
        contents = (tmp_path / relative).read_text()
        assert "exec_failed" in contents and "denied" in contents
        assert "errno" in contents


def test_failed_exec_example_preserves_prior_caller_for_following_child() -> None:
    data = yaml.safe_load(Path("scenarios/macos-failed-exec-example/scenario.yaml").read_text())
    scenario = Scenario.model_validate(data)
    validator = ScenarioValidator(scenario)
    validator._validate_event_sequences()
    assert not [issue for issue in validator.issues if issue.severity == "error"]
    events = [event for entry in scenario.storyline for event in entry.events]
    assert [event.outcome for event in events] == ["success", "exec_failed", "success"]
    assert events[-1].parent_ref == events[1].parent_ref == events[0].process_ref
