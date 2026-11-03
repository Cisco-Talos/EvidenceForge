# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A diagnostic slice must not masquerade as the full acceptance workload."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scripts.measure_macos_workstation import (
    Case,
    RequiredExecution,
    missing_execution_roles,
    realized_step_ids,
    slice_document,
    summarize,
)

from evidenceforge.events.macos_native_coverage import MacosNativeCoverage
from evidenceforge.formats.macos_endpoint_security import ESExit, ESExitEvent
from evidenceforge.generation.engine.typed_handlers.authentication import handle_logoff
from evidenceforge.models.scenario import LogoffEventSpec


def test_measurement_counts_native_exit_union_rather_than_an_unrelated_event_number(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.measure_macos_workstation as measurement

    (tmp_path / "GENERATION_MANIFEST.json").write_text(
        '{"generation_seed":373,"output_target":"default"}'
    )
    (tmp_path / "GROUND_TRUTH.json").write_text("{}")
    data = tmp_path / "data"
    data.mkdir()
    (data / "macos_endpoint_security.ndjson").write_text("invented exit\n")
    monkeypatch.setattr(
        measurement,
        "GroundTruthDocument",
        SimpleNamespace(
            model_validate_json=lambda raw: SimpleNamespace(events=(), macos_native_coverage=None)
        ),
    )
    monkeypatch.setattr(
        measurement,
        "decode_endpoint_security_record",
        lambda raw: SimpleNamespace(event_type=15, event=ESExitEvent(exit=ESExit(stat=0))),
    )
    case = Case(name="exit", description="Known exit", steps=(), required_images=())
    result = summarize(tmp_path, case, full=True, exit_code=0, text="")
    assert result.native_exit_rows == 1
    assert result.exit_outcomes_unknown is None


@pytest.mark.parametrize("outcome", [None, "success", "denied", "exec_failed", "policy_refused"])
def test_measurement_requires_exec_for_success_but_not_for_an_unsuccessful_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str | None
) -> None:
    import scripts.measure_macos_workstation as measurement

    start = datetime(2026, 10, 19, 14, tzinfo=UTC)
    successful = outcome in {None, "success"}
    coverage = MacosNativeCoverage.model_validate(
        {
            "schema_version": 2,
            "scope": "canonical_process_window",
            "policy": "complete",
            "hosts": [
                {
                    "hostname": "MAC",
                    "source_profile": "invented",
                    "observations": [],
                    "process_census": {
                        "window_start": start,
                        "window_end": start + timedelta(minutes=1),
                        "expected_forks": 0,
                        "expected_execs": int(successful),
                        "published_forks": 0,
                        "published_execs": 0,
                        "fork_identities_match": True,
                        "exec_identities_match": not successful,
                        "aggregate_births": 0,
                        "aggregate_examples": [],
                        "complete": not successful,
                    },
                }
            ],
        }
    )
    event = SimpleNamespace(
        storyline_id="attempt",
        kind="process",
        emitted=True,
        system="MAC",
        time=start,
        attributes=SimpleNamespace(pid=777, process_name="/invented", outcome=outcome),
    )
    monkeypatch.setattr(
        measurement,
        "GroundTruthDocument",
        SimpleNamespace(
            model_validate_json=lambda raw: SimpleNamespace(
                events=(event,), macos_native_coverage=coverage
            )
        ),
    )
    (tmp_path / "GENERATION_MANIFEST.json").write_text(
        '{"generation_seed":373,"output_target":"default"}'
    )
    (tmp_path / "GROUND_TRUTH.json").write_text("{}")
    result = summarize(
        tmp_path,
        Case(name="attempt", description="Attempt", steps=("attempt",), required_images=()),
        full=True,
        exit_code=0,
        text="",
    )
    assert result.authored_phase_gaps == (
        ("attempt:exec:authored_identity_missing",) if successful else ()
    )
    assert result.activity_supported is not successful


def test_slice_preserves_baseline_and_environment_and_declares_partial() -> None:
    document = {
        "macos_process_coverage": "complete",
        "generation_seed": 373,
        "baseline_activity": {"intensity": "medium"},
        "environment": {"systems": ["invented"]},
        "storyline": [
            {"id": name, "time": f"+{index}m"}
            for index, name in enumerate(("login", "command", "chrome"))
        ],
    }
    case = Case(name="command", description="One activity", steps=("command",), required_images=())
    sliced = slice_document(document, case, ("login",))
    assert sliced["macos_process_coverage"] == "partial"
    assert sliced["baseline_activity"] == document["baseline_activity"]
    assert sliced["environment"] == document["environment"]
    assert sliced["generation_seed"] == document["generation_seed"]
    assert sliced["storyline"] == document["storyline"][:2]
    assert document["macos_process_coverage"] == "complete"
    assert len(document["storyline"]) == 3


def test_failed_generation_keeps_counts_unknown_without_opening_partial_data(
    tmp_path: Path,
) -> None:
    case = Case(
        name="chrome", description="Blocked app", steps=("browser",), required_images=("/invented",)
    )
    result = summarize(
        tmp_path, case, full=True, exit_code=21, text="Error: Generation failed: missing app policy"
    )
    assert not result.activity_supported and not result.census_complete
    assert result.coverage is None and result.native_exec_images is None
    assert result.background_native_execs is None
    assert result.blocker == "missing app policy"


def test_success_without_completion_manifest_cannot_pass_measurement(tmp_path: Path) -> None:
    case = Case(name="full", description="Incomplete bundle", steps=(), required_images=())
    result = summarize(tmp_path, case, full=True, exit_code=0, text="")
    assert result.blocker and not result.activity_supported and result.coverage is None


def test_logoff_without_matching_session_is_reported_as_unemitted_noop() -> None:
    runtime = SimpleNamespace(
        _session_end_plan_for_current_logoff=lambda: None,
        _last_storyline_logon_for_actor_system=lambda *_args, **_kwargs: None,
        activity_generator=Mock(),
    )
    context = SimpleNamespace(actor=object(), system=object(), time=object(), malicious_event={})
    result = handle_logoff(runtime, LogoffEventSpec(), context)
    assert result["skipped_reason"] == "no_matching_session"
    runtime.activity_generator.generate_logoff.assert_not_called()


def test_shared_helper_image_requires_both_gpu_and_network_invocations() -> None:
    image = "/invented/Chrome Helper"
    requirements = (
        RequiredExecution(image=image, arguments=("--type=gpu-process",)),
        RequiredExecution(
            image=image,
            arguments=("--type=utility", "--utility-sub-type=network.mojom.NetworkService"),
        ),
    )
    network = (
        image,
        (
            image,
            "--type=utility",
            "--utility-sub-type=network.mojom.NetworkService",
            "--seatbelt-client=3",
        ),
    )
    assert missing_execution_roles(requirements, [network]) == (0,)
    assert (
        missing_execution_roles(
            requirements, [network, (image, (image, "--type=gpu-process", "--seatbelt-client=3"))]
        )
        == ()
    )
    assert missing_execution_roles(requirements, [("/different/helper", network[1])]) == (0, 1)


def test_optional_empty_session_cleanup_does_not_hide_skipped_processes_or_other_failures() -> None:
    events = [
        SimpleNamespace(storyline_id=name, kind=kind, skipped_reason=reason, emitted=emitted)
        for name, kind, reason, emitted in (
            ("cleanup", "logoff", "no_matching_session", False),
            ("unapproved-cleanup", "logoff", "no_matching_session", False),
            ("failed-cleanup", "logoff", "other", False),
            ("process", "process", "no_matching_session", False),
            ("actual-start", "process", None, True),
        )
    ]
    assert realized_step_ids(events, ("cleanup", "failed-cleanup", "process")) == {
        "cleanup",
        "actual-start",
    }
