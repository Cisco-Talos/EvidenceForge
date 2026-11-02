# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A diagnostic slice must not masquerade as the full acceptance workload."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from scripts.measure_macos_workstation import Case, slice_document, summarize

from evidenceforge.generation.engine.typed_handlers.authentication import handle_logoff
from evidenceforge.models.scenario import LogoffEventSpec


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
