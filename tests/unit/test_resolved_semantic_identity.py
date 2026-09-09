"""Contracts for generation-relevant resolved scenario identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidenceforge.composition import (
    CompiledScenario,
    EffectiveConfig,
    compile_scenario,
    semantic_resolved_difference_sections,
    semantic_resolved_sha256,
)
from evidenceforge.generation.checkpoints.fingerprint import run_fingerprint_components

_SCENARIO = Path("tests/fixtures/scenarios/minimal.yaml")


def _with_effective_config(
    compiled: CompiledScenario,
    **updates: object,
) -> CompiledScenario:
    payload = compiled.effective_config.model_dump(mode="json")
    payload.update(updates)
    return compiled.model_copy(update={"effective_config": EffectiveConfig.model_validate(payload)})


def _with_legacy_behavior(
    compiled: CompiledScenario,
    *,
    revision: int,
) -> CompiledScenario:
    packaged = dict(compiled.effective_config.packaged_defaults)
    packaged["generation_behavior.yaml"] = {
        "schema_version": "1.0",
        "current_revision": revision,
    }
    return _with_effective_config(compiled, packaged_defaults=packaged)


def test_compiled_effective_config_omits_generation_behavior_control_metadata() -> None:
    compiled = compile_scenario(_SCENARIO)

    assert "generation_behavior.yaml" not in compiled.effective_config.packaged_defaults


def test_legacy_generation_behavior_metadata_does_not_change_semantic_identity() -> None:
    compiled = compile_scenario(_SCENARIO)
    revision_six = _with_legacy_behavior(compiled, revision=6)
    revision_nine = _with_legacy_behavior(compiled, revision=9)

    assert semantic_resolved_sha256(revision_six) == semantic_resolved_sha256(revision_nine)
    assert semantic_resolved_difference_sections(revision_six, compiled) == ()
    assert (
        run_fingerprint_components(
            revision_six,
            output_target="default",
            formats=["windows", "zeek"],
            oob_hosts=(),
        )["resolved_sha256"]
        == run_fingerprint_components(
            revision_nine,
            output_target="default",
            formats=["windows", "zeek"],
            oob_hosts=(),
        )["resolved_sha256"]
    )


@pytest.mark.parametrize(
    ("candidate", "expected_section"),
    (
        ("scenario", "scenario"),
        ("effective_config", "effective_config"),
        ("assets", "assets"),
    ),
)
def test_semantic_identity_reports_generation_relevant_changes(
    candidate: str,
    expected_section: str,
) -> None:
    compiled = compile_scenario(_SCENARIO)
    if candidate == "scenario":
        changed = compiled.model_copy(
            update={"scenario": compiled.scenario.model_copy(update={"name": "changed"})}
        )
    elif candidate == "effective_config":
        changed = _with_effective_config(
            compiled,
            project_overlays={"activity/network_params.yaml": {"changed": True}},
        )
    else:
        changed = compiled.model_copy(update={"assets": {**compiled.assets, "extra": "changed"}})

    assert semantic_resolved_sha256(changed) != semantic_resolved_sha256(compiled)
    assert semantic_resolved_difference_sections(compiled, changed) == (expected_section,)
