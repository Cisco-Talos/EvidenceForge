# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Complete requests reject collection gaps even in an otherwise empty workload."""

from datetime import timedelta

import pytest

from evidenceforge.generation.macos_process_coverage import validate_complete_collection
from evidenceforge.generation.source_deployment_compiler import compile_scenario_source_deployment
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario, SourceObservationOverride
from evidenceforge.utils.time import resolve_time_window
from tests.unit.test_macos_installed_provisioning import _scenario


@pytest.mark.parametrize("mode", [None, "complete", "partial"])
@pytest.mark.parametrize("gap", ["none", "disabled", "capabilities", "loss", "window", "formats"])
def test_complete_preflight_uses_exact_source_policy(mode: str | None, gap: str) -> None:
    scenario = _scenario()
    scenario.macos_process_coverage = mode
    scenario.output.logs = [{"format": "macos_endpoint_security"}]
    start, end = resolve_time_window(scenario.time_window)
    patch: dict = {"source_instance": "macos_endpoint_security:mac-01", "enabled": True}
    if gap == "disabled":
        patch["enabled"] = False
    elif gap == "capabilities":
        patch["capabilities"] = []
    elif gap == "loss":
        patch["missingness"] = 0.1
    elif gap == "window":
        patch["windows"] = [{"start": start + timedelta(seconds=1), "end": end}]
    scenario.environment.observation_overrides = [SourceObservationOverride.model_validate(patch)]
    formats = frozenset({"ecar"} if gap == "formats" else {"macos_endpoint_security"})
    # The override intentionally has no source after CLI filtering; the explicit
    # complete preflight must still reject the omitted format itself.
    if gap == "formats":
        scenario.environment.observation_overrides = []
    deployment = compile_scenario_source_deployment(scenario, emitter_formats=formats).deployment
    rejects = gap != "none" and (mode == "complete" or (mode is None and gap != "formats"))
    if rejects:
        with pytest.raises(StateError, match="Complete macOS process coverage"):
            validate_complete_collection(scenario, deployment, formats, start, end)
    else:
        validate_complete_collection(scenario, deployment, formats, start, end)


def test_implicit_complete_request_survives_runtime_format_filtering() -> None:
    raw = _scenario().model_dump(mode="json")
    raw["output"]["logs"] = [{"format": "macos_endpoint_security"}]
    scenario = Scenario.model_validate(raw)
    assert scenario.macos_process_coverage == "complete"
    scenario.output.logs = [{"format": "ecar"}]
    scenario = Scenario.model_validate(scenario.model_dump())
    from evidenceforge.validation import ScenarioValidator

    findings = ScenarioValidator(scenario).validate()
    assert any(
        issue.field_path == "macos_process_coverage" and issue.severity == "error"
        for issue in findings
    )
