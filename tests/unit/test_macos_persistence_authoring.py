# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.models.scenario import MacosLaunchItemEventSpec, Scenario
from evidenceforge.validation.macos_persistence import persistence_problems


def _data() -> dict:
    return yaml.safe_load(Path("scenarios/macos-persistence-example/scenario.yaml").read_text())


def test_valid_explicit_stages_preserve_removed_loaded_definition() -> None:
    assert persistence_problems(Scenario.model_validate(_data())) == []


@pytest.mark.parametrize(
    "change,message",
    [
        ("caller", "earlier root"),
        ("platform", "arm64 Mac"),
        ("missing_write", "definition write"),
        ("missing_bootstrap", "loaded job"),
        ("missing_unload", "explicit unload"),
        ("double_activate", "Complete the running"),
        ("exit_without_activation", "earlier activation"),
        ("duplicate_version", "larger file version"),
    ],
)
def test_invalid_workflow_rejected_before_generation(change: str, message: str) -> None:
    data = _data()
    steps = data["storyline"]
    if change == "caller":
        steps[1]["events"][0]["caller_ref"] = "missing"
    elif change == "platform":
        data["environment"]["systems"][0]["os"] = "Ubuntu 24.04"
    elif change == "missing_write":
        del steps[1]
    elif change == "missing_bootstrap":
        del steps[2]
    elif change == "missing_unload":
        steps.pop()
    elif change == "double_activate":
        del steps[5]
    elif change == "exit_without_activation":
        del steps[4]
    elif change == "duplicate_version":
        duplicate = deepcopy(steps[1])
        duplicate["id"] = "replacement"
        steps.insert(2, duplicate)
    assert any(
        message in problem for _, problem in persistence_problems(Scenario.model_validate(data))
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"path": "/tmp/fake.plist"},
        {"path": "/Library/LaunchDaemons/../fake.plist"},
        {"program": None},
        {"size_bytes": 0},
        {"process_ref": "not-an-activation"},
        {"exit_code": 0},
    ],
)
def test_write_rejects_inapplicable_or_missing_facts(updates: dict) -> None:
    data = _data()["storyline"][1]["events"][0] | updates
    with pytest.raises(ValidationError):
        MacosLaunchItemEventSpec.model_validate(data)
