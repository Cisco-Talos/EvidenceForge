# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.generation.spillage import expected_sources_for_surface, render_for_surface
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation import ScenarioValidator


def _scenario(formats: tuple[str, ...] = ("ecar", "zsh_history")) -> dict:
    data = yaml.safe_load(
        (
            Path(__file__).resolve().parents[2]
            / "scenarios/macos-workstation-example/native-workspace.yaml"
        ).read_text()
    )
    data["personas"] = [{"name": "developer", "description": "Invented local developer"}]
    data["output"]["logs"] = [{"format": value} for value in formats]
    data["storyline"] = [
        {
            "id": "history-spill",
            "time": "+10m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Enter an independently invented value in an interactive shell",
            "events": [
                {
                    "type": "spillage",
                    "surface": "shell_history",
                    "value": "EvidenceForgeFake_HISTORY",
                }
            ],
        }
    ]
    return data


def _errors(data: dict) -> list[str]:
    validator = ScenarioValidator(Scenario(**data))
    validator.validate()
    return [issue.message for issue in validator.issues if issue.severity == "error"]


def test_mac_history_spillage_uses_existing_surface_and_zsh_source() -> None:
    assert _errors(_scenario()) == []
    result = render_for_surface(
        "EvidenceForgeFake_HISTORY", "shell_history", "", "invented", os_category="macos"
    )
    assert result.expected_sources == ("zsh_history",)
    assert expected_sources_for_surface("shell_history") == ("bash_history",)


@pytest.mark.parametrize("formats", [("ecar",), ("ecar", "bash_history")])
def test_mac_history_requires_its_actual_zsh_collection(formats: tuple[str, ...]) -> None:
    assert any(
        "needs output format 'zsh_history'" in message for message in _errors(_scenario(formats))
    )


def test_mac_history_rejects_unimplemented_metafied_values() -> None:
    data = _scenario()
    data["storyline"][0]["events"][0]["value"] = "EvidenceForgeFake_café"
    assert any("ASCII zsh_history" in message for message in _errors(data))


@pytest.mark.parametrize("actor", ["root", "worker"])
def test_mac_history_rejects_noninteractive_system_actors(actor: str) -> None:
    data = _scenario()
    data["storyline"][0]["actor"] = actor
    data["environment"]["service_accounts"] = ["worker"]
    assert any("non-interactive service account" in message for message in _errors(data))


@pytest.mark.parametrize(
    "host,user,score", [("MAC-01", "alex", 100), ("MAC-01", "someone", 0), ("OTHER", "alex", 0)]
)
def test_zsh_spillage_evaluation_requires_exact_host_and_actor(
    host: str, user: str, score: int
) -> None:
    scenario = Scenario(**_scenario())
    at = scenario.time_window.start + timedelta(minutes=10)
    record = ParsedRecord(
        source_format="zsh_history",
        raw=": 1:0;export TOKEN=EvidenceForgeFake_HISTORY",
        fields={
            "hostname": host,
            "username": user,
            "command": "export TOKEN=EvidenceForgeFake_HISTORY",
        },
        timestamp=at,
    )
    context = EvaluationContext(
        spillage_ground_truth={
            "history-spill": {
                "values": ["EvidenceForgeFake_HISTORY"],
                "time": at,
                "records": [
                    {"value": "EvidenceForgeFake_HISTORY", "expected_sources": ["zsh_history"]}
                ],
            }
        }
    )
    pillar = CausalityScorer().score({"zsh_history": [record]}, scenario, context)
    assert next(item for item in pillar.sub_scores if item.key == "event_presence").score == score


@pytest.mark.parametrize("shell_kind", ["missing", "bash"])
def test_mac_history_does_not_label_a_missing_zsh_submission(shell_kind: str) -> None:
    from types import SimpleNamespace

    from evidenceforge.generation.activity.generator import ActivityGenerator

    scenario = Scenario(**_scenario())
    shell = None if shell_kind == "missing" else SimpleNamespace(image="/bin/bash")
    owner = SimpleNamespace(
        ensure_macos_session_shell=lambda *args: None if shell is None else 99,
        state_manager=SimpleNamespace(get_process=lambda *args: shell),
    )
    # No Linux history or native emission method exists on this owner. Neither
    # may be called when the explicit zsh submission cannot be established.
    result = ActivityGenerator.generate_spillage(
        owner,
        user=scenario.environment.users[0],
        system=scenario.environment.systems[0],
        time=scenario.time_window.start + timedelta(minutes=10),
        surface="shell_history",
        family=None,
        value="EvidenceForgeFake_HISTORY",
        seed_key="invented-missing-history",
        logon_id="invented-session",
    )
    assert result["skipped_reason"] == "not_emitted"
    assert "value" not in result and "expected_sources" not in result


@pytest.mark.parametrize(
    "override,blocked",
    [
        ({"enabled": False}, True),
        ({"capabilities": []}, True),
        ({"missingness": 1.0}, True),
        ({"missingness": 0.5}, False),
    ],
)
def test_other_hosts_history_does_not_satisfy_the_authored_collection(
    override: dict[str, object], blocked: bool
) -> None:
    from evidenceforge.validation.evidence_reachability import analyze_evidence_reachability

    data = _scenario()
    data["environment"]["systems"].append(
        {
            "hostname": "MAC-OTHER",
            "ip": "192.0.2.11",
            "os": "macOS 26",
            "architecture": "arm64",
            "type": "workstation",
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("MAC-OTHER")
    data["environment"]["observation_overrides"] = [
        {"source_instance": "zsh_history:mac-01", **override}
    ]
    findings = analyze_evidence_reachability(Scenario(**data))
    history = [item for item in findings if item.behavior_id == "macos_authored_history_spillage"]
    assert bool(history) == blocked
    if blocked:
        assert history[0].severity == "error"
        assert "mac-01" in history[0].message
