"""Keep the generator's and the evaluator's independent sensor placement in agreement.

Ground-truth agreement re-derives sensor placement on purpose, so the two implementations can
drift when networking changes. Each fixture lists, by hand, which sensors the documented rules
place on each flow; both implementations must match it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from evidenceforge.evaluation.routed_placement import RoutedPlacement
from evidenceforge.events.evidence_source_rules import semantic_source_admission
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import NetworkConfig, System

FIXTURES = Path(__file__).parents[1] / "fixtures" / "visibility"


def _cases() -> list[Any]:
    cases = []
    for path in sorted(FIXTURES.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        network = NetworkConfig.model_validate(document["network"])
        systems = [System.model_validate(system) for system in document["systems"]]
        for case in document["cases"]:
            cases.append(pytest.param(network, systems, case, id=f"{path.stem}: {case['name']}"))
    return cases


@pytest.mark.parametrize(("network", "systems", "case"), _cases())
def test_generator_places_sensors_as_documented(
    network: NetworkConfig, systems: list[System], case: dict[str, Any]
) -> None:
    engine = NetworkVisibilityEngine(network, systems)
    observed = engine.get_observing_sensors(
        case["src"], case["dst"], denied_entities=() if case.get("denied") else None
    )
    assert {sensor.name for sensor in observed} == set(case["observers"])


@pytest.mark.parametrize(("network", "systems", "case"), _cases())
def test_evaluator_places_sensors_as_documented(
    network: NetworkConfig, systems: list[System], case: dict[str, Any]
) -> None:
    placement = RoutedPlacement(network, systems)
    observed = placement.observing(case["src"], case["dst"], denied=bool(case.get("denied")))
    assert observed == set(case["observers"])


def test_every_fixture_is_routed_and_has_cases() -> None:
    paths = sorted(FIXTURES.glob("*.yaml"))
    assert paths
    for path in paths:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert document["network"].get("routing") and document["cases"], path.name


@pytest.mark.parametrize(("network", "systems", "case"), _cases())
def test_ground_truth_agreement_uses_routed_placement(
    network: NetworkConfig, systems: list[System], case: dict[str, Any]
) -> None:
    from evidenceforge.evaluation.ground_truth_agreement import _sensor_visible
    from evidenceforge.models import Scenario

    document = yaml.safe_load(
        (Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml").read_text(encoding="utf-8")
    )
    environment = document["environment"]
    environment["network"] = network.model_dump(mode="json", exclude_none=True)
    environment["systems"] = [
        system.model_dump(mode="json", exclude_none=True) for system in systems
    ]
    for user in environment.get("users", []):
        user.pop("primary_system", None)
    document["storyline"] = []
    scenario = Scenario.model_validate(document)
    facts = {"network": {"src_ip": case["src"], "dst_ip": case["dst"]}}
    observed = {
        sensor.name
        for sensor in scenario.environment.network.sensors
        if _sensor_visible(scenario, sensor.name, facts, denied=bool(case.get("denied")))
    }
    assert observed == set(case["observers"])


@pytest.mark.parametrize(
    "case",
    yaml.safe_load((FIXTURES / "capabilities" / "zeek-x509.yaml").read_text(encoding="utf-8")),
    ids=lambda case: case["name"],
)
def test_zeek_x509_capability_matches_documented_transport_state(case: dict[str, Any]) -> None:
    from evidenceforge.evaluation.ground_truth_agreement import _source_semantic_admission

    facts = {"network": {"conn_state": case["conn_state"]}}
    assert semantic_source_admission("zeek_x509", "connection", facts) is case["eligible"]
    assert _source_semantic_admission("zeek_x509", "connection", facts, "tap") is case["eligible"]
