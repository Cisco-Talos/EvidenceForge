"""Source-native Mac transition facts remain independently checkable."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from tests.integration.test_ground_truth_reconciliation import _truth
from tests.integration.test_ground_truth_source_agreement import _audit

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def mac_transition_bundle(tmp_path_factory: pytest.TempPathFactory) -> tuple:
    root = tmp_path_factory.mktemp("mac-ground-truth-repairs")
    data = yaml.safe_load(
        Path("scenarios/macos-workstation-example/native-workspace.yaml").read_text()
    )
    data["time_window"]["duration"] = "15m"
    data["output"]["logs"] = [
        {"format": fmt} for fmt in ("ecar", "zsh_history", "macos_endpoint_security")
    ]
    data["storyline"].append(
        {
            "id": "literal-find",
            "time": "+3m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Submit a literal file query",
            "events": [
                {
                    "type": "process",
                    "process_name": "/usr/bin/find",
                    "command_line": '/usr/bin/find /Users/alex/Documents -maxdepth 2 -type f -name "*.pdf"',
                }
            ],
        }
    )
    scenario = Scenario(**data)
    GenerationEngine(scenario, root).generate()
    document, rows = _truth(root)
    records, _ = EvaluationEngine(root, scenario)._parse_all_logs()
    return root, scenario, document, rows, records


def test_mac_transitions_and_literal_history_agree(
    mac_transition_bundle: tuple, tmp_path: Path
) -> None:
    result = _audit(mac_transition_bundle, tmp_path)
    assert result.score == 100, result.findings
    transitions = [row for row in mac_transition_bundle[3] if row.kind == "process_exec"]
    assert transitions
    assert all(row.facts["process_transition"]["execution_id"] for row in transitions)
    assert all(
        any(e.provenance.get("timing") for e in row.source_expectations if e.format == "ecar")
        for row in transitions
    )


@pytest.mark.parametrize("fault", ["duplicate", "missing", "image"])
def test_mac_projection_defects_still_fail(
    mac_transition_bundle: tuple, tmp_path: Path, fault: str
) -> None:
    records = deepcopy(mac_transition_bundle[4])
    target = next(
        record
        for record in records["ecar"]
        if record.fields.get("operation") == "exec"
        and record.fields.get("image_path") == "/usr/bin/find"
    )
    if fault == "duplicate":
        records["ecar"].append(target.model_copy(deep=True))
    elif fault == "missing":
        records["ecar"].remove(target)
    else:
        target.fields["image_path"] = "/unexpected/image"
    result = _audit(mac_transition_bundle, tmp_path, records=records)
    assert result.incorrect == 1, result.findings
    assert len({finding["check_id"] for finding in result.findings}) == 1
    assert result.score < 100


@pytest.mark.parametrize("fault", ["wrong_identity", "missing", "malformed"])
def test_false_timing_anchor_is_not_excused_by_matching_records(
    mac_transition_bundle: tuple, tmp_path: Path, fault: str
) -> None:
    rows = deepcopy(mac_transition_bundle[3])
    target = next(
        row
        for row in rows
        if row.kind == "process_exec"
        and any(
            e.provenance.get("timing", {}).get("anchors")
            for e in row.source_expectations
            if e.format == "ecar"
        )
    )
    expectation = next(e for e in target.source_expectations if e.format == "ecar")
    if fault == "wrong_identity":
        expectation.provenance["timing"]["anchors"][0]["identity"] = "unrelated-parent"
        rule = "invalid_timing_dependency_identity"
    elif fault == "missing":
        expectation.provenance.pop("timing")
        rule = "missing_process_timing_provenance"
    else:
        expectation.provenance["timing"] = {"native_time": "not-a-time"}
        rule = "invalid_process_timing_provenance"
    result = _audit(mac_transition_bundle, tmp_path, rows=rows)
    assert result.failure_counts.get(rule) == 1, result.findings
    assert result.incorrect == 1
    assert len({finding["check_id"] for finding in result.findings}) == 1


def test_repeat_and_source_filter_preserve_canonical_facts(
    mac_transition_bundle: tuple, tmp_path: Path
) -> None:
    scenario = mac_transition_bundle[1]

    def canonical(rows: list) -> list:
        return [
            (row.occurrence_id, row.time, row.facts, row.outcome, row.relationships) for row in rows
        ]

    repeated = tmp_path / "repeat"
    GenerationEngine(scenario.model_copy(deep=True), repeated).generate()
    assert canonical(_truth(repeated)[1]) == canonical(mac_transition_bundle[3])
    filtered = scenario.model_copy(deep=True)
    filtered.output.logs = [entry for entry in filtered.output.logs if entry["format"] != "ecar"]
    destination = tmp_path / "filtered"
    GenerationEngine(filtered, destination).generate()
    assert canonical(_truth(destination)[1]) == canonical(mac_transition_bundle[3])


def test_launch_item_no_evidence_does_not_excuse_other_stages(
    mac_transition_bundle: tuple, tmp_path: Path
) -> None:
    data = mac_transition_bundle[1].model_dump(mode="json")
    data["generation_seed"] = 42
    label = "org.example.ground-truth"
    path = "/Library/LaunchDaemons/org.example.ground-truth.plist"

    def step(name: str, time: str, event: dict) -> dict:
        return {
            "id": name,
            "time": time,
            "actor": "root",
            "system": "MAC-01",
            "activity": name,
            "events": [event],
        }

    def operation(name: str) -> dict:
        return {
            "type": "macos_launch_item",
            "operation": name,
            "label": label,
            "caller_ref": "root-admin",
        }

    data["storyline"] = [
        data["storyline"][0],
        step(
            "root-admin",
            "+2m",
            {
                "type": "process",
                "process_name": "/bin/sleep",
                "command_line": "/bin/sleep 600",
                "process_ref": "root-admin",
                "supplementary": "none",
            },
        ),
        step(
            "write-job",
            "+2m10s",
            {
                **operation("write"),
                "path": path,
                "program": "/bin/sleep",
                "arguments": ["/bin/sleep", "1"],
                "size_bytes": 512,
            },
        ),
        step("register-job", "+2m20s", {**operation("bootstrap"), "path": path}),
        data["storyline"][1],
        step("unload-job", "+5m", operation("unload")),
    ]
    scenario = Scenario.model_validate(data)
    root = tmp_path / "bundle"
    GenerationEngine(scenario, root).generate()
    document, rows = _truth(root)
    records, _ = EvaluationEngine(root, scenario)._parse_all_logs()
    bundle = root, scenario, document, rows, records
    control = _audit(bundle, tmp_path / "control")
    assert control.score == 100, control.findings
    zero = [
        action.storyline_id for action in control.actions if action.correct + action.incorrect == 0
    ]
    assert set(zero) == {"register-job", "unload-job"}

    altered = deepcopy(rows)
    registration = next(row for row in altered if row.storyline_id == "register-job")
    registration.facts["job_control"]["launchd_label"] = "different-job"
    result = _audit(bundle, tmp_path / "wrong-label", rows=altered)
    assert result.failure_counts.get("authored_launch_item_facts_disagreement") == 1

    altered = deepcopy(rows)
    write = next(
        row for row in altered if row.storyline_id == "write-job" and row.kind.startswith("file_")
    )
    altered[altered.index(write)] = write.model_copy(
        update={
            "kind": "job_control",
            "facts": {
                "job_control": {
                    "launchd_operation": "write",
                    "launchd_label": label,
                    "file_path": path,
                }
            },
            "source_expectations": [],
            "source_views": {},
            "coverage_gaps": [],
        }
    )
    result = _audit(bundle, tmp_path / "missing-write", rows=altered)
    assert result.failure_counts.get("missing_required_consequence") == 1, result.findings
