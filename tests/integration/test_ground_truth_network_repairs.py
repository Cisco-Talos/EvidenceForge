"""Canonical UDP budgets and scan enforcement agree with actual source projections."""

from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.ground_truth_agreement import evaluate_ground_truth
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import NetworkSegment, NetworkSensor, System
from tests.integration.test_ground_truth_reconciliation import _scenario, _truth


def test_dns_budgets_survive_canonical_capture_and_native_rendering(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {"type": "dns_query", "query": "one.example.net", "answer": "93.184.216.34"},
            {"type": "dns_query", "query": "empty.example.net", "qtype": "AAAA", "answer": []},
        ],
    )
    scenario.generation_seed = 42
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    dns = [row for row in rows if row.facts.get("dns")]
    assert len(dns) >= 2
    for row in dns:
        for side in ("orig", "resp"):
            budget = row.facts["traffic"][side]
            assert budget["ip_bytes"] == budget["payload_bytes"] + 28 * budget["packets"]
        for exp in (
            e
            for e in row.source_expectations
            if e.format == "zeek_conn" and e.expected == "present"
        ):
            evidence = next(
                r
                for r in records["zeek_conn"]
                if r.fields.get("uid") == exp.identifiers["zeek_uid"]
            )
            view = row.source_views[exp.source_instance]
            for side in ("orig", "resp"):
                assert view.traffic[side] == row.facts["traffic"][side]
                assert evidence.fields[side + "_ip_bytes"] == view.traffic[side]["ip_bytes"]
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings


@pytest.mark.parametrize("mode", ["same_lan", "drop", "reject"])
def test_scan_failure_is_separate_from_path_policy_prevention(tmp_path: Path, mode: str) -> None:
    target_ip = "10.0.10.20" if mode == "same_lan" else "10.0.20.20"
    scenario = _scenario(
        tmp_path,
        [{"type": "port_scan", "target_ips": [target_ip], "ports": [445, 3389], "scan_rate": 10}],
        formats=["zeek", "ecar", "cisco_asa"],
    )
    scenario.generation_seed = 42
    scenario.environment.systems.append(
        System(hostname="WS02", ip=target_ip, os="Windows 11", type="workstation")
    )
    network = scenario.environment.network
    assert network is not None
    if mode == "same_lan":
        network.segments[0].systems.append("WS02")
    else:
        network.segments.append(
            NetworkSegment(
                name="targets", cidr="10.0.20.0/24", systems=["WS02"], exposure="internal"
            )
        )
        network.segments.append(
            NetworkSegment(name="isolated", cidr="10.99.0.0/24", exposure="internal")
        )
        network.sensors.insert(
            0,
            NetworkSensor(
                type="firewall",
                name="off-path",
                monitoring_segments=["isolated"],
                placement="tap",
                drop_mode="reject" if mode == "drop" else "drop",
                log_formats=["cisco_asa"],
            ),
        )
    network.sensors.append(
        NetworkSensor(
            type="firewall",
            name="gateway",
            monitoring_segments=[s.name for s in network.segments],
            placement="tap",
            default_action="deny",
            drop_mode="drop" if mode == "same_lan" else mode,
            log_formats=["cisco_asa"],
        )
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    probes = [
        row
        for row in rows
        if row.kind == "connection" and (row.facts.get("network") or {}).get("dst_ip") == target_ip
    ]
    assert len(probes) == 2
    for row in probes:
        net = row.facts["network"]
        denies = [
            record
            for record in records["cisco_asa"]
            if record.fields.get("msg_id") == 106023
            and record.fields.get("src_port") == net["src_port"]
            and record.fields.get("dst_ip") == target_ip
        ]
        if mode == "same_lan":
            assert not row.facts.get("firewall")
            assert row.outcome.result != "prevented"
            assert not denies
            assert all(
                e.expected == "absent" and e.reason == "topology_exclusion"
                for e in row.source_expectations
                if e.format == "cisco_asa"
            )
        else:
            assert row.outcome.result == "prevented"
            assert row.outcome.enforcing_entity == "gateway"
            assert net["conn_state"] == ("S0" if mode == "drop" else "REJ")
            assert len(denies) == 1
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
