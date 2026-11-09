# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native Mac trace presence retains identity, provenance and authored-time checks."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.storyline import ResolvedEvent

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _event(kind: str = "process") -> ResolvedEvent:
    return ResolvedEvent(
        index=0,
        time=T0,
        actor="root",
        system="MAC-01",
        system_ip="10.0.0.1",
        activity="check",
        details={"process_name": "/usr/bin/sw_vers"},
        event_types=[kind],
        storyline_id="step",
    )


def _record(at: datetime, pid: int = 42) -> ParsedRecord:
    return ParsedRecord(
        source_format="macos_endpoint_security",
        source_host="MAC-01.example.test",
        raw="native",
        timestamp=at,
        fields={
            "event_type": 9,
            "event": {
                "exec": {
                    "target": {
                        "audit_token": {"pid": pid},
                        "executable": {"path": "/usr/bin/sw_vers"},
                    },
                    "args": ["/usr/bin/sw_vers"],
                }
            },
        },
    )


def _facts(at: datetime, pid: int = 42) -> dict[str, object]:
    return {
        "pid": pid,
        "process_name": "/usr/bin/sw_vers",
        "command_line": "/usr/bin/sw_vers",
        "_canonical_time": at,
        "launchd_operation": "activate",
        "process_object_ids": [f"object-{pid}"],
    }


@pytest.mark.parametrize("kind", ["process", "macos_launch_item"])
def test_native_exec_supplies_exact_trace_when_normalized_source_is_missing(kind: str) -> None:
    scorer = CausalityScorer()
    setattr(
        scorer,
        "_macos_process_gt" if kind == "process" else "_macos_launch_gt",
        {"step": [_facts(T0)]},
    )
    assert scorer._record_matches(_record(T0), "macos_endpoint_security", _event(kind), kind)


@pytest.mark.parametrize(
    "fault", ["host", "pid", "image", "argv", "time", "stage", "parse", "missing_provenance"]
)
def test_native_trace_rejects_lookalikes(fault: str) -> None:
    scorer = CausalityScorer()
    scorer._macos_process_gt = {"step": [_facts(T0)]}
    record = _record(T0)
    if fault == "host":
        record.source_host = "OTHER-MAC"
    elif fault == "missing_provenance":
        record.source_host = None
    elif fault == "pid":
        record.fields["event"]["exec"]["target"]["audit_token"]["pid"] = 99
    elif fault == "image":
        record.fields["event"]["exec"]["target"]["executable"]["path"] = "/bin/sh"
    elif fault == "argv":
        record.fields["event"]["exec"]["args"].append("-productVersion")
    elif fault == "time":
        record.timestamp += timedelta(minutes=5)
    elif fault == "stage":
        record.fields["event_type"] = 11
    else:
        record.parse_errors.append("invalid native record")
    assert not scorer._record_matches(record, "macos_endpoint_security", _event(), "process")


def test_launch_exit_requires_activated_identity_and_current_image() -> None:
    scorer = CausalityScorer()
    scorer._macos_launch_gt = {
        "step": [
            _facts(T0),
            {
                "launchd_operation": "exit",
                "process_object_ids": ["object-42"],
                "_canonical_time": T0 + timedelta(seconds=1),
            },
        ]
    }
    record = _record(T0 + timedelta(seconds=1))
    record.fields = {"event_type": 15, "process": record.fields["event"]["exec"]["target"]}
    assert scorer._record_matches(
        record, "macos_endpoint_security", _event("macos_launch_item"), "macos_launch_item"
    )
    scorer._macos_launch_gt["step"][1]["process_object_ids"] = ["unrelated-object"]
    assert not scorer._record_matches(
        record, "macos_endpoint_security", _event("macos_launch_item"), "macos_launch_item"
    )


def test_actual_search_anchors_do_not_hide_authored_timing_drift() -> None:
    scorer = CausalityScorer()
    times = [T0 + timedelta(minutes=20), T0 + timedelta(minutes=40)]
    scorer._macos_process_gt = {"step": [_facts(at, 42 + i) for i, at in enumerate(times)]}
    scorer._macos_trace_times = {("step", "process"): times}
    records = [_record(at, 42 + i) for i, at in enumerate(times)]
    event = _event()
    found = scorer._search_for_event_indexed(
        event, "process", scorer._build_host_time_index({"macos_endpoint_security": records})
    )
    assert found == records
    assert event.time == T0
    assert not any(key.startswith("_anchor_time") for key in event.details)
    event.traces = found
    assert scorer._score_temporal_integrity([event], EvaluationContext()).score == 0
    scorer._pivot_host_aliases = {"mac-01.example.test": "mac-01", "mac-01": "mac-01"}
    scorer._pivot_user_aliases = {}
    scorer._pivot_host_ips = {}
    scorer._pivot_ip_hosts = {}
    values = scorer._observed_indicator_values(event)
    assert "host:mac-01" in values
    assert not any(value.startswith("user:") for value in values)
