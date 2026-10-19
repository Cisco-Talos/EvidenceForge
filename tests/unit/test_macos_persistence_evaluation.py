# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import UTC, datetime

import pytest

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.storyline import ResolvedEvent


@pytest.mark.parametrize(
    "operation,object_type,action",
    [
        ("activate", "PROCESS", "CREATE"),
        ("exit", "PROCESS", "TERMINATE"),
        ("unload", "PROCESS", "TERMINATE"),
        ("write", "FILE", "CREATE"),
        ("remove", "FILE", "DELETE"),
    ],
)
def test_persistence_trace_requires_exact_stage_and_identity(
    operation: str, object_type: str, action: str
) -> None:
    scorer = CausalityScorer()
    scorer._macos_launch_gt = {
        "stage": [
            dict(
                launchd_operation=operation,
                actor_object_id="exact-actor",
                process_object_ids=["exact-process"],
                action=action.lower(),
                file_path="/Library/LaunchDaemons/org.example.worker.plist",
            )
        ]
    }
    event = ResolvedEvent(
        index=0,
        time=datetime(2026, 10, 19, tzinfo=UTC),
        actor="root",
        system="MAC-01",
        system_ip="192.0.2.10",
        activity="Invented stage",
        details={},
        event_types=["macos_launch_item"],
        storyline_id="stage",
    )
    fields = dict(
        hostname="MAC-01",
        object=object_type,
        action=action,
        objectID="exact-process",
        actorID="exact-actor",
        file_path="/Library/LaunchDaemons/org.example.worker.plist",
    )
    record = ParsedRecord(source_format="ecar", raw="", fields=fields, timestamp=event.time)
    fields = record.fields
    assert scorer._record_matches(record, "ecar", event, "macos_launch_item")
    fields["action"] = "MODIFY"
    assert not scorer._record_matches(record, "ecar", event, "macos_launch_item")
    fields["action"] = action
    fields["hostname"] = "ANOTHER-MAC"
    assert not scorer._record_matches(record, "ecar", event, "macos_launch_item")
    fields["hostname"] = "MAC-01"
    if object_type == "FILE":
        fields["actorID"] = "another-actor"
        assert not scorer._record_matches(record, "ecar", event, "macos_launch_item")
        fields["actorID"] = "exact-actor"
    fields["objectID"] = "other-process"
    fields["file_path"] = "/Library/LaunchDaemons/org.example.other.plist"
    assert not scorer._record_matches(record, "ecar", event, "macos_launch_item")
