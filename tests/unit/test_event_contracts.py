# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the behavior-preserving canonical event contract foundation."""

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from evidenceforge.events import NetworkContext, SecurityEvent
from evidenceforge.events.contexts import RawContext
from evidenceforge.events.contracts import (
    EVENT_KIND_CONTRACTS,
    LEGACY_CONSUMER_ONLY_EVENT_TYPES,
    RAW_EVENT_TYPE,
    ContextKind,
    ContractViolationCode,
    EventKind,
    FormatKind,
    OccurrenceRole,
    SemanticOccurrenceKey,
    shadow_seal,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.state_manager import StateManager


def _timestamp() -> datetime:
    return datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


def _network() -> NetworkContext:
    return NetworkContext(
        src_ip="10.0.0.10",
        src_port=50000,
        dst_ip="198.51.100.20",
        dst_port=443,
        protocol="tcp",
    )


def test_registry_is_closed_over_every_event_kind() -> None:
    """Every typed canonical kind has exactly one registry contract."""

    assert set(EVENT_KIND_CONTRACTS) == set(EventKind)
    assert RAW_EVENT_TYPE not in {kind.value for kind in EventKind}
    assert LEGACY_CONSUMER_ONLY_EVENT_TYPES.isdisjoint(kind.value for kind in EventKind)


def test_registry_matches_reviewed_constructor_context_and_format_inventory() -> None:
    """The approved path census seeds an exact closure gate for the foundation registry."""

    root = Path(__file__).resolve().parents[2]
    inventory = json.loads(
        (root / "docs/design/realism-review/event-context-paths.json").read_text(encoding="utf-8")
    )
    produced = {row["event_type"] for row in inventory["events"] if row.get("constructors")}
    consumer_only = {
        row["event_type"]
        for row in inventory["events"]
        if not row.get("constructors") and row.get("emitter_consumers")
    }
    context_fields = set(inventory["security_event"]["payload_field_names"]) - {
        "identity_plan",
        "network_observations",
        "source_timing",
    }

    assert produced == {kind.value for kind in EventKind} | {RAW_EVENT_TYPE}
    assert consumer_only == LEGACY_CONSUMER_ONLY_EVENT_TYPES
    assert context_fields == {context.value for context in ContextKind}
    assert {row["format"] for row in inventory["formats"]} == {
        format_kind.value for format_kind in FormatKind
    }


def test_source_has_no_unregistered_literal_security_event_kind() -> None:
    """A new literal constructor cannot bypass the closed registry unnoticed."""

    root = Path(__file__).resolve().parents[2]
    permitted = {kind.value for kind in EventKind} | {RAW_EVENT_TYPE}
    discovered: set[str] = set()
    for source in (root / "src/evidenceforge").rglob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if call_name != "SecurityEvent":
                continue
            event_type = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "event_type"),
                None,
            )
            if isinstance(event_type, ast.Constant) and isinstance(event_type.value, str):
                discovered.add(event_type.value)

    assert discovered <= permitted


def test_shadow_seal_captures_valid_immutable_occurrence() -> None:
    """A valid event produces a frozen occurrence snapshot without changing the event."""

    event = SecurityEvent(timestamp=_timestamp(), event_type="connection", network=_network())

    result = shadow_seal(event)

    assert result.valid
    assert result.occurrence is not None
    assert result.occurrence.kind is EventKind.CONNECTION
    assert result.occurrence.canonical_time == event.timestamp
    assert event.event_id == ""


def test_shadow_seal_reports_missing_and_forbidden_contexts() -> None:
    """Shadow mode reports contract defects without rejecting legacy construction."""

    event = SecurityEvent(
        timestamp=_timestamp(),
        event_type="connection",
        raw=RawContext(target_format="syslog", fields={}),
    )

    result = shadow_seal(event)

    assert {violation.code for violation in result.violations} == {
        ContractViolationCode.MISSING_CONTEXT,
        ContractViolationCode.FORBIDDEN_CONTEXT,
    }


def test_shadow_seal_keeps_raw_outside_canonical_registry() -> None:
    """The explicit raw adapter is recognized without registering it as canonical truth."""

    event = SecurityEvent(
        timestamp=_timestamp(),
        event_type=RAW_EVENT_TYPE,
        raw=RawContext(target_format="syslog", fields={"message": "test"}),
    )

    result = shadow_seal(event)

    assert result.valid
    assert result.raw_escape_hatch
    assert result.occurrence is None


def test_shadow_seal_reports_unknown_event_kind() -> None:
    """Unknown internal strings remain compatible but become visible contract debt."""

    result = shadow_seal(SecurityEvent(timestamp=_timestamp(), event_type="future_event"))

    assert result.occurrence is None
    assert [violation.code for violation in result.violations] == [
        ContractViolationCode.UNKNOWN_EVENT_KIND
    ]


def test_semantic_occurrence_id_ignores_unrelated_dispatch_position() -> None:
    """Action-relative occurrence IDs depend only on semantic identity."""

    anchor = ActionAnchor(family="ssh", stable_id="story-1:ssh:transport", source="storyline")
    first = anchor.occurrence_key(OccurrenceRole.PRIMARY, "tcp-10.0.0.10-50000-10.0.0.20-22")
    unrelated = SemanticOccurrenceKey(
        action_id="another-action",
        role=OccurrenceRole.PRIMARY,
        instance_key="unrelated",
    )
    repeated = anchor.occurrence_key(
        OccurrenceRole.PRIMARY,
        "tcp-10.0.0.10-50000-10.0.0.20-22",
    )

    assert unrelated.occurrence_id != first.occurrence_id
    assert repeated.occurrence_id == first.occurrence_id


def test_dispatcher_records_shadow_violations_without_blocking() -> None:
    """Dispatch preserves compatibility while exposing aggregate shadow debt."""

    state_manager = MagicMock(spec=StateManager)
    dispatcher = EventDispatcher(state_manager=state_manager, emitters={})
    event = SecurityEvent(timestamp=_timestamp(), event_type="future_event")

    assert dispatcher.dispatch(event) == {}

    state_manager.apply.assert_called_once_with(event)
    assert event.contract_seal is not None
    assert dispatcher.contract_violation_counts == {"unknown_event_kind": 1}
    assert dispatcher.contract_violations_by_event == {"future_event": {"unknown_event_kind": 1}}
