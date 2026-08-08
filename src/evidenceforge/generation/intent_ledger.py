# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independent authored-intent ledger for future ground-truth reconciliation."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import TYPE_CHECKING

from pydantic import BaseModel

from evidenceforge.events.contracts import SemanticOccurrenceKey
from evidenceforge.utils.rng import stable_uuid

if TYPE_CHECKING:
    from evidenceforge.models.scenario import Scenario


class IntentSection(StrEnum):
    """Authored narrative section that owns one intent."""

    STORYLINE = "storyline"
    RED_HERRING = "red_herring"


@dataclass(frozen=True, slots=True)
class AuthoredIntent:
    """One immutable typed event specification captured before planning."""

    intent_id: str
    section: IntentSection
    step_id: str
    event_type: str
    semantic_instance_key: str
    authored_time: str
    actor: str
    system: str
    activity: str


@dataclass(frozen=True, slots=True)
class IntentReconciliation:
    """Comparison between independent authored intent and planned intent references."""

    expected_intent_ids: frozenset[str]
    planned_intent_ids: frozenset[str]
    missing_intent_ids: frozenset[str]
    unexpected_intent_ids: frozenset[str]

    @property
    def complete(self) -> bool:
        """Return whether planning accounts for every and only authored intent."""

        return not self.missing_intent_ids and not self.unexpected_intent_ids


@dataclass(frozen=True, slots=True)
class AuthoredIntentLedger:
    """Frozen authored oracle retained independently from generated occurrences."""

    scenario_name: str
    intents: tuple[AuthoredIntent, ...]

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> AuthoredIntentLedger:
        """Capture typed storyline and red-herring intent without consulting generation output."""

        intents: list[AuthoredIntent] = []
        duplicate_counts: Counter[tuple[IntentSection, str, str]] = Counter()
        sections = (
            (IntentSection.STORYLINE, scenario.storyline or []),
            (IntentSection.RED_HERRING, scenario.red_herrings or []),
        )
        for section, steps in sections:
            for step in steps:
                for spec in step.events:
                    fingerprint = _semantic_spec_fingerprint(spec)
                    peer_key = (section, step.id, fingerprint)
                    peer_ordinal = duplicate_counts[peer_key]
                    duplicate_counts[peer_key] += 1
                    semantic_instance_key = f"{fingerprint}:{peer_ordinal}"
                    intents.append(
                        AuthoredIntent(
                            intent_id=stable_uuid(
                                "authored-intent",
                                scenario.name,
                                section.value,
                                step.id,
                                semantic_instance_key,
                            ),
                            section=section,
                            step_id=step.id,
                            event_type=spec.type,
                            semantic_instance_key=semantic_instance_key,
                            authored_time=step.time,
                            actor=step.actor,
                            system=step.system,
                            activity=step.activity,
                        )
                    )
        return cls(scenario_name=scenario.name, intents=tuple(intents))

    @property
    def intent_ids(self) -> frozenset[str]:
        """Return all authored intent IDs."""

        return frozenset(intent.intent_id for intent in self.intents)

    def reconcile(self, planned_intent_ids: Iterable[str]) -> IntentReconciliation:
        """Compare authored intent with the IDs acknowledged by an action planner."""

        expected = self.intent_ids
        planned = frozenset(planned_intent_ids)
        return IntentReconciliation(
            expected_intent_ids=expected,
            planned_intent_ids=planned,
            missing_intent_ids=expected - planned,
            unexpected_intent_ids=planned - expected,
        )

    def intent_at(
        self,
        section: IntentSection,
        step_id: str,
        event_index: int,
    ) -> AuthoredIntent:
        """Return the authored intent at one typed step-relative position."""

        matches = tuple(
            intent
            for intent in self.intents
            if intent.section == section and intent.step_id == step_id
        )
        try:
            return matches[event_index]
        except IndexError as exc:
            raise KeyError(
                f"No authored intent for {section.value} step {step_id!r} event {event_index}"
            ) from exc


@dataclass(frozen=True, slots=True)
class IntentSourceObservation:
    """One source-observation counter attached to an authored intent."""

    source: str
    status: str
    count: int


@dataclass(frozen=True, slots=True)
class IntentExecutionSnapshot:
    """Immutable planned/occurrence/observation evidence for one authored intent."""

    intent_id: str
    planned: bool
    action_ids: tuple[str, ...]
    occurrence_ids: tuple[str, ...]
    source_observations: tuple[IntentSourceObservation, ...]

    @property
    def source_status(self) -> dict[str, dict[str, int]]:
        """Return source observations in the ground-truth manifest shape."""

        result: dict[str, dict[str, int]] = {}
        for observation in self.source_observations:
            result.setdefault(observation.source, {})[observation.status] = observation.count
        return result


class IntentExecutionLedger:
    """Thread-safe mutable recorder that freezes execution evidence for reconciliation."""

    def __init__(self, authored: AuthoredIntentLedger):
        self._authored = authored
        self._planned: set[str] = set()
        self._action_ids: dict[str, set[str]] = {}
        self._occurrence_ids: dict[str, set[str]] = {}
        self._source_counts: Counter[tuple[str, str, str]] = Counter()
        self._lock = RLock()

    def mark_planned(self, intent_id: str) -> None:
        """Record that execution entered the planner path for one authored intent."""

        with self._lock:
            self._planned.add(intent_id)

    def record_occurrence(
        self,
        intent_id: str,
        occurrence_key: SemanticOccurrenceKey,
    ) -> None:
        """Record one stable semantic occurrence identity."""

        with self._lock:
            self._action_ids.setdefault(intent_id, set()).add(occurrence_key.action_id)
            self._occurrence_ids.setdefault(intent_id, set()).add(occurrence_key.occurrence_id)

    def record_observation(
        self,
        intent_id: str,
        source: str,
        status: str,
    ) -> None:
        """Record one source decision for an authored intent."""

        with self._lock:
            self._source_counts[(intent_id, source, status)] += 1

    def snapshot(self) -> tuple[IntentExecutionSnapshot, ...]:
        """Freeze execution evidence in stable authored-intent order."""

        with self._lock:
            known_ids = [intent.intent_id for intent in self._authored.intents]
            observed_ids = {intent_id for intent_id, _source, _status in self._source_counts}
            execution_ids = (
                self._planned | set(self._action_ids) | set(self._occurrence_ids) | observed_ids
            )
            unexpected_ids = sorted(execution_ids - set(known_ids))
            intent_ids = [*known_ids, *unexpected_ids]
            snapshots = []
            for intent_id in intent_ids:
                observations = tuple(
                    IntentSourceObservation(source=source, status=status, count=count)
                    for (candidate_id, source, status), count in sorted(self._source_counts.items())
                    if candidate_id == intent_id
                )
                snapshots.append(
                    IntentExecutionSnapshot(
                        intent_id=intent_id,
                        planned=intent_id in self._planned,
                        action_ids=tuple(sorted(self._action_ids.get(intent_id, set()))),
                        occurrence_ids=tuple(sorted(self._occurrence_ids.get(intent_id, set()))),
                        source_observations=observations,
                    )
                )
            return tuple(snapshots)

    def reconcile(self) -> IntentReconciliation:
        """Compare the current planned set with the independent authored oracle."""

        with self._lock:
            return self._authored.reconcile(self._planned)


def _semantic_spec_fingerprint(spec: BaseModel) -> str:
    """Return a stable fingerprint of execution semantics, excluding documentation metadata."""

    payload = spec.model_dump(mode="json", exclude_none=False)
    payload.pop("description", None)
    payload.pop("technique", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]
