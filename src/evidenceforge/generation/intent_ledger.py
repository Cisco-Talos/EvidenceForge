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
from typing import TYPE_CHECKING

from pydantic import BaseModel

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


def _semantic_spec_fingerprint(spec: BaseModel) -> str:
    """Return a stable fingerprint of execution semantics, excluding documentation metadata."""

    payload = spec.model_dump(mode="json", exclude_none=False)
    payload.pop("description", None)
    payload.pop("technique", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]
