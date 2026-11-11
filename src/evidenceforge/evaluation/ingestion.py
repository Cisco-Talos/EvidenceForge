"""Shared sufficient statistics computed during independent source ingestion."""

from __future__ import annotations

from datetime import UTC

from evidenceforge.evaluation._shared import _extract_hostname, _extract_username
from evidenceforge.evaluation.anomaly import _extract_process_key
from evidenceforge.evaluation.ground_truth_agreement import _RecordIndex
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.plausibility import (
    _MAX_PIVOT_BUCKET_RECORDS,
    PlausibilityAccumulator,
    _coerce_key,
    _extract_event_type,
    _get_pivot_key_b,
    _matches_condition,
)
from evidenceforge.evaluation.pillars.timing import (
    _extract_system_service,
    _is_rate_plausibility_user_event,
)
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.evaluation.storage import (
    append_group,
    bounded_counter,
    bounded_counter_groups,
    bounded_groups,
    bounded_list,
)
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS


class IngestionStatistics:
    """Share exact counts and ordered timestamps across otherwise independent checks."""

    def __init__(
        self,
        scenario: Scenario,
        *,
        source_index: bool = False,
        available_formats: set[str] | None = None,
    ) -> None:
        self.source_index = _RecordIndex({}, scenario) if source_index else None
        enabled = {item["format"] for item in scenario.output.logs if "format" in item}
        self.plausibility = PlausibilityAccumulator(VisibilityModel(scenario, enabled))
        self.pair_definitions = load_rules_file("cross_source_pairs.yaml").get("pairs", [])
        self.pair_a = {index: bounded_list() for index in range(len(self.pair_definitions))}
        self.pair_b = {index: bounded_groups() for index in range(len(self.pair_definitions))}
        self.pairs_by_format: dict[str, list[tuple[int, str]]] = {}
        for index, definition in enumerate(self.pair_definitions):
            if available_formats is not None and any(
                definition.get(f"format_{side}", "") not in available_formats for side in ("a", "b")
            ):
                continue
            for side in ("a", "b"):
                self.pairs_by_format.setdefault(definition.get(f"format_{side}", ""), []).append(
                    (index, side)
                )
        self.users = bounded_groups(ordered=True)
        self.rate_users = bounded_groups(ordered=True)
        self.services = bounded_groups(ordered=True)
        self.system_events = 0
        self.user_types = bounded_counter_groups()
        self.process_frequency = bounded_counter()
        self.failed_logons = bounded_counter()
        self.distributions = bounded_counter_groups()
        self.profiles = load_rules_file("distributions.yaml")
        self.system_accounts = {account.lower() for account in BUILTIN_ACCOUNTS}
        self.process_total = 0

    def consume(self, format_name: str, record: ParsedRecord) -> None:
        """Consume only schema-valid records, preserving downstream exclusion semantics."""
        if self.source_index is not None:
            self.source_index.add(format_name, record)
        self.plausibility.consume_value(format_name, record)
        self.plausibility.consume_cooccurrence(format_name, record)
        for index, side in self.pairs_by_format.get(format_name, ()):
            definition = self.pair_definitions[index]
            if not _matches_condition(record, definition.get(f"condition_{side}") or {}):
                continue
            if side == "a":
                self.pair_a[index].append(record)
            else:
                key = _get_pivot_key_b(record, definition.get("pivot_key", {}))
                if key is not None:
                    bucket = self.pair_b[index][key]
                    if len(bucket) < _MAX_PIVOT_BUCKET_RECORDS:
                        bucket.append(record)
        user = _extract_username(record)
        if user:
            self.user_types[user][_extract_event_type(record)] += 1
        process = _extract_process_key(record, format_name)
        if process:
            self.process_frequency[process] += 1
            self.process_total += 1
        if (
            format_name == "windows_event_security"
            and record.fields.get("EventID") == 4625
            and record.timestamp is not None
        ):
            target = record.fields.get("TargetUserName", "")
            if target and target != "-":
                self.failed_logons[(target.lower(), int(record.timestamp.timestamp()) // 600)] += 1
        for index, profile in enumerate(self.profiles.get(format_name, ())):
            value = record.fields.get(profile["field"])
            if value is not None:
                self.distributions[(format_name, index)][
                    _coerce_key(value, profile["reference"])
                ] += 1
        timestamp = record.timestamp
        if timestamp is None:
            return
        timestamp = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
        if user:
            append_group(self.users, user, timestamp, sort=timestamp)
            if _is_rate_plausibility_user_event(record):
                append_group(self.rate_users, user, timestamp, sort=timestamp)
            if user in self.system_accounts:
                hostname = _extract_hostname(record)
                service = _extract_system_service(record)
                if hostname and service != "other":
                    append_group(self.services, (hostname, service), timestamp, sort=timestamp)
                    self.system_events += 1
