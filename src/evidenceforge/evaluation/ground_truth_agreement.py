"""Independent source expectation and native-record verification for schema-v5 truth."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import re
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict, defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from email.utils import getaddresses
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import pytz
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.config.observation_profiles import get_observation_profile
from evidenceforge.events.evidence_projection import (
    candidate_formats,
    host_routes,
    native_requirements,
    projection_phase,
    required_capabilities,
    source_event_contracts,
)
from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    GroundTruthSourceExpectation,
    read_ground_truth_occurrences,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
from evidenceforge.generation.activity.timing_profiles import load_timing_profiles
from evidenceforge.generation.collection_deployment import SourceInstanceDeployment
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger
from evidenceforge.generation.source_deployment_compiler import compile_scenario_source_deployment
from evidenceforge.models import Scenario
from evidenceforge.models.exceptions import EvaluationError
from evidenceforge.models.scenario import EmailDistributionGroup, EmailMessageEventSpec

from .finding_samples import FindingSamples
from .parsers import ParsedRecord, RecordCorpus
from .process_commands import process_commands_agree
from .storage import (
    SpillGroups,
    SpillSequence,
    append_group,
    bounded_groups,
    bounded_list,
    bounded_map,
    current_workspace,
    record_identity,
)


class ActionAgreement(BaseModel):
    """One equally weighted authored action, regardless of source fan-out."""

    model_config = ConfigDict(extra="forbid")
    intent_id: str
    storyline_id: str
    correct: int = 0
    incorrect: int = 0
    expected_absences: int = 0
    coverage_gaps: int = 0
    occurrences: int = 0
    found: int = 0
    fact_checks: int = 0
    fact_errors: int = 0
    timing_checks: int = 0
    timing_errors: int = 0
    score: float = 100.0
    zero_check_reason: str | None = None


class GroundTruthAgreementResult(BaseModel):
    """Bounded diagnostics plus complete counts for every authored action."""

    model_config = ConfigDict(extra="forbid")
    score: float
    actions: list[ActionAgreement]
    findings: list[dict] = Field(default_factory=list)
    failure_counts: dict[str, int] = Field(default_factory=dict)
    correct: int = 0
    incorrect: int = 0
    expected_absences: int = 0
    coverage_gaps: int = 0
    total_findings: int = 0
    displayed_findings: int = 0
    findings_truncated: bool = False
    verification_limitations: list[str] = Field(default_factory=list)


class _RecordIndex:
    def __init__(self, records: RecordCorpus, scenario: Scenario) -> None:
        self.aliases: dict[str, str] = {}
        domain = scenario.environment.domain or next(
            (
                user.email.split("@", 1)[1]
                for user in scenario.environment.users
                if user.email and "@" in user.email and "." in user.email.split("@", 1)[1]
            ),
            "corp.local",
        )
        original_hosts = {
            host.hostname.casefold(): host.hostname for host in scenario.environment.systems
        }
        if scenario.environment.network:
            original_hosts.update(
                {
                    str(sensor.hostname or sensor.name).casefold(): str(
                        sensor.hostname or sensor.name
                    )
                    for sensor in scenario.environment.network.sensors
                }
            )
        for host in scenario.environment.systems:
            name = host.hostname.casefold()
            self.aliases[name] = name
            self.aliases[f"{name}.{domain}".casefold()] = name
        for sensor in scenario.environment.network.sensors if scenario.environment.network else []:
            name = str(sensor.hostname or sensor.name).casefold()
            self.aliases[name] = name
            self.aliases[sensor.name.casefold()] = name
            self.aliases[f"{name}.{domain}".casefold()] = name
        self.times = {}
        self.timestamps = bounded_map()
        self._scenario = scenario
        self._original_hosts = original_hosts
        workspace = current_workspace()
        buckets = SpillGroups(workspace, ordered=True) if workspace else defaultdict(list)
        self.ids = bounded_groups()
        self.buckets = buckets
        for fmt, items in records.items():
            for record in items:
                self.add(fmt, record)
        if workspace is not None:
            self.buckets = buckets
            self.times = None
        else:
            self.buckets = {
                key: sorted(items, key=lambda r: self.time(r).timestamp() if self.time(r) else 0)
                for key, items in buckets.items()
            }
            self.times = {
                key: [self.time(r).timestamp() if self.time(r) else 0 for r in items]
                for key, items in self.buckets.items()
            }

    def add(self, fmt: str, record: ParsedRecord) -> None:
        """Index one independently validated source record during ingestion."""
        if record.parse_errors:
            return
        host = self.host(
            record.source_host
            or record.source_instance
            or str(record.fields.get("hostname") or record.fields.get("Computer") or "")
        )
        if record.timestamp is not None:
            timestamp = record.timestamp
            if timestamp.tzinfo is None:
                from evidenceforge.utils.time import get_system_timezone

                zone = pytz.timezone(
                    get_system_timezone(
                        self._original_hosts.get(host, host), self._scenario.environment
                    )
                )
                timestamp = zone.localize(timestamp)
            timestamp = timestamp.astimezone(UTC)
            if current_workspace() is None:
                self.timestamps[record_identity(record)] = timestamp
        append_group(
            self.buckets,
            (fmt, host),
            record,
            sort=timestamp.timestamp() if record.timestamp is not None else 0.0,
        )
        for field in ("uid", "fuid", "objectID", "execution_id", "logon_id", "ppid", "pid"):
            if record.fields.get(field):
                append_group(
                    self.ids,
                    (fmt, host, field, str(record.fields[field])),
                    record,
                    sort=timestamp.timestamp() if record.timestamp is not None else 0.0,
                )

    def host(self, value: str) -> str:
        return self.aliases.get(value.casefold(), value.casefold())

    def time(self, record: ParsedRecord) -> datetime | None:
        """Return an independently normalized source timestamp without mutating input."""
        if self.times is not None:
            return self.timestamps.get(record_identity(record))
        timestamp = record.timestamp
        if timestamp is None:
            return None
        if timestamp.tzinfo is None:
            from evidenceforge.utils.time import get_system_timezone

            host = self.host(
                record.source_host
                or record.source_instance
                or str(record.fields.get("hostname") or record.fields.get("Computer") or "")
            )
            zone = pytz.timezone(
                get_system_timezone(
                    self._original_hosts.get(host, host), self._scenario.environment
                )
            )
            timestamp = zone.localize(timestamp)
        return timestamp.astimezone(UTC)

    def identity_at(
        self, fmt: str, host: str, field: str, value: str, at: datetime
    ) -> Sequence[ParsedRecord]:
        """Find timing witnesses without scanning a process's complete lifetime."""
        records = self.ids.get((fmt, host, field, value), ())
        if isinstance(records, SpillSequence):
            return records.in_range(at.timestamp() - 0.001, at.timestamp() + 0.001)
        return records

    @staticmethod
    def anchor(
        row: GroundTruthOccurrence,
        expectation: GroundTruthSourceExpectation,
        timing: str,
        selector: dict | None = None,
    ) -> datetime:
        """Resolve source-native lifecycle timing from its frozen receipt."""
        if (
            selector
            and selector.get("EventID") == 22
            and expectation.format == "windows_event_sysmon"
            and expectation.identifiers.get("sysmon_dns_render_time")
        ):
            return datetime.fromisoformat(expectation.identifiers["sysmon_dns_render_time"])
        anchor = expectation.expected_time or row.time
        view = row.source_views.get(expectation.source_instance)
        if (
            timing == "transport_close"
            and view is not None
            and view.firewall_teardown_time is not None
        ):
            return view.firewall_teardown_time + (anchor - (view.start_time or row.time))
        return anchor

    def candidates(
        self,
        row: GroundTruthOccurrence,
        expectation: GroundTruthSourceExpectation,
        selector: dict,
        timing: str,
    ) -> list[ParsedRecord]:
        fmt, host = expectation.format, self.host(expectation.source_host)
        for context in (row.facts.get("src_host"), row.facts.get("dst_host")):
            if (
                isinstance(context, dict)
                and self.host(str(context.get("hostname") or "")) == host
                and context.get("fqdn")
            ):
                self.aliases[str(context["fqdn"]).casefold()] = host
        for field in ("uid", "fuid"):
            if selector.get(field):
                return self.ids.get((fmt, host, field, str(selector[field])), [])
        anchor = self.anchor(row, expectation, timing, selector)
        tolerance = (
            0.001
            if fmt == "windows_event_sysmon" and selector.get("EventID") == 22
            else expectation.timing_tolerance_seconds
        )
        start = anchor.timestamp() - tolerance
        end = anchor.timestamp() + tolerance
        quantum = (
            source_event_contracts()
            .get("native_identity_clock_microseconds", {})
            .get(row.kind, {})
            .get(fmt)
        )
        if quantum and timing == "point":
            start = (int(anchor.timestamp() * 1_000_000) // quantum) * quantum / 1_000_000
            end = ((int(anchor.timestamp() * 1_000_000) // quantum) + 1) * quantum / 1_000_000
        if timing == "interval":
            network = row.facts.get("network") or {}
            if network.get("closed_at"):
                end = max(end, datetime.fromisoformat(network["closed_at"]).timestamp() + 2)
        key = (fmt, host)
        items = self.buckets.get(key, [])
        if isinstance(items, SpillSequence):
            return items.in_range(start, end, exclusive_upper=bool(quantum and timing == "point"))
        if self.times is None:
            return []
        times = self.times.get(key, [])
        upper = (
            bisect_left(times, end) if quantum and timing == "point" else bisect_right(times, end)
        )
        return items[bisect_left(times, start) : upper]


def _normalize_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return getattr(address, "ipv4_mapped", None) or address


def _short_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    workspace = current_workspace()
    limit = min(4096, workspace.memory_bytes // 4096) if workspace else 0
    if not limit:
        return _normalize_ip(value)
    cache = workspace.shared.setdefault("ip_normalization", OrderedDict())
    if value in cache:
        cache.move_to_end(value)
        return cache[value]
    result = _normalize_ip(value)
    cache[value] = result
    if len(cache) > limit:
        cache.popitem(last=False)
    return result


def _equal(actual: object, expected: object, key: str) -> bool:
    if isinstance(actual, str) and isinstance(expected, str) and actual == expected:
        return True
    if key.casefold() in {"sha256", "sha1", "md5", "fingerprint"}:
        return str(actual).casefold() == str(expected).casefold()
    if key.endswith("destination.new_path") and isinstance(actual, dict):
        actual = str(
            PurePosixPath(actual.get("dir", {}).get("path", "")) / actual.get("filename", "")
        )
    if (
        key == "TargetObject"
        and isinstance(expected, str)
        and expected.startswith("HKCU\\")
        and isinstance(actual, str)
        and actual.startswith("HKU\\")
    ):
        return actual.split("\\", 2)[-1].casefold() == expected.removeprefix("HKCU\\").casefold()
    if key == "QueryResults" and isinstance(actual, str) and isinstance(expected, list):
        actual = [item for item in actual.rstrip(";").split(";") if item and item != "-"]
    if isinstance(expected, list):
        return (
            sorted(str(x) for x in (actual or [])) == sorted(str(x) for x in expected)
            if isinstance(actual, (list, tuple)) or not actual
            else False
        )
    if isinstance(expected, int):
        try:
            return int(str(actual), 16 if str(actual).lower().startswith("0x") else 10) == expected
        except (TypeError, ValueError):
            return False
    if any(part in key.lower() for part in ("ip", "address", "orig_h", "resp_h")):
        a_text, b_text = str(actual), str(expected)
        a = _short_ip(a_text) if len(a_text) <= 128 else _normalize_ip(a_text)
        b = _short_ip(b_text) if len(b_text) <= 128 else _normalize_ip(b_text)
        if a is not None and b is not None:
            return a == b
    if "UserName" in key or key in {"principal", "User"}:
        return (
            str(actual).rsplit("\\", 1)[-1].casefold()
            == str(expected).rsplit("\\", 1)[-1].casefold()
        )
    if key.endswith("LogonId"):
        return str(actual).lower().lstrip("0") == str(expected).lower().lstrip("0")
    return actual == expected


def _field_value(fields: dict, path: str) -> object:
    if path in fields:
        return fields[path]
    result: object = fields
    for part in path.split("."):
        if isinstance(result, dict):
            result = result.get(part)
        elif isinstance(result, (list, tuple)) and part.isdigit() and int(part) < len(result):
            result = result[int(part)]
        else:
            return None
    return result


def _fields_match(record: ParsedRecord, fields: dict) -> bool:

    return all(
        any(_equal(_field_value(record.fields, alias), expected, alias) for alias in key.split("|"))
        for key, expected in fields.items()
    )


def _email_recipients_match(
    spec: EmailMessageEventSpec, email: dict, groups: list[EmailDistributionGroup]
) -> bool:
    """Check requested headers separately from independently expanded mailboxes."""
    requested: set[str] = set()
    for channel in ("to", "cc", "bcc"):
        expected = {address.casefold() for address in getattr(spec, channel)}
        actual = {address.casefold() for _, address in getaddresses(email.get(channel, []))}
        if actual != expected:
            return False
        requested.update(expected)
    memberships = {
        group.address.casefold(): {member.casefold() for member in group.members}
        for group in groups
    }
    expanded: set[str] = set()
    for address in requested:
        expanded.update(memberships.get(address, {address}))
    return expanded == {address.casefold() for address in email.get("expanded_rcptto", [])}


def _bounded_facts(fields: dict) -> dict:
    """Bound examples by field count and value length as well as example count."""
    result = {}
    for key, value in list(fields.items())[:20]:
        encoded = json.dumps(value, default=str)
        result[key] = value if len(encoded) <= 512 else encoded[:512] + "…"
    return result


def _timing_details(value: object) -> dict:
    """Keep every bounded dependency visible without retaining arbitrary payloads."""
    if not isinstance(value, dict):
        return {"invalid_value": str(value)[:512]} if value is not None else {}
    result = _bounded_facts(value)
    anchors = value.get("anchors")
    if isinstance(anchors, list):
        result["anchor_count"] = len(anchors)
        result["anchors_truncated"] = len(anchors) > 8
        result["anchors"] = [
            _bounded_facts(anchor) if isinstance(anchor, dict) else str(anchor)[:512]
            for anchor in anchors[:8]
        ]
    return result


def _sensor_visible(scenario: Scenario, source_host: str, facts: dict, *, denied: bool) -> bool:
    """Verify the declared segment/path rules without invoking runtime routing."""
    config = scenario.environment.network
    network = facts.get("network") or {}
    if config is None or not network or facts.get("local_only"):
        return False
    sensor = next(
        (
            s
            for s in config.sensors
            if source_host.casefold() in {s.name.casefold(), str(s.hostname or s.name).casefold()}
        ),
        None,
    )
    if sensor is None:
        return False

    def segments(ip: str) -> set[str]:
        for item in config.sensors:
            for rule in item.nat_rules:
                if rule.type == "static" and rule.mapped_ip == ip and rule.real_ip:
                    ip = rule.real_ip
                    break
        explicit = {
            seg.name
            for seg in config.segments
            for host in scenario.environment.systems
            if host.ip == ip and host.hostname in seg.systems
        }
        if explicit:
            return explicit
        return {
            seg.name
            for seg in config.segments
            if ipaddress.ip_address(ip) in ipaddress.ip_network(seg.cidr, strict=False)
        }

    src = segments(str(network["src_ip"]))
    dst = segments(str(network["dst_ip"]))
    if facts.get("dhcp") and network.get("link_local"):
        return (
            sensor.placement == "span"
            and sensor.type != "firewall"
            and bool(set(sensor.monitoring_segments) & src)
            and sensor.direction in {"bidirectional", "outbound"}
        )
    if denied:
        if src:
            dst = set()
        else:
            boundary = set().union(
                *(
                    set(s.monitoring_segments) & dst if dst else set(s.monitoring_segments)
                    for s in config.sensors
                    if s.type == "firewall"
                )
            )
            if sensor.type != "firewall":
                return False
            dst = boundary
    monitored = set(sensor.monitoring_segments)
    visible = (
        bool(monitored & src)
        if sensor.direction == "outbound"
        else bool(monitored & dst)
        if sensor.direction == "inbound"
        else bool(monitored & (src | dst))
    )
    if sensor.placement == "tap" and src and dst:
        visible = (
            visible
            and src != dst
            and (len(monitored) <= 1 or bool(monitored & src and monitored & dst))
        )
    return visible


def _source_inventory(scenario: Scenario) -> dict[str, SourceInstanceDeployment]:
    formats = set(DEFAULT_SOURCE_CATALOG.expand(item["format"] for item in scenario.output.logs))
    inventory_formats = {
        fmt
        for fmt in formats
        if DEFAULT_SOURCE_CATALOG.descriptor(fmt).owner is SourceOwnerKind.HOST
    }
    if scenario.environment.network:
        for sensor in scenario.environment.network.sensors:
            inventory_formats.update(DEFAULT_SOURCE_CATALOG.expand(sensor.log_formats))
    deployment = compile_scenario_source_deployment(
        scenario, emitter_formats=inventory_formats
    ).deployment
    return {source.identity.source_instance: source for source in deployment}


def _expectation_errors(
    row: GroundTruthOccurrence,
    expectation: GroundTruthSourceExpectation,
    scenario: Scenario,
    inventory: dict,
) -> list[str]:
    errors = []
    source = inventory.get(expectation.source_instance)
    if (
        source is None
        or expectation.format not in source.formats
        or source.identity.hostname != expectation.source_host
    ):
        return ["unknown_source_identity"]
    if expectation.phase != row.kind:
        errors.append("incorrect_phase")
    if (expectation.connection_leg, expectation.transaction_phase) != projection_phase(
        expectation.format, row.kind, row.facts
    ):
        errors.append("incorrect_leg_or_transaction_phase")
    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(expectation.format)
    roles = {
        (host.casefold(), role)
        for host, role in host_routes(expectation.format, row.kind, row.facts)
    }
    if (
        expectation.family != descriptor.family
        or (descriptor.owner is SourceOwnerKind.SENSOR and expectation.role != "sensor")
        or (
            descriptor.owner is SourceOwnerKind.HOST
            and (expectation.source_host.casefold(), expectation.role) not in roles
        )
    ):
        errors.append("incorrect_projection_identity")
    if expectation.timing_tolerance_seconds != 2.0:
        errors.append("invalid_timing_contract")
    if (
        expectation.format == "windows_event_sysmon"
        and row.facts.get("dns")
        and expectation.expected == "present"
        and not expectation.identifiers.get("sysmon_dns_render_time")
    ):
        errors.append("missing_native_dns_identity")
    if expectation.provenance.get("contract_version") != 1:
        errors.append("unsupported_projection_contract")
    stages = {condition.stage: condition for condition in expectation.conditions}
    selected = set(DEFAULT_SOURCE_CATALOG.expand(item["format"] for item in scenario.output.logs))
    known = {"deployment": source.policy.enabled, "export": expectation.format in selected}
    known["capability"] = source.policy.capabilities.covers(
        required_capabilities(expectation.format, row.kind, row.facts, expectation.role)
    )
    from evidenceforge.events.evidence_source_rules import native_projection_applicable

    if (
        expectation.format in {"zeek_smb_files", "zeek_smb_mapping"}
        or expectation.format == "windows_event_security"
        and row.kind.startswith("smb_")
    ):
        known["source_filter"] = native_projection_applicable(
            expectation.format, row.kind, row.facts, scenario.generation_seed
        )
    if expectation.format in {"ecar", "cisco_asa"} and (
        expectation.format == "ecar"
        and (row.facts.get("firewall") or {}).get("action") == "deny"
        or (row.facts.get("network") or {}).get("application_layer_only")
    ):
        known["capability"] = False
    if descriptor.owner is SourceOwnerKind.SENSOR:
        known["placement"] = _sensor_visible(
            scenario,
            expectation.source_host,
            row.facts,
            denied=(row.facts.get("firewall") or {}).get("action") == "deny",
        )
        from evidenceforge.evaluation.ground_truth_policy import sensor_identifier

        sensor = (
            next(
                (
                    item
                    for item in scenario.environment.network.sensors
                    if str(item.hostname or item.name).casefold()
                    == expectation.source_host.casefold()
                ),
                None,
            )
            if scenario.environment.network
            else None
        )
        identity = (
            str(sensor.hostname or sensor.name) if sensor is not None else expectation.source_host
        )
        network = row.facts.get("network") or {}
        if network.get("zeek_uid") and expectation.identifiers.get("zeek_uid") != sensor_identifier(
            network["zeek_uid"], identity
        ):
            errors.append("source_identifier_disagreement")
        for item in [
            *row.facts.get("file_transfers", []),
            *row.facts.get("x509_chain", []),
            *row.facts.get("pe_analyses", []),
        ]:
            canonical = item.get("fuid") or item.get("id")
            if canonical and expectation.identifiers.get("file:" + canonical) != sensor_identifier(
                canonical, identity
            ):
                errors.append("source_identifier_disagreement")
    if (
        expectation.format == "zeek_http"
        and (row.facts.get("network") or {}).get("service") == "ssl"
    ):
        known["capability"] = False
    if expectation.format == "windows_event_sysmon":
        from evidenceforge.config.sysmon_filters import load_sysmon_filters
        from evidenceforge.events.evidence_source_rules import sysmon_event_ids

        known["source_filter"] = bool(
            sysmon_event_ids(row.kind, row.facts, load_sysmon_filters(), scenario.generation_seed)
        )
        if (
            not row.facts.get("src_host")
            or row.kind == "wfp_connection"
            and (row.facts.get("network_endpoint") or {}).get("role") != "responder"
        ):
            known["capability"] = False
    if expectation.format == "macos_unified_log" and not row.facts.get("unified_log"):
        known["capability"] = False
    if expectation.source_instance in row.source_views:
        from evidenceforge.evaluation.ground_truth_capture import capture_errors

        view = row.source_views[expectation.source_instance]
        rules = load_timing_profiles().get("network_sensor_observation", {})
        errors.extend(capture_errors(row, view, rules, scenario.generation_seed))
        sensor = (
            next(
                (
                    item
                    for item in scenario.environment.network.sensors
                    if str(item.hostname or item.name).casefold()
                    == expectation.source_host.casefold()
                ),
                None,
            )
            if scenario.environment.network
            else None
        )
        if (
            sensor is None
            or view.profile != (sensor.capture_profile or rules.get("default_profile"))
            or view.sensor_identity != str(sensor.hostname or sensor.name)
        ):
            errors.append("capture_profile_identity_disagreement")
        if expectation.format in {"zeek_pe", "zeek_x509"}:
            ids = {
                item.get("id") or item.get("fuid")
                for item in row.facts.get(
                    "pe_analyses" if expectation.format == "zeek_pe" else "x509_chain", []
                )
            }
            known["capability"] = known["capability"] and any(
                item["analyzers_visible"] for item in view.files if item["canonical_id"] in ids
            )
    for stage, allowed in known.items():
        if stage not in stages or (stages[stage].state == "eligible") != allowed:
            errors.append("invalid_" + stage + "_decision")
    first = next(
        (condition.reason for condition in expectation.conditions if condition.state == "excluded"),
        None,
    )
    if (expectation.expected == "absent") != bool(first) or expectation.reason != first:
        errors.append("invalid_absence_explanation")
    if not {"deployment", "placement", "capability", "window", "export"} <= stages.keys():
        errors.append("incomplete_decision_stages")
    loss = expectation.provenance.get("loss") or {}
    if expectation.reason == "modeled_collection_loss" or (
        "loss" in stages and stages["loss"].state != "unknown"
    ):
        if not loss:
            errors.append("missing_loss_provenance")
        else:
            probability = float(loss.get("probability", -1))
            base = source.policy.missingness_for(expectation.format)
            if (
                float(loss.get("base_probability", -1)) != base
                or loss.get("seed") != scenario.generation_seed
            ):
                errors.append("loss_policy_mismatch")
            if probability < 0 or probability > 1 or base == 0 and probability != 0:
                errors.append("invalid_loss_probability")
            profile = get_observation_profile(scenario.observation_profile)
            settings = dict(profile.get("default", {}))
            settings.update(profile.get("sources", {}).get(expectation.family, {}))
            multipliers = settings.get("host_missingness_multiplier", {})
            minimum = max(0.0, min(float(multipliers.get("min", 1)), 10.0))
            maximum = max(0.0, min(float(multipliers.get("max", 1)), 10.0))
            if maximum < minimum:
                minimum = maximum = 1.0
            key = f"observation.host-mult|{scenario.observation_profile}|{expectation.family}|{expectation.source_host.casefold()}"
            if scenario.generation_seed != 42:
                key = f"seed:{scenario.generation_seed}:{key}"
            host_seed = int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)
            multiplier = random.Random(host_seed).uniform(minimum, maximum)
            effective = max(0.0, min(base * multiplier, 1.0))
            syslog = row.facts.get("syslog") or {}
            message = syslog.get("message", "")
            preserved = (
                expectation.family == "syslog"
                and (
                    syslog.get("app_name") == "sshd"
                    and (
                        message.startswith(
                            (
                                "Connection from ",
                                "Accepted ",
                                "Invalid user ",
                                "Failed password ",
                                "Connection closed by ",
                            )
                        )
                        or "pam_unix(sshd:session): session " in message
                    )
                    or syslog.get("app_name") == "systemd-logind"
                    and message.startswith(("New session ", "Removed session "))
                )
                or expectation.family == "ecar"
                and str(
                    (row.facts.get("process") or {}).get("concurrency_group_id", "")
                ).startswith("cron:")
            )
            if preserved:
                effective = 0.0
            if abs(probability - effective) > 1e-12:
                errors.append("loss_probability_policy_disagreement")
            identity = str(loss.get("identity") or "")
            from evidenceforge.evaluation.ground_truth_policy import expected_loss_identity

            if identity != expected_loss_identity(
                row,
                expectation,
                format_specific=expectation.format in source.policy.format_missingness,
            ):
                errors.append("loss_identity_mismatch")
            # A UID or canonical lifecycle must anchor the observation group.
            group = (row.facts.get("lifecycle") or {}).get("group_id")
            uid = (row.facts.get("network") or {}).get("zeek_uid")
            if (
                group
                and ("action-lifecycle:" + group) not in identity
                and not identity.count("remote-session:")
                and not identity.count("process-group:")
                and not (expectation.format == "zeek_http" and "uid:" + str(uid) in identity)
            ):
                errors.append("loss_identity_mismatch")
            elif not group and uid and "uid:" + str(uid) not in identity:
                errors.append("loss_identity_mismatch")
            key = f"observation.drop|{scenario.observation_profile}|{expectation.source_instance}|{identity}"
            if scenario.generation_seed != 42:
                key = f"seed:{scenario.generation_seed}:{key}"
            seed = int(hashlib.sha256(key.encode()).hexdigest(), 16) % (2**32)
            sample = random.Random(seed).random()
            dropped = sample < probability
            if (
                sample != loss.get("sample")
                or dropped != loss.get("dropped")
                or ("loss" in stages and (stages["loss"].state == "excluded") != dropped)
            ):
                errors.append("invalid_loss_decision")
    if "window" in expectation.provenance:
        from evidenceforge.utils.time import resolve_time_window

        receipt = expectation.provenance["window"]
        source_time = datetime.fromisoformat(receipt["source_time"])
        admission_time = datetime.fromisoformat(receipt["admission_time"])
        lifecycle_start = datetime.fromisoformat(receipt["lifecycle_start"])
        delay = float(receipt.get("source_delay_seconds", 0))
        view = row.source_views.get(expectation.source_instance)
        expected_admission = source_time
        if expectation.format == "zeek_conn":
            if view is not None and view.close_time is not None:
                expected_admission = view.close_time + timedelta(seconds=delay)
            elif (row.facts.get("network") or {}).get("closed_at"):
                expected_admission = datetime.fromisoformat(row.facts["network"]["closed_at"])
        elif view is not None:
            expected_admission = max(
                [
                    source_time,
                    *[
                        value + timedelta(seconds=delay)
                        for key, value in view.source_times.items()
                        if key == expectation.format or key.startswith(expectation.format + ":")
                    ],
                ]
            )
        if admission_time != expected_admission:
            errors.append("invalid_phase_window_provenance")
        start, end = resolve_time_window(scenario.time_window)
        active = [window for window in source.policy.windows if window.contains(row.time)]
        in_window = (
            bool(active) and start <= source_time and admission_time < end and lifecycle_start < end
        )
        if active and active[0].end is not None:
            in_window = (
                in_window and admission_time < active[0].end and lifecycle_start < active[0].end
            )
        if "window" not in stages or (stages["window"].state == "eligible") != in_window:
            errors.append("invalid_window_decision")
        if expectation.expected_time is not None and expectation.expected_time != source_time:
            errors.append("window_timestamp_disagreement")
        lifecycle = row.facts.get("lifecycle") or {}
        if lifecycle.get("canonical_start") and lifecycle_start != source_time + (
            datetime.fromisoformat(lifecycle["canonical_start"]) - row.time
        ):
            errors.append("lifecycle_window_disagreement")
        settings = dict(get_observation_profile(scenario.observation_profile).get("default", {}))
        settings.update(
            get_observation_profile(scenario.observation_profile)
            .get("sources", {})
            .get(expectation.family, {})
        )
        maximum_delay = max(0, float(settings.get("delay_ms", {}).get("max_ms", 0))) / 1000
        if not 0 <= delay <= maximum_delay:
            errors.append("invalid_collection_delay")
        network = row.facts.get("network") or {}
        span = (
            max(0, (datetime.fromisoformat(network["closed_at"]) - row.time).total_seconds())
            if network.get("closed_at")
            else 0
        )
        native_bound = (
            source_event_contracts()
            .get("native_source_time_bounds", {})
            .get(row.kind, {})
            .get(expectation.family, 2)
        )
        if (
            not -2
            <= (source_time - row.time).total_seconds()
            <= maximum_delay + span + native_bound
        ):
            errors.append("unjustified_source_time")
    elif expectation.reason == "collection_window_exclusion":
        timestamp = expectation.expected_time or row.time
        source_excluded = not any(
            (w.start is None or timestamp >= w.start) and (w.end is None or timestamp < w.end)
            for w in source.policy.windows
        )
        from evidenceforge.utils.time import resolve_time_window

        start, end = resolve_time_window(scenario.time_window)
        if not source_excluded and start <= timestamp < end:
            errors.append("unjustified_collection_window_exclusion")
    if (
        expectation.reason == "missing_capability"
        and source.policy.capabilities == descriptor.capabilities
        and known.get("capability", True)
    ):
        if not (
            (row.facts.get("firewall") or {}).get("action") == "deny"
            or (row.facts.get("network") or {}).get("application_layer_only")
            or row.facts.get("smb")
        ):
            errors.append("unjustified_capability_exclusion")
    return errors


def evaluate_ground_truth(
    root: Path,
    document: GroundTruthDocument,
    scenario: Scenario,
    records: RecordCorpus,
) -> tuple[GroundTruthAgreementResult, RecordCorpus]:
    """Verify all three contracts and score each authored action with equal weight."""
    authored = AuthoredIntentLedger.from_scenario(scenario)
    actions = {
        intent.intent_id: ActionAgreement(intent_id=intent.intent_id, storyline_id=intent.step_id)
        for intent in authored.intents
    }
    samples = FindingSamples()
    limitations: set[str] = set()
    counts: Counter[str] = Counter()
    bindings = bounded_groups()
    workspace = current_workspace()
    index = (
        workspace.shared["statistics"].source_index
        if workspace is not None
        and workspace.shared.get("statistics")
        and workspace.shared["statistics"].source_index is not None
        else _RecordIndex(records, scenario)
    )
    inventory = _source_inventory(scenario)
    smb_results: dict[str, set[str]] = defaultdict(set)
    seen_by_intent: dict[str, set[str]] = defaultdict(set)
    specs = {}
    intent_inputs = {intent.intent_id: intent for intent in authored.intents}
    root_matches: set[str] = set()
    root_connection_counts: Counter[str] = Counter()
    process_network_matches: set[str] = set()
    seen_facts: dict[str, set[str]] = defaultdict(set)
    semantic_errors: dict[str, set[str]] = defaultdict(set)
    semantic_actual: dict[str, list[dict]] = defaultdict(list)
    from .source_timing_proof import TimingPoints

    timing_points = TimingPoints()
    if document.event_stream is not None:
        for point in read_ground_truth_occurrences(root, document.event_stream):
            for source in point.source_expectations:
                if source.format != "ecar":
                    continue
                payload = source.provenance.get("timing")
                receipt = payload if isinstance(payload, dict) else {}
                native = receipt.get("native_time")
                if not native and source.expected_time is not None:
                    from datetime import timedelta

                    native = (
                        source.expected_time
                        - timedelta(
                            seconds=float(
                                (source.provenance.get("window") or {}).get(
                                    "source_delay_seconds", 0
                                )
                            )
                        )
                    ).isoformat()
                if native:
                    try:
                        native_point = datetime.fromisoformat(native)
                    except (TypeError, ValueError):
                        continue
                    if native_point.tzinfo is None:
                        continue
                    identity = point.facts.get("process") or {}
                    keys = (
                        ["frontier:" + str(identity["object_id"])]
                        if identity.get("object_id")
                        else []
                    )
                    if point.kind in {
                        "process_create",
                        "system_process_create",
                        "process_fork",
                    } and identity.get("object_id"):
                        keys.append("create:" + str(identity["object_id"]))
                    if point.kind == "process_exec" and identity.get("execution_id"):
                        keys.append("exec:" + str(identity["execution_id"]))
                    actor_identity = point.facts.get("actor_process") or {}
                    if (
                        str(actor_identity.get("hostname", "")).casefold()
                        == source.source_host.casefold()
                    ):
                        if actor_identity.get("object_id"):
                            keys.append("frontier:" + str(actor_identity["object_id"]))
                    if point.kind in {"process_create", "process_fork"}:
                        parent_id = (point.facts.get("actor_process") or {}).get("object_id")
                        if parent_id:
                            keys.append("children:" + str(parent_id))
                    if point.kind in {"logon", "ssh_session"}:
                        session_id = (point.facts.get("auth") or {}).get("logon_id")
                        if session_id:
                            keys.append("session:" + str(session_id))
                    for key in filter(None, keys):
                        timing_points.add(
                            (source.source_instance, str(key)), native_point, point.occurrence_id
                        )
    for section, steps in [
        ("storyline", scenario.storyline),
        ("red_herring", scenario.red_herrings),
    ]:
        for step in steps or []:
            intents = [
                i for i in authored.intents if i.section.value == section and i.step_id == step.id
            ]
            for intent, spec in zip(intents, step.events, strict=True):
                specs[intent.intent_id] = spec

    def fail(
        action: ActionAgreement,
        code: str,
        row: GroundTruthOccurrence | None = None,
        expectation: GroundTruthSourceExpectation | None = None,
        details: object = None,
        *,
        check_id: str | None = None,
    ) -> None:
        counts[code] += 1
        if check_id is None:
            check_id = (
                f"source:{row.occurrence_id}:{expectation.expectation_id}"
                if row is not None and expectation is not None
                else f"canonical:{action.intent_id}:{row.occurrence_id if row else 'action'}:"
                f"{code}:"
                + hashlib.sha256(
                    json.dumps(details, sort_keys=True, default=str).encode()
                ).hexdigest()[:16]
            )
        samples.add(
            code,
            expectation.format if expectation else "canonical",
            {
                "check_id": check_id,
                "intent_id": action.intent_id,
                "storyline_id": action.storyline_id,
                "occurrence_id": row.occurrence_id if row else None,
                "source_instance": expectation.source_instance if expectation else None,
                "format": expectation.format if expectation else None,
                "rule": code,
                "details": details
                if details is not None
                else {
                    "expected": _bounded_facts(specs[action.intent_id].model_dump(mode="json")),
                    "actual_occurrence_kinds": sorted(seen_by_intent[action.intent_id]),
                    "actual": semantic_actual[action.intent_id],
                    "outcome": document.intent_outcomes.get(action.intent_id),
                },
            },
        )

    contract = document.expectation_contract
    data = scenario.model_dump(mode="json")
    data["output"].pop("destination", None)
    digest = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    contract_invalid = (
        contract is None
        or contract.scenario_sha256 != digest
        or contract.profile != scenario.observation_profile
        or contract.profile_settings != get_observation_profile(scenario.observation_profile)
    )
    if contract is not None:
        from evidenceforge.config.sysmon_filters import load_sysmon_filters

        captured_rules = dict(contract.source_rules)
        timing_rules = captured_rules.pop("process_timing", None)
        if timing_rules is not None:
            contract_invalid |= timing_rules != {
                key: dict(load_timing_profiles().get("relationships", {}).get(key, {}))
                for key in (
                    "source.ecar_process_create",
                    "source.ecar_process_terminate",
                    "source.ecar_dependent_after_process_create",
                )
            }
        contract_invalid |= captured_rules != json.loads(
            json.dumps(
                {
                    "windows_event_sysmon": load_sysmon_filters(),
                    "network_sensor_observation": load_timing_profiles().get(
                        "network_sensor_observation", {}
                    ),
                }
            )
        )
        expected_sources = {
            identity: {
                "hostname": source.identity.hostname,
                "family": source.identity.family,
                "formats": list(source.formats),
                "enabled": source.policy.enabled,
                "capabilities": int(source.policy.capabilities),
                "missingness": source.policy.missingness,
                "format_missingness": dict(source.policy.format_missingness),
                "optional_fields": sorted(source.policy.optional_fields),
                "windows": [
                    {
                        "start": window.start.isoformat() if window.start else None,
                        "end": window.end.isoformat() if window.end else None,
                    }
                    for window in source.policy.windows
                ],
            }
            for identity, source in inventory.items()
        }
        contract_invalid |= contract.sources != expected_sources
    if document.event_stream is None or document.event_stream.schema_version != 2:
        contract_invalid = True
    if contract_invalid:
        if not actions:
            raise EvaluationError(
                "Missing or invalid schema-v5 expectation contract; zero actions cannot establish agreement"
            )
        for action in actions.values():
            action.incorrect += 1
            fail(action, "missing_or_invalid_expectation_contract")
    if document.event_stream is None:
        stream = ()
    else:
        stream = read_ground_truth_occurrences(root, document.event_stream)
        from evidenceforge.evaluation.ground_truth_relationships import relationship_violations

        for intent_id, violations in relationship_violations(root, document.event_stream).items():
            if intent_id in actions:
                actions[intent_id].incorrect += 1
                fail(actions[intent_id], "canonical_relationship_disagreement", details=violations)
    for row in stream:
        if row.intent_id not in actions:
            for action in actions.values():
                action.incorrect += 1
                fail(action, "unknown_intent", row)
            continue
        action = actions[row.intent_id]
        action.occurrences += 1
        if row.facts.get("smb"):
            smb_results[row.intent_id].add(str(row.facts["smb"].get("result")))
        seen_facts[row.intent_id].update(row.facts)
        seen_by_intent[row.intent_id].add(row.kind)
        spec = specs[row.intent_id]
        intent = intent_inputs[row.intent_id]
        if (
            row.kind in source_event_contracts()["authored_kinds"].get(spec.type, [])
            or row.kind == "job_control"
        ):
            semantic_actual[row.intent_id].append(
                {
                    "occurrence_id": row.occurrence_id,
                    "kind": row.kind,
                    "time": row.time.isoformat(),
                    "facts": {
                        name: _bounded_facts(value)
                        for name, value in row.facts.items()
                        if name
                        in {"process", "attempt", "auth", "http", "network", "job_control", "dns"}
                        and isinstance(value, dict)
                    },
                }
            )
            semantic_actual[row.intent_id] = semantic_actual[row.intent_id][-2:]
        if spec.type == "macos_launch_item" and row.kind == "job_control":
            control = row.facts.get("job_control") or {}
            if (
                control.get("launchd_operation") != spec.operation
                or control.get("launchd_label") != spec.label
                or spec.path is not None
                and control.get("file_path") != spec.path
            ):
                semantic_errors[row.intent_id].add("authored_launch_item_facts_disagreement")
        if row.kind in source_event_contracts()["authored_kinds"].get(spec.type, []):
            for path, field in (
                source_event_contracts()["authored_bindings"].get(spec.type, {}).items()
            ):
                context, key = path.split(".", 1)
                actual = (row.facts.get(context) or {}).get(key)
                expected = getattr(spec, field)
                if field == "target_process":
                    actual = str(actual).replace("\\", "/").rsplit("/", 1)[-1].casefold()
                    expected = str(expected).replace("\\", "/").rsplit("/", 1)[-1].casefold()
                if actual != expected:
                    semantic_errors[row.intent_id].add("authored_typed_facts_disagreement")
        if spec.type == "process" and row.kind == "connection" and not row.facts.get("dns"):
            match = re.search(r"https?://[^\s'\"<>]+", spec.command_line or "")
            if match:
                try:
                    url = urlsplit(match.group(0).rstrip(").,;]"))
                    network = row.facts.get("network") or {}
                    proxy = row.facts.get("proxy") or {}
                    if (
                        str(network.get("hostname", "")).casefold() == str(url.hostname).casefold()
                        and network.get("dst_port")
                        == (url.port or (443 if url.scheme == "https" else 80))
                    ) or str(proxy.get("host", "")).casefold() == str(url.hostname).casefold():
                        process_network_matches.add(row.intent_id)
                except ValueError:
                    pass
        if spec.type == "process" and row.kind in {"process_create", "process_exec"}:
            proc = row.facts.get("process") or {}

            def basename(value: object) -> str:
                return str(value).replace("\\", "/").rsplit("/", 1)[-1].casefold()

            if (
                basename(proc.get("image")) == basename(spec.process_name)
                and int(proc.get("pid") or 0) > 0
                and (
                    not spec.command_line
                    or process_commands_agree(
                        spec.command_line,
                        str(proc.get("command_line") or ""),
                        str((row.facts.get("src_host") or {}).get("os_category", "")),
                    )
                )
                and str((row.facts.get("src_host") or {}).get("hostname", "")).casefold()
                == intent.system.casefold()
            ):
                root_matches.add(row.intent_id)
        if spec.type == "dns_query" and row.facts.get("dns"):
            dns = row.facts["dns"]
            answers = (
                spec.answer
                if isinstance(spec.answer, list)
                else [spec.answer]
                if spec.answer
                else []
            )
            if (
                dns.get("query") == spec.query
                and dns.get("query_type") == spec.qtype
                and dns.get("rcode") == spec.rcode
                and dns.get("answers", []) == answers
            ):
                root_matches.add(row.intent_id)
        if (
            spec.type in {"connection", "beacon"}
            and row.kind == "connection"
            and not row.facts.get("dns")
        ):
            network = row.facts.get("network") or {}
            proxy = row.facts.get("proxy") or {}
            if (
                network.get("dst_ip") == spec.dst_ip
                and network.get("dst_port") == spec.dst_port
                and not proxy
            ):
                root_connection_counts[row.intent_id] += 1
            if (
                network.get("dst_ip") == spec.dst_ip and network.get("dst_port") == spec.dst_port
            ) or proxy.get("host") == (spec.hostname or spec.dst_ip):
                root_matches.add(row.intent_id)
            if (
                getattr(spec, "action", "allow") == "deny"
                and (row.facts.get("firewall") or {}).get("action") != "deny"
            ):
                semantic_errors[row.intent_id].add("authored_enforcement_disagreement")
        if spec.type in {"logon", "failed_logon"} and row.kind == spec.type:
            auth = row.facts.get("auth") or {}
            expected_user = getattr(spec, "target_username", None) or intent.actor
            if auth.get("username", "").rsplit("\\", 1)[-1].casefold() != expected_user.casefold():
                semantic_errors[row.intent_id].add("authored_authentication_disagreement")
        if spec.type == "email_message" and row.facts.get("email"):
            email = row.facts["email"]
            if (
                email.get("mail_action") != spec.mail_action
                or email.get("outcome") != spec.outcome
                or not _email_recipients_match(
                    spec,
                    email,
                    scenario.environment.email.distribution_groups
                    if scenario.environment.email is not None
                    else [],
                )
            ):
                semantic_errors[row.intent_id].add("authored_email_outcome_disagreement")
        formats = candidate_formats(row.kind, row.facts)
        expected_pairs = set()
        for fmt in formats:
            descriptor = DEFAULT_SOURCE_CATALOG.descriptor(fmt)
            routes = host_routes(fmt, row.kind, row.facts)
            hosts = {host.casefold() for host, _ in routes}
            for source in inventory.values():
                if fmt in source.formats and (
                    descriptor.owner is SourceOwnerKind.SENSOR
                    or source.identity.hostname.casefold() in hosts
                ):
                    roles = (
                        ["sensor"]
                        if descriptor.owner is SourceOwnerKind.SENSOR
                        else [
                            role
                            for host, role in routes
                            if host.casefold() == source.identity.hostname.casefold()
                        ]
                    )
                    for role in roles:
                        expected_pairs.add((source.identity.source_instance, fmt, role))
        actual_pairs = [
            (item.source_instance, item.format, item.role) for item in row.source_expectations
        ]
        for pair in expected_pairs - set(actual_pairs):
            action.incorrect += 1
            fail(action, "missing_source_expectation", row, details=pair)
        if len(actual_pairs) != len(set(actual_pairs)):
            action.incorrect += 1
            fail(action, "duplicate_source_expectation", row)
        gap_formats = {gap.format for gap in row.coverage_gaps}
        for fmt in formats - {fmt for _, fmt, _ in expected_pairs} - gap_formats:
            action.incorrect += 1
            fail(action, "missing_coverage_gap", row, details=fmt)
        if (
            not row.source_expectations
            and not row.coverage_gaps
            and row.kind not in {"process_attempt", "job_control"}
        ):
            action.incorrect += 1
            fail(action, "unaccounted_source_coverage", row)
        for gap in row.coverage_gaps:
            action.coverage_gaps += 1
            if any(fmt == gap.format for _, fmt, _ in expected_pairs):
                action.incorrect += 1
                fail(action, "fabricated_coverage_gap", row, details=gap.model_dump())
        if row.facts.get("http") and not any(
            item.format in {"zeek_http", "web_access", "proxy_access"}
            and item.expected == "present"
            for item in row.source_expectations
        ):
            sequence = getattr(spec, "http_sequence", [])
            entry = next(
                (item for item in sequence if item.uri == row.facts["http"].get("uri")), None
            )
            authored_status = (
                entry.status_code
                if entry and entry.status_code is not None
                else getattr(spec, "status_code", None)
            )
            if (
                authored_status is not None
                and row.facts["http"].get("status_code") != authored_status
            ):
                semantic_errors[row.intent_id].add("authored_http_status_disagreement")
        for expectation in row.source_expectations:
            errors = _expectation_errors(row, expectation, scenario, inventory)
            if expectation.format == "ecar" and (
                row.kind.startswith("process_") or row.kind == "system_process_create"
            ):
                from evidenceforge.evaluation.source_timing_proof import verify_process_timing

                proof_errors = verify_process_timing(
                    row,
                    expectation,
                    index,
                    timing_points,
                    collection_start=scenario.time_window.start,
                )
                if (
                    contract is not None
                    and "process_timing" in contract.source_rules
                    and expectation.expected == "present"
                    and (row.facts.get("process") or {}).get("object_id")
                    and not expectation.provenance.get("timing")
                ):
                    proof_errors.append("missing_process_timing_provenance")
                if not expectation.provenance.get("timing") and "unjustified_source_time" in errors:
                    errors.append("missing_process_timing_provenance")
                    limitations.add(
                        "Earlier feature bundle lacks the timing dependencies needed to verify inherited source delays; regenerate for complete verification."
                    )
                if not proof_errors and expectation.provenance.get("timing"):
                    errors = [code for code in errors if code != "unjustified_source_time"]
                errors.extend(proof_errors)
            if contract_invalid:
                errors.append("unverifiable_projection_contract")
            if (
                expectation.source_instance,
                expectation.format,
                expectation.role,
            ) not in expected_pairs:
                errors.append("unexpected_source_expectation")
            if (
                (
                    getattr(spec, "status_code", None) is not None
                    or getattr(spec, "http_sequence", [])
                )
                and expectation.expected == "present"
                and expectation.format in {"zeek_http", "web_access", "proxy_access"}
                and row.facts.get("http")
                and row.kind == "connection"
                and not row.facts.get("proxy")
            ):
                sequence = getattr(spec, "http_sequence", [])
                entry = next(
                    (item for item in sequence if item.uri == row.facts["http"].get("uri")), None
                )
                expected_status = (
                    entry.status_code
                    if entry and entry.status_code is not None
                    else getattr(spec, "status_code", None)
                )
                if (
                    expected_status is not None
                    and row.facts["http"].get("status_code") != expected_status
                ):
                    errors.append("authored_http_status_disagreement")
            try:
                requirements = native_requirements(
                    expectation.format,
                    row.kind,
                    row.facts,
                    expectation.identifiers,
                    expectation.role,
                    (contract.source_rules.get("windows_event_sysmon") if contract else None),
                    scenario.generation_seed,
                    source_view=row.source_views[expectation.source_instance].model_dump(
                        mode="json"
                    )
                    if expectation.source_instance in row.source_views
                    else None,
                )
                expected_requirements = [item.model_dump(mode="json") for item in requirements]
                legacy_requirements = json.loads(json.dumps(expected_requirements))
                if expectation.format in {"bash_history", "zsh_history"}:
                    for item in legacy_requirements:
                        item["selector"].pop("command", None)
                        item["selector"].pop("username", None)
                if (
                    expectation.format == "ecar"
                    and not row.facts.get("process_transition")
                    and row.kind
                    in {
                        "process_audit_bind",
                        "process_privilege_drop",
                        "process_service_drop",
                        "process_job_control",
                    }
                ):
                    for item in legacy_requirements:
                        item["selector"].pop("operation", None)
                    limitations.add(
                        "Earlier feature bundle lacks process transition identities and before/after facts; regenerate for complete verification."
                    )
                if expectation.requirements not in (expected_requirements, legacy_requirements):
                    errors.append("invalid_required_fact_contract")
            except (ValueError, KeyError) as exc:
                errors.append("unsupported_evidence_contract")
                requirements = []
                fail(action, "unsupported_evidence_contract", row, expectation, str(exc))
            if not requirements and expectation.expected == "present":
                errors.append("empty_evidence_contract")
            found = bounded_list()
            facts_ok = True
            time_ok = True
            cardinality_ok = True
            requirement_diagnostics = []
            for requirement in requirements:
                candidates = index.candidates(
                    row, expectation, requirement.selector, requirement.timing
                )
                selected = bounded_list(
                    record for record in candidates if _fields_match(record, requirement.selector)
                )
                matched = bounded_list(
                    record
                    for record in selected
                    if _fields_match(record, requirement.required)
                    and all(value in record.raw for value in requirement.contains)
                )
                requirement_diagnostics.append(
                    {
                        "selector": _bounded_facts(requirement.selector),
                        "required": _bounded_facts(requirement.required),
                        "contains": [value[:512] for value in requirement.contains[:5]],
                        "predicate_truncated": len(requirement.contains) > 5
                        or any(len(value) > 512 for value in requirement.contains),
                        "minimum": requirement.minimum,
                        "maximum": requirement.maximum,
                        "timing": requirement.timing,
                        "anchor": index.anchor(
                            row, expectation, requirement.timing, requirement.selector
                        ).isoformat(),
                        "tolerance_seconds": expectation.timing_tolerance_seconds,
                        "candidate_count": len(candidates),
                        "selected_count": len(selected),
                        "matched_count": len(matched),
                        "selected_evidence": [
                            {
                                "path": record.source_path,
                                "line": record.line_number,
                                "time": index.time(record).isoformat()
                                if index.time(record)
                                else None,
                                "delta_seconds": (
                                    index.time(record)
                                    - index.anchor(
                                        row, expectation, requirement.timing, requirement.selector
                                    )
                                ).total_seconds()
                                if index.time(record)
                                else None,
                            }
                            for record in selected[:2]
                        ],
                    }
                )
                # Avoid borrowing an unrelated simultaneous row when semantic identities disagree.
                if expectation.expected == "absent":
                    found.extend(
                        record
                        for record in selected
                        if all(value in record.raw for value in requirement.contains)
                    )
                    continue
                if requirement.expected == "absent":
                    if selected:
                        found.extend(selected)
                        cardinality_ok = False
                    continue
                found.extend(matched or selected)
                if len(matched) < requirement.minimum:
                    if selected:
                        facts_ok = False
                    else:
                        cardinality_ok = False
                if requirement.maximum is not None and len(selected) > requirement.maximum:
                    cardinality_ok = False
                if (
                    matched
                    and requirement.timing in {"point", "transport_close"}
                    and expectation.expected_time
                ):
                    if any(
                        index.time(record) is None
                        or abs(
                            (
                                index.time(record)
                                - index.anchor(
                                    row, expectation, requirement.timing, requirement.selector
                                )
                            ).total_seconds()
                        )
                        > (
                            0.001
                            if expectation.format == "windows_event_sysmon"
                            and requirement.selector.get("EventID") == 22
                            else expectation.timing_tolerance_seconds
                        )
                        for record in matched
                    ):
                        time_ok = False
                elif matched and requirement.timing == "interval":
                    network = row.facts.get("network") or {}
                    lower = min(row.time, expectation.expected_time or row.time).timestamp() - 2
                    upper = (
                        max(
                            (expectation.expected_time or row.time).timestamp(),
                            datetime.fromisoformat(network["closed_at"]).timestamp()
                            if network.get("closed_at")
                            else row.time.timestamp(),
                        )
                        + 2
                    )
                    if any(
                        index.time(record) is None
                        or not lower <= index.time(record).timestamp() <= upper
                        for record in matched
                    ):
                        time_ok = False
            if expectation.expected == "absent":
                action.expected_absences += 1
                if found:
                    errors.append("unexpected_evidence")
            else:
                action.fact_checks += 1
                action.timing_checks += 1
                if found:
                    action.found += 1
                if not facts_ok:
                    action.fact_errors += 1
                    errors.append("factual_disagreement")
                if not time_ok:
                    action.timing_errors += 1
                    errors.append("timing_disagreement")
                if not cardinality_ok:
                    errors.append("missing_or_duplicate_evidence")
                if not found:
                    errors.append("missing_evidence")
            if errors:
                action.incorrect += 1
                for code in sorted(set(errors)):
                    fail(
                        action,
                        code,
                        row,
                        expectation,
                        {
                            "expected": expectation.expected,
                            "reason": expectation.reason,
                            "requirements": requirement_diagnostics[:5],
                            "canonical_time": row.time.isoformat(),
                            "expected_time": expectation.expected_time.isoformat()
                            if expectation.expected_time
                            else None,
                            "timing_provenance": _timing_details(
                                expectation.provenance.get("timing")
                            ),
                            "required_facts": [
                                _bounded_facts({**requirement.selector, **requirement.required})
                                for requirement in requirements[:5]
                            ],
                            "evidence": [
                                {
                                    "source": record.source_instance or record.source_host,
                                    "line": record.line_number,
                                    "path": record.source_path,
                                    "fields": _bounded_facts(
                                        {
                                            key: next(
                                                (
                                                    _field_value(record.fields, alias)
                                                    for alias in key.split("|")
                                                    if _field_value(record.fields, alias)
                                                    is not None
                                                ),
                                                None,
                                            )
                                            for requirement in requirements[:5]
                                            for key in {
                                                **requirement.selector,
                                                **requirement.required,
                                            }
                                        }
                                    ),
                                }
                                for record in found[:2]
                            ],
                        },
                    )
            elif expectation.expected == "present":
                action.correct += 1
            if expectation.expected == "present":
                bindings[row.intent_id].extend(found)
    required_kinds = source_event_contracts()["authored_kinds"]
    for identity, action in actions.items():
        outcome = document.intent_outcomes.get(identity, {})
        spec = specs[identity]
        allowed_noop = (
            outcome.get("status") == "no_op"
            and outcome.get("reason") == "workstation_already_locked"
            and spec.type == "workstation_lock"
        )
        if (
            outcome.get("status") == "no_op"
            and outcome.get("reason") == "outside_collection_window"
        ):
            from evidenceforge.utils.time import parse_duration, resolve_time_window

            start, end = resolve_time_window(scenario.time_window)
            text = intent_inputs[identity].authored_time
            try:
                at = (
                    start + parse_duration(text[1:])
                    if text.startswith("+")
                    else datetime.fromisoformat(text.replace("Z", "+00:00"))
                )
                allowed_noop = not start <= at < end
            except ValueError:
                allowed_noop = False
        if spec.type == "raw" and not allowed_noop:
            from .ground_truth_raw import validate_raw_expectation

            selected_formats = set(
                DEFAULT_SOURCE_CATALOG.expand(item["format"] for item in scenario.output.logs)
            )
            if spec.target_format in selected_formats:
                receipt = outcome.get("raw_expectation", {})
                expected, errors = validate_raw_expectation(
                    receipt, scenario, spec, intent_inputs[identity].system
                )
                candidates = bounded_list(
                    record
                    for record in records.get(spec.target_format, [])
                    if str(record.source_host or record.fields.get("hostname") or "").casefold()
                    in {
                        intent_inputs[identity].system.casefold(),
                        next(
                            (
                                str(getattr(host, "fqdn", None) or host.hostname).casefold()
                                for host in scenario.environment.systems
                                if host.hostname == intent_inputs[identity].system
                            ),
                            "",
                        ),
                    }
                    and _fields_match(
                        record,
                        {key: value for key, value in spec.fields.items() if key != "timestamp"},
                    )
                    and index.time(record) is not None
                    and receipt.get("time") is not None
                    and abs(
                        (
                            index.time(record) - datetime.fromisoformat(receipt["time"])
                        ).total_seconds()
                    )
                    <= 2
                )
                if errors or (expected and len(candidates) != 1) or (not expected and candidates):
                    action.incorrect += 1
                    fail(
                        action,
                        "raw_evidence_disagreement",
                        details=errors or {"expected": expected, "actual_count": len(candidates)},
                    )
                elif expected:
                    action.correct += 1
                    bindings[identity].extend(candidates)
                else:
                    action.expected_absences += 1

        if (
            not action.occurrences
            and not allowed_noop
            and not (outcome.get("status") == "modeled_outcome" and spec.type == "raw")
        ):
            action.incorrect += 1
            fail(action, "missing_canonical_occurrence")
        needed = required_kinds.get(spec.type)
        if spec.type == "macos_launch_item":
            needed = source_event_contracts()["authored_launch_item_consequences"][spec.operation]
        if action.occurrences and needed and not seen_by_intent[identity] & set(needed):
            action.incorrect += 1
            fail(action, "missing_required_consequence")
        if needed is None and spec.type != "raw":
            semantic_errors[identity].add("unsupported_authored_contract")
        root_required = (
            spec.type in {"connection", "beacon", "dns_query"}
            or spec.type == "process"
            and spec.outcome == "success"
        )
        if root_required and action.occurrences and identity not in root_matches:
            semantic_errors[identity].add("authored_typed_facts_disagreement")
        if spec.type == "beacon" and spec.count is not None and "proxy" not in seen_facts[identity]:
            from evidenceforge.utils.time import parse_duration, resolve_time_window

            start, end = resolve_time_window(scenario.time_window)
            authored_time = intent_inputs[identity].authored_time
            if authored_time.startswith("+"):
                latest = (
                    start
                    + parse_duration(authored_time[1:])
                    + parse_duration(spec.interval) * max(0, spec.count - 1) * (1 + spec.jitter)
                )
                if latest < end and root_connection_counts[identity] != spec.count:
                    semantic_errors[identity].add("authored_sequence_cardinality_disagreement")
        if (
            (getattr(spec, "status_code", None) is not None or getattr(spec, "http_sequence", []))
            and action.occurrences
            and "http" not in seen_facts[identity]
            and "firewall" not in seen_facts[identity]
            and "proxy" not in seen_facts[identity]
        ):
            semantic_errors[identity].add("missing_authored_http_consequence")
        if spec.type == "smb_activity" and not allowed_noop:
            results = smb_results[identity]
            if spec.outcome != "auto" and (
                spec.outcome not in results or spec.outcome == "success" and results != {"success"}
            ):
                semantic_errors[identity].add("authored_storage_outcome_disagreement")
            if spec.outcome == "success" or results == {"success"}:
                required = source_event_contracts()["authored_smb_consequences"][spec.operation]
                if not set(required) & seen_by_intent[identity]:
                    semantic_errors[identity].add("missing_required_storage_consequence")
        if semantic_errors[identity]:
            action.incorrect += 1
            for code in sorted(semantic_errors[identity]):
                fail(action, code, check_id=f"intent:{identity}:typed-facts")
        if (
            spec.type == "process"
            and spec.outcome == "success"
            and getattr(spec, "command_line", None)
            and re.search(r"https?://[^\s'\"<>]+", spec.command_line)
            and action.occurrences
            and identity not in process_network_matches
        ):
            action.incorrect += 1
            fail(action, "missing_process_network_consequence")
        total = action.correct + action.incorrect
        action.score = 100 * action.correct / total if total else 100.0
        if not total:
            action.zero_check_reason = outcome.get("reason") or (
                "expected_absence" if action.expected_absences else "no_configured_source"
            )
    values = list(actions.values())
    findings = samples.examples()
    result = GroundTruthAgreementResult(
        score=sum(a.score for a in values) / len(values) if values else 100,
        actions=values,
        findings=findings,
        failure_counts=dict(sorted(counts.items())),
        correct=sum(a.correct for a in values),
        incorrect=sum(a.incorrect for a in values),
        expected_absences=sum(a.expected_absences for a in values),
        coverage_gaps=sum(a.coverage_gaps for a in values),
        total_findings=sum(counts.values()),
        displayed_findings=len(findings),
        findings_truncated=sum(counts.values()) > len(findings),
        verification_limitations=sorted(limitations),
    )
    return result, bindings
