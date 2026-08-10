# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Pillar 3: Causality scoring.

Sub-scores (weights sum to 1.0):
  causal_ordering        (0.25): Known before/after pairs are correctly sequenced.
  event_presence         (0.20): Storyline events leave at least one trace.
  indicator_accuracy     (0.15): Found traces carry correct IPs/usernames/hostnames.
  pivot_linkability      (0.15): Consecutive attack steps share a pivotable indicator.
  temporal_integrity     (0.15): Events timed and ordered correctly.
  storyline_trace_coverage (0.10): All expected format-groups have traces.
"""

import ipaddress
import logging
import re
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar
from urllib.parse import urlsplit

from evidenceforge.evaluation._shared import _condition_matches, _extract_hostname, _normalize_ts
from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
    aggregate_sub_scores,
)
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.evaluation.storyline import (
    _DURATION_EVENT_TYPES,
    TIME_TOLERANCE,
    ResolvedEvent,
    resolve_storyline,
)
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.events.observation import source_family_for_format
from evidenceforge.events.observation_manifest import (
    ObservationManifestEvent,
    observation_manifest_matches_scenario,
)
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.time import parse_duration

logger = logging.getLogger(__name__)


class CausalityScorer(DimensionScorer):
    number = 3
    name = "Causality"
    weight = 0.25

    _NETWORK_ONLY_PIVOT_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            "beacon",
            "connection",
            "credential_spray",
            "dga_queries",
            "dhcp_lease",
            "dns_query",
            "dns_tunnel",
            "port_scan",
            "web_scan",
        }
    )

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        context = context or EvaluationContext()
        if context.observation_manifest is not None and not observation_manifest_matches_scenario(
            context.observation_manifest, scenario
        ):
            context = replace(context, observation_manifest=None)
        # storyline_id -> rendered spillage values (from GROUND_TRUTH.json), used
        # by _spillage_record_matches to verify the credential landed in the logs.
        self._spillage_gt = context.spillage_ground_truth or {}
        self._email_gt = context.email_ground_truth or {}
        # storyline_id -> adversarial-payload labels (from the canonical GROUND_TRUTH.json)
        # + per-format searchable text (parsed fields + raw lines, newline-normalized)
        # so a labeled payload — including a CRLF split that spans two physical
        # lines — can be verified present without re-running synthesis.
        self._adversarial_payload_gt = context.adversarial_payload_ground_truth or {}
        self._ap_search_text = self._build_ap_search_text(records)
        storyline = scenario.storyline or []
        resolved: list[ResolvedEvent] = []

        if storyline:
            resolved = resolve_storyline(storyline, scenario)
            # Anchor spillage / adversarial_payload events to the actual emitted time
            # from the canonical document: dwell/session scheduling can shift evidence
            # past the storyline time, beyond the match tolerance, so search + timing
            # key off where the evidence really landed.
            # A single storyline step can carry BOTH a spillage and an adversarial_payload
            # event, anchored at different emitted times/hosts. Stash a PER-TYPE anchor so
            # the trace search keys each type off its own evidence (a shared event.time
            # would let the later writer clobber the other and falsely miss it). The shared
            # event.time/hostname are still set for single-type steps and other consumers.
            for event in resolved:
                gt = self._spillage_gt.get(event.storyline_id)
                if gt and "spillage" in event.event_types:
                    if gt.get("time"):
                        event.time = gt["time"]
                        event.details["_anchor_time_spillage"] = gt["time"]
                    if gt.get("target_system"):
                        # http_* spillage lands on the destination web server's access
                        # log (not the actor's host), so add that host to the record
                        # search keys; the value match itself stays host-agnostic.
                        event.details["hostname"] = gt["target_system"]
                        event.details["_anchor_host_spillage"] = gt["target_system"]
                apgt = self._adversarial_payload_gt.get(event.storyline_id)
                if apgt and "adversarial_payload" in event.event_types:
                    if apgt.get("time"):
                        event.time = apgt["time"]
                        event.details["_anchor_time_adversarial_payload"] = apgt["time"]
                    if apgt.get("target_system"):
                        event.details["hostname"] = apgt["target_system"]
                        event.details["_anchor_host_adversarial_payload"] = apgt["target_system"]
            self._proxy_mode = scenario.environment.proxy.mode
            self._proxy_listener_port = scenario.environment.proxy.listener_port
            self._proxy_ips = {
                system.ip
                for system in scenario.environment.systems
                if "forward_proxy" in (system.roles or [])
            }
            self._email_actor_emails = {
                user.username.lower(): user.email.lower()
                for user in scenario.environment.users
                if user.email
            }
            systems_by_name = {system.hostname: system for system in scenario.environment.systems}
            email_config = getattr(scenario.environment, "email", None)
            self._email_server_ips = {}
            self._email_server_hosts = {}
            if email_config is not None:
                self._email_server_ips = {
                    server.name.lower(): systems_by_name[server.system].ip
                    for server in email_config.mail_servers
                    if server.system in systems_by_name
                }
                self._email_server_hosts = {
                    server.name.lower(): server.hostname.lower()
                    for server in email_config.mail_servers
                }
            self._initialize_pivot_identity(scenario)
            # Build host-time index and find traces
            host_time_index = self._build_host_time_index(records)
            self._find_traces(resolved, records, host_time_index)
        else:
            self._proxy_mode = "transparent"
            self._proxy_listener_port = 8080
            self._proxy_ips = set()
            self._email_actor_emails = {}
            self._email_server_ips = {}
            self._email_server_hosts = {}
            self._initialize_pivot_identity(scenario)
            host_time_index = self._build_host_time_index(records)

        enabled = {log_spec["format"] for log_spec in scenario.output.logs if "format" in log_spec}
        vis = VisibilityModel(scenario, enabled)

        progress("sub_score_start", {"name": "Causal Ordering", "step": 1, "total": 7})
        s1 = self._score_causal_ordering(records, scenario)
        progress("sub_score_done", {"name": "Causal Ordering", "score": s1.score})

        progress("sub_score_start", {"name": "Event Presence", "step": 2, "total": 7})
        s2 = self._score_event_presence(resolved, context)
        progress("sub_score_done", {"name": "Event Presence", "score": s2.score})

        progress("sub_score_start", {"name": "Indicator Accuracy", "step": 3, "total": 7})
        s3 = self._score_indicator_accuracy(resolved)
        progress("sub_score_done", {"name": "Indicator Accuracy", "score": s3.score})

        progress("sub_score_start", {"name": "Pivot Linkability", "step": 4, "total": 7})
        s4 = self._score_pivot_linkability(resolved, context)
        progress("sub_score_done", {"name": "Pivot Linkability", "score": s4.score})

        progress("sub_score_start", {"name": "Temporal Integrity", "step": 5, "total": 7})
        s5 = self._score_temporal_integrity(resolved, context)
        progress("sub_score_done", {"name": "Temporal Integrity", "score": s5.score})

        progress("sub_score_start", {"name": "Storyline Trace Coverage", "step": 6, "total": 7})
        s6 = self._score_storyline_trace_coverage(resolved, vis, host_time_index, context)
        progress("sub_score_done", {"name": "Storyline Trace Coverage", "score": s6.score})

        progress("sub_score_start", {"name": "Intent Reconciliation", "step": 7, "total": 7})
        s7 = self._score_intent_reconciliation(scenario, context)
        progress("sub_score_done", {"name": "Intent Reconciliation", "score": s7.score})

        sub_scores = [s1, s2, s3, s4, s5, s6, s7]
        dim_score = aggregate_sub_scores(sub_scores)

        host_log_profile = _build_host_log_profile(records, vis, scenario)

        return PillarScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
            supplementary={"host_log_profile": host_log_profile},
        )

    @staticmethod
    def _score_intent_reconciliation(
        scenario: Scenario,
        context: EvaluationContext,
    ) -> SubScore:
        """Require every authored typed intent to survive planning reconciliation."""

        authored = AuthoredIntentLedger.from_scenario(scenario)
        if not authored.intents:
            return SubScore(
                name="Intent Reconciliation",
                key="intent_reconciliation",
                weight=0.0,
                score=None,
                skipped=True,
                details="Scenario has no authored storyline or red-herring intents",
            )
        ground_truth = context.ground_truth
        if ground_truth is None or ground_truth.intent_reconciliation is None:
            return SubScore(
                name="Intent Reconciliation",
                key="intent_reconciliation",
                weight=0.0,
                score=0.0,
                details="Canonical ground truth has no authored-intent reconciliation",
                sample_failures=["GROUND_TRUTH.json is missing the intent_reconciliation contract"],
            )

        reconciliation = ground_truth.intent_reconciliation
        rows_by_id = {row.intent_id: row for row in reconciliation.intents}
        authored_by_id = {intent.intent_id: intent for intent in authored.intents}
        expected_ids = authored.intent_ids
        actual_ids = frozenset(rows_by_id)
        missing_rows = expected_ids - actual_ids
        unexpected_rows = actual_ids - expected_ids
        unplanned = {
            intent_id
            for intent_id in expected_ids & actual_ids
            if not rows_by_id[intent_id].planned
        }
        mismatched_metadata = {
            intent_id
            for intent_id in expected_ids & actual_ids
            if (
                rows_by_id[intent_id].ground_truth_section,
                rows_by_id[intent_id].storyline_id,
                rows_by_id[intent_id].event_type,
                rows_by_id[intent_id].semantic_instance_key,
                rows_by_id[intent_id].authored_time,
                rows_by_id[intent_id].actor,
                rows_by_id[intent_id].system,
                rows_by_id[intent_id].activity,
            )
            != (
                authored_by_id[intent_id].section.value,
                authored_by_id[intent_id].step_id,
                authored_by_id[intent_id].event_type,
                authored_by_id[intent_id].semantic_instance_key,
                authored_by_id[intent_id].authored_time,
                authored_by_id[intent_id].actor,
                authored_by_id[intent_id].system,
                authored_by_id[intent_id].activity,
            )
        }
        failures = [
            f"Missing reconciliation row for authored intent {value}" for value in missing_rows
        ]
        failures.extend(f"Authored intent was not planned: {value}" for value in unplanned)
        failures.extend(
            f"Reconciliation metadata differs from authored intent: {value}"
            for value in mismatched_metadata
        )
        failures.extend(f"Unexpected reconciliation intent: {value}" for value in unexpected_rows)
        failures.extend(
            f"Reconciliation reported missing intent: {value}"
            for value in reconciliation.missing_intent_ids
        )
        failures.extend(
            f"Reconciliation reported unexpected intent: {value}"
            for value in reconciliation.unexpected_intent_ids
        )
        reported_missing = frozenset(reconciliation.missing_intent_ids)
        reported_unexpected = frozenset(reconciliation.unexpected_intent_ids)
        expected_missing = missing_rows | unplanned
        missing_summary_drift = reported_missing ^ expected_missing
        unexpected_ids = unexpected_rows | reported_unexpected
        failures.extend(
            f"Reconciliation missing-intent summary differs from rows: {value}"
            for value in missing_summary_drift
        )
        invalid_ids = expected_missing | mismatched_metadata | missing_summary_drift
        total_assertions = len(expected_ids) + len(unexpected_ids)
        correct = max(0, len(expected_ids) - len(invalid_ids))
        score = 100.0 * correct / total_assertions if total_assertions else 0.0
        return SubScore(
            name="Intent Reconciliation",
            key="intent_reconciliation",
            weight=0.0,
            score=score,
            details=(
                f"{correct}/{total_assertions} authored/planner reconciliation assertions pass; "
                f"{reconciliation.occurred_count} intents dispatched canonical events and "
                f"{reconciliation.observed_count} had visible or delayed source evidence"
            ),
            sample_failures=sorted(set(failures))[:10],
        )

    # --- Host-time index ---

    @staticmethod
    def _build_host_time_index(
        records: dict[str, list[ParsedRecord]],
    ) -> dict[str, dict[str, list[ParsedRecord]]]:
        index: dict[str, dict[str, list[ParsedRecord]]] = defaultdict(lambda: defaultdict(list))
        for format_name, record_list in records.items():
            for rec in record_list:
                if rec.timestamp is None:
                    continue
                hostname = None
                for field_name in ("Computer", "hostname", "host_name"):
                    val = rec.fields.get(field_name)
                    if val and isinstance(val, str):
                        hostname = val
                        break
                if hostname is None and rec.source_host:
                    hostname = rec.source_host
                ts = rec.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                bucket = int(ts.timestamp()) // 60
                if hostname:
                    hn_lower = hostname.lower()
                    index[f"{hn_lower}|{bucket}"][format_name].append(rec)
                    if "." in hn_lower:
                        bare = hn_lower.split(".")[0]
                        index[f"{bare}|{bucket}"][format_name].append(rec)
                for ip_field in (
                    "id.orig_h",
                    "id.resp_h",
                    "src_ip",
                    "dst_ip",
                    "mapped_src_ip",
                    "mapped_dst_ip",
                    "client_addr",
                    "host",
                    "server_name",
                ):
                    ip_val = rec.fields.get(ip_field)
                    if ip_val and ip_val not in (hostname, ""):
                        normalized = CausalityScorer._normalize_index_value(ip_val)
                        if normalized:
                            index[f"{normalized}|{bucket}"][format_name].append(rec)
        return dict(index)

    @classmethod
    def _normalize_index_value(cls, value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip().lower()
        if not text or text == "-":
            return ""
        return cls._normalize_beacon_host(text) or text

    # --- Trace finding ---

    def _find_traces(
        self,
        resolved: list[ResolvedEvent],
        records: dict[str, list[ParsedRecord]],
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> None:
        for event in resolved:
            for event_type in event.event_types:
                if event_type in {"email_message", "email_read"}:
                    traces = self._search_for_email_event(event, event_type, records)
                else:
                    traces = self._search_for_event_indexed(event, event_type, host_time_index)
                event.traces.extend(traces)

    def _search_for_email_event(
        self,
        event: ResolvedEvent,
        event_type: str,
        records: dict[str, list[ParsedRecord]],
    ) -> list[ParsedRecord]:
        """Search email storyline traces without relying on the actor host index.

        Email delivery evidence can land on SMTP servers, external MX peers, or the
        artifact manifest rather than the storyline actor's workstation. Mailbox reads
        are opaque TLS sessions keyed by the reader host and mailbox server.
        """
        found: list[ParsedRecord] = []
        seen: set[int] = set()
        for format_name, record_list in records.items():
            for record in record_list:
                if id(record) in seen:
                    continue
                matches = self._record_matches(record, format_name, event, event_type)
                if matches and (
                    self._record_near_event(record, event)
                    or self._email_record_has_ground_truth_identity(record, event)
                ):
                    found.append(record)
                    seen.add(id(record))
        return found

    def _email_record_has_ground_truth_identity(
        self,
        record: ParsedRecord,
        event: ResolvedEvent,
    ) -> bool:
        ground_truth = self._email_gt.get(event.storyline_id) or {}
        message_id = ground_truth.get("message_id")
        if message_id and record.fields.get("message_id") == message_id:
            return True
        uid = record.fields.get("uid")
        return bool(uid and uid in set(ground_truth.get("smtp_uids") or ()))

    @staticmethod
    def _record_near_event(record: ParsedRecord, event: ResolvedEvent) -> bool:
        if record.timestamp is None:
            return False
        record_ts = record.timestamp
        if record_ts.tzinfo is None:
            record_ts = record_ts.replace(tzinfo=UTC)
        event_ts = event.time
        if event_ts.tzinfo is None:
            event_ts = event_ts.replace(tzinfo=UTC)
        return abs((record_ts - event_ts).total_seconds()) <= TIME_TOLERANCE.total_seconds()

    # --- Observation-profile adjustment helpers ---

    @staticmethod
    def _manifest_event(
        event: ResolvedEvent,
        context: EvaluationContext,
    ) -> ObservationManifestEvent | None:
        manifest = context.observation_manifest
        if manifest is None or manifest.observation_profile == "complete":
            return None
        return manifest.storyline_by_id().get(event.storyline_id)

    @classmethod
    def _event_observation_exempt(
        cls,
        event: ResolvedEvent,
        context: EvaluationContext,
    ) -> bool:
        if cls._event_generation_exempt(event, context):
            return True
        manifest_event = cls._manifest_event(event, context)
        if manifest_event is None:
            return False
        return manifest_event.visible_or_delayed_count == 0 and manifest_event.non_visible_count > 0

    @staticmethod
    def _event_generation_exempt(
        event: ResolvedEvent,
        context: EvaluationContext,
    ) -> bool:
        """Return whether ground truth records an authored step as a valid no-op."""

        document = context.ground_truth
        if document is None or not event.storyline_id:
            return False
        matching = [
            record
            for record in document.events
            if record.storyline_id == event.storyline_id and record.kind in event.event_types
        ]
        return bool(matching) and all(not record.emitted for record in matching)

    @classmethod
    def _format_group_observation_exempt(
        cls,
        event: ResolvedEvent,
        group_formats: set[str],
        context: EvaluationContext,
    ) -> bool:
        if cls._event_generation_exempt(event, context):
            return True
        manifest_event = cls._manifest_event(event, context)
        if manifest_event is None:
            return False
        source_families = {source_family_for_format(fmt) for fmt in group_formats}
        relevant = {
            source: counts
            for source, counts in manifest_event.source_status.items()
            if source in source_families
        }
        if not relevant:
            return False
        visible_or_delayed = sum(
            counts.get("visible", 0) + counts.get("delayed", 0) for counts in relevant.values()
        )
        non_visible = sum(
            counts.get("dropped", 0) + counts.get("filtered", 0) + counts.get("out_of_window", 0)
            for counts in relevant.values()
        )
        return visible_or_delayed == 0 and non_visible > 0

    @staticmethod
    def _adjusted_details(
        adjusted_details: str,
        raw_found: int,
        raw_total: int,
        excluded: int,
    ) -> str:
        if excluded <= 0:
            return adjusted_details
        raw_score = (100.0 * raw_found / raw_total) if raw_total > 0 else 100.0
        return (
            f"{adjusted_details}; raw {raw_found}/{raw_total} ({raw_score:.1f}/100), "
            f"{excluded} excluded by generation/observation contract"
        )

    def _search_for_event_indexed(
        self,
        event: ResolvedEvent,
        event_type: str,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> list[ParsedRecord]:
        found: list[ParsedRecord] = []
        # Prefer a per-type anchor time when set (a step carrying both spillage and
        # adversarial_payload anchors each type to its own emitted time); else event.time.
        evt_time = event.details.get(f"_anchor_time_{event_type}") or event.time
        if evt_time.tzinfo is None:
            evt_time = evt_time.replace(tzinfo=UTC)
        evt_bucket = int(evt_time.timestamp()) // 60

        forward_extra_secs = 0
        if event_type in _DURATION_EVENT_TYPES:
            duration_str = event.details.get("duration", "")
            interval_str = event.details.get("interval", "")
            window_str = duration_str or interval_str
            if window_str:
                try:
                    forward_extra_secs = min(int(parse_duration(window_str).total_seconds()), 3600)
                except (TypeError, ValueError):
                    forward_extra_secs = 3600
            else:
                forward_extra_secs = 3600
        elif event_type == "connection":
            forward_extra_secs = self._connection_trace_forward_secs(event)
        total_fwd_secs = TIME_TOLERANCE.total_seconds() + forward_extra_secs
        bwd_secs = TIME_TOLERANCE.total_seconds()

        fwd_buckets = int(total_fwd_secs / 60) + 1
        bucket_range = range(evt_bucket - 2, evt_bucket + fwd_buckets + 1)

        lookup_keys = [event.system.lower()]
        if event.system_ip:
            lookup_keys.append(event.system_ip)
        # For events with an explicit source_ip (e.g. external attack origin),
        # also search records indexed under that IP.
        explicit_src = event.details.get("source_ip")
        if explicit_src and explicit_src != event.system_ip:
            lookup_keys.append(explicit_src)
        explicit_dst = event.details.get("dst_ip")
        if explicit_dst:
            lookup_keys.append(str(explicit_dst))
        # Per-type destination host (the spillage/adversarial web server) takes
        # precedence over the shared hostname slot when both types share a step.
        expected_hostname = event.details.get(f"_anchor_host_{event_type}") or event.details.get(
            "hostname"
        )
        if expected_hostname:
            lookup_keys.append(str(expected_hostname).lower())

        seen: set[int] = set()
        for hostname_key in lookup_keys:
            for b in bucket_range:
                key = f"{hostname_key}|{b}"
                if key not in host_time_index:
                    continue
                for format_name, recs in host_time_index[key].items():
                    for record in recs:
                        if id(record) in seen:
                            continue
                        ts = record.timestamp
                        if ts is None:
                            continue
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=UTC)
                        delta = (ts - evt_time).total_seconds()
                        if delta < -bwd_secs or delta > total_fwd_secs:
                            continue
                        if self._record_matches(record, format_name, event, event_type):
                            found.append(record)
                            seen.add(id(record))
        return found

    @staticmethod
    def _connection_trace_forward_secs(event: ResolvedEvent) -> int:
        """Allow modest forward trace drift for web-style connection steps.

        Storyline timestamps often describe the beginning of a human-readable
        step, while web exploit/upload evidence can fan out into several
        request, endpoint, and network observations a few minutes later.
        """
        detail_sets = event.sub_details if event.sub_details else [event.details]
        web_markers = {"method", "uri", "user_agent", "status_code"}
        for details in detail_sets:
            if web_markers & details.keys():
                return 600
            if details.get("service") in {"http", "https"}:
                return 600
        return 0

    @staticmethod
    def _event_port_set(event: ResolvedEvent) -> set[int]:
        raw_ports = event.details.get("ports")
        if raw_ports is None:
            raw_port = event.details.get("dst_port")
            raw_ports = [] if raw_port is None else [raw_port]
        elif not isinstance(raw_ports, list | tuple | set):
            raw_ports = [raw_ports]

        ports: set[int] = set()
        for raw_port in raw_ports:
            try:
                ports.add(int(raw_port))
            except (TypeError, ValueError):
                continue
        return ports

    @staticmethod
    def _record_has_expected_port(
        fields: dict[str, Any],
        expected_ports: set[int],
        field_names: tuple[str, ...],
    ) -> bool:
        if not expected_ports:
            return True
        for field_name in field_names:
            try:
                if int(fields.get(field_name)) in expected_ports:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def _record_matches(
        self,
        record: ParsedRecord,
        format_name: str,
        event: ResolvedEvent,
        event_type: str,
    ) -> bool:
        f = record.fields
        if event_type == "logon":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4624
                    and self._user_matches(f.get("TargetUserName"), event.actor)
                    and self._host_matches(f.get("Computer"), event.system)
                )
            if format_name == "syslog":
                return self._host_matches(f.get("hostname"), event.system) and event.actor in f.get(
                    "message", ""
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and self._user_matches(f.get("principal"), event.actor)
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "process":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4688
                    and self._host_matches(f.get("Computer"), event.system)
                    and self._process_detail_matches(f, event)
                    and (
                        self._user_matches(f.get("SubjectUserName"), event.actor)
                        or self._user_matches(f.get("TargetUserName"), event.actor)
                    )
                )
            if format_name == "bash_history":
                return (
                    self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("username"), event.actor)
                    and self._process_detail_matches(f, event)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._process_detail_matches(f, event)
                    and self._user_matches(f.get("principal"), event.actor)
                )
        elif event_type == "connection":
            if format_name == "zeek_conn":
                return self._connection_matches_zeek(f, event)
            if format_name == "ecar":
                return (
                    f.get("object") == "FLOW"
                    and f.get("action") == "CONNECT"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._connection_ip_matches(f, event)
                )
            if format_name in {"proxy_access", "zeek_http"}:
                if not self._beacon_source_matches(f, event):
                    return False
                expected_dst = str(event.details.get("dst_ip") or "")
                expected_hostname = str(event.details.get("hostname") or "")
                return self._beacon_dst_matches(f, expected_dst) or self._beacon_dst_matches(
                    f, expected_hostname
                )
        elif event_type == "process_terminate":
            if format_name == "windows_event_security":
                return f.get("EventID") == 4689 and self._host_matches(
                    f.get("Computer"), event.system
                )
            if format_name == "windows_event_sysmon":
                return f.get("EventID") == 5 and self._host_matches(f.get("Computer"), event.system)
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "TERMINATE"
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "create_remote_thread":
            if format_name == "windows_event_sysmon":
                return (
                    f.get("EventID") == 8
                    and self._host_matches(f.get("Computer"), event.system)
                    and self._process_detail_matches(f, event)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "THREAD"
                    and f.get("action") == "REMOTE_CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._process_detail_matches(f, event)
                    and self._user_matches(f.get("principal"), event.actor)
                )
        elif event_type == "process_access":
            if format_name == "windows_event_sysmon":
                return (
                    f.get("EventID") == 10
                    and self._host_matches(f.get("Computer"), event.system)
                    and self._process_detail_matches(f, event)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "OPEN"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._process_detail_matches(f, event)
                    and self._user_matches(f.get("principal"), event.actor)
                )
        elif event_type == "service_installed":
            if format_name == "windows_event_security":
                return f.get("EventID") in (4697, 7045) and self._host_matches(
                    f.get("Computer"), event.system
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "SERVICE"
                    and f.get("action") == "CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "failed_logon":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4625
                    and self._host_matches(f.get("Computer"), event.system)
                    and self._user_matches(f.get("TargetUserName"), event.actor)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and f.get("failure_reason") is not None
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "account_created":
            if format_name == "windows_event_security":
                return f.get("EventID") == 4720 and self._host_matches(
                    f.get("Computer"), event.system
                )
        elif event_type == "account_deleted":
            if format_name == "windows_event_security":
                expected_target = event.details.get("target_username")
                return (
                    f.get("EventID") == 4726
                    and self._host_matches(f.get("Computer"), event.system)
                    and (
                        not expected_target
                        or self._user_matches(f.get("TargetUserName"), str(expected_target))
                    )
                )
        elif event_type == "group_member_added":
            if format_name == "windows_event_security":
                return f.get("EventID") in (4728, 4732, 4756) and self._host_matches(
                    f.get("Computer"), event.system
                )
        elif event_type == "log_cleared":
            if format_name == "windows_event_security":
                return f.get("EventID") == 1102 and self._host_matches(
                    f.get("Computer"), event.system
                )
        elif event_type == "scheduled_task_created":
            if format_name == "windows_event_security":
                return f.get("EventID") == 4698 and self._host_matches(
                    f.get("Computer"), event.system
                )
        elif event_type == "ssh_session":
            if format_name == "syslog":
                msg = f.get("message", "")
                if not self._host_matches(f.get("hostname"), event.system) or not (
                    "Accepted" in msg or "session opened" in msg
                ):
                    return False
                if event.actor and event.actor not in msg:
                    return False
                expected_src = event.details.get("source_ip")
                if expected_src and "Accepted" in msg and f" from {expected_src} " not in msg:
                    return False
                return True
            if format_name == "ecar":
                if not (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("principal"), event.actor)
                ):
                    return False
                expected_src = event.details.get("source_ip")
                return not expected_src or f.get("src_ip") == expected_src
        elif event_type == "rdp_session":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4624
                    and f.get("LogonType") in (10, "10")
                    and self._host_matches(f.get("Computer"), event.system)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "dhcp_lease":
            if format_name == "zeek_dhcp":
                return True
        elif event_type == "port_scan":
            # Use explicit source_ip from spec when present (e.g. external attack origin);
            # fall back to system_ip for internally-sourced scans.
            scan_src = event.details.get("source_ip") or event.system_ip
            scan_ports = self._event_port_set(event)
            if format_name == "cisco_asa":
                msg_id = f.get("msg_id")
                if msg_id == 733100:
                    return True
                return (
                    msg_id in (302013, 302014, 106023)
                    and f.get("src_ip") == scan_src
                    and self._record_has_expected_port(
                        f,
                        scan_ports,
                        ("dst_port", "mapped_dst_port"),
                    )
                )
            if format_name == "zeek_conn":
                return (
                    f.get("id.orig_h") == scan_src
                    and f.get("conn_state") in ("S0", "REJ", "RSTO", "RSTR")
                    and self._record_has_expected_port(
                        f,
                        scan_ports,
                        ("id.resp_p",),
                    )
                )
        elif event_type == "beacon":
            expected_dst = event.details.get("dst_ip", "")
            expected_hostname = event.details.get("hostname", "")
            expected_port = event.details.get("dst_port")
            action = event.details.get("action", "allow")
            if action == "deny":
                if format_name == "cisco_asa":
                    return (
                        f.get("msg_id") == 106023
                        and f.get("dst_ip") == expected_dst
                        and f.get("dst_port") == expected_port
                    )
                if format_name == "zeek_conn":
                    return (
                        f.get("id.resp_h") == expected_dst
                        and f.get("id.resp_p") == expected_port
                        and f.get("conn_state") in ("S0", "REJ")
                    )
                if format_name == "proxy_access":
                    # Proxy DENIED rows have status_code 403 or DENIED cache_result
                    denied = f.get("status_code") == 403 or f.get("cache_result") == "DENIED"
                    if not denied:
                        return False
                    if not self._beacon_source_matches(f, event):
                        return False
                    return self._beacon_dst_matches(f, expected_dst) or self._beacon_dst_matches(
                        f, expected_hostname
                    )
            else:
                if format_name == "zeek_conn":
                    return (
                        f.get("id.resp_h") == expected_dst and f.get("id.resp_p") == expected_port
                    )
                if format_name in ("proxy_access", "web_access", "zeek_http"):
                    if not self._beacon_source_matches(f, event):
                        return False
                    return self._beacon_dst_matches(f, expected_dst) or self._beacon_dst_matches(
                        f, expected_hostname
                    )
        elif event_type == "dns_query":
            expected_queries = {
                str(details["query"])
                for details in (event.sub_details or [event.details])
                if details.get("query")
            }
            if format_name == "zeek_dns":
                return f.get("query") in expected_queries
            if format_name == "zeek_conn":
                return f.get("id.resp_p") == 53 and f.get("id.orig_h") == event.system_ip
        elif event_type == "web_scan":
            expected_dst = event.details.get("dst_ip", "")
            expected_port = event.details.get("dst_port")
            expected_src = event.details.get("source_ip")
            if format_name == "web_access":
                source_ok = not expected_src or f.get("client_ip") == expected_src
                return (
                    source_ok
                    and self._host_matches(record.source_host, event.system)
                    and self._web_scan_profile_matches(f, event)
                )
            if format_name == "zeek_http":
                source_ok = not expected_src or f.get("id.orig_h") == expected_src
                return (
                    source_ok
                    and f.get("id.resp_h", f.get("dst_ip", "")) == expected_dst
                    and self._web_scan_profile_matches(f, event)
                )
            if format_name == "zeek_conn":
                source_ok = not expected_src or f.get("id.orig_h") == expected_src
                port_ok = expected_port is None or f.get("id.resp_p") == expected_port
                state_ok = f.get("conn_state") == "SF"
                return source_ok and f.get("id.resp_h") == expected_dst and port_ok and state_ok
        elif event_type == "credential_spray":
            target_accounts = event.details.get("target_accounts", [])
            if format_name == "windows_event_security":
                event_id = f.get("EventID")
                target_user = f.get("TargetUserName", "")
                return event_id in (4625, 4776, 4624) and (
                    not target_accounts or target_user in target_accounts
                )
            if format_name == "syslog":
                msg = f.get("message", "")
                if not ("Failed password" in msg or "Accepted password" in msg):
                    return False
                return not target_accounts or any(acct in msg for acct in target_accounts)
        elif event_type == "dga_queries":
            tld = event.details.get("tld", ".com")
            if format_name == "zeek_dns":
                query = f.get("query", "")
                return query.endswith(tld) and len(query) > 10
            if format_name == "zeek_conn":
                return f.get("id.resp_p") == 53 and f.get("id.orig_h") == event.system_ip
        elif event_type == "dns_tunnel":
            base_domain = event.details.get("base_domain", "")
            if format_name == "zeek_dns":
                query = f.get("query", "")
                return base_domain and query.endswith(base_domain)
            if format_name == "zeek_conn":
                return f.get("id.resp_p") == 53 and f.get("id.orig_h") == event.system_ip
        elif event_type == "explicit_credentials":
            target_user = event.details.get("target_username", "")
            if format_name == "windows_event_security":
                return f.get("EventID") == 4648 and (
                    not target_user or f.get("TargetUserName", "") == target_user
                )
        elif event_type in ("workstation_lock", "workstation_unlock"):
            expected_id = 4800 if event_type == "workstation_lock" else 4801
            if format_name == "windows_event_security":
                return f.get("EventID") == expected_id
        elif event_type == "logoff":
            if format_name == "windows_event_security":
                if f.get("EventID") not in (4634, 4647) or not self._host_matches(
                    f.get("Computer"), event.system
                ):
                    return False
                username = f.get("TargetUserName") or f.get("SubjectUserName")
                return self._user_matches(username, event.actor)
            if format_name == "syslog":
                msg = f.get("message", "")
                return (
                    self._host_matches(f.get("hostname"), event.system)
                    and event.actor in msg
                    and ("session closed" in msg or "Disconnected from" in msg)
                )
            if format_name == "bash_history":
                return (
                    self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("username"), event.actor)
                    and (
                        f.get("command", "").startswith("exit")
                        or f.get("command", "").startswith("logout")
                    )
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGOUT"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("principal"), event.actor)
                )
        elif event_type == "spillage":
            return self._spillage_record_matches(f, format_name, event)
        elif event_type == "adversarial_payload":
            return self._adversarial_payload_record_matches(f, format_name, event)
        elif event_type == "email_message":
            return self._email_message_record_matches(f, format_name, event)
        elif event_type == "email_read":
            return self._email_read_record_matches(f, format_name, event)
        elif event_type == "raw":
            return self._raw_record_matches(f, format_name, event)
        return False

    def _email_message_record_matches(
        self,
        fields: dict[str, Any],
        format_name: str,
        event: ResolvedEvent,
    ) -> bool:
        """Match storyline email delivery to manifest or plaintext SMTP evidence."""
        if format_name == "email_artifacts":
            gt = self._email_gt.get(event.storyline_id) or {}
            message_id = gt.get("message_id")
            return bool(message_id and fields.get("message_id") == message_id)
        gt = self._email_gt.get(event.storyline_id) or {}
        if format_name in {"zeek_smtp", "zeek_conn", "zeek_ssl"}:
            uid = fields.get("uid")
            if uid and uid in set(gt.get("smtp_uids") or ()):
                return True
        if format_name != "zeek_smtp":
            return False

        sender = str(
            event.details.get("sender") or self._email_actor_emails.get(event.actor.lower()) or ""
        ).lower()
        if sender and str(fields.get("mailfrom") or "").lower() != sender:
            return False

        expected_visible = {
            self._normalize_email_address(address)
            for key in ("to", "cc")
            for address in (event.details.get(key) or [])
        }
        if expected_visible:
            observed_visible = {
                self._normalize_email_address(address)
                for key in ("to", "cc")
                for address in (fields.get(key) or [])
            }
            if not (expected_visible & observed_visible):
                return False

        subject = event.details.get("subject")
        if subject and fields.get("subject") and str(fields["subject"]) != str(subject):
            return False
        return True

    def _email_read_record_matches(
        self,
        fields: dict[str, Any],
        format_name: str,
        event: ResolvedEvent,
    ) -> bool:
        """Match opaque TLS mailbox reads to Zeek connection/SSL evidence."""
        if format_name == "proxy_access":
            if event.system_ip and fields.get("client_ip") != event.system_ip:
                return False
            server_name = str(event.details.get("server") or "").lower()
            expected_host = self._email_server_hosts.get(server_name)
            return bool(expected_host and str(fields.get("host") or "").lower() == expected_host)
        if format_name not in {"zeek_conn", "zeek_ssl"}:
            return False
        if event.system_ip and fields.get("id.orig_h") != event.system_ip:
            return False

        server_name = str(event.details.get("server") or "").lower()
        expected_server_ips: set[str] = set(self._email_server_ips.values())
        if server_name:
            server_ip = self._email_server_ips.get(server_name)
            if server_ip is None:
                return False
            expected_server_ips = {server_ip}
        if expected_server_ips and fields.get("id.resp_h") not in expected_server_ips:
            return False

        protocol = event.details.get("protocol")
        expected_ports = {443, 993}
        if protocol == "owa":
            expected_ports = {443}
        elif protocol == "imaps":
            expected_ports = {993}
        if not self._record_has_expected_port(fields, expected_ports, ("id.resp_p",)):
            return False
        if format_name == "zeek_conn" and fields.get("service") not in {"ssl", "https"}:
            return False
        return True

    @staticmethod
    def _normalize_email_address(value: Any) -> str:
        text = str(value or "").strip().lower()
        match = re.search(r"<?([a-z0-9._%+$-]+@[a-z0-9.-]+\.[a-z]{2,})>?", text)
        return match.group(1) if match else text

    # The text field(s) that carry a spilled credential, per parsed log format.
    # process_command_line requires `ecar` (the cross-OS EDR process source — see
    # SURFACE_FORMATS), so credentials on a command line are matched there on both
    # Linux and Windows; no Windows-specific parser arm is needed. web_access
    # carries the URL surface in `path` and the Referer surface in `referer`.
    _SPILLAGE_TEXT_FIELD = {
        "bash_history": ("command",),
        "syslog": ("message",),
        "ecar": ("command_line",),
        "web_access": ("path", "referer"),
        "zeek_http": ("uri", "referrer"),
    }

    # Web evidence lands on the destination web server / sensor path (not
    # event.system), so it is matched by the unique, marked credential value alone.
    _SPILLAGE_HOST_AGNOSTIC = frozenset({"web_access", "zeek_http"})

    def _spillage_record_matches(self, f: dict, format_name: str, event: ResolvedEvent) -> bool:
        """Match a spillage event to the record carrying its credential.

        Reads the on-disk rendered value(s) from the canonical GROUND_TRUTH.json
        (loaded into context) and substring-matches them in the record's text
        field(s) on the right host (+actor for shell). The evaluator does not
        re-run generation synthesis — it verifies the labeled value is present.
        """
        expected = (self._spillage_gt.get(event.storyline_id) or {}).get("values", [])
        if not expected:
            return False
        text_fields = self._SPILLAGE_TEXT_FIELD.get(format_name)
        if not text_fields:
            return False
        if format_name not in self._SPILLAGE_HOST_AGNOSTIC:
            if not self._host_matches(f.get("hostname"), event.system):
                return False
            if format_name == "bash_history" and not self._user_matches(
                f.get("username"), event.actor
            ):
                return False
        text = "\n".join(str(f.get(field, "") or "") for field in text_fields)
        return any(value and value in text for value in expected)

    def _event_present(self, event: ResolvedEvent) -> bool:
        """Whether a storyline event counts as observed in the logs.

        Default: at least one trace. For spillage, EVERY labeled credential for the
        event's storyline_id must appear in a trace — finding one spill in a
        multi-spill storyline step does not vouch for the others. The same holds for
        adversarial_payload; when a step carries BOTH families, both must be present.
        """
        if not event.traces:
            return False
        present = True
        if "spillage" in event.event_types and self._spillage_gt.get(event.storyline_id):
            present = present and self._all_spillage_values_traced(event)
        if "adversarial_payload" in event.event_types and self._adversarial_payload_gt.get(
            event.storyline_id
        ):
            present = present and self._all_adversarial_payloads_landed(event)
        return present

    def _all_spillage_values_traced(self, event: ResolvedEvent) -> bool:
        """True only if every labeled spillage record for this event is observed.

        Each labeled record must be satisfied by a DISTINCT trace whose source
        format is one of the record's ``expected_sources`` (consuming each trace at
        most once). This makes N identical-valued spills require N separate
        landings (no multiset collapse) and stops a trace in the wrong format from
        crediting a value spilled to a different surface (no cross-surface credit).
        """
        gt = self._spillage_gt.get(event.storyline_id) or {}
        records = gt.get("records")
        if not records:
            # Empty record set: fall back to all-values-present semantics.
            expected = gt.get("values", [])
            if not expected:
                return bool(event.traces)
            observed: list[str] = []
            for record in event.traces:
                for field in self._SPILLAGE_TEXT_FIELD.get(record.source_format, ()):
                    value = record.fields.get(field)
                    if value:
                        observed.append(str(value))
            blob = "\n".join(observed)
            return all(value and value in blob for value in expected)

        remaining = list(event.traces)
        for rec in records:
            wanted = rec.get("value")
            allowed = set(rec.get("expected_sources") or ())
            hit: int | None = None
            for i, trace in enumerate(remaining):
                if allowed and trace.source_format not in allowed:
                    continue
                text = "\n".join(
                    str(trace.fields.get(field, "") or "")
                    for field in self._SPILLAGE_TEXT_FIELD.get(trace.source_format, ())
                )
                if wanted and wanted in text:
                    hit = i
                    break
            if hit is None:
                return False
            remaining.pop(hit)
        return True

    # The parsed text field(s) that can carry an adversarial payload, per format.
    # web_access adds `user_agent` over the spillage set because http_user_agent is
    # a first-class adversarial surface (the classic Log4Shell/UA vector).
    _ADVERSARIAL_TEXT_FIELD: ClassVar[dict[str, tuple[str, ...]]] = {
        "syslog": ("message",),
        "ecar": ("command_line",),
        "web_access": ("path", "referer", "user_agent"),
        # A plaintext-http payload is also visible on the wire (Zeek http.log); an
        # https one is not. The server's web_access log stays the authoritative
        # landing (expected_sources), but recognizing the value in zeek_http lets a
        # defender forcing `scheme: http` see it matched in network evidence too.
        "zeek_http": ("uri", "referrer", "user_agent"),
        # dns_qname encodes the payload into a DNS query NAME; a host keeps no DNS log of
        # its own, so the network sensor's Zeek dns.log `query` field is the authoritative
        # landing (expected_sources), matched by the unique marked QNAME value.
        "zeek_dns": ("query",),
    }

    # Web/network evidence lands on the destination server / sensor path (not
    # event.system), so it is matched by the unique, marked payload value alone. zeek_dns
    # joins this set: the dns.log row is keyed by the actor's IP, not a hostname field.
    _ADVERSARIAL_HOST_AGNOSTIC = frozenset({"web_access", "zeek_http", "zeek_dns"})

    @staticmethod
    def _normalize_nl(text: str) -> str:
        """Collapse CRLF/CR to LF so a forged-line split matches its source text."""
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def _build_ap_search_text(self, records: dict[str, list[ParsedRecord]]) -> dict[str, str]:
        """Build a per-format, newline-normalized search blob for payload presence.

        Concatenates each record's parsed text field(s) AND its raw line, in file
        order, then normalizes newlines. The raw lines are what let a crlf_log_forging
        payload — whose rendered value spans two physical syslog lines (the injected
        line plus the forged ``forged-entry`` line, which fails to parse and so carries
        no ``message`` field) — be found as a single contiguous substring even though
        no single parsed record contains it.
        """
        blobs: dict[str, str] = {}
        for fmt, recs in records.items():
            text_fields = self._ADVERSARIAL_TEXT_FIELD.get(fmt, ())
            parts: list[str] = []
            for rec in recs:
                for field in text_fields:
                    val = rec.fields.get(field)
                    if val:
                        parts.append(str(val))
                if rec.raw:
                    parts.append(rec.raw)
            blobs[fmt] = self._normalize_nl("\n".join(parts))
        return blobs

    def _adversarial_payload_record_matches(
        self, f: dict, format_name: str, event: ResolvedEvent
    ) -> bool:
        """Link a single parsed record to an adversarial_payload event as a trace.

        Lenient by design: matches if the record's text carries the full rendered
        value OR any substantial physical line of it. The full-span correctness
        check (that a forged second line also landed) is done against the per-format
        search blob in :meth:`_all_adversarial_payloads_landed`; here we only need to
        anchor the event to at least one observed record so it is not orphaned.
        """
        records = (self._adversarial_payload_gt.get(event.storyline_id) or {}).get("records", [])
        if not records:
            return False
        if format_name not in self._ADVERSARIAL_HOST_AGNOSTIC:
            if not self._host_matches(f.get("hostname"), event.system):
                return False
        text_fields = self._ADVERSARIAL_TEXT_FIELD.get(format_name)
        if not text_fields:
            return False
        text = self._normalize_nl("\n".join(str(f.get(field, "") or "") for field in text_fields))
        for rec in records:
            value = rec.get("value")
            allowed = rec.get("expected_sources") or ()
            if not value or (allowed and format_name not in allowed):
                continue
            norm = self._normalize_nl(value)
            # A line ≥8 chars cannot be benign: every payload line carries the marker
            # (≥3 chars) plus distinctive content by the generation safety contract.
            candidates = [ln for ln in norm.split("\n") if len(ln.strip()) >= 8] or [norm]
            if any(c in text for c in candidates):
                return True
        return False

    def _all_adversarial_payloads_landed(self, event: ResolvedEvent) -> bool:
        """True only if every labeled payload for this event is present, intact.

        Each labeled rendered value (newline-normalized) must appear as a contiguous
        substring of the search blob for one of its ``expected_sources`` — verifying
        the full injection, including a forged CRLF second line, survived to disk.
        Paired with the trace requirement in :meth:`_event_present`, this also stops
        a value that landed for a different event from crediting one that did not.

        Match is by value presence, not distinct-landing consumption: per-event
        synthesis gives every family payload a unique ``{alnum}`` token, so distinct
        labels have distinct values. Residual: two byte-identical *literal* payloads in
        one step (an unusual authoring choice) where only one lands would over-credit —
        the blob cannot consume per-landing because a single line contributes the value
        to both its parsed field and its raw text.
        """
        records = (self._adversarial_payload_gt.get(event.storyline_id) or {}).get("records", [])
        if not records:
            return bool(event.traces)
        for rec in records:
            value = rec.get("value")
            if not value:
                return False
            norm = self._normalize_nl(value)
            allowed = rec.get("expected_sources") or ()
            blobs = [self._ap_search_text.get(fmt, "") for fmt in allowed]
            if not blobs:
                blobs = list(self._ap_search_text.values())
            if not any(norm and norm in blob for blob in blobs):
                return False
        return True

    def _raw_record_matches(
        self,
        fields: dict[str, Any],
        format_name: str,
        event: ResolvedEvent,
    ) -> bool:
        target_format = event.details.get("target_format")
        if target_format and format_name != target_format:
            return False
        expected_fields = event.details.get("fields")
        if not isinstance(expected_fields, dict):
            return True
        for key, expected in expected_fields.items():
            if key == "timestamp":
                continue
            actual = fields.get(key)
            if key == "hostname":
                if not self._host_matches(actual, str(expected)):
                    return False
                continue
            if key == "message":
                if not self._message_fragment_matches(expected, actual):
                    return False
                continue
            if actual is not None and str(actual) != str(expected):
                return False
        return True

    @staticmethod
    def _message_fragment_matches(expected: Any, actual: Any) -> bool:
        if actual is None:
            return False
        expected_text = str(expected)
        actual_text = str(actual)
        if expected_text in actual_text or actual_text in expected_text:
            return True
        expected_tokens = {
            token
            for token in re.findall(r"[A-Za-z0-9_./:%=,-]{12,}", expected_text)
            if not token.startswith("[")
        }
        actual_tokens = set(re.findall(r"[A-Za-z0-9_./:%=,-]{12,}", actual_text))
        return bool(expected_tokens & actual_tokens)

    @staticmethod
    def _process_detail_sets(event: ResolvedEvent) -> list[dict[str, Any]]:
        detail_sets = event.sub_details if event.sub_details else [event.details]
        process_details = [
            details
            for details in detail_sets
            if details.get("process_name") or details.get("command_line")
        ]
        return process_details

    @classmethod
    def _process_detail_matches(cls, fields: dict[str, Any], event: ResolvedEvent) -> bool:
        process_details = cls._process_detail_sets(event)
        if not process_details:
            return True
        record_image = str(
            fields.get("NewProcessName")
            or fields.get("SourceImage")
            or fields.get("image_path")
            or fields.get("process_name")
            or fields.get("command")
            or ""
        ).lower()
        record_command = str(
            fields.get("CommandLine") or fields.get("command_line") or fields.get("command") or ""
        ).lower()
        for details in process_details:
            process_name = str(details.get("process_name") or "").lower()
            command_line = str(details.get("command_line") or "").lower()
            image_ok = not process_name or record_image.endswith(process_name.rsplit("\\", 1)[-1])
            command_ok = not command_line or command_line in record_command
            if image_ok and command_ok:
                return True
        return False

    @staticmethod
    def _web_scan_profile_matches(fields: dict[str, Any], event: ResolvedEvent) -> bool:
        preset = str(event.details.get("preset") or "").lower()
        if preset == "nikto":
            user_agent = str(fields.get("user_agent") or "").lower()
            return "nikto" in user_agent
        return True

    def _connection_matches_zeek(self, fields: dict, event: ResolvedEvent) -> bool:
        orig_h = fields.get("id.orig_h", "")
        resp_h = fields.get("id.resp_h", "")
        details = event.details
        proxy_mode = getattr(self, "_proxy_mode", "transparent")
        proxy_ips = getattr(self, "_proxy_ips", set())

        if "source_ip" in details and "dst_ip" in details:
            source_ip = details["source_ip"]
            dst_ip = details["dst_ip"]
            if (
                orig_h == source_ip
                and resp_h == dst_ip
                and self._connection_port_matches(fields, details)
            ):
                return True
            if (
                proxy_mode == "explicit"
                and orig_h == source_ip
                and resp_h in proxy_ips
                and self._proxy_client_port_matches(fields)
            ):
                return True
            if (
                proxy_mode == "explicit"
                and orig_h in proxy_ips
                and resp_h == dst_ip
                and self._connection_port_matches(fields, details)
            ):
                return True
            return False

        if event.system_ip and orig_h == event.system_ip:
            if "dst_ip" in details:
                if proxy_mode == "explicit" and resp_h in proxy_ips:
                    return self._proxy_client_port_matches(fields)
                return resp_h == details["dst_ip"] and self._connection_port_matches(
                    fields, details
                )
            return self._connection_port_matches(fields, details)

        if (
            proxy_mode == "explicit"
            and orig_h in proxy_ips
            and "dst_ip" in details
            and resp_h == details["dst_ip"]
        ):
            return self._connection_port_matches(fields, details)

        if "dst_ip" in details and resp_h == details["dst_ip"]:
            return self._connection_port_matches(fields, details)
        if "source_ip" in details and orig_h == details["source_ip"]:
            return self._connection_port_matches(fields, details)
        return False

    def _proxy_client_port_matches(self, fields: dict[str, Any]) -> bool:
        """Match the physical client-to-proxy listener, not the logical origin port."""

        return self._record_has_expected_port(
            fields,
            {int(getattr(self, "_proxy_listener_port", 8080))},
            ("id.resp_p", "dst_port"),
        )

    @staticmethod
    def _connection_port_matches(fields: dict[str, Any], details: dict[str, Any]) -> bool:
        expected_port = details.get("dst_port")
        if expected_port is None:
            return True
        for port_field in ("id.resp_p", "dst_port"):
            actual_port = fields.get(port_field)
            if actual_port is None:
                continue
            try:
                return int(actual_port) == int(expected_port)
            except (TypeError, ValueError):
                return str(actual_port) == str(expected_port)
        return True

    @staticmethod
    def _connection_detail_sets(event: ResolvedEvent) -> list[dict[str, Any]]:
        detail_sets = event.sub_details if event.sub_details else [event.details]
        constrained = [
            details
            for details in detail_sets
            if "source_ip" in details or "dst_ip" in details or "dst_port" in details
        ]
        if any("dst_ip" in details for details in constrained):
            return [details for details in constrained if "dst_ip" in details]
        return constrained or [event.details]

    @classmethod
    def _connection_detail_matches(
        cls,
        fields: dict[str, Any],
        details: dict[str, Any],
        *,
        src_field: str,
        dst_field: str,
    ) -> bool:
        if "source_ip" in details and fields.get(src_field) != details["source_ip"]:
            return False
        if "dst_ip" in details and fields.get(dst_field) != details["dst_ip"]:
            return False
        return cls._connection_port_matches(fields, details)

    @classmethod
    def _connection_ip_matches(cls, fields: dict, event: ResolvedEvent) -> bool:
        for details in cls._connection_detail_sets(event):
            if cls._connection_detail_matches(
                fields,
                details,
                src_field="src_ip",
                dst_field="dst_ip",
            ):
                return True
        return False

    @staticmethod
    def _expected_usernames_for_event(event: ResolvedEvent) -> set[str]:
        details = event.details
        expected: set[str] = set()
        target_username = details.get("target_username")
        if isinstance(target_username, str) and target_username:
            expected.add(target_username)
        target_accounts = details.get("target_accounts")
        if isinstance(target_accounts, list):
            expected.update(str(account) for account in target_accounts if account)
        success = details.get("success")
        if isinstance(success, dict) and success.get("account"):
            expected.add(str(success["account"]))
        return expected or {event.actor}

    @classmethod
    def _username_indicator_matches(cls, record_user: Any, event: ResolvedEvent) -> bool:
        return any(
            cls._user_matches(record_user, username)
            for username in cls._expected_usernames_for_event(event)
        )

    @classmethod
    def _user_matches(cls, record_user: Any, expected: str) -> bool:
        if record_user is None:
            return False
        return bool(
            cls._username_match_aliases(record_user) & cls._username_match_aliases(expected)
        )

    @staticmethod
    def _username_match_aliases(raw: Any) -> set[str]:
        text = str(raw or "").strip().lower()
        if not text or text == "-":
            return set()
        aliases = {text}
        email_match = re.search(r"<?([a-z0-9._%+$-]+@[a-z0-9.-]+\.[a-z]{2,})>?", text)
        if email_match:
            email = email_match.group(1)
            aliases.update({email, email.split("@", 1)[0]})
        if "\\" in text:
            aliases.add(text.rsplit("\\", 1)[-1])
        if "@" in text:
            aliases.add(text.split("@", 1)[0])
        return aliases

    @staticmethod
    def _host_matches(record_host: Any, expected: str) -> bool:
        if record_host is None:
            return False
        record_str = str(record_host).lower()
        expected_lower = expected.lower()
        return (
            record_str == expected_lower
            or record_str.startswith(expected_lower + ".")
            or expected_lower.startswith(record_str + ".")
        )

    @classmethod
    def _beacon_dst_matches(cls, fields: dict, expected_dst: str) -> bool:
        """Check whether a record references expected_dst as a beacon destination.

        Handles proxy_access (stores destination as 'host' hostname), zeek_http
        (id.resp_h / host / uri), and fallback IP fields. URL/URI values are
        parsed so only authority hostnames can satisfy the destination check.
        """
        expected = cls._normalize_beacon_host(expected_dst)
        if not expected:
            return False

        candidates: list[str] = []
        for field_name in ("id.resp_h", "dst_ip", "host"):
            candidate = cls._normalize_beacon_host(fields.get(field_name))
            if candidate:
                candidates.append(candidate)

        for field_name in ("url", "uri"):
            candidate = cls._extract_beacon_url_host(fields.get(field_name))
            if candidate:
                candidates.append(candidate)

        return any(cls._beacon_host_matches(candidate, expected) for candidate in candidates)

    def _beacon_source_matches(self, fields: dict[str, Any], event: ResolvedEvent) -> bool:
        expected_src = event.details.get("source_ip") or event.system_ip
        if not expected_src:
            return True
        proxy_ips = getattr(self, "_proxy_ips", set())
        client_ip = fields.get("client_ip")
        if client_ip:
            return self._ip_matches(client_ip, expected_src)
        orig_h = fields.get("id.orig_h")
        if orig_h:
            if self._ip_matches(orig_h, expected_src):
                return True
            # An explicit proxy's origin-side protocol trace is still part of the
            # logical transaction even though its physical source is the proxy.
            return orig_h in proxy_ips
        return True

    @staticmethod
    def _normalize_beacon_host(value: Any) -> str:
        """Normalize a beacon destination host/IP for exact comparisons."""
        if value is None:
            return ""
        host = str(value).strip().lower().strip("[]")
        if not host:
            return ""
        if host.endswith("."):
            host = host[:-1]
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return host

    @classmethod
    def _extract_beacon_url_host(cls, value: Any) -> str:
        """Extract and normalize only the authority host from an absolute URL/URI."""
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        try:
            parsed = urlsplit(text)
            hostname = parsed.hostname
        except ValueError:
            return ""
        if not hostname and text.startswith("//"):
            try:
                parsed = urlsplit(f"http:{text}")
                hostname = parsed.hostname
            except ValueError:
                return ""
        return cls._normalize_beacon_host(hostname)

    @staticmethod
    def _beacon_host_matches(candidate: str, expected: str) -> bool:
        """Compare beacon hosts/IPs without unsafe substring matching."""
        if candidate == expected:
            return True
        try:
            ipaddress.ip_address(candidate)
            return False
        except ValueError:
            pass
        try:
            ipaddress.ip_address(expected)
            return False
        except ValueError:
            pass
        return candidate.endswith(f".{expected}")

    # --- Sub-score 1: Causal Ordering ---

    def _score_causal_ordering(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
    ) -> SubScore:
        causal_rules = load_rules_file("causal_pairs.yaml")
        pairs_list = causal_rules.get("pairs", [])
        if not pairs_list:
            return SubScore(
                name="Causal Ordering",
                key="causal_ordering",
                weight=0.25,
                score=None,
                skipped=True,
                details="No causal pair rules defined",
            )

        scenario_start = scenario.time_window.start
        if scenario_start.tzinfo is None:
            scenario_start = scenario_start.replace(tzinfo=UTC)
        try:
            grace_td = parse_duration(scenario.logon_grace_period)
        except (ValueError, TypeError):
            grace_td = timedelta(minutes=30)
        grace_end = scenario_start + grace_td

        total_pairs = 0
        correct_pairs = 0
        failures: list[str] = []

        for rule in pairs_list:
            before_fmt = rule["before"]["format"]
            after_fmt = rule["after"]["format"]
            before_cond = rule["before"].get("condition", {})
            after_cond = rule["after"].get("condition", {})
            match_fields = rule.get("match_fields", {})
            before_field = match_fields.get("before")
            after_field = match_fields.get("after")
            extra_match = rule.get("extra_match")
            msg_contains = rule.get("before", {}).get("message_contains")

            before_records = records.get(before_fmt, [])
            after_records = records.get(after_fmt, [])
            if not before_records or not after_records:
                continue

            match_mode = rule.get("match_mode", "exact")
            exclude_ports = rule.get("exclude_ports", [])

            before_index: dict[str, list[ParsedRecord]] = defaultdict(list)
            for rec in before_records:
                if rec.timestamp is None:
                    continue
                if msg_contains:
                    if msg_contains not in rec.fields.get("message", ""):
                        continue
                elif not _condition_matches(before_cond, rec.fields):
                    continue
                if before_field:
                    key_val = rec.fields.get(before_field)
                    if key_val:
                        if match_mode == "list_contains" and isinstance(key_val, list):
                            for item in key_val:
                                idx_key = str(item)
                                if extra_match:
                                    idx_key = f"{idx_key}|{rec.fields.get(extra_match, '')}"
                                before_index[idx_key].append(rec)
                        else:
                            idx_key = str(key_val)
                            if extra_match:
                                idx_key = f"{idx_key}|{rec.fields.get(extra_match, '')}"
                            before_index[idx_key].append(rec)

            exclude_accounts = rule.get("exclude_accounts", [])
            tolerance = rule.get("tolerance", 0.0)
            allow_missing_prior = bool(rule.get("allow_missing_prior", False))
            rule_total = 0
            rule_correct = 0

            for rec in after_records:
                if rec.timestamp is None:
                    continue
                if not _condition_matches(after_cond, rec.fields):
                    continue
                rec_ts = rec.timestamp
                if rec_ts.tzinfo is None:
                    rec_ts = rec_ts.replace(tzinfo=UTC)
                if rec_ts <= grace_end:
                    continue
                if exclude_ports:
                    resp_p = rec.fields.get("id.resp_p")
                    if resp_p is not None:
                        try:
                            resp_p_int = int(resp_p)
                        except (TypeError, ValueError):
                            resp_p_int = None
                        if resp_p_int in exclude_ports:
                            continue
                if exclude_accounts:
                    subject = rec.fields.get("SubjectUserName") or rec.fields.get("principal")
                    if isinstance(subject, str):
                        normalized_subject = subject.upper()
                        if any(
                            isinstance(ea, str) and normalized_subject == ea.upper()
                            for ea in exclude_accounts
                        ) or subject.endswith("$"):
                            continue
                if after_field:
                    key_val = rec.fields.get(after_field)
                    if not key_val:
                        continue
                    idx_key = str(key_val)
                    if extra_match:
                        idx_key = f"{idx_key}|{rec.fields.get(extra_match, '')}"
                    matching_befores = before_index.get(idx_key, [])
                    if not matching_befores:
                        continue
                    rec_ts_norm = _normalize_ts(rec.timestamp)
                    any_before_earlier = any(
                        _normalize_ts(b.timestamp) <= rec_ts_norm
                        for b in matching_befores
                        if b.timestamp is not None
                    )
                    if any_before_earlier:
                        rule_total += 1
                        rule_correct += 1
                    elif allow_missing_prior:
                        # Some rules use weak keys such as principal+host or destination IP.
                        # A later matching "before" record is not enough to prove the current
                        # after-record is inverted; it can be a continuing pre-window session,
                        # DNS cache hit, hosts-file lookup, or static infrastructure flow.
                        continue
                    else:
                        rule_total += 1
                        if len(failures) < 10:
                            failures.append(
                                f"Rule '{rule['name']}': after event at line "
                                f"{rec.line_number} precedes all matching before events"
                            )

            if rule_total > 0 and tolerance > 0:
                failure_rate = 1.0 - (rule_correct / rule_total)
                if failure_rate <= tolerance:
                    rule_correct = rule_total

            total_pairs += rule_total
            correct_pairs += rule_correct

        remote_total, remote_correct, remote_failures = self._score_ecar_remote_auth_ordering(
            records.get("ecar", [])
        )
        total_pairs += remote_total
        correct_pairs += remote_correct
        for failure in remote_failures:
            if len(failures) >= 10:
                break
            failures.append(failure)

        parent_total, parent_correct, parent_failures = self._score_process_parent_integrity(
            records
        )
        total_pairs += parent_total
        correct_pairs += parent_correct
        for failure in parent_failures:
            if len(failures) >= 10:
                break
            failures.append(failure)

        if total_pairs == 0:
            return SubScore(
                name="Causal Ordering",
                key="causal_ordering",
                weight=0.25,
                score=None,
                skipped=True,
                details="No applicable causal pairs in this dataset",
            )
        score = 100.0 * correct_pairs / total_pairs
        return SubScore(
            name="Causal Ordering",
            key="causal_ordering",
            weight=0.25,
            score=score,
            details=f"{correct_pairs}/{total_pairs} causal pairs correctly ordered",
            sample_failures=failures,
        )

    @classmethod
    def _score_ecar_remote_auth_ordering(
        cls,
        records: list[ParsedRecord],
    ) -> tuple[int, int, list[str]]:
        """Score exact-tuple remote logins after the closest visible inbound FLOW."""

        flows: dict[tuple[str, ...], list[ParsedRecord]] = defaultdict(list)
        for record in records:
            fields = record.fields
            if (
                record.timestamp is None
                or fields.get("object") != "FLOW"
                or fields.get("action") != "CONNECT"
                or str(fields.get("direction") or "").upper() != "INBOUND"
            ):
                continue
            key = cls._ecar_remote_auth_transport_key(fields)
            if key is not None:
                flows[key].append(record)

        total = 0
        correct = 0
        failures: list[str] = []
        for record in records:
            fields = record.fields
            if (
                record.timestamp is None
                or fields.get("object") != "USER_SESSION"
                or fields.get("action") != "LOGIN"
                or str(fields.get("logon_type") or "") not in {"3", "10"}
            ):
                continue
            key = cls._ecar_remote_auth_transport_key(fields)
            matching_flows = flows.get(key, []) if key is not None else []
            if not matching_flows:
                continue
            login_time = _normalize_ts(record.timestamp)
            bounded_flows = [
                flow
                for flow in matching_flows
                if flow.timestamp is not None
                and abs((_normalize_ts(flow.timestamp) - login_time).total_seconds()) <= 5.0
            ]
            if not bounded_flows:
                continue
            nearest_flow = min(
                bounded_flows,
                key=lambda flow: abs((_normalize_ts(flow.timestamp) - login_time).total_seconds()),
            )
            total += 1
            if _normalize_ts(nearest_flow.timestamp) < login_time:
                correct += 1
            elif len(failures) < 10:
                failures.append(
                    "Rule 'eCAR remote FLOW before login': USER_SESSION at line "
                    f"{record.line_number} precedes its exact inbound FLOW"
                )
        return total, correct, failures

    @classmethod
    def _score_process_parent_integrity(
        cls,
        records: dict[str, list[ParsedRecord]],
    ) -> tuple[int, int, list[str]]:
        """Reject only parents proven terminated before a child without PID reuse."""

        lifecycles: dict[tuple[str, str, int], dict[str, list[datetime]]] = defaultdict(
            lambda: {"create": [], "terminate": []}
        )
        children: list[tuple[str, str, int, datetime, int | None]] = []
        for format_name in ("ecar", "windows_event_sysmon"):
            for record in records.get(format_name, []):
                if record.timestamp is None:
                    continue
                fields = record.fields
                host = str(
                    fields.get("hostname") or fields.get("Computer") or record.source_host or ""
                ).lower()
                if not host:
                    continue
                is_create = (
                    format_name == "ecar"
                    and fields.get("object") == "PROCESS"
                    and fields.get("action") == "CREATE"
                ) or (format_name == "windows_event_sysmon" and fields.get("EventID") == 1)
                is_terminate = (
                    format_name == "ecar"
                    and fields.get("object") == "PROCESS"
                    and fields.get("action") == "TERMINATE"
                ) or (format_name == "windows_event_sysmon" and fields.get("EventID") == 5)
                if not (is_create or is_terminate):
                    continue
                pid = cls._coerce_pid(fields.get("pid") or fields.get("ProcessId"))
                if pid is None:
                    continue
                timestamp = _normalize_ts(record.timestamp)
                key = (format_name, host, pid)
                lifecycles[key]["create" if is_create else "terminate"].append(timestamp)
                if is_create:
                    parent = cls._coerce_pid(fields.get("ppid") or fields.get("ParentProcessId"))
                    children.append((format_name, host, pid, timestamp, parent))

        total = 0
        correct = 0
        failures: list[str] = []
        for format_name, host, child_pid, child_time, parent_pid in children:
            if parent_pid in {None, 0, 4}:
                continue
            lifecycle = lifecycles.get((format_name, host, parent_pid))
            if lifecycle is None or not lifecycle["create"] or not lifecycle["terminate"]:
                continue
            prior_creates = [time for time in lifecycle["create"] if time <= child_time]
            prior_terminations = [time for time in lifecycle["terminate"] if time < child_time]
            if not prior_creates or not prior_terminations:
                continue
            total += 1
            last_create = max(prior_creates)
            last_terminate = max(prior_terminations)
            if last_create > last_terminate:
                correct += 1
            elif len(failures) < 10:
                failures.append(
                    f"{format_name} {host} child PID {child_pid} references stale parent "
                    f"PID {parent_pid}"
                )
        return total, correct, failures

    @staticmethod
    def _coerce_pid(value: Any) -> int | None:
        if value in (None, "", "-"):
            return None
        try:
            return int(str(value), 0)
        except ValueError:
            return None

    @staticmethod
    def _ecar_remote_auth_transport_key(fields: dict[str, Any]) -> tuple[str, ...] | None:
        """Return an exact host-local tuple correlation key."""

        required = (
            "hostname",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
        )
        if any(fields.get(name) in {None, "", "-"} for name in required):
            return None
        return (
            str(fields["hostname"]).lower(),
            str(fields["src_ip"]).removeprefix("::ffff:").lower(),
            str(fields["src_port"]),
            str(fields["dst_ip"]).removeprefix("::ffff:").lower(),
            str(fields["dst_port"]),
            str(fields["protocol"]).lower(),
        )

    # --- Sub-score 2: Event Presence ---

    def _score_event_presence(
        self,
        resolved: list[ResolvedEvent],
        context: EvaluationContext,
    ) -> SubScore:
        if not resolved:
            return SubScore(
                name="Event Presence",
                key="event_presence",
                weight=0.20,
                score=None,
                skipped=True,
                details="No storyline events",
            )
        raw_total = len(resolved)
        raw_found = sum(1 for e in resolved if self._event_present(e))
        total = 0
        found = 0
        excluded = 0
        for event in resolved:
            if self._event_present(event):
                total += 1
                found += 1
            elif self._event_observation_exempt(event, context):
                excluded += 1
            else:
                total += 1
        failures = [
            f"Event {e.index}: {e.actor}@{e.system} '{e.activity[:60]}' — no traces"
            for e in resolved
            if not self._event_present(e) and not self._event_observation_exempt(e, context)
        ]
        score = (100.0 * found / total) if total > 0 else 100.0
        raw_score = (100.0 * raw_found / raw_total) if raw_total > 0 else 100.0
        details = self._adjusted_details(
            f"{found}/{total} expected-visible storyline events have traces in logs",
            raw_found,
            raw_total,
            excluded,
        )
        # Explain, rather than mystify, a 0 caused by a missing ground-truth document.
        if not self._spillage_gt and any("spillage" in e.event_types for e in resolved):
            details += (
                " — spillage events need a GROUND_TRUTH.json document to match; "
                "none was loaded, so they score as untraced"
            )
        if not self._adversarial_payload_gt and any(
            "adversarial_payload" in e.event_types for e in resolved
        ):
            details += (
                " — adversarial_payload events need a GROUND_TRUTH.json document to match; "
                "none was loaded, so they score as untraced"
            )
        return SubScore(
            name="Event Presence",
            key="event_presence",
            weight=0.20,
            score=score,
            raw_score=raw_score if excluded else None,
            adjusted=excluded > 0,
            details=details,
            sample_failures=failures[:10],
        )

    # --- Sub-score 3: Indicator Accuracy ---

    def _score_indicator_accuracy(self, resolved: list[ResolvedEvent]) -> SubScore:
        if not resolved:
            return SubScore(
                name="Indicator Accuracy",
                key="indicator_accuracy",
                weight=0.15,
                score=None,
                skipped=True,
                details="No storyline events",
            )
        total_checks = 0
        correct_checks = 0
        failures: list[str] = []

        for event in resolved:
            if not event.traces:
                continue
            for trace in event.traces:
                checks = self._check_indicators(event, trace)
                for indicator_name, is_correct in checks:
                    total_checks += 1
                    if is_correct:
                        correct_checks += 1
                    else:
                        failures.append(
                            f"Event {event.index}: {indicator_name} mismatch in {trace.source_format}"
                        )

        if total_checks == 0:
            return SubScore(
                name="Indicator Accuracy",
                key="indicator_accuracy",
                weight=0.15,
                score=None,
                skipped=True,
                details="No checkable authored indicators were present in matched traces",
            )
        score = 100.0 * correct_checks / total_checks
        return SubScore(
            name="Indicator Accuracy",
            key="indicator_accuracy",
            weight=0.15,
            score=score,
            details=f"{correct_checks}/{total_checks} indicator checks correct",
            sample_failures=sorted(failures)[:10],
        )

    def _check_indicators(
        self,
        event: ResolvedEvent,
        trace: ParsedRecord,
    ) -> list[tuple[str, bool]]:
        checks: list[tuple[str, bool]] = []
        f = trace.fields
        details = self._best_sub_detail(event, f) if event.sub_details else event.details

        if (
            "group_member_added" in event.event_types
            and f.get("EventID") in (4728, 4732, 4756)
            and details.get("member_name")
        ):
            member_name = str(details["member_name"]).lower()
            member_field = str(f.get("MemberName") or f.get("MemberSid") or "").lower()
            checks.append(("username", member_name in member_field))
        else:
            for uf in ["TargetUserName", "SubjectUserName", "principal", "username"]:
                if uf in f and f[uf]:
                    if self._is_process_indicator_trace(f):
                        user_ok = self._user_matches(f[uf], event.actor)
                    else:
                        user_ok = self._username_indicator_matches(f[uf], event)
                    checks.append(("username", user_ok))
                    break
        if trace.source_format != "cisco_asa":
            for hf in ["Computer", "hostname"]:
                if hf in f and f[hf]:
                    checks.append(("hostname", self._host_matches(f[hf], event.system)))
                    break
        if "source_ip" in details:
            for ipf in ["IpAddress", "id.orig_h", "src_ip"]:
                if ipf in f and f[ipf] and f[ipf] != "-":
                    source_ok = self._ip_matches(f[ipf], details["source_ip"])
                    if not source_ok and self._is_explicit_proxy_egress_trace(f, details):
                        source_ok = True
                    checks.append(("source_ip", source_ok))
                    break
        if "dst_ip" in details:
            for df in ["id.resp_h", "dst_ip"]:
                if df in f and f[df]:
                    dst_ok = self._ip_matches(f[df], details["dst_ip"])
                    if not dst_ok and self._is_explicit_proxy_client_trace(f, event):
                        dst_ok = True
                    checks.append(("dst_ip", dst_ok))
                    break
        return checks

    @staticmethod
    def _ip_matches(actual: Any, expected: Any) -> bool:
        if actual == expected:
            return True
        try:
            actual_ip = ipaddress.ip_address(str(actual))
            expected_ip = ipaddress.ip_address(str(expected))
        except ValueError:
            return str(actual) == str(expected)
        if actual_ip.version == 6 and getattr(actual_ip, "ipv4_mapped", None) is not None:
            actual_ip = actual_ip.ipv4_mapped
        if expected_ip.version == 6 and getattr(expected_ip, "ipv4_mapped", None) is not None:
            expected_ip = expected_ip.ipv4_mapped
        return actual_ip == expected_ip

    @staticmethod
    def _is_process_indicator_trace(fields: dict[str, Any]) -> bool:
        return fields.get("EventID") == 4688 or (
            fields.get("object") == "PROCESS" and fields.get("action") == "CREATE"
        )

    def _is_explicit_proxy_client_trace(self, fields: dict, event: ResolvedEvent) -> bool:
        if getattr(self, "_proxy_mode", "transparent") != "explicit":
            return False
        return fields.get("id.orig_h", fields.get("src_ip")) == event.system_ip and fields.get(
            "id.resp_h", fields.get("dst_ip")
        ) in getattr(self, "_proxy_ips", set())

    def _is_explicit_proxy_egress_trace(self, fields: dict, details: dict[str, Any]) -> bool:
        if getattr(self, "_proxy_mode", "transparent") != "explicit":
            return False
        return fields.get("id.orig_h", fields.get("src_ip")) in getattr(
            self, "_proxy_ips", set()
        ) and fields.get("id.resp_h", fields.get("dst_ip")) == details.get("dst_ip")

    @staticmethod
    def _best_sub_detail(event: ResolvedEvent, fields: dict) -> dict[str, Any]:
        if len(event.sub_details) <= 1:
            return event.sub_details[0] if event.sub_details else event.details
        source_values = {
            str(fields[ip_field])
            for ip_field in ("IpAddress", "id.orig_h", "src_ip")
            if fields.get(ip_field) and fields.get(ip_field) != "-"
        }
        dest_values = {
            str(fields[ip_field])
            for ip_field in ("id.resp_h", "dst_ip")
            if fields.get(ip_field) and fields.get(ip_field) != "-"
        }
        all_values = source_values | dest_values
        if not all_values:
            return event.details
        best_detail = event.details
        best_score = -1
        for sd in event.sub_details:
            score = 0
            if sd.get("source_ip"):
                score += 2 if str(sd["source_ip"]) in source_values else -2
            if sd.get("dst_ip"):
                score += 2 if str(sd["dst_ip"]) in dest_values else -2
            for key in ("source_ip", "dst_ip"):
                value = sd.get(key)
                if value and str(value) in all_values:
                    score += 1
            if score > best_score:
                best_score = score
                best_detail = sd
        return best_detail

    # --- Sub-score 4: Pivot Linkability ---

    def _score_pivot_linkability(
        self,
        resolved: list[ResolvedEvent],
        context: EvaluationContext,
    ) -> SubScore:
        if len(resolved) < 2:
            return SubScore(
                name="Pivot Linkability",
                key="pivot_linkability",
                weight=0.15,
                score=None,
                skipped=True,
                details="Fewer than 2 events — nothing to link",
            )
        expected_visible = [
            event
            for event in resolved
            if event.traces or not self._event_observation_exempt(event, context)
        ]
        excluded = len(resolved) - len(expected_visible)
        expected_by_event = {
            event.index: self._expected_indicator_values(event) for event in expected_visible
        }
        events_by_indicator: dict[str, list[ResolvedEvent]] = defaultdict(list)
        for event in expected_visible:
            for indicator in expected_by_event[event.index]:
                events_by_indicator[indicator].append(event)
        edges: dict[tuple[int, int], set[str]] = defaultdict(set)
        for indicator, events in events_by_indicator.items():
            ordered = sorted(events, key=lambda event: (event.time, event.index))
            for first, second in zip(ordered, ordered[1:], strict=False):
                edges[(first.index, second.index)].add(indicator)

        total_pairs = 0
        linkable = 0
        failures: list[str] = []
        by_index = {event.index: event for event in expected_visible}
        for (first_index, second_index), indicators in sorted(edges.items()):
            a, b = by_index[first_index], by_index[second_index]
            total_pairs += 1
            observed_a = self._observed_indicator_values(a)
            observed_b = self._observed_indicator_values(b)
            pair_linkable = bool(indicators & observed_a & observed_b)
            if pair_linkable:
                linkable += 1
            elif len(failures) < 10:
                failures.append(
                    f"Events {first_index}→{second_index}: expected pivot not present in both "
                    f"rendered traces ({a.actor}@{a.system} → {b.actor}@{b.system})"
                )
        if total_pairs == 0:
            return SubScore(
                name="Pivot Linkability",
                key="pivot_linkability",
                weight=0.15,
                score=None,
                skipped=True,
                details=(
                    f"No expected-visible narrative edges share an expected pivot; "
                    f"{len(expected_visible)} events are isolated, {excluded} contract-exempt"
                ),
            )
        score = 100.0 * linkable / total_pairs
        connected = {index for edge in edges for index in edge}
        isolated = len(expected_visible) - len(connected)
        return SubScore(
            name="Pivot Linkability",
            key="pivot_linkability",
            weight=0.15,
            score=score,
            adjusted=excluded > 0,
            details=(
                f"{linkable}/{total_pairs} inferred expected-visible narrative edges retain a "
                f"shared rendered pivot; {isolated} isolated events, {excluded} contract-exempt"
            ),
            sample_failures=failures,
        )

    def _initialize_pivot_identity(self, scenario: Scenario) -> None:
        """Build scenario-owned identity aliases used only by pivot evaluation."""

        self._pivot_host_aliases: dict[str, str] = {}
        self._pivot_host_ips: dict[str, str] = {}
        self._pivot_ip_hosts: dict[str, str] = {}
        for system in scenario.environment.systems:
            canonical = system.hostname.lower().rstrip(".")
            aliases = {canonical, canonical.split(".", 1)[0]}
            for alias in aliases:
                self._pivot_host_aliases[alias] = canonical
            normalized_ip = self._normalize_pivot_ip(system.ip)
            if normalized_ip:
                self._pivot_host_ips[canonical] = normalized_ip
                self._pivot_ip_hosts[normalized_ip] = canonical

        self._pivot_user_aliases: dict[str, str] = {}
        for user in scenario.environment.users:
            canonical = user.username.lower()
            self._pivot_user_aliases[canonical] = canonical
            if user.email:
                self._pivot_user_aliases[user.email.lower()] = canonical

    def _expected_indicator_values(self, event: ResolvedEvent) -> set[str]:
        values: set[str] = set()
        include_actor, include_system = self._implicit_pivot_owners(event)
        if include_actor:
            self._add_expected_actor(values, event.actor, event.system)
        if include_system:
            self._add_pivot_value(values, "host", event.system)
            self._add_pivot_value(values, "ip", event.system_ip)

        key_namespaces = {
            "source_ip": "ip",
            "dst_ip": "ip",
            "answer_ip": "ip",
            "answer": "ip",
            "requested_ip": "ip",
            "target_ips": "ip",
            "hostname": "host",
            "server": "host",
            "target_system": "host",
            "target_server": "host",
            "query": "domain",
            "base_domain": "domain",
            "url": "url",
            "uri": "url",
            "artifact_id": "artifact",
            "message_ids": "artifact",
            "target_username": "user",
            "target_accounts": "user",
            "success_account": "user",
            "member_name": "user",
            "sender": "user",
            "to": "user",
            "cc": "user",
            "bcc": "user",
            "mailbox": "user",
            "output_file": "file",
            "process_name": "process",
            "target_process": "process",
        }
        for detail in event.sub_details or [event.details]:
            for key, namespace in key_namespaces.items():
                if "email_read" in event.event_types and key == "message_ids":
                    # EmailReadEventSpec documents these IDs for the narrative only.
                    # Opaque TLS/proxy mailbox access cannot prove which message was read.
                    continue
                if key == "server" and "email_read" in event.event_types:
                    server_name = str(detail.get(key) or "").lower()
                    resolved_server = self._email_server_hosts.get(server_name)
                    if resolved_server:
                        self._add_pivot_value(values, namespace, resolved_server)
                    continue
                if key == "mailbox" and not include_actor:
                    continue
                if (
                    key == "answer"
                    and "dns_query" in event.event_types
                    and str(detail.get("rcode") or "").upper() != "NOERROR"
                ):
                    continue
                raw = detail.get(key)
                self._add_pivot_value(values, namespace, raw)

            success = detail.get("success")
            if isinstance(success, dict):
                self._add_pivot_value(values, "user", success.get("account"))

        email_gt = self._email_gt.get(event.storyline_id) or {}
        for key, namespace in (
            ("message_id", "artifact"),
            ("smtp_uids", "artifact"),
            ("uid", "artifact"),
        ):
            raw = email_gt.get(key)
            self._add_pivot_value(values, namespace, raw)
        return values

    def _implicit_pivot_owners(self, event: ResolvedEvent) -> tuple[bool, bool]:
        """Return whether actor and system identity are observable for this event."""

        event_types = set(event.event_types)
        if event_types == {"raw"}:
            return False, False
        if event_types == {"email_message"}:
            sender = str(event.details.get("sender") or "").lower()
            actor_email = self._email_actor_emails.get(event.actor.lower(), "")
            outbound = not sender or bool(actor_email and sender == actor_email)
            return outbound, outbound
        if event_types == {"email_read"}:
            actor_observable = not event.traces or any(
                trace.source_format == "proxy_access" for trace in event.traces
            )
            return actor_observable, True
        if event_types and event_types <= self._NETWORK_ONLY_PIVOT_TYPES:
            return False, True
        return True, True

    def _add_expected_actor(self, values: set[str], actor: str, system: str) -> None:
        normalized = self._normalize_pivot_user(actor)
        if not normalized:
            return
        if normalized in {"root", "system", "local service", "network service"}:
            canonical_host = self._canonical_pivot_host(system)
            values.add(f"user:{normalized}@{canonical_host}")
            return
        values.add(f"user:{normalized}")

    def _observed_indicator_values(self, event: ResolvedEvent) -> set[str]:
        values: set[str] = set()
        for trace in event.traces:
            field_namespaces = {
                "TargetUserName": "user",
                "SubjectUserName": "user",
                "principal": "user",
                "username": "user",
                "mailfrom": "user",
                "sender": "user",
                "mailbox": "user",
                "to": "user",
                "cc": "user",
                "bcc": "user",
                "Computer": "host",
                "hostname": "host",
                "host": "host",
                "server_name": "host",
                "TargetServerName": "host",
                "TargetInfo": "host",
                "IpAddress": "ip",
                "id.orig_h": "ip",
                "id.resp_h": "ip",
                "src_ip": "ip",
                "dst_ip": "ip",
                "client_ip": "ip",
                "client_addr": "ip",
                "assigned_addr": "ip",
                "mapped_src_ip": "ip",
                "mapped_dst_ip": "ip",
                "query": "domain",
                "url": "url",
                "uri": "url",
                "artifact_id": "artifact",
                "message_id": "artifact",
                "msg_id": "artifact",
                "uid": "artifact",
                "sha256": "file",
                "image_path": "process",
                "NewProcessName": "process",
            }
            for field_name, namespace in field_namespaces.items():
                self._add_pivot_value(values, namespace, trace.fields.get(field_name))
            for answer in self._iter_pivot_values(trace.fields.get("answers")):
                namespace = "ip" if self._normalize_pivot_ip(answer) else "domain"
                self._add_pivot_value(values, namespace, answer)
        actor_indicator = self._scoped_actor_indicator(event.actor, event.system)
        normalized_actor = self._normalize_pivot_user(event.actor)
        if any(value in values for value in {f"user:{normalized_actor}", actor_indicator}):
            values.add(actor_indicator)
        return values

    def _add_pivot_value(self, values: set[str], namespace: str, raw: Any) -> None:
        for item in self._iter_pivot_values(raw):
            if item in (None, "", "-"):
                continue
            if namespace == "ip":
                normalized_ip = self._normalize_pivot_ip(item)
                if not normalized_ip:
                    continue
                values.add(f"ip:{normalized_ip}")
                host = self._pivot_ip_hosts.get(normalized_ip)
                if host:
                    values.add(f"host:{host}")
                continue
            if namespace == "host":
                normalized_ip = self._normalize_pivot_ip(item)
                if normalized_ip:
                    self._add_pivot_value(values, "ip", normalized_ip)
                    continue
                host = self._canonical_pivot_host(item)
                if not host:
                    continue
                values.add(f"host:{host}")
                host_ip = self._pivot_host_ips.get(host)
                if host_ip:
                    values.add(f"ip:{host_ip}")
                continue
            if namespace == "user":
                user = self._normalize_pivot_user(item)
                if user:
                    values.add(f"user:{user}")
                continue
            text = str(item).strip().lower()
            if namespace == "domain":
                text = text.rstrip(".")
            if text:
                values.add(f"{namespace}:{text}")

    @staticmethod
    def _iter_pivot_values(raw: Any) -> list[Any]:
        if isinstance(raw, list | tuple | set):
            return list(raw)
        return [raw]

    @staticmethod
    def _normalize_pivot_ip(raw: Any) -> str | None:
        try:
            parsed = ipaddress.ip_address(str(raw).strip().strip("[]"))
        except ValueError:
            return None
        if parsed.version == 6 and getattr(parsed, "ipv4_mapped", None) is not None:
            parsed = parsed.ipv4_mapped
        return parsed.compressed.lower()

    def _canonical_pivot_host(self, raw: Any) -> str:
        host = str(raw or "").strip().lower().rstrip(".")
        if not host:
            return ""
        return self._pivot_host_aliases.get(
            host, self._pivot_host_aliases.get(host.split(".", 1)[0], host)
        )

    def _normalize_pivot_user(self, raw: Any) -> str:
        text = self._normalize_email_address(raw).strip().lower()
        if not text:
            return ""
        direct = self._pivot_user_aliases.get(text)
        if direct:
            return direct
        if "\\" in text:
            text = text.rsplit("\\", 1)[-1]
        direct = self._pivot_user_aliases.get(text)
        if direct:
            return direct
        if "@" in text:
            local = text.split("@", 1)[0]
            return self._pivot_user_aliases.get(local, text)
        return text

    def _scoped_actor_indicator(self, actor: str, system: str) -> str:
        normalized = self._normalize_pivot_user(actor)
        if normalized in {"root", "system", "local service", "network service"}:
            return f"user:{normalized}@{self._canonical_pivot_host(system)}"
        return f"user:{normalized}"

    # --- Sub-score 5: Temporal Integrity ---

    def _score_temporal_integrity(
        self,
        resolved: list[ResolvedEvent],
        context: EvaluationContext,
    ) -> SubScore:
        if not resolved:
            return SubScore(
                name="Temporal Integrity",
                key="temporal_integrity",
                weight=0.15,
                score=None,
                skipped=True,
                details="No storyline events",
            )
        raw_total = len(resolved)
        raw_correct = 0
        total = 0
        correct = 0
        excluded = 0
        failures: list[str] = []
        prev_expected: datetime | None = None

        for event in resolved:
            if not event.traces:
                if self._event_observation_exempt(event, context):
                    excluded += 1
                    prev_expected = event.time
                    continue
                total += 1
                if len(failures) < 10:
                    failures.append(f"Event {event.index}: no traces to verify timing")
                prev_expected = event.time
                continue

            trace_times = []
            for t in event.traces:
                if t.timestamp:
                    ts = t.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    trace_times.append(ts)

            if not trace_times:
                continue

            total += 1
            earliest = min(trace_times)
            # A step can carry both a spillage and an adversarial_payload event anchored
            # at different emitted times; credit the trace if it is near ANY of the
            # event's candidate anchors (the shared event.time plus per-type anchors),
            # not only the last-written event.time.
            anchors = [event.time]
            for _anchor_key in ("_anchor_time_spillage", "_anchor_time_adversarial_payload"):
                _anchor = event.details.get(_anchor_key)
                if _anchor is not None:
                    anchors.append(
                        _anchor.replace(tzinfo=UTC) if _anchor.tzinfo is None else _anchor
                    )
            anchor_delta = min(((earliest - anchor).total_seconds() for anchor in anchors), key=abs)
            time_ok = abs(anchor_delta) <= TIME_TOLERANCE.total_seconds()
            # Storyline events can overlap, and source-specific telemetry can arrive after the
            # action began. Treat a later event as ordered when its evidence does not predate the
            # previous event's intended time, rather than requiring it to follow the previous
            # event's earliest matched trace.
            order_ok = prev_expected is None or earliest >= prev_expected - timedelta(seconds=5)

            if time_ok and order_ok:
                correct += 1
                raw_correct += 1
            elif len(failures) < 10:
                if not time_ok:
                    failures.append(
                        f"Event {event.index}: trace at {anchor_delta:+.0f}s from expected "
                        f"(tolerance ±{TIME_TOLERANCE.total_seconds():.0f}s)"
                    )
                if not order_ok:
                    failures.append(f"Event {event.index}: out of order relative to previous")

            prev_expected = event.time

        score = (100.0 * correct / total) if total > 0 else 100.0
        raw_score = (100.0 * raw_correct / raw_total) if raw_total > 0 else 100.0
        return SubScore(
            name="Temporal Integrity",
            key="temporal_integrity",
            weight=0.15,
            score=score,
            raw_score=raw_score if excluded else None,
            adjusted=excluded > 0,
            details=self._adjusted_details(
                f"{correct}/{total} expected-visible events correctly timed and ordered",
                raw_correct,
                raw_total,
                excluded,
            ),
            sample_failures=failures,
        )

    # --- Sub-score 6: Storyline Trace Coverage ---

    def _score_storyline_trace_coverage(
        self,
        resolved: list[ResolvedEvent],
        vis: VisibilityModel,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
        context: EvaluationContext,
    ) -> SubScore:
        if not resolved:
            return SubScore(
                name="Storyline Trace Coverage",
                key="storyline_trace_coverage",
                weight=0.10,
                score=None,
                skipped=True,
                details="No storyline events",
            )

        raw_total_expected = 0
        raw_found = 0
        total_expected = 0
        found = 0
        excluded = 0
        failures: list[str] = []

        for event in resolved:
            groups = vis.get_expected_format_groups(
                event.system,
                event.event_types,
                event.sub_details,
            )
            evt_time = _normalize_ts(event.time)
            evt_bucket = int(evt_time.timestamp()) // 60

            lookup_keys: list[str] = [event.system.lower()]
            if event.system_ip:
                lookup_keys.append(event.system_ip)
            for sd in event.sub_details:
                for k in ("source_ip", "dst_ip"):
                    val = sd.get(k)
                    if val and val not in lookup_keys:
                        lookup_keys.append(val)

            for group_name, group_formats in groups:
                raw_total_expected += 1
                group_found = False
                for fmt in group_formats:
                    if fmt not in host_time_index.get("__formats__", {fmt: True}):
                        has_format = any(
                            fmt in host_time_index.get(key, {})
                            for lookup_key in lookup_keys
                            for bucket in range(evt_bucket - 2, evt_bucket + 3)
                            for key in [f"{lookup_key}|{bucket}"]
                        )
                        if not has_format:
                            continue
                    for bucket in range(evt_bucket - 2, evt_bucket + 3):
                        for lookup_key in lookup_keys:
                            key = f"{lookup_key}|{bucket}"
                            if key in host_time_index and fmt in host_time_index[key]:
                                group_found = True
                                break
                        if group_found:
                            break
                    if group_found:
                        break

                if group_found:
                    raw_found += 1
                    total_expected += 1
                    found += 1
                elif self._format_group_observation_exempt(event, group_formats, context):
                    excluded += 1
                elif len(failures) < 10:
                    total_expected += 1
                    failures.append(
                        f"Event {event.index}: no trace in {group_name} group "
                        f"for {event.actor}@{event.system}"
                    )
                else:
                    total_expected += 1

        if total_expected == 0 and raw_total_expected == 0:
            return SubScore(
                name="Storyline Trace Coverage",
                key="storyline_trace_coverage",
                weight=0.10,
                score=0.0,
                details=(
                    f"0/0 format traces: {len(resolved)} authored storyline events have no "
                    "enabled expected source group"
                ),
                sample_failures=[
                    "No enabled output source can prove the authored storyline evidence"
                ],
            )
        score = (100.0 * found / total_expected) if total_expected > 0 else 100.0
        raw_score = (100.0 * raw_found / raw_total_expected) if raw_total_expected > 0 else 100.0
        return SubScore(
            name="Storyline Trace Coverage",
            key="storyline_trace_coverage",
            weight=0.10,
            score=score,
            raw_score=raw_score if excluded else None,
            adjusted=excluded > 0,
            details=self._adjusted_details(
                f"{found}/{total_expected} expected-visible format-traces found",
                raw_found,
                raw_total_expected,
                excluded,
            ),
            sample_failures=failures,
        )


# --- Module-level helpers ---


def _build_host_log_profile(
    records: dict[str, list[ParsedRecord]],
    vis: VisibilityModel,
    scenario: Scenario | None = None,
) -> dict[str, dict]:
    present: dict[str, set[str]] = defaultdict(set)
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for format_name, record_list in records.items():
        for rec in record_list:
            hostname = _extract_hostname(rec)
            if hostname:
                h = hostname.lower()
                present[h].add(format_name)
                counts[h][format_name] += 1

    profile: dict[str, dict] = {}
    all_hosts = set(present.keys())
    # vis._os_map contains both bare and FQDN keys for lookup flexibility;
    # resolve each to the canonical bare hostname before deduplicating.
    if hasattr(vis, "_os_map"):
        for key in vis._os_map.keys():
            canonical = vis.resolve_hostname(key)
            if canonical:
                all_hosts.add(canonical.lower())

    shell_hosts = {
        event.system.lower()
        for event in (
            *((scenario.storyline or []) if scenario is not None else []),
            *((scenario.red_herrings or []) if scenario is not None else []),
        )
        if any(spec.type in {"process", "ssh_session"} for spec in event.events)
    }

    for hostname in sorted(all_hosts):
        expected = set(vis.get_expected_formats(hostname))
        if not expected:
            continue
        present_fmts = present.get(hostname, set())
        if "bash_history" not in present_fmts and hostname not in shell_hosts:
            expected.discard("bash_history")
        missing = sorted(expected - present_fmts)
        profile[hostname] = {
            "expected_formats": sorted(expected),
            "present_formats": sorted(present_fmts),
            "missing_formats": missing,
            "volume_by_format": dict(counts.get(hostname, {})),
        }

    return profile
