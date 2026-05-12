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
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from evidenceforge.evaluation._shared import _condition_matches, _extract_hostname, _normalize_ts
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
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.time import parse_duration

logger = logging.getLogger(__name__)


class CausalityScorer(DimensionScorer):
    number = 3
    name = "Causality"
    weight = 0.25

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        storyline = scenario.storyline or []
        resolved: list[ResolvedEvent] = []

        if storyline:
            resolved = resolve_storyline(storyline, scenario)
            self._proxy_mode = scenario.environment.proxy.mode
            self._proxy_ips = {
                system.ip
                for system in scenario.environment.systems
                if "forward_proxy" in (system.roles or [])
            }
            # Build host-time index and find traces
            host_time_index = self._build_host_time_index(records)
            self._find_traces(resolved, records, host_time_index)
        else:
            self._proxy_mode = "transparent"
            self._proxy_ips = set()
            host_time_index = self._build_host_time_index(records)

        enabled = {log_spec["format"] for log_spec in scenario.output.logs if "format" in log_spec}
        vis = VisibilityModel(scenario, enabled)

        progress("sub_score_start", {"name": "Causal Ordering", "step": 1, "total": 6})
        s1 = self._score_causal_ordering(records, scenario)
        progress("sub_score_done", {"name": "Causal Ordering", "score": s1.score})

        progress("sub_score_start", {"name": "Event Presence", "step": 2, "total": 6})
        s2 = self._score_event_presence(resolved)
        progress("sub_score_done", {"name": "Event Presence", "score": s2.score})

        progress("sub_score_start", {"name": "Indicator Accuracy", "step": 3, "total": 6})
        s3 = self._score_indicator_accuracy(resolved)
        progress("sub_score_done", {"name": "Indicator Accuracy", "score": s3.score})

        progress("sub_score_start", {"name": "Pivot Linkability", "step": 4, "total": 6})
        s4 = self._score_pivot_linkability(resolved)
        progress("sub_score_done", {"name": "Pivot Linkability", "score": s4.score})

        progress("sub_score_start", {"name": "Temporal Integrity", "step": 5, "total": 6})
        s5 = self._score_temporal_integrity(resolved)
        progress("sub_score_done", {"name": "Temporal Integrity", "score": s5.score})

        progress("sub_score_start", {"name": "Storyline Trace Coverage", "step": 6, "total": 6})
        s6 = self._score_storyline_trace_coverage(resolved, vis, host_time_index)
        progress("sub_score_done", {"name": "Storyline Trace Coverage", "score": s6.score})

        sub_scores = [s1, s2, s3, s4, s5, s6]
        dim_score = aggregate_sub_scores(sub_scores)

        host_log_profile = _build_host_log_profile(records, vis)

        return PillarScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
            supplementary={"host_log_profile": host_log_profile},
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
                ):
                    ip_val = rec.fields.get(ip_field)
                    if ip_val and ip_val not in (hostname, ""):
                        index[f"{ip_val}|{bucket}"][format_name].append(rec)
        return dict(index)

    # --- Trace finding ---

    def _find_traces(
        self,
        resolved: list[ResolvedEvent],
        records: dict[str, list[ParsedRecord]],
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> None:
        for event in resolved:
            for event_type in event.event_types:
                traces = self._search_for_event_indexed(event, event_type, host_time_index)
                event.traces.extend(traces)

    def _search_for_event_indexed(
        self,
        event: ResolvedEvent,
        event_type: str,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> list[ParsedRecord]:
        found: list[ParsedRecord] = []
        evt_time = event.time
        if evt_time.tzinfo is None:
            evt_time = evt_time.replace(tzinfo=UTC)
        evt_bucket = int(evt_time.timestamp()) // 60

        forward_extra_secs = 0
        if event_type in _DURATION_EVENT_TYPES:
            interval_str = event.details.get("interval", "")
            if interval_str:
                try:
                    forward_extra_secs = min(
                        int(parse_duration(interval_str).total_seconds()), 3600
                    )
                except Exception:
                    forward_extra_secs = 3600
            else:
                forward_extra_secs = 3600
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
                    and (
                        self._user_matches(f.get("SubjectUserName"), event.actor)
                        or self._user_matches(f.get("TargetUserName"), event.actor)
                    )
                )
            if format_name == "bash_history":
                return self._host_matches(f.get("hostname"), event.system) and self._user_matches(
                    f.get("username"), event.actor
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
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
                return f.get("EventID") == 8 and self._host_matches(f.get("Computer"), event.system)
            if format_name == "ecar":
                return (
                    f.get("object") == "THREAD"
                    and f.get("action") == "REMOTE_CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
                )
        elif event_type == "process_access":
            if format_name == "windows_event_sysmon":
                return f.get("EventID") == 10 and self._host_matches(
                    f.get("Computer"), event.system
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "OPEN"
                    and self._host_matches(f.get("hostname"), event.system)
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
                return self._host_matches(f.get("hostname"), event.system) and (
                    "Accepted" in msg or "session opened" in msg
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and self._host_matches(f.get("hostname"), event.system)
                )
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
            if format_name == "cisco_asa":
                msg_id = f.get("msg_id")
                return (msg_id == 106023 and f.get("src_ip") == scan_src) or msg_id == 733100
            if format_name == "zeek_conn":
                return f.get("id.orig_h") == scan_src and f.get("conn_state") in (
                    "S0",
                    "REJ",
                )
        elif event_type == "beacon":
            expected_dst = event.details.get("dst_ip", "")
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
                    return self._beacon_dst_matches(f, expected_dst)
            else:
                if format_name == "zeek_conn":
                    return (
                        f.get("id.resp_h") == expected_dst and f.get("id.resp_p") == expected_port
                    )
                if format_name in ("proxy_access", "web_access", "zeek_http"):
                    return self._beacon_dst_matches(f, expected_dst)
        elif event_type == "dns_query":
            expected_query = event.details.get("query", "")
            if format_name == "zeek_dns":
                return f.get("query") == expected_query
            if format_name == "zeek_conn":
                return f.get("id.resp_p") == 53 and f.get("id.orig_h") == event.system_ip
        elif event_type == "web_scan":
            expected_dst = event.details.get("dst_ip", "")
            expected_port = event.details.get("dst_port")
            expected_src = event.details.get("source_ip")
            if format_name == "web_access":
                source_ok = not expected_src or f.get("client_ip") == expected_src
                return source_ok and self._host_matches(record.source_host, event.system)
            if format_name == "zeek_http":
                source_ok = not expected_src or f.get("id.orig_h") == expected_src
                return source_ok and f.get("id.resp_h", f.get("dst_ip", "")) == expected_dst
            if format_name == "zeek_conn":
                source_ok = not expected_src or f.get("id.orig_h") == expected_src
                port_ok = expected_port is None or f.get("id.resp_p") == expected_port
                return source_ok and f.get("id.resp_h") == expected_dst and port_ok
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
                return f.get("EventID") in (4634, 4647)
            if format_name == "syslog":
                msg = f.get("message", "")
                return "session closed" in msg or "Disconnected from" in msg
            if format_name == "bash_history":
                return f.get("command", "").startswith("exit") or f.get("command", "").startswith(
                    "logout"
                )
        elif event_type == "raw":
            return True
        return False

    def _connection_matches_zeek(self, fields: dict, event: ResolvedEvent) -> bool:
        orig_h = fields.get("id.orig_h", "")
        resp_h = fields.get("id.resp_h", "")
        details = event.details
        proxy_mode = getattr(self, "_proxy_mode", "transparent")
        proxy_ips = getattr(self, "_proxy_ips", set())

        if event.system_ip and orig_h == event.system_ip:
            if "dst_ip" in details:
                if proxy_mode == "explicit" and resp_h in proxy_ips:
                    return True
                return resp_h == details["dst_ip"]
            return True

        if (
            proxy_mode == "explicit"
            and orig_h in proxy_ips
            and "dst_ip" in details
            and resp_h == details["dst_ip"]
        ):
            return True

        if "dst_ip" in details and resp_h == details["dst_ip"]:
            return True
        if "source_ip" in details and orig_h == details["source_ip"]:
            return True
        return False

    @staticmethod
    def _connection_ip_matches(fields: dict, event: ResolvedEvent) -> bool:
        src_ip = fields.get("src_ip", "")
        dst_ip = fields.get("dst_ip", "")
        detail_sets = event.sub_details if event.sub_details else [event.details]
        ip_details = [d for d in detail_sets if "source_ip" in d or "dst_ip" in d]
        if not ip_details:
            return True
        for details in ip_details:
            src_ok = True
            dst_ok = True
            if "source_ip" in details:
                src_ok = src_ip == details["source_ip"] or dst_ip == details["source_ip"]
            if "dst_ip" in details:
                dst_ok = dst_ip == details["dst_ip"] or src_ip == details["dst_ip"]
            if src_ok and dst_ok:
                return True
        return False

    @staticmethod
    def _user_matches(record_user: Any, expected: str) -> bool:
        if record_user is None:
            return False
        return str(record_user).lower() == expected.lower()

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
                score=100.0,
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

        score = (100.0 * correct_pairs / total_pairs) if total_pairs > 0 else 100.0
        return SubScore(
            name="Causal Ordering",
            key="causal_ordering",
            weight=0.25,
            score=score,
            details=f"{correct_pairs}/{total_pairs} causal pairs correctly ordered",
            sample_failures=failures,
        )

    # --- Sub-score 2: Event Presence ---

    def _score_event_presence(self, resolved: list[ResolvedEvent]) -> SubScore:
        if not resolved:
            return SubScore(
                name="Event Presence",
                key="event_presence",
                weight=0.20,
                score=100.0,
                details="No storyline events",
            )
        total = len(resolved)
        found = sum(1 for e in resolved if e.traces)
        failures = [
            f"Event {e.index}: {e.actor}@{e.system} '{e.activity[:60]}' — no traces"
            for e in resolved
            if not e.traces
        ]
        score = (100.0 * found / total) if total > 0 else 100.0
        return SubScore(
            name="Event Presence",
            key="event_presence",
            weight=0.20,
            score=score,
            details=f"{found}/{total} storyline events have traces in logs",
            sample_failures=failures[:10],
        )

    # --- Sub-score 3: Indicator Accuracy ---

    def _score_indicator_accuracy(self, resolved: list[ResolvedEvent]) -> SubScore:
        if not resolved:
            return SubScore(
                name="Indicator Accuracy",
                key="indicator_accuracy",
                weight=0.15,
                score=100.0,
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
                    elif len(failures) < 10:
                        failures.append(
                            f"Event {event.index}: {indicator_name} mismatch in {trace.source_format}"
                        )

        score = (100.0 * correct_checks / total_checks) if total_checks > 0 else 100.0
        return SubScore(
            name="Indicator Accuracy",
            key="indicator_accuracy",
            weight=0.15,
            score=score,
            details=f"{correct_checks}/{total_checks} indicator checks correct",
            sample_failures=failures,
        )

    def _check_indicators(
        self,
        event: ResolvedEvent,
        trace: ParsedRecord,
    ) -> list[tuple[str, bool]]:
        checks: list[tuple[str, bool]] = []
        f = trace.fields
        details = self._best_sub_detail(event, f) if event.sub_details else event.details

        for uf in ["TargetUserName", "SubjectUserName", "principal", "username"]:
            if uf in f and f[uf]:
                checks.append(("username", self._user_matches(f[uf], event.actor)))
                break
        for hf in ["Computer", "hostname"]:
            if hf in f and f[hf]:
                checks.append(("hostname", self._host_matches(f[hf], event.system)))
                break
        if "source_ip" in details:
            for ipf in ["IpAddress", "id.orig_h", "src_ip"]:
                if ipf in f and f[ipf] and f[ipf] != "-":
                    source_ok = f[ipf] == details["source_ip"]
                    if not source_ok and self._is_explicit_proxy_egress_trace(f, details):
                        source_ok = True
                    checks.append(("source_ip", source_ok))
                    break
        if "dst_ip" in details:
            for df in ["id.resp_h", "dst_ip"]:
                if df in f and f[df]:
                    dst_ok = f[df] == details["dst_ip"]
                    if not dst_ok and self._is_explicit_proxy_client_trace(f, event):
                        dst_ok = True
                    checks.append(("dst_ip", dst_ok))
                    break
        return checks

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
        trace_ips: set[str] = set()
        for ip_field in ("IpAddress", "id.orig_h", "id.resp_h", "src_ip", "dst_ip"):
            val = fields.get(ip_field)
            if val and val != "-":
                trace_ips.add(val)
        if not trace_ips:
            return event.details
        best_detail = event.details
        best_score = -1
        for sd in event.sub_details:
            score = sum(1 for k in ("source_ip", "dst_ip") if sd.get(k) and sd[k] in trace_ips)
            if score > best_score:
                best_score = score
                best_detail = sd
        return best_detail

    # --- Sub-score 4: Pivot Linkability ---

    def _score_pivot_linkability(self, resolved: list[ResolvedEvent]) -> SubScore:
        if len(resolved) < 2:
            return SubScore(
                name="Pivot Linkability",
                key="pivot_linkability",
                weight=0.15,
                score=100.0,
                details="Fewer than 2 events — nothing to link",
            )
        total_pairs = len(resolved) - 1
        linkable = 0
        failures: list[str] = []
        for i in range(total_pairs):
            a, b = resolved[i], resolved[i + 1]
            if self._extract_indicator_values(a) & self._extract_indicator_values(b):
                linkable += 1
            elif len(failures) < 10:
                failures.append(
                    f"Events {i}→{i + 1}: no shared indicator "
                    f"({a.actor}@{a.system} → {b.actor}@{b.system})"
                )
        score = (100.0 * linkable / total_pairs) if total_pairs > 0 else 100.0
        return SubScore(
            name="Pivot Linkability",
            key="pivot_linkability",
            weight=0.15,
            score=score,
            details=f"{linkable}/{total_pairs} consecutive pairs share a pivotable indicator",
            sample_failures=failures,
        )

    def _extract_indicator_values(self, event: ResolvedEvent) -> set[str]:
        values: set[str] = {event.actor.lower(), event.system.lower()}
        if event.system_ip:
            values.add(event.system_ip)
        for key in ("source_ip", "dst_ip"):
            if key in event.details and event.details[key]:
                values.add(str(event.details[key]))
        for trace in event.traces:
            for field_name in (
                "TargetUserName",
                "SubjectUserName",
                "principal",
                "username",
                "Computer",
                "hostname",
                "IpAddress",
                "id.orig_h",
                "id.resp_h",
                "src_ip",
                "dst_ip",
            ):
                val = trace.fields.get(field_name)
                if val and val != "-":
                    values.add(str(val).lower())
        return values

    # --- Sub-score 5: Temporal Integrity ---

    def _score_temporal_integrity(self, resolved: list[ResolvedEvent]) -> SubScore:
        if not resolved:
            return SubScore(
                name="Temporal Integrity",
                key="temporal_integrity",
                weight=0.15,
                score=100.0,
                details="No storyline events",
            )
        total = len(resolved)
        correct = 0
        failures: list[str] = []
        prev_earliest: datetime | None = None

        for event in resolved:
            if not event.traces:
                if len(failures) < 10:
                    failures.append(f"Event {event.index}: no traces to verify timing")
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

            earliest = min(trace_times)
            time_ok = abs((earliest - event.time).total_seconds()) <= TIME_TOLERANCE.total_seconds()
            order_ok = prev_earliest is None or earliest >= prev_earliest - timedelta(seconds=5)

            if time_ok and order_ok:
                correct += 1
            elif len(failures) < 10:
                if not time_ok:
                    delta = (earliest - event.time).total_seconds()
                    failures.append(
                        f"Event {event.index}: trace at {delta:+.0f}s from expected "
                        f"(tolerance ±{TIME_TOLERANCE.total_seconds():.0f}s)"
                    )
                if not order_ok:
                    failures.append(f"Event {event.index}: out of order relative to previous")

            prev_earliest = earliest

        score = (100.0 * correct / total) if total > 0 else 100.0
        return SubScore(
            name="Temporal Integrity",
            key="temporal_integrity",
            weight=0.15,
            score=score,
            details=f"{correct}/{total} events correctly timed and ordered",
            sample_failures=failures,
        )

    # --- Sub-score 6: Storyline Trace Coverage ---

    def _score_storyline_trace_coverage(
        self,
        resolved: list[ResolvedEvent],
        vis: VisibilityModel,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> SubScore:
        if not resolved:
            return SubScore(
                name="Storyline Trace Coverage",
                key="storyline_trace_coverage",
                weight=0.10,
                score=100.0,
                details="No storyline events",
            )

        total_expected = 0
        found = 0
        failures: list[str] = []

        for event in resolved:
            groups = vis.get_expected_format_groups(event.system, event.event_types)
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
                total_expected += 1
                group_found = False
                for fmt in group_formats:
                    if fmt not in host_time_index.get("__formats__", {fmt: True}):
                        # Check if format has any records at all
                        has_format = any(
                            fmt in host_time_index.get(k, {})
                            for lk in lookup_keys
                            for b in range(evt_bucket - 2, evt_bucket + 3)
                            for k in [f"{lk}|{b}"]
                        )
                        if not has_format:
                            continue
                    for b in range(evt_bucket - 2, evt_bucket + 3):
                        for lk in lookup_keys:
                            key = f"{lk}|{b}"
                            if key in host_time_index and fmt in host_time_index[key]:
                                group_found = True
                                break
                        if group_found:
                            break
                    if group_found:
                        break

                if group_found:
                    found += 1
                elif len(failures) < 10:
                    failures.append(
                        f"Event {event.index}: no trace in {group_name} group "
                        f"for {event.actor}@{event.system}"
                    )

        score = (100.0 * found / total_expected) if total_expected > 0 else 100.0
        return SubScore(
            name="Storyline Trace Coverage",
            key="storyline_trace_coverage",
            weight=0.10,
            score=score,
            details=f"{found}/{total_expected} expected format-traces found",
            sample_failures=failures,
        )


# --- Module-level helpers ---


def _build_host_log_profile(
    records: dict[str, list[ParsedRecord]],
    vis: VisibilityModel,
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

    for hostname in sorted(all_hosts):
        expected = vis.get_expected_formats(hostname)
        if not expected:
            continue
        present_fmts = present.get(hostname, set())
        missing = sorted(expected - present_fmts)
        profile[hostname] = {
            "expected_formats": sorted(expected),
            "present_formats": sorted(present_fmts),
            "missing_formats": missing,
            "volume_by_format": dict(counts.get(hostname, {})),
        }

    return profile
