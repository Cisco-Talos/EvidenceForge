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

"""Tests for Causality scoring (merged from signal_integrity)."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.storyline import ResolvedEvent, _match_activity, resolve_storyline
from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

# Alias for tests that use the old SignalIntegrityScorer name
SignalIntegrityScorer = CausalityScorer

GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"
SCENARIOS_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

CAUSALITY_SUB_SCORE_KEYS = [
    "causal_ordering",
    "event_presence",
    "indicator_accuracy",
    "pivot_linkability",
    "temporal_integrity",
    "storyline_trace_coverage",
    "intent_reconciliation",
    "effect_reconciliation",
]


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(
        source_format=fmt,
        raw="test",
        fields=fields,
        timestamp=ts,
    )


def _scenario_with_storyline(storyline_yaml: list[dict]) -> Scenario:
    """Build a minimal Scenario with the given storyline events."""
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        StorylineEvent,
        System,
        TimeWindow,
        User,
    )

    return Scenario(
        name="test-scenario",
        description="Test",
        environment=Environment(
            description="Test env",
            users=[
                User(
                    username="jsmith",
                    full_name="J Smith",
                    email="j@x.com",
                    persona="analyst",
                    primary_system="WS-01",
                ),
                User(
                    username="attacker",
                    full_name="Attacker",
                    email="a@x.com",
                    persona="analyst",
                    primary_system="SRV-01",
                ),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(hostname="SRV-01", ip="10.0.20.10", os="Linux Ubuntu", type="server"),
            ],
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal activity",
            intensity="low",
            variation="low",
        ),
        storyline=[StorylineEvent(**e) for e in storyline_yaml],
        output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
    )


def test_smb_trace_matching_uses_canonical_transport_and_file_identities():
    scorer = CausalityScorer()
    scorer._smb_gt = {
        "smb-read": {
            "transport_uids": ["C-SMB-1"],
            "operations": [
                {
                    "share": "FS-01.finance",
                    "path": r"Reports\FY26\forecast.xlsx",
                    "fuid": "F-SMB-1",
                }
            ],
        }
    }
    event = ResolvedEvent(
        index=0,
        time=T0,
        actor="jsmith",
        system="WS-01",
        system_ip="10.0.0.10",
        activity="Read forecast",
        details={},
        event_types=["smb_activity"],
        storyline_id="smb-read",
    )

    assert scorer._smb_record_matches({"uid": "C-SMB-1"}, "zeek_smb_files", event)
    assert scorer._smb_record_matches({"fuid": "F-SMB-1"}, "zeek_files", event)
    assert scorer._smb_record_matches(
        {
            "EventID": 4663,
            "SubjectUserName": "jsmith",
            "ObjectName": r"D:\Departments\Finance\Reports\FY26\forecast.xlsx",
        },
        "windows_event_security",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "object": "FILE",
            "action": "READ",
            "principal": "jsmith",
            "file_path": r"D:\Departments\Finance\Reports\FY26\forecast.xlsx",
        },
        "ecar",
        event,
    )
    assert not scorer._smb_record_matches({"uid": "C-OTHER"}, "zeek_conn", event)


def test_smb_trace_matching_accepts_samba_syslog_and_posix_endpoint_paths():
    """Samba-native evidence should match the same canonical share/file identity."""

    scorer = CausalityScorer()
    scorer._smb_gt = {
        "samba-read": {
            "transport_uids": ["C-SAMBA-1"],
            "operations": [
                {
                    "share": "SAMBA-01.finance",
                    "path": r"Reports\FY26\linux-plan.xlsx",
                    "fuid": "F-SAMBA-1",
                }
            ],
        }
    }
    event = ResolvedEvent(
        index=0,
        time=T0,
        actor="jsmith",
        system="LNX-CLIENT-01",
        system_ip="10.0.0.10",
        activity="Read Samba workbook",
        details={},
        event_types=["smb_activity"],
        storyline_id="samba-read",
    )

    assert scorer._smb_record_matches(
        {
            "object": "FILE",
            "action": "READ",
            "hostname": "SAMBA-01",
            "principal": "jsmith",
            "file_path": "/srv/samba/data/Departments/Finance/Reports/FY26/linux-plan.xlsx",
        },
        "ecar",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd_audit",
            "message": (
                "smbd_audit: jsmith|10.0.0.10|Finance|read|success|"
                "/srv/samba/data/Departments/Finance/Reports/FY26/linux-plan.xlsx"
            ),
        },
        "syslog",
        event,
    )
    assert not scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd_audit",
            "message": (
                "smbd_audit: other-user|10.0.0.10|Finance|read|success|"
                "/srv/samba/data/Departments/Finance/Reports/FY26/other.xlsx"
            ),
        },
        "syslog",
        event,
    )

    external_event = replace(event, system="SAMBA-01")
    assert scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd_audit",
            "message": (
                "smbd_audit: jsmith|198.51.100.42|Finance|read|success|"
                "/srv/samba/data/Departments/Finance/Reports/FY26/linux-plan.xlsx"
            ),
        },
        "syslog",
        external_event,
    )


def test_smb_trace_matching_accepts_fixed_mapping_principal():
    """Server-native evidence can use fixed SMB credentials distinct from the local actor."""

    scorer = CausalityScorer()
    scorer._smb_gt = {
        "fixed-read": {
            "transport_uids": ["C-FIXED-1"],
            "operations": [
                {
                    "share": "SAMBA-01.finance",
                    "path": r"Reports\fixed.xlsx",
                    "fuid": "F-FIXED-1",
                }
            ],
        }
    }
    scorer._smb_mapping_principals = {"finance-fixed": "svc_smb_reader"}
    event = ResolvedEvent(
        index=0,
        time=T0,
        actor="jsmith",
        system="LNX-CLIENT-01",
        system_ip="10.0.0.10",
        activity="Read through a fixed CIFS credential",
        details={"mapping": "FINANCE-FIXED"},
        event_types=["smb_activity"],
        storyline_id="fixed-read",
    )

    assert scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd_audit",
            "message": (
                "smbd_audit: svc_smb_reader|10.0.0.10|Finance|read|success|"
                "/srv/samba/data/Reports/fixed.xlsx"
            ),
        },
        "syslog",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd",
            "message": "connect to service Finance as user svc_smb_reader (uid=20041)",
        },
        "syslog",
        event,
    )
    assert not scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd",
            "message": "connect to service Finance as user jsmith (uid=20041)",
        },
        "syslog",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd",
            "message": "closed connection to service Finance",
        },
        "syslog",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "object": "FILE",
            "hostname": "SAMBA-01",
            "principal": "svc_smb_reader",
            "file_path": "/srv/samba/data/Reports/fixed.xlsx",
        },
        "ecar",
        event,
    )
    assert not scorer._smb_record_matches(
        {
            "object": "FILE",
            "hostname": "SAMBA-01",
            "principal": "jsmith",
            "file_path": "/srv/samba/data/Reports/fixed.xlsx",
        },
        "ecar",
        event,
    )
    assert not scorer._smb_record_matches(
        {
            "hostname": "SAMBA-01",
            "app_name": "smbd_audit",
            "message": (
                "smbd_audit: jsmith|10.0.0.10|Finance|read|success|"
                "/srv/samba/data/Reports/fixed.xlsx"
            ),
        },
        "syslog",
        event,
    )
    assert scorer._smb_record_matches(
        {
            "object": "FILE",
            "hostname": "LNX-CLIENT-01",
            "principal": "jsmith",
            "file_path": "/mnt/finance/Reports/fixed.xlsx",
        },
        "ecar",
        event,
    )
    assert not scorer._smb_record_matches(
        {
            "object": "FILE",
            "hostname": "LNX-CLIENT-01",
            "principal": "svc_smb_reader",
            "file_path": "/mnt/finance/Reports/fixed.xlsx",
        },
        "ecar",
        event,
    )


class TestProcessParentIntegrity:
    @staticmethod
    def _ecar(action: str, pid: int, at: int, ppid: int | None = None) -> ParsedRecord:
        fields = {"object": "PROCESS", "action": action, "hostname": "WS-01", "pid": pid}
        if ppid is not None:
            fields["ppid"] = ppid
        return _record("ecar", fields, T0 + timedelta(seconds=at))

    def test_detects_parent_terminated_before_child(self) -> None:
        records = {
            "ecar": [
                self._ecar("CREATE", 100, 0, 4),
                self._ecar("TERMINATE", 100, 10),
                self._ecar("CREATE", 200, 20, 100),
            ]
        }

        total, correct, failures = CausalityScorer._score_process_parent_integrity(records)

        assert (total, correct) == (1, 0)
        assert "stale parent PID 100" in failures[0]

    def test_allows_parent_pid_reuse_before_child(self) -> None:
        records = {
            "ecar": [
                self._ecar("CREATE", 100, 0, 4),
                self._ecar("TERMINATE", 100, 10),
                self._ecar("CREATE", 100, 15, 4),
                self._ecar("CREATE", 200, 20, 100),
            ]
        }

        total, correct, failures = CausalityScorer._score_process_parent_integrity(records)

        assert (total, correct) == (1, 1)
        assert not failures

    def test_pre_window_or_observation_gap_is_not_scored(self) -> None:
        records = {"ecar": [self._ecar("CREATE", 200, 20, 100)]}

        assert CausalityScorer._score_process_parent_integrity(records) == (0, 0, [])


class TestStorylineResolution:
    def test_iso_timestamp(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-1",
                    "time": "2024-01-15T12:00:00Z",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                }
            ]
        )
        resolved = resolve_storyline(scenario.storyline, scenario)
        assert len(resolved) == 1
        assert resolved[0].time == datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

    def test_relative_offset(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-2",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                }
            ]
        )
        resolved = resolve_storyline(scenario.storyline, scenario)
        assert resolved[0].time == T0 + timedelta(hours=2)

    def test_relative_seconds(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-3",
                    "time": "+3600",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                }
            ]
        )
        resolved = resolve_storyline(scenario.storyline, scenario)
        assert resolved[0].time == T0 + timedelta(seconds=3600)

    def test_activity_keyword_matching(self):
        assert "logon" in _match_activity("User login to workstation")
        assert "process" in _match_activity("Execute powershell command")
        assert "connection" in _match_activity("Download payload from C2 server")
        assert "process" in _match_activity("Something unknown happens")  # default

    def test_system_ip_resolved(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-4",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Connect to server",
                    "events": [{"type": "connection", "dst_ip": "10.0.20.10", "dst_port": 443}],
                }
            ]
        )
        resolved = resolve_storyline(scenario.storyline, scenario)
        assert resolved[0].system_ip == "10.0.10.50"


class TestEventPresence:
    def test_all_events_found(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-5",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
                {
                    "id": "evt-test-6",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=2),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ep = next(s for s in result.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0

    def test_web_scan_found_from_host_scoped_web_access_log(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-web-scan",
                    "time": "+1h",
                    "actor": "attacker",
                    "system": "SRV-01",
                    "activity": "Directory brute-force scan",
                    "events": [
                        {
                            "type": "web_scan",
                            "dst_ip": "10.0.20.10",
                            "source_ip": "192.0.2.45",
                            "count": 1,
                            "rate": 1,
                            "paths": [{"uri": "/admin"}],
                        }
                    ],
                }
            ]
        )
        records = {
            "web_access": [
                _record(
                    "web_access",
                    {
                        "client_ip": "192.0.2.45",
                        "method": "GET",
                        "path": "/admin",
                        "status_code": 404,
                    },
                    ts=T0 + timedelta(hours=1),
                ).model_copy(update={"source_host": "SRV-01"})
            ],
        }

        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)

        ep = next(s for s in result.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0

    def test_web_scan_found_from_zeek_http_responder_ip(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-web-scan-zeek",
                    "time": "+1h",
                    "actor": "attacker",
                    "system": "SRV-01",
                    "activity": "Directory brute-force scan",
                    "events": [
                        {
                            "type": "web_scan",
                            "dst_ip": "10.0.20.10",
                            "source_ip": "192.0.2.45",
                            "count": 1,
                            "rate": 1,
                            "paths": [{"uri": "/admin"}],
                        }
                    ],
                }
            ]
        )
        records = {
            "zeek_http": [
                _record(
                    "zeek_http",
                    {
                        "id.orig_h": "192.0.2.45",
                        "id.resp_h": "10.0.20.10",
                        "id.resp_p": 80,
                        "method": "GET",
                        "uri": "/admin",
                    },
                    ts=T0 + timedelta(hours=1),
                )
            ],
        }

        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)

        ep = next(s for s in result.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0

    def test_missing_events(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-7",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
                {
                    "id": "evt-test-8",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
            ]
        )
        # Only one matching record — second event has no trace
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ep = next(s for s in result.sub_scores if s.key == "event_presence")
        assert ep.score == 50.0

    def test_no_storyline(self):
        scenario = _scenario_with_storyline([])
        scorer = SignalIntegrityScorer()
        result = scorer.score({}, scenario)
        assert result.score is None
        assert all(sub.skipped for sub in result.sub_scores)


class TestIndicatorAccuracy:
    def test_correct_indicators(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-9",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon", "source_ip": "10.0.10.50"}],
                }
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                        "IpAddress": "10.0.10.50",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ia = next(s for s in result.sub_scores if s.key == "indicator_accuracy")
        assert ia.score == 100.0

    def test_wrong_ip(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-10",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon", "source_ip": "10.0.10.50"}],
                }
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                        "IpAddress": "192.168.1.1",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ia = next(s for s in result.sub_scores if s.key == "indicator_accuracy")
        assert ia.score < 100.0


class TestPivotLinkability:
    def test_same_actor_is_linkable(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-11",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
                {
                    "id": "evt-test-12",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=2),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        pl = next(s for s in result.sub_scores if s.key == "pivot_linkability")
        assert pl.score == 100.0

    def test_single_event_has_no_applicable_pivot_contract(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-13",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        pl = next(s for s in result.sub_scores if s.key == "pivot_linkability")
        assert pl.score is None
        assert pl.skipped

    def test_account_deletion_links_to_deleted_accounts_later_logoff(self):
        """Windows 4726 should preserve the account pivot into later session evidence."""
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-delete-account",
                    "time": "+1h",
                    "actor": "attacker",
                    "system": "WS-01",
                    "activity": "Delete compromised account",
                    "events": [{"type": "account_deleted", "target_username": "jsmith"}],
                },
                {
                    "id": "evt-account-logoff",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Existing session logs off",
                    "events": [{"type": "logoff"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4726,
                        "Computer": "WS-01",
                        "SubjectUserName": "attacker",
                        "TargetUserName": "jsmith",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4634,
                        "Computer": "WS-01",
                        "TargetUserName": "jsmith",
                    },
                    ts=T0 + timedelta(hours=2),
                ),
            ]
        }

        result = SignalIntegrityScorer().score(records, scenario)

        presence = next(score for score in result.sub_scores if score.key == "event_presence")
        pivot = next(score for score in result.sub_scores if score.key == "pivot_linkability")
        assert presence.score == 100.0
        assert pivot.score == 100.0

    def test_ground_truth_noop_is_removed_from_expected_pivot_graph(self):
        """A truthful already-satisfied action should not require phantom evidence."""
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-before-lock",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute first command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
                {
                    "id": "evt-lock-noop",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Lock workstation",
                    "events": [{"type": "workstation_lock"}],
                },
                {
                    "id": "evt-after-lock",
                    "time": "+3h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute second command",
                    "events": [{"type": "process", "process_name": "whoami.exe"}],
                },
            ]
        )
        ground_truth = GroundTruthDocument.model_validate(
            {
                "scenario_name": scenario.name,
                "scenario_description": scenario.description,
                "generated_at": T0 + timedelta(hours=8),
                "observation_profile": scenario.observation_profile,
                "collection_window": {
                    "start": "2024-01-15T10:00:00Z",
                    "end": "2024-01-15T18:00:00Z",
                },
                "events": [
                    {
                        "record_id": "evt-lock-noop#0",
                        "kind": "workstation_lock",
                        "storyline_id": "evt-lock-noop",
                        "time": T0 + timedelta(hours=2),
                        "actor": "jsmith",
                        "system": "WS-01",
                        "activity": "Lock workstation",
                        "ground_truth_section": "storyline",
                        "emitted": False,
                        "skipped_reason": "workstation_already_locked",
                        "attributes": {},
                    }
                ],
            }
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": r"C:\Windows\System32\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": r"C:\Windows\System32\whoami.exe",
                    },
                    ts=T0 + timedelta(hours=3),
                ),
            ]
        }

        result = SignalIntegrityScorer().score(
            records,
            scenario,
            context=EvaluationContext(ground_truth=ground_truth),
        )

        presence = next(score for score in result.sub_scores if score.key == "event_presence")
        pivot = next(score for score in result.sub_scores if score.key == "pivot_linkability")
        assert presence.score == 100.0
        assert presence.adjusted is True
        assert presence.raw_score == 100.0 * 2 / 3
        assert pivot.score == 100.0
        assert pivot.adjusted is True
        assert not pivot.sample_failures

    def test_host_and_inventory_ip_are_one_pivot(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-pivot-host",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
                {
                    "id": "evt-pivot-dns",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Resolve command endpoint",
                    "events": [
                        {
                            "type": "dns_query",
                            "query": "api.example.test",
                            "answer": "192.0.2.10",
                        }
                    ],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01.example.test",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=1),
                )
            ],
            "zeek_dns": [
                _record(
                    "zeek_dns",
                    {
                        "id.orig_h": "10.0.10.50",
                        "id.resp_h": "10.0.20.10",
                        "query": "api.example.test",
                        "answers": ["192.0.2.10"],
                    },
                    ts=T0 + timedelta(hours=2),
                )
            ],
        }

        result = SignalIntegrityScorer().score(records, scenario)

        pivot = next(score for score in result.sub_scores if score.key == "pivot_linkability")
        assert pivot.score == 100.0

    def test_source_native_proxy_and_dhcp_fields_are_normalized(self):
        from evidenceforge.evaluation.storyline import ResolvedEvent

        scenario = _scenario_with_storyline([])
        scorer = SignalIntegrityScorer()
        scorer._initialize_pivot_identity(scenario)
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="jsmith",
            system="WS-01",
            system_ip="10.0.10.50",
            activity="network activity",
            details={},
            event_types=["connection"],
            traces=[
                _record(
                    "proxy_access",
                    {
                        "client_ip": "10.0.10.50",
                        "username": "EXAMPLE\\jsmith",
                    },
                    ts=T0,
                ),
                _record(
                    "zeek_dhcp",
                    {
                        "client_addr": "10.0.10.50",
                        "assigned_addr": "10.0.10.50",
                    },
                    ts=T0,
                ),
            ],
        )

        observed = scorer._observed_indicator_values(event)

        assert "ip:10.0.10.50" in observed
        assert "host:ws-01" in observed
        assert "user:jsmith" in observed

    def test_target_server_and_domain_account_are_normalized(self):
        from evidenceforge.evaluation.storyline import ResolvedEvent

        scenario = _scenario_with_storyline([])
        scorer = SignalIntegrityScorer()
        scorer._initialize_pivot_identity(scenario)
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="jsmith",
            system="WS-01",
            system_ip="10.0.10.50",
            activity="explicit credentials",
            details={},
            event_types=["explicit_credentials"],
            traces=[
                _record(
                    "windows_event_security",
                    {
                        "TargetUserName": "EXAMPLE\\jsmith",
                        "TargetServerName": "SRV-01.example.test",
                    },
                    ts=T0,
                )
            ],
        )

        observed = scorer._observed_indicator_values(event)

        assert "user:jsmith" in observed
        assert "host:srv-01" in observed
        assert "ip:10.0.20.10" in observed
        assert scorer._user_matches("EXAMPLE\\jsmith", "jsmith")
        assert scorer._user_matches("jsmith@example.test", "jsmith")

    def test_unknown_email_domains_remain_distinct_pivots(self):
        scenario = _scenario_with_storyline([])
        scorer = SignalIntegrityScorer()
        scorer._initialize_pivot_identity(scenario)

        first = scorer._normalize_pivot_user("notice@external-one.test")
        second = scorer._normalize_pivot_user("notice@external-two.test")

        assert first == "notice@external-one.test"
        assert second == "notice@external-two.test"
        assert first != second

    def test_opaque_email_read_does_not_claim_message_identity(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-email-delivery",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Receive external email",
                    "events": [
                        {
                            "type": "email_message",
                            "sender": "notice@external.test",
                            "to": ["j@x.com"],
                            "artifact_id": "message-one",
                        }
                    ],
                },
                {
                    "id": "evt-email-read",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Read email over IMAPS",
                    "events": [
                        {
                            "type": "email_read",
                            "protocol": "imaps",
                            "message_ids": ["message-one"],
                        }
                    ],
                },
            ]
        )
        scorer = SignalIntegrityScorer()
        scorer._email_gt = {}
        scorer._email_actor_emails = {"jsmith": "j@x.com"}
        scorer._email_server_hosts = {}
        scorer._initialize_pivot_identity(scenario)
        delivery, mailbox_read = resolve_storyline(scenario.storyline, scenario)
        mailbox_read.traces = [
            _record(
                "zeek_conn",
                {"id.orig_h": "10.0.10.50", "id.resp_h": "10.0.20.10"},
                ts=T0 + timedelta(hours=2),
            )
        ]

        delivery_expected = scorer._expected_indicator_values(delivery)
        read_expected = scorer._expected_indicator_values(mailbox_read)

        assert "artifact:message-one" in delivery_expected
        assert "artifact:message-one" not in read_expected
        assert not delivery_expected & read_expected

    def test_nxdomain_answer_is_not_an_expected_pivot(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-nxdomain",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Resolve missing domain",
                    "events": [
                        {
                            "type": "dns_query",
                            "query": "missing.example.test",
                            "rcode": "NXDOMAIN",
                            "answer": "192.0.2.99",
                        }
                    ],
                }
            ]
        )
        scorer = SignalIntegrityScorer()
        scorer._email_gt = {}
        scorer._email_server_hosts = {}
        scorer._email_actor_emails = {"jsmith": "j@x.com"}
        scorer._initialize_pivot_identity(scenario)
        event = resolve_storyline(scenario.storyline, scenario)[0]

        expected = scorer._expected_indicator_values(event)

        assert "ip:192.0.2.99" not in expected

    def test_duration_event_search_covers_authored_window_up_to_one_hour(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-dga-window",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Run DGA queries",
                    "events": [
                        {
                            "type": "dga_queries",
                            "interval": "30s",
                            "duration": "45m",
                            "tld": ".top",
                        }
                    ],
                }
            ]
        )
        scorer = SignalIntegrityScorer()
        scorer._email_gt = {}
        scorer._email_server_hosts = {}
        scorer._email_actor_emails = {"jsmith": "j@x.com"}
        scorer._initialize_pivot_identity(scenario)
        event = resolve_storyline(scenario.storyline, scenario)[0]
        late_record = _record(
            "zeek_dns",
            {
                "id.orig_h": "10.0.10.50",
                "id.resp_h": "10.0.20.10",
                "query": "late-generated-name.top",
            },
            ts=T0 + timedelta(hours=1, minutes=30),
        )
        records = {"zeek_dns": [late_record]}
        index = scorer._build_host_time_index(records)

        traces = scorer._search_for_event_indexed(event, "dga_queries", index)

        assert traces == [late_record]

    def test_missing_local_lifecycle_trace_still_fails(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-before-lock",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
                {
                    "id": "evt-missing-lock",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Lock workstation",
                    "events": [{"type": "workstation_lock"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=1),
                )
            ]
        }

        result = SignalIntegrityScorer().score(records, scenario)

        pivot = next(score for score in result.sub_scores if score.key == "pivot_linkability")
        assert pivot.score == 0.0
        assert "Events 0→1" in pivot.sample_failures[0]


class TestTemporalIntegrity:
    def test_correct_order(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-14",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
                {
                    "id": "evt-test-15",
                    "time": "+2h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=2),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ti = next(s for s in result.sub_scores if s.key == "temporal_integrity")
        assert ti.score == 100.0

    def test_delayed_previous_trace_does_not_create_false_order_failure(self):
        """Source delay on an earlier step should not make overlapping later evidence fail."""
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-15a",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
                {
                    "id": "evt-test-15b",
                    "time": "+1h1m",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Execute command",
                    "events": [{"type": "process", "process_name": "cmd.exe"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1, seconds=90),
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "Computer": "WS-01",
                        "SubjectUserName": "jsmith",
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    },
                    ts=T0 + timedelta(hours=1, minutes=1, seconds=10),
                ),
            ],
        }

        result = SignalIntegrityScorer().score(records, scenario)

        ti = next(s for s in result.sub_scores if s.key == "temporal_integrity")
        assert ti.score == 100.0

    def test_out_of_tolerance(self):
        """Trace timestamp far from expected time should fail."""
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-16",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
            ]
        )
        # Trace is 10 minutes late (> 120s tolerance)
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1, minutes=10),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ti = next(s for s in result.sub_scores if s.key == "temporal_integrity")
        assert ti.score == 0.0


class TestBashHistoryMatching:
    def test_linux_process_matches_bash(self):
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-17",
                    "time": "+1h",
                    "actor": "attacker",
                    "system": "SRV-01",
                    "activity": "Execute 'whoami' command",
                    "events": [{"type": "process", "process_name": "whoami"}],
                }
            ]
        )
        records = {
            "bash_history": [
                _record(
                    "bash_history",
                    {
                        "hostname": "SRV-01",
                        "username": "attacker",
                        "command": "whoami",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        ep = next(s for s in result.sub_scores if s.key == "event_presence")
        assert ep.score == 100.0


class TestEndToEnd:
    def test_returns_dimension_score(self):
        """Full scorer returns proper DimensionScore structure."""
        scenario = _scenario_with_storyline(
            [
                {
                    "id": "evt-test-18",
                    "time": "+1h",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Login to workstation",
                    "events": [{"type": "logon"}],
                },
            ]
        )
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                        "Computer": "WS-01",
                    },
                    ts=T0 + timedelta(hours=1),
                ),
            ],
        }
        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        assert result.number == 3
        assert result.name == "Causality"
        assert result.weight == 0.25
        assert result.score is not None
        assert [sub_score.key for sub_score in result.sub_scores] == CAUSALITY_SUB_SCORE_KEYS

    def test_with_retail_scenario(self):
        """Run scorer on existing good fixtures with real scenario."""
        data = load_yaml(SCENARIOS_DIR / "retail-store-ftp-attack.yaml")
        scenario = Scenario(**data)

        # Parse good fixtures
        from evidenceforge.evaluation.parsers import discover_log_files, get_parser

        file_map = discover_log_files(GOOD_FIXTURES)
        records: dict[str, list[ParsedRecord]] = {}
        for fmt, paths in file_map.items():
            parser = get_parser(fmt)
            recs: list[ParsedRecord] = []
            for p in paths:
                recs.extend(parser.parse_file(p))
            records[fmt] = recs

        scorer = SignalIntegrityScorer()
        result = scorer.score(records, scenario)
        # Should produce a score (may be low since fixtures don't match storyline)
        assert result.score is not None
        assert [sub_score.key for sub_score in result.sub_scores] == CAUSALITY_SUB_SCORE_KEYS
