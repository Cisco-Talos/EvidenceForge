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

from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.storyline import _match_activity, resolve_storyline
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

# Alias for tests that use the old SignalIntegrityScorer name
SignalIntegrityScorer = CausalityScorer

GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"
SCENARIOS_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


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
        assert result.score == 100.0


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

    def test_single_event_is_perfect(self):
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
        assert pl.score == 100.0


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
        assert len(result.sub_scores) == 6

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
        assert len(result.sub_scores) == 6
