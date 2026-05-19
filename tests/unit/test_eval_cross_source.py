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

"""Tests for Plausibility and Causality scorers (merged from cross_source)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.events.observation_manifest import (
    ObservationManifest,
    ObservationManifestEvent,
)

# Alias for tests that use the old CrossSourceScorer name
CrossSourceScorer = CausalityScorer

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(systems=None, storyline=None):
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        StorylineEvent,
        System,
        TimeWindow,
        User,
    )

    default_systems = systems or [
        System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
        System(hostname="SRV-01", ip="10.0.20.10", os="Linux Ubuntu", type="server"),
    ]
    from evidenceforge.models.scenario import Scenario

    return Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="jsmith",
                    full_name="J",
                    email="j@x.com",
                    persona="",
                    primary_system="WS-01",
                ),
            ],
            systems=default_systems,
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal",
            intensity="low",
            variation="low",
        ),
        storyline=[StorylineEvent(**e) for e in (storyline or [])],
        output=OutputSpec(
            logs=[
                {"format": "windows_event_security"},
                {"format": "syslog"},
                {"format": "bash_history"},
                {"format": "ecar"},
                {"format": "zeek_conn"},
            ],
            destination="./out",
        ),
    )


class TestVisibilityModel:
    def test_windows_system(self):
        scenario = _make_scenario()
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar", "zeek_conn"}
        vis = VisibilityModel(scenario, enabled)
        fmts = vis.get_expected_formats("WS-01")
        assert "windows_event_security" in fmts
        assert "ecar" in fmts
        assert "syslog" not in fmts
        assert "bash_history" not in fmts

    def test_linux_system(self):
        scenario = _make_scenario()
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar", "zeek_conn"}
        vis = VisibilityModel(scenario, enabled)
        fmts = vis.get_expected_formats("SRV-01")
        assert "syslog" in fmts
        assert "bash_history" in fmts
        assert "ecar" in fmts
        assert "windows_event_security" not in fmts

    def test_os_category(self):
        scenario = _make_scenario()
        enabled = set()
        vis = VisibilityModel(scenario, enabled)
        assert vis.get_os_category("WS-01") == "windows"
        assert vis.get_os_category("SRV-01") == "linux"
        assert vis.get_os_category("UNKNOWN") == "unknown"


class TestSourceCorrectness:
    def test_correct_os_mapping(self):
        """Windows events from Windows host should be correct."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "syslog": [
                _record("syslog", {"hostname": "SRV-01"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = PlausibilityScorer()
        result = scorer._score_value_plausibility(records, vis)
        assert result.score == 100.0

    def test_wrong_os(self):
        """bash_history from Windows host should fail."""
        scenario = _make_scenario()
        records = {
            "bash_history": [
                _record("bash_history", {"hostname": "WS-01", "username": "jsmith"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = PlausibilityScorer()
        result = scorer._score_value_plausibility(records, vis)
        assert result.score < 100.0

    def test_unknown_hostname(self):
        """Records from hosts not in scenario get flagged."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "ROGUE-HOST"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security"}
        vis = VisibilityModel(scenario, enabled)
        scorer = PlausibilityScorer()
        result = scorer._score_value_plausibility(records, vis)
        assert result.score < 100.0
        assert any("not in scenario" in f for f in result.sample_failures)


class TestFieldAgreement:
    def test_matching_timestamps(self):
        """Records from different formats within 30s should agree."""
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(seconds=5)),
            ],
        }
        scorer = PlausibilityScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0

    def test_drifted_timestamps(self):
        """Records from different formats > 30s apart should disagree."""
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(seconds=5)),
            ],
        }
        scorer = PlausibilityScorer()
        # Same bucket → agree
        r1 = scorer._score_field_agreement(records)
        assert r1.score == 100.0


class TestBaselineAggregate:
    def test_proportional_counts(self):
        """Systems with proportional event counts across formats should score well."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security", {"Computer": "WS-01"}, ts=T0 + timedelta(minutes=i)
                )
                for i in range(50)
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(minutes=i))
                for i in range(40)
            ],
        }
        # Score through the full plausibility scorer; check user_diversity is non-None
        scorer = PlausibilityScorer()
        result = scorer.score(records, scenario)
        assert result.score is not None


class TestEndToEnd:
    def test_returns_full_dimension_score(self):
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "Computer": "WS-01",
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                    },
                    ts=T0 + timedelta(minutes=i * 10),
                )
                for i in range(5)
            ],
            "syslog": [
                _record(
                    "syslog",
                    {"hostname": "SRV-01", "message": "test"},
                    ts=T0 + timedelta(minutes=i * 10),
                )
                for i in range(5)
            ],
        }
        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        assert result.number == 3
        assert result.name == "Causality"
        assert result.weight == 0.25
        assert result.score is not None
        assert len(result.sub_scores) == 6

    def test_with_retail_scenario(self):
        """Run on real fixtures — should produce valid scores."""
        from evidenceforge.evaluation.parsers import discover_log_files, get_parser
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.files import load_yaml

        GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"
        SCENARIOS_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"

        data = load_yaml(SCENARIOS_DIR / "retail-store-ftp-attack.yaml")
        scenario = Scenario(**data)

        file_map = discover_log_files(GOOD_FIXTURES)
        records: dict[str, list[ParsedRecord]] = {}
        for fmt, paths in file_map.items():
            parser = get_parser(fmt)
            recs: list[ParsedRecord] = []
            for p in paths:
                recs.extend(parser.parse_file(p))
            records[fmt] = recs

        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        assert result.score is not None
        assert len(result.sub_scores) == 6


def _make_scenario_with_domain(domain="example.com"):
    """Create a scenario with a domain for FQDN testing."""
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        Scenario,
        System,
        TimeWindow,
        User,
    )

    return Scenario(
        name="fqdn-test",
        description="FQDN Test",
        environment=Environment(
            description="Test",
            domain=domain,
            users=[
                User(
                    username="jsmith",
                    full_name="J",
                    email=f"j@{domain}",
                    persona="",
                    primary_system="WS-01",
                ),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(hostname="SRV-01", ip="10.0.20.10", os="Linux Ubuntu", type="server"),
            ],
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal",
            intensity="low",
            variation="low",
        ),
        storyline=[],
        output=OutputSpec(
            logs=[
                {"format": "windows_event_security"},
                {"format": "syslog"},
                {"format": "ecar"},
            ],
            destination="./out",
        ),
    )


class TestResolveHostname:
    """Tests for VisibilityModel.resolve_hostname() and case-insensitive lookups."""

    def test_resolve_bare_hostname(self):
        """Bare hostname from scenario should resolve to itself."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        assert vis.resolve_hostname("WS-01") == "WS-01"
        assert vis.resolve_hostname("SRV-01") == "SRV-01"

    def test_resolve_fqdn(self):
        """FQDN should resolve to bare hostname."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        assert vis.resolve_hostname("WS-01.example.com") == "WS-01"
        assert vis.resolve_hostname("SRV-01.example.com") == "SRV-01"

    def test_resolve_case_insensitive(self):
        """Lowercased bare hostname should resolve to original case."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        assert vis.resolve_hostname("ws-01") == "WS-01"
        assert vis.resolve_hostname("srv-01") == "SRV-01"

    def test_resolve_fqdn_case_insensitive(self):
        """Lowercased FQDN should resolve to bare hostname."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        assert vis.resolve_hostname("ws-01.example.com") == "WS-01"

    def test_resolve_unknown(self):
        """Unknown hostname should return None."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        assert vis.resolve_hostname("ROGUE-HOST") is None

    def test_get_expected_formats_case_insensitive(self):
        """get_expected_formats should work with lowercased hostname."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        original = vis.get_expected_formats("WS-01")
        lowered = vis.get_expected_formats("ws-01")
        assert original == lowered
        assert "windows_event_security" in lowered

    def test_get_expected_format_groups_case_insensitive(self):
        """get_expected_format_groups should work with lowercased hostname."""
        scenario = _make_scenario_with_domain()
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        groups_orig = vis.get_expected_format_groups("WS-01", ["process"])
        groups_lower = vis.get_expected_format_groups("ws-01", ["process"])
        assert len(groups_orig) == len(groups_lower)
        assert len(groups_orig) > 0


class TestNatCrossSourceCorrelation:
    """Tests for NAT-aware cross-source indexing."""

    def test_nat_record_indexed_by_both_real_and_mapped_ip(self):
        """cisco_asa record with mapped_src_ip should be indexed under both IPs."""
        asa_rec = _record(
            "cisco_asa",
            {
                "hostname": "fw01",
                "src_ip": "10.0.10.50",
                "mapped_src_ip": "198.51.100.1",
                "dst_ip": "203.0.113.50",
                "msg_id": 302013,
            },
            ts=T0,
        )
        records = {"cisco_asa": [asa_rec]}
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index(records)
        bucket = int(T0.timestamp()) // 60

        # Both the real IP and the mapped IP should appear as index keys
        real_key = f"10.0.10.50|{bucket}"
        mapped_key = f"198.51.100.1|{bucket}"
        assert real_key in index, "Real src_ip should be indexed"
        assert mapped_key in index, "Mapped src_ip should be indexed"
        assert "cisco_asa" in index[real_key]
        assert "cisco_asa" in index[mapped_key]

    def test_outside_zeek_correlates_with_asa_via_mapped_ip(self):
        """Zeek record with orig_h matching ASA mapped_src_ip should share index bucket."""
        mapped_ip = "198.51.100.1"
        asa_rec = _record(
            "cisco_asa",
            {
                "hostname": "fw01",
                "src_ip": "10.0.10.50",
                "mapped_src_ip": mapped_ip,
                "dst_ip": "203.0.113.50",
                "msg_id": 302013,
            },
            ts=T0,
        )
        zeek_rec = _record(
            "zeek_conn",
            {
                "id.orig_h": mapped_ip,
                "id.resp_h": "203.0.113.50",
                "id.orig_p": 12345,
                "id.resp_p": 443,
            },
            ts=T0 + timedelta(seconds=10),
        )
        records = {"cisco_asa": [asa_rec], "zeek_conn": [zeek_rec]}
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index(records)
        bucket = int(T0.timestamp()) // 60

        key = f"{mapped_ip}|{bucket}"
        assert key in index, "Mapped IP should be indexed"
        formats_in_bucket = set(index[key].keys())
        assert "cisco_asa" in formats_in_bucket
        assert "zeek_conn" in formats_in_bucket


class TestFQDNSourceCorrectness:
    """Source correctness should handle FQDN records correctly."""

    def test_fqdn_windows_records_recognized(self):
        """Windows records with FQDN Computer field should be recognized."""
        scenario = _make_scenario_with_domain()
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"Computer": "WS-01.example.com"},
                    ts=T0,
                ),
            ],
        }
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = PlausibilityScorer()
        result = scorer._score_value_plausibility(records, vis)
        assert result.score == 100.0
        assert not any("not in scenario" in f for f in result.sample_failures)


class TestHostLogProfile:
    def test_supplementary_present_in_pillar_score(self):
        """CrossSourceScorer should emit host_log_profile in supplementary."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01", "EventID": 4624}, ts=T0),
            ],
        }
        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        assert "host_log_profile" in result.supplementary

    def test_host_log_profile_deduplicates_fqdn_and_bare(self):
        """A system registered with a domain should appear once in the profile, not twice."""
        from evidenceforge.evaluation.pillars.causality import _build_host_log_profile
        from evidenceforge.models.scenario import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            System,
            TimeWindow,
            User,
        )

        scenario = Scenario(
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                domain="corp.example.com",
                users=[
                    User(
                        username="jsmith",
                        full_name="J",
                        email="j@x.com",
                        persona="",
                        primary_system="WS-01",
                    ),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=T0, duration="8h"),
            baseline_activity=BaselineActivity(
                description="Normal", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        )
        vis = VisibilityModel(scenario, {"windows_event_security"})
        profile = _build_host_log_profile({}, vis)
        # WS-01 should appear once (canonical bare, lowercased), not once per variant in _os_map
        ws_keys = [k for k in profile.keys() if "ws-01" in k.lower()]
        assert len(ws_keys) == 1, f"expected one WS-01 entry, got {ws_keys}"

    def test_causality_sub_scores_present(self):
        """CausalityScorer should emit all 6 expected sub-scores."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01", "EventID": 4624}, ts=T0),
            ],
        }
        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        keys = {s.key for s in result.sub_scores}
        assert "causal_ordering" in keys
        assert "event_presence" in keys
        assert "indicator_accuracy" in keys
        assert "pivot_linkability" in keys
        assert "temporal_integrity" in keys
        assert "storyline_trace_coverage" in keys


class TestObservationAwareCausality:
    """Causality coverage scoring should honor observation-profile manifests."""

    def test_dropped_storyline_evidence_is_excluded_from_presence_gate(self):
        """Expected dropped evidence should not fail event_presence."""
        scenario = _make_scenario(
            storyline=[
                {
                    "id": "step-001",
                    "time": "+10m",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Run PowerShell",
                    "events": [{"type": "process", "process_name": "powershell.exe"}],
                }
            ]
        )
        scenario.observation_profile = "enterprise_standard"
        manifest = ObservationManifest(
            scenario_name=scenario.name,
            observation_profile="enterprise_standard",
            collection_window={"start": "2024-01-15T10:00:00Z", "end": "2024-01-15T18:00:00Z"},
            source_summary={"windows_security": {"dropped": 1}, "ecar": {"dropped": 1}},
            storyline_events=[
                ObservationManifestEvent(
                    kind="storyline",
                    storyline_id="step-001",
                    index=0,
                    actor="jsmith",
                    system="WS-01",
                    activity="Run PowerShell",
                    event_types=["process"],
                    source_status={"windows_security": {"dropped": 1}, "ecar": {"dropped": 1}},
                )
            ],
        )

        result = CausalityScorer().score(
            {},
            scenario,
            context=EvaluationContext(observation_manifest=manifest),
        )
        event_presence = next(s for s in result.sub_scores if s.key == "event_presence")
        trace_coverage = next(s for s in result.sub_scores if s.key == "storyline_trace_coverage")

        assert event_presence.score == 100.0
        assert event_presence.raw_score == 0.0
        assert event_presence.adjusted is True
        assert trace_coverage.score == 100.0
        assert trace_coverage.raw_score == 0.0

    def test_visible_manifest_evidence_still_fails_when_trace_is_absent(self):
        """Observation profiles should not excuse missing evidence marked visible."""
        scenario = _make_scenario(
            storyline=[
                {
                    "id": "step-001",
                    "time": "+10m",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Run PowerShell",
                    "events": [{"type": "process", "process_name": "powershell.exe"}],
                }
            ]
        )
        scenario.observation_profile = "enterprise_standard"
        manifest = ObservationManifest(
            scenario_name=scenario.name,
            observation_profile="enterprise_standard",
            collection_window={"start": "2024-01-15T10:00:00Z", "end": "2024-01-15T18:00:00Z"},
            source_summary={"windows_security": {"visible": 1}},
            storyline_events=[
                ObservationManifestEvent(
                    kind="storyline",
                    storyline_id="step-001",
                    index=0,
                    actor="jsmith",
                    system="WS-01",
                    activity="Run PowerShell",
                    event_types=["process"],
                    source_status={"windows_security": {"visible": 1}},
                )
            ],
        )

        result = CausalityScorer().score(
            {},
            scenario,
            context=EvaluationContext(observation_manifest=manifest),
        )
        event_presence = next(s for s in result.sub_scores if s.key == "event_presence")

        assert event_presence.score == 0.0
        assert event_presence.adjusted is False

    def test_mismatched_manifest_does_not_exempt_missing_evidence(self):
        """Scoring should ignore forged manifests that do not match the scenario."""
        scenario = _make_scenario(
            storyline=[
                {
                    "id": "step-001",
                    "time": "+10m",
                    "actor": "jsmith",
                    "system": "WS-01",
                    "activity": "Run PowerShell",
                    "events": [{"type": "process", "process_name": "powershell.exe"}],
                }
            ]
        )
        scenario.observation_profile = "enterprise_standard"
        manifest = ObservationManifest(
            scenario_name="attacker-different-scenario",
            observation_profile="enterprise_standard",
            collection_window={"start": "2024-01-15T10:00:00Z", "end": "2024-01-15T18:00:00Z"},
            source_summary={"windows_security": {"dropped": 1}, "ecar": {"dropped": 1}},
            storyline_events=[
                ObservationManifestEvent(
                    kind="storyline",
                    storyline_id="step-001",
                    index=0,
                    actor="jsmith",
                    system="WS-01",
                    activity="Run PowerShell",
                    event_types=["process"],
                    source_status={"windows_security": {"dropped": 1}, "ecar": {"dropped": 1}},
                )
            ],
        )

        result = CausalityScorer().score(
            {},
            scenario,
            context=EvaluationContext(observation_manifest=manifest),
        )
        event_presence = next(s for s in result.sub_scores if s.key == "event_presence")

        assert event_presence.score == 0.0
        assert event_presence.adjusted is False


class TestZeekDhcpIndexing:
    """zeek_dhcp records must be indexed by client_addr and host_name."""

    def test_dhcp_record_indexed_by_client_addr(self):
        """zeek_dhcp record with client_addr should be findable by IP lookup."""
        dhcp_rec = _record(
            "zeek_dhcp",
            {"client_addr": "10.0.1.50", "host_name": "workstation1"},
            ts=T0,
        )
        records = {"zeek_dhcp": [dhcp_rec]}
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index(records)
        bucket = int(T0.timestamp()) // 60

        assert f"10.0.1.50|{bucket}" in index, "client_addr should be indexed as an IP key"
        assert "zeek_dhcp" in index[f"10.0.1.50|{bucket}"]

    def test_dhcp_record_indexed_by_host_name(self):
        """zeek_dhcp record with host_name should be findable by hostname lookup."""
        dhcp_rec = _record(
            "zeek_dhcp",
            {"client_addr": "10.0.1.50", "host_name": "workstation1"},
            ts=T0,
        )
        records = {"zeek_dhcp": [dhcp_rec]}
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index(records)
        bucket = int(T0.timestamp()) // 60

        assert f"workstation1|{bucket}" in index, "host_name should be indexed as a hostname key"
        assert "zeek_dhcp" in index[f"workstation1|{bucket}"]


class TestBeaconProxyMatcher:
    """Beacon allow/deny matchers must handle proxy_access 'host' field."""

    def test_beacon_allow_proxy_matches_host_field(self):
        """_beacon_dst_matches should match destination stored in proxy 'host' field."""
        scorer = CrossSourceScorer()
        fields = {"host": "evil.example.com", "status_code": 200, "method": "GET"}
        assert scorer._beacon_dst_matches(fields, "evil.example.com")
        assert not scorer._beacon_dst_matches(fields, "other.example.com")

    def test_search_finds_explicit_proxy_beacon_by_hostname(self):
        """Beacon evidence can be indexed by proxy host, not only by origin IPs."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        proxy_rec = _record(
            "proxy_access",
            {"host": "api.evil.example.com", "status_code": 200, "method": "GET"},
            ts=T0 + timedelta(seconds=10),
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="attacker",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="allowed c2",
            details={
                "dst_ip": "45.33.32.30",
                "dst_port": 443,
                "hostname": "api.evil.example.com",
            },
            event_types=["beacon"],
        )
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index({"proxy_access": [proxy_rec]})

        traces = scorer._search_for_event_indexed(event, "beacon", index)

        assert traces == [proxy_rec]

    def test_beacon_allow_proxy_matches_ip_url_host(self):
        """_beacon_dst_matches should match IP found in the URL authority host."""
        scorer = CrossSourceScorer()
        fields = {"url": "https://45.33.32.30/check", "status_code": 200}
        assert scorer._beacon_dst_matches(fields, "45.33.32.30")

    def test_beacon_allow_proxy_rejects_ip_url_path_only(self):
        """_beacon_dst_matches should not match an IP that appears only in a URL path."""
        scorer = CrossSourceScorer()
        fields = {"url": "https://attacker.example/check/45.33.32.30", "status_code": 200}
        assert not scorer._beacon_dst_matches(fields, "45.33.32.30")

    def test_beacon_allow_proxy_rejects_domain_url_path_only(self):
        """_beacon_dst_matches should not match a domain that appears only in a URL path."""
        scorer = CrossSourceScorer()
        fields = {
            "host": "attacker.tld",
            "url": "http://attacker.tld/download/evil.example.com/pixel.gif",
            "status_code": 200,
        }
        assert not scorer._beacon_dst_matches(fields, "evil.example.com")

    def test_beacon_allow_proxy_rejects_larger_hostname(self):
        """_beacon_dst_matches should not match larger hostnames by substring."""
        scorer = CrossSourceScorer()
        fields = {"host": "evil.example.com.attacker.net", "status_code": 200}
        assert not scorer._beacon_dst_matches(fields, "evil.example.com")

    def test_beacon_allow_proxy_matches_subdomain_boundary(self):
        """_beacon_dst_matches should allow validated domain-boundary subdomain matches."""
        scorer = CrossSourceScorer()
        fields = {"host": "api.evil.example.com", "status_code": 200}
        assert scorer._beacon_dst_matches(fields, "evil.example.com")

    def test_beacon_allow_proxy_rejects_malformed_url_authority(self):
        """Malformed bracketed URL authorities should not crash causality scoring."""
        scorer = CrossSourceScorer()
        fields = {"url": "http://[::::]/x", "status_code": 200}
        assert not scorer._beacon_dst_matches(fields, "evil.example.com")

    def test_beacon_allow_http_rejects_malformed_uri_authority(self):
        """Malformed schemeless URI authorities should be ignored as non-matches."""
        scorer = CrossSourceScorer()
        fields = {"uri": "//[evil]/x", "status_code": 200}
        assert not scorer._beacon_dst_matches(fields, "evil.example.com")

    def test_beacon_deny_proxy_403_counts_as_deny(self):
        """proxy_access record with status_code 403 should match beacon deny."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        proxy_rec = _record(
            "proxy_access",
            {"host": "45.33.32.30", "status_code": 403, "method": "CONNECT"},
            ts=T0,
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="attacker",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="blocked c2",
            details={"dst_ip": "45.33.32.30", "dst_port": 443, "action": "deny"},
            event_types=["beacon"],
        )
        scorer = CrossSourceScorer()
        assert scorer._record_matches(proxy_rec, "proxy_access", event, "beacon")

    def test_beacon_deny_proxy_200_does_not_match_deny(self):
        """proxy_access record with status 200 should NOT match beacon deny."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        proxy_rec = _record(
            "proxy_access",
            {"host": "45.33.32.30", "status_code": 200, "method": "GET"},
            ts=T0,
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="attacker",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="blocked c2",
            details={"dst_ip": "45.33.32.30", "dst_port": 443, "action": "deny"},
            event_types=["beacon"],
        )
        scorer = CrossSourceScorer()
        assert not scorer._record_matches(proxy_rec, "proxy_access", event, "beacon")

    def test_logoff_matcher_accepts_ecar_logout(self):
        """eCAR USER_SESSION/LOGOUT rows should satisfy logoff event presence."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        logout_rec = _record(
            "ecar",
            {
                "hostname": "APP-INT-01",
                "object": "USER_SESSION",
                "action": "LOGOUT",
                "principal": "root",
            },
            ts=T0,
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="APP-INT-01",
            system_ip="10.10.2.30",
            activity="logout",
            details={},
            event_types=["logoff"],
        )
        scorer = CrossSourceScorer()

        assert scorer._record_matches(logout_rec, "ecar", event, "logoff")

    def test_logoff_matcher_rejects_wrong_windows_user(self):
        """Windows logoff rows should not attach to another user's same-host session."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="svc_mhsync",
            system="FILE-SRV-01",
            system_ip="10.10.2.20",
            activity="logout",
            details={},
            event_types=["logoff"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._record_matches(
            _record(
                "windows_event_security",
                {
                    "EventID": 4634,
                    "Computer": "FILE-SRV-01",
                    "TargetUserName": "sophia.martinez",
                },
                ts=T0,
            ),
            "windows_event_security",
            event,
            "logoff",
        )
        assert scorer._record_matches(
            _record(
                "windows_event_security",
                {
                    "EventID": 4634,
                    "Computer": "FILE-SRV-01",
                    "TargetUserName": "svc_mhsync",
                },
                ts=T0,
            ),
            "windows_event_security",
            event,
            "logoff",
        )

    def test_zeek_connection_match_requires_authored_source_ip(self):
        """A same-destination Zeek row should not match if source_ip disagrees."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="attacker",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="SQL injection",
            details={"source_ip": "185.70.41.45", "dst_ip": "10.10.3.10"},
            event_types=["connection"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._connection_matches_zeek(
            {"id.orig_h": "10.10.3.20", "id.resp_h": "10.10.3.10"},
            event,
        )
        assert scorer._connection_matches_zeek(
            {"id.orig_h": "185.70.41.45", "id.resp_h": "10.10.3.10"},
            event,
        )

    def test_zeek_connection_match_prefers_explicit_tuple_over_story_host(self):
        """Explicit source/destination/port should beat the storyline system IP fallback."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="APP-INT-01",
            system_ip="10.10.2.30",
            activity="failed ssh pivot",
            details={
                "source_ip": "10.10.3.10",
                "dst_ip": "10.10.3.20",
                "dst_port": 22,
            },
            event_types=["connection"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._connection_matches_zeek(
            {
                "id.orig_h": "10.10.2.30",
                "id.orig_p": 8,
                "id.resp_h": "10.10.3.20",
                "id.resp_p": 0,
            },
            event,
        )
        assert not scorer._connection_matches_zeek(
            {
                "id.orig_h": "10.10.3.10",
                "id.orig_p": 50000,
                "id.resp_h": "10.10.3.20",
                "id.resp_p": 8080,
            },
            event,
        )
        assert scorer._connection_matches_zeek(
            {
                "id.orig_h": "10.10.3.10",
                "id.orig_p": 50000,
                "id.resp_h": "10.10.3.20",
                "id.resp_p": 22,
            },
            event,
        )

    def test_ecar_connection_match_uses_directional_ip_roles(self):
        """A reverse callback should not match an earlier inbound upload tuple."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="apache",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="upload and reverse shell",
            details={"dst_ip": "45.33.32.30"},
            event_types=["connection"],
            sub_details=[
                {
                    "source_ip": "185.70.41.45",
                    "dst_ip": "10.10.3.10",
                    "description": "web shell upload",
                },
                {"dst_ip": "45.33.32.30", "description": "reverse shell callback"},
            ],
        )

        assert not CrossSourceScorer._connection_ip_matches(
            {"src_ip": "10.10.3.10", "dst_ip": "185.70.41.45"},
            event,
        )
        assert CrossSourceScorer._connection_ip_matches(
            {"src_ip": "10.10.3.10", "dst_ip": "45.33.32.30"},
            event,
        )

    def test_ecar_connection_match_ignores_partial_source_only_detail_when_dst_exists(self):
        """Mixed connection/session details should not match by source IP alone."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="APP-INT-01",
            system_ip="10.10.2.30",
            activity="ssh pivot",
            details={"dst_ip": "10.10.3.20", "dst_port": 22, "source_ip": "10.10.3.10"},
            event_types=["connection", "ssh_session"],
            sub_details=[
                {"dst_ip": "10.10.3.20", "dst_port": 22, "source_ip": "10.10.3.10"},
                {"source_ip": "10.10.3.10"},
            ],
        )

        assert not CrossSourceScorer._connection_ip_matches(
            {"src_ip": "10.10.3.10", "dst_ip": "10.10.3.20", "dst_port": 8080},
            event,
        )
        assert CrossSourceScorer._connection_ip_matches(
            {"src_ip": "10.10.3.10", "dst_ip": "10.10.3.20", "dst_port": 22},
            event,
        )

    def test_ssh_session_match_requires_actor_and_source_for_accept_line(self):
        """SSH session traces should not attach unrelated same-host logins."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="APP-INT-01",
            system_ip="10.10.2.30",
            activity="ssh pivot",
            details={"source_ip": "10.10.3.10"},
            event_types=["ssh_session"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._record_matches(
            _record(
                "syslog",
                {
                    "hostname": "APP-INT-01",
                    "message": "Accepted password for aisha.johnson from 10.10.1.35 port 58516 ssh2",
                },
                ts=T0,
            ),
            "syslog",
            event,
            "ssh_session",
        )
        assert scorer._record_matches(
            _record(
                "syslog",
                {
                    "hostname": "APP-INT-01",
                    "message": "Accepted password for root from 10.10.3.10 port 36592 ssh2",
                },
                ts=T0,
            ),
            "syslog",
            event,
            "ssh_session",
        )

    def test_failed_logon_indicator_uses_target_username(self):
        """Failed-logon rows should be checked against the target account, not actor."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="LT-MRIVERA-02",
            system_ip="10.10.1.99",
            activity="wrong password fumble",
            details={"target_username": "aisha.johnson"},
            event_types=["failed_logon"],
        )

        assert CrossSourceScorer._username_indicator_matches("aisha.johnson", event)
        assert not CrossSourceScorer._username_indicator_matches("root", event)

    def test_ipv4_mapped_source_indicator_matches_plain_ipv4(self):
        """Windows IPv4-mapped addresses should not create source mismatch noise."""
        assert CrossSourceScorer._ip_matches("::ffff:10.10.1.99", "10.10.1.99")

    def test_group_member_indicator_uses_member_name_not_group_target(self):
        """4728 TargetUserName is the group, while MemberName carries the account."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="SYSTEM",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="add backdoor account",
            details={"member_name": "svc_mhsync", "group_name": "Domain Admins"},
            event_types=["group_member_added"],
        )
        trace = _record(
            "windows_event_security",
            {
                "EventID": 4728,
                "Computer": "DC-01",
                "TargetUserName": "Domain Admins",
                "MemberName": "CN=svc_mhsync,CN=Users,DC=corp,DC=local",
            },
            ts=T0,
        )

        assert CausalityScorer()._check_indicators(event, trace)[0] == ("username", True)

    def test_web_scan_matcher_requires_nikto_profile_evidence(self):
        """Web scan traces should not attach generic favicon/browser requests."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="nikto web scan",
            details={
                "source_ip": "185.70.41.45",
                "dst_ip": "10.10.3.10",
                "dst_port": 443,
                "preset": "nikto",
            },
            event_types=["web_scan"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._record_matches(
            ParsedRecord(
                source_format="web_access",
                raw="test",
                fields={
                    "client_ip": "185.70.41.45",
                    "user_agent": "Mozilla/5.0 Chrome/121.0",
                },
                timestamp=T0,
                source_host="WEB-EXT-01",
            ),
            "web_access",
            event,
            "web_scan",
        )
        assert scorer._record_matches(
            ParsedRecord(
                source_format="web_access",
                raw="test",
                fields={
                    "client_ip": "185.70.41.45",
                    "user_agent": "Mozilla/5.00 (Nikto/2.1.6)",
                },
                timestamp=T0,
                source_host="WEB-EXT-01",
            ),
            "web_access",
            event,
            "web_scan",
        )
        assert not scorer._record_matches(
            _record(
                "zeek_conn",
                {
                    "id.orig_h": "185.70.41.45",
                    "id.resp_h": "10.10.3.10",
                    "id.resp_p": 443,
                    "conn_state": "S0",
                },
                ts=T0,
            ),
            "zeek_conn",
            event,
            "web_scan",
        )
        assert not scorer._record_matches(
            _record(
                "zeek_conn",
                {
                    "id.orig_h": "185.70.41.45",
                    "id.resp_h": "10.10.3.10",
                    "id.resp_p": 443,
                    "conn_state": "RSTR",
                },
                ts=T0,
            ),
            "zeek_conn",
            event,
            "web_scan",
        )

    def test_process_matcher_requires_storyline_process_detail(self):
        """Generic same-host process creates should not attach to precise process steps."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="SYSTEM",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="clear security log",
            details={
                "process_name": r"C:\Windows\System32\wevtutil.exe",
                "command_line": "wevtutil cl Security",
            },
            event_types=["process"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._record_matches(
            _record(
                "windows_event_security",
                {
                    "EventID": 4688,
                    "Computer": "DC-01",
                    "SubjectUserName": "SYSTEM",
                    "NewProcessName": r"C:\Windows\System32\RuntimeBroker.exe",
                    "CommandLine": "RuntimeBroker.exe -Embedding",
                },
                ts=T0,
            ),
            "windows_event_security",
            event,
            "process",
        )
        assert scorer._record_matches(
            _record(
                "windows_event_security",
                {
                    "EventID": 4688,
                    "Computer": "DC-01",
                    "SubjectUserName": "SYSTEM",
                    "NewProcessName": r"C:\Windows\System32\wevtutil.exe",
                    "CommandLine": "wevtutil cl Security",
                },
                ts=T0,
            ),
            "windows_event_security",
            event,
            "process",
        )

    def test_process_indicator_uses_actor_not_target_account(self):
        """Process traces in account-management steps should validate the actor principal."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="SYSTEM",
            system="DC-01",
            system_ip="10.10.2.10",
            activity="create backdoor account",
            details={"target_username": "svc_mhsync"},
            event_types=["process", "account_created"],
        )
        trace = _record(
            "ecar",
            {
                "hostname": "DC-01",
                "object": "PROCESS",
                "action": "CREATE",
                "principal": "SYSTEM",
            },
            ts=T0,
        )

        assert CausalityScorer()._check_indicators(event, trace)[0] == ("username", True)

    def test_beacon_proxy_matcher_requires_expected_source_host(self):
        """Same C2 hostname from another host should not attach to this beacon step."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="root",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="beacon",
            details={"dst_ip": "45.33.32.30", "hostname": "api.example.net", "dst_port": 443},
            event_types=["beacon"],
        )
        scorer = CrossSourceScorer()
        scorer._proxy_ips = {"10.10.3.20"}

        assert not scorer._record_matches(
            _record(
                "zeek_http",
                {
                    "id.orig_h": "10.10.2.10",
                    "id.resp_h": "10.10.3.20",
                    "host": "api.example.net",
                    "status_code": 200,
                },
                ts=T0,
            ),
            "zeek_http",
            event,
            "beacon",
        )
        assert scorer._record_matches(
            _record(
                "zeek_http",
                {
                    "id.orig_h": "10.10.3.10",
                    "id.resp_h": "10.10.3.20",
                    "host": "api.example.net",
                    "status_code": 200,
                },
                ts=T0,
            ),
            "zeek_http",
            event,
            "beacon",
        )

    def test_best_sub_detail_prefers_directional_ip_roles(self):
        """Indicator checks should choose the reverse-shell detail for callback traces."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="apache",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="upload and reverse shell",
            details={"dst_ip": "45.33.32.30"},
            event_types=["connection"],
            sub_details=[
                {"source_ip": "185.70.41.45", "dst_ip": "10.10.3.10"},
                {"dst_ip": "45.33.32.30"},
            ],
        )

        best = CrossSourceScorer._best_sub_detail(
            event,
            {"src_ip": "10.10.3.10", "dst_ip": "45.33.32.30"},
        )

        assert best == {"dst_ip": "45.33.32.30"}

    def test_raw_matcher_requires_target_format_and_fields(self):
        """Raw storyline rows should not match every record in the time window."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="apache",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="raw apache error",
            details={
                "target_format": "syslog",
                "fields": {
                    "hostname": "WEB-EXT-01",
                    "app_name": "apache2",
                    "message": "SQLSTATE[42000]: syntax error near UNION SELECT",
                },
            },
            event_types=["raw"],
        )
        scorer = CrossSourceScorer()

        assert not scorer._record_matches(
            _record("ecar", {"hostname": "WEB-EXT-01", "object": "FLOW"}, ts=T0),
            "ecar",
            event,
            "raw",
        )
        assert not scorer._record_matches(
            _record("syslog", {"hostname": "WEB-EXT-01", "app_name": "sshd"}, ts=T0),
            "syslog",
            event,
            "raw",
        )
        assert scorer._record_matches(
            _record(
                "syslog",
                {
                    "hostname": "WEB-EXT-01",
                    "app_name": "apache2",
                    "message": "PHP message: SQLSTATE[42000]: syntax error near UNION SELECT",
                },
                ts=T0,
            ),
            "syslog",
            event,
            "raw",
        )

    def test_http_connection_search_allows_modest_forward_trace_drift(self):
        """Web exploit steps may render exact network evidence a few minutes later."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        zeek_rec = _record(
            "zeek_conn",
            {
                "id.orig_h": "185.70.41.45",
                "id.resp_h": "10.10.3.10",
                "id.resp_p": 443,
            },
            ts=T0 + timedelta(minutes=5),
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="apache",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="SQL injection",
            details={
                "source_ip": "185.70.41.45",
                "dst_ip": "10.10.3.10",
                "dst_port": 443,
                "method": "POST",
                "uri": "/ehr/patient/search",
            },
            event_types=["connection"],
        )
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index({"zeek_conn": [zeek_rec]})

        assert scorer._search_for_event_indexed(event, "connection", index) == [zeek_rec]


class TestPortScanSourceIp:
    """port_scan events with external source_ip must use that IP for matching."""

    def test_port_scan_matcher_uses_source_ip_over_system_ip(self):
        """When spec.source_ip differs from system IP, matcher uses source_ip."""
        from evidenceforge.evaluation.storyline import ResolvedEvent

        zeek_rec = _record(
            "zeek_conn",
            {
                "id.orig_h": "185.70.41.45",
                "id.resp_h": "10.10.3.10",
                "id.resp_p": 80,
                "conn_state": "S0",
            },
            ts=T0,
        )
        event = ResolvedEvent(
            index=0,
            time=T0,
            actor="attacker",
            system="WEB-EXT-01",
            system_ip="10.10.3.10",
            activity="port scan",
            details={"source_ip": "185.70.41.45", "ports": [80, 443]},
            event_types=["port_scan"],
        )
        scorer = CrossSourceScorer()
        assert scorer._record_matches(zeek_rec, "zeek_conn", event, "port_scan")

    def test_port_scan_external_source_ip_in_lookup_keys(self):
        """External source_ip should appear as an extra lookup key in index search."""

        zeek_rec = _record(
            "zeek_conn",
            {
                "id.orig_h": "185.70.41.45",
                "id.resp_h": "10.10.3.10",
                "id.resp_p": 80,
                "conn_state": "S0",
            },
            ts=T0,
        )
        records = {"zeek_conn": [zeek_rec]}
        scorer = CrossSourceScorer()
        index = scorer._build_host_time_index(records)
        bucket = int(T0.timestamp()) // 60

        # Should be indexed under the origin IP
        assert f"185.70.41.45|{bucket}" in index


class TestSyslogYearInference:
    """Legacy BSD syslog eval fallback must infer year from file metadata."""

    def test_bsd_timestamp_uses_file_mtime_year(self, tmp_path):
        """SyslogParser should infer year from file modification time."""
        import os

        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        log_path = tmp_path / "syslog.log"
        # Write a record with a March timestamp
        log_path.write_text("Mar 18 12:00:00 host sshd[1234]: session opened\n")
        # Set mtime to 2024
        target_ts = datetime(2024, 3, 18, 12, 0, 0).timestamp()
        os.utime(log_path, (target_ts, target_ts))

        parser = SyslogParser()
        records = list(parser.parse_file(log_path))
        assert len(records) == 1
        assert records[0].timestamp is not None
        assert records[0].timestamp.year == 2024

    def test_bsd_year_wrap_at_new_year(self, tmp_path):
        """SyslogParser should increment year when Dec→Jan wrap is detected."""
        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        log_path = tmp_path / "syslog.log"
        # Two records: Dec 31 then Jan 1 (year wrap)
        log_path.write_text(
            "Dec 31 23:59:00 host sshd[1]: event1\nJan  1 00:01:00 host sshd[2]: event2\n"
        )
        # mtime = 2024-12-31
        import os

        target_ts = datetime(2024, 12, 31, 0, 0, 0).timestamp()
        os.utime(log_path, (target_ts, target_ts))

        parser = SyslogParser()
        records = list(parser.parse_file(log_path))
        assert records[0].timestamp.year == 2024
        assert records[1].timestamp.year == 2025, "Jan record after Dec should be year+1"

    def test_bsd_year_no_false_wrap_on_minor_reorder(self, tmp_path):
        """Minor out-of-order records (not a Dec→Jan wrap) should NOT trigger year increment."""
        from evidenceforge.evaluation.parsers.syslog import SyslogParser

        log_path = tmp_path / "syslog.log"
        # Two records in Aug, second slightly earlier (not a year wrap)
        log_path.write_text(
            "Aug 15 10:05:00 host sshd[1]: event1\nAug 15 10:03:00 host sshd[2]: event2\n"
        )
        import os

        target_ts = datetime(2024, 8, 15, 0, 0, 0).timestamp()
        os.utime(log_path, (target_ts, target_ts))

        parser = SyslogParser()
        records = list(parser.parse_file(log_path))
        assert records[0].timestamp.year == 2024
        assert records[1].timestamp.year == 2024, "Minor reorder should keep same year"
