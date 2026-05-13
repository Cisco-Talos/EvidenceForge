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

"""Tests for Parseability and distribution scoring (merged from record_fidelity)."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from evidenceforge.evaluation._shared import _jensen_shannon_divergence
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer

# Alias for tests that use the old RecordFidelityScorer name
RecordFidelityScorer = ParseabilityScorer

GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"


def _make_record(format_name: str, fields: dict, errors: list[str] | None = None) -> ParsedRecord:
    return ParsedRecord(
        source_format=format_name,
        raw="test",
        fields=fields,
        parse_errors=errors or [],
    )


class TestTierA:
    def test_good_fixtures_score_high(self):
        """Well-formed fixtures should score well on Tier A."""
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        assert len(records) > 0

        scorer = RecordFidelityScorer()
        tier_a = scorer._score_spec_conformance({"zeek_conn": records})
        # Well-formed Zeek records should all pass
        assert tier_a.score == 100.0

    def test_snort_native_timestamps_pass_spec_validation(self):
        """Snort fast-alert timestamps are source-native, not ISO strings."""
        from evidenceforge.evaluation.parsers.snort import SnortAlertParser

        parser = SnortAlertParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "snort_alert.alert"))

        scorer = RecordFidelityScorer()
        tier_a = scorer._score_spec_conformance({"snort_alert": records})
        assert tier_a.score == 100.0

    def test_records_with_parse_errors_score_low(self):
        """Records that failed to parse should reduce Tier A score."""
        records = [
            _make_record("zeek_conn", {}, errors=["JSON parse error"]),
            _make_record("zeek_conn", {}, errors=["JSON parse error"]),
        ]
        scorer = RecordFidelityScorer()
        tier_a = scorer._score_spec_conformance({"zeek_conn": records})
        assert tier_a.score == 0.0

    def test_mixed_good_and_bad(self):
        """Mix of parseable and unparseable records."""
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        good_records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))
        bad_records = [
            _make_record("zeek_conn", {}, errors=["JSON parse error"]),
        ]
        all_records = good_records + bad_records

        scorer = RecordFidelityScorer()
        tier_a = scorer._score_spec_conformance({"zeek_conn": all_records})
        # 3 good out of 4 total = 75%
        assert tier_a.score == 75.0


class TestTierB:
    def test_valid_zeek_records_pass_rules(self):
        """Valid Zeek SF records with all required fields should pass co-occurrence rules."""
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))

        scorer = RecordFidelityScorer()
        tier_b = scorer._score_format_constraints({"zeek_conn": records})
        assert tier_b.score >= 80.0

    def test_missing_field_fails_rule(self):
        """A record missing a required co-occurrence field should fail."""
        records = [
            _make_record(
                "zeek_conn",
                {
                    "proto": "tcp",
                    "conn_state": "SF",
                    # Missing duration, orig_bytes, resp_bytes
                },
            ),
        ]
        scorer = RecordFidelityScorer()
        tier_b = scorer._score_format_constraints({"zeek_conn": records})
        # Should fail the SF rules requiring duration and byte counts
        assert tier_b.score < 100.0


class TestTierC:
    def test_matching_distribution_scores_high(self):
        """Records matching reference distribution should score well."""
        # Create records matching the zeek proto distribution (80% tcp, 18% udp, 2% icmp)
        records = (
            [_make_record("zeek_conn", {"proto": "tcp"})] * 80
            + [_make_record("zeek_conn", {"proto": "udp"})] * 18
            + [_make_record("zeek_conn", {"proto": "icmp"})] * 2
        )
        scorer = PlausibilityScorer()
        tier_c = scorer._score_distribution_fit({"zeek_conn": records})
        assert tier_c.score >= 90.0

    def test_skewed_distribution_scores_lower(self):
        """Records with heavily skewed distribution should score lower."""
        # All records are tcp — no diversity
        records = [_make_record("zeek_conn", {"proto": "tcp"})] * 100
        scorer = PlausibilityScorer()
        tier_c = scorer._score_distribution_fit({"zeek_conn": records})
        # Should still be positive but lower than the matching distribution
        assert tier_c.score < 90.0


class TestOverallDimension:
    def test_score_returns_dimension_score(self):
        """Full dimension scoring returns a DimensionScore with all sub-scores."""
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = {"zeek_conn": list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))}

        scorer = RecordFidelityScorer()
        scenario = MagicMock()
        result = scorer.score(records, scenario)

        assert result.number == 1
        assert result.name == "Parseability"
        assert result.weight == 0.30
        assert result.score is not None
        assert len(result.sub_scores) == 2

    def test_empty_records_score_perfect(self):
        """No records means nothing to fail — default to 100."""
        scorer = RecordFidelityScorer()
        scenario = MagicMock()
        result = scorer.score({}, scenario)
        assert result.score == 100.0


class TestWindowsVariantMapCoverage:
    """Every entry in WINDOWS_VARIANT_MAP must resolve to a real variant in the format YAML."""

    def test_all_mapped_variants_exist(self):
        from evidenceforge.evaluation.pillars.parseability import WINDOWS_VARIANT_MAP
        from evidenceforge.formats import load_format

        fmt = load_format("windows_event_security")
        variant_names = {v.name for v in (fmt.variants or [])}
        for event_id, variant_name in WINDOWS_VARIANT_MAP.items():
            assert variant_name in variant_names, (
                f"WINDOWS_VARIANT_MAP[{event_id}] = {variant_name!r} "
                "but no such variant exists in windows_event_security.yaml"
            )

    def test_lock_unlock_variants_mapped(self):
        """EventIDs 4800/4801 must be in the variant map so validation sees variant fields."""
        from evidenceforge.evaluation.pillars.parseability import WINDOWS_VARIANT_MAP

        assert WINDOWS_VARIANT_MAP[4800] == "workstation_locked"
        assert WINDOWS_VARIANT_MAP[4801] == "workstation_unlocked"


class TestJensenShannonDivergence:
    def test_identical_distributions(self):
        p = {"a": 0.5, "b": 0.5}
        q = {"a": 0.5, "b": 0.5}
        assert _jensen_shannon_divergence(p, q) == pytest.approx(0.0, abs=1e-10)

    def test_completely_different_distributions(self):
        p = {"a": 1.0}
        q = {"b": 1.0}
        jsd = _jensen_shannon_divergence(p, q)
        # JSD should be ln(2) ≈ 0.693
        assert jsd == pytest.approx(0.693, abs=0.01)
