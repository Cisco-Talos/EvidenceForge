"""Tests for Dimension 1: Record-Level Fidelity scoring."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from evidenceforge.evaluation.dimensions.record_fidelity import RecordFidelityScorer
from evidenceforge.evaluation.parsers import ParsedRecord

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
        tier_a = scorer._score_tier_a({"zeek_conn": records})
        # Well-formed Zeek records should all pass
        assert tier_a.score == 100.0

    def test_records_with_parse_errors_score_low(self):
        """Records that failed to parse should reduce Tier A score."""
        records = [
            _make_record("zeek_conn", {}, errors=["JSON parse error"]),
            _make_record("zeek_conn", {}, errors=["JSON parse error"]),
        ]
        scorer = RecordFidelityScorer()
        tier_a = scorer._score_tier_a({"zeek_conn": records})
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
        tier_a = scorer._score_tier_a({"zeek_conn": all_records})
        # 3 good out of 4 total = 75%
        assert tier_a.score == 75.0


class TestTierB:
    def test_valid_zeek_records_pass_rules(self):
        """Valid Zeek SF records with all required fields should pass co-occurrence rules."""
        from evidenceforge.evaluation.parsers.zeek import ZeekConnParser

        parser = ZeekConnParser()
        records = list(parser.parse_file(GOOD_FIXTURES / "zeek_conn.json"))

        scorer = RecordFidelityScorer()
        tier_b = scorer._score_tier_b({"zeek_conn": records})
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
        tier_b = scorer._score_tier_b({"zeek_conn": records})
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
        scorer = RecordFidelityScorer()
        tier_c = scorer._score_tier_c({"zeek_conn": records})
        assert tier_c.score >= 90.0

    def test_skewed_distribution_scores_lower(self):
        """Records with heavily skewed distribution should score lower."""
        # All records are tcp — no diversity
        records = [_make_record("zeek_conn", {"proto": "tcp"})] * 100
        scorer = RecordFidelityScorer()
        tier_c = scorer._score_tier_c({"zeek_conn": records})
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
        assert result.name == "Record-Level Fidelity"
        assert result.weight == 0.15
        assert result.score is not None
        assert len(result.sub_scores) == 3

    def test_empty_records_score_perfect(self):
        """No records means nothing to fail — default to 100."""
        scorer = RecordFidelityScorer()
        scenario = MagicMock()
        result = scorer.score({}, scenario)
        assert result.score == 100.0


class TestJensenShannonDivergence:
    def test_identical_distributions(self):
        scorer = RecordFidelityScorer()
        p = {"a": 0.5, "b": 0.5}
        q = {"a": 0.5, "b": 0.5}
        assert scorer._jensen_shannon_divergence(p, q) == pytest.approx(0.0, abs=1e-10)

    def test_completely_different_distributions(self):
        scorer = RecordFidelityScorer()
        p = {"a": 1.0}
        q = {"b": 1.0}
        jsd = scorer._jensen_shannon_divergence(p, q)
        # JSD should be ln(2) ≈ 0.693
        assert jsd == pytest.approx(0.693, abs=0.01)
