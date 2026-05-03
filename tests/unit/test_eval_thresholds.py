# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the evaluation thresholds loader."""

from evidenceforge.evaluation.thresholds import (
    EvalThresholds,
    PillarThresholds,
    SubScoreThreshold,
    _defaults,
    load_thresholds,
)


class TestSubScoreThreshold:
    def test_defaults(self):
        t = SubScoreThreshold(minimum=70.0, aspirational=90.0)
        assert t.hard_gate is False

    def test_hard_gate(self):
        t = SubScoreThreshold(minimum=95.0, aspirational=99.0, hard_gate=True)
        assert t.hard_gate is True


class TestEvalThresholds:
    def test_sub_score_lookup(self):
        thresh = EvalThresholds(
            overall_minimum=70.0,
            overall_aspirational=85.0,
            pillars={
                "parseability": PillarThresholds(
                    weight=0.30,
                    sub_scores={
                        "spec_conformance": SubScoreThreshold(
                            minimum=95.0, aspirational=99.0, hard_gate=True
                        )
                    },
                )
            },
        )
        t = thresh.sub_score("parseability", "spec_conformance")
        assert t is not None
        assert t.minimum == 95.0
        assert t.aspirational == 99.0

    def test_missing_pillar_returns_none(self):
        thresh = EvalThresholds(overall_minimum=70.0, overall_aspirational=85.0)
        assert thresh.sub_score("nonexistent", "key") is None

    def test_missing_sub_score_returns_none(self):
        thresh = EvalThresholds(
            overall_minimum=70.0,
            overall_aspirational=85.0,
            pillars={"parseability": PillarThresholds(weight=0.30, sub_scores={})},
        )
        assert thresh.sub_score("parseability", "nonexistent") is None

    def test_hard_gates_list(self):
        thresh = EvalThresholds(
            overall_minimum=70.0,
            overall_aspirational=85.0,
            pillars={
                "parseability": PillarThresholds(
                    weight=0.30,
                    sub_scores={
                        "spec_conformance": SubScoreThreshold(
                            minimum=95.0, aspirational=99.0, hard_gate=True
                        ),
                        "format_constraints": SubScoreThreshold(
                            minimum=90.0, aspirational=98.0, hard_gate=False
                        ),
                    },
                )
            },
        )
        gates = thresh.hard_gates()
        assert len(gates) == 1
        pillar, key, t = gates[0]
        assert pillar == "parseability"
        assert key == "spec_conformance"
        assert t.minimum == 95.0


class TestLoadThresholds:
    def test_loads_yaml_file(self):
        """Should load from thresholds.yaml and return a valid EvalThresholds."""
        # Use real YAML — the file exists in the package
        thresh = load_thresholds()
        assert isinstance(thresh, EvalThresholds)
        assert thresh.overall_minimum > 0
        assert thresh.overall_aspirational > thresh.overall_minimum

    def test_all_four_pillars_present(self):
        thresh = load_thresholds()
        assert "parseability" in thresh.pillars
        assert "plausibility" in thresh.pillars
        assert "causality" in thresh.pillars
        assert "timing" in thresh.pillars

    def test_pillar_weights_sum_to_one(self):
        thresh = load_thresholds()
        total = sum(p.weight for p in thresh.pillars.values())
        assert abs(total - 1.0) < 0.001

    def test_hard_gates_include_spec_conformance(self):
        thresh = load_thresholds()
        gates = {key for _, key, _ in thresh.hard_gates()}
        assert "spec_conformance" in gates

    def test_hard_gates_include_causal_ordering(self):
        thresh = load_thresholds()
        gates = {key for _, key, _ in thresh.hard_gates()}
        assert "causal_ordering" in gates

    def test_hard_gates_include_event_presence(self):
        thresh = load_thresholds()
        gates = {key for _, key, _ in thresh.hard_gates()}
        assert "event_presence" in gates

    def test_defaults_fallback(self):
        """_defaults() should return a valid minimal EvalThresholds."""
        thresh = _defaults()
        assert isinstance(thresh, EvalThresholds)
        assert thresh.overall_minimum == 70.0
        assert thresh.overall_aspirational == 85.0
        assert len(thresh.pillars) == 0
