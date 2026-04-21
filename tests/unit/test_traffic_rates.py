# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for traffic rate configuration loader and resolver."""

import pytest

from evidenceforge.config.traffic_rates import (
    VALID_TRAFFIC_TYPES,
    get_rates_for_intensity,
    load_traffic_rates,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset cached traffic rates between tests."""
    reset_cache()
    yield
    reset_cache()


class TestLoadTrafficRates:
    """Tests for YAML loading."""

    def test_loads_successfully(self):
        data = load_traffic_rates()
        assert isinstance(data, dict)
        assert "low" in data
        assert "medium" in data
        assert "high" in data

    def test_all_intensity_levels_have_all_keys(self):
        data = load_traffic_rates()
        for level in ("low", "medium", "high"):
            for key in VALID_TRAFFIC_TYPES:
                assert key in data[level], f"{level} missing key {key}"

    def test_all_values_are_two_element_lists(self):
        data = load_traffic_rates()
        for level in ("low", "medium", "high"):
            for key, val in data[level].items():
                assert isinstance(val, list), f"{level}.{key} is not a list"
                assert len(val) == 2, f"{level}.{key} has {len(val)} elements"
                assert val[0] > 0, f"{level}.{key}[0] must be > 0"
                assert val[1] >= val[0], f"{level}.{key}: lo > hi"


class TestGetRatesForIntensity:
    """Tests for get_rates_for_intensity."""

    def test_returns_correct_structure(self):
        rates = get_rates_for_intensity("medium")
        assert isinstance(rates, dict)
        for key in VALID_TRAFFIC_TYPES:
            assert key in rates
            assert isinstance(rates[key], list)
            assert len(rates[key]) == 2

    def test_low_matches_legacy_defaults(self):
        """Low intensity should match the previous hardcoded values."""
        rates = get_rates_for_intensity("low")
        assert rates["user_activity"] == [5, 5]
        assert rates["web"] == [10, 30]
        assert rates["kerberos"] == [1, 3]
        assert rates["ldap"] == [2, 5]
        assert rates["persona_connections"] == [3, 10]

    def test_high_has_higher_web_than_low(self):
        low = get_rates_for_intensity("low")
        high = get_rates_for_intensity("high")
        assert high["web"][0] > low["web"][1]

    def test_invalid_intensity_raises(self):
        with pytest.raises(KeyError):
            get_rates_for_intensity("extreme")


class TestResolveTrafficRate:
    """Tests for BaselineMixin._resolve_traffic_rate via a mock scenario."""

    def _make_engine(self, intensity="medium", traffic_rates=None):
        """Create a minimal mock engine with scenario."""
        from unittest.mock import MagicMock

        engine = MagicMock()
        engine.scenario.baseline_activity.intensity = intensity
        engine.scenario.baseline_activity.traffic_rates = traffic_rates

        from evidenceforge.generation.engine.baseline import BaselineMixin

        engine._resolve_traffic_rate = BaselineMixin._resolve_traffic_rate.__get__(engine)
        return engine

    def test_no_override_uses_config_default(self):
        engine = self._make_engine(intensity="low")
        lo, hi = engine._resolve_traffic_rate("web")
        assert (lo, hi) == (10, 30)

    def test_int_override(self):
        engine = self._make_engine(intensity="high", traffic_rates={"web": 500})
        lo, hi = engine._resolve_traffic_rate("web")
        assert (lo, hi) == (500, 500)

    def test_list_override(self):
        engine = self._make_engine(intensity="high", traffic_rates={"web": [5000, 12000]})
        lo, hi = engine._resolve_traffic_rate("web")
        assert (lo, hi) == (5000, 12000)

    def test_preset_string_override(self):
        engine = self._make_engine(intensity="high", traffic_rates={"web": "low"})
        lo, hi = engine._resolve_traffic_rate("web")
        assert (lo, hi) == (10, 30)

    def test_override_only_affects_specified_type(self):
        engine = self._make_engine(intensity="high", traffic_rates={"web": 500})
        lo, hi = engine._resolve_traffic_rate("kerberos")
        # Should get high defaults, not affected by web override
        high_rates = get_rates_for_intensity("high")
        assert (lo, hi) == tuple(high_rates["kerberos"])

    def test_empty_overrides_uses_defaults(self):
        engine = self._make_engine(intensity="medium", traffic_rates={})
        lo, hi = engine._resolve_traffic_rate("web")
        medium_rates = get_rates_for_intensity("medium")
        assert (lo, hi) == tuple(medium_rates["web"])
