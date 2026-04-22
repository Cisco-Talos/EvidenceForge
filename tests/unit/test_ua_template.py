# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for render_ua() in ua_template.py."""

import random
import re

from evidenceforge.utils.ua_template import render_ua


def _rng(seed: int = 42) -> random.Random:
    return random.Random(seed)


class TestRenderUaPassThrough:
    def test_no_tokens_unchanged(self):
        ua = "gobuster/3.6"
        assert render_ua(ua, _rng()) == ua

    def test_no_at_sign_unchanged(self):
        ua = "sqlmap/1.7.12#stable (https://sqlmap.org)"
        assert render_ua(ua, _rng()) == ua

    def test_unknown_token_passes_through(self):
        ua = "Scanner/1.0 (Token:@UNKNOWN_TOKEN@)"
        result = render_ua(ua, _rng())
        assert "@UNKNOWN_TOKEN@" in result


class TestNiktoTestId:
    def test_token_substituted(self):
        ua = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:@NIKTO_TESTID@)"
        result = render_ua(ua, _rng())
        assert "@NIKTO_TESTID@" not in result
        assert "Test:" in result

    def test_substituted_value_is_6_digits(self):
        ua = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:@NIKTO_TESTID@)"
        result = render_ua(ua, _rng())
        match = re.search(r"Test:(\d+)", result)
        assert match is not None
        assert len(match.group(1)) == 6

    def test_values_vary_across_calls(self):
        ua = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:@NIKTO_TESTID@)"
        rng = _rng()
        results = {render_ua(ua, rng) for _ in range(100)}
        # Very unlikely to produce the same 6-digit ID 100 times in a row
        assert len(results) > 1

    def test_full_nikto_ua_format_preserved(self):
        ua = "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:@NIKTO_TESTID@)"
        result = render_ua(ua, _rng())
        assert result.startswith("Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:")
        assert result.endswith(")")
