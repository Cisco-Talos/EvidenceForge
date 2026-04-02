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

"""TDD tests for NatRule model, NatContext dataclass, and SecurityEvent.nat field.

These tests define the planned API for the NAT feature. All tests will fail
until the implementation is added.
"""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NatContext
from evidenceforge.models.scenario import NatRule

T0 = datetime(2024, 6, 15, 14, 0, 0, tzinfo=UTC)


class TestNatRuleModel:
    """Tests for the NatRule pydantic model."""

    def test_nat_rule_dynamic_pat_defaults(self):
        """Dynamic PAT rule should create successfully with minimal fields."""
        rule = NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1")
        assert rule.type == "dynamic_pat"
        assert rule.mapped_ip == "198.51.100.1"

    def test_nat_rule_static_requires_real_ip(self):
        """Static NAT rule works without real_ip but defaults to empty string."""
        rule = NatRule(type="static", src="dmz", mapped_ip="203.0.113.5")
        assert rule.real_ip == ""

        rule_with_real = NatRule(
            type="static", src="dmz", mapped_ip="203.0.113.5", real_ip="172.16.0.5"
        )
        assert rule_with_real.real_ip == "172.16.0.5"

    def test_nat_rule_invalid_type_rejected(self):
        """NatRule with an invalid type should raise ValidationError."""
        with pytest.raises(ValidationError):
            NatRule(type="invalid", src="workstations", mapped_ip="198.51.100.1")

    def test_nat_rule_src_string_normalized_to_list(self):
        """A single string src should be normalized to a one-element list."""
        rule = NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1")
        assert rule.src == ["workstations"]

    def test_nat_rule_src_list_accepted(self):
        """A list of segment names should be accepted as-is."""
        rule = NatRule(
            type="dynamic_pat", src=["workstations", "servers"], mapped_ip="198.51.100.1"
        )
        assert rule.src == ["workstations", "servers"]


class TestNatContext:
    """Tests for the NatContext dataclass."""

    def test_nat_context_fields(self):
        """NatContext should store all NAT translation fields."""
        ctx = NatContext(
            nat_type="dynamic_pat",
            mapped_src_ip="198.51.100.1",
            mapped_src_port=12345,
            mapped_dst_ip="203.0.113.50",
            mapped_dst_port=443,
        )
        assert ctx.nat_type == "dynamic_pat"
        assert ctx.mapped_src_ip == "198.51.100.1"
        assert ctx.mapped_src_port == 12345
        assert ctx.mapped_dst_ip == "203.0.113.50"
        assert ctx.mapped_dst_port == 443


class TestSecurityEventNatField:
    """Tests for the nat field on SecurityEvent."""

    def test_security_event_nat_field_default_none(self):
        """SecurityEvent.nat should default to None."""
        event = SecurityEvent(timestamp=T0, event_type="connection")
        assert event.nat is None
