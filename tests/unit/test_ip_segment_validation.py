# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for IP segment validation in baseline generation."""

import ipaddress
import random

import pytest


class TestGenerateExternalClientIp:
    """External client IPs must not land in org CIDRs."""

    def test_excludes_org_public_cidrs(self):
        """Generated external IPs must not fall in scenario public_cidrs."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        obj = MagicMock(spec=EmitterSetupMixin)
        obj._org_cidr_networks = [
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("45.33.32.0/24"),
        ]
        # Bind the method to the mock so 'self' resolves
        method = EmitterSetupMixin._generate_external_client_ip.__get__(obj)

        rng = random.Random(42)
        for _ in range(200):
            ip = method(rng)
            addr = ipaddress.ip_address(ip)
            for net in obj._org_cidr_networks:
                assert addr not in net, f"External IP {ip} landed in org CIDR {net}"

    def test_excludes_rfc1918(self):
        """External IPs must never be RFC 1918."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        obj = MagicMock(spec=EmitterSetupMixin)
        obj._org_cidr_networks = []
        method = EmitterSetupMixin._generate_external_client_ip.__get__(obj)

        rng = random.Random(123)
        for _ in range(200):
            ip = method(rng)
            addr = ipaddress.ip_address(ip)
            assert not addr.is_private, f"External IP {ip} is RFC 1918"

    def test_excludes_org_internal_segments(self):
        """External IPs must not fall in org internal CIDRs."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        obj = MagicMock(spec=EmitterSetupMixin)
        obj._org_cidr_networks = [
            ipaddress.ip_network("10.10.0.0/16"),
            ipaddress.ip_network("172.16.50.0/24"),
        ]
        method = EmitterSetupMixin._generate_external_client_ip.__get__(obj)

        rng = random.Random(99)
        for _ in range(200):
            ip = method(rng)
            addr = ipaddress.ip_address(ip)
            # 10.x and 172.16-31.x are already excluded by RFC 1918 check,
            # but verify the org CIDR check would also catch them
            for net in obj._org_cidr_networks:
                assert addr not in net


class TestValidateIpInSegments:
    """Diagnostic validator catches out-of-segment internal IPs."""

    @pytest.fixture()
    def _make_validator(self):
        """Create a bound _validate_ip_in_segments with configurable segments."""
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.baseline import BaselineMixin

        def _factory(cidrs: list[str]):
            obj = MagicMock()
            segments = [SimpleNamespace(cidr=c) for c in cidrs]
            obj.scenario.environment.network = SimpleNamespace(segments=segments)
            return BaselineMixin._validate_ip_in_segments.__get__(obj)

        return _factory

    def test_warns_on_out_of_segment_ip(self, caplog, _make_validator):
        """Internal IP not in any segment triggers a warning."""
        import logging

        validate = _make_validator(["10.10.10.0/24", "10.10.20.0/24"])
        with caplog.at_level(logging.WARNING, logger="evidenceforge.generation.engine.baseline"):
            validate("10.10.30.1", "test_context")

        assert any("10.10.30.1" in r.message for r in caplog.records)

    def test_no_warning_for_valid_ip(self, caplog, _make_validator):
        """Internal IP in a defined segment triggers no warning."""
        import logging

        validate = _make_validator(["10.10.10.0/24"])
        with caplog.at_level(logging.WARNING, logger="evidenceforge.generation.engine.baseline"):
            validate("10.10.10.5", "test_context")

        assert not any("10.10.10.5" in r.message for r in caplog.records)

    def test_skips_external_ips(self, caplog, _make_validator):
        """Public IPs should not trigger segment validation warnings."""
        import logging

        validate = _make_validator(["10.10.10.0/24"])
        with caplog.at_level(logging.WARNING, logger="evidenceforge.generation.engine.baseline"):
            validate("93.184.216.34", "test_context")

        assert not any("93.184.216.34" in r.message for r in caplog.records)
