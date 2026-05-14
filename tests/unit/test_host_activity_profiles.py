# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for host/persona/role activity profile configuration."""

import base64
import random
from types import SimpleNamespace

import pytest

from evidenceforge.generation.activity.host_activity_profiles import (
    RATE_FAMILIES,
    firewall_deny_hash_values,
    generate_encoded_powershell_command,
    load_host_activity_profiles,
    reset_cache,
    resolve_host_activity_profile,
    scale_count_range,
    scale_interval_range,
)
from evidenceforge.generation.engine.baseline import BaselineMixin


@pytest.fixture(autouse=True)
def _reset_host_activity_profiles_cache():
    reset_cache()
    yield
    reset_cache()


def _system(
    hostname: str,
    system_type: str,
    roles: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(hostname=hostname, type=system_type, roles=roles or [])


def test_host_activity_profiles_cover_core_families():
    data = load_host_activity_profiles()

    assert {"workstation", "server", "domain_controller"} <= set(data["host_types"])
    assert set(data["rate_families"]["bounds"]) <= RATE_FAMILIES
    assert set(data["host_types"]["domain_controller"]["families"]) <= RATE_FAMILIES


def test_resolved_profiles_shape_infrastructure_hosts_differently():
    workstation = resolve_host_activity_profile(
        scenario_name="profile-test",
        system=_system("wkstn01", "workstation"),
    )
    server = resolve_host_activity_profile(
        scenario_name="profile-test",
        system=_system("files01", "server", ["file_server"]),
    )
    dc = resolve_host_activity_profile(
        scenario_name="profile-test",
        system=_system("dc01", "domain_controller", ["domain_controller"]),
    )

    assert dc.multiplier("dc_kerberos") > workstation.multiplier("dc_kerberos")
    assert dc.multiplier("windows_machine_auth") > workstation.multiplier("windows_machine_auth")
    assert server.multiplier("inbound_network") > workstation.multiplier("inbound_network")


def test_count_and_interval_scaling_preserve_sensible_bounds():
    assert scale_count_range(2, 6, 2.0) == (4, 12)
    assert scale_count_range(0, 3, 0.25) == (0, 1)
    assert scale_interval_range(300, 900, 2.0) == (150, 450)
    assert scale_interval_range(300, 900, 0.5) == (600, 1800)


def test_host_activity_profiles_overlay_merges(tmp_path, monkeypatch):
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "host_activity_profiles.yaml").write_text(
        """
role_profiles:
  web_server:
    families:
      firewall_deny: 2.0
firewall_deny:
  metadata_hash_nonzero_probability: 1.0
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    reset_cache()

    data = load_host_activity_profiles()
    assert data["host_types"]["workstation"]
    assert data["role_profiles"]["web_server"]["families"]["firewall_deny"] == 2.0
    assert firewall_deny_hash_values(random.Random(4)) != ("0x0", "0x0")


def test_encoded_powershell_variants_are_data_driven_and_decodable():
    encoded = generate_encoded_powershell_command(
        rng=random.Random(7),
        hostname="wkstn01",
        username="alice",
    )

    decoded = base64.b64decode(encoded).decode("utf-16-le")
    assert "{" not in decoded
    assert any(
        decoded.startswith(prefix)
        for prefix in (
            "Get-Service",
            "Get-EventLog",
            "Test-NetConnection",
            "Get-Process",
            "Get-ChildItem",
            "Get-WmiObject",
            "Get-HotFix",
            "Get-CimInstance",
            "Get-ScheduledTask",
        )
    )


def test_baseline_mixin_resolves_primary_host_activity_profile():
    class Harness(BaselineMixin):
        pass

    workstation = _system("wkstn01", "workstation")
    server = _system("files01", "server", ["file_server"])
    harness = Harness()
    harness.scenario = SimpleNamespace(
        name="baseline-profile-test",
        environment=SimpleNamespace(systems=[workstation, server]),
    )

    user = SimpleNamespace(username="alice", primary_system="wkstn01", persona="developer")

    assert harness._activity_system_for_user(user) is workstation
    assert harness._activity_multiplier(server, "inbound_network") > harness._activity_multiplier(
        workstation,
        "inbound_network",
    )
