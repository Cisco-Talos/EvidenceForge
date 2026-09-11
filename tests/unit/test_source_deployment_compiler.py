# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the canonical source catalog and scenario deployment compiler."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from evidenceforge.events.collection_policy import (
    CollectionCapability,
    SourceCollectionOverride,
)
from evidenceforge.events.source_catalog import (
    DEFAULT_SOURCE_CATALOG,
    SourceCatalog,
    SourceCatalogError,
    SourceFormatDescriptor,
    SourceOwnerKind,
)
from evidenceforge.generation.source_deployment_compiler import (
    SourceDeploymentCompilationError,
    compile_scenario_source_deployment,
    exact_source_instance_id,
)
from evidenceforge.models.scenario import Scenario

_COMPLETE_PROFILE: dict[str, object] = {
    "default": {"missingness": 0.0},
    "sources": {},
}


def _scenario(
    *,
    systems: list[dict[str, object]] | None = None,
    sensors: list[dict[str, object]] | None = None,
    logs: list[str] | None = None,
    observation_profile: str = "complete",
    observation_overrides: list[dict[str, object]] | None = None,
) -> Scenario:
    if systems is None:
        systems = [
            {
                "hostname": "WIN-01",
                "ip": "10.0.0.10",
                "os": "Windows 11",
                "type": "workstation",
                "roles": ["forward_proxy"],
            },
            {
                "hostname": "LINUX-01",
                "ip": "10.0.0.20",
                "os": "Ubuntu 24.04",
                "type": "server",
                "roles": ["web_server"],
            },
        ]
    if sensors is None:
        sensors = [
            {
                "type": "network",
                "name": "TAP-01",
                "hostname": "sensor-a.example.test",
                "monitoring_segments": ["lan"],
                "log_formats": ["zeek"],
            },
            {
                "type": "ids",
                "name": "IDS-01",
                "monitoring_segments": ["lan"],
                "log_formats": ["snort_alert"],
            },
            {
                "type": "firewall",
                "name": "FW-01",
                "monitoring_segments": ["lan"],
                "log_formats": ["cisco_asa"],
            },
        ]
    logs = logs or [
        "windows",
        "ecar",
        "syslog",
        "bash_history",
        "web_access",
        "proxy_access",
        "zeek",
        "snort_alert",
        "cisco_asa",
    ]
    return Scenario.model_validate(
        {
            "version": "2.0",
            "name": "source-deployment-test",
            "description": "Source deployment compiler test",
            "environment": {
                "description": "Small mixed fleet",
                "users": [
                    {
                        "username": "analyst",
                        "full_name": "Case Analyst",
                        "email": "analyst@example.test",
                    }
                ],
                "systems": systems,
                "network": {
                    "segments": [
                        {
                            "name": "lan",
                            "cidr": "10.0.0.0/24",
                            "exposure": "internal",
                        }
                    ],
                    "sensors": sensors,
                },
                "observation_overrides": observation_overrides or [],
            },
            "time_window": {"start": "2026-08-16T12:00:00Z", "duration": "8h"},
            "baseline_activity": {
                "description": "Low-volume baseline",
                "intensity": "low",
                "variation": "low",
            },
            "observation_profile": observation_profile,
            "output": {
                "logs": [{"format": format_name} for format_name in logs],
                "destination": "./output",
            },
        }
    )


def _descriptor(name: str, family: str = "test") -> SourceFormatDescriptor:
    return SourceFormatDescriptor(
        name=name,
        family=family,
        owner=SourceOwnerKind.HOST,
        capabilities=CollectionCapability.PROCESS,
        platforms=frozenset({"linux"}),
    )


def test_default_catalog_is_complete_and_expands_existing_groups() -> None:
    from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes

    expected_formats = {
        "windows_event_security",
        "windows_event_sysmon",
        "ecar",
        "syslog",
        "bash_history",
        "proxy_access",
        "web_access",
        "zeek_conn",
        "zeek_dns",
        "zeek_http",
        "zeek_smtp",
        "zeek_ssl",
        "zeek_files",
        "zeek_smb_files",
        "zeek_smb_mapping",
        "zeek_x509",
        "zeek_dhcp",
        "zeek_ntp",
        "zeek_weird",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_packet_filter",
        "zeek_reporter",
        "snort_alert",
        "cisco_asa",
    }

    assert set(DEFAULT_SOURCE_CATALOG.format_names) == expected_formats
    assert set(_build_emitter_classes()) == expected_formats
    assert DEFAULT_SOURCE_CATALOG.expand(["windows"]) == (
        "windows_event_security",
        "windows_event_sysmon",
    )
    assert set(DEFAULT_SOURCE_CATALOG.expand(["zeek"])) == {
        name for name in expected_formats if name.startswith("zeek_")
    }


def test_ecar_catalog_supports_independent_endpoint_projection_roles() -> None:
    descriptor = DEFAULT_SOURCE_CATALOG.descriptor("ecar")

    assert descriptor.capabilities.covers(CollectionCapability.SOURCE_ENDPOINT)
    assert descriptor.capabilities.covers(CollectionCapability.DESTINATION_ENDPOINT)


def test_catalog_aliases_groups_and_digest_are_order_independent() -> None:
    alpha = _descriptor("alpha")
    beta = _descriptor("beta")
    first = SourceCatalog(
        descriptors=(beta, alpha),
        groups={"all": ("beta", "alpha")},
        aliases={"everything": "all"},
    )
    second = SourceCatalog(
        descriptors=(alpha, beta),
        groups={"all": ("alpha", "beta")},
        aliases={"everything": "all"},
    )

    assert first.expand(["everything"]) == ("alpha", "beta")
    assert first.digest == second.digest


@pytest.mark.parametrize(
    ("groups", "aliases", "message"),
    [
        ({"alpha": ("alpha",)}, {}, "ambiguous"),
        ({"one": ("two",), "two": ("one",)}, {}, "cyclic"),
        ({"all": ("missing",)}, {}, "unknown"),
        ({}, {"alias": "missing"}, "unknown"),
    ],
)
def test_catalog_rejects_ambiguous_or_invalid_expansions(
    groups: dict[str, tuple[str, ...]],
    aliases: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(SourceCatalogError, match=message):
        SourceCatalog(descriptors=(_descriptor("alpha"),), groups=groups, aliases=aliases)


def test_catalog_enforces_platform_role_and_sensor_type_applicability() -> None:
    proxy = DEFAULT_SOURCE_CATALOG.descriptor("proxy_access")
    zeek = DEFAULT_SOURCE_CATALOG.descriptor("zeek_conn")

    assert proxy.applies_to_host("linux", ["forward_proxy"])
    assert not proxy.applies_to_host("windows", ["workstation"])
    assert zeek.applies_to_sensor("network")
    assert not zeek.applies_to_sensor("ids")


def test_compiler_creates_exact_host_and_sensor_sources() -> None:
    result = compile_scenario_source_deployment(
        _scenario(),
        named_profile=_COMPLETE_PROFILE,
    )

    assert result.source_instances == (
        "asa:fw-01",
        "bash_history:linux-01",
        "ecar:linux-01",
        "ecar:win-01",
        "ids:ids-01",
        "proxy:win-01",
        "syslog:linux-01",
        "sysmon:win-01",
        "web:linux-01",
        "windows_security:win-01",
        "zeek:tap-01",
    )
    zeek = result.deployment.source_by_instance("ZEEK:TAP-01")
    assert zeek is not None
    assert zeek.identity.hostname == "sensor-a.example.test"
    assert zeek.policy.capabilities.covers(
        CollectionCapability.NETWORK
        | CollectionCapability.DNS_ANALYZER
        | CollectionCapability.TLS_ANALYZER
        | CollectionCapability.HTTP_ANALYZER
        | CollectionCapability.FILE_ANALYZER
        | CollectionCapability.SMB_ANALYZER
    )
    assert (
        result.deployment.source_for("WIN-01", "windows_security", "windows_security:win-01")
        is not None
    )


def test_actual_emitter_formats_intersect_sensor_catalog_exactly() -> None:
    result = compile_scenario_source_deployment(
        _scenario(),
        emitter_formats=("zeek_conn", "windows_event_security"),
        named_profile=_COMPLETE_PROFILE,
    )

    assert result.source_instances == ("windows_security:win-01", "zeek:tap-01")
    zeek = result.deployment.source_by_instance("zeek:tap-01")
    assert zeek is not None
    assert zeek.formats == ("zeek_conn",)
    assert zeek.policy.capabilities == (
        CollectionCapability.NETWORK
        | CollectionCapability.SOURCE_ENDPOINT
        | CollectionCapability.DESTINATION_ENDPOINT
    )


def test_four_policy_layers_apply_in_documented_precedence() -> None:
    profile = {
        "default": {"missingness": 0.01},
        "sources": {
            "sysmon": {
                "missingness": 0.1,
                "format_missingness": {"windows_event_sysmon": 0.11},
            }
        },
    }
    scenario = _scenario(
        logs=["windows_event_sysmon"],
        observation_profile="enterprise_standard",
        observation_overrides=[
            {
                "source_instance": "sysmon:win-01",
                "family": "sysmon",
                "system": "WIN-01",
                "missingness": 0.3,
            }
        ],
    )

    result = compile_scenario_source_deployment(
        scenario,
        named_profile=profile,
        project_pack_overrides={
            "SYSMON:WIN-01": SourceCollectionOverride(
                missingness=0.2,
                optional_fields=frozenset({"Hashes"}),
            )
        },
    )
    source = result.deployment.source_by_instance("sysmon:win-01")

    assert source is not None
    assert source.policy.missingness == 0.3
    assert source.policy.format_missingness == {"windows_event_sysmon": 0.11}
    assert source.policy.optional_fields == frozenset({"Hashes"})


def test_default_profile_format_overrides_are_filtered_per_source_family() -> None:
    profile = {
        "default": {
            "missingness": 0.0,
            "format_missingness": {
                "windows_event_sysmon": 0.02,
                "zeek_conn": 0.03,
            },
        },
        "sources": {},
    }

    result = compile_scenario_source_deployment(
        _scenario(logs=["windows_event_sysmon"]),
        named_profile=profile,
    )
    source = result.deployment.source_by_instance("sysmon:win-01")

    assert source is not None
    assert source.policy.format_missingness == {"windows_event_sysmon": 0.02}


def test_named_profile_compiles_stable_batching_and_collection_window() -> None:
    profile = {
        "default": {
            "missingness": 0.0,
            "collection_batching": {
                "enabled": True,
                "interval_ms": {"min_ms": 100, "max_ms": 200},
            },
            "collection_window": {
                "enabled": True,
                "start": "2026-08-16T12:00:00Z",
                "end": "2026-08-16T20:00:00Z",
            },
        },
        "sources": {},
    }
    scenario = _scenario(logs=["windows_event_security"])

    first = compile_scenario_source_deployment(scenario, named_profile=profile)
    second = compile_scenario_source_deployment(scenario, named_profile=profile)
    source = first.deployment.source_by_instance("windows_security:win-01")

    assert source is not None
    assert 100_000 <= source.policy.batching.interval_us <= 200_000
    assert source.policy.capabilities.covers(
        CollectionCapability.BATCHING | CollectionCapability.COLLECTION_WINDOWS
    )
    assert source.policy.windows[0].start == datetime(2026, 8, 16, 12, tzinfo=UTC)
    assert first.digest == second.digest


@pytest.mark.parametrize(
    ("profile", "message"),
    [
        (
            {"default": {}, "sources": {"typo": {"missingness": 0.1}}},
            "unknown source families",
        ),
        (
            {
                "default": {},
                "sources": {
                    "sysmon": {"format_missingness": {"zeek_conn": 0.1}},
                },
            },
            "does not belong",
        ),
        (
            {"default": {"format_missingness": {"missing_format": 0.1}}, "sources": {}},
            "unknown concrete source format",
        ),
    ],
)
def test_compiler_rejects_profile_catalog_typos(
    profile: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(SourceDeploymentCompilationError, match=message):
        compile_scenario_source_deployment(
            _scenario(logs=["windows_event_sysmon"]),
            named_profile=profile,
        )


def test_compilation_digest_and_order_ignore_authored_catalog_order() -> None:
    systems = [
        {
            "hostname": "WIN-01",
            "ip": "10.0.0.10",
            "os": "Windows 11",
            "type": "workstation",
        },
        {
            "hostname": "LINUX-01",
            "ip": "10.0.0.20",
            "os": "Ubuntu 24.04",
            "type": "server",
        },
    ]
    first = compile_scenario_source_deployment(
        _scenario(systems=systems, sensors=[], logs=["windows", "ecar", "syslog"]),
        named_profile=_COMPLETE_PROFILE,
    )
    second = compile_scenario_source_deployment(
        _scenario(
            systems=list(reversed(systems)),
            sensors=[],
            logs=["syslog", "ecar", "windows_event_sysmon", "windows_event_security"],
        ),
        named_profile=_COMPLETE_PROFILE,
    )

    assert first.source_instances == second.source_instances
    assert first.digest == second.digest


def test_large_fleet_compile_keeps_exact_lookup_candidate_bound_flat() -> None:
    systems = [
        {
            "hostname": f"WIN-{index:05d}",
            "ip": f"10.42.{index // 250}.{(index % 250) + 1}",
            "os": "Windows 11",
            "type": "workstation",
        }
        for index in range(2_000)
    ]

    result = compile_scenario_source_deployment(
        _scenario(systems=systems, sensors=[], logs=["ecar"]),
        named_profile=_COMPLETE_PROFILE,
    )

    assert result.census.source_instances == 2_000
    assert result.census.host_sources == 2_000
    assert result.census.sensor_sources == 0
    assert result.census.host_applicability_checks == 2_000
    assert result.census.exact_lookup_candidate_bound == 1
    assert result.deployment.census.max_host_family_bucket == 1
    assert result.deployment.source_by_instance("ecar:win-01999") is not None


def test_compiler_rejects_duplicate_exact_sensor_source_identity() -> None:
    sensors = [
        {
            "type": "network",
            "name": "TAP-01",
            "monitoring_segments": ["lan"],
            "log_formats": ["zeek"],
        },
        {
            "type": "network",
            "name": "tap-01",
            "hostname": "second.example.test",
            "monitoring_segments": ["lan"],
            "log_formats": ["zeek"],
        },
    ]

    with pytest.raises(SourceDeploymentCompilationError, match="ambiguous source-instance"):
        compile_scenario_source_deployment(
            _scenario(sensors=sensors, logs=["zeek"]),
            named_profile=_COMPLETE_PROFILE,
        )


def test_compiler_rejects_format_on_wrong_sensor_type() -> None:
    sensors = [
        {
            "type": "ids",
            "name": "IDS-01",
            "monitoring_segments": ["lan"],
            "log_formats": ["zeek_conn"],
        }
    ]

    with pytest.raises(SourceDeploymentCompilationError, match="requires one of: network"):
        compile_scenario_source_deployment(
            _scenario(sensors=sensors, logs=["zeek_conn"]),
            named_profile=_COMPLETE_PROFILE,
        )


def test_compiler_rejects_overlapping_sensor_group_and_format_selectors() -> None:
    sensors = [
        {
            "type": "network",
            "name": "TAP-01",
            "monitoring_segments": ["lan"],
            "log_formats": ["zeek", "zeek_conn"],
        }
    ]

    with pytest.raises(SourceDeploymentCompilationError, match="ambiguous log_formats selectors"):
        compile_scenario_source_deployment(
            _scenario(sensors=sensors, logs=["zeek_conn"]),
            named_profile=_COMPLETE_PROFILE,
        )


def test_compiler_requires_a_deployment_for_selected_sensor_formats() -> None:
    with pytest.raises(SourceDeploymentCompilationError, match="no applicable deployed sensor"):
        compile_scenario_source_deployment(
            _scenario(sensors=[], logs=["zeek_conn"]),
            named_profile=_COMPLETE_PROFILE,
        )


def test_compiler_rejects_undeployed_exact_overrides() -> None:
    scenario = _scenario(
        logs=["ecar"],
        observation_overrides=[
            {"source_instance": "sysmon:win-01", "enabled": False},
        ],
    )

    with pytest.raises(SourceDeploymentCompilationError, match="undeployed sources"):
        compile_scenario_source_deployment(scenario, named_profile=_COMPLETE_PROFILE)

    with pytest.raises(SourceDeploymentCompilationError, match="undeployed sources"):
        compile_scenario_source_deployment(
            _scenario(logs=["ecar"]),
            named_profile=_COMPLETE_PROFILE,
            project_pack_overrides={"sysmon:win-01": SourceCollectionOverride(enabled=False)},
        )


def test_compiler_rejects_undeployed_format_and_unsupported_capability() -> None:
    scenario = _scenario(logs=["windows_event_security"])

    with pytest.raises(SourceDeploymentCompilationError, match="not deployed"):
        compile_scenario_source_deployment(
            scenario,
            named_profile=_COMPLETE_PROFILE,
            project_pack_overrides={
                "windows_security:win-01": SourceCollectionOverride(
                    format_missingness={"windows_event_sysmon": 0.1}
                )
            },
        )

    with pytest.raises(SourceDeploymentCompilationError, match="unsupported capability"):
        compile_scenario_source_deployment(
            scenario,
            named_profile=_COMPLETE_PROFILE,
            project_pack_overrides={
                "windows_security:win-01": SourceCollectionOverride(
                    capabilities=CollectionCapability.SMB_ANALYZER
                )
            },
        )


def test_exact_source_ids_are_canonical_and_reject_ambiguous_owner_names() -> None:
    assert exact_source_instance_id("SysMon", "WS-01") == "sysmon:ws-01"
    assert exact_source_instance_id("zeek", "tap-01", "west") == "zeek:tap-01:west"
    with pytest.raises(SourceDeploymentCompilationError, match="stable source ID"):
        exact_source_instance_id("zeek", "tap west")
