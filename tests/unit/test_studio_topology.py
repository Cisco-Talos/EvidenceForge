"""Studio topology must reflect engine membership and exact pack snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from evidenceforge.artifacts.lifecycle import create_draft
from evidenceforge.composition.packs import PackRepository
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import NetworkConfig, System
from evidenceforge.studio.service import create_app
from evidenceforge.studio.topology import project_topology
from tests.unit.test_studio_pack_lifecycle import HEADERS, _pack
from tests.unit.test_studio_service import _paths


def _network() -> dict[str, Any]:
    return {
        "segments": [
            {"name": "v4", "cidr": "10.0.0.0/8", "exposure": "internal"},
            {"name": "v4-narrow", "cidr": "10.1.0.0/16", "exposure": "both"},
            {"name": "v6", "cidr": "2001:db8::/32", "exposure": "internal"},
            {"name": "v6-narrow", "cidr": "2001:db8:1::/48", "exposure": "internal"},
            {
                "name": "explicit",
                "cidr": "192.0.2.0/24",
                "systems": ["MANUAL", "CONSUMER-ONLY"],
                "exposure": "internal",
            },
        ],
        "sensors": [
            {"name": "core", "type": "network", "placement": "span", "monitoring_segments": ["v4"]},
            {
                "name": "edge",
                "hostname": "FW-01",
                "type": "firewall",
                "placement": "tap",
                "monitoring_segments": ["v4", "v6", "consumer-segment"],
                "interfaces": {"v4": "inside", "v4-narrow": "inside", "_default": "wan"},
            },
        ],
    }


def test_topology_matches_explicit_and_cidr_membership_for_both_ip_families() -> None:
    environment = {
        "systems": [
            {"hostname": "MANUAL", "ip": "203.0.113.1", "type": "server", "os": "Cisco IOS XE"},
            {"hostname": "IPV4", "ip": "10.1.0.2", "type": "server", "os": "Windows Server 2022"},
            {"hostname": "IPV6", "ip": "2001:db8:1::2", "type": "server", "os": "macOS 27"},
            {"hostname": "FALLBACK", "ip": "192.0.2.2", "type": "server", "os": "Linux"},
            {"hostname": "FREE", "ip": "198.51.100.1", "type": "server", "os": "Linux"},
        ],
        "network": _network(),
    }
    graph = project_topology(environment)
    visibility = NetworkVisibilityEngine(
        NetworkConfig.model_validate(environment["network"]),
        [System.model_validate(entry) for entry in environment["systems"]],
    )
    assert {host.hostname: host.segment_ids for host in graph.hosts} == {
        "FALLBACK": ["segment:explicit"],
        "FREE": [],
        "IPV4": ["segment:v4", "segment:v4-narrow"],
        "IPV6": ["segment:v6", "segment:v6-narrow"],
        "MANUAL": ["segment:explicit"],
    }
    for host in graph.hosts:
        assert set(host.segment_ids) == {
            f"segment:{segment}" for segment in visibility._resolve_ip_segments(host.ip)
        }
    assert {host.hostname: host.os_family for host in graph.hosts} == {
        "FALLBACK": "linux",
        "FREE": "linux",
        "IPV4": "windows",
        "IPV6": "macos",
        "MANUAL": "unknown",
    }
    firewall, passive = graph.devices
    assert (firewall.kind, firewall.placement, firewall.default_interface) == (
        "firewall",
        "tap",
        "wan",
    )
    assert [
        (edge.segment_id, edge.monitored, edge.interface_name) for edge in firewall.associations
    ] == [
        ("segment:v4", True, "inside"),
        ("segment:v4-narrow", False, "inside"),
        ("segment:v6", True, None),
    ]
    assert passive.kind == "network" and passive.placement == "span"
    assert [finding.entity_id for finding in graph.findings] == ["segment:explicit", "device:FW-01"]
    assert graph == project_topology(environment)


def test_host_details_preserve_declared_primary_users_and_roles() -> None:
    graph = project_topology(
        {
            "systems": [
                {
                    "hostname": "WS-01",
                    "type": "workstation",
                    "os": "Windows 11",
                    "ip": "192.0.2.1",
                    "assigned_user": "alex",
                    "roles": ["workstation", "developer"],
                },
                {
                    "hostname": "WS-02",
                    "type": "workstation",
                    "os": "Linux",
                    "ip": "192.0.2.2",
                },
                {"hostname": "FREE", "type": "server", "os": "Linux", "ip": "192.0.2.3"},
            ],
            "users": [
                {"username": "alex", "primary_system": "WS-01"},
                {"username": "sam", "primary_system": "WS-01"},
                {"username": "jo", "primary_system": "WS-02"},
                {"username": "lee"},
            ],
        }
    )
    hosts = {host.hostname: host for host in graph.hosts}
    assert hosts["WS-01"].primary_users == ["alex", "sam"]
    assert hosts["WS-01"].roles == ["workstation", "developer"]
    assert hosts["WS-02"].primary_users == ["jo"]
    assert hosts["FREE"].primary_users == hosts["FREE"].roles == []


def test_pack_diagrams_are_read_only_and_bound_to_exact_catalog_items(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace_pack = _pack(workspace, "organization")
    environment_file = workspace_pack.parent / "model/environment.yaml"
    environment_file.write_text(yaml.safe_dump({"environment": {"network": _network()}}))
    draft = create_draft(workspace_pack, project_root=workspace, upgrade=True)
    draft_environment = draft.parent / "model/environment.yaml"
    draft_environment.write_text(
        yaml.safe_dump(
            {
                "environment": {
                    "network": {
                        "segments": [
                            {"name": "draft-lan", "cidr": "192.0.2.0/24", "exposure": "internal"},
                        ]
                    }
                }
            }
        )
    )
    bundled = PackRepository(workspace).package_root / (
        "evidenceforge/organization/northstar-health/1.0.0/pack.yaml"
    )
    industry = _pack(workspace)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(workspace))
    with TestClient(create_app(_paths(tmp_path / "app"), "pack-test")) as client:
        catalog = client.get("/v1/bootstrap", headers=HEADERS).json()["items"]
        items = {item["path"]: item for item in catalog}
        before = {path: path.read_bytes() for path in workspace.rglob("*.yaml")}
        for source, expected in (
            (workspace_pack, {"explicit", "v4", "v4-narrow", "v6", "v6-narrow"}),
            (draft, {"draft-lan"}),
            (bundled, {"clinical_lan", "server_lan"}),
        ):
            item = items[str(source)]
            endpoint = f"/v1/packs/{item['id']}/topology"
            assert client.get(endpoint).status_code == 401
            response = client.get(endpoint, headers=HEADERS)
            assert response.status_code == 200, response.text
            report = response.json()
            assert report["source_sha256"] == item["source_sha256"]
            assert len(report["digest"]) == 64
            assert {segment["name"] for segment in report["topology"]["segments"]} == expected
            if source == workspace_pack:
                assert report["topology"]["hosts"] == []
                assert len(report["topology"]["findings"]) == 3
            if source == draft:
                assert report["reference"].startswith("draft:organization:")
            if source == bundled:
                host = next(
                    host
                    for host in report["topology"]["hosts"]
                    if host["hostname"] == "NSH-CLIN-01"
                )
                assert host["primary_users"] == ["maya.patel"]
                assert host["roles"] == ["workstation"]
        industry_id = items[str(industry)]["id"]
        assert client.get(f"/v1/packs/{industry_id}/topology", headers=HEADERS).status_code == 400
        assert before == {path: path.read_bytes() for path in workspace.rglob("*.yaml")}
        client.post(
            "/v1/workspaces/select", headers=HEADERS, json={"path": str(tmp_path / "other")}
        )
        assert client.get(endpoint, headers=HEADERS).status_code == 404
