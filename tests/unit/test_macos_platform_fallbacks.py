# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import random
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.composition.semantic_validation import packaged_builtin_executable_claims
from evidenceforge.generation.activity import dns_registry, edr_pools, endpoint_noise
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.activity.tls_realism import _tls_profile_domains
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.models.scenario import System
from tests.unit.test_pack_models import _custom_process, _industry_pack, _validate_semantics
from tests.unit.test_process_exec_projection import _START


@pytest.mark.parametrize("child", [False, True])
def test_pack_cannot_claim_a_packaged_mac_executable_as_a_custom_process(child: bool) -> None:
    from evidenceforge.models.exceptions import PackError

    image = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
    claims = packaged_builtin_executable_claims()
    assert "macos:basename:terminal" in claims
    custom = _custom_process()
    custom["platforms"] = {
        "macos": {
            "image_path": "/Applications/Invented.app/Contents/MacOS/Invented" if child else image,
            "command_templates": ["Invented" if child else "Terminal"],
            "children": [image] if child else [],
        }
    }
    with pytest.raises(PackError, match="packaged builtin executable"):
        _validate_semantics(
            [_industry_pack(custom=[custom])],
            builtin_application_ids={"chrome"},
            builtin_executable_claims=claims,
        )


@pytest.mark.parametrize("source", ["macos", "windows", "linux"])
def test_dns_and_tls_use_the_same_configured_platform_tag_pool(
    monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    entries = [
        {"domain": f"{tag}.example.test", "ips": [f"192.0.2.{index}"], "tags": ["background", tag]}
        for index, tag in enumerate(("windows", "linux", "macos"), start=1)
    ]
    entries.append({"domain": "shared.example.test", "ips": ["192.0.2.4"], "tags": ["background"]})
    monkeypatch.setattr(
        dns_registry,
        "_CACHED_DATA",
        {"domains": entries, "valid_tags": {"os_tags": ["windows", "linux", "macos"]}},
    )
    monkeypatch.setattr(dns_registry, "_CACHED_TAG_INDEX", None)
    monkeypatch.setattr(dns_registry, "_CACHED_DOMAIN_TAGS", None)
    expected = {f"{source}.example.test", "shared.example.test"}
    tls = _tls_profile_domains(
        {"domains": [entry["domain"] for entry in entries]}, random.Random(3), source_os=source
    )
    assert set(tls) == expected
    rng = random.Random(4)
    assert {
        dns_registry.pick_domain_and_ip(rng, "background", include_os=source)[0] for _ in range(40)
    } == expected


def test_mac_tls_still_excludes_foreign_tags_in_a_legacy_two_platform_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        dns_registry,
        "_CACHED_DATA",
        {
            "domains": [
                {"domain": "windows.example.test", "tags": ["windows"]},
                {"domain": "linux.example.test", "tags": ["linux"]},
                {"domain": "shared.example.test", "tags": []},
            ],
            "valid_tags": {"os_tags": ["windows", "linux"]},
        },
    )
    monkeypatch.setattr(dns_registry, "_CACHED_DOMAIN_TAGS", None)
    profile = {"domains": ["windows.example.test", "linux.example.test", "shared.example.test"]}
    assert _tls_profile_domains(profile, random.Random(3), source_os="macos") == [
        "shared.example.test"
    ]
    assert (
        _tls_profile_domains(profile, random.Random(3), source_os="unknown") == profile["domains"]
    )


@pytest.mark.parametrize("os_name", ["macOS 26", "Windows 11", "Ubuntu 24.04"])
@pytest.mark.parametrize("agent", ["Apple Mail", "Thunderbird", "Microsoft Outlook"])
def test_known_mail_clients_use_shared_starttls_policy_on_each_supported_platform(
    os_name: str, agent: str
) -> None:
    generator = object.__new__(ActivityGenerator)
    source = System(hostname="CLIENT", ip="192.0.2.10", os=os_name, type="workstation")
    target = System(hostname="MAIL", ip="192.0.2.20", os="Ubuntu 24.04", type="server")
    assert generator._smtp_submission_uses_starttls(
        src_system=source,
        dst_system=target,
        message_id="invented-message",
        hop_index=0,
        user_agent=agent,
    )
    unknown = source.model_copy(update={"os": "Unknown OS"})
    assert not generator._smtp_submission_uses_starttls(
        src_system=unknown,
        dst_system=target,
        message_id="invented-message",
        hop_index=0,
        user_agent=agent,
    )


@pytest.mark.parametrize(
    ("platform", "expected"), [("macos", "root"), ("linux", "root"), ("windows", "SYSTEM")]
)
def test_system_file_churn_uses_platform_appropriate_fallback_owner(
    monkeypatch: pytest.MonkeyPatch, platform: str, expected: str
) -> None:
    monkeypatch.setattr(
        endpoint_noise,
        "ecar_file_churn_config",
        lambda: {platform: {"count_min": 1, "count_max": 1}},
    )
    monkeypatch.setattr(edr_pools, "get_file_paths", lambda _: ["{username}/invented"])
    selected = Mock(return_value=None)
    monkeypatch.setattr(edr_pools, "select_ambient_file_churn_effect", selected)
    process = SimpleNamespace(
        pid=10,
        start_time=_START - timedelta(seconds=1),
        image="invented",
        command_line="invented",
        username="",
    )
    owner = SimpleNamespace(
        state_manager=SimpleNamespace(get_process=lambda *_: process),
        _scaled_randint=lambda *_: 1,
        activity_generator=SimpleNamespace(
            _build_host_context=lambda _: None,
            _foreground_process_expired_for_attribution=lambda *_: False,
            _process_termination_recorded=lambda *_: False,
        ),
    )
    system = System(hostname="CLIENT", ip="192.0.2.10", os="macOS 26", type="workstation")
    BaselineMixin._emit_ecar_file_churn(
        owner, system, _START, random.Random(3), platform, {"invented": 10}
    )
    assert selected.call_args.args[4] == expected


@pytest.mark.slow
def test_mac_smtp_submission_is_correlated_with_the_shared_tls_transport(tmp_path: Path) -> None:
    from evidenceforge.generation.engine import GenerationEngine
    from tests.unit.test_email_evidence import _email_scenario, _read_ndjson

    scenario = _email_scenario()
    scenario.environment.systems[0].os = "macOS 26"
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )
    engine.generate()
    smtp = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    ssl = _read_ndjson(tmp_path / "data" / "zeek-core" / "ssl.json")
    connections = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    submission = next(
        row for row in smtp if row["id.orig_h"] == "10.10.1.10" and row["id.resp_p"] == 587
    )
    assert submission["tls"] is True
    assert any(row["uid"] == submission["uid"] for row in ssl)
    assert any(row["uid"] == submission["uid"] for row in connections)


def test_mac_custom_process_and_traffic_values_use_existing_pack_schema() -> None:
    from evidenceforge.composition.models import CustomProcess, TrafficConnection

    custom = _custom_process()
    custom["platforms"] = {
        "macos": {
            "image_path": "/Applications/Invented.app/Contents/MacOS/Invented",
            "command_templates": [
                '"/Applications/Invented.app/Contents/MacOS/Invented" {username}'
            ],
        }
    }
    process = CustomProcess.model_validate(custom)
    assert set(process.platforms) == {"macos"}
    assert CustomProcess.model_validate_json(process.model_dump_json()) == process
    connection = TrafficConnection(port=443, os="macos")
    assert TrafficConnection.model_validate_json(connection.model_dump_json()) == connection


@pytest.mark.parametrize("invalid", ["relative", "windows_path", "pe_metadata", "foreign_command"])
def test_mac_custom_process_rejects_foreign_platform_facts(invalid: str) -> None:
    from pydantic import ValidationError

    from evidenceforge.composition.models import CustomProcess

    custom = _custom_process()
    platform = {"image_path": "/usr/local/bin/invented", "command_templates": ["invented"]}
    if invalid == "relative":
        platform["image_path"] = "relative/invented"
    elif invalid == "windows_path":
        platform["image_path"] = "C:/invented.exe"
    elif invalid == "foreign_command":
        platform["command_templates"] = ["foreign.exe"]
    else:
        platform["loaded_modules"] = [{"path": "C:/invented.dll"}]
    custom["platforms"] = {"macos": platform}
    with pytest.raises(ValidationError):
        CustomProcess.model_validate(custom)
