from __future__ import annotations

import json
import random
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.cli.info import gather_info
from evidenceforge.cli.validate_config import validate_config
from evidenceforge.generation.activity.command_parameter_pools import (
    command_parameter_pools,
    reset_command_parameter_pools_cache,
)
from evidenceforge.generation.activity.email_background import (
    load_email_background,
    pick_email_background_domain,
    pick_email_background_local_part,
    reset_email_background_cache,
)
from evidenceforge.generation.activity.external_actor_profiles import (
    load_external_actor_profiles,
    pick_external_actor_ip,
    reset_external_actor_profiles_cache,
)
from evidenceforge.generation.activity.helpers import _parameterize_command
from evidenceforge.generation.activity.mail_public_identities import (
    public_safe_mail_hostname,
    reset_mail_public_identities_cache,
)
from evidenceforge.generation.activity.public_identity_profiles import (
    PublicIdentityRegistry,
    authored_public_identity_reuse,
    load_public_identity_profiles,
    reset_public_identity_profiles_cache,
    translate_external_actor_profiles,
    translate_mail_public_identities,
)
from evidenceforge.generation.activity.suspicious_benign_config import (
    load_suspicious_benign,
    pick_suspicious_dns_host,
    pick_unusual_connection,
    reset_suspicious_benign_cache,
)
from evidenceforge.utils.yaml_loader import load_yaml_file


def _reset_identity_pool_caches() -> None:
    reset_email_background_cache()
    reset_mail_public_identities_cache()
    reset_external_actor_profiles_cache()
    reset_suspicious_benign_cache()
    reset_command_parameter_pools_cache()


@pytest.fixture(autouse=True)
def reset_identity_pool_caches() -> None:
    _reset_identity_pool_caches()
    yield
    _reset_identity_pool_caches()


def test_identity_pool_defaults_are_loaded() -> None:
    email_background = load_email_background()
    assert {entry["domain"] for entry in email_background["external_domains"]} >= {
        "vendorpost.net",
        "partnerrelay.io",
    }
    assert pick_email_background_domain(random.Random(1)) in {
        entry["domain"] for entry in email_background["external_domains"]
    }
    assert pick_email_background_local_part(random.Random(2), "inbound_local_parts") in {
        entry["local_part"] for entry in email_background["inbound_local_parts"]
    }

    profiles = load_external_actor_profiles()
    assert pick_external_actor_ip("logon_source_ips", random.Random(3)) in {
        entry["ip"] for entry in profiles["logon_source_ips"]
    }

    suspicious = load_suspicious_benign()
    assert pick_suspicious_dns_host(random.Random(4)) in {
        entry["hostname"] for entry in suspicious["dns_hosts"]
    }
    unusual = pick_unusual_connection(random.Random(5))
    assert unusual["hostname"] in {entry["hostname"] for entry in suspicious["unusual_connections"]}


def test_identity_pool_cache_reset_preserves_timing_profile_coordinator() -> None:
    from evidenceforge.generation.activity import timing_profiles

    coordinator = timing_profiles._CACHED_TIMING_PROFILES

    _reset_identity_pool_caches()

    assert timing_profiles._CACHED_TIMING_PROFILES is coordinator
    assert timing_profiles.load_timing_profiles()


def test_identity_pool_overlays_are_loaded(tmp_path, monkeypatch) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "email_background.yaml").write_text(
        """
external_domains:
  - domain: auditrelay.net
    weight: 500
inbound_local_parts:
  - local_part: notices
    weight: 500
outbound_local_parts:
  - local_part: contracts
    weight: 500
""",
        encoding="utf-8",
    )
    (overlay / "external_actor_profiles.yaml").write_text(
        """
logon_source_ips:
  - ip: 8.8.8.8
    weight: 500
connection_c2_ips:
  - ip: 1.1.1.1
    weight: 500
""",
        encoding="utf-8",
    )
    (overlay / "suspicious_benign.yaml").write_text(
        """
dns_hosts:
  - hostname: overlay-cdn.auditrelay.net
    weight: 500
unusual_connections:
  - hostname: overlay-api.auditrelay.net
    dst_ip: 9.9.9.9
    dst_port: 443
    service: ssl
    desc: Overlay API
    weight: 500
""",
        encoding="utf-8",
    )
    (overlay / "command_parameter_pools.yaml").write_text(
        """
general:
  external_api_url:
    - https://api.auditrelay.net/v1/status
query:
  db_server:
    - SQL-AUDIT-01
""",
        encoding="utf-8",
    )
    (overlay / "mail_public_identities.yaml").write_text(
        """
reserved_replacement_domains:
  - auditrelay.net
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    assert "auditrelay.net" in {
        entry["domain"] for entry in load_email_background()["external_domains"]
    }
    assert "8.8.8.8" in {
        entry["ip"] for entry in load_external_actor_profiles()["logon_source_ips"]
    }
    assert "overlay-cdn.auditrelay.net" in {
        entry["hostname"] for entry in load_suspicious_benign()["dns_hosts"]
    }
    assert (
        "https://api.auditrelay.net/v1/status"
        in command_parameter_pools()["general"]["external_api_url"]
    )
    assert public_safe_mail_hostname("mail.example.net").endswith(".auditrelay.net")


def test_command_parameterization_uses_config_backed_url_and_host_pools(
    tmp_path, monkeypatch
) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "command_parameter_pools.yaml").write_text(
        """
general:
  url:
    - https://portal.auditrelay.net/home
query:
  db_server:
    - SQL-AUDIT-01
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    rendered_url = _parameterize_command(random.Random(0), "curl {url}")
    rendered_db = _parameterize_command(random.Random(0), "sqlcmd -S {db_server}")

    assert rendered_url in {
        "curl https://portal.auditrelay.net/home",
        "curl https://mail.google.com/mail/u/0/#inbox",
        "curl https://outlook.office365.com/mail/inbox",
        "curl https://app.slack.com/client/T01234567",
        "curl https://jira.corp.local/browse/PROJ-1234",
    }
    assert rendered_db in {
        "sqlcmd -S SQL-AUDIT-01",
        "sqlcmd -S localhost",
        "sqlcmd -S DB-SRV-01",
        "sqlcmd -S sqlprod01",
        "sqlcmd -S 10.0.2.50",
        "sqlcmd -S SQLEXPRESS",
    }
    assert "https://portal.auditrelay.net/home" in command_parameter_pools()["general"]["url"]
    assert "SQL-AUDIT-01" in command_parameter_pools()["query"]["db_server"]


def test_validate_config_rejects_reserved_email_background_domain(tmp_path, monkeypatch) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "email_background.yaml").write_text(
        """
external_domains:
  - domain: vendor.example.net
    weight: 1
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "email_background.yaml"
        and "reserved documentation domain" in issue.message
        for issue in result.issues
    )


def test_validate_config_rejects_bad_external_actor_ip(tmp_path, monkeypatch) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "external_actor_profiles.yaml").write_text(
        """
logon_source_ips:
  - ip: 10.1.2.3
    weight: 1
""",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "external_actor_profiles.yaml"
        and "routable public IP address" in issue.message
        for issue in result.issues
    )


def test_info_exposes_identity_pool_inventory() -> None:
    data = gather_info("identity_pools")

    assert "identity_pools" in data
    assert "activity/email_background.yaml" in data["identity_pools"]["overlay_paths"]
    assert "activity/public_identity_profiles.yaml" in data["identity_pools"]["overlay_paths"]
    canonical = data["identity_pools"]["public_identity_profiles"]
    assert set(canonical["roles"]) >= {
        "scanner",
        "external_logon",
        "failed_logon",
        "c2",
        "human",
        "crawler",
        "api_client",
        "ordinary_responder",
        "cdn",
        "dns",
        "ntp",
        "mail",
    }
    assert "google-workspace" in canonical["providers"]
    assert data["identity_pools"]["email_background"]["external_domains"] >= 1


def test_public_identity_registry_is_stable_and_role_scoped() -> None:
    registry = PublicIdentityRegistry()
    roles = (
        "scanner",
        "external_logon",
        "failed_logon",
        "c2",
        "human",
        "crawler",
        "api_client",
        "ordinary_responder",
    )
    bindings = {
        role: registry.bind(role, f"identity-test:{role}", prefer_fixed=False) for role in roles
    }

    assert all(
        registry.bind(role, f"identity-test:{role}", prefer_fixed=False) == binding
        for role, binding in bindings.items()
    )
    assert len({binding.ip for binding in bindings.values()}) == len(bindings)
    assert all(binding.role == role for role, binding in bindings.items())
    with pytest.raises(AttributeError, match="immutable"):
        registry._roles = {}  # type: ignore[assignment]


def test_public_identity_registry_parallel_assignment_is_deterministic() -> None:
    registry = PublicIdentityRegistry()
    keys = [f"parallel:{index}" for index in range(64)]

    serial = [registry.bind("ordinary_responder", key) for key in keys]
    with ThreadPoolExecutor(max_workers=8) as executor:
        parallel = list(executor.map(lambda key: registry.bind("ordinary_responder", key), keys))

    assert parallel == serial


def test_public_identity_registry_preserves_authored_identity_and_fingerprint() -> None:
    registry = PublicIdentityRegistry()

    first = registry.bind("c2", "authored-one", authored_ip="45.90.12.34")
    repeated = registry.bind("c2", "authored-one", authored_ip="45.90.12.34")
    changed = registry.bind("c2", "authored-two", authored_ip="45.90.12.34")

    assert first.ip == "45.90.12.34"
    assert first.authored is True
    assert "scenario-authored" in first.provenance
    assert first == repeated
    assert first.fingerprint != changed.fingerprint


def test_legacy_translation_preserves_external_and_mail_values() -> None:
    external = {
        "logon_source_ips": [{"ip": "45.67.89.10", "weight": 7}],
        "failed_logon_source_ips": [{"ip": "45.67.89.11", "weight": 5}],
        "connection_c2_ips": [{"ip": "45.67.89.12", "weight": 3}],
    }
    mail = {
        "reserved_replacement_domains": ["auditrelay.net"],
        "providers": [
            {
                "name": "audit_mail",
                "weight": 9,
                "hostname_patterns": ["auditrelay.net"],
                "prefixes": [[45, 67, 80, 95]],
                "ptr_templates": ["mx{slot}.{domain}"],
            }
        ],
    }

    translated_external = translate_external_actor_profiles(external)
    translated_mail = translate_mail_public_identities(mail)

    by_role = {entry["id"]: entry for entry in translated_external["roles"]}
    assert by_role["external_logon"]["identities"][0]["ip"] == "45.67.89.10"
    assert by_role["failed_logon"]["identities"][0]["weight"] == 5
    assert by_role["c2"]["identities"][0]["weight"] == 3
    assert translated_mail["providers"][0]["id"] == "audit-mail"
    assert translated_mail["providers"][0]["ipv4_prefixes"] == [[45, 67, 80, 95]]
    assert translated_mail["reserved_replacement_domains"] == ["auditrelay.net"]


def test_legacy_fixture_translation_preserves_former_packaged_defaults() -> None:
    fixture_root = Path(__file__).parents[1] / "fixtures" / "config" / "activity"
    external = load_yaml_file(fixture_root / "external_actor_profiles.yaml")
    mail = load_yaml_file(fixture_root / "mail_public_identities.yaml")

    translated_external = translate_external_actor_profiles(external)
    translated_mail = translate_mail_public_identities(mail)
    translated_roles = {entry["id"]: entry for entry in translated_external["roles"]}
    for legacy_field, role in {
        "logon_source_ips": "external_logon",
        "failed_logon_source_ips": "failed_logon",
        "connection_c2_ips": "c2",
    }.items():
        projected = [
            {"ip": entry["ip"], "weight": entry["weight"]}
            for entry in translated_roles[role]["identities"]
        ]
        assert projected == external[legacy_field]

    assert len(translated_mail["providers"]) == len(mail["providers"])
    for translated, original in zip(translated_mail["providers"], mail["providers"], strict=True):
        assert translated["id"] == original["name"].replace("_", "-")
        assert translated["weight"] == original["weight"]
        assert translated["hostname_patterns"] == original["hostname_patterns"]
        assert translated["ipv4_prefixes"] == original["prefixes"]
        assert translated["ptr_templates"] == original["ptr_templates"]
    assert translated_mail["reserved_replacement_domains"] == mail["reserved_replacement_domains"]


def test_canonical_overlay_wins_over_translated_legacy_overlay(tmp_path, monkeypatch) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "external_actor_profiles.yaml").write_text(
        "logon_source_ips:\n  - {ip: 45.67.89.10, weight: 9}\n",
        encoding="utf-8",
    )
    (overlay / "public_identity_profiles.yaml").write_text(
        """
roles:
  - id: external_logon
    identities:
      - {ip: 45.67.89.20, provider: external-access, weight: 11}
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_public_identity_profiles_cache()

    registry = PublicIdentityRegistry()
    fixed = registry.fixed_bindings("external_logon")

    assert [binding.ip for binding in fixed] == ["45.67.89.20"]
    assert "legacy:activity/external_actor_profiles.yaml" not in fixed[0].provenance


def test_translated_legacy_binding_retains_provenance(tmp_path, monkeypatch) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "external_actor_profiles.yaml").write_text(
        "logon_source_ips:\n  - {ip: 45.67.89.10, weight: 9}\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_external_actor_profiles_cache()

    binding = PublicIdentityRegistry().bind(
        "external_logon",
        "legacy-provenance",
        authored_ip="45.67.89.10",
        authored=False,
    )

    assert binding.provenance == (
        "packaged",
        "legacy:activity/external_actor_profiles.yaml",
    )
    assert len(binding.fingerprint) == 64


def test_packaged_distribution_uses_only_canonical_public_identity_data() -> None:
    activity_dir = Path(__file__).parents[2] / "src" / "evidenceforge" / "config" / "activity"
    names = {path.name for path in activity_dir.glob("*.yaml")}

    assert "public_identity_profiles.yaml" in names
    assert "external_actor_profiles.yaml" not in names
    assert "mail_public_identities.yaml" not in names
    assert load_public_identity_profiles()["schema_version"] == "1.0"


def test_registry_schema_rejects_unshared_cross_role_fixed_identity() -> None:
    document = deepcopy(load_public_identity_profiles())
    roles = {entry["id"]: entry for entry in document["roles"]}
    roles["human"]["identities"] = [
        {
            "ip": roles["scanner"]["identities"][0]["ip"],
            "provider": "residential-human",
        }
    ]

    with pytest.raises(ValueError, match="reused by disjoint roles"):
        PublicIdentityRegistry(document)


def test_authored_cross_role_reuse_is_reported_without_rewriting_identity() -> None:
    public_ip = "45.90.12.34"
    scenario = SimpleNamespace(
        storyline=[
            SimpleNamespace(
                events=[
                    SimpleNamespace(type="logon", source_ip=public_ip),
                    SimpleNamespace(type="connection", dst_ip=public_ip),
                ]
            )
        ],
        red_herrings=[],
    )

    findings = authored_public_identity_reuse(scenario)
    authored = PublicIdentityRegistry().bind("c2", "authored-reuse", authored_ip=public_ip)

    assert len(findings) == 1
    assert findings[0].ip == public_ip
    assert findings[0].roles == ("c2", "external_logon")
    assert authored.ip == public_ip


def test_only_validate_warns_for_consumed_legacy_identity_overlays(tmp_path) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "external_actor_profiles.yaml").write_text(
        "logon_source_ips:\n  - {ip: 45.67.89.10, weight: 9}\n",
        encoding="utf-8",
    )
    (overlay / "mail_public_identities.yaml").write_text(
        """
reserved_replacement_domains: [auditrelay.net]
providers:
  - name: audit_mail
    weight: 1
    hostname_patterns: [auditrelay.net]
    prefixes: [[45, 67, 80, 95]]
    ptr_templates: ["mx{slot}.{domain}"]
""",
        encoding="utf-8",
    )
    scenario = Path("tests/fixtures/scenarios/minimal.yaml").resolve()
    runner = CliRunner()

    validated = runner.invoke(
        app,
        ["validate", str(scenario), "--project-root", str(tmp_path), "--json"],
    )
    assert validated.exit_code == 0, validated.stdout
    warnings = [
        issue
        for issue in json.loads(validated.stdout)["issues"]
        if "deprecated user overlay" in issue["message"]
    ]
    assert len(warnings) == 2
    assert all("public_identity_profiles.yaml" in issue["message"] for issue in warnings)
    assert all("EvidenceForge 3.0" in issue["message"] for issue in warnings)

    silent_commands = (
        [
            "resolve",
            str(scenario),
            "--project-root",
            str(tmp_path),
            "--explain-composition",
            "--json",
        ],
        ["validate-config", "--project-root", str(tmp_path), "--json"],
        ["info", "identity_pools", "--project-root", str(tmp_path), "--json"],
    )
    for arguments in silent_commands:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0, result.stdout
        assert "deprecated user overlay" not in result.stdout

    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved_result = runner.invoke(
        app,
        [
            "resolve",
            str(scenario),
            "--project-root",
            str(tmp_path),
            "--output",
            str(resolved),
        ],
    )
    assert resolved_result.exit_code == 0, resolved_result.stdout
    assert "deprecated user overlay" not in resolved_result.stdout

    resolved_validation = runner.invoke(app, ["validate", str(resolved), "--json"])
    assert resolved_validation.exit_code == 0, resolved_validation.stdout
    assert "deprecated user overlay" not in resolved_validation.stdout
