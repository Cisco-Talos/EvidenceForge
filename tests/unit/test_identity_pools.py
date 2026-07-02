from __future__ import annotations

import random
import sys

import pytest

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
from evidenceforge.generation.activity.suspicious_benign_config import (
    load_suspicious_benign,
    pick_suspicious_dns_host,
    pick_unusual_connection,
    reset_suspicious_benign_cache,
)


def _reset_identity_pool_caches() -> None:
    reset_email_background_cache()
    reset_mail_public_identities_cache()
    reset_external_actor_profiles_cache()
    reset_suspicious_benign_cache()
    reset_command_parameter_pools_cache()
    for module_name, module in list(sys.modules.items()):
        if not module_name.startswith("evidenceforge."):
            continue
        for attr_name in dir(module):
            if attr_name.startswith("_CACHED"):
                setattr(module, attr_name, None)


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
    assert data["identity_pools"]["email_background"]["external_domains"] >= 1
