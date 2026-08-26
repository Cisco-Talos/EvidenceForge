# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for eforge info inventory collection."""

import json
from pathlib import Path

from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.cli.info import gather_info


def test_system_roles_include_author_facing_topology_and_activity_roles():
    roles = set(gather_info(field="system_roles")["system_roles"])

    assert {
        "app_server",
        "database",
        "dns_server",
        "domain_controller",
        "file_server",
        "forward_proxy",
        "load_balancer",
        "log_server",
        "mail_server",
        "monitoring",
        "nfs_server",
        "print_server",
        "web_server",
        "workstation",
    } <= roles
    assert "_default" not in roles


def test_pack_builtin_inventories_are_packaged_only_and_stable():
    info = gather_info()

    assert {"chrome", "excel", "acrobat"} <= set(info["pack_builtin_application_ids"])
    assert {"web", "saas", "storage"} <= set(info["pack_builtin_dns_tags"])


def test_ids_signature_inventory_exposes_authoring_context() -> None:
    signatures = gather_info(field="ids_signatures")["ids_signatures"]
    scan_signature = next(signature for signature in signatures if signature["sid"] == 2002910)

    assert scan_signature == {
        "sid": 2002910,
        "rev": 4,
        "message": "ET SCAN Rapid HTTP/HTTPS Connection Attempts",
        "classification": "attempted-recon",
        "priority": 2,
        "proto": "tcp",
        "dst_port": 80,
        "direction": "in",
        "alert_policy": {
            "event_filter": {"type": "both", "track": "by_src", "count": 5, "seconds": 60}
        },
    }
    assert all("predicate" not in signature for signature in signatures)


def test_ids_signature_inventory_honors_project_overlay(tmp_path: Path) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "ids_signatures.yaml").write_text(
        """
signatures:
  - sid: 2999999
    rev: 1
    message: Example scenario-only IDS signature
    classification: attempted-recon
    priority: 2
    proto: tcp
    dst_port: 8443
    direction: in
    target_services: [https]
    predicate:
      inspection: payload_cleartext
""",
        encoding="utf-8",
    )

    signatures = gather_info(field="ids_signatures", project_root=tmp_path)["ids_signatures"]
    added = next(signature for signature in signatures if signature["sid"] == 2999999)

    assert added["message"] == "Example scenario-only IDS signature"
    assert added["target_services"] == ["https"]
    assert added["inspection"] == "payload_cleartext"


def test_ids_signature_inventory_has_text_and_json_cli_contracts() -> None:
    runner = CliRunner()

    text_result = runner.invoke(app, ["info", "ids_signatures"])
    json_result = runner.invoke(app, ["info", "ids_signatures", "--json"])

    assert text_result.exit_code == 0, text_result.stdout
    assert text_result.stdout.startswith("SID\tPROTO/PORT\tDIRECTION\tMESSAGE\n")
    assert "2002910\ttcp/80\tin\tET SCAN Rapid HTTP/HTTPS Connection Attempts" in text_result.stdout
    assert json_result.exit_code == 0, json_result.stdout
    assert any(signature["sid"] == 2002910 for signature in json.loads(json_result.stdout))
