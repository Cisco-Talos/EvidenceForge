"""Frozen ordering contracts for raw, scoped and merged configuration validation."""

import copy
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

import pytest

from evidenceforge.config import overlay
from evidenceforge.generation.activity import extra_syslog, network_params
from evidenceforge.validation.configuration import validate_config


def _raw_overlay(root: Path) -> Path:
    (root / "activity").mkdir(parents=True)
    (root / "personas").mkdir()
    (root / "activity/network_params.yaml").write_text(
        "public_ntp_servers: wrong\nunknown_field: true\n"
    )
    (root / "activity/unknown.yaml").write_text("ignored: true\n")
    (root / "personas/alice.yaml").write_text("name: bob\n")
    return root


def _expected(name: str) -> dict[str, object]:
    return json.loads(
        (Path(__file__).parents[1] / "fixtures/cleanup-validation-expectations.json").read_text()
    )[name]


def test_raw_overlay_diagnostics_block_provider_activation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _raw_overlay(tmp_path / "overlay")
    monkeypatch.setattr(overlay, "get_overlay_directory", lambda: root)

    @contextmanager
    def forbidden_scope() -> Iterator[None]:
        raise AssertionError("Invalid raw overlays must block scope entry")
        yield  # pragma: no cover

    assert asdict(validate_config(merged_scope_factory=forbidden_scope)) == _expected("raw")


def test_effective_scope_rechecks_overlay_before_merged_loaders(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _raw_overlay(tmp_path / "overlay")
    monkeypatch.setattr(overlay, "get_overlay_directory", lambda: None)
    entries: list[str] = []

    @contextmanager
    def changed_scope() -> Iterator[None]:
        entries.append("enter")
        with monkeypatch.context() as scoped:
            scoped.setattr(overlay, "get_overlay_directory", lambda: root)
            yield
        entries.append("exit")

    assert asdict(validate_config(merged_scope_factory=changed_scope)) == _expected("raw")
    assert entries == ["enter", "exit"]


def test_merged_family_diagnostics_precede_deferred_schemas_and_deduplicate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(overlay, "get_overlay_directory", lambda: None)
    net = copy.deepcopy(network_params.load_network_params())
    net["dns_tunnel_response_templates"] = ["{token}_{unknown}", "readable{token}"]
    net["dns_tunnel_rcode_weights"] = {"UNKNOWN": 1, "NOERROR": 0}
    net["proxy_connect_status_messages"] = {
        "bad": ["message"],
        "600": ["message"],
        "200": [],
        "403": [None],
    }
    syslog = [
        {
            "app": "NetworkManager",
            "system_types": ["unknown"],
            "weight": 0,
            "messages": [
                "daemon started",
                "daemon started",
                "state change: connected -> connected",
                "cron.daily job",
            ],
            "params": {},
        }
    ]
    monkeypatch.setattr(network_params, "load_network_params", lambda: net)
    monkeypatch.setattr(extra_syslog, "load_extra_syslog_messages", lambda: syslog)
    result = validate_config()
    assert asdict(result) == _expected("merged")
    assert len(result.errors) == 14
    assert result.warnings == result.infos == []
