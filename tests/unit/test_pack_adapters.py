# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime-effect tests for public pack catalog adapters."""

from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import yaml

from evidenceforge.composition import compile_scenario
from evidenceforge.config.provider import (
    _application_graph,
    _destination_overlay,
    _traffic_overlay,
    effective_config_scope,
)
from evidenceforge.generation.activity.application_catalog import (
    get_applications_for_ids,
    is_browser_application_process,
    parameterize_scoped_command,
)
from evidenceforge.generation.activity.dns_registry import load_dns_registry
from evidenceforge.generation.activity.traffic_profiles import (
    get_persona_connections,
    load_traffic_profiles,
)


def _profile(terms: list[str]) -> dict:
    """Return one process profile using the packaged Excel definition."""

    return {
        "description": "Scoped reporting profile",
        "data": {"builtins": ["excel"], "custom": [], "document_terms": terms},
    }


def _application(process: str, persona: str) -> dict:
    """Return one local-only public application definition."""

    return {
        "description": "Reporting application",
        "data": {"personas": [persona], "processes": [process], "connections": {}},
    }


def _write_yaml(path: Path, document: dict[str, object]) -> None:
    """Write one deterministic test-owned YAML document."""

    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_builtin_process_profiles_keep_personas_and_document_terms_isolated() -> None:
    """Reusing one packaged executable never unions profile-scoped authoring data."""

    compiled = compile_scenario("tests/fixtures/scenarios/finance-industry-pack.yaml")
    packaged = compiled.effective_config.packaged_defaults
    effective = SimpleNamespace(
        packaged_defaults=packaged,
        catalogs={
            "process_catalog": {
                "alpha:reports": _profile(["Alpha Ledger"]),
                "beta:reports": _profile(["Beta Ledger"]),
            },
            "application_catalog": {
                "alpha:reporting": _application("alpha:reports", "alpha:operator"),
                "beta:reporting": _application("beta:reports", "beta:operator"),
            },
        },
    )

    applications, runtime = _application_graph(effective)
    by_id = {application["id"]: application for application in applications}

    assert set(by_id) == {"alpha:reports::excel", "beta:reports::excel"}
    assert by_id["alpha:reports::excel"]["personas"] == ["alpha:operator"]
    assert by_id["beta:reports::excel"]["personas"] == ["beta:operator"]
    alpha_pools = by_id["alpha:reports::excel"]["platforms"]["windows"]["command_parameter_pools"]
    beta_pools = by_id["beta:reports::excel"]["platforms"]["windows"]["command_parameter_pools"]
    assert alpha_pools["document_term"] == ["Alpha Ledger"]
    assert beta_pools["document_term"] == ["Beta Ledger"]
    assert "Beta Ledger" not in str(alpha_pools)
    assert "Alpha Ledger" not in str(beta_pools)
    assert runtime["alpha:reporting"]["application_ids"] == ["alpha:reports::excel"]
    assert runtime["beta:reporting"]["application_ids"] == ["beta:reports::excel"]

    assert (
        is_browser_application_process(
            ["alpha:reports::excel"],
            "windows",
            r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
        )
        is False
    )


def test_dependency_custom_process_keeps_defining_pack_namespace() -> None:
    """An organization application cannot re-home a dependency-owned custom process."""

    compiled = compile_scenario("tests/fixtures/scenarios/finance-industry-pack.yaml")
    effective = SimpleNamespace(
        packaged_defaults=compiled.effective_config.packaged_defaults,
        catalogs={
            "process_catalog": {
                "industry:case-tools": {
                    "data": {
                        "builtins": [],
                        "document_terms": ["Case Notes"],
                        "custom": [
                            {
                                "id": "case-client",
                                "display_name": "Case Client",
                                "platforms": {
                                    "linux": {
                                        "image_path": "/opt/case/bin/case-client",
                                        "command_templates": ["case-client --open {document_term}"],
                                    }
                                },
                                "categories": ["user_app"],
                                "selection_weight": 7,
                                "singleton_per_session": False,
                            }
                        ],
                    }
                }
            },
            "application_catalog": {
                "organization:case-work": {
                    "data": {
                        "personas": ["organization:operator"],
                        "processes": ["industry:case-tools"],
                        "connections": {},
                    }
                }
            },
        },
    )

    applications, runtime = _application_graph(effective)

    assert {application["id"] for application in applications} == {"industry:case-client"}
    assert runtime["organization:case-work"]["application_ids"] == ["industry:case-client"]


def test_finance_pack_adapts_exact_app_destination_service_and_cadence() -> None:
    """Every generation-facing finance catalog field reaches its owning runtime family."""

    compiled = compile_scenario("tests/fixtures/scenarios/finance-industry-pack.yaml")

    with effective_config_scope(compiled.effective_config):
        runtime_apps = get_applications_for_ids(["finance:finance-reporting::excel"], "windows")
        dns = load_dns_registry()
        traffic = load_traffic_profiles()["pack_persona_traffic"]
        finance_browser = is_browser_application_process(
            ["finance:finance-browser::chrome"],
            "windows",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
        legacy_fallback = get_persona_connections("finance:finance_operations", "windows")

    assert len(runtime_apps) == 1
    platform = runtime_apps[0]["platforms"]["windows"]
    command = parameterize_scoped_command(
        random.Random(7),
        'EXCEL.EXE "{spreadsheet_path}"',
        platform,
    )
    assert any(term in command for term in ("reconciliation", "settlement", "close", "variance"))

    endpoint = next(item for item in dns["domains"] if item["domain"] == "payments.finance.example")
    assert endpoint["ips"] == ["192.0.2.80"]
    assert "finance:payment-network" in endpoint["tags"]

    group = traffic["finance:finance_operations"]["finance:settlement-window"]
    assert group["cadence"] == {
        "pattern": "weighted",
        "days": ["mon", "tue", "wed", "thu", "fri"],
        "windows": [{"start": "15:00", "end": "18:00"}],
    }
    connection = group["outbound"][0]
    assert connection["port"] == 443
    assert connection["service"] == "ssl"
    assert connection["dns_tags"] == ["finance:payment-network"]
    assert connection["application_ids"] == ["finance:finance-browser::chrome"]
    assert finance_browser is True
    assert legacy_fallback == []


def test_finance_pack_generation_preserves_exact_browser_process(tmp_path: Path) -> None:
    """A bound Chrome application owns its payment flows even when host affinity differs."""

    repository_root = Path(__file__).resolve().parents[2]
    scenario = repository_root / "tests/fixtures/scenarios/finance-industry-pack.yaml"
    output = tmp_path / "output"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "42",
        ],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    records = [
        json.loads(line)
        for path in (output / "data").rglob("ecar.json")
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    payment_flows = [
        record
        for record in records
        if record.get("object") == "FLOW"
        and record.get("properties", {}).get("dst_ip") == "192.0.2.80"
    ]

    assert payment_flows
    assert {
        record.get("properties", {}).get("image_path", "").replace("\\", "/").rsplit("/", 1)[-1]
        for record in payment_flows
    } == {"chrome.exe"}


def test_singleton_exact_pack_application_reuses_process_for_scheduled_connections(
    tmp_path: Path,
) -> None:
    """Exact traffic finds its singleton after bounded process history evicts it."""

    pack_root = tmp_path / ".eforge" / "packs" / "industry" / "singleton-app" / "1.0.0"
    catalogs = pack_root / "catalogs"
    catalogs.mkdir(parents=True)
    _write_yaml(
        pack_root / "pack.yaml",
        {
            "pack_schema_version": "1.0",
            "type": "industry",
            "name": "singleton-app",
            "version": "1.0.0",
            "requires_evidenceforge": ">=2.0.0,<3.0.0",
            "description": "Synthetic singleton application regression pack.",
            "industry_dependencies": [],
        },
    )
    _write_yaml(
        catalogs / "persona_catalog.yaml",
        {
            "persona_catalog": {
                "operator": {
                    "name": "operator",
                    "description": "Synthetic singleton application operator.",
                    "typical_activities": ["Synchronize records"],
                    "work_hours": "8am-6pm",
                    "application_usage": ["Singleton Client"],
                    "risk_profile": "medium",
                    "browsing_intensity": "light",
                }
            }
        },
    )
    _write_yaml(
        catalogs / "process_catalog.yaml",
        {
            "process_catalog": {
                "client-tools": {
                    "description": "Synthetic singleton desktop client.",
                    "data": {
                        "builtins": [],
                        "custom": [
                            {
                                "id": "singleton-client",
                                "display_name": "Singleton Client",
                                "platforms": {
                                    "windows": {
                                        "image_path": (
                                            r"C:\Program Files\Singleton Client\singleton-client.exe"
                                        ),
                                        "command_templates": ["singleton-client.exe --sync"],
                                    }
                                },
                                "categories": ["user_app"],
                                "selection_weight": 10,
                                "singleton_per_session": True,
                            }
                        ],
                        "document_terms": [],
                    },
                }
            }
        },
    )
    _write_yaml(
        catalogs / "application_catalog.yaml",
        {
            "application_catalog": {
                "records-client": {
                    "description": "Synthetic exact application binding.",
                    "data": {
                        "personas": ["operator"],
                        "processes": ["client-tools"],
                        "connections": {"api": {"destination": "records-api", "service": "web"}},
                    },
                }
            }
        },
    )
    _write_yaml(
        catalogs / "destination_catalog.yaml",
        {
            "destination_catalog": {
                "records-api": {
                    "description": "Synthetic exact application destination.",
                    "data": {
                        "tags": ["records"],
                        "endpoints": [
                            {
                                "domain": "records.singleton.example",
                                "ips": ["192.0.2.211"],
                            }
                        ],
                        "services": {"web": {"protocol": "https"}},
                    },
                }
            }
        },
    )
    _write_yaml(
        catalogs / "traffic_catalog.yaml",
        {
            "traffic_catalog": {
                "scheduled-sync": {
                    "description": "Two scheduled exact application connections.",
                    "data": {
                        "audience": ["operator"],
                        "applications": [
                            {
                                "application": "records-client",
                                "connection": "api",
                                "weight": 1,
                            }
                        ],
                        "outbound": [],
                        "cadence": {
                            "pattern": "burst",
                            "days": ["mon"],
                            "windows": [
                                {"start": "10:25", "end": "10:40"},
                                {"start": "11:30", "end": "12:00"},
                            ],
                            "jitter_minutes": 0,
                            "burst_count": [1, 1],
                        },
                    },
                }
            }
        },
    )
    _write_yaml(catalogs / "storage_catalog.yaml", {"storage_catalog": {}})

    scenario = tmp_path / "scenario.yaml"
    _write_yaml(
        scenario,
        {
            "scenario_version": "2.0",
            "composition": {
                "industries": [{"source": "project", "name": "singleton-app", "version": "1.0.0"}]
            },
            "name": "singleton-exact-application-regression",
            "description": "Exercise repeated exact singleton application traffic.",
            "time_window": {
                "start": "2026-08-17T10:00:00Z",
                "duration": "2h",
                "warmup": "1h",
            },
            "environment": {
                "description": "Synthetic singleton application workstation.",
                "timezone": {"default": "UTC"},
                "users": [
                    {
                        "username": "casey.park",
                        "full_name": "Casey Park",
                        "email": "casey.park@singleton.example",
                        "persona": "singleton-app:operator",
                        "primary_system": "SINGLETON-WS-01",
                    }
                ],
                "systems": [
                    {
                        "hostname": "SINGLETON-WS-01",
                        "ip": "10.77.10.21",
                        "os": "Windows 11",
                        "type": "workstation",
                        "assigned_user": "casey.park",
                        "roles": ["workstation"],
                    }
                ],
            },
            "baseline_activity": {
                "description": "Normal singleton application activity.",
                "intensity": "low",
                "variation": "medium",
                "suspicious_noise": "low",
            },
            "storyline": [
                {
                    "id": f"history-fill-{index:02}",
                    "time": f"2026-08-17T10:{42 + index:02}:00Z",
                    "actor": "casey.park",
                    "system": "SINGLETON-WS-01",
                    "activity": "Run an intervening foreground utility.",
                    "events": [
                        {
                            "type": "process",
                            "process_name": (
                                rf"C:\Program Files\History Fill\history-fill-{index:02}.exe"
                            ),
                            "command_line": f"history-fill-{index:02}.exe --refresh",
                        }
                    ],
                }
                for index in range(12)
            ],
            "output": {
                "logs": [{"format": "ecar"}],
                "destination": "./output",
                "compression": False,
            },
        },
    )

    repository_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "output"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
            "--seed",
            "42",
        ],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    records = [
        json.loads(line)
        for path in (output / "data").rglob("ecar.json")
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    process_creates = [
        record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and record.get("properties", {})
        .get("image_path", "")
        .replace("\\", "/")
        .endswith("/singleton-client.exe")
    ]
    application_flows = [
        record
        for record in records
        if record.get("object") == "FLOW"
        and record.get("properties", {}).get("dst_ip") == "192.0.2.211"
    ]
    history_fill_creates = [
        record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and "/history-fill-"
        in record.get("properties", {}).get("image_path", "").replace("\\", "/")
    ]

    assert len(process_creates) == 1
    assert len(application_flows) == 2
    assert {record.get("pid") for record in application_flows} == {process_creates[0]["pid"]}
    first_flow, second_flow = sorted(
        application_flows,
        key=lambda record: record["timestamp_ms"],
    )
    intervening_creates = [
        record
        for record in history_fill_creates
        if first_flow["timestamp_ms"] < record["timestamp_ms"] < second_flow["timestamp_ms"]
    ]
    assert len(intervening_creates) > 10


def test_custom_process_and_low_level_traffic_are_runtime_effective() -> None:
    """Custom process definitions and low-level outbound rows survive pure adapters."""

    compiled = compile_scenario("tests/fixtures/scenarios/finance-industry-pack.yaml")
    effective = SimpleNamespace(
        packaged_defaults=compiled.effective_config.packaged_defaults,
        catalogs={
            "process_catalog": {
                "custom:tools": {
                    "data": {
                        "builtins": [],
                        "document_terms": ["Case Notes"],
                        "custom": [
                            {
                                "id": "case-client",
                                "display_name": "Case Client",
                                "platforms": {
                                    "linux": {
                                        "image_path": "/opt/case/bin/case-client",
                                        "command_templates": ["case-client --open {document_term}"],
                                    }
                                },
                                "categories": ["user_app"],
                                "selection_weight": 7,
                                "singleton_per_session": False,
                            }
                        ],
                    }
                }
            },
            "application_catalog": {
                "custom:case-work": {
                    "data": {
                        "personas": ["custom:operator"],
                        "processes": ["custom:tools"],
                        "connections": {},
                    }
                }
            },
            "destination_catalog": {
                "custom:updates": {
                    "data": {
                        "tags": ["updates"],
                        "endpoints": [{"domain": "updates.custom.example", "ips": ["192.0.2.44"]}],
                        "services": {"web": {"protocol": "https"}},
                    }
                }
            },
            "traffic_catalog": {
                "custom:heartbeat": {
                    "data": {
                        "audience": ["custom:operator"],
                        "applications": [],
                        "outbound": [
                            {
                                "role": "_external",
                                "port": 443,
                                "proto": "tcp",
                                "service": "ssl",
                                "weight": 2,
                                "os": "linux",
                                "emit_dns": True,
                                "dns_tags": ["updates"],
                            }
                        ],
                        "cadence": {
                            "pattern": "periodic",
                            "interval_minutes": 30,
                            "jitter_minutes": 2,
                        },
                    }
                }
            },
        },
    )

    apps, runtime = _application_graph(effective)
    destinations = _destination_overlay(effective)
    traffic = _traffic_overlay(effective)

    custom = next(app for app in apps if app["id"] == "custom:case-client")
    assert custom["platforms"]["linux"]["image_path"] == "/opt/case/bin/case-client"
    assert custom["platforms"]["linux"]["command_templates"] == [
        "case-client --open {document_term}"
    ]
    assert runtime["custom:case-work"]["application_ids"] == ["custom:case-client"]
    assert destinations is not None
    assert destinations["domains"][0]["tags"] == ["custom:updates"]
    assert traffic is not None
    connection = traffic["pack_persona_traffic"]["custom:operator"]["custom:heartbeat"]["outbound"][
        0
    ]
    assert connection["dns_tags"] == ["custom:updates"]
    assert connection["os"] == "linux"
    assert connection["weight"] == 2


def test_destination_adapter_preserves_builtin_and_qualified_custom_tags() -> None:
    """Public tags remain data-driven and already-qualified tags are not qualified twice."""

    compiled = compile_scenario("tests/fixtures/scenarios/finance-industry-pack.yaml")
    effective = SimpleNamespace(
        packaged_defaults=compiled.effective_config.packaged_defaults,
        catalogs={
            "destination_catalog": {
                "custom:portal": {
                    "data": {
                        "tags": ["web", "custom:regulated"],
                        "endpoints": [{"domain": "portal.custom.example", "ips": ["192.0.2.45"]}],
                        "services": {"web": {"protocol": "https"}},
                    }
                }
            }
        },
    )

    destinations = _destination_overlay(effective)

    assert destinations is not None
    assert destinations["domains"][0]["tags"] == [
        "custom:portal",
        "web",
        "custom:regulated",
    ]
    assert "custom:custom:regulated" not in destinations["valid_tags"]
