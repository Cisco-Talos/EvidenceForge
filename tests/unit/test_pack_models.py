# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused public-schema and whole-pack semantic validation tests."""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import ValidationError

from evidenceforge.composition.models import (
    ApplicationCatalogDocument,
    BaselineActivityFragment,
    DestinationCatalogDocument,
    EnvironmentFragment,
    PackManifest,
    ProcessCatalogDocument,
    StorageCatalogDocument,
    TrafficCatalogDocument,
)
from evidenceforge.composition.semantic_validation import (
    packaged_builtin_application_ids,
    packaged_builtin_dns_domains,
    packaged_builtin_dns_tags,
    packaged_builtin_executable_claims,
    packaged_builtin_persona_ids,
    packaged_builtin_storage_preset_ids,
    validate_selected_pack_semantics,
)
from evidenceforge.generation.activity.application_catalog import parameterize_scoped_command
from evidenceforge.generation.activity.helpers import _parameterize_command
from evidenceforge.models.exceptions import PackError
from evidenceforge.models.scenario import User


def _custom_process(*, process_id: str = "case-client", image: str = "caseclient.exe") -> dict:
    """Return one valid portable custom Windows process definition."""

    return {
        "id": process_id,
        "display_name": "Case Client",
        "platforms": {
            "windows": {
                "image_path": rf"C:\Program Files\Case Client\{image}",
                "command_templates": [
                    rf'"C:\Program Files\Case Client\{image}" --case "{{document_term}}"'
                ],
                "pe_metadata": {
                    "file_version": "1.2.3.4",
                    "description": "Case Client",
                    "product": "Case Suite",
                    "company": "Example Corp",
                    "original_filename": image,
                },
                "children": [f'{image} --worker "{{document_path}}"'],
                "loaded_modules": [
                    {
                        "path": r"C:\Program Files\Case Client\caseclient.dll",
                        "signature": "Example Corp",
                        "pe_metadata": {
                            "file_version": "1.2.3.4",
                            "description": "Case Client Library",
                            "product": "Case Suite",
                            "company": "Example Corp",
                            "original_filename": "caseclient.dll",
                        },
                    }
                ],
            }
        },
        "categories": ["user_app", "office"],
        "system_types": ["workstation"],
        "selection_weight": 7,
        "singleton_per_session": True,
    }


def _process_document(*, custom: list[dict] | None = None) -> dict:
    """Return one valid process catalog document."""

    return {
        "process_catalog": {
            "case-workflow": {
                "description": "Case workflow",
                "data": {
                    "builtins": ["chrome"],
                    "custom": custom or [],
                    "document_terms": ["Case Review", "open-items"],
                },
            }
        }
    }


def _destination_document(*, domain: str = "portal.example.test") -> dict:
    """Return one valid destination catalog document."""

    return {
        "destination_catalog": {
            "case-portal": {
                "description": "Case portal",
                "data": {
                    "tags": ["case", "saas"],
                    "endpoints": [{"domain": domain, "ips": ["192.0.2.40", "2001:db8::40"]}],
                    "services": {
                        "web": {"protocol": "https"},
                        "database": {"protocol": "postgresql", "port": 55432},
                    },
                },
            }
        }
    }


def _application_document(*, personas: list[str] | None = None) -> dict:
    """Return one valid application catalog document."""

    return {
        "application_catalog": {
            "case-management": {
                "description": "Case management",
                "data": {
                    "personas": personas or ["case-worker"],
                    "processes": ["case-workflow"],
                    "connections": {"portal": {"destination": "case-portal", "service": "web"}},
                },
            }
        }
    }


def _traffic_document(*, audience: list[str] | None = None) -> dict:
    """Return one valid application-backed traffic catalog document."""

    return {
        "traffic_catalog": {
            "case-activity": {
                "description": "Case activity",
                "data": {
                    "audience": audience or ["case-worker"],
                    "applications": [
                        {
                            "application": "case-management",
                            "connection": "portal",
                            "weight": 8,
                        }
                    ],
                    "outbound": [],
                    "cadence": {
                        "pattern": "periodic",
                        "days": ["mon", "tue", "wed", "thu", "fri"],
                        "windows": [{"start": "22:00", "end": "02:00"}],
                        "interval_minutes": 60,
                        "jitter_minutes": 10,
                    },
                },
            }
        }
    }


def _storage_document() -> dict:
    """Return one valid bounded storage vocabulary."""

    return {
        "storage_catalog": {
            "case-files": {
                "description": "Case files",
                "data": {
                    "directories": ["Records", "Case Reviews"],
                    "subjects": ["case-summary", "open items"],
                    "files": [
                        {"extension": ".pdf", "mime": "application/pdf", "weight": 3},
                        {
                            "extension": ".efx",
                            "mime": "application/x-evidenceforge",
                            "weight": 1,
                        },
                    ],
                },
            }
        }
    }


def _persona(name: str = "case-worker") -> dict:
    """Return one valid pack persona."""

    return {
        "name": name,
        "description": "Case worker",
        "typical_activities": ["Review cases"],
        "work_hours": "9am-5pm",
        "application_usage": ["Case management"],
        "risk_profile": "medium",
        "browsing_intensity": "normal",
    }


@dataclass
class _Pack:
    """Minimal loaded-pack shape consumed by semantic validation."""

    manifest: PackManifest
    catalogs: dict[str, dict[str, Any]]
    source: str = "project"
    environment: dict[str, Any] = field(default_factory=dict)
    baseline_activity: dict[str, Any] = field(default_factory=dict)


def _industry_pack(
    name: str = "cases",
    *,
    domain: str = "portal.example.test",
    custom: list[dict] | None = None,
) -> _Pack:
    """Return a semantically complete industry pack without filesystem concerns."""

    return _Pack(
        manifest=PackManifest(
            pack_schema_version="1.0",
            type="industry",
            name=name,
            version="1.0.0",
            description="Cases industry",
        ),
        catalogs={
            "persona_catalog": {f"{name}:case-worker": _persona(f"{name}:case-worker")},
            "process_catalog": {
                f"{name}:case-workflow": _process_document(custom=custom)["process_catalog"][
                    "case-workflow"
                ]
            },
            "application_catalog": {
                f"{name}:case-management": _application_document()["application_catalog"][
                    "case-management"
                ]
            },
            "destination_catalog": {
                f"{name}:case-portal": _destination_document(domain=domain)["destination_catalog"][
                    "case-portal"
                ]
            },
            "traffic_catalog": {
                f"{name}:case-activity": _traffic_document()["traffic_catalog"]["case-activity"]
            },
            "storage_catalog": {},
        },
    )


def _validate_semantics(
    packs: list[_Pack],
    *,
    builtin_application_ids: set[str],
    builtin_executable_claims: set[str] | None = None,
    builtin_dns_domains: set[str] | None = None,
    builtin_persona_ids: set[str] | None = None,
    builtin_storage_preset_ids: set[str] | None = None,
) -> None:
    """Validate a test composition with a small deterministic built-in registry."""

    validate_selected_pack_semantics(
        packs,
        builtin_application_ids=builtin_application_ids,
        builtin_dns_tags={"background", "saas", "web"},
        builtin_executable_claims=builtin_executable_claims or set(),
        builtin_dns_domains=builtin_dns_domains or set(),
        builtin_persona_ids=builtin_persona_ids or set(),
        builtin_storage_preset_ids=builtin_storage_preset_ids or set(),
    )


def test_runtime_effective_catalog_models_accept_complete_contract() -> None:
    """Every new public catalog shape is strictly typed and serializable."""

    process = ProcessCatalogDocument.model_validate(_process_document(custom=[_custom_process()]))
    application = ApplicationCatalogDocument.model_validate(_application_document())
    destination = DestinationCatalogDocument.model_validate(_destination_document())
    traffic = TrafficCatalogDocument.model_validate(_traffic_document())

    assert process.process_catalog["case-workflow"].data.custom[0].selection_weight == 7
    assert (
        application.application_catalog["case-management"].data.connections["portal"].service
        == "web"
    )
    services = destination.destination_catalog["case-portal"].data.services
    assert services["web"].resolved_port == 443
    assert services["database"].resolved_port == 55432
    cadence = traffic.traffic_catalog["case-activity"].data.cadence
    assert cadence is not None and cadence.pattern == "periodic"
    assert cadence.windows[0].duration_minutes == 240


def test_storage_catalog_accepts_canonical_and_extensible_file_types() -> None:
    """Known extensions use canonical MIME while safe unknown extensions remain extensible."""

    document = StorageCatalogDocument.model_validate(_storage_document())
    files = document.storage_catalog["case-files"].data.files

    assert [(file_type.extension, file_type.mime) for file_type in files] == [
        (".pdf", "application/pdf"),
        (".efx", "application/x-evidenceforge"),
    ]


@pytest.mark.parametrize(
    "directory",
    [
        "",
        "   ",
        "/absolute",
        r"C:\Cases",
        r"\\server\share",
        "../escape",
        "Cases/Reports",
        r"Cases\Reports",
        "Cases:Reports",
        "Cases\nReports",
        "a" * 129,
    ],
)
def test_storage_catalog_rejects_unsafe_directory_components(directory: str) -> None:
    """Storage directories cannot escape or create ambiguous filesystem components."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"]["directories"] = [directory]

    with pytest.raises(ValidationError, match="storage directories"):
        StorageCatalogDocument.model_validate(raw)


@pytest.mark.parametrize(
    "subject",
    ["", "   ", "../secret", "case.pdf", "case/report", "$(payload)", "a" * 65],
)
def test_storage_catalog_rejects_unsafe_subject_stems(subject: str) -> None:
    """Generated file subjects remain bounded extension-free stems."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"]["subjects"] = [subject]

    with pytest.raises(ValidationError, match="storage subjects"):
        StorageCatalogDocument.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "values", "message"),
    [
        ("directories", ["Records", "records"], "directories.*duplicates"),
        ("subjects", ["Case", "case"], "subjects.*duplicates"),
        (
            "files",
            [
                {"extension": ".PDF", "mime": "application/pdf"},
                {"extension": ".pdf", "mime": "application/pdf"},
            ],
            "extensions.*duplicates",
        ),
    ],
)
def test_storage_catalog_rejects_case_insensitive_duplicates(
    field: str,
    values: list[Any],
    message: str,
) -> None:
    """Case-insensitive target filesystems cannot receive ambiguous vocabulary."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"][field] = values

    with pytest.raises(ValidationError, match=message):
        StorageCatalogDocument.model_validate(raw)


@pytest.mark.parametrize("mime", ["application", "text/ plain", "text/plain; charset=utf-8"])
def test_storage_catalog_rejects_invalid_mime_syntax(mime: str) -> None:
    """File types require one parameter-free MIME type/subtype token."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"]["files"] = [{"extension": ".efx", "mime": mime}]

    with pytest.raises(ValidationError, match="MIME"):
        StorageCatalogDocument.model_validate(raw)


def test_storage_catalog_enforces_common_extension_mime_mapping() -> None:
    """A familiar extension cannot contaminate runtime MIME identity."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"]["files"] = [
        {"extension": ".pdf", "mime": "text/plain"}
    ]

    with pytest.raises(ValidationError, match="requires canonical MIME 'application/pdf'"):
        StorageCatalogDocument.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "values"),
    [
        ("directories", [f"directory-{index}" for index in range(129)]),
        ("subjects", [f"subject-{index}" for index in range(129)]),
        (
            "files",
            [
                {"extension": f".x{index}", "mime": "application/x-evidenceforge"}
                for index in range(33)
            ],
        ),
    ],
)
def test_storage_catalog_bounds_vocabulary_sizes(field: str, values: list[Any]) -> None:
    """Authored storage vocabularies cannot grow without a deterministic bound."""

    raw = _storage_document()
    raw["storage_catalog"]["case-files"]["data"][field] = values

    with pytest.raises(ValidationError, match="too_long"):
        StorageCatalogDocument.model_validate(raw)


def test_local_only_application_may_omit_connections() -> None:
    """An application can affect process selection without generating network traffic."""

    raw = _application_document()
    raw["application_catalog"]["case-management"]["data"].pop("connections")

    document = ApplicationCatalogDocument.model_validate(raw)

    assert document.application_catalog["case-management"].data.connections == {}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("document_terms", ["safe", "../../escape"], "safe filename stems"),
        ("document_terms", ["safe", "$(touch owned)"], "safe filename stems"),
        ("builtins", [], "at least one of builtins or custom"),
    ],
)
def test_process_catalog_rejects_inert_or_unsafe_data(
    field: str,
    value: list[str],
    message: str,
) -> None:
    """Process profiles cannot be empty or inject syntax through document data."""

    raw = _process_document()
    raw["process_catalog"]["case-workflow"]["data"][field] = value

    with pytest.raises(ValidationError, match=message):
        ProcessCatalogDocument.model_validate(raw)


def test_custom_process_requires_schedulable_category_and_native_paths() -> None:
    """Custom processes must map to a real generator activity on a typed platform."""

    unschedulable = _custom_process()
    unschedulable["categories"] = ["browser", "office"]
    with pytest.raises(ValidationError, match="schedulable category"):
        ProcessCatalogDocument.model_validate(_process_document(custom=[unschedulable]))

    relative_linux = _custom_process()
    relative_linux["platforms"] = {
        "linux": {"image_path": "usr/bin/case", "command_templates": ["case --list"]}
    }
    with pytest.raises(ValidationError, match="absolute POSIX path"):
        ProcessCatalogDocument.model_validate(_process_document(custom=[relative_linux]))


@pytest.mark.parametrize(
    ("field", "command", "message"),
    [
        ("command_templates", 'caseclient.exe --case "{unknown_value}"', "unsupported"),
        ("command_templates", 'caseclient.exe --case "{document_path"', "malformed braces"),
        ("command_templates", "/usr/bin/caseclient --case safe", "Windows drive path"),
        ("children", "/usr/bin/renderer --type worker", "Windows drive path"),
        ("children", 'case-renderer.exe --open "{unknown_value}"', "unsupported"),
    ],
)
def test_custom_process_rejects_unknown_placeholders_and_cross_os_commands(
    field: str,
    command: str,
    message: str,
) -> None:
    """Authored command templates cannot retain braces or cross OS boundaries."""

    custom = _custom_process()
    custom["platforms"]["windows"][field] = [command]

    with pytest.raises(ValidationError, match=message):
        ProcessCatalogDocument.model_validate(_process_document(custom=[custom]))


def test_custom_linux_process_rejects_windows_command_shape() -> None:
    """A Linux custom executable cannot emit a Windows command line."""

    custom = _custom_process()
    custom["platforms"] = {
        "linux": {
            "image_path": "/opt/cases/caseclient",
            "command_templates": [r"C:\Program Files\Cases\caseclient.exe --case safe"],
        }
    }

    with pytest.raises(ValidationError, match="POSIX executable"):
        ProcessCatalogDocument.model_validate(_process_document(custom=[custom]))


def test_custom_document_placeholder_requires_terms_and_resolves_at_runtime() -> None:
    """A schema-valid authored template has a runtime pool that leaves no unknown braces."""

    raw = _process_document(custom=[_custom_process()])
    document = ProcessCatalogDocument.model_validate(raw)
    platform = document.process_catalog["case-workflow"].data.custom[0].platforms["windows"]
    runtime_platform = platform.model_dump(mode="python")
    runtime_platform["command_parameter_pools"] = {
        "document_term": ["Case Review"],
        "document_path": [r"C:\Users\{username}\Documents\Case Review.docx"],
    }
    rendered = parameterize_scoped_command(
        random.Random(7),
        platform.command_templates[0],
        runtime_platform,
    )
    rendered = _parameterize_command(random.Random(7), rendered, username="analyst")
    assert "{" not in rendered and "}" not in rendered

    raw["process_catalog"]["case-workflow"]["data"]["document_terms"] = []
    with pytest.raises(ValidationError, match="document placeholders require"):
        ProcessCatalogDocument.model_validate(raw)


def test_catalogs_reject_prototype_inert_fields_and_qualified_export_keys() -> None:
    """The unreleased prototype shape cannot silently survive into pack schema 1.0."""

    with pytest.raises(ValidationError, match="process_names"):
        ProcessCatalogDocument.model_validate(
            {
                "process_catalog": {
                    "old": {"data": {"process_names": ["chrome.exe"], "document_terms": []}}
                }
            }
        )
    with pytest.raises(ValidationError, match="category"):
        ApplicationCatalogDocument.model_validate(
            {
                "application_catalog": {
                    "old": {"data": {"category": "legacy", "protocols": ["https"]}}
                }
            }
        )
    raw = _destination_document()
    raw["destination_catalog"]["cases:portal"] = raw["destination_catalog"].pop("case-portal")
    with pytest.raises(ValidationError, match="without colons"):
        DestinationCatalogDocument.model_validate(raw)


def test_pack_manifest_requires_canonical_semver() -> None:
    """Persisted pack identities reject ambiguous leading-zero numeric identifiers."""

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        PackManifest(
            pack_schema_version="1.0",
            type="industry",
            name="cases",
            version="01.0.0",
            description="Cases",
        )


@pytest.mark.parametrize("raw_version", [None, "2.0"])
def test_pack_manifest_requires_supported_schema_version(raw_version: str | None) -> None:
    """Manifest schema dispatch cannot silently default or accept an unknown version."""

    raw: dict[str, Any] = {
        "type": "industry",
        "name": "cases",
        "version": "1.0.0",
        "description": "Cases",
    }
    if raw_version is not None:
        raw["pack_schema_version"] = raw_version

    with pytest.raises(ValidationError, match="pack_schema_version"):
        PackManifest.model_validate(raw)


def test_destination_validates_domains_addresses_and_service_protocols() -> None:
    """Stable endpoint pools and their service registry reject malformed identities."""

    raw = _destination_document()
    raw["destination_catalog"]["case-portal"]["data"]["endpoints"][0]["ips"] = ["not-an-ip"]
    with pytest.raises(ValidationError, match="invalid endpoint IP"):
        DestinationCatalogDocument.model_validate(raw)

    raw = _destination_document(domain="https://portal.example.test/path")
    with pytest.raises(ValidationError, match="bare hostname"):
        DestinationCatalogDocument.model_validate(raw)

    raw = _destination_document()
    raw["destination_catalog"]["case-portal"]["data"]["services"]["web"] = {"protocol": "rdp"}
    with pytest.raises(ValidationError, match="literal_error"):
        DestinationCatalogDocument.model_validate(raw)


def test_cadence_variants_enforce_pattern_specific_bounds() -> None:
    """Cadence fields cannot be accepted when their runtime pattern would ignore them."""

    raw = _traffic_document()
    cadence = raw["traffic_catalog"]["case-activity"]["data"]["cadence"]
    cadence["jitter_minutes"] = 31
    with pytest.raises(ValidationError, match="half interval_minutes"):
        TrafficCatalogDocument.model_validate(raw)

    raw = _traffic_document()
    raw["traffic_catalog"]["case-activity"]["data"]["cadence"] = {
        "pattern": "weighted",
        "jitter_minutes": 1,
    }
    with pytest.raises(ValidationError, match="jitter_minutes"):
        TrafficCatalogDocument.model_validate(raw)

    raw = _traffic_document()
    raw["traffic_catalog"]["case-activity"]["data"]["cadence"] = {
        "pattern": "burst",
        "windows": [{"start": "09:00", "end": "10:00"}],
        "burst_count": [2, 5],
        "jitter_minutes": 31,
    }
    with pytest.raises(ValidationError, match="half the shortest window"):
        TrafficCatalogDocument.model_validate(raw)

    raw = _traffic_document()
    raw["traffic_catalog"]["case-activity"]["data"]["cadence"] = {
        "pattern": "burst",
        "burst_count": [1, 51],
    }
    with pytest.raises(ValidationError, match="bound <= 50"):
        TrafficCatalogDocument.model_validate(raw)


def test_partial_organization_fragments_validate_nested_values() -> None:
    """Partial fragments may omit siblings but cannot defer nested schema validation."""

    fragment = EnvironmentFragment.model_validate(
        {
            "environment": {
                "users": [
                    {
                        "username": "analyst",
                        "full_name": "Case Analyst",
                        "email": "analyst@example.test",
                        "persona": "cases:case-worker",
                    }
                ]
            }
        }
    )
    assert fragment.model_dump(mode="json")["environment"]["users"][0]["username"] == "analyst"

    with pytest.raises(ValidationError, match="Invalid email format"):
        EnvironmentFragment.model_validate(
            {
                "environment": {
                    "users": [
                        {
                            "username": "analyst",
                            "full_name": "Case Analyst",
                            "email": "invalid",
                        }
                    ]
                }
            }
        )
    with pytest.raises(ValidationError, match="primary_sytem"):
        EnvironmentFragment.model_validate(
            {
                "environment": {
                    "users": [
                        {
                            "username": "analyst",
                            "full_name": "Case Analyst",
                            "email": "analyst@example.test",
                            "primary_sytem": "CASE-WS-01",
                        }
                    ]
                }
            }
        )
    with pytest.raises(ValidationError, match="traffic_rates"):
        BaselineActivityFragment.model_validate(
            {"baseline_activity": {"traffic_rates": {"not_a_runtime_rate": 1}}}
        )
    with pytest.raises(ValidationError, match="identty"):
        BaselineActivityFragment.model_validate(
            {
                "baseline_activity": {
                    "traffic_affinities": [
                        {
                            "name": "case-portal",
                            "kind": "connection",
                            "direction": "outbound",
                            "destination": {"identty": "case-portal"},
                        }
                    ]
                }
            }
        )


def test_organization_environment_fragment_serializes_explicit_proxy() -> None:
    """Organization packs can serialize an explicitly deployed forward proxy."""

    fragment = EnvironmentFragment.model_validate(
        {"environment": {"proxy": {"mode": "explicit", "listener_port": 8080}}}
    )

    assert fragment.model_dump(mode="json")["environment"]["proxy"] == {
        "mode": "explicit",
        "listener_port": 8080,
        "auth_policy": {
            "mode": "realistic",
            "allowlisted_domain_classes": [
                "windows_update",
                "windows_trust_list",
                "software_update",
                "telemetry",
                "crl",
                "ocsp",
            ],
            "non_human_principals": False,
            "machine_account_probability": 0.0,
            "service_account_probability": 0.0,
        },
    }


def test_pack_fragment_strictness_does_not_change_canonical_user_behavior() -> None:
    """Pack-only wrappers must not change permissive nested Scenario 1 models."""

    user = User.model_validate(
        {
            "username": "analyst",
            "full_name": "Case Analyst",
            "email": "analyst@example.test",
            "primary_sytem": "CASE-WS-01",
        }
    )

    assert user.primary_system is None


def test_whole_pack_semantics_accept_complete_local_reference_graph() -> None:
    """Local references resolve within an industry and builtins use the injected registry."""

    _validate_semantics(
        [_industry_pack(custom=[_custom_process()])],
        builtin_application_ids={"chrome", "excel"},
    )


def test_packaged_validation_registries_read_packaged_defaults() -> None:
    """Semantic validation obtains stable builtins directly from packaged YAML."""

    assert {"chrome", "excel", "acrobat"} <= packaged_builtin_application_ids()
    assert {"web", "saas", "background"} <= packaged_builtin_dns_tags()
    assert {
        "windows:basename:chrome.exe",
        "linux:basename:google-chrome",
    } <= packaged_builtin_executable_claims()
    assert {"www.google.com", "accounts.google.com"} <= packaged_builtin_dns_domains()
    assert {"developer", "data_analyst", "sysadmin"} <= packaged_builtin_persona_ids()
    assert {"collaboration", "department", "backup"} <= (packaged_builtin_storage_preset_ids())


def test_packaged_identity_registries_are_safe_with_no_selected_packs() -> None:
    """Immutable legacy registries do not require a pack to be selected."""

    _validate_semantics(
        [],
        builtin_application_ids=packaged_builtin_application_ids(),
        builtin_executable_claims=packaged_builtin_executable_claims(),
        builtin_dns_domains=packaged_builtin_dns_domains(),
    )


def test_semantics_rejects_pack_collisions_with_packaged_runtime_identities() -> None:
    """Packs cannot overlay legacy executable or DNS identities through composition."""

    parent_collision = _industry_pack(custom=[_custom_process(image="chrome.exe")])
    with pytest.raises(PackError, match="packaged builtin executable.*chrome.exe"):
        _validate_semantics(
            [parent_collision],
            builtin_application_ids={"chrome"},
            builtin_executable_claims={"windows:basename:chrome.exe"},
        )

    child = _custom_process()
    child["platforms"]["windows"]["children"] = ["chrome.exe --type=renderer"]
    child_collision = _industry_pack(custom=[child])
    with pytest.raises(PackError, match="packaged builtin executable.*chrome.exe"):
        _validate_semantics(
            [child_collision],
            builtin_application_ids={"chrome"},
            builtin_executable_claims={"windows:basename:chrome.exe"},
        )

    dns_collision = _industry_pack(domain="www.google.com")
    with pytest.raises(PackError, match="packaged DNS domain 'www.google.com'"):
        _validate_semantics(
            [dns_collision],
            builtin_application_ids={"chrome"},
            builtin_dns_domains={"www.google.com"},
        )


def test_whole_pack_semantics_reject_missing_builtin_service_and_persona_eligibility() -> None:
    """Generation-effective links fail at the field that would otherwise become inert."""

    unknown_builtin = _industry_pack()
    unknown_builtin.catalogs["process_catalog"]["cases:case-workflow"]["data"]["builtins"] = [
        "not-installed"
    ]
    with pytest.raises(PackError, match="unknown builtin application ID"):
        _validate_semantics([unknown_builtin], builtin_application_ids={"chrome", "excel"})

    missing_service = _industry_pack()
    connection = missing_service.catalogs["application_catalog"]["cases:case-management"]["data"][
        "connections"
    ]["portal"]
    connection["service"] = "missing"
    with pytest.raises(PackError, match="missing service"):
        _validate_semantics([missing_service], builtin_application_ids={"chrome", "excel"})

    disallowed = _industry_pack()
    disallowed.catalogs["persona_catalog"]["cases:auditor"] = _persona("cases:auditor")
    disallowed.catalogs["traffic_catalog"]["cases:case-activity"]["data"]["audience"] = ["auditor"]
    with pytest.raises(PackError, match="not allowed by that application"):
        _validate_semantics([disallowed], builtin_application_ids={"chrome", "excel"})


def test_industry_cannot_reference_peer_namespace_even_when_selected() -> None:
    """Industry peers do not gain an implicit dependency language through composition order."""

    cases = _industry_pack()
    audits = _industry_pack("audits", domain="audit.example.test")
    cases.catalogs["application_catalog"]["cases:case-management"]["data"]["personas"] = [
        "audits:case-worker"
    ]

    with pytest.raises(PackError, match="undeclared pack namespace 'audits'"):
        _validate_semantics([cases, audits], builtin_application_ids={"chrome", "excel"})


@pytest.mark.parametrize(
    ("source", "version"),
    [("package", "1.0.0"), ("project", "1.1.0")],
)
def test_selected_pack_namespace_requires_one_exact_identity(source: str, version: str) -> None:
    """Disjoint or empty exports cannot make one namespace identify two selected packs."""

    catalogs = {
        "persona_catalog": {},
        "process_catalog": {},
        "application_catalog": {},
        "destination_catalog": {},
        "traffic_catalog": {},
        "storage_catalog": {},
    }
    first = _Pack(
        manifest=PackManifest(
            pack_schema_version="1.0",
            type="industry",
            name="cases",
            version="1.0.0",
            description="Cases industry",
        ),
        catalogs=copy.deepcopy(catalogs),
        source="project",
    )
    second = _Pack(
        manifest=PackManifest(
            pack_schema_version="1.0",
            type="industry",
            name="cases",
            version=version,
            description="Other cases industry",
        ),
        catalogs=copy.deepcopy(catalogs),
        source=source,
    )

    with pytest.raises(PackError, match="share namespace 'cases'.*different exact identities"):
        _validate_semantics([first, second], builtin_application_ids={"chrome"})


def test_low_level_dns_tags_resolve_builtin_or_visible_custom_destinations() -> None:
    """Low-level DNS selection cannot name a nonexistent or undeclared custom tag."""

    pack = _industry_pack()
    application_data = pack.catalogs["application_catalog"]["cases:case-management"]["data"]
    application_data["connections"] = {}
    traffic_data = pack.catalogs["traffic_catalog"]["cases:case-activity"]["data"]
    traffic_data["applications"] = []
    traffic_data["outbound"] = [
        {
            "role": "_external",
            "port": 443,
            "service": "ssl",
            "emit_dns": True,
            "dns_tags": ["case"],
        },
        {
            "role": "_external",
            "port": 443,
            "service": "ssl",
            "emit_dns": True,
            "dns_tags": ["background"],
        },
    ]

    _validate_semantics([pack], builtin_application_ids={"chrome"})

    traffic_data["outbound"][0]["dns_tags"] = ["missing"]
    with pytest.raises(PackError, match="unknown built-in or visible custom DNS tag"):
        _validate_semantics([pack], builtin_application_ids={"chrome"})


def test_semantics_reject_orphan_process_connection_and_destination_exports() -> None:
    """Catalog definitions must have a runtime consumer rather than provenance-only presence."""

    orphan_process = _industry_pack()
    orphan_process.catalogs["process_catalog"]["cases:unused"] = copy.deepcopy(
        orphan_process.catalogs["process_catalog"]["cases:case-workflow"]
    )
    with pytest.raises(PackError, match="orphan process profile"):
        _validate_semantics([orphan_process], builtin_application_ids={"chrome"})

    orphan_connection = _industry_pack()
    connections = orphan_connection.catalogs["application_catalog"]["cases:case-management"][
        "data"
    ]["connections"]
    connections["unused"] = {"destination": "case-portal", "service": "database"}
    with pytest.raises(PackError, match="orphan application connection"):
        _validate_semantics([orphan_connection], builtin_application_ids={"chrome"})

    orphan_destination = _industry_pack()
    unused = _destination_document(domain="unused.example.test")["destination_catalog"][
        "case-portal"
    ]
    orphan_destination.catalogs["destination_catalog"]["cases:unused"] = unused
    with pytest.raises(PackError, match="orphan destination export"):
        _validate_semantics([orphan_destination], builtin_application_ids={"chrome"})


def test_organization_may_reference_only_exact_pinned_dependency() -> None:
    """An organization model may consume its selected, exactly pinned industry personas."""

    industry = _industry_pack()
    organization = _Pack(
        manifest=PackManifest.model_validate(
            {
                "pack_schema_version": "1.0",
                "type": "organization",
                "name": "example-org",
                "version": "1.0.0",
                "description": "Example organization",
                "industry_dependencies": [
                    {
                        "source": "project",
                        "name": "cases",
                        "version": "1.0.0",
                    }
                ],
            }
        ),
        catalogs={name: {} for name in industry.catalogs},
        environment={
            "users": [
                {
                    "username": "analyst",
                    "full_name": "Case Analyst",
                    "email": "analyst@example.test",
                    "persona": "cases:case-worker",
                }
            ]
        },
        baseline_activity={
            "traffic_suppression": [
                {"audience": {"personas": ["cases:case-worker"]}, "factor": 0.5}
            ]
        },
    )

    _validate_semantics([industry, organization], builtin_application_ids={"chrome", "excel"})

    with pytest.raises(PackError, match="was not selected"):
        _validate_semantics([organization], builtin_application_ids={"chrome", "excel"})

    organization.baseline_activity["traffic_suppression"][0]["audience"]["personas"] = [
        "cases:missing-persona"
    ]
    with pytest.raises(PackError, match="baseline_activity.*missing export"):
        _validate_semantics([industry, organization], builtin_application_ids={"chrome", "excel"})


def test_organization_model_accepts_packaged_builtin_shorthand() -> None:
    """Organization fragments may use built-in persona and storage preset IDs directly."""

    organization = _Pack(
        manifest=PackManifest(
            pack_schema_version="1.0",
            type="organization",
            name="example-org",
            version="1.0.0",
            description="Example organization",
        ),
        catalogs={
            "persona_catalog": {},
            "process_catalog": {},
            "application_catalog": {},
            "destination_catalog": {},
            "traffic_catalog": {},
            "storage_catalog": {},
        },
        environment={
            "users": [
                {
                    "username": "developer",
                    "full_name": "Example Developer",
                    "email": "developer@example.test",
                    "persona": "developer",
                }
            ],
            "storage": {
                "servers": [
                    {
                        "system": "FILE-01",
                        "volumes": [{"id": "data", "mount": "D:\\"}],
                        "default_volume": "data",
                        "shares": [
                            {
                                "id": "department",
                                "name": "Department",
                                "volume": "data",
                                "preset": "department",
                            }
                        ],
                    }
                ]
            },
        },
        baseline_activity={
            "traffic_suppression": [{"audience": {"personas": ["developer"]}, "factor": 0.5}]
        },
    )

    _validate_semantics(
        [organization],
        builtin_application_ids={"chrome"},
        builtin_persona_ids={"developer"},
        builtin_storage_preset_ids={"department"},
    )

    organization.environment["storage"]["servers"][0]["shares"][0]["preset"] = "missing"
    with pytest.raises(PackError, match="missing export 'example-org:missing'"):
        _validate_semantics(
            [organization],
            builtin_application_ids={"chrome"},
            builtin_persona_ids={"developer"},
            builtin_storage_preset_ids={"department"},
        )


def test_whole_pack_semantics_reject_duplicate_domain_and_executable_claims() -> None:
    """Selected packs cannot depend on ordering for generated domains or process identity."""

    first = _industry_pack(custom=[_custom_process()])
    second = _industry_pack(
        "audits",
        domain="portal.example.test",
        custom=[_custom_process(process_id="audit-client", image="auditclient.exe")],
    )
    with pytest.raises(PackError, match="duplicates endpoint domain"):
        _validate_semantics([first, second], builtin_application_ids={"chrome", "excel"})

    second = _industry_pack(
        "audits",
        domain="audit.example.test",
        custom=[_custom_process(process_id="audit-client")],
    )
    with pytest.raises(PackError, match="duplicates executable claim"):
        _validate_semantics([first, second], builtin_application_ids={"chrome", "excel"})

    duplicate_custom_id = _industry_pack(custom=[_custom_process()])
    second_profile = copy.deepcopy(
        duplicate_custom_id.catalogs["process_catalog"]["cases:case-workflow"]
    )
    second_profile["data"]["builtins"] = []
    second_profile["data"]["custom"][0]["platforms"]["windows"]["image_path"] = (
        r"C:\Program Files\Different\different.exe"
    )
    second_profile["data"]["custom"][0]["platforms"]["windows"]["command_templates"] = [
        r'"C:\Program Files\Different\different.exe" --case "{document_term}"'
    ]
    duplicate_custom_id.catalogs["process_catalog"]["cases:second-workflow"] = second_profile
    with pytest.raises(PackError, match="duplicates custom process ID"):
        _validate_semantics([duplicate_custom_id], builtin_application_ids={"chrome"})


def test_semantic_validation_does_not_mutate_loaded_catalogs() -> None:
    """Validation is safe to call before compilation digests are computed."""

    pack = _industry_pack(custom=[_custom_process()])
    original = copy.deepcopy(pack.catalogs)

    _validate_semantics([pack], builtin_application_ids={"chrome"})

    assert pack.catalogs == original
