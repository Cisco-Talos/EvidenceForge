# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Acceptance tests for supported public configuration compatibility shapes."""

from __future__ import annotations

import warnings
from copy import deepcopy

import pytest
from pydantic import ValidationError

from evidenceforge.config.compatibility import (
    EvidenceForgeDeprecationWarning,
    stable_config_id,
)
from evidenceforge.config.schemas import (
    ApplicationCatalogConfig,
    ApplicationEntry,
    EdrInstalledSoftwareProduct,
    ObservationProfilesConfig,
)
from evidenceforge.generation.activity.application_catalog import _merge_catalog


def _legacy_warnings(records: list[warnings.WarningMessage]) -> list[warnings.WarningMessage]:
    return [
        record for record in records if issubclass(record.category, EvidenceForgeDeprecationWarning)
    ]


def _assert_actionable(records: list[warnings.WarningMessage]) -> None:
    assert records
    for record in records:
        message = str(record.message)
        assert "Replace it with" in message
        assert "in a future release" in message


def test_observation_legacy_wrapper_is_typed_and_semantically_equivalent() -> None:
    profiles = {
        "complete": {
            "description": "Complete collection",
            "default": {
                "missingness": 0.0,
                "delay_ms": {"min_ms": 0, "max_ms": 0},
            },
            "sources": {},
        },
        "branch": {
            "description": "Branch collection",
            "default": {
                "missingness": 0.05,
                "delay_ms": {"min_ms": 10, "max_ms": 30},
            },
            "sources": {},
        },
    }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        legacy = ObservationProfilesConfig.model_validate({"profiles": deepcopy(profiles)})
    current = ObservationProfilesConfig.model_validate(
        {"schema_version": 2, "profiles": deepcopy(profiles)}
    )

    records = _legacy_warnings(caught)
    assert legacy == current
    assert len(records) == 2
    _assert_actionable(records)


def test_application_missing_deployments_normalize_once_per_entry() -> None:
    authored = {
        "id": "contoso-editor",
        "display_name": "Contoso Editor",
        "platforms": {
            "windows": {"image_path": r"C:\Program Files\Contoso\editor.exe"},
            "linux": {"image_path": "/opt/contoso/editor"},
        },
        "categories": ["user_app"],
        "personas": ["developer"],
    }
    current = deepcopy(authored)
    for platform in current["platforms"].values():
        platform["deployment"] = {"kind": "legacy_static"}

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        legacy_model = ApplicationEntry.model_validate(authored)
    current_model = ApplicationEntry.model_validate(current)

    records = _legacy_warnings(caught)
    assert legacy_model == current_model
    assert len(records) == 1
    assert "contoso-editor" in str(records[0].message)
    _assert_actionable(records)


def test_unversioned_application_catalog_matches_versioned_default_descriptor() -> None:
    application = {
        "id": "contoso-editor",
        "display_name": "Contoso Editor",
        "platforms": {
            "linux": {
                "image_path": "/opt/contoso/editor",
                "deployment": {"kind": "legacy_static"},
            }
        },
        "categories": ["user_app"],
        "personas": ["developer"],
    }
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        legacy = ApplicationCatalogConfig.model_validate({"applications": [application]})
    current = ApplicationCatalogConfig.model_validate(
        {
            "schema_version": 2,
            "default_deployment": {"kind": "legacy_static"},
            "applications": [application],
        }
    )

    records = _legacy_warnings(caught)
    assert legacy == current
    assert len(records) == 1
    _assert_actionable(records)


def test_unversioned_partial_application_overlay_warns_once_before_current_merge() -> None:
    default = {
        "schema_version": 2,
        "default_deployment": {"kind": "legacy_static"},
        "applications": [
            {
                "id": "contoso-editor",
                "display_name": "Contoso Editor",
                "platforms": {"linux": {"image_path": "/opt/contoso/editor"}},
                "categories": ["user_app"],
                "personas": ["developer"],
            }
        ],
    }
    overlay = {"applications": [{"id": "contoso-editor", "personas": ["analyst"]}]}

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        merged = _merge_catalog(default, overlay)
        normalized = ApplicationCatalogConfig.model_validate(merged)

    records = _legacy_warnings(caught)
    assert normalized.applications[0].personas == ["developer", "analyst"]
    assert normalized.applications[0].platforms["linux"].deployment is not None
    assert len(records) == 1
    _assert_actionable(records)


def test_application_managed_descriptor_without_kind_preserves_release_semantics() -> None:
    managed = {
        "product_id": "contoso-chat",
        "version": "4.2.1",
        "build": "4210",
        "architectures": ["x64"],
        "scope": "machine",
    }
    authored = {
        "id": "contoso-chat",
        "display_name": "Contoso Chat",
        "platforms": {
            "windows": {
                "image_path": r"C:\Program Files\Contoso\chat.exe",
                "deployment": managed,
                "pe_metadata": {
                    "file_version": "4.2.1",
                    "description": "Contoso Chat",
                    "product": "Contoso Chat",
                    "company": "Contoso Ltd.",
                    "original_filename": "chat.exe",
                },
            }
        },
        "categories": ["user_app"],
        "personas": ["sales"],
    }
    current = deepcopy(authored)
    current["platforms"]["windows"]["deployment"] = {"kind": "managed", **managed}

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        legacy_model = ApplicationEntry.model_validate(authored)
    current_model = ApplicationEntry.model_validate(current)

    records = _legacy_warnings(caught)
    assert legacy_model == current_model
    assert len(records) == 1
    _assert_actionable(records)


def test_installed_software_legacy_triple_maps_to_stable_current_identity() -> None:
    legacy = {
        "name": "Contoso Endpoint Agent",
        "publisher": "Contoso Ltd.",
        "version": "8.4.2",
    }
    current = {
        "product_id": "contoso-endpoint-agent",
        **legacy,
        "build": "8.4.2",
        "architectures": ["neutral"],
        "scope": "machine",
    }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        legacy_model = EdrInstalledSoftwareProduct.model_validate(legacy)
    current_model = EdrInstalledSoftwareProduct.model_validate(current)

    records = _legacy_warnings(caught)
    assert legacy_model == current_model
    assert legacy_model.model_dump(include={"name", "publisher", "version"}) == legacy
    assert stable_config_id(" Contoso Endpoint Agent ") == "contoso-endpoint-agent"
    assert len(records) == 1
    _assert_actionable(records)


def test_installed_software_partial_current_descriptor_fails_closed() -> None:
    with pytest.raises(ValidationError, match="mixes legacy and current fields"):
        EdrInstalledSoftwareProduct.model_validate(
            {
                "product_id": "contoso-endpoint-agent",
                "name": "Contoso Endpoint Agent",
                "publisher": "Contoso Ltd.",
                "version": "8.4.2",
            }
        )
