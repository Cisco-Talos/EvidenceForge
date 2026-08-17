# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused provider boundary tests for compiled application deployment."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from evidenceforge.config.provider import (
    _application_graph,
    effective_config_scope,
    pack_overlay_document,
)


def _effective_config() -> SimpleNamespace:
    application = {
        "id": "chrome",
        "display_name": "Google Chrome",
        "platforms": {
            "windows": {
                "image_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "deployment": {
                    "kind": "catalog",
                    "release_policy": "pe_metadata",
                    "scope": "machine",
                    "architectures": ["x64"],
                },
                "pe_metadata": {
                    "file_version": "120.0.6099.225",
                    "description": "Google Chrome",
                    "product": "Google Chrome",
                    "company": "Google LLC",
                    "original_filename": "chrome.exe",
                },
            }
        },
        "categories": ["browser"],
        "personas": ["knowledge_worker"],
    }
    packaged = {
        "schema_version": 2,
        "default_deployment": {"kind": "legacy_static"},
        "applications": [application],
    }
    return SimpleNamespace(
        ambient_overlay_compat=False,
        packaged_defaults={"activity/application_catalog.yaml": deepcopy(packaged)},
        project_overlays={},
        catalogs={
            "process_catalog": {
                "finance:browsers": {
                    "data": {
                        "builtins": ["chrome"],
                        "custom": [],
                        "document_terms": [],
                    }
                }
            },
            "application_catalog": {
                "finance:browser": {
                    "data": {
                        "personas": ["finance:analyst"],
                        "processes": ["finance:browsers"],
                        "connections": {},
                    }
                }
            },
        },
    )


def test_pack_application_overlay_preserves_product_identity_and_current_root_fields() -> None:
    effective = _effective_config()

    applications, runtime = _application_graph(effective)
    qualified = applications[0]
    deployment = qualified["platforms"]["windows"]["deployment"]

    assert qualified["id"] == "finance:browsers::chrome"
    assert deployment["product_id"] == "chrome"
    assert (
        "product_id"
        not in effective.packaged_defaults["activity/application_catalog.yaml"]["applications"][0][
            "platforms"
        ]["windows"]["deployment"]
    )
    assert runtime["finance:browser"]["application_ids"] == ["finance:browsers::chrome"]

    with effective_config_scope(effective, refresh_legacy_globals=False):
        overlay = pack_overlay_document("activity/application_catalog.yaml")

    assert overlay is not None
    assert overlay["schema_version"] == 2
    assert overlay["default_deployment"] == {"kind": "legacy_static"}
    assert overlay["applications"] == applications
