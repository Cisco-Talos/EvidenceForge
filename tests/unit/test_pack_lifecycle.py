# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Safety and machine-readable contracts for pack lifecycle operations."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import evidenceforge.composition.packs as pack_module
from evidenceforge.cli import pack_commands
from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import PackRepository, _rewrite_pack_self_references
from evidenceforge.models.exceptions import PackError
from evidenceforge.utils import ScenarioIncludeBudget

runner = CliRunner()


pytestmark = pytest.mark.slow


def _create_pack(
    repository: PackRepository,
    pack_type: str,
    name: str,
    version: str,
) -> Path:
    """Create a test pack under one explicit publisher identity."""

    return repository.create_skeleton(
        pack_type,  # type: ignore[arg-type]
        name,
        version,
        publisher="test-publisher",
        publisher_display_name="Test Publisher",
    )


def _copy_pack(
    repository: PackRepository,
    source: Any,
    *,
    name: str,
    version: str,
) -> Path:
    """Copy a test pack under one explicit publisher identity."""

    return repository.copy(
        source,
        name=name,
        version=version,
        publisher="test-publisher",
        publisher_display_name="Test Publisher",
    )


def _write_yaml(path: Path, document: dict[str, Any]) -> None:
    """Write one test-owned YAML document."""

    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


@pytest.mark.parametrize(
    ("name", "version"),
    [
        ("../escape", "1.0.0"),
        ("/absolute", "1.0.0"),
        ("valid-name", "../1.0.0"),
        ("valid-name", "latest"),
    ],
)
def test_pack_identity_is_validated_before_authoring_paths(
    tmp_path: Path, name: str, version: str
) -> None:
    """Invalid names and versions never create repository directories."""

    repository = PackRepository(tmp_path)

    with pytest.raises(PackError, match="invalid pack identity"):
        _create_pack(repository, "industry", name, version)

    assert not (tmp_path / ".eforge").exists()


def test_pack_authoring_rejects_symlinked_repository_ancestry(tmp_path: Path) -> None:
    """A project-local registry symlink cannot redirect lifecycle writes."""

    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".eforge").symlink_to(outside, target_is_directory=True)
    repository = PackRepository(tmp_path)

    with pytest.raises(PackError, match="cannot contain a symlink"):
        _create_pack(repository, "industry", "safe-name", "1.0.0")

    assert list(outside.iterdir()) == []


def test_pack_authoring_never_replaces_an_existing_empty_destination(tmp_path: Path) -> None:
    """Even an empty existing version directory remains caller-owned."""

    destination = (
        tmp_path / ".eforge" / "packs" / "test-publisher" / "industry" / "existing-pack" / "1.0.0"
    )
    destination.mkdir(parents=True)
    repository = PackRepository(tmp_path)

    with pytest.raises(PackError, match="already exists"):
        _create_pack(repository, "industry", "existing-pack", "1.0.0")

    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_pack_include_escape_is_rejected_before_outside_file_is_read(tmp_path: Path) -> None:
    """Pack include containment is enforced before parsing an external source."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "contained-pack", "1.0.0")
    outside = tmp_path / "outside-secret.yaml"
    outside.write_text("DO_NOT_LEAK: [invalid\n", encoding="utf-8")
    _write_yaml(
        root / "catalogs/persona_catalog.yaml",
        {"includes": [str(outside)], "persona_catalog": {}},
    )

    with pytest.raises(PackError, match="escapes allowed root") as exc_info:
        repository.resolve(
            PackReference(
                source="project", publisher="test-publisher", name="contained-pack", version="1.0.0"
            ),
            expected_type="industry",
        )

    assert "DO_NOT_LEAK" not in str(exc_info.value)


def test_path_cli_entrypoints_expand_contained_manifest_includes(tmp_path: Path) -> None:
    """Show, validate, and copy accept the same bounded included manifest contract."""

    repository = PackRepository(tmp_path)
    configured = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "test-publisher",
            "--display-name",
            "Test Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert configured.exit_code == 0, configured.stdout
    root = _create_pack(repository, "industry", "included-cli", "1.0.0")
    manifest_path = root / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    description = manifest.pop("description")
    manifest["includes"] = ["manifest/description.yaml"]
    _write_yaml(manifest_path, manifest)
    fragment = root / "manifest" / "description.yaml"
    fragment.parent.mkdir()
    _write_yaml(fragment, {"description": description})

    shown = runner.invoke(
        app,
        ["pack", "show", str(root), "--project-root", str(tmp_path), "--json"],
    )
    validated = runner.invoke(
        app,
        ["pack", "validate", str(root), "--project-root", str(tmp_path), "--json"],
    )
    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            str(root / "pack.yaml"),
            "--name",
            "included-cli-copy",
            "--version",
            "1.1.0",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )

    assert shown.exit_code == 0, shown.stdout
    assert json.loads(shown.stdout)["description"] == description
    assert validated.exit_code == 0, validated.stdout
    assert json.loads(validated.stdout)["valid"] is True
    assert copied.exit_code == 0, copied.stdout
    assert json.loads(copied.stdout)["pack"]["name"] == "included-cli-copy"


def test_pack_semantic_documents_share_one_cumulative_include_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Individually small catalog roots cannot each reset the pack parser byte budget."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "bounded-semantic", "1.0.0")
    semantic_paths = [root / "pack.yaml"] + [
        root / relative for _name, relative, _model in pack_module.CATALOG_FILES
    ]
    individual_max = max(path.stat().st_size for path in semantic_paths)
    assert sum(path.stat().st_size for path in semantic_paths) > individual_max + 1
    monkeypatch.setattr(
        pack_module,
        "PACK_SEMANTIC_BUDGET",
        ScenarioIncludeBudget(max_bytes=individual_max + 1),
    )

    with pytest.raises(PackError, match="include bytes exceed limit"):
        repository.resolve(
            PackReference(
                source="project",
                publisher="test-publisher",
                name="bounded-semantic",
                version="1.0.0",
            ),
            expected_type="industry",
        )


@pytest.mark.parametrize("filename", ["README.md", "LICENSE", "COPY_PROVENANCE.md"])
def test_pack_tree_byte_budget_includes_nonsemantic_companions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> None:
    """Every allowed companion file participates in the whole-pack byte limit."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "bounded-companion", "1.0.0")
    baseline_bytes = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    (root / filename).write_bytes(b"x" * 64)
    monkeypatch.setattr(
        pack_module,
        "PACK_TREE_BUDGET",
        pack_module.PackTreeBudget(max_bytes=baseline_bytes + 63),
    )

    with pytest.raises(PackError, match="pack bytes exceed limit"):
        repository.resolve(
            PackReference(
                source="project",
                publisher="test-publisher",
                name="bounded-companion",
                version="1.0.0",
            ),
            expected_type="industry",
        )


def test_pack_tree_bounds_depth_file_count_and_entry_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Directories and files are bounded independently during no-follow discovery."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "bounded-tree", "1.0.0")
    baseline_entries = sum(1 for _path in root.rglob("*"))
    baseline_files = sum(1 for path in root.rglob("*") if path.is_file())

    extra_directory = root / "extra"
    extra_directory.mkdir()
    monkeypatch.setattr(
        pack_module,
        "PACK_TREE_BUDGET",
        pack_module.PackTreeBudget(max_entries=baseline_entries),
    )
    with pytest.raises(PackError, match="entry count exceeds limit"):
        repository.resolve(
            PackReference(
                source="project", publisher="test-publisher", name="bounded-tree", version="1.0.0"
            ),
            expected_type="industry",
        )

    monkeypatch.setattr(
        pack_module,
        "PACK_TREE_BUDGET",
        pack_module.PackTreeBudget(max_files=baseline_files),
    )
    (root / "README.md").write_text("bounded\n", encoding="utf-8")
    with pytest.raises(PackError, match="file count exceeds limit"):
        repository.resolve(
            PackReference(
                source="project", publisher="test-publisher", name="bounded-tree", version="1.0.0"
            ),
            expected_type="industry",
        )

    monkeypatch.setattr(
        pack_module,
        "PACK_TREE_BUDGET",
        pack_module.PackTreeBudget(max_depth=2),
    )
    (extra_directory / "nested" / "too-deep").mkdir(parents=True)
    with pytest.raises(PackError, match="tree depth exceeds limit"):
        repository.resolve(
            PackReference(
                source="project", publisher="test-publisher", name="bounded-tree", version="1.0.0"
            ),
            expected_type="industry",
        )


def test_pack_copy_rechecks_immutable_snapshot_budget_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a caller-supplied LoadedPack snapshot must remain inside hard limits."""

    repository = PackRepository(tmp_path)
    _create_pack(repository, "industry", "copy-budget-source", "1.0.0")
    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="copy-budget-source", version="1.0.0"
        ),
        expected_type="industry",
    )
    baseline_bytes = sum(len(content) for _path, content in source.semantic_file_bytes)
    source = replace(source, companion_file_bytes=(("README.md", b"x" * 64),))
    monkeypatch.setattr(
        pack_module,
        "PACK_TREE_BUDGET",
        pack_module.PackTreeBudget(max_bytes=baseline_bytes + 63),
    )

    with pytest.raises(PackError, match="pack bytes exceed limit"):
        _copy_pack(repository, source, name="copy-budget-destination", version="1.0.0")

    assert not (
        tmp_path / ".eforge" / "packs" / "industry" / "copy-budget-destination" / "1.0.0"
    ).exists()


def test_pack_digest_and_assets_use_the_exact_bytes_parsed_for_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-size mutation after parsing cannot desynchronize runtime data and identity."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "captured-load", "1.0.0")
    storage_path = root / "catalogs" / "storage_catalog.yaml"
    validated_bytes = b"storage_catalog: {}\n"
    mutated_bytes = b"storage_catalog: []\n"
    assert len(validated_bytes) == len(mutated_bytes)
    storage_path.write_bytes(validated_bytes)
    original_loader = pack_module._load_pack_document

    def load_then_mutate(
        pack_root: Path,
        relative_path: str,
        model: type[Any],
        **kwargs: Any,
    ) -> tuple[Any, Any]:
        result = original_loader(pack_root, relative_path, model, **kwargs)
        if relative_path == "catalogs/storage_catalog.yaml":
            storage_path.write_bytes(mutated_bytes)
        return result

    monkeypatch.setattr(pack_module, "_load_pack_document", load_then_mutate)

    pack = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="captured-load", version="1.0.0"
        ),
        expected_type="industry",
    )
    captured = dict(pack.semantic_file_bytes)

    assert storage_path.read_bytes() == mutated_bytes
    assert pack.catalogs["storage_catalog"] == {}
    assert captured["catalogs/storage_catalog.yaml"] == validated_bytes
    assert pack.assets["catalogs/storage_catalog.yaml"] == validated_bytes.decode("utf-8")
    assert pack.digest == pack_module._canonical_digest(captured)


def test_pack_copy_uses_the_resolved_immutable_source_snapshot(tmp_path: Path) -> None:
    """Later same-size source mutations cannot alter copied payload or provenance."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "captured-copy", "1.0.0")
    storage_path = root / "catalogs" / "storage_catalog.yaml"
    readme_path = root / "README.md"
    validated_storage = b"storage_catalog: {}\n"
    mutated_storage = b"storage_catalog: []\n"
    validated_readme = b"alpha\n"
    mutated_readme = b"bravo\n"
    assert len(validated_storage) == len(mutated_storage)
    assert len(validated_readme) == len(mutated_readme)
    storage_path.write_bytes(validated_storage)
    readme_path.write_bytes(validated_readme)
    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="captured-copy", version="1.0.0"
        ),
        expected_type="industry",
    )

    storage_path.write_bytes(mutated_storage)
    readme_path.write_bytes(mutated_readme)
    destination = _copy_pack(repository, source, name="captured-copy-fork", version="1.1.0")

    assert (destination / "catalogs" / "storage_catalog.yaml").read_bytes() == validated_storage
    assert (destination / "README.md").read_bytes() == validated_readme
    provenance = (destination / "COPY_PROVENANCE.md").read_text(encoding="utf-8")
    assert f"Source digest: `sha256:{source.digest}`" in provenance


def test_pack_authoring_rolls_back_a_failed_post_publish_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed normal-path reload removes both the published tree and its stage."""

    repository = PackRepository(tmp_path)

    def fail_reload(*_args: object, **_kwargs: object) -> None:
        raise PackError("injected reload failure")

    monkeypatch.setattr(repository, "_reload_authored_pack", fail_reload)

    with pytest.raises(PackError, match="injected reload failure"):
        _create_pack(repository, "organization", "rollback-org", "1.0.0")

    parent = tmp_path / ".eforge" / "packs" / "organization" / "rollback-org"
    assert not (parent / "1.0.0").exists()
    assert not list(parent.glob(".1.0.0.tmp-*"))


def test_copy_rolls_back_a_semantically_invalid_destination(tmp_path: Path) -> None:
    """Per-file-valid but cross-catalog-invalid copies never remain published."""

    repository = PackRepository(tmp_path)
    source_root = _create_pack(repository, "industry", "invalid-source", "1.0.0")
    _write_yaml(
        source_root / "catalogs/application_catalog.yaml",
        {
            "application_catalog": {
                "orphan-app": {
                    "data": {
                        "personas": ["missing-persona"],
                        "processes": ["missing-process"],
                        "connections": {
                            "primary": {"destination": "missing-destination", "service": "web"}
                        },
                    }
                }
            }
        },
    )
    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="invalid-source", version="1.0.0"
        ),
        expected_type="industry",
    )

    with pytest.raises(PackError, match="missing export"):
        _copy_pack(repository, source, name="invalid-copy", version="1.0.0")

    parent = tmp_path / ".eforge" / "packs" / "industry" / "invalid-copy"
    assert not (parent / "1.0.0").exists()
    assert not list(parent.glob(".1.0.0.tmp-*"))


def test_copy_flattens_manifest_includes_without_leaving_orphan_yaml(tmp_path: Path) -> None:
    """A valid included manifest remains copyable under the canonical destination manifest."""

    repository = PackRepository(tmp_path)
    source_root = _create_pack(repository, "industry", "included-manifest", "1.0.0")
    manifest_path = source_root / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    description = manifest.pop("description")
    manifest["includes"] = ["manifest-description.yaml"]
    _write_yaml(manifest_path, manifest)
    _write_yaml(source_root / "manifest-description.yaml", {"description": description})

    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="included-manifest", version="1.0.0"
        ),
        expected_type="industry",
    )
    destination = _copy_pack(repository, source, name="flattened-copy", version="1.1.0")

    copied_manifest = yaml.safe_load((destination / "pack.yaml").read_text(encoding="utf-8"))
    assert copied_manifest["description"] == description
    assert "includes" not in copied_manifest
    assert not (destination / "manifest-description.yaml").exists()
    copied = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="flattened-copy", version="1.1.0"
        ),
        expected_type="industry",
    )
    assert copied.manifest.description == description


def test_catalog_field_origins_retain_qualified_include_paths(tmp_path: Path) -> None:
    """Catalog provenance names the qualified export and its exact portable source."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "origin-pack", "1.0.0")
    catalog_root = root / "catalogs" / "storage_catalog.yaml"
    _write_yaml(catalog_root, {"includes": ["fragments/storage.yaml"]})
    fragment = root / "catalogs" / "fragments" / "storage.yaml"
    fragment.parent.mkdir()
    _write_yaml(
        fragment,
        {
            "storage_catalog": {
                "records": {
                    "data": {
                        "directories": ["Records"],
                        "subjects": ["Case"],
                        "files": [
                            {
                                "extension": ".pdf",
                                "mime": "application/pdf",
                                "weight": 1,
                            }
                        ],
                    }
                }
            }
        },
    )

    pack = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="origin-pack", version="1.0.0"
        ),
        expected_type="industry",
    )

    assert (
        pack.catalog_field_origins[
            "storage_catalog.test-publisher/origin-pack:records.data.files.0.mime"
        ]
        == "catalogs/fragments/storage.yaml"
    )
    assert all(not Path(origin).is_absolute() for origin in pack.catalog_field_origins.values())


def test_path_pack_copy_records_source_digest_and_location(tmp_path: Path) -> None:
    """Non-semantic copy provenance identifies the exact validated external source."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "path-source", "1.0.0")
    source = repository.resolve(
        PackReference(
            source="path",
            path=str(root),
            publisher="test-publisher",
            name="path-source",
            version="1.0.0",
        ),
        expected_type="industry",
    )

    destination = _copy_pack(repository, source, name="path-copy", version="1.1.0")
    provenance = (destination / "COPY_PROVENANCE.md").read_text(encoding="utf-8")

    assert "Source reference: `path:test-publisher:industry:path-source@1.0.0`" in provenance
    assert f"Source location: `{root.resolve()}`" in provenance
    assert f"Source digest: `sha256:{source.digest}`" in provenance


def test_manifest_include_path_dependency_survives_validation_compile_and_copy(
    tmp_path: Path,
) -> None:
    """A nested manifest dependency keeps its declaring origin and resolved copy target."""

    repository = PackRepository(tmp_path)
    dependency_root = _create_pack(repository, "industry", "path-industry", "1.0.0")
    source_root = _create_pack(repository, "organization", "path-org", "1.0.0")
    manifest_path = source_root / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("industry_dependencies", None)
    manifest["includes"] = ["manifest/dependencies.yaml"]
    _write_yaml(manifest_path, manifest)
    dependency_fragment = source_root / "manifest" / "dependencies.yaml"
    dependency_fragment.parent.mkdir()
    relative_dependency = Path(
        os.path.relpath(dependency_root, start=dependency_fragment.parent)
    ).as_posix()
    _write_yaml(
        dependency_fragment,
        {
            "industry_dependencies": [
                {
                    "source": "path",
                    "publisher": "test-publisher",
                    "type": "industry",
                    "path": relative_dependency,
                    "name": "path-industry",
                    "version_constraint": ">=1.0.0,<2.0.0",
                }
            ]
        },
    )
    dependency = repository.resolve(
        PackReference(
            source="project",
            publisher="test-publisher",
            name="path-industry",
            version="1.0.0",
        ),
        expected_type="industry",
    )
    _write_yaml(
        source_root / "pack.lock.yaml",
        {
            "lock_schema_version": "1.0",
            "dependencies": [
                {
                    "publisher": "test-publisher",
                    "type": "industry",
                    "name": "path-industry",
                    "version": "1.0.0",
                    "digest": dependency.digest,
                }
            ],
        },
    )

    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="path-org", version="1.0.0"
        ),
        expected_type="organization",
    )
    dependencies = repository.validate_semantics(source)
    assert dependencies[0].root == dependency_root.resolve()

    scenario_document = yaml.safe_load(
        Path("tests/fixtures/scenarios/minimal.yaml").read_text(encoding="utf-8")
    )
    scenario_document.pop("version", None)
    scenario_document["scenario_version"] = "2.0"
    scenario_document["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "test-publisher",
            "name": "path-org",
            "version": "1.0.0",
        }
    }
    scenario_path = tmp_path / "path-org-scenario.yaml"
    _write_yaml(scenario_path, scenario_document)
    compiled = compile_scenario(scenario_path, project_root=tmp_path)
    assert [pack.name for pack in compiled.selected_packs] == ["path-industry", "path-org"]

    destination = _copy_pack(repository, source, name="copied-path-org", version="2.0.0")
    copied_manifest = yaml.safe_load((destination / "pack.yaml").read_text(encoding="utf-8"))
    copied_dependency_path = Path(copied_manifest["industry_dependencies"][0]["path"])
    assert not copied_dependency_path.is_absolute()
    assert (destination / copied_dependency_path).resolve() == dependency_root.resolve()
    copied = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="copied-path-org", version="2.0.0"
        ),
        expected_type="organization",
    )
    assert repository.validate_semantics(copied)[0].root == dependency_root.resolve()


def test_copy_rewrites_only_typed_exact_self_references(tmp_path: Path) -> None:
    """Renaming a pack updates its typed reference graph without rewriting prose."""

    repository = PackRepository(tmp_path)
    source_root = _create_pack(repository, "organization", "source-org", "1.0.0")
    _write_yaml(
        source_root / "catalogs/persona_catalog.yaml",
        {
            "persona_catalog": {
                "operator": {
                    "name": "operator",
                    "description": "Operations user",
                    "typical_activities": ["Review operational queues"],
                    "work_hours": "9am-5pm",
                    "application_usage": ["Source Org Portal"],
                    "risk_profile": "medium",
                    "browsing_intensity": "normal",
                }
            }
        },
    )
    _write_yaml(
        source_root / "catalogs/process_catalog.yaml",
        {
            "process_catalog": {
                "portal-processes": {
                    "description": "Portal process pool",
                    "data": {"builtins": ["chrome"], "document_terms": ["Daily Queue"]},
                }
            }
        },
    )
    _write_yaml(
        source_root / "catalogs/destination_catalog.yaml",
        {
            "destination_catalog": {
                "portal-destination": {
                    "description": "Portal destination",
                    "data": {
                        "tags": ["test-publisher/source-org:portal"],
                        "endpoints": [
                            {"domain": "portal.source-org.example", "ips": ["203.0.113.10"]}
                        ],
                        "services": {"web": {"protocol": "https"}},
                    },
                }
            }
        },
    )
    _write_yaml(
        source_root / "catalogs/application_catalog.yaml",
        {
            "application_catalog": {
                "portal": {
                    "description": "test-publisher/source-org:portal",
                    "data": {
                        "personas": ["test-publisher/source-org:operator"],
                        "processes": ["test-publisher/source-org:portal-processes"],
                        "connections": {
                            "primary": {
                                "destination": "test-publisher/source-org:portal-destination",
                                "service": "web",
                            }
                        },
                    },
                }
            }
        },
    )
    _write_yaml(
        source_root / "catalogs/traffic_catalog.yaml",
        {
            "traffic_catalog": {
                "portal-traffic": {
                    "description": "Portal traffic",
                    "data": {
                        "audience": ["test-publisher/source-org:operator"],
                        "applications": [
                            {
                                "application": "test-publisher/source-org:portal",
                                "connection": "primary",
                            }
                        ],
                        "outbound": [
                            {
                                "port": 443,
                                "service": "ssl",
                                "emit_dns": True,
                                "dns_tags": ["test-publisher/source-org:portal"],
                            }
                        ],
                    },
                }
            }
        },
    )
    _write_yaml(
        source_root / "model/environment.yaml",
        {
            "environment": {
                "users": [
                    {
                        "username": "casey.lee",
                        "full_name": "Casey Lee",
                        "email": "casey.lee@source-org.example",
                        "persona": "test-publisher/source-org:operator",
                    }
                ]
            }
        },
    )
    source = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="source-org", version="1.0.0"
        ),
        expected_type="organization",
    )

    destination = _copy_pack(repository, source, name="renamed-org", version="2.0.0")

    application = yaml.safe_load(
        (destination / "catalogs/application_catalog.yaml").read_text(encoding="utf-8")
    )["application_catalog"]["portal"]
    traffic = yaml.safe_load(
        (destination / "catalogs/traffic_catalog.yaml").read_text(encoding="utf-8")
    )["traffic_catalog"]["portal-traffic"]["data"]
    destination_catalog = yaml.safe_load(
        (destination / "catalogs/destination_catalog.yaml").read_text(encoding="utf-8")
    )["destination_catalog"]["portal-destination"]["data"]
    environment = yaml.safe_load(
        (destination / "model/environment.yaml").read_text(encoding="utf-8")
    )["environment"]

    assert application["description"] == "test-publisher/source-org:portal"
    assert application["data"]["personas"] == ["test-publisher/renamed-org:operator"]
    assert application["data"]["processes"] == ["test-publisher/renamed-org:portal-processes"]
    assert application["data"]["connections"]["primary"]["destination"] == (
        "test-publisher/renamed-org:portal-destination"
    )
    assert traffic["audience"] == ["test-publisher/renamed-org:operator"]
    assert traffic["applications"][0]["application"] == "test-publisher/renamed-org:portal"
    assert traffic["outbound"][0]["dns_tags"] == ["test-publisher/renamed-org:portal"]
    assert destination_catalog["tags"] == ["test-publisher/renamed-org:portal"]
    assert environment["users"][0]["persona"] == "test-publisher/renamed-org:operator"
    assert (destination / "COPY_PROVENANCE.md").is_file()

    before = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="renamed-org", version="2.0.0"
        ),
        expected_type="organization",
    ).digest
    (destination / "COPY_PROVENANCE.md").write_text(
        "Updated local provenance notes.\n", encoding="utf-8"
    )
    after = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="renamed-org", version="2.0.0"
        ),
        expected_type="organization",
    ).digest
    assert after == before


def test_organization_loader_qualifies_local_environment_references(tmp_path: Path) -> None:
    """Local organization references become public qualified runtime identities."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "organization", "local-org", "1.0.0")
    _write_yaml(
        root / "catalogs/persona_catalog.yaml",
        {
            "persona_catalog": {
                "operator": {
                    "name": "operator",
                    "description": "Operations user",
                    "typical_activities": ["Review queues"],
                    "work_hours": "9am-5pm",
                    "application_usage": ["Operations portal"],
                    "risk_profile": "medium",
                    "browsing_intensity": "normal",
                }
            }
        },
    )
    _write_yaml(
        root / "catalogs/storage_catalog.yaml",
        {
            "storage_catalog": {
                "records": {
                    "data": {
                        "directories": ["Records"],
                        "subjects": ["Case"],
                        "files": [
                            {
                                "extension": ".pdf",
                                "mime": "application/pdf",
                                "weight": 1,
                            }
                        ],
                    }
                }
            }
        },
    )
    _write_yaml(
        root / "model/environment.yaml",
        {
            "environment": {
                "users": [
                    {
                        "username": "casey.lee",
                        "full_name": "Casey Lee",
                        "email": "casey.lee@local-org.example",
                        "persona": "operator",
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
                                    "id": "records",
                                    "name": "Records",
                                    "volume": "data",
                                    "preset": "records",
                                }
                            ],
                        }
                    ]
                },
            }
        },
    )
    _write_yaml(
        root / "model/baseline_activity.yaml",
        {
            "baseline_activity": {
                "traffic_suppression": [{"audience": {"personas": ["operator"]}, "factor": 0.5}]
            }
        },
    )

    loaded = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="local-org", version="1.0.0"
        ),
        expected_type="organization",
    )

    assert loaded.environment["users"][0]["persona"] == "test-publisher/local-org:operator"
    assert (
        loaded.environment["storage"]["servers"][0]["shares"][0]["preset"]
        == "test-publisher/local-org:records"
    )
    assert loaded.baseline_activity["traffic_suppression"][0]["audience"]["personas"] == [
        "test-publisher/local-org:operator"
    ]


def test_organization_loader_preserves_packaged_builtin_shorthand(tmp_path: Path) -> None:
    """Built-in persona and storage IDs remain available inside organization models."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "organization", "builtin-org", "1.0.0")
    _write_yaml(
        root / "model/environment.yaml",
        {
            "environment": {
                "users": [
                    {
                        "username": "dev.user",
                        "full_name": "Development User",
                        "email": "dev.user@builtin-org.example",
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
                                },
                                {
                                    "id": "backup",
                                    "name": "Backup",
                                    "volume": "data",
                                    "preset": "backup",
                                },
                            ],
                        }
                    ]
                },
            }
        },
    )
    _write_yaml(
        root / "model/baseline_activity.yaml",
        {
            "baseline_activity": {
                "traffic_suppression": [{"audience": {"personas": ["developer"]}, "factor": 0.5}]
            }
        },
    )

    loaded = repository.resolve(
        PackReference(
            source="project", publisher="test-publisher", name="builtin-org", version="1.0.0"
        ),
        expected_type="organization",
    )

    assert loaded.environment["users"][0]["persona"] == "developer"
    assert [share["preset"] for share in loaded.environment["storage"]["servers"][0]["shares"]] == [
        "department",
        "backup",
    ]
    assert loaded.baseline_activity["traffic_suppression"][0]["audience"]["personas"] == [
        "developer"
    ]
    assert repository.validate_semantics(loaded) == []


def test_copy_reference_rewriter_covers_organization_storage_presets() -> None:
    """The nested SMB preset reference is renamed while adjacent prose is untouched."""

    document = {
        "environment": {
            "description": "test-publisher/source-org:records",
            "storage": {
                "servers": [
                    {
                        "shares": [
                            {
                                "preset": "test-publisher/source-org:records",
                                "description": "test-publisher/source-org:records",
                            }
                        ]
                    }
                ]
            },
        }
    }

    changed = _rewrite_pack_self_references(
        document,
        old_name="test-publisher/source-org",
        new_name="test-publisher/renamed-org",
    )

    share = document["environment"]["storage"]["servers"][0]["shares"][0]
    assert changed is True
    assert share["preset"] == "test-publisher/renamed-org:records"
    assert share["description"] == "test-publisher/source-org:records"
    assert document["environment"]["description"] == "test-publisher/source-org:records"


def test_copy_reference_rewriter_covers_baseline_persona_audiences() -> None:
    """Typed baseline persona selectors follow a renamed organization namespace."""

    document = {
        "baseline_activity": {
            "traffic_affinities": [
                {
                    "name": "portal",
                    "audience": {
                        "personas": ["test-publisher/source-org:operator", "dependency:analyst"],
                    },
                }
            ],
            "traffic_suppression": [
                {"audience": {"personas": ["test-publisher/source-org:operator"]}, "factor": 0.5}
            ],
            "description": "test-publisher/source-org:operator",
        }
    }

    changed = _rewrite_pack_self_references(
        document,
        old_name="test-publisher/source-org",
        new_name="test-publisher/renamed-org",
    )

    baseline = document["baseline_activity"]
    assert changed is True
    assert baseline["traffic_affinities"][0]["audience"]["personas"] == [
        "test-publisher/renamed-org:operator",
        "dependency:analyst",
    ]
    assert baseline["traffic_suppression"][0]["audience"]["personas"] == [
        "test-publisher/renamed-org:operator"
    ]
    assert baseline["description"] == "test-publisher/source-org:operator"


def test_pack_init_and_copy_have_stable_json_contracts(tmp_path: Path) -> None:
    """Lifecycle success and failure results are JSON-only and machine-readable."""

    configured = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "test-publisher",
            "--display-name",
            "Test Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert configured.exit_code == 0, configured.stdout
    initialized = runner.invoke(
        app,
        [
            "pack",
            "init",
            "industry",
            "source-pack",
            "--version",
            "1.0.0",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    initialized_payload = json.loads(initialized.stdout)

    assert initialized.exit_code == 0
    assert initialized_payload["created"] is True
    assert initialized_payload["pack"]["name"] == "source-pack"

    invalid_init = runner.invoke(
        app,
        [
            "pack",
            "init",
            "industry",
            "invalid-version",
            "--version",
            "latest",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    invalid_init_payload = json.loads(invalid_init.stdout)

    assert invalid_init.exit_code == 1
    assert invalid_init_payload["created"] is False
    assert "invalid pack identity" in invalid_init_payload["error"]
    assert "Error:" not in invalid_init.stdout

    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "project:test-publisher:industry:source-pack@1.0.0",
            "--name",
            "copied-pack",
            "--version",
            "1.1.0",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    copied_payload = json.loads(copied.stdout)

    assert copied.exit_code == 0
    assert copied_payload["copied"] is True
    assert copied_payload["source_pack"]["name"] == "source-pack"
    assert copied_payload["pack"]["name"] == "copied-pack"

    refused = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "project:test-publisher:industry:source-pack@1.0.0",
            "--name",
            "../escape",
            "--version",
            "1.1.0",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    refused_payload = json.loads(refused.stdout)

    assert refused.exit_code == 1
    assert refused_payload["copied"] is False
    assert "invalid pack identity" in refused_payload["error"]
    assert "Error:" not in refused.stdout


def test_pack_show_normalizes_malformed_yaml_as_json(tmp_path: Path) -> None:
    """Expected parsing failures do not leak a traceback or Rich text in JSON mode."""

    pack_root = tmp_path / "malformed"
    pack_root.mkdir()
    (pack_root / "pack.yaml").write_text(
        "type: industry\nname: malformed\nname: duplicate\nversion: 1.0.0\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "pack",
            "show",
            str(pack_root),
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload["valid"] is False
    assert "duplicate key" in payload["error"]
    assert "Error:" not in result.stdout


def test_pack_list_failure_has_a_stable_json_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inventory failures never mix Rich diagnostics into JSON output."""

    class BrokenRepository:
        def list(self) -> list[object]:
            raise PackError("injected inventory failure")

    monkeypatch.setattr(pack_commands, "_repository", lambda _project_root: BrokenRepository())

    result = runner.invoke(app, ["pack", "list", "--json"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload == {"packs": [], "issues": [], "error": "injected inventory failure"}
    assert "Error:" not in result.stdout


def test_pack_validate_normalizes_include_errors_as_json(tmp_path: Path) -> None:
    """Pack include/configuration failures use the stable validation error envelope."""

    repository = PackRepository(tmp_path)
    root = _create_pack(repository, "industry", "broken-include", "1.0.0")
    _write_yaml(
        root / "catalogs/persona_catalog.yaml",
        {"includes": ["missing-personas.yaml"]},
    )

    result = runner.invoke(
        app,
        [
            "pack",
            "validate",
            "project:test-publisher:industry:broken-include@1.0.0",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    payload = json.loads(result.stdout)

    assert result.exit_code == 2
    assert payload["valid"] is False
    assert "include" in payload["error"].lower()
    assert "Invalid pack:" not in result.stdout
