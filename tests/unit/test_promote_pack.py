# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the developer-only official pack promotion utility."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from tools.promote_pack import main

from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import PackRepository


def _target_repo(tmp_path: Path) -> Path:
    """Create the minimum EvidenceForge source tree required by the utility."""

    root = tmp_path / "target"
    package_root = root / "src/evidenceforge/config/packs"
    package_root.mkdir(parents=True)
    (package_root / "index.json").write_text(
        json.dumps({"packs": {}, "schema_version": "1.0"}) + "\n",
        encoding="utf-8",
    )
    return root


def _copy_pack(
    source_repo: PackRepository,
    source_reference: PackReference,
    destination_root: Path,
    *,
    publisher: str,
    name: str,
    version: str,
) -> Path:
    """Copy one packaged fixture into a personal source project."""

    source_pack = source_repo.resolve(source_reference, expected_type="industry")
    destination_repo = PackRepository(destination_root)
    return destination_repo.copy(
        source_pack,
        name=name,
        version=version,
        publisher=publisher,
        publisher_display_name="Personal Publisher",
    )


def _rewrite_namespace(value: Any, old: str, new: str) -> Any:
    """Rewrite exact qualified references in a fixture organization pack."""

    if isinstance(value, dict):
        return {key: _rewrite_namespace(nested, old, new) for key, nested in value.items()}
    if isinstance(value, list):
        return [_rewrite_namespace(nested, old, new) for nested in value]
    if isinstance(value, str) and (value == old or value.startswith(f"{old}:")):
        return f"{new}{value[len(old) :]}"
    return value


def _personal_industry(tmp_path: Path, name: str = "publishing") -> tuple[Path, Path]:
    """Create a valid personal industry pack from the packaged fixture catalog."""

    source_root = tmp_path / "personal"
    source_root.mkdir()
    source_repo = PackRepository(Path.cwd())
    source_path = _copy_pack(
        source_repo,
        PackReference(source="package", publisher="evidenceforge", name="finance", version="1.0.0"),
        source_root,
        publisher="alice",
        name=name,
        version="0.1.0",
    )
    return source_root, source_path


def test_plan_reissues_industry_pack_without_writing(tmp_path: Path, capsys: Any) -> None:
    """The plan command reports official identity and leaves the source tree untouched."""

    source_root, source_path = _personal_industry(tmp_path)
    target_root = _target_repo(tmp_path)

    assert (
        main(
            [
                str(source_path),
                "--source-project-root",
                str(source_root),
                "--target-repo-root",
                str(target_root),
                "--target-version",
                "1.0.0",
                "--target-publisher-display-name",
                "EvidenceForge Official",
            ]
        )
        == 0
    )
    plan = json.loads(capsys.readouterr().out)
    assert plan["root"]["action"] == "create"
    assert plan["root"]["name"] == "publishing"
    assert plan["root"]["version"] == "1.0.0"
    assert plan["target_publisher"] == "evidenceforge"
    assert not (target_root / "src/evidenceforge/config/packs/evidenceforge/industry").exists()


def test_apply_reissues_industry_pack_and_updates_digest_index(tmp_path: Path, capsys: Any) -> None:
    """Apply publishes the official pack and its authoritative digest index entry."""

    source_root, source_path = _personal_industry(tmp_path)
    target_root = _target_repo(tmp_path)
    assert (
        main(
            [
                str(source_path),
                "--source-project-root",
                str(source_root),
                "--target-repo-root",
                str(target_root),
                "--target-version",
                "1.0.0",
                "--apply",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["applied"] is True

    package_path = (
        target_root / "src/evidenceforge/config/packs/evidenceforge/industry/publishing/1.0.0"
    )
    loaded = PackRepository(target_root).resolve(
        PackReference(
            source="path",
            path=str(package_path),
            publisher="evidenceforge",
            name="publishing",
            version="1.0.0",
        ),
        expected_type="industry",
    )
    manifest = yaml.safe_load((package_path / "pack.yaml").read_text(encoding="utf-8"))
    index = json.loads(
        (target_root / "src/evidenceforge/config/packs/index.json").read_text(encoding="utf-8")
    )
    assert manifest["publisher"] == "evidenceforge"
    assert manifest["publisher_display_name"] == "EvidenceForge"
    assert index["packs"]["evidenceforge/industry/publishing/1.0.0"] == loaded.digest
    assert source_path.exists()


def test_org_promotion_can_promote_missing_personal_industry_dependency(
    tmp_path: Path, capsys: Any
) -> None:
    """Organization promotion reissues its locked personal industry dependency first."""

    source_root = tmp_path / "personal"
    source_root.mkdir()
    source_repo = PackRepository(Path.cwd())
    industry_path = _copy_pack(
        source_repo,
        PackReference(
            source="package", publisher="evidenceforge", name="healthcare", version="1.0.0"
        ),
        source_root,
        publisher="alice",
        name="healthcare",
        version="1.0.0",
    )
    organization_source = source_repo.resolve(
        PackReference(
            source="package",
            publisher="evidenceforge",
            name="northstar-health",
            version="1.0.0",
        ),
        expected_type="organization",
    )
    personal_repo = PackRepository(source_root)
    organization_path = personal_repo.copy(
        organization_source,
        name="northstar-demo",
        version="0.1.0",
        publisher="alice",
        publisher_display_name="Personal Publisher",
    )
    manifest_path = organization_path / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["industry_dependencies"][0].update(source="project", publisher="alice")
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    for path in organization_path.rglob("*.yaml"):
        if path.name == "pack.yaml":
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        rewritten = _rewrite_namespace(document, "evidenceforge/healthcare", "alice/healthcare")
        path.write_text(yaml.safe_dump(rewritten, sort_keys=False), encoding="utf-8")
    personal_pack = personal_repo.resolve(
        PackReference(source="project", publisher="alice", name="northstar-demo", version="0.1.0"),
        expected_type="organization",
    )
    personal_repo.update_lock(personal_pack, personal_repo.proposed_lock(personal_pack))

    target_root = _target_repo(tmp_path)
    assert (
        main(
            [
                str(organization_path),
                "--source-project-root",
                str(source_root),
                "--target-repo-root",
                str(target_root),
                "--target-name",
                "northstar-official",
                "--target-version",
                "1.0.0",
                "--apply",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["dependencies"][0]["action"] == "create"
    assert result["namespace_rewrites"] == {"alice/healthcare": "evidenceforge/healthcare"}

    org_path = (
        target_root
        / "src/evidenceforge/config/packs/evidenceforge/organization/northstar-official/1.0.0"
    )
    org_manifest = yaml.safe_load((org_path / "pack.yaml").read_text(encoding="utf-8"))
    org_lock = yaml.safe_load((org_path / "pack.lock.yaml").read_text(encoding="utf-8"))
    environment = yaml.safe_load((org_path / "model/environment.yaml").read_text(encoding="utf-8"))
    assert org_manifest["industry_dependencies"][0]["source"] == "package"
    assert org_manifest["industry_dependencies"][0]["publisher"] == "evidenceforge"
    assert org_lock["dependencies"][0]["publisher"] == "evidenceforge"
    assert environment["environment"]["users"][0]["persona"].startswith("evidenceforge/healthcare:")
    assert (
        target_root / "src/evidenceforge/config/packs/evidenceforge/industry/healthcare/1.0.0"
    ).is_dir()
    assert industry_path.exists()
