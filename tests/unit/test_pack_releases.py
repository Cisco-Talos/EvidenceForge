# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Fast contracts for portable pack release artifacts and immutable libraries."""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest
import yaml

import evidenceforge.composition.releases as release_module
from evidenceforge.composition.models import PackReference
from evidenceforge.composition.packs import PackRepository
from evidenceforge.composition.releases import (
    EFPACK_MANIFEST,
    build_efpack,
    hydrate_release,
    import_efpack,
    list_release_library,
    validate_efpack,
)
from evidenceforge.models.exceptions import PackError


class _TemporaryHomePath(type(Path())):
    """Path implementation whose user-library root is owned by one test."""

    _home: Path

    @classmethod
    def home(cls) -> Path:
        """Return the test-owned substitute for the user's home directory."""

        return cls._home


def _metrolink_release(repository_root: Path, destination: Path) -> tuple[PackRepository, Path]:
    """Build the packaged MetroLink organization and healthcare closure."""

    repository = PackRepository(repository_root)
    root = repository.resolve(
        PackReference(
            source="package",
            publisher="evidenceforge",
            name="metrolink-specialty-care",
            version="1.0.0",
        ),
        expected_type="organization",
    )
    build_efpack(repository, root, destination)
    return repository, destination


def _rewrite_zip(path: Path, entries: dict[str, bytes]) -> None:
    """Write test-controlled ZIP bytes without inheriting source archive metadata."""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)


def _archive_entries(path: Path) -> dict[str, bytes]:
    """Read one archive into exact test-controlled member bytes."""

    with zipfile.ZipFile(path) as archive:
        return {entry.filename: archive.read(entry) for entry in archive.infolist()}


def _use_test_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect user-library operations to a temporary test home."""

    home = tmp_path / "home"
    _TemporaryHomePath._home = home
    monkeypatch.setattr(release_module, "Path", _TemporaryHomePath)
    return home


def test_build_is_deterministic_and_contains_the_locked_dependency_closure(tmp_path: Path) -> None:
    """A release artifact is reproducible and carries the exact healthcare dependency bytes."""

    _repository, first = _metrolink_release(tmp_path, tmp_path / "first.efpack")
    _repository, second = _metrolink_release(tmp_path, tmp_path / "second.efpack")

    assert first.read_bytes() == second.read_bytes()
    validated = validate_efpack(first)
    assert validated.root == {
        "publisher": "evidenceforge",
        "type": "organization",
        "name": "metrolink-specialty-care",
        "version": "1.0.0",
        "digest": "c8d6db51dfa75cc1cfe4455efb4f656912045b23cf65710bd80e656d200ab132",
    }
    assert {
        (member["publisher"], member["type"], member["name"], member["version"])
        for member in validated.members
    } == {
        ("evidenceforge", "industry", "healthcare", "1.0.0"),
        ("evidenceforge", "organization", "metrolink-specialty-care", "1.0.0"),
    }


def test_inspection_rejects_archive_traversal_and_hash_mismatch(tmp_path: Path) -> None:
    """Validation rejects unsafe paths and altered bytes before library state can change."""

    traversal = tmp_path / "traversal.efpack"
    _rewrite_zip(traversal, {"../outside.yaml": b"not a pack"})
    with pytest.raises(PackError, match="unsafe archive entry"):
        validate_efpack(traversal)

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    entries = _archive_entries(archive)
    altered = next(name for name in entries if name != EFPACK_MANIFEST)
    entries[altered] += b"\n"
    corrupted = tmp_path / "corrupted.efpack"
    _rewrite_zip(corrupted, entries)
    with pytest.raises(PackError, match="hash mismatch"):
        validate_efpack(corrupted)


def test_inspection_rejects_duplicate_release_identities(tmp_path: Path) -> None:
    """An archive cannot alias one release identity through repeated member declarations."""

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    entries = _archive_entries(archive)
    document = yaml.safe_load(entries[EFPACK_MANIFEST])
    document["members"].append(document["members"][0])
    entries[EFPACK_MANIFEST] = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    duplicated = tmp_path / "duplicated.efpack"
    _rewrite_zip(duplicated, entries)

    with pytest.raises(PackError, match="duplicate release identities"):
        validate_efpack(duplicated)


def test_project_import_is_idempotent_but_never_becomes_an_implicit_resolver_source(
    tmp_path: Path,
) -> None:
    """Project release storage reuses exact bytes and remains separate from editable packs."""

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    first = import_efpack(
        archive,
        scope="project",
        project_root=tmp_path,
        accepted_publishers={"evidenceforge"},
    )
    second = import_efpack(
        archive,
        scope="project",
        project_root=tmp_path,
        accepted_publishers={"evidenceforge"},
    )

    assert first == second
    immutable = (
        tmp_path
        / ".eforge"
        / "releases"
        / "evidenceforge"
        / "organization"
        / "metrolink-specialty-care"
        / "1.0.0"
    )
    assert (immutable / "pack.lock.yaml").is_file()
    with pytest.raises(PackError, match="was not found"):
        PackRepository(tmp_path).resolve(
            PackReference(
                source="project",
                publisher="evidenceforge",
                name="metrolink-specialty-care",
                version="1.0.0",
            ),
            expected_type="organization",
        )


def test_import_requires_fresh_consent_after_complete_archive_validation(tmp_path: Path) -> None:
    """Declared publisher consent is mandatory and is not persisted between imports."""

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    with pytest.raises(PackError, match="--accept-publisher evidenceforge"):
        import_efpack(
            archive,
            scope="project",
            project_root=tmp_path,
            accepted_publishers=set(),
        )
    assert not (tmp_path / ".eforge" / "releases").exists()


def test_user_import_requires_explicit_hydration_and_rejects_digest_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The user library is opt-in and cannot silently replace a same-version release."""

    home = _use_test_home(monkeypatch, tmp_path)
    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    import_efpack(
        archive,
        scope="user",
        project_root=tmp_path,
        accepted_publishers={"evidenceforge"},
    )

    with pytest.raises(PackError, match="was not found"):
        PackRepository(tmp_path).resolve(
            PackReference(
                source="project",
                publisher="evidenceforge",
                name="metrolink-specialty-care",
                version="1.0.0",
            ),
            expected_type="organization",
        )

    hydrated = hydrate_release(
        "evidenceforge:organization:metrolink-specialty-care@1.0.0",
        tmp_path,
        scope="user",
    )
    assert hydrated["hydrated"] is True
    assert (
        PackRepository(tmp_path)
        .resolve(
            PackReference(
                source="project",
                publisher="evidenceforge",
                name="metrolink-specialty-care",
                version="1.0.0",
            ),
            expected_type="organization",
        )
        .digest
        == "c8d6db51dfa75cc1cfe4455efb4f656912045b23cf65710bd80e656d200ab132"
    )
    organization = PackRepository(tmp_path).resolve(
        PackReference(
            source="project",
            publisher="evidenceforge",
            name="metrolink-specialty-care",
            version="1.0.0",
        ),
        expected_type="organization",
    )
    assert [
        dependency.manifest.name
        for dependency in PackRepository(tmp_path).validate_semantics(organization)
    ] == ["healthcare"]

    installed_manifest = (
        home
        / ".eforge"
        / "releases"
        / "evidenceforge"
        / "organization"
        / "metrolink-specialty-care"
        / "1.0.0"
        / "pack.yaml"
    )
    document = yaml.safe_load(installed_manifest.read_text(encoding="utf-8"))
    document["description"] = "Different bytes under the same release identity."
    installed_manifest.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(PackError, match="different release"):
        import_efpack(
            archive,
            scope="user",
            project_root=tmp_path,
            accepted_publishers={"evidenceforge"},
        )


def test_hydration_revalidates_manifest_constraint_against_the_immutable_lock(
    tmp_path: Path,
) -> None:
    """Library tampering cannot hydrate a locked version outside its declared constraint."""

    package_root = Path("src/evidenceforge/config/packs/evidenceforge").resolve()
    library = tmp_path / ".eforge" / "releases" / "evidenceforge"
    industry = library / "industry" / "healthcare" / "1.0.0"
    organization = library / "organization" / "metrolink-specialty-care" / "1.0.0"
    shutil.copytree(package_root / "industry" / "healthcare" / "1.0.0", industry)
    shutil.copytree(
        package_root / "organization" / "metrolink-specialty-care" / "1.0.0",
        organization,
    )
    manifest_path = organization / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    manifest["industry_dependencies"][0]["version_constraint"] = ">=2.0.0,<3.0.0"
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")

    with pytest.raises(PackError, match="outside constraint"):
        hydrate_release(
            "evidenceforge:organization:metrolink-specialty-care@1.0.0",
            tmp_path,
            scope="project",
        )


def test_import_rolls_back_the_entire_closure_when_publication_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed later publish cannot leave an earlier dependency release installed."""

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    original_replace = release_module.os.replace
    calls = 0

    def fail_second_publish(source: Path | str, destination: Path | str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected publication failure")
        original_replace(source, destination)

    monkeypatch.setattr(release_module.os, "replace", fail_second_publish)
    with pytest.raises(PackError, match="unable to publish"):
        import_efpack(
            archive,
            scope="project",
            project_root=tmp_path,
            accepted_publishers={"evidenceforge"},
        )

    library = tmp_path / ".eforge" / "releases" / "evidenceforge"
    assert not (library / "industry" / "healthcare" / "1.0.0").exists()
    assert not (library / "organization" / "metrolink-specialty-care" / "1.0.0").exists()


def test_release_inventory_preserves_valid_records_when_one_entry_is_corrupt(
    tmp_path: Path,
) -> None:
    """One invalid immutable directory cannot hide unaffected release records."""

    _repository, archive = _metrolink_release(tmp_path, tmp_path / "release.efpack")
    import_efpack(
        archive,
        scope="project",
        project_root=tmp_path,
        accepted_publishers={"evidenceforge"},
    )
    corrupt = tmp_path / ".eforge" / "releases" / "broken" / "industry" / "bad-pack" / "1.0.0"
    corrupt.mkdir(parents=True)
    (corrupt / "pack.yaml").write_text("pack_schema_version: '1.0'\n", encoding="utf-8")

    records, issues = list_release_library(tmp_path, scope="project")

    assert {record["name"] for record in records} == {
        "healthcare",
        "metrolink-specialty-care",
    }
    assert len(issues) == 1
    assert issues[0]["scope"] == "project-release"
    assert "Pack Schema 2.0 is required" in issues[0]["error"]


def test_release_inventory_reports_a_version_directory_without_a_manifest(
    tmp_path: Path,
) -> None:
    """A malformed immutable version directory remains visible as an inventory issue."""

    corrupt = (
        tmp_path / ".eforge" / "releases" / "broken" / "industry" / "missing-manifest" / "1.0.0"
    )
    corrupt.mkdir(parents=True)

    records, issues = list_release_library(tmp_path, scope="project")

    assert records == []
    assert len(issues) == 1
    assert issues[0]["location"] == str(corrupt)
    assert "pack.yaml" in issues[0]["error"]
