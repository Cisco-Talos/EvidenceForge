"""Native bundled-resource reads must not depend on Windows long-path policy."""

import os
import shutil
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows resource path contract")


def test_long_runtime_catalogs_preserve_behavior_digest_and_pack_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import evidenceforge
    from evidenceforge import config
    from evidenceforge._windows_paths import package_resource_path
    from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
    from evidenceforge.generation.checkpoints.behavior import generation_behavior_surface_digest

    original = Path(evidenceforge.__file__).parent
    expected = generation_behavior_surface_digest(original)
    relocated = tmp_path / ("runtime-" + "a" * 90) / ("private-" + "b" * 90) / "evidenceforge"
    extended = package_resource_path(relocated)
    shutil.copytree(original, extended, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    catalog = (
        Path("config/packs/evidenceforge/organization/metrolink-specialty-care/1.0.0/catalogs")
        / "destination_catalog.yaml"
    )
    assert len(str(relocated / catalog)) >= 260
    stat = Path.stat
    denied: list[Path] = []

    def legacy_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
        if len(str(path)) >= 260 and not str(path).startswith("\\\\?\\"):
            denied.append(path)
            raise FileNotFoundError("Legacy Windows path limit")
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", legacy_stat)
    assert not (relocated / catalog).is_file()
    denied.clear()
    assert generation_behavior_surface_digest(relocated) == expected
    monkeypatch.setattr(config, "_CONFIG_DIR", extended / "config")
    repository = PackRepository(tmp_path / "workspace")
    reference, kind = parse_pack_cli_reference(
        "package:evidenceforge:organization:metrolink-specialty-care@1.0.0"
    )
    loaded = repository.resolve(reference, expected_type=kind)
    assert loaded.manifest.name == "metrolink-specialty-care"
    assert (extended / catalog).read_bytes()
    assert denied == []

    (extended / catalog).write_bytes(b"changed catalog\n")
    assert generation_behavior_surface_digest(relocated) != expected
