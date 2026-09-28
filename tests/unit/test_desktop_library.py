"""File-backed scenario and pack library contracts."""

from __future__ import annotations

from pathlib import Path

from evidenceforge.desktop.library import discover_packs, discover_scenarios


def test_scenario_library_finds_authored_files_without_generated_bundles(tmp_path: Path) -> None:
    authored = tmp_path / "scenarios" / "example" / "scenario.yaml"
    authored.parent.mkdir(parents=True)
    authored.write_text(
        "version: '1.0'\nname: example\ndescription: Example scenario\n"
        "environment:\n  users:\n    - username: alex\n  systems:\n    - hostname: ws1\n"
        "storyline:\n  events:\n    - type: process\n",
        encoding="utf-8",
    )
    generated = tmp_path / "scenarios" / "example" / "data" / "resolved.yaml"
    generated.parent.mkdir()
    generated.write_text(authored.read_text(encoding="utf-8"), encoding="utf-8")
    external = tmp_path / "external.yaml"
    external.write_text(authored.read_text(encoding="utf-8"), encoding="utf-8")

    items = discover_scenarios(tmp_path, [external])

    assert {item.path for item in items} == {authored, external}
    assert items[0].users == 1
    assert items[0].systems == 1
    assert items[0].events == 1


def test_pack_library_reads_workspace_catalog(tmp_path: Path) -> None:
    pack = tmp_path / ".eforge" / "packs" / "local" / "organization" / "demo" / "1.0.0"
    pack.mkdir(parents=True)
    (pack / "pack.yaml").write_text(
        "type: organization\nname: demo\nversion: 1.0.0\ndescription: Demo pack\n",
        encoding="utf-8",
    )

    items = discover_packs(tmp_path, "organization")

    assert any(
        item.path == pack / "pack.yaml" and item.description == "Demo pack" for item in items
    )
