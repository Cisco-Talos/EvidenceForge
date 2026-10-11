"""Starter recognition requires the shared managed scaffold rather than empty entity counts."""

import json
from pathlib import Path

import pytest
import yaml

from evidenceforge.artifacts.lifecycle import create_new_draft
from evidenceforge.artifacts.scaffolds import is_starter_draft


def test_new_scaffold_marker_ignores_metadata_but_detects_authoring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = create_new_draft("scenario", "starter", description="", project_root=tmp_path)
    data = yaml.safe_load(source.read_bytes())
    assert data["baseline_activity"]["description"] == ""
    assert is_starter_draft(source)
    data.update(name="renamed", display_name="New title", release_notes="Draft notes")
    source.write_text(yaml.safe_dump(data))
    assert is_starter_draft(source)
    data["environment"]["description"] = "An authored environment"
    source.write_text(yaml.safe_dump(data))
    assert not is_starter_draft(source)


def test_older_scaffold_matches_exact_template_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = create_new_draft("scenario", "starter", description="", project_root=tmp_path)
    receipt = source.parent.parent / "draft.json"
    marker = json.loads(receipt.read_bytes())
    marker.pop("scaffold_sha256")
    receipt.write_text(json.dumps(marker))
    data = yaml.safe_load(source.read_bytes())
    data["baseline_activity"].pop("description")
    source.write_text(yaml.safe_dump(data))
    assert is_starter_draft(source)
    data["composition"] = {"organization": "testing:organization:example@1.0.0"}
    source.write_text(yaml.safe_dump(data))
    assert not is_starter_draft(source)  # Empty inline entities may be supplied by packs.
    data["composition"] = {}
    source.write_text(yaml.safe_dump(data))
    marker["draft_id"] = "different"
    receipt.write_text(json.dumps(marker))
    assert not is_starter_draft(source)


def test_broken_source_or_receipt_is_not_hidden_as_a_starter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    source = create_new_draft("scenario", "starter", description="", project_root=tmp_path)
    receipt = source.parent.parent / "draft.json"
    receipt.write_text("[]")
    assert not is_starter_draft(source)
    receipt.unlink()
    assert not is_starter_draft(source)
    source.write_text("environment: [broken")
    assert not is_starter_draft(source)
    source.unlink()
    assert not is_starter_draft(source)
