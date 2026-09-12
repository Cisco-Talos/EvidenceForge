"""Cleanup acceptance must detect evidence drift and authenticate manifests."""

import hashlib
import json
from pathlib import Path

import pytest
from scripts.compare_cleanup_output import snapshot


def test_comparison_detects_record_order_and_file_set_changes(tmp_path: Path) -> None:
    output = tmp_path / "events.log"
    output.write_bytes(b"first\nsecond\n")
    original = snapshot(tmp_path)
    output.write_bytes(b"second\nfirst\n")
    assert snapshot(tmp_path) != original
    output.write_bytes(b"first\nsecond\n")
    output.rename(tmp_path / "renamed.log")
    assert snapshot(tmp_path) != original


def test_comparison_only_exempts_manifest_creation_time(tmp_path: Path) -> None:
    payload = b"canonical evidence\n"
    (tmp_path / "events.log").write_bytes(payload)
    manifest = {
        "created_at": "2026-09-12T00:00:00Z",
        "generation_seed": 42,
        "files": {"events.log": hashlib.sha256(payload).hexdigest()},
    }
    path = tmp_path / "GENERATION_MANIFEST.json"
    path.write_text(json.dumps(manifest))
    original = snapshot(tmp_path)
    manifest["created_at"] = "2026-09-13T00:00:00Z"
    path.write_text(json.dumps(manifest))
    assert snapshot(tmp_path) == original
    manifest["generation_seed"] = 137
    path.write_text(json.dumps(manifest))
    assert snapshot(tmp_path) != original
    (tmp_path / "events.log").write_bytes(b"corrupt evidence")
    with pytest.raises(ValueError, match="Manifest hash mismatch"):
        snapshot(tmp_path)


def test_diagnostic_exception_is_scoped_to_bundle_root(tmp_path: Path) -> None:
    (tmp_path / "generation.log").write_bytes(b"runtime diagnostic")
    original = snapshot(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    (host / "generation.log").write_bytes(b"source evidence")
    assert snapshot(tmp_path) != original
