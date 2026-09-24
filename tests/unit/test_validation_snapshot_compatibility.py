# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Only recognized immutable validation snapshots receive compatibility decoding."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.config import get_config_directory, provider
from evidenceforge.formats.snapshot_compatibility import decode_validation_snapshot
from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.utils.yaml_loader import load_yaml_text

ROOT = Path(__file__).parents[1] / "fixtures/record_validation/legacy"


@pytest.mark.parametrize("name", ["zeek_conn", "thresholds"])
def test_known_snapshot_decodes_without_mutating_input(monkeypatch, name: str) -> None:
    group = "evaluation" if name == "thresholds" else "formats"
    path = get_config_directory() / group / f"{name}.yaml"
    legacy = load_yaml_text((ROOT / path.name).read_text())
    original = deepcopy(legacy)
    runtime = load_yaml_text(path.read_text())
    effective = SimpleNamespace(
        ambient_overlay_compat=False, packaged_defaults={f"{group}/{name}.yaml": legacy}
    )
    monkeypatch.setattr(provider, "current_effective_config", lambda: effective)
    assert decode_validation_snapshot(path, legacy) == runtime
    assert legacy == original
    if name != "thresholds":
        assert runtime["output"] == legacy["output"]
    changed = deepcopy(legacy)
    changed["unexpected"] = True
    assert decode_validation_snapshot(path, changed) is changed
    monkeypatch.setattr(provider, "current_effective_config", lambda: None)
    assert decode_validation_snapshot(path, legacy) is legacy
    assert decode_validation_snapshot(path, runtime) is runtime


def test_legacy_windows_snapshot_refuses_changed_native_rdp_rendering(monkeypatch) -> None:
    """A pre-4778/4779 contract snapshot cannot silently retain non-native fields."""
    path = get_config_directory() / "formats/windows_event_security.yaml"
    legacy = load_yaml_text((ROOT / path.name).read_text())
    original = deepcopy(legacy)
    effective = SimpleNamespace(
        ambient_overlay_compat=False,
        packaged_defaults={"formats/windows_event_security.yaml": legacy},
    )
    monkeypatch.setattr(provider, "current_effective_config", lambda: effective)

    with pytest.raises(ConfigurationError, match="rendering-compatible"):
        decode_validation_snapshot(path, legacy)
    assert legacy == original


def test_decoder_refuses_changed_rendering(monkeypatch) -> None:
    import evidenceforge.formats.snapshot_compatibility as decoder

    path = get_config_directory() / "formats/zeek_conn.yaml"
    legacy = load_yaml_text((ROOT / path.name).read_text())
    monkeypatch.setattr(decoder, "packaged_default_document", lambda path: (True, legacy))
    runtime = deepcopy(legacy)
    runtime["output"]["template"] += "changed"
    monkeypatch.setattr(decoder, "load_yaml_text", lambda *args, **kwargs: runtime)
    with pytest.raises(ConfigurationError, match="rendering-compatible"):
        decoder.decode_validation_snapshot(path, legacy)
