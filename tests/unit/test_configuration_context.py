"""Optional layered contexts preserve legacy CLI and per-family merge contracts."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import write_resolved_scenario
from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.context import ConfigurationContextError, select_context
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay, merge_keyed_list
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.sysmon_filters import _merge_sysmon_filters


def write_yaml(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


def context_files(root: Path) -> tuple[Path, Path]:
    root.mkdir(exist_ok=True)
    source = root / "scenarios/scenario.yaml"
    source.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[1] / "fixtures/scenarios/minimal.yaml", source)
    (root / "project-config").mkdir()
    (root / "scenario-config").mkdir()
    context = write_yaml(
        root / "contexts/clinic.yaml",
        {
            "context_version": "1.0",
            "project_root": "..",
            "overlays": [
                {"name": "Clinic", "path": "../project-config"},
                {"name": "Scenario", "path": "../scenario-config"},
            ],
        },
    )
    return source, context


def test_context_is_explicit_and_paths_are_declaring_file_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "workspace"
    _, context = context_files(root)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert select_context().project_root == other
    selected = select_context(context=context)
    assert selected.project_root == root
    assert [layer.path for layer in selected.overlays] == [
        root / "project-config",
        root / "scenario-config",
    ]
    assert not (other / ".eforge").exists()
    with pytest.raises(ConfigurationContextError, match="conflicts"):
        select_context(other, context)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unknown", "symlink"])
def test_bad_context_fails_without_fallback_or_writes(tmp_path: Path, mutation: str) -> None:
    source, context = context_files(tmp_path)
    document = yaml.safe_load(context.read_text())
    if mutation == "missing":
        document["overlays"][0]["path"] = "../missing"
    elif mutation == "duplicate":
        document["overlays"].append(document["overlays"][0])
    elif mutation == "unknown":
        document["evaluation_threshold"] = 0
    else:
        link = tmp_path / "linked"
        link.symlink_to(tmp_path / "project-config")
        document["overlays"][0]["path"] = "../linked"
    write_yaml(context, document)
    before = sorted(str(path) for path in tmp_path.rglob("*"))
    with pytest.raises(ConfigurationContextError):
        compile_scenario(source, context=context)
    assert before == sorted(str(path) for path in tmp_path.rglob("*"))


def test_legacy_effective_config_and_digest_remain_unchanged(tmp_path: Path) -> None:
    source, context = context_files(tmp_path)
    legacy = compile_scenario(source, project_root=tmp_path)
    assert "overlay_layers" not in legacy.effective_config.model_dump(mode="json")
    assert "configuration_context" not in legacy.provenance
    assert legacy.digests == compile_scenario(source, project_root=tmp_path, context=None).digests
    # Creating a context does not opt the ordinary invocation into it.
    write_yaml(tmp_path / "project-config/activity/traffic_rates.yaml", {"global_multiplier": 0.01})
    assert compile_scenario(source, project_root=tmp_path).digests == legacy.digests


def test_real_family_loaders_apply_layers_without_leaking_between_contexts(tmp_path: Path) -> None:
    from evidenceforge.generation.activity.public_identity_profiles import (
        load_public_identity_profiles,
    )
    from evidenceforge.generation.activity.smb_profiles import load_smb_profiles

    _, context = context_files(tmp_path)
    write_yaml(
        tmp_path / "project-config/activity/smb_profiles.yaml",
        {"client_profiles": {"linux_cifs_mount": {"weight": 22}}},
    )
    write_yaml(
        tmp_path / "scenario-config/activity/smb_profiles.yaml",
        {"client_profiles": {"linux_cifs_mount": {"weight": 44}}},
    )
    write_yaml(
        tmp_path / "project-config/activity/public_identity_profiles.yaml",
        {"providers": [{"id": "hostile-scanner", "weight": 7}]},
    )
    write_yaml(
        tmp_path / "scenario-config/activity/public_identity_profiles.yaml",
        {"providers": [{"id": "hostile-scanner", "weight": 9}]},
    )
    selected = build_management_effective_config(context=context)
    defaults = build_management_effective_config(tmp_path)
    with effective_config_scope(selected):
        assert load_smb_profiles().client_profiles["linux_cifs_mount"].weight == 44
        assert (
            next(
                entry
                for entry in load_public_identity_profiles()["providers"]
                if entry["id"] == "hostile-scanner"
            )["weight"]
            == 9
        )
        with effective_config_scope(defaults):
            assert (
                next(
                    entry
                    for entry in load_public_identity_profiles()["providers"]
                    if entry["id"] == "hostile-scanner"
                )["weight"]
                == 1
            )
        assert (
            next(
                entry
                for entry in load_public_identity_profiles()["providers"]
                if entry["id"] == "hostile-scanner"
            )["weight"]
            == 9
        )


@pytest.mark.parametrize(
    "command", [["info"], ["validate-config"], ["resolve"], ["validate"], ["resources", "predict"]]
)
def test_explicit_missing_context_has_readable_json_errors(
    tmp_path: Path, command: list[str]
) -> None:
    source, _ = context_files(tmp_path)
    args = [*command]
    if command[0] in {"resolve", "validate", "resources"}:
        args.append(str(source))
    if command[0] == "resolve":
        args.append("--explain-composition")
    result = CliRunner().invoke(app, [*args, "--context", str(tmp_path / "missing.yaml"), "--json"])
    assert result.exit_code != 0
    data = json.loads(result.stdout)
    assert "context" in str(data).lower()
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("strategy", ["deep", "keyed", "section"])
def test_layers_replay_family_merge_in_order_and_keep_replace_directives(
    tmp_path: Path, strategy: str
) -> None:
    _, context = context_files(tmp_path)
    family = "activity/traffic_rates.yaml"
    if strategy == "deep":
        initial = {"settings": {"values": ["default"], "enabled": True}}
        base = {"settings": {"values": ["base"]}}
        project = {"settings": {"values": ["project"]}}
        scenario = {"settings": {"enabled": False}}
        merge = deep_merge_dict
        expected = {"settings": {"values": ["default", "base", "project"], "enabled": False}}
    elif strategy == "keyed":
        initial = {"entries": [{"id": "one", "values": ["default"], "weight": 1}]}
        base = {"entries": [{"id": "one", "values": ["base"]}]}
        project = {"entries": [{"id": "one", "values": ["project"], "_replace": True}]}
        scenario = {"entries": [{"id": "one", "weight": 9}]}

        def merge(lower: dict, higher: dict) -> dict:
            return {"entries": merge_keyed_list(lower["entries"], higher["entries"], "id")}

        expected = {"entries": [{"id": "one", "values": ["project"], "weight": 9}]}
    else:
        initial = {"section": {"a": True, "b": True}, "retained": {"c": True}}
        base = {"section": {"a": False}}
        project = {"section": {"b": False}}
        scenario = {"other": {"d": True}}
        merge = _merge_sysmon_filters
        expected = {"section": {"b": False}, "retained": {"c": True}, "other": {"d": True}}
    packaged = write_yaml(tmp_path / "defaults.yaml", initial)
    write_yaml(tmp_path / ".eforge/config" / family, base)
    write_yaml(tmp_path / "project-config" / family, project)
    write_yaml(tmp_path / "scenario-config" / family, scenario)
    effective = build_management_effective_config(context=context)
    with effective_config_scope(effective, refresh_legacy_globals=False):
        actual = load_with_overlay(packaged, family, merge)
    assert actual == expected


def test_resolved_context_survives_original_configuration_deletion(tmp_path: Path) -> None:
    source, context = context_files(tmp_path)
    write_yaml(tmp_path / "project-config/activity/traffic_rates.yaml", {"global_multiplier": 0.02})
    compiled = compile_scenario(source, context=context)
    snapshot = write_resolved_scenario(compiled, tmp_path / "snapshot")
    shutil.rmtree(tmp_path / "project-config")
    shutil.rmtree(tmp_path / "scenario-config")
    context.unlink()
    restored = compile_scenario(snapshot)
    assert all(restored.digests[key] == value for key, value in compiled.digests.items())
    assert restored.effective_config.overlay_layers == compiled.effective_config.overlay_layers
    with pytest.raises(ConfigurationContextError, match="omit --context"):
        compile_scenario(snapshot, context=context)


def test_cli_info_and_resolve_use_the_same_context_without_studio(tmp_path: Path) -> None:
    source, context = context_files(tmp_path)
    write_yaml(
        tmp_path / "project-config/activity/dns_registry.yaml",
        {
            "valid_tags": {"clinic": "Clinic traffic"},
            "domains": [{"domain": "clinic.internal", "tags": ["clinic"], "ips": ["10.0.0.5"]}],
        },
    )
    runner = CliRunner()
    info = runner.invoke(app, ["info", "dns_tags", "--context", str(context), "--json"])
    assert info.exit_code == 0, info.output
    assert "clinic" in json.loads(info.stdout)
    resolved = runner.invoke(
        app, ["resolve", str(source), "--context", str(context), "--explain-composition", "--json"]
    )
    assert resolved.exit_code == 0, resolved.output
    assert (
        json.loads(resolved.stdout)["compiled_sha256"]
        == compile_scenario(source, context=context).digests["compiled_sha256"]
    )


def test_invalid_extra_layer_identifies_its_declaring_file(tmp_path: Path) -> None:
    _, context = context_files(tmp_path)
    patch = write_yaml(
        tmp_path / "scenario-config/activity/traffic_rates.yaml", {"global_multiplier": "invalid"}
    )
    result = CliRunner().invoke(app, ["validate-config", "--context", str(context), "--json"])
    assert result.exit_code != 0
    assert str(patch) in result.stdout
