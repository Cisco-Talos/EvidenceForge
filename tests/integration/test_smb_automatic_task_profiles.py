# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Configured task admission and native mounted execution use the same actor policy."""

import json
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.schemas import SmbClientProfile, SmbProfilesConfig
from evidenceforge.generation.actions import smb_activity
from evidenceforge.generation.activity.smb_profiles import (
    client_process_for_operation,
    load_smb_profiles,
    reset_smb_profiles_cache,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario, SmbActivityEventSpec, SmbShareLocation
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_smb import macos_smb_scenario


def test_default_profiles_bind_text_tasks_without_restricting_byte_inspection_or_transfers() -> (
    None
):
    reset_smb_profiles_cache()
    try:
        profiles = load_smb_profiles()
        mac = profiles.client_profiles["macos_smb_mount"]
        linux = profiles.client_profiles["linux_cifs_mount"]
        for operation in ("read", "create", "update"):
            assert ".txt" in client_process_for_operation(mac, operation).automatic_file_extensions
            assert (
                ".docx"
                not in client_process_for_operation(mac, operation).automatic_file_extensions
            )
        assert ".txt" in client_process_for_operation(linux, "update").automatic_file_extensions
        assert client_process_for_operation(linux, "read").automatic_file_extensions is None
        for name in ("macos_smb_mount", "linux_cifs_mount", "windows_explorer", "linux_smbclient"):
            profile = profiles.client_profiles[name]
            for operation in ("copy", "move", "browse"):
                process = client_process_for_operation(profile, operation)
                assert process is None or process.automatic_file_extensions is None
    finally:
        reset_smb_profiles_cache()


def test_old_frozen_profiles_retain_unrestricted_policy_and_restore_current(tmp_path: Path) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    for profile in packaged["activity/smb_profiles.yaml"]["client_profiles"].values():
        for process in [profile.get("process"), *profile.get("operation_processes", {}).values()]:
            if process is not None:
                process.pop("automatic_file_extensions", None)
    legacy = current.model_copy(update={"packaged_defaults": packaged})
    try:
        with effective_config_scope(legacy, refresh_legacy_globals=False):
            reset_smb_profiles_cache()
            assert (
                client_process_for_operation(
                    load_smb_profiles().client_profiles["macos_smb_mount"], "read"
                ).automatic_file_extensions
                is None
            )
        with effective_config_scope(current, refresh_legacy_globals=False):
            reset_smb_profiles_cache()
            assert (
                ".txt"
                in client_process_for_operation(
                    load_smb_profiles().client_profiles["macos_smb_mount"], "read"
                ).automatic_file_extensions
            )
    finally:
        reset_smb_profiles_cache()


def test_root_profile_schema_rejects_malformed_nested_task_policy() -> None:
    reset_smb_profiles_cache()
    data = load_smb_profiles().model_dump()
    data["client_profiles"]["macos_smb_mount"]["operation_processes"]["read"][
        "automatic_file_extensions"
    ] = []
    with pytest.raises(ValidationError, match="automatic_file_extensions"):
        SmbProfilesConfig.model_validate(data)
    reset_smb_profiles_cache()


@pytest.mark.slow
def test_native_auto_text_and_explicit_binary_share_the_exact_operation_owner(
    scenarios_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = macos_smb_scenario(scenarios_dir).model_dump()
    data["environment"]["storage"]["servers"][0]["shares"][0]["seed_files"].append(
        {"ref": "binary", "path": "Reports\\plan.docx", "size_bytes": 8192}
    )
    scenario = Scenario.model_validate(data)
    with generation_seed_scope(99):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        engine._chronological_es_delivery = True
        try:
            engine._initialize()
            generator = engine.activity_generator
            actor, client = scenario.environment.users[0], scenario.environment.systems[0]
            logon = generator.generate_logon(
                actor, client, engine.start_time + timedelta(minutes=1)
            )
            assert (
                generator.ensure_macos_session_shell(
                    actor, client, logon, engine.start_time + timedelta(minutes=2)
                )
                is not None
            )
            selected_scopes: list[str] = []
            original_select = smb_activity.select_client_profile

            def inspect_profile(*args: Any, **kwargs: Any) -> SmbClientProfile:
                selected_scopes.append(kwargs["scope_key"])
                return original_select(*args, **kwargs)

            monkeypatch.setattr(smb_activity, "select_client_profile", inspect_profile)
            at = engine.start_time + timedelta(minutes=10)
            automatic = SmbActivityEventSpec(
                type="smb_activity",
                operation="read",
                purpose="interactive",
                target=SmbShareLocation(share="FS-TEST.team"),
            )
            refined = generator.automatic_smb_task_spec(
                spec=automatic, actor=actor, parent_system=client, time=at
            )
            assert refined is not None and refined.target.selector is not None
            plan = generator.prepare_smb_activity(
                spec=refined, actor=actor, parent_system=client, time=at, activity_source="baseline"
            )
            assert plan.selected and all(
                file.extension in refined.target.selector.extensions for file in plan.selected
            )
            assert all(file.extension != ".docx" for file in plan.selected)
            assert generator.execute_prepared_smb_activity(plan).transport_uids
            assert len(selected_scopes) >= 2 and len(set(selected_scopes)) == 1
            explicit = automatic.model_copy(
                update={"target": SmbShareLocation(share="FS-TEST.team", file_ref="binary")}
            )
            result = generator.generate_smb_activity(
                spec=explicit,
                actor=actor,
                parent_system=client,
                time=at + timedelta(minutes=2),
                activity_source="storyline",
            )
            assert result.transport_uids
            engine._finalize_macos_process_coverage()
        finally:
            engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        if path.parent.name.startswith(client.hostname)
        for line in path.read_text().splitlines()
    ]
    files = [row for row in rows if row["object"] == "FILE"]
    assert any("plan.docx" in json.dumps(row) for row in files)
    assert any("plan.txt" in json.dumps(row) for row in files)
