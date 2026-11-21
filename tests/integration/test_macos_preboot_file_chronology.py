# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Installed OS objects consume the same boot facts as their canonical processes."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from evidenceforge.config import get_activity_directory
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.schemas import MacosInstalledFileProfile
from tests.unit.test_macos_finder_generation import _finder_engine


def test_public_boot_inventory_uses_preboot_installed_os_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import evidenceforge.generation.engine.core as core
    import evidenceforge.generation.macos_installed_provisioning as provisioning

    data = yaml.safe_load((get_activity_directory() / "macos_installed_files.yaml").read_text())
    data["installation_age_seconds"] = {"min": 1, "max": 40 * 86400}
    profile = MacosInstalledFileProfile.model_validate(data)
    monkeypatch.setattr(provisioning, "load_macos_installed_file_profile", lambda: profile)
    original_seed = core._stable_seed
    monkeypatch.setattr(
        core, "_stable_seed", lambda key: 27 if key.startswith("boot_days_") else original_seed(key)
    )
    engine = _finder_engine(tmp_path, monkeypatch, native=True)
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        boot = engine.state_manager.get_boot_time("MAC-01")
        assert boot is not None
        launchd = engine.state_manager.get_process_identity("MAC-01", 1)
        assert launchd is not None and launchd.started_at == boot
        provider = engine.macos_installed_provisioning.filesystem
        seen = set()
        for running in engine.state_manager.get_processes_on_system("MAC-01"):
            process = engine.state_manager.get_process_identity("MAC-01", running.pid)
            observation = provider.observe(
                engine.deployment_registry, process, observed_at=engine.start_time
            )
            if observation is None or observation.binary.key.product_id != "apple-macos":
                continue
            seen.add(process.image)
            born = observation.metadata.born
            epoch = datetime(1970, 1, 1, tzinfo=UTC)
            elapsed = process.started_at - epoch
            started_ns = (
                (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds
            ) * 1000
            assert born.seconds * 1_000_000_000 + born.nanoseconds < started_ns, process.image
        assert "/sbin/launchd" in seen and len(seen) > 3
    finally:
        engine._close_emitters()
