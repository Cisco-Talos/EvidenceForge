# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Preboot placement stays inside explicit support and preserves other installations."""

from datetime import UTC, datetime, timedelta

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.config import get_activity_directory
from evidenceforge.config.schemas import MacosInstalledFileProfile
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_installed_provisioning import (
    compile_macos_installed_provisioning,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import resolve_time_window
from tests.unit.test_macos_installed_provisioning import _deployments, _scenario


def _profile() -> dict:
    return yaml.safe_load((get_activity_directory() / "macos_installed_files.yaml").read_text())


def test_preboot_products_consume_known_boot_but_third_party_dates_stay_unchanged() -> None:
    scenario = _scenario()
    deployments = _deployments(scenario)
    start, end = resolve_time_window(scenario.time_window)
    boot = start - timedelta(days=90)
    identities = IdentityDirectory.from_scenario(scenario)
    common = dict(window_start=start - timedelta(hours=1), window_end=end)
    before = compile_macos_installed_provisioning(scenario, deployments, identities, **common)
    after = compile_macos_installed_provisioning(
        scenario, deployments, identities, boot_times={"MAC-01": boot}, **common
    )
    assert before is not None and after is not None
    delta = boot - datetime(1970, 1, 1, tzinfo=UTC)
    boot_ns = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000
    selected, other = 0, 0
    for installation in deployments.iter_installations_on_host("MAC-01"):
        if installation.platform != "macos":
            continue
        for path in installation.image_paths:
            binary = deployments.resolve_binary(
                "MAC-01", path, "macos", principal=installation.principal
            )
            selected_installation = deployments.installation_for_image(
                "MAC-01", path, "macos", principal=installation.principal
            )
            if selected_installation != installation:
                continue
            old = before.filesystem.observe_image(
                "MAC-01", path, installation.principal, binary=binary, observed_at=start
            )
            new = after.filesystem.observe_image(
                "MAC-01", path, installation.principal, binary=binary, observed_at=start
            )
            assert new.binary == old.binary and new.metadata.size_bytes == old.metadata.size_bytes
            assert new.metadata.modified == old.metadata.modified
            if installation.scope == "machine" and binary.key.product_id == "apple-macos":
                selected += 1
                born = new.metadata.born
                assert born.seconds * 1_000_000_000 + born.nanoseconds < boot_ns
            else:
                other += 1
                assert (new.metadata.born, new.metadata.changed, new.metadata.accessed) == (
                    old.metadata.born,
                    old.metadata.changed,
                    old.metadata.accessed,
                )
    assert selected > 3 and other > 0


def test_legacy_profile_keeps_its_prior_dates_even_with_explicit_boot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import evidenceforge.generation.macos_installed_provisioning as production

    data = _profile()
    data.pop("preboot_product_ids", None)
    profile = MacosInstalledFileProfile.model_validate(data)
    monkeypatch.setattr(production, "load_macos_installed_file_profile", lambda: profile)
    scenario = _scenario()
    deployments = _deployments(scenario)
    start, end = resolve_time_window(scenario.time_window)
    identities = IdentityDirectory.from_scenario(scenario)
    common = dict(window_start=start - timedelta(hours=1), window_end=end)
    before = compile_macos_installed_provisioning(scenario, deployments, identities, **common)
    after = compile_macos_installed_provisioning(
        scenario,
        deployments,
        identities,
        boot_times={"MAC-01": start - timedelta(days=90)},
        **common,
    )
    binary = deployments.resolve_binary("MAC-01", "/sbin/launchd", "macos", principal="root")
    assert before.filesystem.observe_image(
        "MAC-01", "/sbin/launchd", "root", binary=binary, observed_at=start
    ) == after.filesystem.observe_image(
        "MAC-01", "/sbin/launchd", "root", binary=binary, observed_at=start
    )


def test_incompatible_preboot_age_support_fails_without_expanding_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import evidenceforge.generation.macos_installed_provisioning as production

    data = _profile()
    data["preboot_product_ids"] = ["apple-macos"]
    data["installation_age_seconds"] = {"min": 1, "max": 86400}
    profile = MacosInstalledFileProfile.model_validate(data)
    monkeypatch.setattr(production, "load_macos_installed_file_profile", lambda: profile)
    scenario = _scenario()
    start, end = resolve_time_window(scenario.time_window)
    with pytest.raises(StateError, match="configured age support"):
        compile_macos_installed_provisioning(
            scenario,
            _deployments(scenario),
            IdentityDirectory.from_scenario(scenario),
            window_start=start - timedelta(hours=1),
            window_end=end,
            boot_times={"MAC-01": start - timedelta(days=90)},
        )


def test_release_after_preboot_deadline_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:

    scenario = _scenario()
    deployments = _deployments(scenario)
    start, end = resolve_time_window(scenario.time_window)
    monkeypatch.setattr(
        type(deployments),
        "binary_available_from",
        lambda self, content_id: (start - timedelta(days=2)).date(),
    )
    with pytest.raises(StateError, match="release must precede"):
        compile_macos_installed_provisioning(
            scenario,
            deployments,
            IdentityDirectory.from_scenario(scenario),
            window_start=start - timedelta(hours=1),
            window_end=end,
            boot_times={"MAC-01": start - timedelta(days=90)},
        )


@pytest.mark.parametrize(
    "selectors", [[""], ["apple-macos", "apple-macos"], ["apple-macos\0"], [" apple-macos"]]
)
def test_invalid_preboot_product_selectors_are_rejected(selectors: list[str]) -> None:
    data = _profile()
    data["preboot_product_ids"] = selectors
    with pytest.raises(ValidationError):
        MacosInstalledFileProfile.model_validate(data)
