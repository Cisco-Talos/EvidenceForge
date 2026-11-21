# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unknown client defaults do not invent an OS or replace selected wire headers."""

import random
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.activity import proxy_user_agents as agents
from evidenceforge.generation.engine.baseline import BaselineMixin

WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/121.0.0.0 Safari/537.36"


def _data() -> dict[str, Any]:
    return {
        "workstation": {"windows": [WINDOWS]},
        "unknown_source": {"user_agents": [MAC]},
        "browser_process_families": {"chrome": ["chrome.exe"]},
    }


def test_unknown_default_uses_configured_unmodeled_client_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agents, "load_proxy_user_agents", _data)
    assert agents.pick_proxy_user_agent(random.Random(1), None) == MAC


def test_unknown_process_family_filters_the_generic_presentation_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agents, "load_proxy_user_agents", _data)
    assert agents.browser_user_agent_for_process(random.Random(1), None, "chrome.exe") == MAC


def test_real_generator_default_uses_unknown_client_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.unit.test_http_channel_integration import _generator

    monkeypatch.setattr(agents, "load_proxy_user_agents", _data)
    generator, _state, _emitters = _generator(formats=())
    assert (
        generator._proxy_user_agent_for_context(
            random.Random(3),
            None,
            hostname="portal.example.test",
            domain_tags=[],
            apply_domain_override=False,
            source_identity="192.0.2.17",
        )
        == MAC
    )


def test_frozen_catalog_without_optional_policy_keeps_previous_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _data()
    del data["unknown_source"]
    monkeypatch.setattr(agents, "load_proxy_user_agents", lambda: data)
    assert agents.pick_proxy_user_agent(random.Random(1), None) == WINDOWS
    assert agents.browser_user_agent_for_process(random.Random(1), None, "chrome.exe") == WINDOWS


def test_real_frozen_catalog_does_not_acquire_new_packaged_policy(tmp_path: Path) -> None:
    from evidenceforge.composition.compiler import build_management_effective_config
    from evidenceforge.config.provider import effective_config_scope

    defaults = build_management_effective_config(tmp_path)
    packaged = deepcopy(defaults.packaged_defaults)
    packaged["activity/proxy_user_agents.yaml"].pop("unknown_source", None)
    old = defaults.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(old):
        catalog = agents.load_proxy_user_agents()
        assert "unknown_source" not in catalog
        expected = set(catalog["workstation"]["windows"])
        assert {
            agents.pick_proxy_user_agent(random.Random(seed), None) for seed in range(16)
        } == expected


@pytest.mark.parametrize("selected", [MAC, WINDOWS, "AhrefsBot/7.0"])
def test_selected_header_survives_real_activity_generator_boundary(
    monkeypatch: pytest.MonkeyPatch, selected: str
) -> None:
    import evidenceforge.generation.activity.web_session_profiles as profiles
    from tests.unit.test_http_channel_integration import _generator

    monkeypatch.setattr(
        profiles,
        "load_web_session_profiles",
        lambda: {"user_agent_pools": {"selected": [selected]}},
    )
    generator, _state, _emitters = _generator(formats=())
    engine = BaselineMixin()
    engine.activity_generator = generator
    assert (
        engine._source_sticky_browser_user_agent(
            source_system=None,
            src_ip="192.0.2.17",
            os_cat="external",
            rng=random.Random(3),
            profile={"user_agent_pool": "selected"},
        )
        == selected
    )


@pytest.mark.parametrize(
    "profile",
    [
        {"user_agents": []},
        {"user_agents": ["bad\nheader"]},
        {"user_agents": [" "]},
        {"user_agents": ["x"], "typo": True},
    ],
)
def test_invalid_selected_profile_reports_runtime_and_configuration_errors(
    monkeypatch: pytest.MonkeyPatch, profile: dict[str, Any]
) -> None:
    from evidenceforge.models.exceptions import ConfigurationError
    from evidenceforge.validation.configuration import (
        ValidationResult,
        _validate_unknown_source_user_agents,
    )

    data = _data()
    data["unknown_source"] = profile
    monkeypatch.setattr(agents, "load_proxy_user_agents", lambda: data)
    with pytest.raises(ConfigurationError, match="unknown_source"):
        agents.pick_proxy_user_agent(random.Random(1), None)
    result = ValidationResult()
    _validate_unknown_source_user_agents(result, data)
    assert len(result.issues) == 1
    assert result.issues[0].severity == "ERROR"
