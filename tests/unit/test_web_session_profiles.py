# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for inbound web visitor profile config."""

import random

import pytest

from evidenceforge.generation.activity.web_session_profiles import (
    load_web_session_profiles,
    pick_profile_request,
    pick_web_user_agent,
    pick_web_visitor_profile,
    request_count_bounds,
    reset_web_session_profiles_cache,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    reset_web_session_profiles_cache()
    yield
    reset_web_session_profiles_cache()


def test_web_session_profiles_load_default_classes():
    data = load_web_session_profiles()

    assert "visitor_classes" in data
    assert "human_browser" in data["visitor_classes"]
    assert data["visitor_classes"]["human_browser"]["kind"] == "session"
    assert "user_agent_pools" in data
    assert data["user_agent_pools"]["browser_any"]


def test_external_profile_selection_excludes_internal_health_checks():
    rng = random.Random(4)

    for _ in range(100):
        name, _profile = pick_web_visitor_profile(rng, is_external=True)
        assert name != "health_check"


def test_health_check_profile_is_server_scoped():
    profile = load_web_session_profiles()["visitor_classes"]["health_check"]

    assert profile["source_type_any"] == ["server", "domain_controller"]
    assert "monitoring" in profile["source_role_any"]


def test_internal_human_browser_profile_is_workstation_scoped():
    profile = load_web_session_profiles()["visitor_classes"]["human_browser"]

    assert profile["source_type_any"] == ["workstation"]


def test_user_agent_honors_source_os_pool():
    profile = load_web_session_profiles()["visitor_classes"]["human_browser"]
    ua = pick_web_user_agent(random.Random(1), profile, source_os="linux")

    assert "Linux" in ua


def test_profile_request_and_bounds_are_safe():
    profile = load_web_session_profiles()["visitor_classes"]["opportunistic_probe"]
    request = pick_profile_request(random.Random(3), profile)
    lo, hi = request_count_bounds(profile)

    assert request["status"] in {403, 404}
    assert 1 <= lo <= hi
