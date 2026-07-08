# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for blind-safe collection profile metadata."""

from evidenceforge.events.collection_profile import build_collection_profile
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)
from evidenceforge.output_targets import OutputTarget


def test_collection_profile_describes_rendered_log_tree_only() -> None:
    """The blind-safe log-tree profile must not advertise package-root artifacts."""
    scenario = Scenario(
        version="1.0",
        name="profile-test",
        description="Profile test",
        environment=Environment(
            description="Small environment",
            users=[
                User(
                    username="analyst",
                    full_name="Analyst User",
                    email="analyst@example.com",
                    primary_system="WS-01",
                )
            ],
            systems=[
                System(
                    hostname="WS-01",
                    ip="10.10.1.10",
                    os="Windows 11",
                    type="workstation",
                )
            ],
        ),
        time_window=TimeWindow(start="2024-03-18T12:00:00Z", duration="6h"),
        baseline_activity=BaselineActivity(
            description="Baseline",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(
            logs=[{"format": "windows"}, {"format": "zeek"}],
            destination="./data",
        ),
        personas=[],
    )

    profile = build_collection_profile(scenario, OutputTarget.DEFAULT)
    families = {family.family: family for family in profile.source_families}
    formats = {fmt for family in profile.source_families for fmt in family.formats}

    assert "mail_artifacts" not in families
    assert "email_artifacts" not in formats
    assert "eml" not in formats
