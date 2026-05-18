# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for extra syslog activity selection helpers."""

from evidenceforge.generation.activity.extra_syslog import filter_syslog_messages


def test_filter_syslog_messages_skips_invalid_overlay_weights() -> None:
    programs = [
        {"app": "bad-string", "messages": ["ignored"], "weight": "not-a-number"},
        {"app": "bad-negative", "messages": ["ignored"], "weight": -1_000_000},
        {"app": "bad-zero", "messages": ["ignored"], "weight": 0},
        {"app": "bad-bool", "messages": ["ignored"], "weight": True},
        {"app": "good", "messages": ["kept"], "weight": 4},
    ]

    filtered = filter_syslog_messages(programs, is_rhel_like=False, host_roles=None)

    assert filtered == [("good", ["kept"], 4)]


def test_filter_syslog_messages_returns_empty_when_all_weights_are_invalid() -> None:
    programs = [
        {"app": "bad-string", "messages": ["ignored"], "weight": "not-a-number"},
        {"app": "bad-negative", "messages": ["ignored"], "weight": -1_000_000},
    ]

    assert filter_syslog_messages(programs, is_rhel_like=False, host_roles=None) == []


def test_filter_syslog_messages_preserves_default_and_castable_weights() -> None:
    programs = [
        {"app": "default", "messages": ["default weight"]},
        {"app": "castable", "messages": ["cast weight"], "weight": "3"},
    ]

    filtered = filter_syslog_messages(programs, is_rhel_like=False, host_roles=None)

    assert filtered == [
        ("default", ["default weight"], 10),
        ("castable", ["cast weight"], 3),
    ]
