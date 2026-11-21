# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Finder phase allocation reaches native clocks without fixed ratios."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.config.provider import effective_config_scope
from tests.unit.test_macos_finder_generation import _APP, _finder_engine


def test_native_finder_phases_keep_birth_and_readiness_without_linear_subdivision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True)
    expected: dict[int, tuple[datetime, datetime]] = {}
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        system, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        original = generator._sample_profile_activity_gap
        total_gaps: list[timedelta] = []

        def capture(relationship_key: str, **kwargs: object) -> timedelta:
            result = original(relationship_key, **kwargs)
            if (
                relationship_key == "macos.finder_preimage_before_exec"
                and kwargs.get("sample_key", "gap") == "gap"
            ):
                total_gaps.append(result)
            return result

        monkeypatch.setattr(generator, "_sample_profile_activity_gap", capture)
        for index in range(3):
            at = engine.start_time + timedelta(minutes=2 + index)
            pid = generator.generate_process(
                user,
                system,
                at,
                logon,
                _APP,
                _APP,
                parent_pid=1,
                require_exact_parent=True,
                arguments=(_APP,),
                macos_launch_kind="finder",
                from_storyline=True,
            )
            identity = engine.state_manager.get_process_identity(system.hostname, pid)
            assert identity is not None and identity.started_at == at
            assert identity.execution_started_at == at + total_gaps[-1]
            expected[pid] = at, identity.execution_started_at
        assert len(expected) == 3
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    records = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    residuals = []
    for pid, (birth, ready) in expected.items():
        selected = [
            r
            for r in records
            if (r["event_type"] == 11 and r["event"]["fork"]["child"]["audit_token"]["pid"] == pid)
            or (r["event_type"] == 9 and r["process"]["audit_token"]["pid"] == pid)
        ]
        assert [r["event_type"] for r in selected] == [11, 9, 9]
        times = [datetime.fromisoformat(r["time"].replace("Z", "+00:00")) for r in selected]
        assert times[0] == birth and times[-1] == ready
        assert times[0] < times[1] < times[2]
        assert selected[0]["mach_time"] < selected[1]["mach_time"] < selected[2]["mach_time"]
        first, second = (
            round((b - a).total_seconds() * 1_000_000)
            for a, b in zip(times, times[1:], strict=False)
        )
        residuals.append(second - 2 * first)
    assert any(abs(value) > 2 for value in residuals), residuals
