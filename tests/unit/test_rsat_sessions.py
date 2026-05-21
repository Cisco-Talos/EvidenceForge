# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for RSAT (Remote Server Administration Tools) session generation."""

import random
from datetime import UTC, datetime, timedelta

from evidenceforge.generation.activity.rsat_tools import load_rsat_tools, pick_rsat_tool
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


class TestRsatConfig:
    def test_config_loads(self) -> None:
        tools = load_rsat_tools()
        assert len(tools) >= 5

    def test_required_fields_present(self) -> None:
        required = {"id", "snap_in", "command_line", "target_ports", "weight"}
        for tool in load_rsat_tools():
            missing = required - set(tool.keys())
            assert not missing, f"Tool {tool.get('id')} missing {missing}"

    def test_target_ports_have_port_and_service(self) -> None:
        for tool in load_rsat_tools():
            for port_info in tool["target_ports"]:
                assert "port" in port_info, f"{tool['id']} port_info missing port"
                assert "service" in port_info, f"{tool['id']} port_info missing service"

    def test_loaded_modules_have_windows_paths(self) -> None:
        for tool in load_rsat_tools():
            for mod in tool.get("loaded_modules", []):
                assert "\\" in mod["path"], f"{tool['id']} module path not a Windows path"


class TestRsatToolSelection:
    def test_pick_returns_valid_tool(self) -> None:
        rng = random.Random(42)
        tool = pick_rsat_tool(rng)
        assert "id" in tool
        assert "command_line" in tool

    def test_weighted_selection_favors_high_weight(self) -> None:
        rng = random.Random(42)
        counts: dict[str, int] = {}
        for _ in range(1000):
            tool = pick_rsat_tool(rng)
            counts[tool["id"]] = counts.get(tool["id"], 0) + 1
        assert counts.get("aduc", 0) > counts.get("dfs_mgr", 0), (
            "aduc (weight 40) should appear more often than dfs_mgr (weight 5)"
        )

    def test_all_tools_selectable(self) -> None:
        rng = random.Random(42)
        seen = set()
        for _ in range(500):
            seen.add(pick_rsat_tool(rng)["id"])
        tools = load_rsat_tools()
        assert seen == {t["id"] for t in tools}


class TestRsatSessionTiming:
    def test_rsat_activity_moves_after_existing_future_workstation_session(self) -> None:
        mixin = BaselineMixin()
        mixin.state_manager = StateManager()
        user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha@example.com",
            enabled=True,
        )
        system = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
        )
        base_time = datetime(2024, 3, 18, 13, 1, tzinfo=UTC)
        future_time = datetime(2024, 3, 18, 13, 8, tzinfo=UTC)
        mixin.state_manager.set_current_time(future_time)
        mixin.state_manager.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=future_time,
            session_kind="interactive",
        )

        aligned = mixin._align_rsat_with_future_workstation_session(
            user,
            system,
            base_time,
            base_time.replace(hour=14),
            random.Random(7),
        )

        assert aligned is not None
        assert future_time < aligned < base_time.replace(hour=14)

    def test_rsat_activity_skips_when_future_session_too_close_to_hour_end(self) -> None:
        mixin = BaselineMixin()
        mixin.state_manager = StateManager()
        user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha@example.com",
            enabled=True,
        )
        system = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
        )
        base_time = datetime(2024, 3, 18, 13, 45, tzinfo=UTC)
        hour_end = datetime(2024, 3, 18, 14, 0, tzinfo=UTC)
        future_time = hour_end - timedelta(seconds=5)
        mixin.state_manager.set_current_time(future_time)
        mixin.state_manager.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=future_time,
            session_kind="interactive",
        )

        aligned = mixin._align_rsat_with_future_workstation_session(
            user,
            system,
            base_time,
            hour_end,
            random.Random(7),
        )

        assert aligned is None
