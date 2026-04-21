# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for RSAT (Remote Server Administration Tools) session generation."""

import random

from evidenceforge.generation.activity.rsat_tools import load_rsat_tools, pick_rsat_tool


class TestRsatConfig:
    def test_config_loads(self):
        tools = load_rsat_tools()
        assert len(tools) >= 5

    def test_required_fields_present(self):
        required = {"id", "snap_in", "command_line", "target_ports", "weight"}
        for tool in load_rsat_tools():
            missing = required - set(tool.keys())
            assert not missing, f"Tool {tool.get('id')} missing {missing}"

    def test_target_ports_have_port_and_service(self):
        for tool in load_rsat_tools():
            for port_info in tool["target_ports"]:
                assert "port" in port_info, f"{tool['id']} port_info missing port"
                assert "service" in port_info, f"{tool['id']} port_info missing service"

    def test_loaded_modules_have_windows_paths(self):
        for tool in load_rsat_tools():
            for mod in tool.get("loaded_modules", []):
                assert "\\" in mod["path"], f"{tool['id']} module path not a Windows path"


class TestRsatToolSelection:
    def test_pick_returns_valid_tool(self):
        rng = random.Random(42)
        tool = pick_rsat_tool(rng)
        assert "id" in tool
        assert "command_line" in tool

    def test_weighted_selection_favors_high_weight(self):
        rng = random.Random(42)
        counts: dict[str, int] = {}
        for _ in range(1000):
            tool = pick_rsat_tool(rng)
            counts[tool["id"]] = counts.get(tool["id"], 0) + 1
        assert counts.get("aduc", 0) > counts.get("dfs_mgr", 0), (
            "aduc (weight 40) should appear more often than dfs_mgr (weight 5)"
        )

    def test_all_tools_selectable(self):
        rng = random.Random(42)
        seen = set()
        for _ in range(500):
            seen.add(pick_rsat_tool(rng)["id"])
        tools = load_rsat_tools()
        assert seen == {t["id"] for t in tools}
