# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for CallTrace patterns YAML loader."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.generation.activity.calltrace_patterns import (
    load_calltrace_patterns,
    render_call_trace_for_source,
    source_family_for_image,
)
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


class TestLoadCalltracePatterns:
    """Test that the YAML loads correctly."""

    def test_returns_list(self):
        patterns = load_calltrace_patterns()
        assert isinstance(patterns, list)

    def test_at_least_8_patterns(self):
        patterns = load_calltrace_patterns()
        assert len(patterns) >= 8, f"Expected >=8 patterns, got {len(patterns)}"

    def test_each_pattern_has_modules_and_ranges(self):
        for pat in load_calltrace_patterns():
            assert "modules" in pat, f"Pattern missing 'modules': {pat}"
            assert "offset_ranges" in pat, f"Pattern missing 'offset_ranges': {pat}"
            for mod in pat["modules"]:
                assert mod in pat["offset_ranges"], f"Module {mod} not in offset_ranges"

    def test_offset_ranges_are_valid(self):
        for pat in load_calltrace_patterns():
            for mod, (lo, hi) in pat["offset_ranges"].items():
                assert lo < hi, f"{mod}: lo ({lo}) >= hi ({hi})"
                assert lo > 0, f"{mod}: lo must be positive"

    def test_source_image_maps_to_expected_family(self):
        expected = {
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe": "defender",
            r"C:\Windows\System32\csrss.exe": "csrss",
            r"C:\Windows\System32\services.exe": "services",
            r"C:\Windows\System32\svchost.exe": "svchost",
            r"C:\Windows\System32\wbem\WmiPrvSE.exe": "wmi",
            r"C:\Tools\procdump64.exe": "suspicious_tool",
        }
        for image, family in expected.items():
            assert source_family_for_image(image) == family

    def test_rendered_call_trace_uses_source_family_palette(self):
        host = "HOST-A"
        seed_parts = (500, 700, "0x1010")
        traces = {
            "defender": render_call_trace_for_source(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
                host,
                seed_parts=seed_parts,
            ),
            "csrss": render_call_trace_for_source(
                r"C:\Windows\System32\csrss.exe",
                host,
                seed_parts=seed_parts,
            ),
            "services": render_call_trace_for_source(
                r"C:\Windows\System32\services.exe",
                host,
                seed_parts=seed_parts,
            ),
            "wmi": render_call_trace_for_source(
                r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                host,
                seed_parts=seed_parts,
            ),
        }
        assert "advapi32.dll" in traces["defender"]
        assert traces["csrss"].count("|") == 0
        assert "sechost.dll" in traces["services"]
        assert "wbemcomn.dll" in traces["wmi"] or "combase.dll" in traces["wmi"]
        assert len(set(traces.values())) == len(traces)


class TestCalltraceRendering:
    """Test that rendered CallTrace strings are correct."""

    def test_offsets_consistent_per_host(self):
        """Same host should always produce the same cached patterns."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter

        fmt = load_format("windows_event_sysmon")
        emitter = SysmonEventEmitter(fmt, Path("/dev/null"))

        emitter._get_call_trace("HOST-A")
        cached = list(emitter._call_trace_cache["HOST-A"])
        # Fetch again — cache should return identical patterns
        emitter._get_call_trace("HOST-A")
        assert emitter._call_trace_cache["HOST-A"] == cached

    def test_offsets_vary_across_hosts(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter

        fmt = load_format("windows_event_sysmon")
        emitter = SysmonEventEmitter(fmt, Path("/dev/null"))

        trace_a = emitter._get_call_trace("HOST-A")
        trace_b = emitter._get_call_trace("HOST-B")
        off_a = trace_a.split("|")[0].split("+")[1]
        off_b = trace_b.split("|")[0].split("+")[1]
        assert off_a != off_b, "Different hosts should have different offsets"

    def test_more_patterns_than_before(self):
        """Should have more than the old hardcoded 3 patterns."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter

        fmt = load_format("windows_event_sysmon")
        emitter = SysmonEventEmitter(fmt, Path("/dev/null"))

        # Force cache population
        emitter._get_call_trace("HOST-TEST")
        patterns = emitter._call_trace_cache["HOST-TEST"]
        assert len(patterns) >= 8, f"Expected >=8 patterns, got {len(patterns)}"


class TestProcessAccessCallTraceOwnership:
    """ProcessAccess contexts should own source-aware CallTrace strings."""

    def test_process_access_context_gets_source_aware_call_trace(self):
        state_manager = StateManager()
        start_time = datetime(2024, 3, 18, 9, 59, 0, tzinfo=UTC)
        event_time = start_time + timedelta(minutes=1)
        state_manager.set_current_time(start_time)
        system = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2019",
            type="domain_controller",
        )
        user = User(username="svc.admin", full_name="Svc Admin", email="svc@example.com")
        target_pid = state_manager.create_process(
            system.hostname,
            4,
            r"C:\Windows\System32\lsass.exe",
            "lsass.exe",
            "NT AUTHORITY\\SYSTEM",
            "System",
            "0x3e7",
        )
        source_pid = state_manager.create_process(
            system.hostname,
            4,
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "WmiPrvSE.exe -secured -Embedding",
            "NT AUTHORITY\\SYSTEM",
            "System",
            "0x3e7",
        )
        state_manager.set_current_time(event_time)
        generator = ActivityGenerator(state_manager, {})
        dispatched = []
        generator.dispatcher = Mock()
        generator.dispatcher.dispatch.side_effect = dispatched.append

        assert generator.generate_process_access(
            user,
            system,
            event_time,
            source_pid,
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            target_pid,
            granted_access="0x1010",
        )
        access = dispatched[0].process_access
        assert access is not None
        assert access.call_trace
        assert "wbemcomn.dll" in access.call_trace or "combase.dll" in access.call_trace
