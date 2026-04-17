# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for CallTrace patterns YAML loader."""

from evidenceforge.generation.activity.calltrace_patterns import load_calltrace_patterns


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
