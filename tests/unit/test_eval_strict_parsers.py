# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for strict-mode validators in evidenceforge.formats.validator."""

from evidenceforge.formats.validator import STRICT_FORMATS, validate_strict

# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------


class TestStrictSyslog:
    def test_bsd_without_legacy_marker_is_invalid(self):
        """Generated syslog strict mode requires RFC 5424."""
        raw = "Mar 18 12:00:00 PROXY-01 sudo[50424]: root : TTY=pts/1"
        result = validate_strict("syslog", raw, {})
        assert not result.valid
        assert any("rfc 5424" in e.lower() for e in result.errors)

    def test_legacy_bsd_parser_records_are_valid(self):
        """Legacy BSD remains acceptable when the parser marks it as eval fallback input."""
        raw = "Mar 18 12:00:00 PROXY-01 sudo[50424]: root : TTY=pts/1"
        result = validate_strict("syslog", raw, {"syslog_protocol": "rfc3164_legacy"})
        assert result.valid, result.errors

    def test_valid_rfc5424_with_pri(self):
        """RFC 5424 with PRI < 192 — valid."""
        raw = "<86>1 2026-03-18T12:00:00.000000Z PROXY-01 sudo 50424 - - message"
        result = validate_strict("syslog", raw, {})
        assert result.valid, result.errors

    def test_valid_pri_boundary_191(self):
        """PRI == 191 is the maximum valid priority."""
        raw = "<191>1 2026-03-18T12:00:00Z host app 123 - - msg"
        result = validate_strict("syslog", raw, {})
        assert result.valid, result.errors

    def test_invalid_bsd_no_pri_wrong_format(self):
        """Plain text that is not RFC 5424 — fails."""
        raw = "not a syslog line"
        result = validate_strict("syslog", raw, {})
        assert not result.valid
        assert any("rfc 5424" in e.lower() for e in result.errors)

    def test_invalid_pri_exceeds_191(self):
        """PRI > 191 — fails."""
        raw = "<200>1 2026-03-18T12:00:00Z host app 123 - - msg"
        result = validate_strict("syslog", raw, {})
        assert not result.valid
        assert any("192" in e or "200" in e or "191" in e for e in result.errors)

    def test_invalid_malformed_pri_bracket(self):
        """Opening angle bracket without digits — fails."""
        raw = "<>1 2026-03-18T12:00:00Z host app 123 - - msg"
        result = validate_strict("syslog", raw, {})
        assert not result.valid

    def test_invalid_rfc5424_version(self):
        """RFC 5424 VERSION must be 1."""
        raw = "<86>2 2026-03-18T12:00:00Z host app 123 - - msg"
        result = validate_strict("syslog", raw, {})
        assert not result.valid
        assert any("version" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# Zeek JSON
# ---------------------------------------------------------------------------


class TestStrictZeekJson:
    def test_valid_zeek_json_object(self):
        """A well-formed JSON object passes."""
        raw = '{"ts": 1234567890.0, "uid": "CabcDEF"}'
        result = validate_strict("zeek_files", raw, {})
        assert result.valid, result.errors

    def test_valid_zeek_conn_json(self):
        raw = '{"ts": 1700000000.0, "uid": "C1234", "id.orig_h": "10.0.0.1"}'
        result = validate_strict("zeek_conn", raw, {})
        assert result.valid, result.errors

    def test_invalid_csv_line(self):
        """Old-style Zeek TSV/CSV is not valid JSON — fails."""
        raw = "10.0.0.1,10.0.0.2,12345,443"
        result = validate_strict("zeek_files", raw, {})
        assert not result.valid
        assert any("json" in e.lower() for e in result.errors)

    def test_invalid_json_array_not_object(self):
        """JSON array at top level — fails (must be object)."""
        raw = "[1, 2, 3]"
        result = validate_strict("zeek_http", raw, {})
        assert not result.valid
        assert any("object" in e.lower() for e in result.errors)

    def test_invalid_bare_string(self):
        """A bare JSON string — fails."""
        raw = '"just a string"'
        result = validate_strict("zeek_ssl", raw, {})
        assert not result.valid

    def test_empty_line_is_valid(self):
        """Empty / whitespace-only line is skipped without error."""
        result = validate_strict("zeek_conn", "   ", {})
        assert result.valid


# ---------------------------------------------------------------------------
# Windows XML
# ---------------------------------------------------------------------------

_VALID_WINDOWS_XML = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>"""

_WRONG_ROOT_XML = "<Log xmlns='http://example.com'><System/></Log>"

_MISSING_SYSTEM_XML = "<Event xmlns='http://schemas.microsoft.com'><EventData/></Event>"


class TestStrictWindowsXml:
    def test_valid_event_xml(self):
        """Well-formed XML with Event root and System child — passes."""
        result = validate_strict("windows_event_security", _VALID_WINDOWS_XML, {})
        assert result.valid, result.errors

    def test_invalid_malformed_xml(self):
        """XML that fails to parse — fails."""
        raw = "<Event><no close>"
        result = validate_strict("windows_event_security", raw, {})
        assert not result.valid
        assert any("xml" in e.lower() for e in result.errors)

    def test_wrong_root_element(self):
        """Root element other than Event — fails."""
        result = validate_strict("windows_event_security", _WRONG_ROOT_XML, {})
        assert not result.valid
        assert any("event" in e.lower() for e in result.errors)

    def test_missing_system_child(self):
        """Event root without a System child — fails."""
        result = validate_strict("windows_event_security", _MISSING_SYSTEM_XML, {})
        assert not result.valid
        assert any("system" in e.lower() for e in result.errors)

    def test_sysmon_format_also_checked(self):
        """windows_event_sysmon uses the same XML validator."""
        result = validate_strict("windows_event_sysmon", _VALID_WINDOWS_XML, {})
        assert result.valid, result.errors

    def test_empty_raw_is_valid(self):
        """Empty raw string is silently skipped."""
        result = validate_strict("windows_event_security", "", {})
        assert result.valid


# ---------------------------------------------------------------------------
# eCAR
# ---------------------------------------------------------------------------


class TestStrictEcar:
    def test_valid_ecar_process_create(self):
        """Valid JSON with known object and action — passes."""
        raw = '{"object": "PROCESS", "action": "CREATE"}'
        result = validate_strict("ecar", raw, {})
        assert result.valid, result.errors

    def test_valid_ecar_flow_connect(self):
        raw = '{"object": "FLOW", "action": "CONNECT"}'
        result = validate_strict("ecar", raw, {})
        assert result.valid, result.errors

    def test_valid_ecar_user_session_login(self):
        raw = '{"object": "USER_SESSION", "action": "LOGIN"}'
        result = validate_strict("ecar", raw, {})
        assert result.valid, result.errors

    def test_invalid_unknown_object(self):
        """Object type not in the allowed set — fails."""
        raw = '{"object": "KERNEL_MODULE", "action": "CREATE"}'
        result = validate_strict("ecar", raw, {})
        assert not result.valid
        assert any("kernel_module" in e.lower() or "object" in e.lower() for e in result.errors)

    def test_invalid_unknown_action(self):
        """Action not in the allowed set — fails."""
        raw = '{"object": "PROCESS", "action": "EXPLODE"}'
        result = validate_strict("ecar", raw, {})
        assert not result.valid
        assert any("explode" in e.lower() or "action" in e.lower() for e in result.errors)

    def test_invalid_not_json(self):
        """Non-JSON raw string — fails."""
        raw = "not json at all"
        result = validate_strict("ecar", raw, {})
        assert not result.valid
        assert any("json" in e.lower() for e in result.errors)

    def test_invalid_json_array(self):
        """Top-level JSON array instead of object — fails."""
        raw = '[{"object": "PROCESS"}]'
        result = validate_strict("ecar", raw, {})
        assert not result.valid

    def test_missing_object_action_fields_is_valid(self):
        """Object/action are optional; missing means no enum check performed."""
        raw = '{"hostname": "WS-01", "pid": 1234}'
        result = validate_strict("ecar", raw, {})
        assert result.valid, result.errors


# ---------------------------------------------------------------------------
# STRICT_FORMATS membership
# ---------------------------------------------------------------------------


class TestStrictFormats:
    def test_required_formats_present(self):
        required = {"syslog", "zeek_files", "windows_event_security", "ecar"}
        assert required.issubset(STRICT_FORMATS), (
            f"Missing from STRICT_FORMATS: {required - STRICT_FORMATS}"
        )

    def test_zeek_variants_present(self):
        """Several zeek sub-formats must be present."""
        for fmt in ("zeek_conn", "zeek_http", "zeek_ssl", "zeek_dns"):
            assert fmt in STRICT_FORMATS, f"{fmt} not in STRICT_FORMATS"

    def test_unknown_format_returns_valid_no_errors(self):
        """Formats not covered by strict mode return an empty-valid result."""
        result = validate_strict("bash_history", "some raw line", {})
        assert result.valid
        assert result.errors == []
