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

"""Tests for cross_source.py pivot-key helpers and field-agreement logic."""

from datetime import UTC, datetime

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.plausibility import (
    PlausibilityScorer as CrossSourceScorer,
)
from evidenceforge.evaluation.pillars.plausibility import (
    _build_pivot_index,
    _matches_condition,
    _normalize_value,
    _score_pair,
    _values_agree,
)

T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


def _rec(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


# ---------------------------------------------------------------------------
# _matches_condition
# ---------------------------------------------------------------------------


class TestMatchesCondition:
    def test_empty_condition_always_matches(self):
        r = _rec("ecar", {"object": "PROCESS"})
        assert _matches_condition(r, {}) is True

    def test_simple_equality_match(self):
        r = _rec("windows_event_security", {"EventID": 4688})
        assert _matches_condition(r, {"EventID": 4688}) is True

    def test_simple_equality_no_match(self):
        r = _rec("windows_event_security", {"EventID": 4624})
        assert _matches_condition(r, {"EventID": 4688}) is False

    def test_multiple_fields_all_must_match(self):
        r = _rec("ecar", {"object": "PROCESS", "action": "CREATE"})
        assert _matches_condition(r, {"object": "PROCESS", "action": "CREATE"}) is True
        assert _matches_condition(r, {"object": "PROCESS", "action": "DELETE"}) is False

    def test_msg_id_in_present(self):
        """msg_id_in: record.fields['msg_id'] must appear in the list."""
        r = _rec("cisco_asa", {"msg_id": 302013})
        assert _matches_condition(r, {"msg_id_in": [302013, 302014]}) is True

    def test_msg_id_in_absent(self):
        r = _rec("cisco_asa", {"msg_id": 999})
        assert _matches_condition(r, {"msg_id_in": [302013, 302014]}) is False

    def test_msg_id_in_missing_field(self):
        """Record without msg_id should not match msg_id_in."""
        r = _rec("cisco_asa", {})
        assert _matches_condition(r, {"msg_id_in": [302013]}) is False

    def test_field_not_present_does_not_match(self):
        r = _rec("ecar", {"action": "CREATE"})
        assert _matches_condition(r, {"object": "PROCESS", "action": "CREATE"}) is False

    def test_field_not_excludes_matching_value(self):
        """method_not: CONNECT should reject a record whose method == CONNECT."""
        r = _rec("proxy_access", {"method": "CONNECT"})
        assert _matches_condition(r, {"method_not": "CONNECT"}) is False

    def test_field_not_passes_different_value(self):
        """method_not: CONNECT should accept a record whose method != CONNECT."""
        r = _rec("proxy_access", {"method": "GET"})
        assert _matches_condition(r, {"method_not": "CONNECT"}) is True

    def test_field_not_passes_missing_field(self):
        """method_not: CONNECT on a record with no 'method' field — None != CONNECT → passes."""
        r = _rec("proxy_access", {})
        assert _matches_condition(r, {"method_not": "CONNECT"}) is True


# ---------------------------------------------------------------------------
# _normalize_value
# ---------------------------------------------------------------------------


class TestNormalizeValue:
    def test_lower(self):
        assert _normalize_value("HELLO.EXE", "lower") == "hello.exe"
        assert _normalize_value("jsmith", "lower") == "jsmith"

    def test_lower_none_passthrough(self):
        assert _normalize_value(None, "lower") is None

    def test_path_basename_ci_windows(self):
        assert _normalize_value(r"C:\Windows\System32\cmd.exe", "path_basename_ci") == "cmd.exe"

    def test_path_basename_ci_unix(self):
        assert _normalize_value("/usr/bin/bash", "path_basename_ci") == "bash"

    def test_path_basename_ci_already_bare(self):
        assert _normalize_value("cmd.exe", "path_basename_ci") == "cmd.exe"

    def test_cn_from_dn_extracts_cn(self):
        dn = "CN=jsmith,OU=Users,DC=example,DC=com"
        assert _normalize_value(dn, "cn_from_dn") == "jsmith"

    def test_cn_from_dn_lowercases(self):
        dn = "CN=JSmith,OU=Users,DC=example,DC=com"
        assert _normalize_value(dn, "cn_from_dn") == "jsmith"

    def test_cn_from_dn_no_cn_falls_back(self):
        """Non-DN string without CN= should fall back to lowercased original."""
        assert _normalize_value("just-a-string", "cn_from_dn") == "just-a-string"

    def test_no_normalizer_returns_as_is(self):
        assert _normalize_value(42, None) == 42
        assert _normalize_value("abc", None) == "abc"


# ---------------------------------------------------------------------------
# _values_agree
# ---------------------------------------------------------------------------


class TestValuesAgree:
    def test_exact_match_no_normalize(self):
        assert _values_agree("powershell.exe", "powershell.exe", {}) is True

    def test_exact_mismatch(self):
        assert _values_agree("cmd.exe", "powershell.exe", {}) is False

    def test_normalize_lower(self):
        assert _values_agree("JSmith", "jsmith", {"normalize": "lower"}) is True

    def test_normalize_path_basename_ci(self):
        spec = {"normalize": "path_basename_ci"}
        assert _values_agree(r"C:\Windows\System32\cmd.exe", "cmd.exe", spec) is True
        assert _values_agree(r"C:\Windows\System32\cmd.exe", "powershell.exe", spec) is False

    def test_tolerance_within(self):
        """10 % tolerance: 1000 vs 1050 should pass (5 % diff)."""
        assert _values_agree(1000, 1050, {"tolerance": 0.10}) is True

    def test_tolerance_outside(self):
        """10 % tolerance: 1000 vs 1200 should fail (20 % diff)."""
        assert _values_agree(1000, 1200, {"tolerance": 0.10}) is False

    def test_tolerance_zero_b(self):
        """b_val == 0: only a == 0 agrees."""
        assert _values_agree(0, 0, {"tolerance": 0.10}) is True
        assert _values_agree(5, 0, {"tolerance": 0.10}) is False

    def test_b_is_list_found(self):
        """a_val must appear in the b list after normalisation."""
        spec = {"normalize": "lower", "b_is_list": True}
        assert _values_agree("example.com", ["example.com", "www.example.com"], spec) is True

    def test_b_is_list_not_found(self):
        spec = {"normalize": "lower", "b_is_list": True}
        assert _values_agree("other.com", ["example.com", "www.example.com"], spec) is False

    def test_b_is_list_but_b_not_list_returns_false(self):
        assert _values_agree("x", "x", {"b_is_list": True}) is False


# ---------------------------------------------------------------------------
# _score_pair — 4688 ↔ eCAR fixture
# ---------------------------------------------------------------------------


class TestScorePair:
    """Simple process-create pivot: Windows 4688 ↔ eCAR PROCESS/CREATE by PID+hostname."""

    _PIVOT = {
        "a_field": "NewProcessId",
        "b_field": "pid",
        "require_hostname_match": True,
    }
    _AGREE_ON = [
        {
            "a_field": "NewProcessName",
            "b_field": "image_path",
            "normalize": "path_basename_ci",
        }
    ]

    def _make_win(self, pid, process_name, hostname, ts=None):
        return _rec(
            "windows_event_security",
            {
                "EventID": 4688,
                "NewProcessId": pid,
                "NewProcessName": process_name,
                "Computer": hostname,
            },
            ts=ts or T0,
        )

    def _make_ecar(self, pid, image_path, hostname, ts=None):
        return _rec(
            "ecar",
            {
                "object": "PROCESS",
                "action": "CREATE",
                "pid": pid,
                "image_path": image_path,
                "hostname": hostname,
            },
            ts=ts or T0,
        )

    def test_matching_pid_hostname_agrees_on_process_name(self):
        win = self._make_win(1234, r"C:\Windows\System32\cmd.exe", "WS-01")
        ecar = self._make_ecar(1234, "cmd.exe", "WS-01")

        b_index = _build_pivot_index([ecar], self._PIVOT)
        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            [win],
            b_index,
            self._PIVOT,
            self._AGREE_ON,
        )
        assert matched == 1
        assert agreeing == 1
        assert failures == []

    def test_mismatched_process_name_produces_failure(self):
        win = self._make_win(1234, r"C:\Windows\System32\powershell.exe", "WS-01")
        ecar = self._make_ecar(1234, "cmd.exe", "WS-01")

        b_index = _build_pivot_index([ecar], self._PIVOT)
        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            [win],
            b_index,
            self._PIVOT,
            self._AGREE_ON,
        )
        assert matched == 1
        assert agreeing == 0
        assert len(failures) == 1

    def test_wrong_hostname_no_match(self):
        """Pivot uses require_hostname_match; different hostnames should not join."""
        win = self._make_win(1234, r"C:\Windows\System32\cmd.exe", "WS-01")
        ecar = self._make_ecar(1234, "cmd.exe", "WS-02")  # different host

        b_index = _build_pivot_index([ecar], self._PIVOT)
        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            [win],
            b_index,
            self._PIVOT,
            self._AGREE_ON,
        )
        assert matched == 0
        assert agreeing == 0

    def test_no_matching_pid_no_match(self):
        win = self._make_win(9999, r"C:\Windows\System32\cmd.exe", "WS-01")
        ecar = self._make_ecar(1234, "cmd.exe", "WS-01")

        b_index = _build_pivot_index([ecar], self._PIVOT)
        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            [win],
            b_index,
            self._PIVOT,
            self._AGREE_ON,
        )
        assert matched == 0

    def test_multiple_matching_all_agree(self):
        """Three process-create events that all agree → 3/3."""
        procs = [("cmd.exe", 100), ("notepad.exe", 200), ("powershell.exe", 300)]
        windows_recs = [
            self._make_win(pid, rf"C:\Windows\System32\{name}", "WS-01") for name, pid in procs
        ]
        ecar_recs = [self._make_ecar(pid, name, "WS-01") for name, pid in procs]
        b_index = _build_pivot_index(ecar_recs, self._PIVOT)
        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            windows_recs,
            b_index,
            self._PIVOT,
            self._AGREE_ON,
        )
        assert matched == 3
        assert agreeing == 3

    def test_pivot_index_caps_colliding_buckets(self):
        """High-collision B-side buckets retain only a bounded number of records."""
        ecar_recs = [self._make_ecar(1234, f"proc-{i}.exe", "WS-01") for i in range(5)]

        b_index = _build_pivot_index(ecar_recs, self._PIVOT, max_bucket_records=2)

        assert len(b_index[("ws-01", 1234)]) == 2

    def test_pivot_index_caps_colliding_buckets_b_fields(self):
        """b_fields composite-key path is also subject to the bucket cap."""
        pivot = {
            "b_fields": ["pid", "hostname"],
            "require_hostname_match": False,
        }
        ecar_recs = [self._make_ecar(1234, f"proc-{i}.exe", "WS-01") for i in range(5)]
        b_index = _build_pivot_index(ecar_recs, pivot, max_bucket_records=2)
        assert len(b_index[(1234, "WS-01")]) == 2

    def test_score_pair_stops_at_global_match_cap(self):
        """Colliding pivot keys cannot force exhaustive A×B comparisons."""
        windows_recs = [
            self._make_win(1234, r"C:\Windows\System32\cmd.exe", "WS-01") for _ in range(5)
        ]
        ecar_recs = [self._make_ecar(1234, "cmd.exe", "WS-01") for _ in range(5)]
        b_index = _build_pivot_index(ecar_recs, self._PIVOT)

        matched, agreeing, failures = _score_pair(
            "4688↔eCAR",
            windows_recs,
            b_index,
            self._PIVOT,
            self._AGREE_ON,
            max_matches=7,
        )

        assert matched == 7
        assert agreeing == 7
        assert failures == []


# ---------------------------------------------------------------------------
# CrossSourceScorer._score_field_agreement — empty records
# ---------------------------------------------------------------------------


class TestScoreFieldAgreementEmptyRecords:
    def test_empty_records_returns_100(self):
        """No format data → no pairs can be compared → graceful 100.0."""
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement({})
        assert result.score == 100.0
        assert result.key == "field_agreement"

    def test_records_with_no_matching_formats_returns_100(self):
        """Only formats with no pair definitions → no joins → 100.0."""
        records = {
            "bash_history": [_rec("bash_history", {"username": "jsmith", "command": "ls"}, ts=T0)]
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0


# ---------------------------------------------------------------------------
# proxy_access ↔ zeek_http — CONNECT rows excluded by condition
# ---------------------------------------------------------------------------


class TestProxyZeekHttpConnectExclusion:
    """CONNECT tunnel rows on both sides should be filtered out; only non-CONNECT
    rows are eligible for the pair join.  A lone CONNECT row therefore produces
    zero matched pairs (no violation, no agreement) and the sub-score stays 100.
    """

    def _make_proxy(self, method: str, ts=None) -> ParsedRecord:
        bucket = int((ts or T0).timestamp()) // 10
        return _rec(
            "proxy_access",
            {
                "client_ip": "10.0.10.50",
                "url": "https://evil.example.com/",
                "method": method,
                "status_code": 200,
                "timestamp_bucket_10s": bucket,
            },
            ts=ts or T0,
        )

    def _make_zeek_http(self, method: str, status_code: int, ts=None) -> ParsedRecord:
        bucket = int((ts or T0).timestamp()) // 10
        return _rec(
            "zeek_http",
            {
                "id.orig_h": "10.0.10.50",
                "uri": "https://evil.example.com/",
                "method": method,
                "status_code": status_code,
                "ts_bucket_10s": bucket,
            },
            ts=ts or T0,
        )

    def test_connect_rows_filtered_no_pairs_matched(self):
        """A CONNECT proxy row + a CONNECT zeek_http row → zero matches → score=100."""
        records = {
            "proxy_access": [self._make_proxy("CONNECT")],
            "zeek_http": [self._make_zeek_http("CONNECT", 200)],
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0

    def test_non_connect_rows_are_still_matched(self):
        """GET rows with matching status_code agree → score=100 (agreement found)."""
        records = {
            "proxy_access": [self._make_proxy("GET")],
            "zeek_http": [self._make_zeek_http("GET", 200)],
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0


# ---------------------------------------------------------------------------
# zeek_ssl ↔ zeek_x509 — intermediate CA certs excluded by condition_b
# ---------------------------------------------------------------------------


class TestZeekSslX509IntermediateCAExclusion:
    """Intermediate CA certs (host_cert=False) must not be checked for SAN
    agreement.  A CA cert with empty san.dns should not produce a failure."""

    def _make_ssl(self, server_name: str, cert_chain_fuids: list, ts=None) -> ParsedRecord:
        return _rec(
            "zeek_ssl",
            {
                "server_name": server_name,
                "cert_chain_fuids": cert_chain_fuids,
            },
            ts=ts or T0,
        )

    def _make_x509(self, fuid: str, san_dns: list, host_cert: bool, ts=None) -> ParsedRecord:
        return _rec(
            "zeek_x509",
            {
                "id": fuid,
                "san.dns": san_dns,
                "host_cert": host_cert,
            },
            ts=ts or T0,
        )

    def test_intermediate_ca_with_empty_san_does_not_fail(self):
        """Chain has leaf (host_cert=True) + intermediate (host_cert=False).
        Only the leaf is checked for server_name in san.dns."""
        leaf = self._make_x509("fuid-leaf", ["evil.example.com"], host_cert=True)
        intermediate = self._make_x509("fuid-ca", [], host_cert=False)
        ssl = self._make_ssl("evil.example.com", ["fuid-leaf", "fuid-ca"])

        records = {
            "zeek_ssl": [ssl],
            "zeek_x509": [leaf, intermediate],
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0

    def test_leaf_cert_mismatch_still_fails(self):
        """A leaf cert with the wrong SAN should still produce a failure."""
        leaf = self._make_x509("fuid-leaf", ["other.example.com"], host_cert=True)
        ssl = self._make_ssl("evil.example.com", ["fuid-leaf"])

        records = {
            "zeek_ssl": [ssl],
            "zeek_x509": [leaf],
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score < 100.0
