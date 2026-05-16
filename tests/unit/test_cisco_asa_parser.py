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

"""Tests for the Cisco ASA firewall log parser."""

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from evidenceforge.evaluation.parsers.cisco_asa import CiscoAsaParser


class TestCanParse:
    def test_matches_cisco_asa_log(self):
        parser = CiscoAsaParser()
        assert parser.can_parse(Path("fw01/cisco_asa.log")) is True
        assert parser.can_parse(Path("fw01/2026/cisco_asa.log")) is True

    def test_rejects_other_files(self):
        parser = CiscoAsaParser()
        assert parser.can_parse(Path("syslog.log")) is False
        assert parser.can_parse(Path("snort_alert.alert")) is False


class TestParseBuiltRecords:
    def test_parse_302013_tcp_built(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection "
            "100042 for inside:10.0.10.50/54321 (10.0.10.50/54321) to "
            "outside:203.0.113.50/443 (203.0.113.50/443)\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.source_format == "cisco_asa"
        assert rec.timestamp is not None
        assert rec.fields["hostname"] == "fw01"
        assert rec.fields["severity"] == 6
        assert rec.fields["msg_id"] == 302013
        assert rec.fields["src_ip"] == "10.0.10.50"
        assert rec.fields["src_port"] == 54321
        assert rec.fields["dst_ip"] == "203.0.113.50"
        assert rec.fields["dst_port"] == 443
        assert rec.fields["connection_id"] == 100042
        assert not rec.parse_errors

    def test_parse_302015_udp_built(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302015: Built outbound UDP connection "
            "100043 for inside:10.0.10.50/54322 (10.0.10.50/54322) to "
            "outside:8.8.8.8/53 (8.8.8.8/53)\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        assert records[0].fields["msg_id"] == 302015
        assert records[0].fields["dst_port"] == 53

    def test_parse_302020_icmp_built(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302020: Built outbound ICMP connection "
            "for faddr 203.0.113.50/8 gaddr 10.0.10.50/0 laddr 10.0.10.50/0\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        assert records[0].fields["msg_id"] == 302020
        assert records[0].fields["dst_ip"] == "203.0.113.50"
        assert records[0].fields["icmp_type"] == 8

    def test_parse_302020_icmp_built_accepts_legacy_interface_prefix(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302020: Built outbound ICMP connection "
            "for faddr outside:203.0.113.50/8 gaddr inside:10.0.10.50/0 "
            "laddr inside:10.0.10.50/0\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        assert records[0].fields["msg_id"] == 302020
        assert records[0].fields["dst_interface"] == "outside"
        assert records[0].fields["dst_ip"] == "203.0.113.50"
        assert records[0].fields["icmp_type"] == 8


class TestParseTeardownRecords:
    def test_parse_302014_tcp_teardown(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:24:28 fw01 %ASA-6-302014: Teardown TCP connection "
            "100042 for inside:10.0.10.50/54321 to outside:203.0.113.50/443 "
            "duration 0:01:23 bytes 5120 TCP FINs\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 302014
        assert rec.fields["connection_id"] == 100042
        assert rec.fields["duration"] == "0:01:23"
        assert rec.fields["bytes"] == 5120
        assert rec.fields["src_ip"] == "10.0.10.50"
        assert rec.fields["dst_ip"] == "203.0.113.50"


class TestParseDenyRecords:
    def test_parse_106023_tcp_deny(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<164>Jun 15 14:23:10 fw01 %ASA-4-106023: Deny tcp src "
            'outside:198.51.100.1/44231 dst inside:10.0.10.50/445 by access-group "outside_access_in" [0x0, 0x0]\n'
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 106023
        assert rec.fields["severity"] == 4
        assert rec.fields["protocol"] == "tcp"
        assert rec.fields["src_ip"] == "198.51.100.1"
        assert rec.fields["src_port"] == 44231
        assert rec.fields["dst_ip"] == "10.0.10.50"
        assert rec.fields["dst_port"] == 445
        assert rec.fields["access_group"] == "outside_access_in"

    def test_parse_106023_icmp_deny(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<164>Jun 15 14:23:10 fw01 %ASA-4-106023: Deny icmp src "
            "outside:198.51.100.1 dst inside:10.0.10.50 "
            '(type 8, code 0) by access-group "outside_access_in" [0x0, 0x0]\n'
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["protocol"] == "icmp"
        assert rec.fields["icmp_type"] == 8
        assert rec.fields["icmp_code"] == 0
        assert "src_port" not in rec.fields


class TestParseThreatDetection:
    def test_parse_733100_threat_detection(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<164>Jun 15 14:35:00 fw01 %ASA-4-733100: [Scanning] drop rate-1 exceeded. "
            "Current burst rate is 87 per second, max configured rate is 10; "
            "Current average rate is 45 per second, max configured rate is 5; "
            "Cumulative total count is 2340\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 733100
        assert rec.fields["severity"] == 4
        assert rec.fields["threat_class"] == "Scanning"
        assert rec.fields["rate_id"] == 1
        assert rec.fields["burst_rate"] == 87
        assert rec.fields["burst_max"] == 10
        assert rec.fields["avg_rate"] == 45
        assert rec.fields["avg_max"] == 5
        assert rec.fields["cumulative_count"] == 2340
        assert not rec.parse_errors


class TestParseNatRecords:
    def test_parse_305011_dynamic_tcp(self, tmp_path):
        """305011 Built dynamic TCP translation should parse NAT fields."""
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-305011: Built dynamic TCP translation "
            "from inside:10.0.10.50/54321 to outside:198.51.100.1/12345\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 305011
        assert rec.fields["severity"] == 6
        assert rec.fields["nat_type"] == "dynamic"
        assert rec.fields["protocol"] == "TCP"
        assert rec.fields["src_interface"] == "inside"
        assert rec.fields["real_ip"] == "10.0.10.50"
        assert rec.fields["real_port"] == 54321
        assert rec.fields["dst_interface"] == "outside"
        assert rec.fields["mapped_ip"] == "198.51.100.1"
        assert rec.fields["mapped_port"] == 12345
        assert not rec.parse_errors

    def test_parse_305011_static_udp(self, tmp_path):
        """305011 Built static UDP translation should parse correctly."""
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-305011: Built static UDP translation "
            "from dmz:172.16.0.5/443 to outside:203.0.113.5/443\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 305011
        assert rec.fields["nat_type"] == "static"
        assert rec.fields["protocol"] == "UDP"
        assert rec.fields["src_interface"] == "dmz"
        assert rec.fields["real_ip"] == "172.16.0.5"
        assert rec.fields["real_port"] == 443
        assert rec.fields["dst_interface"] == "outside"
        assert rec.fields["mapped_ip"] == "203.0.113.5"
        assert rec.fields["mapped_port"] == 443
        assert not rec.parse_errors

    def test_parse_305012_teardown_with_duration(self, tmp_path):
        """305012 Teardown translation should parse with duration field."""
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:24:28 fw01 %ASA-6-305012: Teardown dynamic TCP translation "
            "from inside:10.0.10.50/54321 to outside:198.51.100.1/12345 duration 0:01:23\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["msg_id"] == 305012
        assert rec.fields["duration"] == "0:01:23"
        assert rec.fields["real_ip"] == "10.0.10.50"
        assert rec.fields["mapped_ip"] == "198.51.100.1"
        assert not rec.parse_errors

    def test_parse_built_with_different_mapped_ips(self, tmp_path):
        """302013 Built with parenthesized mapped IPs differing from real IPs."""
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection "
            "100042 for inside:10.0.10.50/54321 (198.51.100.1/12345) to "
            "outside:203.0.113.50/443 (203.0.113.50/443)\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        assert rec.fields["src_ip"] == "10.0.10.50"
        assert rec.fields["mapped_src_ip"] == "198.51.100.1"
        assert rec.fields["mapped_src_port"] == 12345
        assert rec.fields["dst_ip"] == "203.0.113.50"
        assert rec.fields["mapped_dst_ip"] == "203.0.113.50"
        assert not rec.parse_errors

    def test_parse_built_identity_nat(self, tmp_path):
        """302013 Built where parens match real (identity NAT) should not crash."""
        log = tmp_path / "cisco_asa.log"
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection "
            "100042 for inside:10.0.10.50/54321 (10.0.10.50/54321) to "
            "outside:203.0.113.50/443 (203.0.113.50/443)\n"
        )
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        rec = records[0]
        # Identity NAT: mapped should equal real (or field may not be set)
        mapped_src = rec.fields.get("mapped_src_ip", rec.fields.get("src_ip"))
        assert mapped_src == "10.0.10.50"
        assert not rec.parse_errors


class TestMalformedLines:
    def test_garbage_line(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text("this is not an ASA log line\n")
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 1
        assert records[0].parse_errors
        assert "does not match" in records[0].parse_errors[0]

    def test_empty_lines_skipped(self, tmp_path):
        log = tmp_path / "cisco_asa.log"
        log.write_text("\n\n\n")
        parser = CiscoAsaParser()
        records = list(parser.parse_file(log))
        assert len(records) == 0


class TestTimestampYear:
    def test_parent_year_overrides_current_year(self, tmp_path):
        log = tmp_path / "fw01" / "2024" / "cisco_asa.log"
        log.parent.mkdir(parents=True)
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302015: Built outbound UDP connection "
            "100043 for inside:10.0.10.50/54322 (10.0.10.50/54322) to "
            "outside:8.8.8.8/53 (8.8.8.8/53)\n"
        )

        records = list(CiscoAsaParser().parse_file(log))

        assert records[0].timestamp is not None
        assert records[0].timestamp.year == 2024

    def test_flat_layout_falls_back_to_scenario_year(self, tmp_path):
        log = tmp_path / "fw01" / "cisco_asa.log"
        log.parent.mkdir()
        log.write_text(
            "<166>Jun 15 14:23:05 fw01 %ASA-6-302015: Built outbound UDP connection "
            "100043 for inside:10.0.10.50/54322 (10.0.10.50/54322) to "
            "outside:8.8.8.8/53 (8.8.8.8/53)\n"
        )
        parser = CiscoAsaParser()
        parser.scenario = SimpleNamespace(
            time_window=SimpleNamespace(start=datetime(2025, 12, 31, 23, 59, 0))
        )

        records = list(parser.parse_file(log))

        assert records[0].timestamp is not None
        assert records[0].timestamp.year == 2025
