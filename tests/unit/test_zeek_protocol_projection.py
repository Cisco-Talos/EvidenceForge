# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical protocol facts retain distinct source-native projections."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import DnsContext, SmbContext
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.network_dns import _dns_rr_rdata_size
from evidenceforge.generation.dns_rdata import dns_txt_character_strings
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter, zeek_dns_answer
from evidenceforge.generation.emitters.zeek_smb import ZeekSmbMappingEmitter
from tests.unit.test_network_observation import _network_event


@pytest.mark.parametrize(
    ("qtype", "answer", "expected"),
    [
        ("SRV", "0 100 389 dc.example.test", "dc.example.test"),
        ("MX", "10 mail.example.test", "mail.example.test"),
        ("SOA", "ns.example.test hostmaster.example.test 42 3600 600 86400 300", "ns.example.test"),
        ("TXT", "hello world", "TXT 11 hello world"),
        ("TXT", "", "TXT 0 "),
        ("SPF", "v=spf1 -all", "SPF 11 v=spf1 -all"),
        ("A", "192.0.2.8", "192.0.2.8"),
        ("AAAA", "2001:db8::1", "2001:db8::1"),
        ("CNAME", "alias.example.test", "alias.example.test"),
        ("SRV", "malformed", "malformed"),
    ],
)
def test_dns_native_projection(qtype: str, answer: str, expected: str) -> None:
    assert zeek_dns_answer(qtype, answer) == expected


@pytest.mark.parametrize("answer", ["", "a" * 255, "b" * 256, "c" * 600, "a" * 254 + "é" * 256])
def test_txt_projection_and_wire_size_share_character_strings(answer: str) -> None:
    chunks = dns_txt_character_strings(answer)
    assert "".join(chunks) == answer
    assert all(len(part.encode("utf-8")) <= 255 for part in chunks)
    assert _dns_rr_rdata_size("TXT", answer) == sum(1 + len(p.encode("utf-8")) for p in chunks)
    assert zeek_dns_answer("TXT", answer) == " ".join(
        f"TXT {len(p.encode('utf-8'))} {p}" for p in chunks
    )


def test_typed_dns_preserves_canonical_answers_and_ttl_alignment(tmp_path: Path) -> None:
    event = _network_event(protocol="udp")
    event.dns = DnsContext(
        query="_ldap._tcp.example.test",
        query_type="SRV",
        qtype=33,
        answers=["0 100 389 dc1.example.test", "10 50 389 dc2.example.test"],
        TTLs=[600.0, 300.0],
    )
    original = list(event.dns.answers)
    emitter = ZeekDnsEmitter(load_format("zeek_dns"), tmp_path / "dns.json", threaded=False)
    capture = Mock()
    emitter.emit_event = capture
    emitter.emit(event)
    data = capture.call_args.args[0]
    assert data["answers"] == ["dc1.example.test", "dc2.example.test"]
    assert data["TTLs"] == [600.0, 300.0]
    assert event.dns.answers == original
    emitter.close()


def test_smb2_mapping_does_not_fabricate_smb1_wire_fields(tmp_path: Path) -> None:
    event = _network_event(protocol="tcp")
    event.event_type = "smb_tree_connect"
    event.smb = SmbContext(
        phase="tree_connect",
        operation="copy",
        purpose="collection",
        session_id="s1",
        tree_id="t1",
        share_ref="files.reports",
        share_name="reports",
        result="success",
        filesystem="ext4",
        backing_filesystem="ext4",
        advertised_filesystem="NTFS",
        server_platform="linux",
        provider="samba",
    )
    emitter = ZeekSmbMappingEmitter(
        load_format("zeek_smb_mapping"), tmp_path / "mapping.json", threaded=False
    )
    capture = Mock()
    emitter.emit_event = capture
    emitter.emit(event)
    data = capture.call_args.args[0]
    assert data["share_type"] == "DISK"
    assert data["path"] == r"\\files\reports"
    assert "service" not in data and "native_file_system" not in data
    assert event.smb.advertised_filesystem == "NTFS"
    # The optional schema also accepts already-native raw SMB1 observations.
    native = {**data, "ts": 1.0, "service": "A:", "native_file_system": "NTFS"}
    parsed = json.loads(emitter._render_event(native))
    assert parsed["service"] == "A:"
    assert parsed["native_file_system"] == "NTFS"
    parsed = json.loads(emitter._render_event({**data, "ts": 1.0}))
    assert "service" not in parsed and "native_file_system" not in parsed
    emitter.close()
