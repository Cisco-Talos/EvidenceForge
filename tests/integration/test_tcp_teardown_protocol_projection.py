# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Real Zeek projections preserve protocol progress before TCP reset/half-close."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import generation_seed_scope


@pytest.mark.parametrize("state", ["RSTO", "RSTR", "S2", "S3"])
@pytest.mark.parametrize("service", ["ssl", "http"])
def test_application_row_remains_inside_preserved_tcp_teardown(
    tmp_path: Path, state: str, service: str
) -> None:
    emitters = {
        key: cls(load_format(key), tmp_path / name, threaded=False)
        for key, cls, name in [
            ("zeek_conn", ZeekEmitter, "conn.json"),
            ("zeek_ssl", ZeekSslEmitter, "ssl.json"),
            ("zeek_http", ZeekHttpEmitter, "http.json"),
            ("zeek_files", ZeekFilesEmitter, "files.json"),
            ("zeek_x509", ZeekX509Emitter, "x509.json"),
        ]
    }
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    with generation_seed_scope(42):
        manager = StateManager()
        manager.set_current_time(at)
        generator = ActivityGenerator(manager, emitters)
        try:
            uid = generator.generate_connection(
                src_ip="10.0.0.10",
                dst_ip="10.0.0.20",
                src_port=51000,
                time=at,
                dst_port=443 if service == "ssl" else 80,
                proto="tcp",
                service=service,
                conn_state=state,
                duration=0.0001,
                orig_bytes=2436,
                resp_bytes=20416,
                hostname="app.example.test",
            )
        finally:
            for emitter in emitters.values():
                emitter.close()
    connections = [json.loads(line) for line in (tmp_path / "conn.json").read_text().splitlines()]
    conn = next(row for row in connections if row["uid"] == uid)
    protocol_file = "ssl.json" if service == "ssl" else "http.json"
    rows = [json.loads(line) for line in (tmp_path / protocol_file).read_text().splitlines()]
    companions = [row for row in rows if row["uid"] == uid]

    assert conn["conn_state"] == state
    assert len(companions) == 1
    assert conn["ts"] <= companions[0]["ts"] <= conn["ts"] + conn["duration"]
    assert "D" in conn["history"] and "d" in conn["history"]
    for field in ["id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]:
        assert companions[0][field] == conn[field]
    if service == "ssl":
        assert companions[0]["established"]
        if companions[0]["version"] == "TLSv13":
            assert not companions[0].get("cert_chain_fuids")
