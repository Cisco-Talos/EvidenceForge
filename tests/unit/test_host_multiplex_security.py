# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Security tests for host-based emitter routing."""

from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.web import WebEmitter


class TestHostMultiplexRoutingSecurity:
    """Validate host routing does not allow path traversal."""

    def test_web_emitter_rejects_path_traversal_host_key(self, tmp_path: Path) -> None:
        fmt = load_format("web_access")
        emitter = WebEmitter(fmt, tmp_path)

        escape_dir = "escape_should_not_be_created"
        emitter.emit_event(
            {
                "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
                "client_ip": "10.0.0.5",
                "username": "-",
                "method": "GET",
                "path": "/",
                "protocol": "HTTP/1.1",
                "status_code": 200,
                "bytes_sent": 128,
                "referer": "-",
                "user_agent": "Mozilla/5.0",
                "_host_fqdn": f"../../{escape_dir}",
            }
        )
        emitter.close()

        assert (tmp_path / "web_access.log").exists()
        assert not (tmp_path.parent / escape_dir / "web_access.log").exists()

    def test_web_emitter_keeps_valid_host_routing(self, tmp_path: Path) -> None:
        fmt = load_format("web_access")
        emitter = WebEmitter(fmt, tmp_path)

        emitter.emit_event(
            {
                "timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
                "client_ip": "10.0.0.5",
                "username": "-",
                "method": "GET",
                "path": "/app",
                "protocol": "HTTP/1.1",
                "status_code": 200,
                "bytes_sent": 128,
                "referer": "-",
                "user_agent": "Mozilla/5.0",
                "_host_fqdn": "web-01.corp.local",
            }
        )
        emitter.close()

        assert (tmp_path / "web-01.corp.local" / "web_access.log").exists()
