# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for new Sysmon events: 3, 7, 11, 12/13, 22."""

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    ImageLoadContext,
    NetworkContext,
    ProcessAccessContext,
    ProcessContext,
    RegistryContext,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters import SysmonEventEmitter


def _win_host():
    return HostContext(
        hostname="WKS-01",
        ip="10.0.1.10",
        os="Windows 10",
        os_category="windows",
        system_type="workstation",
        domain="corp.local",
        fqdn="WKS-01.corp.local",
        netbios_domain="CORP",
    )


def _linux_host():
    return HostContext(
        hostname="SRV-01",
        ip="10.0.2.10",
        os="Ubuntu 22.04",
        os_category="linux",
        system_type="server",
        domain="corp.local",
        fqdn="SRV-01.corp.local",
    )


@pytest.fixture
def format_def():
    return load_format("windows_event_sysmon")


@pytest.fixture
def emitter(format_def, tmp_path):
    return SysmonEventEmitter(format_def, tmp_path / "sysmon.xml", buffer_size=100)


class TestCanHandle:
    """Test can_handle for new event types."""

    def test_connection_on_windows(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.2.20", src_port=49152, dst_port=443, protocol="tcp"
            ),
        )
        assert emitter.can_handle(event) is True

    def test_connection_on_linux_rejected(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_linux_host(),
            network=NetworkContext(
                src_ip="10.0.2.10", dst_ip="10.0.1.10", src_port=49152, dst_port=22, protocol="tcp"
            ),
        )
        assert emitter.can_handle(event) is False

    def test_file_create_on_windows(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            file=FileContext(path=r"C:\Windows\Temp\evil.exe", action="create"),
        )
        assert emitter.can_handle(event) is True

    def test_image_load_on_windows(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\app.dll",
                signed=False,
                signature="-",
                signature_status="Unavailable",
            ),
        )
        assert emitter.can_handle(event) is True

    def test_registry_modify_on_windows(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil",
                value="evil.exe",
                action="modify",
            ),
        )
        assert emitter.can_handle(event) is True


class TestEvent3Filter:
    """Test Event 3 (NetworkConnect) filtering."""

    def test_lolbin_passes_filter(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\System32\powershell.exe",
                command_line="powershell",
                username="user",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.2.20", src_port=49152, dst_port=443, protocol="tcp"
            ),
        )
        assert emitter._passes_event3_filter(event) is True

    def test_browser_user_app_sampling_can_be_disabled(self, emitter):
        emitter._filters = {
            "network_connect": {
                "enabled": True,
                "mode": "include",
                "include_images": [],
                "include_baseline_images": [],
                "include_user_app_images": ["chrome.exe"],
                "user_app_sample_rate": 0.0,
                "include_dest_ports": [],
                "exclude_dest_ips": [],
            }
        }
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=5678,
                parent_pid=1,
                image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                command_line="chrome",
                username="user",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                src_port=49200,
                dst_port=443,
                protocol="tcp",
            ),
        )
        assert emitter._passes_event3_filter(event) is False

    def test_browser_user_app_sampling_can_pass(self, emitter):
        emitter._filters = {
            "network_connect": {
                "enabled": True,
                "mode": "include",
                "include_images": [],
                "include_baseline_images": [],
                "include_user_app_images": ["chrome.exe"],
                "user_app_sample_rate": 1.0,
                "include_dest_ports": [],
                "exclude_dest_ips": [],
            }
        }
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=5678,
                parent_pid=1,
                image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                command_line="chrome",
                username="user",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                src_port=49200,
                dst_port=443,
                protocol="tcp",
            ),
        )
        assert emitter._passes_event3_filter(event) is True

    def test_suspicious_port_passes_filter(self, emitter):
        """Any process connecting to a suspicious port should pass."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=5678,
                parent_pid=1,
                image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                command_line="chrome",
                username="user",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="192.168.1.100",
                src_port=49200,
                dst_port=4444,
                protocol="tcp",
            ),
        )
        assert emitter._passes_event3_filter(event) is True

    def test_loopback_excluded(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\System32\powershell.exe",
                command_line="powershell",
                username="user",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="127.0.0.1", src_port=49152, dst_port=80, protocol="tcp"
            ),
        )
        assert emitter._passes_event3_filter(event) is False


class TestEvent7Filter:
    """Test Event 7 (ImageLoaded) filtering."""

    def test_system32_dll_filtered(self, emitter):
        """Microsoft-signed DLLs from System32 should be excluded."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1000,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Windows\System32\ntdll.dll",
                signed=True,
                signature="Microsoft Windows",
                signature_status="Valid",
            ),
        )
        assert emitter._passes_event7_filter(event) is False

    def test_unsigned_thirdparty_dll_passes(self, emitter):
        """Unsigned DLLs from non-system paths should pass."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1000,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\SomeApp\plugin.dll",
                signed=False,
                signature="-",
                signature_status="Unavailable",
            ),
        )
        assert emitter._passes_event7_filter(event) is True

    def test_disabled_event7(self, emitter):
        """Event 7 should be skipped when disabled in config."""
        with patch.object(
            emitter,
            "_get_filters",
            return_value={
                "image_loaded": {"enabled": False},
            },
        ):
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
                event_type="image_load",
                src_host=_win_host(),
                image_load=ImageLoadContext(
                    image_loaded=r"C:\evil.dll",
                    signed=False,
                    signature="-",
                    signature_status="Unavailable",
                ),
            )
            assert emitter._passes_event7_filter(event) is False


class TestEvent11Filter:
    """Test Event 11 (FileCreate) filtering."""

    def test_exe_in_temp_passes(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            file=FileContext(path=r"C:\Windows\Temp\payload.exe", action="create"),
        )
        assert emitter._passes_event11_filter(event) is True

    def test_txt_file_filtered(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            file=FileContext(path=r"C:\Users\john\Documents\notes.txt", action="create"),
        )
        assert emitter._passes_event11_filter(event) is False

    def test_startup_folder_passes(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            file=FileContext(
                path=r"C:\Users\john\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\persist.lnk",
                action="create",
            ),
        )
        assert emitter._passes_event11_filter(event) is True


class TestEventRegistryFilter:
    """Test Events 12/13 (Registry) filtering."""

    def test_run_key_modify_passes(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
                value="evil.exe",
                action="modify",
            ),
        )
        assert emitter._passes_event12_13_filter(event) is True

    def test_create_key_filtered_by_default(self, emitter):
        """CreateKey actions are filtered by default (log_create_key: false)."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                action="create",
            ),
        )
        assert emitter._passes_event12_13_filter(event) is False

    def test_non_matching_key_filtered(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            registry=RegistryContext(
                key=r"HKLM\Software\SomeApp\Settings\Color",
                value="blue",
                action="modify",
            ),
        )
        assert emitter._passes_event12_13_filter(event) is False


class TestEvent22Filter:
    """Test Event 22 (DNSQuery) filtering."""

    def test_dns_query_passes_by_default(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            dns=DnsContext(query="evil.com", rcode="NOERROR", answers=["1.2.3.4"]),
        )
        assert emitter._passes_event22_filter(event) is True

    def test_disabled_event22(self, emitter):
        with patch.object(
            emitter,
            "_get_filters",
            return_value={
                "dns_query": {"enabled": False},
            },
        ):
            event = SecurityEvent(
                timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
                event_type="connection",
                src_host=_win_host(),
                dns=DnsContext(query="evil.com", rcode="NOERROR"),
            )
            assert emitter._passes_event22_filter(event) is False


class TestRenderEvent3:
    """Test Event 3 (NetworkConnect) rendering."""

    def test_renders_valid_event3(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd",
                username="admin",
            ),
            auth=AuthContext(username="admin"),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="10.0.2.20",
                src_port=49152,
                dst_port=4444,
                protocol="tcp",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>3</EventID>" in content
        assert "cmd.exe" in content
        assert "10.0.2.20" in content
        assert "4444" in content
        assert "tcp" in content

    def test_event3_uses_source_native_timestamp_offset(self, emitter):
        event_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=event_time,
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd",
                username="admin",
            ),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="10.0.2.20",
                src_port=49152,
                dst_port=4444,
                protocol="tcp",
                initiating_pid=4567,
            ),
        )

        emitter.emit(event)

        expected_delta = sample_timing_delta(
            "source.sysmon_network_connection",
            seed_parts=("WKS-01", 4567, "10.0.1.10", 49152, "10.0.2.20", 4444, event_time),
        )
        expected_time = event_time + expected_delta
        assert emitter._event_dicts[0]["TimeCreated"] == expected_time
        assert (
            emitter._event_dicts[0]["UtcTime"]
            == expected_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        )


class TestRenderEvent7:
    """Test Event 7 (ImageLoaded) rendering."""

    def test_renders_valid_event7(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\App\plugin.dll",
                signed=False,
                signature="-",
                signature_status="Unavailable",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>7</EventID>" in content
        assert "plugin.dll" in content
        assert "Unavailable" in content
        assert '<Data Name="Signed">false</Data>' in content

    def test_unsigned_event7_overrides_valid_signature_status(self, emitter):
        """Unsigned image loads should not render a contradictory Valid signature status."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\App\unsigned.dll",
                signed=False,
                signature="-",
                signature_status="Valid",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="Signed">false</Data>' in content
        assert '<Data Name="Signature">-</Data>' in content
        assert '<Data Name="SignatureStatus">Unavailable</Data>' in content
        assert '<Data Name="SignatureStatus">Valid</Data>' not in content

    def test_signed_event7_populates_vendor_metadata_when_catalog_missing(self, emitter):
        """Signed DLL loads should not render all PE metadata fields as '-'."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\Cisco\Secure Client\cscan.dll",
                signed=True,
                signature="Cisco Systems, Inc.",
                signature_status="Valid",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="Company">Cisco Systems, Inc.</Data>' in content
        assert '<Data Name="FileVersion">-</Data>' not in content

    def test_program_files_module_metadata_is_not_windows_os_fallback(self, emitter):
        """Application DLLs should inherit package metadata instead of Windows OS fields."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Program Files\Mozilla Firefox\firefox.exe",
                command_line="firefox.exe",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\Mozilla Firefox\mozglue.dll",
                signed=True,
                signature="Mozilla Corporation",
                signature_status="Valid",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="FileVersion">121.0</Data>' in content
        assert '<Data Name="Product">Firefox</Data>' in content
        assert '<Data Name="Company">Mozilla Corporation</Data>' in content
        assert '<Data Name="Product">Microsoft Windows Operating System</Data>' not in content

    def test_third_party_shell_extension_metadata_is_consistent(self, emitter):
        """7-Zip shell extension loads should render stable third-party metadata."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="explorer.exe",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\7-Zip\7-zip.dll",
                signed=False,
                signature="-",
                signature_status="Unavailable",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="FileVersion">23.01.0.0</Data>' in content
        assert '<Data Name="Product">7-Zip</Data>' in content
        assert '<Data Name="Company">Igor Pavlov</Data>' in content
        assert '<Data Name="Signed">false</Data>' in content
        assert '<Data Name="Product">Microsoft Windows Operating System</Data>' not in content


class TestRenderEvent11:
    """Test Event 11 (FileCreate) rendering."""

    def test_renders_valid_event11(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\powershell.exe",
                command_line="powershell",
                username="admin",
            ),
            file=FileContext(path=r"C:\Windows\Temp\payload.exe", action="create"),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>11</EventID>" in content
        assert "payload.exe" in content
        assert "powershell.exe" in content


class TestRenderEventRegistry:
    """Test Events 12/13 (Registry) rendering."""

    def test_modify_renders_event13(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\reg.exe",
                command_line="reg add",
                username="admin",
            ),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
                value="evil.exe",
                action="modify",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>13</EventID>" in content
        assert "SetValue" in content
        assert "evil.exe" in content
        assert "CurrentVersion\\Run" in content

    def test_delete_renders_event12(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\regedit.exe",
                command_line="regedit",
                username="admin",
            ),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\OldEntry",
                action="delete",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>12</EventID>" in content
        assert "DeleteKey" in content

    def test_value_delete_context_renders_event13(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            auth=AuthContext(username="admin", user_sid="S-1-5-21-111-222-333-1001"),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\regedit.exe",
                command_line="regedit",
                username="admin",
            ),
            registry=RegistryContext(
                key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt",
                value="DWORD (0x00000001)",
                action="delete",
            ),
        )
        emitter.emit(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>13</EventID>" in content
        assert "SetValue" in content
        assert "HideFileExt" in content
        assert "DWORD (0x00000001)" in content
        assert "HKCU\\" not in content
        assert r"HKU\S-1-5-21-111-222-333-1001\Software" in content


class TestProcessCreateMetadata:
    """Test host-specific Sysmon process metadata rendering."""

    def test_windows_os_binary_versions_are_consistent_per_host(self, emitter):
        host = _win_host()
        first = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=host,
            auth=AuthContext(username="admin", logon_id="0x123"),
            process=ProcessContext(
                pid=4100,
                parent_pid=500,
                image=r"C:\Windows\System32\gpresult.exe",
                command_line="gpresult /r",
                username="admin",
                logon_id="0x123",
                start_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            ),
        )
        second = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 1, tzinfo=UTC),
            event_type="process_create",
            src_host=host,
            auth=AuthContext(username="admin", logon_id="0x123"),
            process=ProcessContext(
                pid=4101,
                parent_pid=500,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                username="admin",
                logon_id="0x123",
                start_time=datetime(2024, 1, 15, 10, 30, 1, tzinfo=UTC),
            ),
        )

        emitter.emit(first)
        emitter.emit(second)
        emitter.close()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert content.count('<Data Name="FileVersion">10.0.19041.1</Data>') == 2
        assert "10.0.20348.1" not in content

    def test_os_binary_hashes_follow_host_file_version(self):
        """The same OS binary path on different Windows builds should not share hashes."""
        workstation = _win_host()
        server = HostContext(
            hostname="SRV-01",
            ip="10.0.1.20",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            domain="corp.local",
            fqdn="SRV-01.corp.local",
            netbios_domain="CORP",
        )
        image = r"C:\Windows\System32\cmd.exe"

        workstation_hashes = SysmonEventEmitter._generate_hashes(image, workstation)
        server_hashes = SysmonEventEmitter._generate_hashes(image, server)

        assert workstation_hashes != server_hashes
        assert SysmonEventEmitter._generate_hashes(image, workstation) == workstation_hashes

    def test_hashes_follow_rendered_binary_identity(self):
        """Identical rendered binary metadata should keep hashes stable across hosts."""
        workstation = _win_host()
        server = HostContext(
            hostname="SRV-01",
            ip="10.0.1.20",
            os="Windows Server 2022",
            os_category="windows",
            system_type="server",
            domain="corp.local",
            fqdn="SRV-01.corp.local",
            netbios_domain="CORP",
        )
        image = r"C:\Windows\System32\MpCmdRun.exe"

        assert SysmonEventEmitter._get_pe_metadata(image, workstation)[0] == "4.18.2211.5"
        assert SysmonEventEmitter._get_pe_metadata(image, server)[0] == "4.18.2211.5"
        assert SysmonEventEmitter._generate_hashes(
            image, workstation
        ) == SysmonEventEmitter._generate_hashes(image, server)

    def test_image_load_hashes_include_rendered_signature_identity(self):
        """Same DLL path with different rendered signer metadata must not share hashes."""
        image = r"C:\Program Files\Mozilla Firefox\lgpllibs.dll"

        mozilla_hashes = SysmonEventEmitter._generate_hashes(
            image,
            _win_host(),
            rendered_identity=(
                "1.0.0.0",
                "lgpllibs.dll module",
                "Mozilla Corporation",
                "Mozilla Corporation",
                "lgpllibs.dll",
                "Mozilla Corporation",
                "Valid",
            ),
        )
        microsoft_hashes = SysmonEventEmitter._generate_hashes(
            image,
            _win_host(),
            rendered_identity=(
                "10.0.19041.1",
                "lgpllibs.dll system library",
                "Microsoft Windows Operating System",
                "Microsoft Corporation",
                "lgpllibs.dll",
                "Microsoft Windows",
                "Valid",
            ),
        )

        assert mozilla_hashes != microsoft_hashes


class TestRenderEvent22:
    """Test Event 22 (DNSQuery) rendering."""

    def test_renders_valid_event22(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.0.1", src_port=49152, dst_port=53, protocol="udp"
            ),
            dns=DnsContext(query="evil-c2.com", rcode="NOERROR", answers=["1.2.3.4"]),
        )
        # Event 22 fires when DNS is present, even if Event 3 is filtered
        emitter._render_sysmon_dns_query(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert "<EventID>22</EventID>" in content
        assert "evil-c2.com" in content
        assert "1.2.3.4;" in content
        assert "svchost.exe" in content

    def test_dns_query_uses_source_latency_offset(self, emitter):
        """Sysmon Event 22 should not render at the exact Zeek DNS packet timestamp."""
        event_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)
        event = SecurityEvent(
            timestamp=event_time,
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.0.1", src_port=49152, dst_port=53, protocol="udp"
            ),
            dns=DnsContext(
                query="example.com", query_type="A", rcode="NOERROR", answers=["1.2.3.4"]
            ),
        )

        emitter._render_sysmon_dns_query(event)

        expected_delta = sample_timing_delta(
            "source.sysmon_dns_query",
            seed_parts=("WKS-01", "example.com", "A", event_time),
        )
        assert emitter._event_dicts[0]["TimeCreated"] == event_time + expected_delta

    def test_nxdomain_query_status(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.0.1", src_port=49152, dst_port=53, protocol="udp"
            ),
            dns=DnsContext(query="doesnotexist.com", rcode="NXDOMAIN", answers=[]),
        )
        emitter._render_sysmon_dns_query(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="QueryStatus">9003</Data>' in content
        assert '<Data Name="QueryResults">-</Data>' in content

    def test_servfail_query_status(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10", dst_ip="10.0.0.1", src_port=49152, dst_port=53, protocol="udp"
            ),
            dns=DnsContext(query="flaky.com", rcode="SERVFAIL", answers=[]),
        )
        emitter._render_sysmon_dns_query(event)
        emitter.flush()

        output_path = list(emitter._host_writers.values())[0].output_path
        content = output_path.read_text()
        assert '<Data Name="QueryStatus">9002</Data>' in content


class TestPidResolutionInFilter:
    """Test that Event 3 filter resolves initiating_pid when ProcessContext is absent."""

    def test_lolbin_connection_with_pid_only_passes_filter(self, emitter):
        """powershell.exe connecting to port 443 with only initiating_pid should pass."""
        from unittest.mock import MagicMock

        # Mock StateManager with a running powershell.exe process
        mock_sm = MagicMock()
        mock_proc = MagicMock()
        mock_proc.image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        mock_sm.get_process.return_value = mock_proc
        emitter._state_manager = mock_sm

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            # No ProcessContext — only initiating_pid on NetworkContext
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                src_port=49200,
                dst_port=443,
                protocol="tcp",
                initiating_pid=4567,
            ),
        )
        assert emitter._passes_event3_filter(event) is True

    def test_browser_connection_with_pid_only_can_be_sampled(self, emitter):
        """chrome.exe with only initiating_pid should be eligible for user-app sampling."""
        from unittest.mock import MagicMock

        emitter._filters = {
            "network_connect": {
                "enabled": True,
                "mode": "include",
                "include_images": [],
                "include_baseline_images": [],
                "include_user_app_images": ["chrome.exe"],
                "user_app_sample_rate": 1.0,
                "include_dest_ports": [],
                "exclude_dest_ips": [],
            }
        }

        mock_sm = MagicMock()
        mock_proc = MagicMock()
        mock_proc.image = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        mock_sm.get_process.return_value = mock_proc
        emitter._state_manager = mock_sm

        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="93.184.216.34",
                src_port=49200,
                dst_port=443,
                protocol="tcp",
                initiating_pid=5678,
            ),
        )
        assert emitter._passes_event3_filter(event) is True


class TestTemplateCompleteness:
    """Verify that rendered XML has no empty required fields (catches template variable typos)."""

    def _get_required_fields(self, content: str, event_id: int) -> list[str]:
        """Extract Data Name fields that have empty values."""
        import re

        empty = re.findall(r'<Data Name="(\w+)"></Data>', content)
        # Also check for fields with just whitespace
        whitespace = re.findall(r'<Data Name="(\w+)">\s*</Data>', content)
        return list(set(empty + whitespace))

    def test_event3_no_empty_required_fields(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd",
                username="admin",
            ),
            auth=AuthContext(username="admin"),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="10.0.2.20",
                src_port=49152,
                dst_port=4444,
                protocol="tcp",
            ),
        )
        emitter.emit(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        empty = self._get_required_fields(content, 3)
        # RuleName, SourcePortName, DestinationHostname, DestinationPortName are optional
        optional = {"RuleName", "SourcePortName", "DestinationHostname", "DestinationPortName"}
        required_empty = [f for f in empty if f not in optional]
        assert required_empty == [], f"Empty required fields in Event 3: {required_empty}"

    def test_event7_no_empty_required_fields(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="image_load",
            src_host=_win_host(),
            process=ProcessContext(
                pid=1234,
                parent_pid=1,
                image=r"C:\Windows\explorer.exe",
                command_line="",
                username="user",
            ),
            image_load=ImageLoadContext(
                image_loaded=r"C:\Program Files\App\plugin.dll",
                signed=False,
                signature="-",
                signature_status="Unavailable",
            ),
        )
        emitter.emit(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        empty = self._get_required_fields(content, 7)
        optional = {"RuleName"}
        required_empty = [f for f in empty if f not in optional]
        assert required_empty == [], f"Empty required fields in Event 7: {required_empty}"

    def test_event11_no_empty_required_fields(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="file_create",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\powershell.exe",
                command_line="powershell",
                username="admin",
            ),
            file=FileContext(path=r"C:\Windows\Temp\payload.exe", action="create"),
        )
        emitter.emit(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        empty = self._get_required_fields(content, 11)
        optional = {"RuleName"}
        required_empty = [f for f in empty if f not in optional]
        assert required_empty == [], f"Empty required fields in Event 11: {required_empty}"

    def test_event13_no_empty_required_fields(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="registry_modify",
            src_host=_win_host(),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\reg.exe",
                command_line="reg add",
                username="admin",
            ),
            registry=RegistryContext(
                key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Test",
                value="test.exe",
                action="modify",
            ),
        )
        emitter.emit(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        empty = self._get_required_fields(content, 13)
        optional = {"RuleName"}
        required_empty = [f for f in empty if f not in optional]
        assert required_empty == [], f"Empty required fields in Event 13: {required_empty}"
        assert '<Data Name="User">CORP\\admin</Data>' in content

    def test_event22_no_empty_required_fields(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="connection",
            src_host=_win_host(),
            network=NetworkContext(
                src_ip="10.0.1.10",
                dst_ip="10.0.0.1",
                src_port=49152,
                dst_port=53,
                protocol="udp",
            ),
            dns=DnsContext(query="example.com", rcode="NOERROR", answers=["93.184.216.34"]),
        )
        emitter._render_sysmon_dns_query(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        empty = self._get_required_fields(content, 22)
        optional = {"RuleName"}
        required_empty = [f for f in empty if f not in optional]
        assert required_empty == [], f"Empty required fields in Event 22: {required_empty}"

    def test_sysmon_events_default_rule_name_to_dash(self, emitter):
        """Sysmon RuleName should be consistently populated when no rule matched."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=_win_host(),
            auth=AuthContext(username="admin"),
            process=ProcessContext(
                pid=4567,
                parent_pid=1,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd",
                username="admin",
            ),
        )
        emitter.emit(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        assert '<Data Name="RuleName">-</Data>' in content
        assert '<Data Name="RuleName"></Data>' not in content


# ── Tests for expert review fixes ──────────────────────────────────────


class TestUserFieldFormatting:
    """Fix 1: NT AUTHORITY\\SYSTEM instead of DOMAIN\\SYSTEM."""

    def test_system_user_gets_nt_authority(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=_win_host(),
            auth=AuthContext(username="SYSTEM", logon_id="0x3e7"),
            process=ProcessContext(
                pid=4000,
                parent_pid=600,
                image=r"C:\Windows\System32\svchost.exe",
                command_line="svchost.exe -k netsvcs",
                username="SYSTEM",
            ),
        )
        emitter._render_sysmon_process_create(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        assert "NT AUTHORITY\\SYSTEM" in content
        assert "CORP\\SYSTEM" not in content

    def test_local_service_gets_nt_authority(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=_win_host(),
            auth=AuthContext(username="LOCAL SERVICE", logon_id="0x3e5"),
            process=ProcessContext(
                pid=4001,
                parent_pid=600,
                image=r"C:\Windows\System32\svchost.exe",
                command_line="svchost.exe -k LocalService",
                username="LOCAL SERVICE",
            ),
        )
        emitter._render_sysmon_process_create(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        assert "NT AUTHORITY\\LOCAL SERVICE" in content
        assert "CORP\\LOCAL SERVICE" not in content

    def test_regular_user_gets_domain(self, emitter):
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="process_create",
            src_host=_win_host(),
            auth=AuthContext(username="jsmith", logon_id="0x12345"),
            process=ProcessContext(
                pid=4002,
                parent_pid=3000,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe",
                username="jsmith",
            ),
        )
        emitter._render_sysmon_process_create(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        assert "CORP\\jsmith" in content

    def test_process_access_target_user_gets_domain(self, emitter):
        """Sysmon Event 10 target user should use source-native domain formatting."""
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="process_access",
            src_host=_win_host(),
            auth=AuthContext(username="jsmith", logon_id="0x12345"),
            process=ProcessContext(
                pid=4002,
                parent_pid=3000,
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe",
                username="jsmith",
                start_time=datetime(2024, 1, 15, 9, 59, tzinfo=UTC),
            ),
            process_access=ProcessAccessContext(
                source_pid=4002,
                source_image=r"C:\Windows\System32\cmd.exe",
                source_thread_id=4200,
                target_pid=500,
                target_image=r"C:\Windows\System32\lsass.exe",
                target_user="SYSTEM",
                granted_access="0x1010",
            ),
        )
        emitter._render_sysmon_process_access(event)
        emitter.flush()
        content = list(emitter._host_writers.values())[0].output_path.read_text()
        assert '<Data Name="TargetUser">NT AUTHORITY\\SYSTEM</Data>' in content
        assert '<Data Name="TargetUser">SYSTEM</Data>' not in content


class TestCallTraceConsistency:
    """Fix 3: CallTrace offsets consistent per host, different across hosts."""

    def test_offsets_consistent_per_host(self, emitter):
        """Same pattern picked twice should show same offsets (cache is stable)."""
        # Force cache population
        emitter._get_call_trace("HOST-A")
        cached = emitter._call_trace_cache["HOST-A"]
        # Pick one specific pattern and verify it's always the same string
        pattern_0 = cached[0]
        for _ in range(10):
            assert cached[0] == pattern_0, "Cached patterns should not change"

    def test_offsets_differ_across_hosts(self, emitter):
        emitter._get_call_trace("HOST-A")
        emitter._get_call_trace("HOST-B")
        # Compare first pattern's first offset between hosts
        off_a = emitter._call_trace_cache["HOST-A"][0].split("+")[1].split("|")[0]
        off_b = emitter._call_trace_cache["HOST-B"][0].split("+")[1].split("|")[0]
        assert off_a != off_b, "Different hosts should have different CallTrace offsets"

    def test_multiple_call_patterns_available(self, emitter):
        emitter._get_call_trace("HOST-C")
        patterns = emitter._call_trace_cache["HOST-C"]
        assert len(patterns) >= 8, f"Expected >=8 patterns from YAML, got {len(patterns)}"


class TestProcessGuidBootTime:
    """ProcessGuid shape should be stable, host-specific, and source-native."""

    def test_guid_differs_with_different_boot_times_without_low_counter_shape(self, emitter):
        emitter._host_boot_times = {
            "HOST-A": datetime(2024, 2, 1, 6, 0, tzinfo=UTC),
            "HOST-B": datetime(2024, 3, 15, 12, 0, tzinfo=UTC),
        }
        creation = datetime(2024, 4, 1, 10, 0, tzinfo=UTC)
        guid_a = emitter._generate_process_guid("HOST-A", 1234, creation)
        guid_b = emitter._generate_process_guid("HOST-B", 1234, creation)
        assert guid_a != guid_b
        assert guid_a.split("-")[1] == guid_b.split("-")[1]
        assert guid_a.split("-")[1] != "000c"

    def test_guid_deterministic_with_boot_time(self, emitter):
        emitter._host_boot_times = {
            "HOST-A": datetime(2024, 2, 1, 6, 0, tzinfo=UTC),
        }
        creation = datetime(2024, 4, 1, 10, 0, tzinfo=UTC)
        guid1 = emitter._generate_process_guid("HOST-A", 1234, creation)
        guid2 = emitter._generate_process_guid("HOST-A", 1234, creation)
        assert guid1 == guid2


class TestEvent3PortProcessConstraints:
    """Fix 7: Port-process constraints in Event 3 filter."""

    def _make_conn_event(self, dst_port, image=None, initiating_pid=-1):
        host = _win_host()
        net = NetworkContext(
            src_ip="10.0.1.10",
            dst_ip="10.0.2.20",
            src_port=49152,
            dst_port=dst_port,
            protocol="tcp",
            initiating_pid=initiating_pid,
        )
        proc = (
            ProcessContext(
                pid=5000,
                parent_pid=3000,
                image=image,
                command_line=f"{image} args",
                username="jsmith",
            )
            if image
            else None
        )
        return SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            event_type="connection",
            src_host=host,
            network=net,
            process=proc,
        )

    def test_svchost_ssh_filtered(self, emitter):
        event = self._make_conn_event(22, image=r"C:\Windows\System32\svchost.exe")
        assert emitter._passes_event3_filter(event) is False

    def test_ssh_exe_ssh_passes(self, emitter):
        event = self._make_conn_event(22, image=r"C:\Windows\System32\OpenSSH\ssh.exe")
        assert emitter._passes_event3_filter(event) is True

    def test_powershell_ssh_passes(self, emitter):
        event = self._make_conn_event(
            22, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )
        assert emitter._passes_event3_filter(event) is True

    def test_unconstrained_port_any_process(self, emitter):
        # Port 4444 has no constraints — any process should pass
        event = self._make_conn_event(4444, image=r"C:\Windows\System32\svchost.exe")
        assert emitter._passes_event3_filter(event) is True

    def test_unknown_pid_resolves_to_dash(self, emitter):
        pid, image = emitter._resolve_process_from_pid("WKS-01", 99999)
        assert image == "-"
        assert pid == 99999
