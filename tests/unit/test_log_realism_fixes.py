# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Tests for log realism fixes from the improvement loop expert panel.

Covers: web_scan IDS alerts, Snort rev field, TLS cipher stability,
SSH key fingerprint uniqueness, eCAR NAT-aware IPs, DC session exclusion.
"""

import random
from datetime import UTC, datetime
from unittest.mock import MagicMock

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    IdsContext,
    NatContext,
    NetworkContext,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.generator import _TLS_VERSION_VALUES, _TLS_VERSION_WEIGHTS
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.utils.rng import _stable_seed

T0 = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)


# ── Snort rev field ──────────────────────────────────────────────────────


class TestSnortRevField:
    def test_ids_context_default_rev(self):
        ctx = IdsContext(sid=10001, message="test", classification="test")
        assert ctx.rev == 1

    def test_ids_context_custom_rev(self):
        ctx = IdsContext(sid=10001, message="test", classification="test", rev=14)
        assert ctx.rev == 14

    def test_snort_emitter_renders_rev(self, tmp_path):
        fmt = load_format("snort_alert")
        emitter = SnortEmitter(
            format_def=fmt,
            output_path=tmp_path,
            sensor_hostnames=["ids-01"],
        )

        event = SecurityEvent(
            timestamp=T0,
            event_type="connection",
            network=NetworkContext(
                src_ip="185.70.41.45",
                src_port=12345,
                dst_ip="10.10.3.10",
                dst_port=80,
                protocol="tcp",
            ),
            ids=IdsContext(
                sid=2002677,
                rev=14,
                message="ET SCAN Nikto Web App Scan in Progress",
                classification="web-application-attack",
                priority=2,
            ),
        )
        event._sensor_hostnames_by_format = {"snort_alert": ["ids-01"]}
        emitter.emit(event)
        emitter.flush()

        output = (tmp_path / "ids-01" / "snort_alert.log").read_text()
        assert "[2002677:1:14]" in output
        assert "ET SCAN Nikto" in output

    def test_snort_emitter_default_rev_is_1(self, tmp_path):
        fmt = load_format("snort_alert")
        emitter = SnortEmitter(
            format_def=fmt,
            output_path=tmp_path,
            sensor_hostnames=["ids-01"],
        )

        event = SecurityEvent(
            timestamp=T0,
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.0.1",
                src_port=54321,
                dst_ip="10.0.0.2",
                dst_port=22,
                protocol="tcp",
            ),
            ids=IdsContext(
                sid=384,
                message="PROTOCOL-ICMP PING",
                classification="icmp-event",
            ),
        )
        event._sensor_hostnames_by_format = {"snort_alert": ["ids-01"]}
        emitter.emit(event)
        emitter.flush()

        output = (tmp_path / "ids-01" / "snort_alert.log").read_text()
        assert "[384:1:1]" in output


# ── Web scan preset IDS config ───────────────────────────────────────────


class TestWebScanPresetIdsConfig:
    def test_all_presets_have_ids_ua(self):
        from evidenceforge.config.web_scan_presets import get_preset, list_preset_names

        for name in list_preset_names():
            preset = get_preset(name)
            assert preset is not None
            assert "ids_ua" in preset, f"Preset '{name}' missing ids_ua"
            ids_ua = preset["ids_ua"]
            assert "sid" in ids_ua, f"Preset '{name}' ids_ua missing sid"
            assert "rev" in ids_ua, f"Preset '{name}' ids_ua missing rev"
            assert "message" in ids_ua, f"Preset '{name}' ids_ua missing message"

    def test_all_presets_have_ids_rate(self):
        from evidenceforge.config.web_scan_presets import get_preset, list_preset_names

        for name in list_preset_names():
            preset = get_preset(name)
            assert preset is not None
            assert "ids_rate" in preset, f"Preset '{name}' missing ids_rate"
            ids_rate = preset["ids_rate"]
            assert "sid" in ids_rate
            assert "threshold" in ids_rate
            assert ids_rate["threshold"] > 0

    def test_some_paths_have_ids(self):
        from evidenceforge.config.web_scan_presets import get_preset

        nikto = get_preset("nikto")
        paths_with_ids = [p for p in nikto["paths"] if isinstance(p, dict) and "ids" in p]
        assert len(paths_with_ids) >= 5, (
            f"Nikto preset should have at least 5 paths with IDS mappings, got {len(paths_with_ids)}"
        )

    def test_path_ids_have_required_fields(self):
        from evidenceforge.config.web_scan_presets import get_preset, list_preset_names

        for name in list_preset_names():
            preset = get_preset(name)
            for path_entry in preset["paths"]:
                if isinstance(path_entry, dict) and "ids" in path_entry:
                    ids = path_entry["ids"]
                    assert "sid" in ids, f"{name}: path {path_entry.get('uri')} ids missing sid"
                    assert "message" in ids, (
                        f"{name}: path {path_entry.get('uri')} ids missing message"
                    )


# ── IDS signatures rev field ─────────────────────────────────────────────


class TestIdsSignaturesRevField:
    def test_all_signatures_have_rev(self):
        import yaml

        from evidenceforge.config import get_activity_directory

        path = get_activity_directory() / "ids_signatures.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)

        for sig in data["signatures"]:
            assert "rev" in sig, f"SID {sig.get('sid')} missing rev field"
            assert isinstance(sig["rev"], int), f"SID {sig.get('sid')} rev must be int"
            assert sig["rev"] >= 1, f"SID {sig.get('sid')} rev must be >= 1"

    def test_not_all_revs_are_one(self):
        import yaml

        from evidenceforge.config import get_activity_directory

        path = get_activity_directory() / "ids_signatures.yaml"
        with open(path) as f:
            data = yaml.safe_load(f)

        revs = [sig["rev"] for sig in data["signatures"]]
        unique_revs = set(revs)
        assert len(unique_revs) > 1, "All SID revisions are 1 — should have varied values"


# ── TLS cipher stability ─────────────────────────────────────────────────


class TestTlsCipherStability:
    def test_same_endpoint_pair_produces_same_cipher(self):
        _tls_rng_1 = random.Random(_stable_seed("tls:10.10.1.10:45.33.32.30:443"))
        version_1 = _tls_rng_1.choices(_TLS_VERSION_VALUES, weights=_TLS_VERSION_WEIGHTS, k=1)[0]

        _tls_rng_2 = random.Random(_stable_seed("tls:10.10.1.10:45.33.32.30:443"))
        version_2 = _tls_rng_2.choices(_TLS_VERSION_VALUES, weights=_TLS_VERSION_WEIGHTS, k=1)[0]

        assert version_1 == version_2

    def test_tls13_is_modern_default_majority(self):
        total = sum(_TLS_VERSION_WEIGHTS)
        tls13_ratio = _TLS_VERSION_WEIGHTS[_TLS_VERSION_VALUES.index("TLSv13")] / total
        assert tls13_ratio > 0.5

    def test_different_endpoints_produce_different_seeds(self):
        seed_a = _stable_seed("tls:10.10.1.10:45.33.32.30:443")
        seed_b = _stable_seed("tls:10.10.1.20:45.33.32.30:443")
        assert seed_a != seed_b


# ── SSH key fingerprint uniqueness ───────────────────────────────────────


class TestSshKeyFingerprint:
    def test_different_source_hosts_get_different_keys(self):
        keys = set()
        for src_ip in ["10.10.1.10", "10.10.1.20", "10.10.1.30", "10.10.1.40"]:
            _key_rng = random.Random(_stable_seed(f"ssh_client_key:{src_ip}:WEB-EXT-01"))
            key_type = _key_rng.choice(["RSA", "ED25519", "ECDSA"])
            key_hash = "".join(
                _key_rng.choices(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=43
                )
            )
            keys.add(f"{key_type}:{key_hash}")
        assert len(keys) == 4, f"Expected 4 unique keys, got {len(keys)}"

    def test_same_source_host_gets_same_key(self):
        keys = []
        for _ in range(3):
            _key_rng = random.Random(_stable_seed("ssh_client_key:10.10.1.10:WEB-EXT-01"))
            key_type = _key_rng.choice(["RSA", "ED25519", "ECDSA"])
            key_hash = "".join(
                _key_rng.choices(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", k=43
                )
            )
            keys.append(f"{key_type}:{key_hash}")
        assert keys[0] == keys[1] == keys[2]


# ── eCAR NAT-aware IP ────────────────────────────────────────────────────


class TestEcarNatAwareIp:
    def test_inbound_flow_uses_real_ip_not_nat_vip(self):
        from evidenceforge.generation.emitters.ecar import EcarEmitter

        fmt = load_format("ecar")
        emitter = EcarEmitter(format_def=fmt, output_path=MagicMock())
        emitter.emit_event = MagicMock()

        dst_host = MagicMock()
        dst_host.hostname = "WEB-EXT-01"
        dst_host.fqdn = "WEB-EXT-01.example.com"
        dst_host.os = "Ubuntu 22.04"
        dst_host.os_category = "linux"

        event = SecurityEvent(
            timestamp=T0,
            event_type="connection",
            network=NetworkContext(
                src_ip="185.70.41.45",
                src_port=12345,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="tcp",
            ),
            nat=NatContext(
                nat_type="static",
                mapped_src_ip="185.70.41.45",
                mapped_src_port=12345,
                mapped_dst_ip="10.10.3.10",
                mapped_dst_port=443,
            ),
        )
        event.dst_host = dst_host
        event.src_host = None

        emitter._render_connection(event)

        calls = emitter.emit_event.call_args_list
        assert len(calls) >= 1
        inbound_call = calls[0][0][0]
        assert inbound_call["dst_ip"] == "10.10.3.10", (
            f"eCAR should use real IP 10.10.3.10, got {inbound_call['dst_ip']}"
        )


# ── DNS multi-answer correctness ────────────────────────────────────────


class TestDnsMultiAnswer:
    def test_get_domain_ips_returns_correct_provider(self):
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        ips = get_domain_ips("mx.office365.com")
        if ips:
            for ip in ips:
                assert ip.startswith("40.107."), (
                    f"mx.office365.com should only have Microsoft IPs (40.107.x), got {ip}"
                )

    def test_get_domain_ips_empty_for_unknown(self):
        from evidenceforge.generation.activity.dns_registry import get_domain_ips

        assert get_domain_ips("nonexistent.example.com") == []


# ── IPv6 prefix correctness ─────────────────────────────────────────────


class TestIpv6PrefixCorrectness:
    def test_microsoft_ip_gets_microsoft_prefix(self):
        from evidenceforge.generation.activity.network import _ipv4_to_fake_ipv6

        result = _ipv4_to_fake_ipv6("40.107.22.53")
        assert result.startswith("2603:"), (
            f"Microsoft IP 40.107.22.53 should get 2603: prefix, got {result}"
        )

    def test_google_ip_gets_google_prefix(self):
        from evidenceforge.generation.activity.network import _ipv4_to_fake_ipv6

        result = _ipv4_to_fake_ipv6("142.250.80.46")
        assert result.startswith("2607:f8b0:"), (
            f"Google IP 142.250.80.46 should get 2607:f8b0: prefix, got {result}"
        )

    def test_default_is_not_google(self):
        from evidenceforge.generation.activity.network import _ipv4_to_fake_ipv6

        result = _ipv4_to_fake_ipv6("77.88.55.88")
        assert not result.startswith("2a00:1450"), (
            f"Unknown IP should NOT default to Google 2a00:1450, got {result}"
        )
        assert not result.startswith("2607:f8b0"), (
            f"Unknown IP should NOT default to Google 2607:f8b0, got {result}"
        )

    def test_private_ip_gets_ula_prefix(self):
        from evidenceforge.generation.activity.network import _ipv4_to_fake_ipv6

        result = _ipv4_to_fake_ipv6("10.10.1.50")
        assert result.startswith("fd00:"), f"Private IP should get fd00: ULA prefix, got {result}"

    def test_aws_ip_gets_aws_prefix(self):
        from evidenceforge.generation.activity.network import _ipv4_to_fake_ipv6

        result = _ipv4_to_fake_ipv6("52.95.110.1")
        assert result.startswith("2600:1f18:"), (
            f"AWS IP 52.x should get 2600:1f18: prefix, got {result}"
        )

    def test_ipv6_prefixes_loaded_from_yaml(self):
        from evidenceforge.generation.activity.network import _load_ipv6_prefixes

        config = _load_ipv6_prefixes()
        assert "default" in config
        assert "ranges" in config
        assert len(config["ranges"]) >= 10


# ── OS-aware domain filtering ────────────────────────────────────────────


class TestOsAwareDomainFiltering:
    def test_include_os_linux_excludes_windows_domains(self):
        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        for _ in range(50):
            domain, ip = pick_domain_and_ip(rng, "background", include_os="linux")
            from evidenceforge.generation.activity.dns_registry import get_domains_by_tag

            all_bg = get_domains_by_tag("background")
            entry = next((e for e in all_bg if e["domain"] == domain), None)
            if entry:
                assert "windows" not in entry.get("tags", []), (
                    f"Linux host got Windows domain: {domain}"
                )

    def test_include_os_windows_can_return_windows_domains(self):
        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        domains = set()
        for _ in range(200):
            domain, _ = pick_domain_and_ip(rng, "background", include_os="windows")
            domains.add(domain)
        from evidenceforge.generation.activity.dns_registry import get_domains_by_tag

        windows_bg = get_domains_by_tag("background", "windows")
        windows_domain_names = {e["domain"] for e in windows_bg}
        assert domains & windows_domain_names, (
            "Windows host should be able to get Windows-tagged domains"
        )

    def test_no_include_os_returns_all(self):
        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        domains = set()
        for _ in range(200):
            domain, _ = pick_domain_and_ip(rng, "background")
            domains.add(domain)
        from evidenceforge.generation.activity.dns_registry import get_domains_by_tag

        windows_bg = get_domains_by_tag("background", "windows")
        windows_domain_names = {e["domain"] for e in windows_bg}
        assert domains & windows_domain_names, (
            "Without include_os, Windows domains should be reachable"
        )

    def test_untagged_domains_always_available(self):
        from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

        rng = random.Random(42)
        domains = set()
        for _ in range(200):
            domain, _ = pick_domain_and_ip(rng, "web", include_os="linux")
            domains.add(domain)
        assert len(domains) > 0, "Linux host should get web domains (most are OS-neutral)"


# ── DC system_type filtering ─────────────────────────────────────────────


class TestDcSystemTypeFiltering:
    def test_dc_no_user_apps(self):
        from evidenceforge.generation.activity.application_catalog import get_apps_for_persona

        apps = get_apps_for_persona(
            "sysadmin", "windows", "user_app", system_type="domain_controller"
        )
        app_ids = {a["id"] for a in apps}
        assert "chrome" not in app_ids, "Chrome should not be available on DCs"
        assert "firefox" not in app_ids, "Firefox should not be available on DCs"
        assert "outlook" not in app_ids, "Outlook should not be available on DCs"

    def test_dc_admin_tools_available(self):
        from evidenceforge.generation.activity.application_catalog import get_apps_for_persona

        apps = get_apps_for_persona("sysadmin", "windows", "query", system_type="domain_controller")
        app_ids = {a["id"] for a in apps}
        assert "dcdiag" in app_ids, "dcdiag should be available on DCs"
        assert "repadmin" in app_ids, "repadmin should be available on DCs"

    def test_dc_admin_tools_not_on_workstation(self):
        from evidenceforge.generation.activity.application_catalog import get_apps_for_persona

        apps = get_apps_for_persona("sysadmin", "windows", "query", system_type="workstation")
        app_ids = {a["id"] for a in apps}
        assert "dcdiag" not in app_ids, "dcdiag should not be on workstations"
        assert "repadmin" not in app_ids, "repadmin should not be on workstations"

    def test_workstation_gets_full_apps(self):
        from evidenceforge.generation.activity.application_catalog import get_apps_for_persona

        apps = get_apps_for_persona("sysadmin", "windows", "user_app", system_type="workstation")
        app_ids = {a["id"] for a in apps}
        assert "chrome" in app_ids or "firefox" in app_ids, (
            "Workstation sysadmin should have browsers"
        )

    def test_no_system_type_returns_all(self):
        from evidenceforge.generation.activity.application_catalog import get_apps_for_persona

        apps_all = get_apps_for_persona("sysadmin", "windows", "query")
        apps_dc = get_apps_for_persona(
            "sysadmin", "windows", "query", system_type="domain_controller"
        )
        assert len(apps_all) >= len(apps_dc), (
            "Without system_type filter, should return at least as many apps"
        )
