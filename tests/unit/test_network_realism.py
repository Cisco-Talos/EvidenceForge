# Tests for network realism fixes from expert reviewer feedback.
#
# Verifies statistical distributions are realistic:
# - UDP/TCP overhead not constant/uniform
# - NTP timing varies by stratum
# - SSL has failure rate, diverse history, weighted ciphers
# - Proxy bytes differ from Zeek bytes
# - Proxy UAs match source OS

import math
import random
from collections import Counter

from evidenceforge.generation.activity.generator import (
    _NTP_STRATUM_TIMING,
    _SSL_FAILURE_RATE,
    _SSL_HIST_FAILURE_VALUES,
    _SSL_HIST_SUCCESS_VALUES,
    _SSL_HIST_SUCCESS_WEIGHTS,
    _TCP_OVERHEAD_VALUES,
    _TCP_OVERHEAD_WEIGHTS,
    _TLS12_CIPHER_VALUES,
    _TLS12_CIPHER_WEIGHTS,
    _TLS13_CIPHER_VALUES,
    _TLS13_CIPHER_WEIGHTS,
    _UDP_OVERHEAD_VALUES,
    _UDP_OVERHEAD_WEIGHTS,
    _choose_ssl_history,
)
from evidenceforge.generation.activity.network_params import (
    external_scanner_port_profile_for_source,
    external_scanner_port_profiles,
)
from evidenceforge.generation.activity.proxy_user_agents import load_proxy_user_agents


def _proxy_ua_pool(*path: str) -> list[str]:
    value = load_proxy_user_agents()
    for key in path:
        value = value[key]
    return value


class TestProtocolOverhead:
    """Bug #1 + #8: UDP/TCP overhead distributions."""

    def test_udp_overhead_mostly_28_with_variance(self):
        rng = random.Random(42)
        samples = [
            rng.choices(_UDP_OVERHEAD_VALUES, weights=_UDP_OVERHEAD_WEIGHTS, k=1)[0]
            for _ in range(1000)
        ]
        counts = Counter(samples)
        # Most should be 28 but not all
        assert counts[28] > 800
        assert counts[28] < 1000  # some variance
        assert len(counts) > 1
        assert max(samples) <= 68

    def test_tcp_overhead_bimodal_favoring_52(self):
        rng = random.Random(42)
        samples = [
            rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
            for _ in range(1000)
        ]
        counts = Counter(samples)
        # 52 should dominate (~75%)
        assert counts[52] > 650
        # 40 should be present (~10%)
        assert counts[40] > 50
        # All 4 values should appear
        assert len(counts) == 4


class TestExternalScannerProfiles:
    """External scanner sources should have source-sticky, non-flat port preferences."""

    def test_external_scanner_profiles_are_loaded(self):
        profiles = external_scanner_port_profiles()

        assert len(profiles) >= 4
        assert all(profile["ports"] for profile in profiles)
        assert any(profile["name"] == "web_recon" for profile in profiles)
        assert any(profile["name"] == "windows_exposure" for profile in profiles)

    def test_external_scanner_profiles_are_sticky_by_source(self):
        observed = set()
        for idx in range(40):
            src_ip = f"198.51.100.{idx + 1}"
            profile = external_scanner_port_profile_for_source(src_ip)

            assert profile == external_scanner_port_profile_for_source(src_ip)
            observed.add(profile["name"])

        assert len(observed) >= 4


class TestNtpTiming:
    """Bug #2: NTP timing varies by stratum."""

    def test_stratum_timing_params_exist(self):
        assert 1 in _NTP_STRATUM_TIMING
        assert 2 in _NTP_STRATUM_TIMING
        assert 3 in _NTP_STRATUM_TIMING

    def test_higher_stratum_has_larger_mean(self):
        mean_1 = _NTP_STRATUM_TIMING[1][0]
        mean_2 = _NTP_STRATUM_TIMING[2][0]
        mean_3 = _NTP_STRATUM_TIMING[3][0]
        assert mean_1 < mean_2 < mean_3

    def test_lognormal_produces_varied_rtts(self):
        rng = random.Random(42)
        mean_ms, sigma = _NTP_STRATUM_TIMING[2]
        mu = math.log(mean_ms) - (sigma**2) / 2
        samples = [rng.lognormvariate(mu, sigma) for _ in range(100)]
        # Should have meaningful variance (not all ~10ms)
        assert max(samples) / min(samples) > 3.0


class TestSslRealism:
    """Bugs #5, #6, #7: SSL failure, history diversity, cipher weights."""

    def test_ssl_failure_rate_defined(self):
        assert 0.01 <= _SSL_FAILURE_RATE <= 0.05

    def test_ssl_history_has_more_than_2_patterns(self):
        assert len(_SSL_HIST_SUCCESS_VALUES) > 2
        assert len(_SSL_HIST_FAILURE_VALUES) >= 2

    def test_established_ssl_histories_include_server_hello(self):
        """Zeek ssl.log established handshakes should include ServerHello."""
        allowed_codes = set("^HCSVTXKRNYGFWUAZIBDEOPMJLQ")

        assert all("S" in history for history in _SSL_HIST_SUCCESS_VALUES)
        assert all(set(history) <= allowed_codes for history in _SSL_HIST_SUCCESS_VALUES)
        assert all(
            "S"
            in _choose_ssl_history(
                random.Random(seed),
                tls_version="TLSv13" if seed % 2 else "TLSv12",
                established=True,
                resumed=bool(seed % 3),
            )
            for seed in range(100)
        )

    def test_ssl_history_sampling_produces_diversity(self):
        rng = random.Random(42)
        samples = [
            rng.choices(_SSL_HIST_SUCCESS_VALUES, weights=_SSL_HIST_SUCCESS_WEIGHTS, k=1)[0]
            for _ in range(1000)
        ]
        unique = set(samples)
        assert len(unique) >= 4  # at least 4 of 5 patterns should appear

    def test_tls12_cipher_aes128_dominates(self):
        rng = random.Random(42)
        samples = [
            rng.choices(_TLS12_CIPHER_VALUES, weights=_TLS12_CIPHER_WEIGHTS, k=1)[0]
            for _ in range(1000)
        ]
        counts = Counter(samples)
        aes128 = counts.get("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0)
        assert aes128 > 500  # should be ~60%

    def test_tls13_cipher_aes128_dominates(self):
        rng = random.Random(42)
        samples = [
            rng.choices(_TLS13_CIPHER_VALUES, weights=_TLS13_CIPHER_WEIGHTS, k=1)[0]
            for _ in range(1000)
        ]
        counts = Counter(samples)
        aes128 = counts.get("TLS_AES_128_GCM_SHA256", 0)
        assert aes128 > 450  # should be ~55%


class TestProxyRealism:
    """Bug #3: Proxy bytes differ from wire bytes."""

    def test_proxy_overhead_adds_bytes(self):
        """Proxy cs_bytes should exceed orig_bytes due to header overhead."""
        rng = random.Random(42)
        orig_bytes = 500
        from evidenceforge.generation.activity.generator import _PROXY_CS_OVERHEAD

        cs = orig_bytes + rng.randint(*_PROXY_CS_OVERHEAD)
        assert cs > orig_bytes

    def test_proxy_cache_hit_sc_bytes_include_response_overhead(self):
        """Cache HIT sc-bytes should be response payload plus proxy overhead."""
        rng = random.Random(42)
        resp_bytes = 10000
        from evidenceforge.generation.activity.generator import _PROXY_SC_OVERHEAD

        _sc = resp_bytes + rng.randint(*_PROXY_SC_OVERHEAD)
        assert resp_bytes < _sc <= resp_bytes + _PROXY_SC_OVERHEAD[1]


class TestProxyUaOsMatch:
    """Bug #19: Proxy UAs match source OS."""

    def test_linux_ua_pool_is_generic_not_package_specific(self):
        linux_uas = " ".join(_proxy_ua_pool("workstation", "linux"))
        assert "apt-http" not in linux_uas
        assert "Fedora" not in linux_uas
        assert "python-requests" in linux_uas
        assert "curl" in linux_uas

    def test_windows_ua_pool_has_browsers(self):
        windows_uas = " ".join(_proxy_ua_pool("workstation", "windows"))
        assert "Windows NT" in windows_uas
        assert "Chrome" in windows_uas

    def test_linux_pool_differs_from_windows(self):
        assert set(_proxy_ua_pool("workstation", "linux")) != set(
            _proxy_ua_pool("workstation", "windows")
        )
