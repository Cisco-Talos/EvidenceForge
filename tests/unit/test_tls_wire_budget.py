"""Full-handshake responder budgets across key and application families."""

from dataclasses import replace

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import TlsWireBudgetConfig
from evidenceforge.events.contexts import SslContext, X509Context
from evidenceforge.generation.activity.tls_realism import (
    certificate_file_size,
    tls_server_payload_budget,
)


@pytest.mark.parametrize("key_bits", [2048, 3072, 4096])
@pytest.mark.parametrize("service", ["ssl", "smtp"])
def test_rsa_handshake_budget_includes_signature_and_protocol(key_bits: int, service: str) -> None:
    chain = (X509Context(certificate_key_length=key_bits), X509Context(host_cert=False))
    ssl = SslContext(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    total = tls_server_payload_budget(zeek_uid="Cbudget", ssl=ssl, chain=chain, service=service)
    der = sum(certificate_file_size(cert) for cert in chain)
    assert total > der + key_bits // 8 + 150
    assert total == tls_server_payload_budget(
        zeek_uid="Cbudget", ssl=ssl, chain=chain, service=service
    )


def test_ecdsa_application_budget_and_connection_scope() -> None:
    ssl = SslContext(version="TLSv12", cipher="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
    chain = (X509Context(certificate_key_type="ecdsa", certificate_key_length=256),)
    base = tls_server_payload_budget(zeek_uid="Ca", ssl=ssl, chain=chain)
    body = tls_server_payload_budget(zeek_uid="Ca", ssl=ssl, chain=chain, application_bytes=20000)
    assert body >= base + 20000 + 2 * 29
    assert (
        len({tls_server_payload_budget(zeek_uid=f"C{i}", ssl=ssl, chain=chain) for i in range(20)})
        > 15
    )
    assert (
        tls_server_payload_budget(zeek_uid="Ca", ssl=replace(ssl, resumed=True), chain=chain) == 0
    )
    assert (
        tls_server_payload_budget(zeek_uid="Ca", ssl=replace(ssl, version="TLSv13"), chain=chain)
        == 0
    )


def test_wire_profile_rejects_inverted_range() -> None:
    with pytest.raises(ValidationError, match="extension_bytes_min"):
        TlsWireBudgetConfig(extension_bytes_min=200, extension_bytes_max=100)


@pytest.mark.parametrize("service,port", [("ssl", 443), ("smtp", 25)])
def test_tls_close_tracks_sampled_analyzer_readiness(service: str, port: int) -> None:
    from datetime import UTC, datetime

    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.generation.activity.generator import ActivityGenerator
    from evidenceforge.generation.activity.tls_realism import certificate_analyzer_delay_ms
    from evidenceforge.generation.timing import TimingRuntime
    from tests.network_factories import network_plan

    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = TimingRuntime(reference_time=at, namespace="tls-close-test")
    durations: set[float] = set()
    for index in range(20):
        chain = (X509Context(fuid=f"F{index}a"), X509Context(fuid=f"F{index}b", host_cert=False))
        event = OccurrenceBuilder(
            timestamp=at,
            event_type="connection",
            network=network_plan(
                src_ip="10.0.0.1",
                src_port=50000 + index,
                dst_ip="10.0.0.2",
                dst_port=port,
                protocol="tcp",
                service=service,
                zeek_uid=f"C{index}",
                duration=0.01,
            ),
            ssl=SslContext(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            x509_chain=chain,
        )
        generator._ensure_tls_conn_covers_certificate_bytes(event)
        expected = (
            max(
                certificate_analyzer_delay_ms(
                    zeek_uid=event.network.zeek_uid,
                    event_timestamp=at,
                    fuid=cert.fuid,
                    position=position,
                    timing_runtime=generator.timing_runtime,
                )
                for position, cert in enumerate(chain)
            )
            / 1000
            + 0.005
        )
        assert event.network.duration == pytest.approx(expected)
        assert event.network.closed_at > event.network.started_at
        durations.add(event.network.duration)
    assert len(durations) > 15
    assert any(value < 1.2 for value in durations)


@pytest.mark.parametrize("service,port", [("ssl", 443), ("smtp", 25)])
def test_tls_growth_keeps_retransmitted_payload_in_wire_ledger(service: str, port: int) -> None:
    from datetime import UTC, datetime

    from evidenceforge.events.base import OccurrenceBuilder
    from evidenceforge.generation.activity.generator import ActivityGenerator
    from evidenceforge.generation.timing import TimingRuntime
    from tests.network_factories import network_plan

    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = TimingRuntime(reference_time=at, namespace="tls-retransmission")
    event = OccurrenceBuilder(
        timestamp=at,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.1",
            src_port=50000,
            dst_ip="10.0.0.2",
            dst_port=port,
            protocol="tcp",
            service=service,
            zeek_uid="Ctls-retransmit",
            duration=3,
            orig_bytes=100,
            resp_bytes=100,
            orig_pkts=8,
            resp_pkts=8,
            orig_ip_bytes=616,
            resp_ip_bytes=616,
            history="ShADadTtFf",
        ),
        ssl=SslContext(version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
        x509_chain=(X509Context(fuid="Fa"), X509Context(fuid="Fb", host_cert=False)),
    )
    assert generator._ensure_tls_conn_covers_certificate_bytes(event)
    net = event.network
    assert net.resp_ip_bytes > net.resp_bytes + 40 * net.resp_pkts
    assert net.resp_ip_bytes <= 1500 * net.resp_pkts
