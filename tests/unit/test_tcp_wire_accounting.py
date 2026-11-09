"""Shared TCP IP accounting keeps protocol header words inside the MTU."""

import random

import pytest

from evidenceforge.generation.activity.network_transport import (
    _tcp_ip_byte_count,
    _tcp_packet_counts_from_payload_and_history,
)


@pytest.mark.parametrize("payload", [5_361_807, 1_628_245, 310_775, 314_783_351])
@pytest.mark.parametrize("overhead", [None, 40, 52, 64])
def test_bulk_tcp_headers_remain_word_aligned(payload: int, overhead: int | None) -> None:
    for seed in range(12):
        rng = random.Random(seed)
        orig, resp = _tcp_packet_counts_from_payload_and_history(731, payload, "ShADadfF", rng)
        for body, packets in [(731, orig), (payload, resp)]:
            total = _tcp_ip_byte_count(body, packets, rng, overhead_override=overhead)
            assert (total - body) % 4 == 0
            assert body + 40 * packets <= total <= 1500 * packets


def test_tcp_underallocated_packets_fail_at_the_owning_boundary() -> None:
    with pytest.raises(ValueError, match="packet count"):
        _tcp_ip_byte_count(1461, 1, random.Random(1))


@pytest.mark.parametrize("payload", [1, 53, 4009, 5_361_807])
def test_retransmitted_payload_is_additional_wire_data(payload: int) -> None:
    for seed in range(10):
        rng = random.Random(seed)
        orig, resp = _tcp_packet_counts_from_payload_and_history(
            payload, payload, "ShADadTtFf", rng
        )
        for packets in (orig, resp):
            total = _tcp_ip_byte_count(payload, packets, rng, retransmitted=True)
            assert total >= payload + 40 * packets + min(payload, 1200)
            assert total <= 1500 * packets


def test_retransmission_size_does_not_advance_other_protocol_rng() -> None:
    ordinary = random.Random(932)
    retransmitted = random.Random(932)
    _tcp_ip_byte_count(10000, 16, ordinary)
    _tcp_ip_byte_count(10000, 16, retransmitted, retransmitted=True)
    assert ordinary.getstate() == retransmitted.getstate()


@pytest.mark.parametrize("history", ["ShADadfF", "ShADadTtFf", "ShADadr"])
@pytest.mark.parametrize(("orig", "resp"), [(800, 0), (0, 700), (0, 0)])
def test_final_tcp_history_has_no_data_for_zero_payload(history: str, orig: int, resp: int) -> None:
    from evidenceforge.generation.activity.network_transport import (
        _tcp_history_consistent_with_payload,
    )

    aligned = _tcp_history_consistent_with_payload(history, orig, resp)
    assert aligned is not None
    assert ("D" in aligned) == (orig > 0)
    assert ("d" in aligned) == (resp > 0)
    assert orig > 0 or "T" not in aligned
    assert resp > 0 or "t" not in aligned
    assert "".join(c for c in aligned if c not in "DdTt") == "".join(
        c for c in history if c not in "DdTt"
    )


def test_unknown_tcp_payload_does_not_remove_observed_history() -> None:
    from evidenceforge.generation.activity.network_transport import (
        _tcp_history_consistent_with_payload,
    )

    assert _tcp_history_consistent_with_payload("ShADadTtFf", None, None) == "ShADadTtFf"


def test_history_only_reconciliation_preserves_ack_budget_and_other_rng() -> None:
    from evidenceforge.events.contexts import NetworkTransactionDraft
    from evidenceforge.generation.activity.network_transport import (
        _align_tcp_network_payload_with_history,
    )

    draft = NetworkTransactionDraft(
        src_ip="10.0.0.21",
        src_port=51001,
        dst_ip="10.0.0.40",
        dst_port=514,
        protocol="tcp",
        service="syslog",
        conn_state="SF",
        history="ShADadFf",
        orig_bytes=3000,
        resp_bytes=0,
        orig_pkts=8,
        resp_pkts=4,
        orig_ip_bytes=3416,
        resp_ip_bytes=208,
    )
    before = (draft.orig_pkts, draft.resp_pkts, draft.orig_ip_bytes, draft.resp_ip_bytes)
    rng = random.Random(819)
    state = rng.getstate()
    assert _align_tcp_network_payload_with_history(draft, rng)
    assert "d" not in draft.history
    assert (draft.orig_pkts, draft.resp_pkts, draft.orig_ip_bytes, draft.resp_ip_bytes) == before
    assert rng.getstate() == state
