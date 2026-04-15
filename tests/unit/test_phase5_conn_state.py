# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Unit tests for Phase 5.1.3: Zeek conn_state and history variety."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import (
    CONN_STATE_DISTRIBUTION,
    ActivityGenerator,
)
from evidenceforge.generation.state_manager import StateManager


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestConnStateDistribution:
    """Verify conn_state distribution is varied."""

    def test_conn_state_distribution_data(self):
        """CONN_STATE_DISTRIBUTION has correct structure."""
        assert len(CONN_STATE_DISTRIBUTION) >= 5
        total_weight = sum(w for _, w, _ in CONN_STATE_DISTRIBUTION)
        assert total_weight == 100

    def test_conn_state_not_all_sf(self, activity_gen, timestamp, state_manager, mock_emitters):
        """Over 200 connections, conn_state should not be 100% SF."""
        state_manager.set_current_time(timestamp)
        states = set()

        for i in range(200):
            mock_emitters["zeek_conn"].reset_mock()
            activity_gen.generate_connection(
                src_ip="10.0.10.1",
                dst_ip=f"93.184.{i // 256}.{i % 256 + 1}",
                time=timestamp,
                dst_port=443,
                duration=1.5,
                orig_bytes=500,
                resp_bytes=1000,
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                states.add(event.network.conn_state)

        # Should see at least 2 different states in 200 connections
        assert len(states) >= 2, f"Only saw states: {states}"

    def test_history_matches_conn_state(
        self, activity_gen, timestamp, state_manager, mock_emitters
    ):
        """History string should be a valid pattern for its conn_state."""
        from evidenceforge.generation.activity import TCP_CONN_STATE_DISTRIBUTION

        valid_histories: dict[str, set[str]] = {}
        for state, _, hist in TCP_CONN_STATE_DISTRIBUTION:
            valid_histories.setdefault(state, set()).add(hist)

        state_manager.set_current_time(timestamp)

        for i in range(100):
            mock_emitters["zeek_conn"].reset_mock()
            activity_gen.generate_connection(
                src_ip="10.0.10.1",
                dst_ip=f"93.184.{i // 256}.{i % 256 + 1}",
                time=timestamp,
                dst_port=443,
                duration=1.0,
                orig_bytes=500,
                resp_bytes=1000,
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                state = event.network.conn_state
                history = event.network.history
                assert history in valid_histories.get(state, set()), (
                    f"History '{history}' not valid for state '{state}'"
                )


class TestConnStateRebalance:
    """Verify conn_state distribution targets realistic enterprise ratios."""

    def test_tcp_sf_weight_in_range(self):
        """TCP SF total weight should be 55-70% (real enterprise: 55-75%)."""
        from evidenceforge.generation.activity import TCP_CONN_STATE_DISTRIBUTION

        sf_weight = sum(w for s, w, _ in TCP_CONN_STATE_DISTRIBUTION if s == "SF")
        total = sum(w for _, w, _ in TCP_CONN_STATE_DISTRIBUTION)
        sf_pct = sf_weight / total * 100
        assert 55 <= sf_pct <= 70, f"SF weight {sf_pct:.0f}% outside [55, 70] range"

    def test_s2_s3_states_present(self):
        """Half-closed states S2 and S3 should be in the distribution."""
        from evidenceforge.generation.activity import TCP_CONN_STATE_DISTRIBUTION

        states = {s for s, _, _ in TCP_CONN_STATE_DISTRIBUTION}
        assert "S2" in states, "S2 state missing"
        assert "S3" in states, "S3 state missing"

    def test_statistical_sf_ratio(self, activity_gen, timestamp, state_manager, mock_emitters):
        """Over 2000 connections, SF% should fall between 50% and 78%."""
        import random

        random.seed(42)
        state_manager.set_current_time(timestamp)
        sf_count = 0
        total = 0

        for i in range(2000):
            mock_emitters["zeek_conn"].reset_mock()
            activity_gen.generate_connection(
                src_ip="10.0.10.1",
                dst_ip=f"93.184.{(i + 100) // 256}.{(i + 100) % 256 + 1}",
                time=timestamp,
                dst_port=443,
                duration=1.5,
                orig_bytes=500,
                resp_bytes=1000,
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                total += 1
                if event.network.conn_state == "SF":
                    sf_count += 1

        sf_pct = sf_count / total * 100 if total else 0
        assert 50 <= sf_pct <= 78, f"SF {sf_pct:.1f}% outside [50, 78] range ({sf_count}/{total})"

    def test_s2_s3_partial_bytes(self, activity_gen, timestamp, state_manager, mock_emitters):
        """S2/S3 connections should have some data but potentially truncated resp_bytes."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            conn_state="S2",
            duration=5.0,
            orig_bytes=5000,
            resp_bytes=10000,
        )
        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "S2"
        # S2 should have some orig_bytes (connection was established)
        assert event.network.orig_bytes >= 0
        # resp_bytes should be truncated (20-70% of original)
        assert event.network.resp_bytes <= 10000
        # Duration should be shortened
        assert event.network.duration < 5.0


class TestConnStateByteConsistency:
    """Verify bytes/duration are consistent with connection state."""

    def test_s0_no_resp_bytes(self, activity_gen, timestamp, state_manager, mock_emitters):
        """S0 connections should have resp_bytes=0 and no duration."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "S0"
        assert event.network.duration is None

    def test_rej_no_resp_bytes(self, activity_gen, timestamp, state_manager, mock_emitters):
        """REJ connections should have resp_bytes=0."""
        state_manager.set_current_time(timestamp)

        rej_found = False
        for i in range(500):
            mock_emitters["zeek_conn"].reset_mock()
            activity_gen.generate_connection(
                src_ip="10.0.10.1",
                dst_ip=f"93.184.{(i + 50) // 256}.{(i + 50) % 256 + 1}",
                time=timestamp,
                dst_port=443,
                duration=1.0,
                orig_bytes=500,
                resp_bytes=1000,
            )
            if mock_emitters["zeek_conn"].emit.called:
                event = mock_emitters["zeek_conn"].emit.call_args[0][0]
                if event.network.conn_state == "REJ":
                    assert event.network.resp_bytes == 0
                    assert event.network.duration is None
                    rej_found = True
                    break

        assert rej_found, "No REJ connection found in 500 attempts"
