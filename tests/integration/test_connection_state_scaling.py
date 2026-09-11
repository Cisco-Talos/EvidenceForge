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

"""Scaling regression tests for long-running connection state."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.state_manager import StateManager

pytestmark = pytest.mark.soak


def test_45_day_connection_state_remains_bounded() -> None:
    """Completed connections and secondary indexes should not grow across 45 simulated days."""
    manager = StateManager()
    scenario_start = datetime(2024, 1, 1, tzinfo=UTC)
    connections_per_day = 1_000

    for day in range(45):
        day_start = scenario_start + timedelta(days=day)
        manager.set_current_time(day_start)
        for ordinal in range(connections_per_day):
            source_ip = f"10.0.{ordinal // 256}.{ordinal % 256}"
            source_port = 40_000 + ordinal
            manager.open_connection(
                source_ip,
                source_port,
                "10.10.0.53",
                53,
                "udp",
                close_time=day_start + timedelta(seconds=ordinal % 3 + 1),
            )

        assert not manager.connection_tuple_recently_used(
            "192.0.2.250",
            59_999,
            "10.10.0.53",
            53,
            "udp",
            day_start,
            reuse_window=86_400,
        )
        assert (
            manager.sweep_closed_connections(day_start + timedelta(days=1)) == connections_per_day
        )
        assert manager.state.open_connections == {}
        assert (
            manager._open_connections.find_keys(
                "exact_tuple",
                ("192.0.2.250", 59_999, "10.10.0.53", 53, "udp"),
            )
            == ()
        )
