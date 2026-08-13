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

"""Tests for stateful Linux snapd baseline messages."""

import random
import re

from evidenceforge.generation.engine.baseline import BaselineMixin


def test_snapd_terminal_task_ids_are_unique_and_follow_change_start() -> None:
    """Every terminal snapd task is emitted once after its change starts."""
    engine = BaselineMixin()
    rng = random.Random(4761)
    started_changes: set[int] = set()
    completed_tasks: set[tuple[int, int]] = set()

    for _ in range(500):
        message = engine._linux_snapd_message("WEB-01", rng)
        start_match = re.search(r"starting change (\d+)$", message)
        if start_match:
            started_changes.add(int(start_match.group(1)))
            continue

        done_match = re.search(r"change (\d+) task (\d+) done for (\S+)$", message)
        if not done_match:
            continue
        task_key = (int(done_match.group(1)), int(done_match.group(2)))
        assert task_key[0] in started_changes
        assert task_key not in completed_tasks
        completed_tasks.add(task_key)

    assert len(completed_tasks) >= 50


def test_snapd_state_is_scoped_per_host_and_deterministic() -> None:
    """Fresh generators reproduce each host's stable snapd sequence."""
    first = BaselineMixin()
    second = BaselineMixin()
    first_rng = random.Random(829)
    second_rng = random.Random(829)

    first_messages = [first._linux_snapd_message("MAIL-01", first_rng) for _ in range(40)]
    second_messages = [second._linux_snapd_message("MAIL-01", second_rng) for _ in range(40)]

    assert first_messages == second_messages
