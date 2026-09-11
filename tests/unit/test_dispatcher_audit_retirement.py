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

"""Deterministic lifetime coverage for dispatcher-owned nested audit capabilities."""

import gc
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from tests.unit.test_rdp_deferred_production import (
    _END,
    _close_rdp_terminal_harness,
    _open_rdp_terminal_harness,
)


def test_terminal_audit_retirement_survives_gc_until_successor_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Canceled and committed audit identities cannot be reused before a successor exists."""

    harness = _open_rdp_terminal_harness(tmp_path, include_sysmon=True)
    dispatcher = harness.dispatcher
    original_release = (
        EventDispatcher._release_action_cohort_audit_retirements_after_successor_registration
    )
    transitions: list[tuple[tuple[int, ...], int, tuple[bool, ...]]] = []

    def release_after_successor(owner: EventDispatcher) -> None:
        with owner._action_cohort_lock:
            retired = tuple(owner._action_cohort_audit_retirements)
            current = tuple(
                record.audit_preparation
                for record in owner._action_cohort_prepare_cleanups.values()
                if record.audit_preparation is not None
            )
        if retired:
            assert len(current) == 1
            successor = current[0]
            retired_ids = tuple(id(item.preparation) for item in retired)
            assert all(item.preparation is not successor for item in retired)
            assert id(successor) not in retired_ids
            transitions.append(
                (
                    retired_ids,
                    id(successor),
                    tuple(item.expected_receipt is not None for item in retired),
                )
            )
        original_release(owner)
        del retired
        gc.collect()

    monkeypatch.setattr(
        EventDispatcher,
        "_release_action_cohort_audit_retirements_after_successor_registration",
        release_after_successor,
    )
    original_claim = EventDispatcher.claimed_action_cohort
    injected = False

    @contextmanager
    def fail_before_first_claim(
        owner: EventDispatcher,
        batch: object,
    ) -> Iterator[object]:
        nonlocal injected
        if not injected:
            injected = True
            raise OSError("injected audit-retirement fail-before")
        with original_claim(owner, batch) as capability:
            yield capability

    monkeypatch.setattr(EventDispatcher, "claimed_action_cohort", fail_before_first_claim)
    with pytest.raises(OSError, match="audit-retirement fail-before"):
        harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    gc.collect()
    with dispatcher._action_cohort_lock:
        canceled = tuple(dispatcher._action_cohort_audit_retirements)
    assert len(canceled) == 1
    assert canceled[0].preparation._cancelled
    assert canceled[0].expected_receipt is None

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert len(transitions) >= 5
    assert transitions[0][2] == (False,)
    with dispatcher._action_cohort_lock:
        terminal = tuple(dispatcher._action_cohort_audit_retirements)
    assert len(terminal) == 1
    assert terminal[0].preparation.committed
    assert terminal[0].preparation.receipt is terminal[0].expected_receipt
    _close_rdp_terminal_harness(harness)
