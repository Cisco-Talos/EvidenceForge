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

"""Bash history clears are one canonical effect shared by rendering and ground truth."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.evaluation.ground_truth_agreement import (
    _collect_history_clear,
    _history_retention_errors,
)
from evidenceforge.events.evidence_source_rules import (
    HISTORY_DESTROYED_REASON,
    destroying_history_clear,
    history_entry_admitted,
)
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthCondition,
    GroundTruthOccurrence,
    GroundTruthSourceExpectation,
)
from evidenceforge.generation.activity.shell_history_effects import bash_history_effect
from evidenceforge.generation.emitters.bash_history import _is_clear_entry

_START = datetime(2026, 11, 2, 14, tzinfo=UTC)
_SOURCE = "bash_history:web-ext-01"


@pytest.mark.parametrize(
    ("command", "destroys"),
    [
        ("shred -u /root/.bash_history", True),
        ("history -c && cat /dev/null > ~/.bash_history", True),
        ("rm -f ~/.bash_history", True),
        ("truncate -s 0 /home/a/.bash_history", True),
        ("cat ~/.bash_history", False),
        ("ip addr show", False),
    ],
)
def test_emitter_clear_matches_canonical_history_effect(command: str, destroys: bool) -> None:
    rendered = f"#1793630379\n{command}"

    assert (bash_history_effect(command) == "destroy_prior") is destroys
    assert _is_clear_entry(rendered) is destroys


def test_clear_destroys_itself_and_earlier_entries_only() -> None:
    clears = [(_START + timedelta(hours=1), "clear-1")]

    assert destroying_history_clear(_START, clears) == "clear-1"
    assert destroying_history_clear(_START + timedelta(hours=1), clears) == "clear-1"
    assert destroying_history_clear(_START + timedelta(hours=2), clears) is None


def test_admission_survives_retention_exclusion_but_not_other_exclusions() -> None:
    assert history_entry_admitted("present", [])
    assert history_entry_admitted("absent", ["retention"])
    assert not history_entry_admitted("absent", ["window"])
    assert not history_entry_admitted("absent", ["loss", "retention"])


def _row(
    occurrence: str, at: datetime, command: str, *, destroyed_by: str | None
) -> GroundTruthOccurrence:
    conditions = [GroundTruthCondition(stage="loss", state="eligible")]
    provenance: dict = {}
    if destroyed_by is not None:
        conditions.append(
            GroundTruthCondition(
                stage="retention", state="excluded", reason=HISTORY_DESTROYED_REASON
            )
        )
        provenance = {"retention": {"destroyed_by": destroyed_by}}
    expectation = GroundTruthSourceExpectation(
        expectation_id=f"exp-{occurrence}",
        source_instance=_SOURCE,
        source_host="WEB-EXT-01",
        family="bash_history",
        format="bash_history",
        role="host",
        phase="bash_command",
        expected="absent" if destroyed_by else "present",
        reason=HISTORY_DESTROYED_REASON if destroyed_by else None,
        conditions=conditions,
        provenance=provenance,
    )
    return GroundTruthOccurrence(
        occurrence_id=occurrence,
        action_id=f"action-{occurrence}",
        intent_id=f"intent-{occurrence}",
        storyline_id="evt-test",
        section="storyline",
        kind="bash_command",
        time=at,
        facts={
            "auth": {"username": "root"},
            "shell": {"command": command, "history_effect": bash_history_effect(command)},
        },
        source_expectations=[expectation],
    )


def _clears(*rows: GroundTruthOccurrence) -> dict:
    index: dict = defaultdict(list)
    for row in rows:
        _collect_history_clear(row, index)
    return index


def test_evaluator_accepts_entries_destroyed_by_a_later_clear() -> None:
    clear = _row(
        "clear", _START + timedelta(hours=1), "shred -u /root/.bash_history", destroyed_by="clear"
    )
    entry = _row("entry", _START, "ip addr show", destroyed_by="clear")
    later = _row("later", _START + timedelta(hours=2), "id", destroyed_by=None)
    index = _clears(clear, entry, later)

    for row in (clear, entry, later):
        assert _history_retention_errors(row, row.source_expectations[0], index) == []


def test_evaluator_rejects_missing_or_unjustified_destruction() -> None:
    clear = _row(
        "clear", _START + timedelta(hours=1), "shred -u /root/.bash_history", destroyed_by="clear"
    )
    unmarked = _row("entry", _START, "ip addr show", destroyed_by=None)
    unjustified = _row("later", _START + timedelta(hours=2), "id", destroyed_by="clear")
    index = _clears(clear, unmarked, unjustified)

    assert _history_retention_errors(unmarked, unmarked.source_expectations[0], index) == [
        "invalid_retention_decision"
    ]
    assert _history_retention_errors(unjustified, unjustified.source_expectations[0], index) == [
        "invalid_retention_decision"
    ]
