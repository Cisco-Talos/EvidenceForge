"""Deferred SSH/RDP members may lack rows only at exact collection boundaries."""

from types import SimpleNamespace
from typing import Any

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.models.exceptions import EventContractError


def _dispatcher() -> EventDispatcher:
    dispatcher = EventDispatcher.__new__(EventDispatcher)
    for disposition in ("warmup", "collection", "observation"):
        setattr(
            dispatcher,
            f"_projection_is_exact_{disposition}_suppressed",
            lambda projection, disposition=disposition: projection.disposition == disposition,
        )
    return dispatcher


def _members(*dispositions: str) -> tuple[Any, ...]:
    return tuple(
        SimpleNamespace(_projection=SimpleNamespace(disposition=disposition))
        for disposition in dispositions
    )


@pytest.mark.parametrize(
    ("dispositions", "expected"),
    [
        (("visible", "visible"), set()),
        (("warmup", "warmup", "visible", "visible"), {0, 1}),
        (("visible", "visible", "collection"), {2}),
        (("warmup", "visible", "collection"), {0, 2}),
        (("visible", "observation", "visible"), {1}),
    ],
)
def test_unobserved_members_accept_boundary_runs_and_coherent_missingness(
    dispositions: tuple[str, ...], expected: set[int]
) -> None:
    members = _members(*dispositions)
    assert _dispatcher()._deferred_session_unobserved_members(members) == expected


@pytest.mark.parametrize(
    "dispositions",
    [
        ("visible", "warmup", "visible"),
        ("collection", "visible"),
        ("warmup", "visible", "collection", "visible"),
    ],
)
def test_unobserved_members_reject_suppression_away_from_its_boundary(
    dispositions: tuple[str, ...],
) -> None:
    with pytest.raises(EventContractError, match="boundary run"):
        _dispatcher()._deferred_session_unobserved_members(_members(*dispositions))
