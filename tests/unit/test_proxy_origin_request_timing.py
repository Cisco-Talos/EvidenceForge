"""Proxy origin request timing is shared phase truth with safe close bounds."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.generation.actions.proxy_phase_planner import (
    ProxyPhasePlanner,
    proxy_transaction_close_bound_seconds,
)
from evidenceforge.generation.activity import proxy_phase_profiles
from tests.unit.test_proxy_close_bound_owner import _BASE_TIME, _request


@pytest.mark.parametrize("port", [80, 443])
def test_origin_http_gap_is_scoped_and_inside_lifecycle(port: int) -> None:
    request, proxy = _request(port)
    planner = ProxyPhasePlanner()
    gaps = set()
    for index in range(20):
        changed = replace(request, time=_BASE_TIME + timedelta(seconds=index))
        plan = planner.plan(changed, proxy, changed.time)
        anchor = plan.tls_complete_at or plan.origin_connect_at
        gap = (plan.origin_request_at - anchor).total_seconds()
        assert 0.002 <= gap <= 0.045
        assert plan.origin_request_at < plan.origin_close_at
        assert planner.plan(changed, proxy, changed.time) == plan
        gaps.add(gap)
    assert len(gaps) > 15


@pytest.mark.parametrize("port", [80, 443])
def test_origin_request_overlay_fits_absolute_close_bound(
    monkeypatch: pytest.MonkeyPatch, port: int
) -> None:
    profile = deepcopy(proxy_phase_profiles.load_proxy_phase_profiles())
    profile["phase_timing"]["origin_request_after_setup_ms"] = {"min": 5000, "max": 5000}
    monkeypatch.setattr(proxy_phase_profiles, "load_proxy_phase_profiles", lambda: profile)
    request, proxy = _request(port)
    plan = ProxyPhasePlanner().plan(request, proxy, request.time)
    bound = proxy_transaction_close_bound_seconds(
        origin_duration_max_seconds=0.650, origin_close_extension_seconds=0, dst_port=port
    )
    assert (plan.close_at - plan.client_connect_at).total_seconds() <= bound
    assert (plan.origin_close_at - plan.client_connect_at).total_seconds() <= bound
