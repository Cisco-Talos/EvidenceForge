from evidenceforge.generation.activity.proxy_phase_profiles import proxy_phase_timing


def test_proxy_request_timing_avoids_narrow_exact_grid() -> None:
    timing = proxy_phase_timing()

    assert timing.request_after_connect_ms.minimum == 3
    assert timing.request_after_connect_ms.maximum == 220
