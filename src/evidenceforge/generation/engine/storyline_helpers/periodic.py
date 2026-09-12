# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Storyline periodic helpers without coordinator dependencies."""

import base64
import random
import re
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.generation.actions import (
    dns_transport_close_headroom_seconds,
    network_transport_open_positive_headroom_seconds,
)
from evidenceforge.generation.activity.dns_txt import choose_background_dns_txt_record
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc


def _iter_periodic_ticks(
    start_time: datetime,
    interval_sec: float,
    duration_sec: float | None,
    count: int | None,
    jitter: float,
    rng: random.Random,
    *,
    exclusive_end_time: datetime | None = None,
) -> Iterator[datetime]:
    """Yield timestamps for periodic bulk events.

    Shared timing engine for beacon, web_scan, credential_spray, dga_queries,
    dns_tunnel, and any future periodic event types.

    Args:
        start_time: First event timestamp.
        interval_sec: Seconds between events.
        duration_sec: Total campaign length in seconds (None when using count).
        count: Exact number of events to emit (None when using duration).
        jitter: Fraction of interval to randomize (0.0–1.0).
        rng: Random number generator instance.
        exclusive_end_time: Optional scenario fence. Ticks that cannot land
            before this timestamp are not sampled; later candidates are not yielded.

    Yields:
        datetime for each tick.
    """
    t = 0.0
    emitted = 0
    end_time = start_time + timedelta(seconds=duration_sec) if duration_sec is not None else None
    exclusive_fence = ensure_utc(exclusive_end_time) if exclusive_end_time is not None else None
    if exclusive_fence is not None and ensure_utc(start_time) >= exclusive_fence:
        return
    last_tick = None
    while True:
        if duration_sec is not None and t > duration_sec:
            break
        if count is not None and emitted >= count:
            break
        earliest_tick = start_time + timedelta(seconds=max(0.0, t - jitter * interval_sec))
        if exclusive_fence is not None and ensure_utc(earliest_tick) >= exclusive_fence:
            break
        jitter_offset = rng.uniform(-jitter * interval_sec, jitter * interval_sec)
        tick_time = start_time + timedelta(seconds=max(0.0, t + jitter_offset))
        # Clamp to the inclusive campaign end (jitter can push past duration).
        if end_time is not None and tick_time > end_time:
            tick_time = end_time
        # Ensure monotonic ordering (jitter can cause inversions)
        if last_tick is not None and tick_time < last_tick:
            tick_time = last_tick + timedelta(milliseconds=1)
        if exclusive_fence is not None and ensure_utc(tick_time) >= exclusive_fence:
            break
        last_tick = tick_time
        yield tick_time
        emitted += 1
        t += interval_sec


def _iter_dns_tunnel_ticks(
    start_time: datetime,
    interval_sec: float,
    duration_sec: float | None,
    count: int | None,
    jitter: float,
    rng: random.Random,
    *,
    exclusive_end_time: datetime | None = None,
) -> Iterator[datetime]:
    """Yield DNS tunnel timestamps with transactional pauses, skips, and pacing.

    A campaign that admits no paced tick restores its owner RNG so terminal
    boundary rejection cannot perturb later storyline choices.
    """
    end_time = start_time + timedelta(seconds=duration_sec) if duration_sec is not None else None
    exclusive_fence = ensure_utc(exclusive_end_time) if exclusive_end_time is not None else None
    pause_offset = 0.0
    initial_rng_state = rng.getstate()
    admitted_any = False
    try:
        for tick_index, tick_time in enumerate(
            _iter_periodic_ticks(
                start_time,
                interval_sec,
                duration_sec,
                count,
                jitter,
                rng,
                exclusive_end_time=exclusive_fence,
            )
        ):
            if tick_index > 0 and rng.random() < 0.045:
                pause_offset += rng.uniform(interval_sec * 4.0, interval_sec * 26.0)
            if tick_index > 0 and rng.random() < 0.055:
                continue
            local_spacing = rng.expovariate(1.0 / max(interval_sec * 0.55, 0.001))
            if tick_index > 0 and rng.random() < 0.11:
                local_spacing += rng.uniform(interval_sec * 1.4, interval_sec * 6.5)
            paced_time = tick_time + timedelta(seconds=pause_offset + local_spacing)
            if end_time is not None and paced_time > end_time:
                break
            if exclusive_fence is not None and ensure_utc(paced_time) >= exclusive_fence:
                break
            admitted_any = True
            yield paced_time
    finally:
        if not admitted_any:
            rng.setstate(initial_rng_state)


def _dns_periodic_exclusive_start_fence(
    activity_generator: Any,
    *,
    window_start: datetime,
    exclusive_end_time: datetime | None,
    maximum_rtt_seconds: float,
) -> datetime | None:
    """Return the allocation-free exclusive fence for a fully rendered DNS request.

    The canonical bound composes the transport-open displacement with DNS RTT and
    teardown. The source tail uses every configured sensor route; checking both ends
    of the canonical window bounds each profile's affine clock-drift adjustment.
    """

    if exclusive_end_time is None:
        return None
    canonical_headroom = timedelta(
        seconds=(
            network_transport_open_positive_headroom_seconds()
            + dns_transport_close_headroom_seconds(
                caller_rtt_maximum=maximum_rtt_seconds,
            )
        )
    )
    exclusive_fence = ensure_utc(exclusive_end_time)
    source_tail = timedelta(0)
    network_observation_planner = getattr(
        getattr(activity_generator, "dispatcher", None),
        "network_observation_planner",
        None,
    )
    resolve_source_tail = getattr(
        network_observation_planner,
        "network_sensor_close_positive_headroom",
        None,
    )
    if callable(resolve_source_tail):
        earliest_close = min(
            ensure_utc(window_start) + canonical_headroom,
            exclusive_fence,
        )
        candidates = tuple(
            resolve_source_tail(
                canonical_time,
                protocol="udp",
                conn_state="SF",
                payload_bytes=1,
            )
            for canonical_time in (earliest_close, exclusive_fence)
        )
        if any(
            type(candidate) is not timedelta or candidate < timedelta(0) for candidate in candidates
        ):
            raise ValueError("DNS source-close planner returned an invalid positive headroom")
        source_tail = max(candidates, default=timedelta(0))
    return exclusive_fence - canonical_headroom - source_tail


def _range_or_value(value: int | list[int] | None, rng: random.Random) -> int | None:
    """Resolve a fixed byte value or [lo, hi] range."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return rng.randint(value[0], value[1])


def _beacon_token_scope(spec: Any, system: System) -> dict[str, str]:
    """Return stable per-campaign token values for beacon URI templates."""
    host_key = f"{system.hostname}:{getattr(system, 'ip', '')}"
    campaign_key = f"{spec.profile or ''}:{spec.hostname or ''}:{spec.dst_ip}:{spec.dst_port}"
    return {
        "host_id": f"{_stable_seed('beacon-host:' + host_key) & 0xFFFFFFFF:08x}",
        "campaign_id": f"{_stable_seed('beacon-campaign:' + campaign_key) & 0xFFFFFFFF:08x}",
    }


def _render_beacon_template(
    template: str,
    *,
    spec: Any,
    system: System,
    tick_index: int,
) -> str:
    """Render deterministic, synthetic-safe beacon URI template tokens."""
    scope = _beacon_token_scope(spec, system)
    rng = random.Random(
        _stable_seed(
            f"beacon-template:{system.hostname}:{spec.hostname or spec.dst_ip}:"
            f"{spec.dst_port}:{tick_index}:{template}"
        )
    )
    rendered = template.replace("{host_id}", scope["host_id"])
    rendered = rendered.replace("{campaign_id}", scope["campaign_id"])
    rendered = rendered.replace("{tick}", str(tick_index))
    while "{hex8}" in rendered:
        rendered = rendered.replace("{hex8}", f"{rng.getrandbits(32):08x}", 1)
    while "{guid}" in rendered:
        rendered = rendered.replace(
            "{guid}",
            stable_uuid(
                "beacon-guid",
                system.hostname,
                spec.hostname or spec.dst_ip,
                tick_index,
                rng.getrandbits(64),
            ),
            1,
        )

    def _base64url(match: re.Match[str]) -> str:
        length = int(match.group(1))
        raw = bytes(rng.getrandbits(8) for _ in range(max(1, length)))
        token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return token[:length]

    rendered = re.sub(r"\{base64url:(\d{1,3})\}", _base64url, rendered)
    return rendered


def _entry_value(entry: Any, field: str) -> Any:
    """Read a sequence entry field from either a Pydantic model or config dict."""
    if isinstance(entry, dict):
        return entry.get(field)
    return getattr(entry, field, None)


def _weighted_profile_entry(
    entries: list[dict[str, Any]],
    *,
    tick_index: int,
    spec: Any,
    system: System,
) -> dict[str, Any] | None:
    """Choose one profile entry using deterministic per-tick weighted selection."""
    if not entries:
        return None
    rng = random.Random(
        _stable_seed(
            f"beacon-profile-entry:{system.hostname}:{spec.profile}:"
            f"{spec.hostname or spec.dst_ip}:{tick_index}"
        )
    )
    weights = [float(entry.get("weight", 1.0) or 1.0) for entry in entries]
    return rng.choices(entries, weights=weights, k=1)[0]


def _choose_dns_tunnel_campaign_ttl(
    ttl_choices: list[tuple[int, float]],
    rng: random.Random,
) -> int:
    """Choose the dominant response TTL for one DNS tunnel campaign."""
    values = [value for value, _weight in ttl_choices]
    weights = [weight for _value, weight in ttl_choices]
    return int(rng.choices(values, weights=weights, k=1)[0])


def _choose_dns_tunnel_response_ttl(
    ttl_choices: list[tuple[int, float]],
    campaign_ttl: int,
    rng: random.Random,
) -> float:
    """Pick a source-native DNS tunnel response TTL with campaign-level skew."""
    roll = rng.random()
    if roll < 0.55:
        return float(campaign_ttl)

    near_distance = max(2, min(15, campaign_ttl or 2))
    nearby_ttls = [
        value
        for value, _weight in ttl_choices
        if value != campaign_ttl and abs(value - campaign_ttl) <= near_distance
    ]
    if roll < 0.78 and nearby_ttls:
        return float(rng.choice(nearby_ttls))

    values = [value for value, _weight in ttl_choices]
    weights = [weight for _value, weight in ttl_choices]
    return float(rng.choices(values, weights=weights, k=1)[0])


def _choose_dns_tunnel_response_template(
    templates: list[str],
    primary_template: str,
    secondary_templates: list[str],
    rng: random.Random,
) -> str:
    """Choose a DNS tunnel response template with family-level stickiness."""
    roll = rng.random()
    if roll < 0.46:
        return primary_template
    if roll < 0.82 and secondary_templates:
        return rng.choice(secondary_templates)
    return rng.choice(templates)


def _render_dns_tunnel_response_template(
    template: str,
    *,
    token: str,
    query_count: int,
    ttl: float,
    rng: random.Random,
) -> str:
    """Render a DNS tunnel TXT answer template using deterministic local values."""
    edge_hint = f"{rng.choice(('a', 'b', 'c', 'd', 'e', 'n', 'x'))}{rng.randint(1, 99)}"
    replacements = {
        "{token}": token,
        "{seq}": str(query_count),
        "{seq_hex}": f"{query_count & 0xFFFF:x}",
        "{edge}": edge_hint,
        "{ttl}": str(int(ttl)),
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered


def _dns_tunnel_extra_labels(query_count: int, rng) -> list[str]:
    """Return optional DNS tunnel labels that make query grammar less uniform."""
    roll = rng.random()
    if roll < 0.34:
        return []
    edge = f"{rng.choice(('a', 'b', 'c', 'd', 'e', 'n', 'x', 'u'))}{rng.randint(1, 99)}"
    region = rng.choice(("iad", "ord", "dfw", "sjc", "lax", "atl", "ewr"))
    if roll < 0.54:
        return [edge]
    if roll < 0.72:
        return [rng.choice(("cdn", "api", "img", "edge", "r", region)), edge]
    if roll < 0.86:
        return [f"s{query_count & 0xFFFF:x}", rng.choice(("a", "b", "r", region))]
    if roll < 0.95:
        return [edge, f"r{rng.randint(1, 12)}", rng.choice(("cdn", "cache", "svc", region))]
    return [
        rng.choice(("api", "cdn", "assets", "edge")),
        region,
        f"n{rng.randint(1, 7)}",
    ]


def _dns_tunnel_background_txt_record(rng: random.Random) -> tuple[str, str, int]:
    """Return a benign TXT query/answer that can collide with tunnel-era DNS."""
    return choose_background_dns_txt_record(rng)
