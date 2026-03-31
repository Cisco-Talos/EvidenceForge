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

"""Event timing models for realistic temporal distribution.

Three timing models for different event sources:
- hawkes_timestamps: Self-exciting process for human user activity (bursty)
- periodic_timestamps: Deterministic intervals for system/service traffic
- typing_cadence: Human typing rhythm for storyline intra-step events
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass


@dataclass
class HawkesState:
    """Carries Hawkes process intensity state across time windows.

    Enables cross-hour continuity: a user working intensely at 9:55
    carries momentum into the 10:00 hour instead of resetting.

    Attributes:
        last_event_time: Seconds since simulation start of last event.
        auxiliary_intensity: Sum of decayed excitations from past events.
    """

    last_event_time: float
    auxiliary_intensity: float


def hawkes_timestamps(
    num_events: int,
    duration: float,
    mu: float,
    alpha: float,
    beta: float,
    rng: random.Random,
    state: HawkesState | None = None,
    elapsed_since_last: float = 0.0,
) -> tuple[list[float], HawkesState]:
    """Generate self-exciting event timestamps using a Hawkes process.

    Uses the Lewis-Shedler thinning algorithm with exponential decay kernel.
    Events cluster naturally: each event temporarily increases the probability
    of more events nearby, producing realistic human burst-and-idle patterns.

    Args:
        num_events: Target number of events to generate.
        duration: Time window in seconds (typically 3600 for one hour).
        mu: Base intensity (events/sec when no excitation). Auto-calibrated
            by the caller: mu = num_events / duration * (1 - alpha/beta).
        alpha: Excitation strength — how much each event boosts intensity.
            Must be < beta for process stability.
        beta: Decay rate — how fast excitation fades. Higher = shorter clusters.
        rng: Seeded Random instance for reproducibility.
        state: Optional carry-over from previous time window.
        elapsed_since_last: Seconds elapsed since the last event in the
            previous window (used with state for cross-hour decay).

    Returns:
        Tuple of (offsets, new_state):
        - offsets: Sorted list of floats in [0, duration), length ≈ num_events.
        - new_state: HawkesState for carrying intensity into the next window.

    Raises:
        ValueError: If alpha >= beta (unstable process).
    """
    if alpha >= beta:
        raise ValueError(f"Hawkes process unstable: alpha ({alpha}) must be < beta ({beta})")

    if num_events <= 0:
        return [], HawkesState(last_event_time=0.0, auxiliary_intensity=0.0)

    # Initialize auxiliary intensity from carried-over state
    if state is not None and elapsed_since_last >= 0:
        aux = state.auxiliary_intensity * math.exp(-beta * elapsed_since_last)
    else:
        aux = 0.0

    offsets: list[float] = []
    t = 0.0

    # Safety: cap iterations to prevent infinite loops on degenerate params
    max_iterations = num_events * 50

    for _ in range(max_iterations):
        # Upper bound on current intensity
        lambda_star = mu + aux
        if lambda_star <= 0:
            lambda_star = mu if mu > 0 else 0.001

        # Generate candidate inter-arrival time
        u = rng.random()
        if u <= 0:
            u = 1e-10
        dt = -math.log(u) / lambda_star
        t += dt

        if t >= duration:
            break

        # Decay auxiliary intensity to current time
        aux *= math.exp(-beta * dt)

        # Compute actual intensity at candidate time
        lambda_t = mu + aux

        # Accept/reject
        if rng.random() * lambda_star <= lambda_t:
            offsets.append(t)
            aux += alpha  # Self-excitation: boost intensity

            if len(offsets) >= num_events:
                break

    # Build state for cross-window continuity
    if offsets:
        # Decay aux to the end of the window
        remaining = duration - offsets[-1]
        final_aux = aux * math.exp(-beta * remaining)
        new_state = HawkesState(
            last_event_time=offsets[-1],
            auxiliary_intensity=final_aux,
        )
    else:
        new_state = HawkesState(
            last_event_time=0.0,
            auxiliary_intensity=aux * math.exp(-beta * duration),
        )

    return offsets, new_state


def periodic_timestamps(
    interval: float,
    phase: float,
    duration: float,
    jitter_fraction: float,
    rng: random.Random,
    global_offset: float = 0.0,
) -> list[float]:
    """Generate deterministic periodic event timestamps with Gaussian jitter.

    Models system/service traffic: cron jobs, heartbeats, replication,
    monitoring polls. Produces evenly-spaced ticks with small variance.

    Args:
        interval: Base interval between events in seconds.
        phase: Phase offset in seconds (0 to interval). Determines where
            in the cycle the first tick falls. Use hash-based values for
            per-system deterministic placement.
        duration: Time window in seconds (typically 3600).
        jitter_fraction: Gaussian jitter as fraction of interval (e.g., 0.02
            for 2% jitter). Standard deviation = interval * jitter_fraction.
        rng: Seeded Random instance.
        global_offset: Seconds from simulation start to window start.
            Used to align phase across hour boundaries.

    Returns:
        Sorted list of float offsets in [0, duration).
    """
    if interval <= 0 or duration <= 0:
        return []

    offsets: list[float] = []
    stddev = interval * jitter_fraction

    # Compute first tick aligned to global phase
    cycle_position = (global_offset + phase) % interval
    t = interval - cycle_position if cycle_position > 0 else 0.0

    while t < duration:
        jittered = t + rng.gauss(0, stddev) if stddev > 0 else t
        if 0 <= jittered < duration:
            offsets.append(jittered)
        t += interval

    offsets.sort()
    return offsets


def typing_cadence(
    num_events: int,
    rng: random.Random,
    base_delay: float = 1.5,
    variance: float = 0.8,
    think_pause_prob: float = 0.15,
    think_pause_range: tuple[float, float] = (3.0, 12.0),
) -> list[float]:
    """Generate human typing rhythm offsets for storyline intra-step events.

    Models an attacker (or admin) executing a sequence of commands: quick
    bursts of typing with occasional pauses to read output or think.

    Args:
        num_events: Number of events in the step.
        rng: Seeded Random instance.
        base_delay: Mean delay between actions in seconds.
        variance: Standard deviation of the delay.
        think_pause_prob: Probability of a longer "thinking" pause after
            each action (reading output, deciding next step).
        think_pause_range: (min, max) seconds for thinking pauses.

    Returns:
        List of cumulative offsets from the first event, length num_events.
        First element is always 0.0.
    """
    if num_events <= 0:
        return []
    if num_events == 1:
        return [0.0]

    offsets = [0.0]
    cumulative = 0.0

    for _ in range(num_events - 1):
        delay = max(0.2, rng.gauss(base_delay, variance))
        if rng.random() < think_pause_prob:
            delay += rng.uniform(*think_pause_range)
        cumulative += delay
        offsets.append(cumulative)

    return offsets
