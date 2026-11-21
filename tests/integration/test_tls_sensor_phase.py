# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""The standard mailbox network bundle owns one TLS phase for overlapping sensors."""

import json
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.models.scenario import Scenario
from tests.integration.test_dovecot_session_identity import _scenario


@pytest.mark.slow
def test_mailbox_tls_phase_is_owned_before_sensor_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _scenario("imaps").model_dump()
    sensor = data["environment"]["network"]["sensors"][0]
    sensor["name"] = sensor["hostname"] = "tap-one"
    data["environment"]["network"]["sensors"].append(
        {**sensor, "name": "tap-two", "hostname": "tap-two"}
    )
    phases: list[dict[str, Any]] = []
    original = NetworkObservationPlanner.plan

    def capture_phase(
        self: NetworkObservationPlanner, event: Any, *args: Any, **kwargs: Any
    ) -> Any:
        if (
            event.network is not None
            and event.protocol.ssl is not None
            and not event.network.application_layer_only
        ):
            phases.append(dict(event.network.phase_times))
        return original(self, event, *args, **kwargs)

    monkeypatch.setattr(NetworkObservationPlanner, "plan", capture_phase)
    GenerationEngine(
        Scenario.model_validate(data), tmp_path / "data", ground_truth_dir=tmp_path
    ).generate()
    assert phases and all("tls_detected" in phase for phase in phases)
    observations: dict[tuple[Any, ...], list[Decimal]] = defaultdict(list)
    for folder in (tmp_path / "data").iterdir():
        cp, sp = folder / "conn.json", folder / "ssl.json"
        if not cp.is_file() or not sp.is_file():
            continue
        conns = {r["uid"]: r for r in (json.loads(x) for x in cp.read_text().splitlines() if x)}
        for line in sp.read_text().splitlines():
            if not line:
                continue
            row = json.loads(line)
            conn = conns[row["uid"]]
            key = tuple(conn[k] for k in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"))
            observations[key].append(Decimal(str(row["ts"])) - Decimal(str(conn["ts"])))
    paired = [gaps for gaps in observations.values() if len(gaps) == 2]
    assert len(paired) >= 2
    assert all(abs(gaps[0] - gaps[1]) < Decimal("0.002") for gaps in paired)
