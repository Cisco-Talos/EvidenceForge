# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native status rows retain precision when canonical work starts on whole seconds."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System


def test_native_daemon_start_rows_do_not_reveal_millisecond_delay_quantization(
    tmp_path: Path,
) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = SyslogEmitter(load_format("syslog"), tmp_path / "syslog.log", threaded=False)
    emitters = {"syslog": emitter}
    dispatcher = EventDispatcher(
        state_manager=manager,
        emitters=emitters,
        observation_policy=ObservationPolicy("enterprise_standard"),
    )
    generator = ActivityGenerator(manager, emitters, dispatcher=dispatcher)
    system = System(hostname="LINUX-01", ip="10.0.0.10", os="Ubuntu 24.04", type="server")
    try:
        for index in range(100):
            generator.generate_syslog_event(
                system,
                at + timedelta(seconds=index),
                app_name="anacron" if index % 2 else "scheduler",
                message="daemon ready",
                pid=100 + index,
            )
    finally:
        emitter.close()
    records = [
        record
        for path in tmp_path.rglob("*.log")
        for record in get_parser("syslog").parse_file(path)
    ]
    assert len(records) > 90  # Profile permits small source gaps.
    assert all(record.timestamp is not None for record in records)
    fractions = [record.timestamp.microsecond for record in records]
    assert all(0 <= value <= 250_000 for value in fractions)
    assert len({value % 1000 for value in fractions}) > 50
