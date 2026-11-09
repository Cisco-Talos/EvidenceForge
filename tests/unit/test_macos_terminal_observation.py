# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.macos_file import MacosTerminalMetadata
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.formats.macos_endpoint_security import ESProcess
from evidenceforge.formats.macos_process_snapshot import es_process_from_observations
from tests.unit.test_macos_process_snapshot import _inputs
from tests.unit.test_macos_runtime_file_metadata import _metadata


def _terminal() -> MacosTerminalObservation:
    relationships, collection, _, _ = _inputs()
    metadata = MacosTerminalMetadata.model_validate(
        _metadata().model_dump()
        | dict(mode=0o020620, special_device=1234, file_object_id="invented-tty-1", size_bytes=0)
    )
    return MacosTerminalObservation(
        relationships.parent.process.job_control.session,
        "/dev/ttys007",
        collection.observed_at,
        metadata,
    )


@pytest.mark.parametrize("version", [6, 9, 10])
def test_session_owned_terminal_survives_complete_native_process_projection(version: int) -> None:
    relationships, collection, context, executable = _inputs()
    terminal = _terminal()
    collection = replace(collection, terminal=terminal)
    snapshot = es_process_from_observations(
        relationships, collection, context, executable, version=version
    )
    assert snapshot.tty.path == "/dev/ttys007"
    assert snapshot.tty.stat.st_mode == 0o020620
    assert snapshot.tty.stat.st_rdev == 1234
    assert snapshot.tty.stat.st_size == 0
    assert snapshot.executable.stat.st_mode == 0o100755
    assert ESProcess.model_validate_json(snapshot.model_dump_json()) == snapshot


@pytest.mark.parametrize("damage", ["sid_reuse", "host", "time", "unknown_group"])
def test_terminal_cannot_cross_session_incarnation_or_observation(damage: str) -> None:
    _, collection, _, _ = _inputs()
    terminal = _terminal()
    if damage == "sid_reuse":
        terminal = replace(
            terminal,
            session=replace(terminal.session, leader_object_id="replacement-session-leader"),
        )
    elif damage == "host":
        terminal = replace(terminal, session=replace(terminal.session, hostname="other-mac"))
    elif damage == "time":
        terminal = replace(terminal, observed_at=terminal.observed_at + timedelta(seconds=1))
    else:
        collection = replace(collection, process=replace(collection.process, job_control=None))
    with pytest.raises(ValueError, match="another session or instant"):
        replace(collection, terminal=terminal)


@pytest.mark.parametrize("path", ["/tmp/tty", "/dev/../ttys007", "/dev//ttys007", "/dev/ttys007\0"])
def test_terminal_requires_an_exact_device_placement(path: str) -> None:
    with pytest.raises(ValueError, match="device path"):
        replace(_terminal(), native_path=path)


def test_terminal_stat_cannot_be_a_regular_file_and_detaches_original_model() -> None:
    with pytest.raises(ValidationError, match="character device"):
        MacosTerminalMetadata.model_validate(_metadata().model_dump())
    terminal = _terminal()
    copy = replace(terminal)
    object.__setattr__(terminal.metadata, "special_device", 99)
    assert copy.metadata.special_device == 1234


def test_process_groups_in_the_same_session_can_share_a_terminal() -> None:
    _, collection, _, _ = _inputs()
    process = replace(
        collection.process,
        job_control=replace(
            collection.process.job_control, pgid=4567, leader_object_id="invented-other-group"
        ),
    )
    observation = MacosProcessCollectionObservation(
        process, collection.observed_at, False, _terminal()
    )
    assert observation.terminal.session == process.job_control.session
