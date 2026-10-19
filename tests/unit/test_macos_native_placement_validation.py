# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pending native bytes cannot silently outlive changed canonical file placement."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_macos_es_dispatch_publication import _bind, _setup


@pytest.mark.parametrize("after_bind", [False, True])
def test_changed_placement_rejects_pending_native_publication_without_closing_process(
    tmp_path: Path, after_bind: bool
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    subject = native.process.process
    record = native.executables.resolve_version(subject.executable_version.artifact_version_id)
    if after_bind:
        _bind(native, dispatcher, batch)
    native.executables.withdraw_execution_path(record, native.process.observed_at)
    before = native.owner.state.materialization_digest()
    try:
        with pytest.raises(EventContractError, match="placement"):
            if after_bind:
                dispatcher.publish_prepared_action_cohort_batch(batch)
            else:
                _bind(native, dispatcher, batch)
        assert native.owner.state.materialization_digest() == before
        assert native.owner.collectors.completed_observation(native.delivery) is None
    finally:
        dispatcher.cancel_prepared_action_cohort_batch(batch)
        if native.owner.collectors.owns_pending_delivery(native.delivery):
            native.owner.collectors.cancel(native.delivery)
        emitter.close()


def test_later_placement_change_does_not_invalidate_historical_native_snapshot(
    tmp_path: Path,
) -> None:
    native, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    subject = native.process.process
    record = native.executables.resolve_version(subject.executable_version.artifact_version_id)
    native.executables.withdraw_execution_path(
        record, native.process.observed_at + timedelta(seconds=1)
    )
    _bind(native, dispatcher, batch)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
