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

"""Strict live-owner proofs for binary-bearing deferred transports."""

from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatch
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_rdp_deferred_production import (
    _START,
    _open_rdp_terminal_harness,
)


class _TransportOwnerProofObservedError(RuntimeError):
    """Stop the real fixture immediately after the dispatcher proof boundary."""


TransportProbe = Callable[[EventDispatcher, PreparedDispatch, object], None]


def _clone_prepared(
    prepared: PreparedDispatch,
    occurrence: CanonicalOccurrence,
) -> PreparedDispatch:
    """Copy only the inert carrier fields needed to exercise owner validation."""

    return PreparedDispatch(
        occurrence=occurrence,
        projection=prepared._projection,
        expected_state_version=prepared._expected_state_version,
        state_intent=prepared._state_intent,
        lifecycle_ticket=prepared._lifecycle_ticket,
        binary_identity_kind=prepared._binary_identity_kind,
        artifact_publications=prepared._artifact_publications,
        source_timing_preparation=prepared._source_timing_preparation,
        authored_intent_id=prepared._authored_intent_id,
        integrity_token=prepared._integrity_token,
    )


def _exercise_transport_owner_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe: TransportProbe,
) -> None:
    """Reach the real compiled-Sysmon RDP transport before State materialization."""

    original = EventDispatcher._validate_deferred_session_transport_binary_owner
    observed = False

    def inspect(
        owner: EventDispatcher,
        prepared: PreparedDispatch,
        root: object,
    ) -> None:
        nonlocal observed
        original(owner, prepared, root)
        probe(owner, prepared, root)
        observed = True
        raise _TransportOwnerProofObservedError("transport owner proof observed")

    monkeypatch.setattr(
        EventDispatcher,
        "_validate_deferred_session_transport_binary_owner",
        inspect,
    )
    with pytest.raises(_TransportOwnerProofObservedError, match="transport owner proof observed"):
        _open_rdp_terminal_harness(
            tmp_path,
            clock_profile_name="enterprise_standard",
            output_start_time=_START - timedelta(minutes=1),
            include_sysmon=True,
            include_sysmon_during_open=True,
            modeled_target_pid4=True,
            modeled_source_pid4=True,
            production_timing_runtime=True,
            source_process_lead_seconds=20.0,
        )
    assert observed


def test_binary_transport_accepts_exact_live_root_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real interned binary and authenticated root activity owner are admitted."""

    _exercise_transport_owner_probe(tmp_path, monkeypatch, lambda *_args: None)


def test_binary_transport_rejects_value_equal_binary_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An equal but non-interned binary descriptor cannot replace registry truth."""

    def probe(owner: EventDispatcher, prepared: PreparedDispatch, root: object) -> None:
        process = prepared._occurrence.process
        assert process is not None and process.binary_identity is not None
        copied_binary = replace(process.binary_identity)
        assert copied_binary == process.binary_identity
        assert copied_binary is not process.binary_identity
        occurrence = replace(
            prepared._occurrence,
            process=replace(process, binary_identity=copied_binary),
        )
        with pytest.raises(EventContractError, match="exact live root-owned process"):
            owner._validate_deferred_session_transport_binary_owner(
                _clone_prepared(prepared, occurrence),
                root,
            )

    _exercise_transport_owner_probe(tmp_path, monkeypatch, probe)


def test_binary_transport_rejects_foreign_process_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign actor cannot authenticate by copying the live process values."""

    def probe(owner: EventDispatcher, prepared: PreparedDispatch, root: object) -> None:
        identity_plan = prepared._occurrence.identity_plan
        assert type(identity_plan) is EventIdentityPlan
        actor = identity_plan.actor
        assert type(actor) is ProcessIdentity
        foreign_object_id = f"{actor.object_id}-foreign"
        foreign = replace(
            actor,
            object_id=foreign_object_id,
            primary_thread=(
                replace(actor.primary_thread, process_object_id=foreign_object_id)
                if actor.primary_thread is not None
                else None
            ),
        )
        occurrence = replace(
            prepared._occurrence,
            identity_plan=replace(identity_plan, actor=foreign),
        )
        with pytest.raises(EventContractError, match="exact live root-owned process"):
            owner._validate_deferred_session_transport_binary_owner(
                _clone_prepared(prepared, occurrence),
                root,
            )

    _exercise_transport_owner_probe(tmp_path, monkeypatch, probe)


def test_binary_transport_rejects_foreign_source_hostname_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A host outside the exact short-name/FQDN pair cannot borrow the root actor."""

    def probe(owner: EventDispatcher, prepared: PreparedDispatch, root: object) -> None:
        host = prepared._occurrence.src_host
        assert host is not None
        occurrence = replace(
            prepared._occurrence,
            src_host=replace(
                host,
                hostname=f"{host.hostname}-foreign",
                fqdn=f"{host.fqdn or host.hostname}.foreign.test",
            ),
        )
        with pytest.raises(EventContractError, match="exact live root-owned process"):
            owner._validate_deferred_session_transport_binary_owner(
                _clone_prepared(prepared, occurrence),
                root,
            )

    _exercise_transport_owner_probe(tmp_path, monkeypatch, probe)


def test_binary_transport_rejects_actor_missing_from_live_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authenticated root snapshot cannot revive a process absent from live State."""

    def probe(owner: EventDispatcher, prepared: PreparedDispatch, root: object) -> None:
        with monkeypatch.context() as fault:
            fault.setattr(owner.state_manager, "get_process", lambda *_args: None)
            with pytest.raises(EventContractError, match="exact live root-owned process"):
                owner._validate_deferred_session_transport_binary_owner(prepared, root)

    _exercise_transport_owner_probe(tmp_path, monkeypatch, probe)
