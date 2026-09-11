# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact Windows Security projection at the deferred RDP publication boundary."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from time import perf_counter

import pytest
from jinja2.environment import Environment, Template

import evidenceforge.generation.emitters.windows as windows_emitter_module
from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.collection_policy import (
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.dispatcher import DeferredSessionExactTargetProof
from evidenceforge.events.observation import ObservationDecision, ObservationPolicy
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG
from evidenceforge.formats import load_format
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.deferred_session_composition import DeferredSessionKind
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    LogEmitter,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import (
    WindowsEventEmitter,
    _render_windows_exact_projection,
    _spool_decode,
)
from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id
from evidenceforge.generation.source_finalization import (
    SourceFinalizationCoordinator,
    SourceFinalizationError,
)
from evidenceforge.models.exceptions import EventContractError
from evidenceforge.output_targets import OutputTarget
from tests.unit.test_deferred_session_composition import (
    _START,
    _assert_deferred_dispatcher_reservations_released,
    _cancel_unmaterialized_publication,
    _foundation_publication_fixture,
    _PublicationFixture,
)

pytestmark = pytest.mark.slow


class _WindowsSubclass(WindowsEventEmitter):
    """Concrete-type impostor that repeats the public marker."""

    supports_exact_projection_publication = True


class _DuckMarkerEcarEmitter(EcarEmitter):
    """Wrong concrete type whose marker descriptor must never execute."""

    marker_reads = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        type(self).marker_reads += 1
        raise AssertionError("duck marker descriptor executed")


class _DropWindowsPolicy(ObservationPolicy):
    """Make only Windows Security invisible while retaining transport evidence."""

    def decide(
        self,
        format_name: str,
        event: CanonicalOccurrence,
    ) -> ObservationDecision:
        if format_name == "windows_event_security":
            return ObservationDecision(status="dropped")
        return super().decide(format_name, event)


class _CallbackDict(dict[str, object]):
    """Instance state impostor whose mapping callback must never execute."""

    get_reads = 0

    def get(self, key: object, default: object = None) -> object:
        type(self).get_reads += 1
        return super().get(key, default)


def _authority() -> ExactPublicationAuthority:
    return ExactPublicationAuthority(
        capacity=1,
        row_capacity=64,
        byte_capacity=8 * 1024 * 1024,
    )


def _source(format_name: str, hostname: str) -> SourceInstanceDeployment:
    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=exact_source_instance_id(descriptor.family, hostname),
            hostname=hostname,
            family=descriptor.family,
        ),
        formats=(format_name,),
        policy=SourceCollectionPolicy(capabilities=descriptor.capabilities),
    )


def _compiled_deployment() -> CompiledCollectionDeployment:
    return CompiledCollectionDeployment(
        (
            _source("ecar", "WS-01"),
            _source("ecar", "DB-01"),
            _source("windows_event_security", "DB-01"),
        )
    )


def _windows_emitter(
    root: Path,
    *,
    threaded: bool = False,
    direct: bool = False,
    source_finalization: bool = True,
    format_name: str = "windows_event_security",
) -> WindowsEventEmitter:
    output = root / "windows.xml" if direct else root
    return WindowsEventEmitter(
        load_format(format_name),
        output,
        threaded=threaded,
        source_finalization=source_finalization,
    )


def _prepared_record(publication: _PublicationFixture) -> object:
    records = tuple(publication.dispatcher._deferred_session_publication_batches.values())
    assert len(records) == 1
    return records[0]


def _windows_payloads(publication: _PublicationFixture) -> tuple[str, ...]:
    record = _prepared_record(publication)
    exact_batch = record.exact_publication_batch
    assert exact_batch is not None
    rows = exact_batch._prepared_rows
    assert rows is not None
    proofs = tuple(
        proof
        for proof in record.prepared_target_proofs
        if proof.format_name == "windows_event_security"
    )
    assert len(proofs) == 1
    proof = proofs[0]
    return tuple(row.frozen_content for row in rows[proof.row_start : proof.row_end])


def _materialize(publication: _PublicationFixture) -> object:
    assert publication.batch is not None
    return publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )


def _finish_sources(
    publication: _PublicationFixture,
    windows: WindowsEventEmitter,
) -> SourceFinalizationCoordinator:
    publication.dispatcher.drain_exact_projection_recoveries()
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()
    return coordinator


def _assert_windows_zero(windows: WindowsEventEmitter) -> None:
    exact = windows.exact_candidate_census()
    assert (
        exact.current_rows,
        exact.current_bytes,
        exact.current_participants,
        exact.released_rows,
        exact.released_bytes,
        exact.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)
    source = windows.source_finalization_census()
    assert (
        source.candidate_rows,
        source.candidate_bytes,
        source.final_rows,
        source.final_bytes,
        source.routes,
    ) == (0, 0, 0, 0, 0)


def _close_failed_fixture(
    publication: _PublicationFixture,
    extra: LogEmitter,
) -> None:
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    extra.close()


def _output_bytes(root: Path, target: OutputTarget, *, direct: bool = False) -> bytes:
    if target is OutputTarget.SOF_ELK:
        filename = "windows_event_security_snare.log"
    elif direct:
        filename = "windows.xml"
    else:
        filename = "windows_event_security.xml"
    paths = tuple(root.rglob(filename))
    assert len(paths) == 1
    return paths[0].read_bytes()


def _ordinary_windows_event(ordinal: int) -> dict[str, object]:
    """Return one ordinary engine-owned row outside an exact batch attempt."""

    timestamp = _START.replace(microsecond=10_000 + ordinal)
    return {
        "EventID": 4624,
        "TimeCreated": timestamp,
        "Computer": "db-01.example.test",
        "Channel": "Security",
        "Level": 0,
        "ExecutionProcessID": 4,
        "ExecutionThreadID": 100 + ordinal,
        "TargetUserName": f"ordinary-{ordinal}",
        "TargetDomainName": "EXAMPLE",
        "TargetLogonId": f"0x{ordinal + 0x1000:x}",
        "LogonType": 2,
        "WorkstationName": "DB-01",
        "IpAddress": "10.0.0.20",
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
    }


def test_windows_deferred_capability_remains_concrete_and_sysmon_closed() -> None:
    """Only the concrete Security class owns the new deferred-source marker."""

    assert WindowsEventEmitter.__dict__["supports_exact_projection_publication"] is True
    assert SysmonEventEmitter.__dict__.get("supports_exact_projection_publication") is not True
    assert _WindowsSubclass.__dict__["supports_exact_projection_publication"] is True


def test_real_rdp_4624_prepare_binds_candidate_bytes_and_cancel_is_neutral(
    tmp_path: Path,
) -> None:
    """A real RDP logon reserves one byte-authenticated 4624 before State mutation."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()
    payloads = _windows_payloads(publication)
    assert len(payloads) == 1
    candidate = _spool_decode(payloads[0])
    assert candidate["EventID"] == 4624
    assert type(candidate["TimeCreated"]) is datetime

    record = _prepared_record(publication)
    proof = next(
        proof
        for proof in record.prepared_target_proofs
        if proof.format_name == "windows_event_security"
    )
    assert proof.windows_ordering_facts == (
        (
            4624,
            candidate["TimeCreated"].isoformat(),
            hashlib.sha256(payloads[0].encode("utf-8")).hexdigest(),
            len(payloads[0].encode("utf-8")),
        ),
    )
    exact = windows.exact_candidate_census()
    assert (exact.current_rows, exact.current_bytes, exact.current_participants) == (
        1,
        len(payloads[0].encode("utf-8")),
        1,
    )
    assert not windows_root.exists()

    assert publication.batch is not None
    assert publication.dispatcher.cancel_prepared_deferred_session_publication_batch(
        publication.batch
    )
    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_elevated_rdp_proof_strictly_orders_4624_before_4672(
    tmp_path: Path,
) -> None:
    """The multirow Windows proof binds source-native IDs, times, and candidate bytes."""

    windows = _windows_emitter(tmp_path / "windows")
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        rdp_elevated=True,
    )
    payloads = _windows_payloads(publication)
    candidates = tuple(_spool_decode(payload) for payload in payloads)
    assert tuple(candidate["EventID"] for candidate in candidates) == (4624, 4672)
    assert candidates[0]["TimeCreated"] < candidates[1]["TimeCreated"]

    record = _prepared_record(publication)
    proof = next(
        proof
        for proof in record.prepared_target_proofs
        if proof.format_name == "windows_event_security"
    )
    assert proof.windows_ordering_facts == tuple(
        (
            candidate["EventID"],
            candidate["TimeCreated"].isoformat(),
            hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            len(payload.encode("utf-8")),
        )
        for payload, candidate in zip(payloads, candidates, strict=True)
    )

    assert publication.batch is not None
    assert publication.dispatcher.cancel_prepared_deferred_session_publication_batch(
        publication.batch
    )
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


@pytest.mark.parametrize(
    "case",
    (
        "wrong-type",
        "subclass",
        "duck-marker",
        "source-finalization-false",
        "wrong-format",
        "format-swap",
        "builtin-copy",
    ),
)
def test_windows_allowlist_rejects_impostors_before_state_or_render(
    tmp_path: Path,
    case: str,
) -> None:
    """Type, format, class marker, and journal checks fail before any public write."""

    output = tmp_path / case
    if case == "wrong-type":
        emitter: LogEmitter = EcarEmitter(load_format("ecar"), output)
    elif case == "subclass":
        emitter = _WindowsSubclass(
            load_format("windows_event_security"),
            output,
            source_finalization=True,
        )
    elif case == "duck-marker":
        _DuckMarkerEcarEmitter.marker_reads = 0
        emitter = _DuckMarkerEcarEmitter(load_format("ecar"), output)
    elif case == "source-finalization-false":
        emitter = _windows_emitter(output, source_finalization=False)
    elif case == "wrong-format":
        emitter = _windows_emitter(output, format_name="ecar")
    elif case == "format-swap":
        emitter = _windows_emitter(output)
        emitter.format_def = load_format("ecar")
    else:
        emitter = WindowsEventEmitter(
            load_format("windows_event_security").model_copy(deep=True),
            output,
            source_finalization=True,
        )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": emitter},
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()
    before_timing = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert publication.fixture.timing_planner.state_digest() == before_timing
    assert not output.exists()
    assert _DuckMarkerEcarEmitter.marker_reads == 0
    if isinstance(emitter, WindowsEventEmitter):
        _assert_windows_zero(emitter)
    _close_failed_fixture(publication, emitter)


def test_windows_allowlist_rejects_mutated_builtin_format_snapshot(
    tmp_path: Path,
) -> None:
    """Cached built-in model mutation cannot rewrite constructor-bound source truth."""

    output = tmp_path / "mutated-format"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    format_definition = windows.format_def
    original_name = format_definition.name
    original_footer = format_definition.output.footer_template
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()
    try:
        format_definition.name = "ecar"
        format_definition.output.footer_template = "<NOT-THE-BUILTIN-SECURITY-FOOTER/>"
        with pytest.raises(EventContractError, match="lacks exact projection publication"):
            publication.dispatcher.prepare_deferred_session_publication_batch(
                publication.composition,
                publication.fixture.coordinator,
            )
    finally:
        format_definition.name = original_name
        format_definition.output.footer_template = original_footer

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_allowlist_rejects_preconstructor_cached_builtin_mutation(
    tmp_path: Path,
) -> None:
    """The authoritative built-in snapshot is independent of the mutable loader cache."""

    output = tmp_path / "preconstructor-format"
    format_definition = load_format("windows_event_security")
    original_name = format_definition.name
    original_footer = format_definition.output.footer_template
    try:
        format_definition.name = "ecar"
        format_definition.output.footer_template = "<FORGED-BEFORE-CONSTRUCTION/>"
        windows = _windows_emitter(output)
    finally:
        format_definition.name = original_name
        format_definition.output.footer_template = original_footer
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_allowlist_rejects_false_to_true_finalization_toggle(
    tmp_path: Path,
) -> None:
    """A mutable operational flag cannot forge the closure-held constructor binding."""

    output = tmp_path / "finalization-toggle"
    windows = _windows_emitter(output, source_finalization=False)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()
    windows._source_finalization_bound = True
    try:
        with pytest.raises(EventContractError, match="lacks exact projection publication"):
            publication.dispatcher.prepare_deferred_session_publication_batch(
                publication.composition,
                publication.fixture.coordinator,
            )
    finally:
        windows._source_finalization_bound = False

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_precommit_reauthenticates_format_after_prepare(
    tmp_path: Path,
) -> None:
    """A format mutation between prepare and canonical commit fails before State."""

    output = tmp_path / "precommit-format"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()
    format_definition = windows.format_def
    original_footer = format_definition.output.footer_template
    try:
        format_definition.output.footer_template = "<FORGED-BEFORE-PRECOMMIT/>"
        with pytest.raises(
            EventContractError,
            match="lacks exact projection publication|precommit source batch",
        ):
            _materialize(publication)
    finally:
        format_definition.output.footer_template = original_footer

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not output.exists()
    _cancel_unmaterialized_publication(publication)
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    windows.close()


def test_windows_allowlist_rejects_dict_subclass_without_get_callback(
    tmp_path: Path,
) -> None:
    """Raw instance state must be one exact dict before any mapping method executes."""

    output = tmp_path / "callback-state"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    original_state = windows.__dict__
    _CallbackDict.get_reads = 0
    windows.__dict__ = _CallbackDict(original_state)
    try:
        with pytest.raises(EventContractError, match="lacks exact projection publication"):
            publication.dispatcher.prepare_deferred_session_publication_batch(
                publication.composition,
                publication.fixture.coordinator,
            )
    finally:
        windows.__dict__ = original_state

    assert _CallbackDict.get_reads == 0
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_allowlist_ignores_compiled_template_identity_swap(
    tmp_path: Path,
) -> None:
    """The instance renderer is outside the constructor-bound exact contract."""

    output = tmp_path / "template-swap"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    original_template = windows._template
    windows._template = object()
    try:
        batch = publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )
        assert publication.dispatcher.cancel_prepared_deferred_session_publication_batch(batch)
    finally:
        windows._template = original_template

    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


@pytest.mark.parametrize("mutation", ("cycle", "nested-dict-subclass"))
def test_windows_allowlist_rejects_malformed_format_graph_without_callbacks(
    tmp_path: Path,
    mutation: str,
) -> None:
    """Cyclic or callback-bearing nested format state fails within a bounded walk."""

    output = tmp_path / mutation
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    format_definition = windows.format_def
    original_validators = format_definition.validators
    _CallbackDict.get_reads = 0
    if mutation == "cycle":
        cyclic: list[object] = []
        cyclic.append(cyclic)
        format_definition.validators = cyclic
    else:
        format_definition.validators = [_CallbackDict({"and": []})]
    try:
        with pytest.raises(EventContractError, match="lacks exact projection publication"):
            publication.dispatcher.prepare_deferred_session_publication_batch(
                publication.composition,
                publication.fixture.coordinator,
            )
    finally:
        format_definition.validators = original_validators

    assert _CallbackDict.get_reads == 0
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_proof_must_match_actual_prepared_candidate_facts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shape-valid proof digest and size changes fail against retained candidate bytes."""

    output = tmp_path / "proof-mismatch"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    original_freeze = publication.dispatcher._freeze_deferred_session_exact_projection

    def tamper_proof(
        dispatches: tuple[object, ...],
    ) -> tuple[
        tuple[tuple[tuple[str, str], ...], ...], tuple[DeferredSessionExactTargetProof, ...]
    ]:
        identifiers, proofs = original_freeze(dispatches)
        changed = list(proofs)
        proof_index = next(
            index
            for index, proof in enumerate(changed)
            if proof.format_name == "windows_event_security"
        )
        proof = changed[proof_index]
        event_id, raw_time, _digest, retained_bytes = proof.windows_ordering_facts[0]
        changed[proof_index] = replace(
            proof,
            windows_ordering_facts=(
                (
                    event_id,
                    raw_time,
                    "0" * 64,
                    retained_bytes + 1,
                ),
            ),
        )
        return identifiers, tuple(changed)

    monkeypatch.setattr(
        publication.dispatcher,
        "_freeze_deferred_session_exact_projection",
        tamper_proof,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="prepared bytes"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not output.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_constructor_finalization_truth_survives_true_to_false_toggle(
    tmp_path: Path,
) -> None:
    """A post-prepare field mutation cannot divert an exact row into legacy close."""

    output = tmp_path / "true-to-false"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    windows._source_finalization_bound = False
    try:
        result = _materialize(publication)
        assert all(outcome.status == "succeeded" for outcome in result.publication.projections)
        coordinator = _finish_sources(publication, windows)
    finally:
        windows._source_finalization_bound = True

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    assert windows.source_finalization_census().state == "closed"
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_terminal_publication_uses_constructor_bound_footer(
    tmp_path: Path,
) -> None:
    """A postcommit cached-format mutation cannot change terminal source bytes."""

    output = tmp_path / "terminal-format"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    format_definition = windows.format_def
    original_footer = format_definition.output.footer_template
    try:
        format_definition.output.footer_template = "<FORGED-AFTER-EXACT-COMMIT/>"
        coordinator = _finish_sources(publication, windows)
    finally:
        format_definition.output.footer_template = original_footer

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert "FORGED-AFTER-EXACT-COMMIT" not in rendered
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert rendered.rstrip().endswith("</Events>")
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_terminal_ignores_instance_renderer_swap_before_quiescence(
    tmp_path: Path,
) -> None:
    """Terminal exact rows render through the closure after an instance swap."""

    output = tmp_path / "terminal-template"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    original_template = windows._template
    windows._template = object()
    try:
        coordinator.finalize()
        windows.close()
    finally:
        windows._template = original_template

    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_terminal_uses_closure_renderer_after_root_function_mutation(
    tmp_path: Path,
) -> None:
    """Instance Jinja graph mutation cannot execute or forge terminal exact XML."""

    output = tmp_path / "root-render-function"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    original_root_render = windows._template.root_render_func
    callback_reads = 0

    def forged_root_render(_context: object) -> Iterator[str]:
        nonlocal callback_reads
        callback_reads += 1
        yield "<FORGED-ROOT-RENDER/>"

    windows._template.root_render_func = forged_root_render
    try:
        coordinator = _finish_sources(publication, windows)
    finally:
        windows._template.root_render_func = original_root_render

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert callback_reads == 0
    assert "FORGED-ROOT-RENDER" not in rendered
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_canonical_renderer_closure_retains_only_immutable_source(
    tmp_path: Path,
) -> None:
    """No reusable Jinja renderer reachable from the closure can forge exact XML."""

    output = tmp_path / "closure-renderer"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    closure = _render_windows_exact_projection.__closure__ or ()
    retained = tuple(cell.cell_contents for cell in closure)
    retained_templates = tuple(item for item in retained if isinstance(item, Template))
    callback_reads = 0
    original_root_functions: list[tuple[Template, object]] = []

    def forged_root_render(_context: object) -> Iterator[str]:
        nonlocal callback_reads
        callback_reads += 1
        yield "<FORGED-CLOSURE-RENDER/>"

    for template in retained_templates:
        original_root_functions.append((template, template.root_render_func))
        template.root_render_func = forged_root_render
    try:
        coordinator = _finish_sources(publication, windows)
    finally:
        for template, original_root_render in original_root_functions:
            template.root_render_func = original_root_render

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert retained and all(type(item) is str for item in retained)
    assert not any(isinstance(item, (Environment, Template)) for item in retained)
    assert callback_reads == 0
    assert "FORGED-CLOSURE-RENDER" not in rendered
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


@pytest.mark.parametrize("threaded", (False, True), ids=("sync", "threaded"))
@pytest.mark.parametrize("direct", (False, True), ids=("per-host", "direct"))
def test_windows_mixed_terminal_routes_only_exact_candidate_to_hardened_renderer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    threaded: bool,
    direct: bool,
) -> None:
    """The durable exact marker selects hardening without slowing ordinary rows."""

    output = tmp_path / "mixed-routing"
    windows = _windows_emitter(output, threaded=threaded, direct=direct)
    ordinary_rows = 12
    for ordinal in range(ordinary_rows):
        windows.emit_event(_ordinary_windows_event(ordinal))
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()

    hardened_calls = 0
    ordinary_calls = 0
    hardened_render = windows_emitter_module._render_windows_exact_projection
    ordinary_render = windows._template.render

    def count_hardened(event_data: dict[str, object]) -> str:
        nonlocal hardened_calls
        hardened_calls += 1
        return hardened_render(event_data)

    def count_ordinary(**event_data: object) -> str:
        nonlocal ordinary_calls
        ordinary_calls += 1
        return ordinary_render(**event_data)

    monkeypatch.setattr(
        windows_emitter_module,
        "_render_windows_exact_projection",
        count_hardened,
    )
    monkeypatch.setattr(windows._template, "render", count_ordinary)
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT, direct=direct).decode("utf-8")
    assert hardened_calls == 1
    assert ordinary_calls == ordinary_rows
    assert rendered.count("<EventID>4624</EventID>") == ordinary_rows + 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_ordinary_terminal_throughput_stays_near_precompiled_baseline(
    tmp_path: Path,
) -> None:
    """Terminal ownership must not compile one fresh Jinja graph per ordinary row."""

    row_count = 300
    baseline_root = tmp_path / "baseline-throughput"
    baseline = _windows_emitter(baseline_root, source_finalization=False)
    for ordinal in range(row_count):
        baseline.emit_event(_ordinary_windows_event(ordinal))
    baseline_started = perf_counter()
    baseline.close()
    baseline_elapsed = perf_counter() - baseline_started

    terminal_root = tmp_path / "terminal-throughput"
    terminal = _windows_emitter(terminal_root)
    for ordinal in range(row_count):
        terminal.emit_event(_ordinary_windows_event(ordinal))
    terminal_authority = ExactPublicationAuthority(
        capacity=1,
        row_capacity=512,
        byte_capacity=20 * 1024 * 1024,
    )
    coordinator = SourceFinalizationCoordinator((terminal,), terminal_authority)
    terminal_started = perf_counter()
    coordinator.finalize()
    terminal.close()
    coordinator.mark_closed()
    terminal_elapsed = perf_counter() - terminal_started

    assert _output_bytes(terminal_root, OutputTarget.DEFAULT) == _output_bytes(
        baseline_root,
        OutputTarget.DEFAULT,
    )
    assert terminal_elapsed <= max(2.0, baseline_elapsed * 10)
    assert coordinator.complete
    _assert_windows_zero(terminal)


@pytest.mark.parametrize(
    ("candidate_kind", "forged_route_kind"),
    (
        ("exact", None),
        ("exact", "forged-route"),
        ("ordinary", "exact-candidate-v1"),
        ("ordinary", "forged-route"),
    ),
)
def test_windows_candidate_route_kind_tamper_fails_closed_and_retries(
    tmp_path: Path,
    candidate_kind: str,
    forged_route_kind: str | None,
) -> None:
    """Marker removal, injection, or substitution cannot select a renderer."""

    output = tmp_path / f"route-{candidate_kind}-{forged_route_kind}"
    windows = _windows_emitter(output)
    publication: _PublicationFixture | None = None
    original_route_kind: str | None = None
    if candidate_kind == "exact":
        publication = _foundation_publication_fixture(
            DeferredSessionKind.RDP,
            tmp_path,
            extra_emitters={"windows_event_security": windows},
        )
        _materialize(publication)
        publication.dispatcher.drain_exact_projection_recoveries()
        original_route_kind = "exact-candidate-v1"
    else:
        windows.emit_event(_ordinary_windows_event(0))

    windows.quiesce_source_finalization()
    with windows._file_lock:
        assert windows._spool_conn is not None
        windows._spool_conn.execute(
            "UPDATE events SET route_kind = ? WHERE phase = ?",
            (forged_route_kind, "candidate"),
        )
        windows._spool_conn.commit()
    coordinator = SourceFinalizationCoordinator((windows,), _authority())

    with pytest.raises(
        (ExactPublicationError, SourceFinalizationError),
        match="receipt|metadata|route",
    ):
        coordinator.finalize()

    assert windows.source_finalization_census().state == "quiesced"
    assert not output.exists()
    with windows._file_lock:
        assert windows._spool_conn is not None
        windows._spool_conn.execute(
            "UPDATE events SET route_kind = ? WHERE phase = ?",
            (original_route_kind, "candidate"),
        )
        windows._spool_conn.commit()
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    if publication is not None:
        publication.ecar.close()
        publication.zeek.close()
        _assert_deferred_dispatcher_reservations_released(publication.dispatcher)

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)


def test_windows_ordinary_renderer_callback_cannot_rewrite_later_exact_candidate(
    tmp_path: Path,
) -> None:
    """A mixed ordinary row cannot invalidate the exact row's post-fixup binding."""

    output = tmp_path / "mixed-callback-tamper"
    windows = _windows_emitter(output)
    windows.emit_event(_ordinary_windows_event(0))
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    original_root_render = windows._template.root_render_func
    tampered = False

    def tamper_later_exact_candidate(context: object) -> Iterator[str]:
        nonlocal tampered
        if not tampered:
            tampered = True
            assert windows._spool_conn is not None
            windows._spool_conn.execute(
                """UPDATE events
                   SET payload = REPLACE(payload, '"value": 4624', '"value": 4625')
                   WHERE phase = ? AND route_kind = ?""",
                ("candidate", "exact-candidate-v1"),
            )
        yield from original_root_render(context)

    windows._template.root_render_func = tamper_later_exact_candidate
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    try:
        with pytest.raises(
            (ExactPublicationError, SourceFinalizationError),
            match="binding|changed|metadata",
        ):
            coordinator.finalize()
    finally:
        windows._template.root_render_func = original_root_render

    assert tampered
    assert windows.source_finalization_census().state == "quiesced"
    assert not output.exists()
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert rendered.count("<EventID>4624</EventID>") == 2
    assert "<EventID>4625</EventID>" not in rendered
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_later_ordinary_callback_cannot_rewrite_frozen_exact_row(
    tmp_path: Path,
) -> None:
    """A later ordinary render cannot replace an already-rendered exact row."""

    output = tmp_path / "mixed-final-tamper"
    windows = _windows_emitter(output)
    ordinary = _ordinary_windows_event(0)
    ordinary["TimeCreated"] = _START + timedelta(seconds=10)
    windows.emit_event(ordinary)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    original_root_render = windows._template.root_render_func
    tampered = False

    def tamper_prior_exact_final(context: object) -> Iterator[str]:
        nonlocal tampered
        if not tampered:
            tampered = True
            assert windows._spool_conn is not None
            row = windows._spool_conn.execute(
                """SELECT sequence, payload FROM events
                   WHERE phase = ? ORDER BY ordinal LIMIT 1""",
                ("final",),
            ).fetchone()
            assert row is not None
            forged = str(row[1]).replace("<EventID>4624</EventID>", "<EventID>4625</EventID>")
            assert forged != row[1]
            windows._spool_conn.execute(
                """UPDATE events
                   SET payload = ?, payload_bytes = ?, payload_digest = ?
                   WHERE sequence = ? AND phase = ?""",
                (
                    forged,
                    len(forged.encode("utf-8")),
                    hashlib.sha256(forged.encode("utf-8")).hexdigest(),
                    row[0],
                    "final",
                ),
            )
        yield from original_root_render(context)

    windows._template.root_render_func = tamper_prior_exact_final
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    try:
        with pytest.raises(
            (ExactPublicationError, SourceFinalizationError),
            match="binding|changed|metadata",
        ):
            coordinator.finalize()
    finally:
        windows._template.root_render_func = original_root_render

    assert tampered
    assert windows.source_finalization_census().state == "quiesced"
    assert not output.exists()
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert rendered.count("<EventID>4624</EventID>") == 2
    assert "<EventID>4625</EventID>" not in rendered
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_terminal_ignores_header_footer_field_mutation_after_quiescence(
    tmp_path: Path,
) -> None:
    """Quiesced exact framing comes directly from the closure at every side effect."""

    output = tmp_path / "quiesced-framing"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    windows.quiesce_source_finalization()
    windows._source_finalization_header = "<FORGED-QUIESCED-HEADER/>"
    windows._source_finalization_footer = "<FORGED-QUIESCED-FOOTER/>"
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert "FORGED-QUIESCED" not in rendered
    assert rendered.startswith('<?xml version="1.0" encoding="utf-8"?>\n<Events>')
    assert rendered.rstrip().endswith("</Events>")
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_windows_terminal_ignores_footer_field_mutation_after_publication(
    tmp_path: Path,
) -> None:
    """Published exact rows cannot acquire a forged footer during terminal close."""

    output = tmp_path / "published-framing"
    windows = _windows_emitter(output)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    coordinator.finalize()
    windows._source_finalization_header = "<FORGED-PUBLISHED-HEADER/>"
    windows._source_finalization_footer = "<FORGED-PUBLISHED-FOOTER/>"
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    rendered = _output_bytes(output, OutputTarget.DEFAULT).decode("utf-8")
    assert "FORGED-PUBLISHED" not in rendered
    assert rendered.rstrip().endswith("</Events>")
    assert rendered.count("<EventID>4624</EventID>") == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_suppressed_deferred_members_fail_before_state_and_candidate_admission(
    tmp_path: Path,
) -> None:
    """A wholly out-of-window RDP sequence cannot commit without positive evidence."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        output_end_time=_START,
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="positive exact target"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not windows_root.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_dropped_windows_target_is_neutral_while_transport_remains_exact(
    tmp_path: Path,
) -> None:
    """A policy-suppressed Security source creates no candidate or false proof."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        observation_policy=_DropWindowsPolicy(),
    )
    record = _prepared_record(publication)
    assert not any(
        proof.format_name == "windows_event_security" for proof in record.prepared_target_proofs
    )
    _assert_windows_zero(windows)
    assert publication.batch is not None
    assert publication.dispatcher.cancel_prepared_deferred_session_publication_batch(
        publication.batch
    )
    _close_failed_fixture(publication, windows)


def test_zero_row_windows_target_aborts_exactly_before_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nominally visible Security target must stage a positive real candidate row."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    monkeypatch.setattr(windows, "emit", lambda _event: None)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="staged no durable row"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not windows_root.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


def test_windows_abort_lost_return_keeps_prestate_cleanup_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-abort lost return cannot retain candidate capacity or mutate State."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    original_emit = windows.emit
    monkeypatch.setattr(
        windows,
        "emit",
        lambda event: (original_emit(event), original_emit(event)),
    )
    original_abort = windows._abort_exact_publication_batch
    aborts = 0

    def lose_abort_return(key: tuple[str, int]) -> None:
        nonlocal aborts
        aborts += 1
        original_abort(key)
        raise OSError("injected Windows abort lost return")

    monkeypatch.setattr(windows, "_abort_exact_publication_batch", lose_abort_return)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        prepare_publication=False,
    )
    before_version = publication.fixture.state.materialization_version
    before_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="EventID sequence") as raised:
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert aborts == 1
    assert any("cleanup also failed" in note for note in (raised.value.__notes__ or ()))
    assert publication.fixture.state.materialization_version == before_version
    assert publication.fixture.state.materialization_digest() == before_digest
    assert not windows_root.exists()
    _assert_windows_zero(windows)
    _close_failed_fixture(publication, windows)


@pytest.mark.parametrize("projection_mode", ("legacy", "compiled"))
@pytest.mark.parametrize("threaded", (False, True), ids=("sync", "threaded"))
@pytest.mark.parametrize(
    "target",
    (OutputTarget.DEFAULT, OutputTarget.SPLUNK, OutputTarget.SOF_ELK),
)
@pytest.mark.parametrize("direct", (False, True), ids=("per-host", "direct"))
def test_windows_rdp_exact_projection_matches_direct_candidate_bytes(
    tmp_path: Path,
    projection_mode: str,
    threaded: bool,
    target: OutputTarget,
    direct: bool,
) -> None:
    """Legacy/compiled exact publication preserves every established output layout."""

    windows_root = tmp_path / "bridge"
    windows = _windows_emitter(windows_root, threaded=threaded, direct=direct)
    windows.configure_output_target(target)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
        collection_deployment=(_compiled_deployment() if projection_mode == "compiled" else None),
    )
    payloads = _windows_payloads(publication)
    assert len(payloads) == 1

    baseline_root = tmp_path / "baseline"
    baseline = _windows_emitter(
        baseline_root,
        threaded=threaded,
        direct=direct,
        source_finalization=False,
    )
    baseline.configure_output_target(target)
    for payload in payloads:
        baseline.emit_event(_spool_decode(payload))
    baseline.close()

    result = _materialize(publication)
    assert all(outcome.status == "succeeded" for outcome in result.publication.projections)
    coordinator = _finish_sources(publication, windows)

    assert _output_bytes(windows_root, target, direct=direct) == _output_bytes(
        baseline_root,
        target,
        direct=direct,
    )
    assert coordinator.complete
    assert coordinator.publisher.census().active_child == 0
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


@pytest.mark.parametrize("failure", ("candidate-commit", "candidate-release", "owner-tail"))
def test_windows_rdp_dispatcher_lost_returns_recover_without_duplicate_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """Per-row and owner-tail lost returns retain one resumable dispatcher batch."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    attempts = 0
    if failure == "candidate-commit":
        original = WindowsEventEmitter._commit_exact_candidate_row

        def lose_candidate_commit(
            emitter: WindowsEventEmitter,
            key: tuple[str, int, int],
            digest: str,
            frozen: object,
        ) -> None:
            nonlocal attempts
            attempts += 1
            original(emitter, key, digest, frozen)
            if attempts == 1:
                raise OSError("injected Windows candidate commit lost return")

        monkeypatch.setattr(
            WindowsEventEmitter,
            "_commit_exact_candidate_row",
            lose_candidate_commit,
        )
        expected = "candidate commit lost return"
    elif failure == "candidate-release":
        original_release = WindowsEventEmitter._release_exact_candidate_row

        def lose_candidate_release(
            emitter: WindowsEventEmitter,
            key: tuple[str, int, int],
        ) -> None:
            nonlocal attempts
            attempts += 1
            original_release(emitter, key)
            if attempts == 1:
                raise OSError("injected Windows candidate release lost return")

        monkeypatch.setattr(
            WindowsEventEmitter,
            "_release_exact_candidate_row",
            lose_candidate_release,
        )
        expected = "candidate release lost return"
    else:
        expected = "owner-tail lost return"

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    if failure == "owner-tail":
        original_tail = publication.dispatcher._complete_deferred_session_owner_tail

        def lose_owner_tail(record: object) -> None:
            nonlocal attempts
            attempts += 1
            original_tail(record)
            raise OSError("injected Windows owner-tail lost return")

        monkeypatch.setattr(
            publication.dispatcher,
            "_complete_deferred_session_owner_tail",
            lose_owner_tail,
        )

    with pytest.raises(OSError, match=expected):
        _materialize(publication)
    results = publication.dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    assert attempts in {1, 2}
    _finish_sources(publication, windows)

    output = _output_bytes(windows_root, OutputTarget.DEFAULT).decode("utf-8")
    assert output.count("<EventID>4624</EventID>") == 1
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


@pytest.mark.parametrize("failure", ("finalizer-commit", "finalizer-release"))
def test_windows_rdp_source_finalizer_lost_returns_resume_one_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """The terminal source coordinator reuses the committed child after a lost return."""

    windows_root = tmp_path / "windows"
    windows = _windows_emitter(windows_root)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    _materialize(publication)
    publication.dispatcher.drain_exact_projection_recoveries()
    coordinator = SourceFinalizationCoordinator((windows,), _authority())
    attempts = 0

    if failure == "finalizer-commit":
        original = ExactPublicationBatch.commit

        def lose_finalizer_commit(batch: ExactPublicationBatch) -> object:
            nonlocal attempts
            result = original(batch)
            attempts += 1
            if attempts == 1:
                raise OSError("injected source-finalizer commit lost return")
            return result

        monkeypatch.setattr(ExactPublicationBatch, "commit", lose_finalizer_commit)
        expected = "commit lost return"
    else:
        original_release = ExactPublicationBatch.release_no_fail

        def lose_finalizer_release(batch: ExactPublicationBatch) -> None:
            nonlocal attempts
            original_release(batch)
            attempts += 1
            if attempts == 1:
                raise OSError("injected source-finalizer release lost return")

        monkeypatch.setattr(
            ExactPublicationBatch,
            "release_no_fail",
            lose_finalizer_release,
        )
        expected = "release lost return"

    with pytest.raises(OSError, match=expected):
        coordinator.finalize()
    assert coordinator.publisher.census().active_child == 1
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    publication.ecar.close()
    publication.zeek.close()

    output = _output_bytes(windows_root, OutputTarget.DEFAULT).decode("utf-8")
    assert output.count("<EventID>4624</EventID>") == 1
    assert attempts == 1
    assert coordinator.complete
    _assert_windows_zero(windows)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


@pytest.mark.parametrize(
    "tamper",
    ("event-id", "time", "transport-order", "digest", "bytes"),
)
def test_windows_ordering_proof_rejects_noncanonical_inert_scalars(
    tmp_path: Path,
    tamper: str,
) -> None:
    """Every Windows proof scalar is exact, bounded, and source-native."""

    windows = _windows_emitter(tmp_path / "windows")
    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        extra_emitters={"windows_event_security": windows},
    )
    record = _prepared_record(publication)
    proofs = list(record.prepared_target_proofs)
    proof_index = next(
        index for index, proof in enumerate(proofs) if proof.format_name == "windows_event_security"
    )
    proof = proofs[proof_index]
    event_id, raw_time, digest, retained_bytes = proof.windows_ordering_facts[0]
    if tamper == "event-id":
        event_id = 4625
    elif tamper == "time":
        raw_time = "2026-08-17T13:00:05"
    elif tamper == "transport-order":
        raw_time = _START.isoformat()
    elif tamper == "digest":
        digest = digest.upper()
    else:
        retained_bytes = True
    proofs[proof_index] = DeferredSessionExactTargetProof(
        occurrence_id=proof.occurrence_id,
        member_ordinal=proof.member_ordinal,
        target_ordinal=proof.target_ordinal,
        format_name=proof.format_name,
        row_start=proof.row_start,
        row_end=proof.row_end,
        source_order_keys=proof.source_order_keys,
        windows_ordering_facts=((event_id, raw_time, digest, retained_bytes),),
    )
    exact_batch = record.exact_publication_batch
    assert exact_batch is not None

    with pytest.raises(
        EventContractError,
        match="malformed|EventID|TimeCreated|transport|prepared bytes",
    ):
        publication.dispatcher._validate_deferred_session_target_proofs(
            publication.composition.publication_order,
            tuple(proofs),
            prepared_row_facts=exact_batch._prepared_row_facts(),
        )

    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    windows.close()
