# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented inputs only. No native commands, private kits or captures are opened."""

import json
import plistlib
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_gui_launch_reference as kit

from tests.unit.test_macos_gui_launch_reference import _CANARY, _IMAGE, _raws, _rows


@pytest.fixture(autouse=True)
def no_native_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Only invented record tests are permitted")

    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)


def _chain() -> list[dict]:
    fork, app, exit_row = _rows()
    launcher_target = deepcopy(app["process"])
    launcher_target["executable"]["path"] = "/usr/libexec/xpcproxy"
    launcher_target["executable"]["stat"]["st_ino"] += 100
    launcher_target["signing_id"] = "com.apple.xpcproxy"
    before = deepcopy(launcher_target)
    before["audit_token"]["pidversion"] -= 1
    before["executable"]["path"] = "/sbin/launchd"
    before["executable"]["stat"]["st_ino"] += 1
    first = deepcopy(app)
    first["process"] = before
    first["event"]["exec"].update(
        target=launcher_target,
        args=["/usr/libexec/xpcproxy", _CANARY],
        entitlements={_CANARY: _CANARY},
    )
    fork["event"]["fork"]["child"] = deepcopy(before)
    app["process"] = deepcopy(launcher_target)
    app["event"]["exec"]["entitlements"] = {kit.ENTITLEMENT_MARKER: True}
    first["seq_num"], app["seq_num"] = 0, 1
    for index, row in enumerate((fork, first, app, exit_row)):
        row["global_seq_num"] = index + 1
    return [fork, first, app, exit_row]


def test_chain_filter_retains_launcher_and_fork_only_after_exact_owned_app_exec() -> None:
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    fork, first, app, exit_row = _raws(_chain())
    assert tracker.accept(fork) == tracker.accept(first) == []
    assert not any(tracker.records.values())
    accepted = tracker.accept(app)
    assert [kit._decode(raw)["event_type"] for _, raw in accepted] == [11, 9, 9]
    tracker.accept(exit_row)
    report = tracker.launch_chain_report()
    assert report.launcher_retained == "ONE"
    assert report.candidate_selection == "MATCHED" and report.candidate_ring_evicted is False
    assert report.launcher_linkage == "PASS"
    assert report.launcher_fork_linkage == "RETAINED_MATCH"
    assert report.launcher_shape_excluding_entitlements == "PASS"
    assert report.probe_shape_excluding_entitlements == "PASS"
    assert report.probe_entitlements.marker == "BOOLEAN_TRUE"
    assert report.probe_entitlements.only_controlled_marker == "PASS"
    assert report.launcher_entitlements.only_controlled_marker == "FAIL"
    assert report.launcher_signing_identifier == "EXPECTED_XPCPROXY"
    assert _CANARY not in report.model_dump_json()
    with pytest.raises(ValidationError):
        kit.decode_endpoint_security_record(first.decode())
    assert len(kit._app_case_rows(tracker.records["finder"], _IMAGE)) == 2


@pytest.mark.parametrize("phase", ["ready", "control"])
def test_owned_launcher_prefix_can_precede_finder_phase_without_ambient_persistence(
    phase: str,
) -> None:
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    fork, first, app, exit_row = _raws(_chain())
    tracker.phase = phase
    assert tracker.accept(fork) == tracker.accept(first) == []
    assert not any(tracker.records.values())
    tracker.phase = "finder"
    accepted = tracker.accept(app)
    assert [kit._decode(raw)["event_type"] for _, raw in accepted] == [11, 9, 9]
    tracker.accept(exit_row)
    assert kit.analyze_launch_chain(tracker.records["finder"], _IMAGE).launcher_linkage == "PASS"
    assert not tracker.records["control"]


@pytest.mark.parametrize(
    ("word", "field"),
    [
        ("auid", "audit_user"),
        ("euid", "effective_user"),
        ("egid", "effective_group"),
        ("ruid", "real_user"),
        ("rgid", "real_group"),
        ("asid", "audit_session"),
    ],
)
def test_credential_changes_do_not_split_the_same_owned_launcher_execution(
    word: str,
    field: str,
) -> None:
    rows = _chain()
    rows[1]["event"]["exec"]["target"]["audit_token"][word] += 1
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    for raw in _raws(rows):
        tracker.accept(raw)
    report = tracker.launch_chain_report()
    assert report.launcher_retained == "ONE" and report.launcher_linkage == "PASS"
    assert report.candidate_selection == "MATCHED"
    assert report.launcher_token_agreement.model_dump() == {
        key: "FAIL" if key == field else "PASS"
        for key in type(report.launcher_token_agreement).model_fields
    }
    assert _CANARY not in report.model_dump_json()


@pytest.mark.parametrize(
    "damage",
    ["pid", "pid_version", "birth", "file", "code", "hash", "team", "path", "truncated"],
)
def test_pid_path_or_mutable_credentials_cannot_replace_execution_and_image_proof(
    damage: str,
) -> None:
    rows = _chain()
    target = rows[1]["event"]["exec"]["target"]
    # A credential change never excuses a mismatched lifetime or loaded image.
    target["audit_token"]["egid"] += 1
    if damage == "pid":
        target["audit_token"]["pid"] += 1
    elif damage == "pid_version":
        target["audit_token"]["pidversion"] += 2
    elif damage == "birth":
        target["start_time"] = "2026-01-01T00:00:00Z"
    elif damage == "file":
        target["executable"]["stat"]["st_ino"] += 1
    elif damage == "code":
        target["signing_id"] = _CANARY
    elif damage == "hash":
        target["cdhash"] = "f" * 40
    elif damage == "team":
        target["team_id"] = _CANARY
    elif damage == "path":
        rows[2]["process"]["executable"]["path"] = _CANARY
    else:
        target["executable"]["path_truncated"] = True
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    for raw in _raws(rows):
        tracker.accept(raw)
    assert all(
        kit._decode(raw).get("event_type") != 9
        or kit._owned(kit._decode(raw)["event"]["exec"]["target"], _IMAGE)
        for raw in tracker.records["finder"]
    )
    report = tracker.launch_chain_report()
    assert report.launcher_retained == "NONE"
    assert report.candidate_selection == (
        "NO_EXECUTION_MATCH" if damage in {"pid", "pid_version", "birth"} else "IMAGE_MISMATCH"
    )
    assert _CANARY not in report.model_dump_json()


@pytest.mark.parametrize("missing", ["cdhash", "signing_id", "team_id"])
def test_absent_code_identity_cannot_authenticate_a_launcher(missing: str) -> None:
    rows = _chain()
    for process in (rows[1]["event"]["exec"]["target"], rows[2]["process"]):
        process.pop(missing)
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    for raw in _raws(rows):
        tracker.accept(raw)
    assert tracker.launch_chain_report().candidate_selection == "IMAGE_MISMATCH"
    assert [kit._decode(raw)["event_type"] for raw in tracker.records["finder"]] == [9, 15]


def test_launcher_source_order_is_required_for_retention_and_offline_linkage() -> None:
    rows = _chain()
    rows[1]["global_seq_num"] = rows[2]["global_seq_num"]
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    for raw in _raws(rows):
        tracker.accept(raw)
    assert tracker.launch_chain_report().candidate_selection == "ORDER_MISMATCH"
    assert [kit._decode(raw)["event_type"] for raw in tracker.records["finder"]] == [9, 15]
    assert kit.analyze_launch_chain(_raws(rows), _IMAGE).launcher_linkage == "FAIL"


def test_ambiguous_execution_candidates_are_not_persisted() -> None:
    rows = _chain()
    duplicate = deepcopy(rows[1])
    duplicate["event"]["exec"]["target"]["audit_token"]["egid"] += 1
    rows.insert(2, duplicate)
    for index, row in enumerate(rows):
        row["global_seq_num"] = index + 1
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    for raw in _raws(rows):
        tracker.accept(raw)
    report = tracker.launch_chain_report()
    assert report.candidate_selection == "AMBIGUOUS_EXECUTION"
    assert report.launcher_retained == "NONE"
    assert [kit._decode(raw)["event_type"] for raw in tracker.records["finder"]] == [9, 15]


def test_no_candidate_is_distinct_from_rejected_or_unrecorded_candidates() -> None:
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    assert tracker.launch_chain_report().candidate_selection == "NOT_RECORDED"
    tracker.accept(_raws(_chain())[2])
    assert tracker.launch_chain_report().candidate_selection == "NO_CANDIDATES"
    old = kit.analyze_launch_chain(tracker.records["finder"], _IMAGE)
    assert old.candidate_selection == "NOT_RECORDED" and old.candidate_ring_evicted is None


def test_malformed_unretained_candidate_does_not_drop_the_exact_owned_app() -> None:
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    rows = _chain()
    rows[1]["event"]["exec"]["target"]["executable"]["stat"].pop("st_ino")
    for raw in _raws(rows):
        tracker.accept(raw)
    report = tracker.launch_chain_report()
    assert report.candidate_selection == "IMAGE_MISMATCH"
    assert (
        report.launcher_retained == "NONE" and report.probe_shape_excluding_entitlements == "PASS"
    )
    assert [kit._decode(raw)["event_type"] for raw in tracker.records["finder"]] == [9, 15]
    assert _CANARY not in report.model_dump_json()


def test_offline_candidate_selection_preserves_recorded_labels_without_inventing_history() -> None:
    source = kit.LaunchChainDiagnostic(
        candidate_selection="TOKEN_MISMATCH", candidate_ring_evicted=True
    )
    analyzed = kit.analyze_launch_chain(_raws(_chain())[2:], _IMAGE)
    result = kit._preserve_candidate_selection(analyzed, source)
    assert result.launcher_retained == "NONE"
    assert result.candidate_selection == "TOKEN_MISMATCH" and result.candidate_ring_evicted is True
    assert kit._preserve_candidate_selection(analyzed, None) == analyzed


@pytest.mark.parametrize("form", ["object", "json", "plist", "other", "null"])
def test_entitlement_diagnostic_exports_no_arbitrary_keys_or_values(form: str) -> None:
    value: object = {kit.ENTITLEMENT_MARKER: True, _CANARY: _CANARY}
    if form == "json":
        value = json.dumps(value)
    elif form == "plist":
        value = plistlib.dumps(value).decode()
    elif form == "other":
        value = _CANARY
    elif form == "null":
        value = None
    report = kit.entitlement_shape(value)
    assert _CANARY not in report.model_dump_json()
    if form in {"object", "json", "plist"}:
        assert report.marker == "BOOLEAN_TRUE"
        assert report.only_controlled_marker == "FAIL"


def test_launcher_buffer_is_bounded_and_disabled_for_original_mode() -> None:
    tracker = kit.Tracker(_IMAGE, launch_chain=True)
    tracker.phase = "finder"
    original = kit.Tracker(_IMAGE)
    original.phase = "finder"
    for index in range(100):
        row = _chain()[1]
        row.update(seq_num=index, global_seq_num=index + 1)
        row["event"]["exec"]["env"] = [_CANARY * 100]
        assert tracker.accept(_raws([row])[0]) == []
        assert original.accept(_raws([row])[0]) == []
    assert len(tracker.launchers) <= 64
    assert tracker.launcher_bytes <= kit.MAX_RING_BYTES
    assert tracker.launch_chain_report().candidate_ring_evicted is True
    assert not original.launchers and not any(tracker.records.values())


@pytest.mark.parametrize("synthetic_entitlement", [False, True])
def test_launcher_setup_separates_the_marker_experiment_and_binds_its_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, synthetic_entitlement: bool
) -> None:
    root = kit.prepare(tmp_path / "new-code-only-kit")
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit, "_preflight", lambda: ("27.0", "INVENTED"))
    commands: list[list[str]] = []

    def command(arguments: list[str], _root: Path) -> None:
        commands.append(arguments)
        if "-o" in arguments:
            kit._write(Path(arguments[arguments.index("-o") + 1]), b"INVENTED BINARY")

    monkeypatch.setattr(kit, "_command", command)
    report = kit.setup(launch_chain=True, synthetic_entitlement=synthetic_entitlement)
    assert report.kit_version == 2 and report.stage == "SETUP_READY"
    assert report.synthetic_entitlement is synthetic_entitlement
    manifest = kit._manifest(root)
    assert manifest.collection_mode == "launch_chain" and manifest.kit_version == 2
    assert manifest.synthetic_entitlement is synthetic_entitlement
    assert (root / "CONTROLLED-ENTITLEMENTS.plist").exists() is synthetic_entitlement
    if synthetic_entitlement:
        assert plistlib.loads((root / "CONTROLLED-ENTITLEMENTS.plist").read_bytes()) == {
            kit.ENTITLEMENT_MARKER: True
        }
    assert any("--entitlements" in command for command in commands) is synthetic_entitlement
    assert "collection_mode" in manifest.model_dump()
    legacy = manifest.model_dump()
    legacy.pop("synthetic_entitlement")
    assert kit.Manifest.model_validate(legacy).model_dump() == legacy
    old = manifest.model_copy(
        update={"kit_version": 1, "collection_mode": "app", "synthetic_entitlement": None}
    )
    assert "collection_mode" not in old.model_dump()
    assert "synthetic_entitlement" not in old.model_dump()


def test_marker_requires_explicit_launcher_mode_before_any_native_operation() -> None:
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit.setup(synthetic_entitlement=True)


def test_absent_entitlements_remain_distinct_from_explicit_null() -> None:
    assert kit.entitlement_shape(None).representation == "NULL"
    assert kit.entitlement_shape(None, present=False).representation == "ABSENT"
