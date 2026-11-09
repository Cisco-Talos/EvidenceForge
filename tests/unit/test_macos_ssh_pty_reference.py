# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented PTY graphs and mocked operations only; never run native commands."""

import json
import shlex
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_ssh_startup_reference as kit
from scripts import macos_ssh_startup_review as review

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_endpoint_security_contracts import _file
from tests.unit.test_macos_ssh_startup_reference import (
    _CANARY,
    _chain,
    _manifest,
)
from tests.unit.test_macos_ssh_startup_reference import (
    test_mocked_capture_cleans_up_and_only_persists_proved_rows_after_success as mocked_capture,
)


@pytest.fixture(autouse=True)
def no_native_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("PTY kit tests cannot execute a command, collector, SSH connection or probe")

    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.os, "execve", forbidden)


def _pty_manifest() -> kit.Manifest:
    return _manifest().model_copy(update={"terminal_mode": "PTY"})


def _pty_chain() -> list[dict]:
    rows = _chain()
    rows[0]["event"]["exec"]["args"][3] = "-tt"
    sample = next(
        i
        for i, row in enumerate(rows)
        if row["event_type"] == 9
        and kit._role(row["event"]["exec"]["target"], _manifest()) == "MARKER"
    )
    marker_row = rows[sample]
    shell = deepcopy(marker_row["process"])
    shell.update(group_id=1400, session_id=1400, tty=_file(f"/dev/{_CANARY}"))
    shell["tty"]["stat"].update(st_rdev=991234, st_mode=8592)
    for row in rows[:sample]:
        if (
            row["event_type"] == 9
            and kit._role(row["event"]["exec"]["target"], _manifest()) == "ZSH"
        ):
            row["event"]["exec"]["target"] = deepcopy(shell)
    child = deepcopy(shell)
    child["audit_token"].update(pid=1500, pidversion=2500)
    child["parent_audit_token"] = deepcopy(shell["audit_token"])
    child["ppid"] = child["original_ppid"] = 1400
    fork_row = deepcopy(rows[1])
    fork_row["process"] = deepcopy(shell)
    fork_row["event"]["fork"]["child"] = deepcopy(child)
    child["group_id"] = 1500
    marker_row["process"] = deepcopy(child)
    target = marker_row["event"]["exec"]["target"]
    for field in (
        "audit_token",
        "parent_audit_token",
        "ppid",
        "original_ppid",
        "group_id",
        "session_id",
        "tty",
    ):
        target[field] = deepcopy(child[field])
    target["audit_token"]["pidversion"] += 1
    rows[sample + 1]["process"] = deepcopy(target)
    shell_exit = deepcopy(rows[sample + 1])
    shell_exit["process"] = deepcopy(shell)
    rows.insert(sample + 2, shell_exit)
    rows.insert(sample, fork_row)
    sequences: dict[int, int] = {}
    for i, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"] = sequences.get(kind, 0)
        sequences[kind] = row["seq_num"] + 1
        row["global_seq_num"] = i + 1
    return rows


@requires_posix_reference
def test_pty_graph_distinguishes_shell_command_fork_and_foreground_group() -> None:
    manifest = _pty_manifest()
    tracker = kit.Tracker(manifest)
    tracker.collecting = True
    for row in _pty_chain():
        tracker.accept(json.dumps(row).encode())
    raws = tracker.retained()
    assert raws and tracker.marker_exit and tracker.client_exit and tracker.sequence_ok
    phases = kit.analyze(raws, manifest, Path("/private/tmp") / _CANARY)
    command = next(phase for phase in phases if phase.role == "MARKER")
    assert command.retained_fork == command.same_lifetime == "PASS"
    assert command.terminal == command.before_terminal == "PRESENT"
    assert command.terminal_matches_command == "COMMAND_TTY"
    assert command.parent_role == "ZSH"
    graph = review.classify(
        [kit.reference._decode(raw) for raw in raws], manifest, Path("/private/tmp") / _CANARY
    )
    shell = next(
        event.after for event in graph.events if event.kind == "EXEC" and event.after.role == "ZSH"
    )
    command_exec = next(
        event for event in graph.events if event.kind == "EXEC" and event.after.role == "MARKER"
    )
    command = command_exec.after
    assert command.life != shell.life
    assert command.parent == command.session == shell.life
    assert command.group == command.life
    assert command_exec.before.life == command.life
    assert command_exec.arguments == "CONTROLLED_MARKER"
    assert command.terminal == shell.terminal == "COMMAND_TTY"
    assert any(
        event.kind == "FORK"
        and event.before.life == shell.life
        and event.after.life == command.life
        for event in graph.events
    )
    report = kit.Report(
        terminal_mode="PTY",
        pty="OBSERVED",
        command_fork="PASS",
        phases=phases,
        core_graph=tuple(
            kit.GraphEvent.model_validate(event.model_dump()) for event in graph.events
        ),
    )
    text = report.model_dump_json()
    for sensitive in (_CANARY, manifest.nonce, "1500", "991234", "/dev/", "PRIVATE="):
        assert sensitive not in text


@requires_posix_reference
def test_prepare_pty_writes_only_code_and_an_immutable_experiment_selection(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "pty", pty=True)
    assert {path.name for path in root.iterdir()} == set(kit.CODE) | {
        "PRIVATE-RUN.md",
        "EXPERIMENT.json",
    }
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
    mode, digest = kit._experiment(root)
    assert mode == "PTY" and digest == kit.reference._digest(root / "EXPERIMENT.json")
    assert "SHAREABLE-SSH-PTY-REPORT.json" in (root / "PRIVATE-RUN.md").read_text()
    assert not list(root.glob("*LOCK")) and not list(root.glob("run-*"))
    with pytest.raises(FileExistsError):
        kit.prepare(root, pty=True)


@requires_posix_reference
@pytest.mark.parametrize("damage", ["mode", "extra", "symlink", "dangling_symlink"])
def test_invalid_experiment_does_not_fall_back_to_non_pty(tmp_path: Path, damage: str) -> None:
    root = kit.prepare(tmp_path / "pty", pty=True)
    experiment = root / "EXPERIMENT.json"
    if damage in {"symlink", "dangling_symlink"}:
        experiment.unlink()
        experiment.symlink_to(root / ("PRIVATE-RUN.md" if damage == "symlink" else "missing"))
    else:
        experiment.write_text(
            json.dumps(
                {"terminal_mode": "NON_PTY"}
                if damage == "mode"
                else {"terminal_mode": "PTY", "private": _CANARY}
            )
        )
    with pytest.raises((ValidationError, OSError, kit.reference.PrivateError)):
        kit._experiment(root)


def test_pty_preserves_loopback_controls_and_has_a_real_child_remote_command() -> None:
    root = Path("/private/tmp") / ("space ' " + _CANARY)
    manifest = _pty_manifest()
    args = kit._client_arguments(root, manifest)
    assert args[1:4] == ["-F", "/dev/null", "-tt"] and args[-2:] == ["--", "127.0.0.1"]
    for option in (
        "ForwardAgent=no",
        "ForwardX11=no",
        "IdentityAgent=none",
        "PubkeyAuthentication=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "StrictHostKeyChecking=ask",
    ):
        assert option in args
    remote = kit._remote_command(root, manifest)
    assert remote.endswith("; exit")
    assert shlex.split(remote.removesuffix("; exit")) == [
        str(root / "ssh-marker"),
        "--sample",
        manifest.nonce,
    ]
    assert not remote.startswith("exec ")
    assert kit._remote_command(root, _manifest()).startswith("exec ")


@pytest.mark.parametrize(
    "changed", ["atime", "device", "inode", "rdev", "path", "missing", "truncated", "absent"]
)
def test_terminal_equivalence_ignores_stat_times_but_requires_exact_identity(changed: str) -> None:
    command = {"tty": _file(f"/dev/{_CANARY}")}
    process = deepcopy(command)
    if changed == "atime":
        process["tty"]["stat"]["st_atimespec"] = "changed private timestamp"
    elif changed in {"device", "inode", "rdev"}:
        process["tty"]["stat"][
            {"device": "st_dev", "inode": "st_ino", "rdev": "st_rdev"}[changed]
        ] += 1
    elif changed == "path":
        process["tty"]["path"] += "other"
    elif changed == "missing":
        del process["tty"]["stat"]["st_dev"]
    elif changed == "truncated":
        process["tty"]["path_truncated"] = True
    else:
        process["tty"] = None
    assert kit.terminal_relation(process, command) == (
        "COMMAND_TTY"
        if changed == "atime"
        else "ABSENT"
        if changed == "absent"
        else "UNKNOWN"
        if changed in {"missing", "truncated"}
        else "OTHER"
    )


@requires_posix_reference
@pytest.mark.parametrize(
    "failure", [None, "collector", "interrupted", "analysis", "cleanup", "limit"]
)
@pytest.mark.parametrize("unified_log", [False, True])
def test_pty_capture_uses_shared_cleanup_and_validates_graph_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None, unified_log: bool
) -> None:
    monkeypatch.setattr(
        mocked_capture.__globals__["kit"], "_manifest", lambda _root: _pty_manifest()
    )
    # The shared mocked harness supplies its manifest and rows through these helpers.
    monkeypatch.setitem(mocked_capture.__globals__, "_manifest", _pty_manifest)
    monkeypatch.setitem(mocked_capture.__globals__, "_chain", _pty_chain)
    mocked_capture(tmp_path, monkeypatch, failure, unified_log)
    report = kit.Report.model_validate_json(
        next(tmp_path.rglob("SHAREABLE-REPORT.json")).read_bytes()
    )
    assert report.terminal_mode == "PTY"
    if failure is None:
        assert report.pty == "OBSERVED" and report.command_fork == "PASS" and report.core_graph


def test_connect_rejects_non_terminal_stdio_before_control_or_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(kit, "_manifest", lambda _root: _pty_manifest())
    monkeypatch.setattr(kit.os, "isatty", lambda _fd: False)
    with pytest.raises(kit.reference.PrivateError, match="INPUT"):
        kit.connect()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "field", ["terminal_mode", "pty", "command_fork", "core_graph", "limit_scope", "retained_scope"]
)
def test_new_report_fields_cannot_export_arbitrary_native_text(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate(
            {field: [{"private": _CANARY}] if field == "core_graph" else _CANARY}
        )


def test_compact_capture_status_and_saved_full_report_do_not_depend_on_scrollback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = kit.Report(terminal_mode="PTY", pty="OBSERVED", command_fork="PASS", stage="COMPLETE")
    monkeypatch.setattr(kit, "capture", lambda: report)
    monkeypatch.setattr(kit.sys, "argv", ["private_ssh_startup.py", "capture", "--private-run"])
    kit.main()
    output = json.loads(capsys.readouterr().out)
    assert "phases" not in output and "core_graph" not in output
    assert output["terminal_mode"] == "PTY" and output["stage"] == "COMPLETE"


@requires_posix_reference
def test_graph_loader_is_code_only_and_works_from_the_prepared_kit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = kit.prepare(tmp_path / "pty", pty=True)
    monkeypatch.setattr(kit, "__file__", str(root / kit.CODE[0]))
    graph = kit._graph_module()
    report = graph.classify(_pty_chain(), _pty_manifest(), Path("/private/tmp") / _CANARY)
    assert report.core_lineage == "PASS"
    assert not (root / "SETUP.json").exists()


@requires_posix_reference
@pytest.mark.parametrize("damage", ["remove", "content", "manifest_mode"])
def test_provenance_freezes_pty_selection_without_live_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    root = kit.prepare(tmp_path / "pty", pty=True)
    for name in ("ssh-marker", "collector-guard"):
        kit.reference._write(root / name, b"invented control")
    manifest = _pty_manifest().model_copy(
        update={
            "code_sha256": {name: kit.reference._digest(root / name) for name in kit.CODE},
            "guard_sha256": kit.reference._digest(root / "collector-guard"),
            "codec_sha256": kit.reference._codec_digest(),
            "experiment_sha256": kit.reference._digest(root / "EXPERIMENT.json"),
        }
    )
    monkeypatch.setattr(kit.support, "_image", lambda _path: manifest.marker)
    monkeypatch.setattr(
        kit.support,
        "_installed_image",
        lambda path: manifest.images[
            next(role for role, value in kit.PATHS.items() if str(path) == value)
        ],
    )
    kit.reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    assert kit._manifest(root).terminal_mode == "PTY"
    if damage == "remove":
        (root / "EXPERIMENT.json").unlink()
    elif damage == "content":
        (root / "EXPERIMENT.json").write_text('{ "terminal_mode": "PTY" }')
    else:
        (root / "SETUP.json").write_text(
            manifest.model_copy(update={"terminal_mode": "NON_PTY"}).model_dump_json()
        )
    with pytest.raises(kit.reference.PrivateError, match="BUILD"):
        kit._manifest(root)


@requires_posix_reference
def test_report_recovery_reads_only_saved_fixed_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = tmp_path / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    kit.reference._write(tmp_path / "ACTIVE-RUN", (run.name + "\n").encode())
    report = kit.Report(terminal_mode="PTY", pty="OBSERVED", stage="COMPLETE")
    kit.reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json().encode())
    kit.reference._write(run / "ssh-chain-events.jsonl", _CANARY.encode())
    original = kit.reference._read
    reads: list[str] = []

    def read(path: Path, limit: int = kit.reference.MAX_LINE) -> bytes:
        assert path.name in {"ACTIVE-RUN", "SHAREABLE-REPORT.json"}
        reads.append(path.name)
        return original(path, limit)

    monkeypatch.setattr(kit.reference, "_read", read)
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(kit.sys, "argv", ["private_ssh_startup.py", "report", "--private-run"])
    kit.main()
    assert reads == ["ACTIVE-RUN", "SHAREABLE-REPORT.json"]
    output = capsys.readouterr()
    assert _CANARY not in output.out + output.err
    assert kit.Report.model_validate_json(output.out) == report


@requires_posix_reference
def test_ancestry_unknown_image_reports_other_without_exposing_it_or_admitting_a_template() -> None:
    rows = _pty_chain()
    for row in rows:
        processes = [row["process"]]
        if row["event_type"] == 9:
            processes.append(row["event"]["exec"]["target"])
        elif row["event_type"] == 11:
            processes.append(row["event"]["fork"]["child"])
        for process in processes:
            if process["executable"]["path"] == kit.PATHS["WRAPPER"]:
                process["executable"]["path"] = "/private/" + _CANARY
    report = review.classify(rows, _pty_manifest(), Path("/private/tmp") / _CANARY)
    unknown = [event for event in report.events if event.after and event.after.role == "OTHER"]
    assert unknown and any(event.arguments == "OTHER" for event in unknown)
    assert _CANARY not in report.model_dump_json()


def test_timeout_is_reported_as_timeout_without_private_exception_text() -> None:
    assert kit._failure(kit.reference.PrivateError("TIMEOUT")) == "TIMEOUT"


@requires_posix_reference
def test_connect_preserves_window_streams_and_uses_only_the_prepared_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _pty_manifest()
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(kit, "_manifest", lambda _root: manifest)
    monkeypatch.setattr(kit.os, "isatty", lambda _fd: True)
    monkeypatch.setattr(kit.os, "getpid", lambda: 8811)
    monkeypatch.setattr(kit.os, "environ", {"INVENTED_TEST_VALUE": _CANARY})
    kit.reference._write(tmp_path / "COLLECTOR-READY", b"READY\n")
    observed: list[tuple] = []

    def replace(image: str, arguments: list[str], environment: dict[str, str]) -> None:
        observed.append((image, arguments, environment))

    monkeypatch.setattr(kit.os, "execve", replace)
    kit.connect()
    assert observed == [
        (
            "/usr/bin/ssh",
            kit._client_arguments(tmp_path, manifest),
            {
                "INVENTED_TEST_VALUE": _CANARY,
                "EFORGE_SSH_REFERENCE_TOKEN": manifest.nonce,
            },
        )
    ]
    assert json.loads((tmp_path / "CLIENT-CONTROL.json").read_bytes()) == {
        "pid": 8811,
        "nonce": manifest.nonce,
    }
    output = capsys.readouterr().out
    assert "PRIVATE_REMOTE_COMMAND:" in output and "; exit" in output
    assert "NO PROMPT" not in output


def _with_startup_branches(*, helper_siblings: bool = False) -> list[dict]:
    rows = _pty_chain()
    role = "SESSION" if helper_siblings else "ZSH"
    at = next(
        i
        for i, row in enumerate(rows)
        if row["event_type"] == 9
        and kit._role(row["event"]["exec"]["target"], _pty_manifest()) == role
    )
    parent = rows[at]["event"]["exec"]["target"]
    extras = []
    for index in range(15 if helper_siblings else 100):
        child = deepcopy(parent)
        child["audit_token"].update(pid=7000 + index, pidversion=9000 + index)
        child["parent_audit_token"] = deepcopy(parent["audit_token"])
        child["ppid"] = child["original_ppid"] = parent["audit_token"]["pid"]
        fork = deepcopy(rows[1])
        fork["process"], fork["event"]["fork"]["child"] = deepcopy(parent), deepcopy(child)
        extras.append(fork)
        if not helper_siblings:
            executed = deepcopy(child)
            executed["audit_token"]["pidversion"] += 1
            executed["executable"]["path"] = "/private/STARTUP_NOISE_CANARY"
            executed["executable"]["stat"]["st_ino"] = 55000 + index
            execution = deepcopy(rows[0])
            execution["process"] = child
            execution["event"]["exec"].update(
                target=deepcopy(executed),
                args=["/private/STARTUP_NOISE_CANARY"],
                env=["PRIVATE=STARTUP_NOISE_CANARY"],
            )
            extras.append(execution)
            child = executed
        ended = deepcopy(rows[-1])
        ended["process"] = deepcopy(child)
        extras.append(ended)
    rows[at + 1 : at + 1] = extras
    sequences: dict[int, int] = {}
    for i, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"] = sequences.get(kind, 0)
        sequences[kind] = row["seq_num"] + 1
        row["global_seq_num"] = i + 1
    return rows


@requires_posix_reference
def test_pty_core_selection_precedes_limits_and_excludes_large_shell_startup_trees() -> None:
    rows, manifest = _with_startup_branches(), _pty_manifest()
    tracker = kit.Tracker(manifest)
    tracker.collecting = True
    for row in rows:
        tracker.accept(json.dumps(row).encode())
    assert not tracker.evicted and tracker.sequence_ok
    sample = next(
        i
        for i, row in enumerate(rows)
        if row["event_type"] == 9
        and kit._role(row["event"]["exec"]["target"], manifest) == "MARKER"
    )
    with pytest.raises(kit.CaptureLimit) as old_tree_limit:
        kit.select_receiver(rows, sample, manifest, core_only=False)
    assert old_tree_limit.value.scope == "RETAINED_ROWS"
    retained = tracker.retained()
    assert len(retained) == len(_pty_chain()) < kit.MAX_RETAINED
    assert b"STARTUP_NOISE_CANARY" not in b"".join(retained)
    graph = kit._classify_core(retained, manifest, Path("/private/tmp") / _CANARY)
    baseline = kit._classify_core(
        [json.dumps(row).encode() for row in _pty_chain()], manifest, Path("/private/tmp") / _CANARY
    )
    assert graph == baseline
    assert any(event.kind == "FORK" and event.before.role == "SESSION" for event in graph)


def test_true_helper_graph_overflow_still_rejects_with_a_fixed_limit_label() -> None:
    raws = [json.dumps(row).encode() for row in _with_startup_branches(helper_siblings=True)]
    with pytest.raises(kit.CaptureLimit) as limit:
        kit._classify_core(raws, _pty_manifest(), Path("/private/tmp") / _CANARY)
    assert limit.value.scope == "CORE_LIFETIMES"
    assert kit._failure(limit.value) == "LIMIT"


def test_classifier_private_errors_cross_prepared_module_boundary_as_fixed_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = kit._graph_module()

    def fail(*_args: object) -> None:
        raise module.reference.PrivateError("DATA")

    monkeypatch.setattr(module, "classify", fail)
    monkeypatch.setattr(kit, "_graph_module", lambda: module)
    with pytest.raises(kit.reference.PrivateError) as error:
        kit._classify_core([], _pty_manifest(), Path("/private/tmp") / _CANARY)
    assert kit._failure(error.value) == "DATA"


def test_compact_failure_status_identifies_the_limit_without_records(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        kit,
        "capture",
        lambda: kit.Report(
            terminal_mode="PTY",
            error="LIMIT",
            limit_scope="CORE_EVENTS",
            retained_scope="CONTROLLED_SSH_CORE",
        ),
    )
    monkeypatch.setattr(kit.sys, "argv", ["private_ssh_startup.py", "capture", "--private-run"])
    kit.main()
    output = json.loads(capsys.readouterr().out)
    assert output["error"] == "LIMIT" and output["limit_scope"] == "CORE_EVENTS"
    assert output["retained_scope"] == "CONTROLLED_SSH_CORE" and "core_graph" not in output
