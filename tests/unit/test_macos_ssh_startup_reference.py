# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented records only: never execute a collector, SSH connection or native probe."""

import json
from copy import deepcopy
from itertools import count
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_ssh_startup_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _process, _record

_CANARY = "INVENTED_PRIVATE_SSH_CANARY"


@pytest.fixture(autouse=True)
def no_native_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("SSH reference tests cannot start any native command")

    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.os, "execve", forbidden)


def _manifest() -> kit.Manifest:
    return kit.Manifest(
        os_version="27.0",
        os_build="invented",
        marker=kit.reference.Image(device=123, inode=19001, sha256="a" * 64),
        images={
            role: kit.reference.Image(device=123, inode=7000 + i, sha256="b" * 64)
            for i, role in enumerate(kit.PATHS)
        },
        guard_sha256="c" * 64,
        codec_sha256="d" * 64,
        code_sha256={},
        nonce="e" * 32,
        username=_CANARY,
        home=f"/Users/{_CANARY}",
        uid=501,
        gid=20,
    )


def _chain() -> list[dict]:
    manifest = _manifest()
    rows: list[dict] = []

    def image(process: dict, role: kit.Role) -> dict:
        value = manifest.marker if role == "MARKER" else manifest.images[role]
        process["executable"]["path"] = (
            str(Path("/private/tmp") / _CANARY / "ssh-marker")
            if role == "MARKER"
            else kit.PATHS[role]
        )
        process["executable"]["stat"].update(st_dev=value.device, st_ino=value.inode)
        return process

    def fork(parent: dict, pid: int) -> dict:
        child = deepcopy(parent)
        child["audit_token"].update(pid=pid, pidversion=pid + 1000)
        child["parent_audit_token"] = deepcopy(parent["audit_token"])
        child["ppid"] = child["original_ppid"] = parent["audit_token"]["pid"]
        row = _record(11, "fork")
        row["process"], row["event"]["fork"]["child"] = deepcopy(parent), deepcopy(child)
        rows.append(row)
        return child

    def execute(before: dict, role: kit.Role, args: list[str] | None = None) -> dict:
        target = image(deepcopy(before), role)
        target["audit_token"]["pidversion"] += 1
        row = _record(11, "exec")
        row["process"] = deepcopy(before)
        row["event"]["exec"].update(
            target=deepcopy(target),
            args=args or [target["executable"]["path"]],
            env=[f"PRIVATE={_CANARY}"],
            entitlements=deepcopy(kit.TEMPLATES.get(role)),
            fds=[{"fd": fd, "fdtype": 1} for fd in range(3)],
            last_fd=2,
            dyld_exec_path=target["executable"]["path"],
        )
        rows.append(row)
        return target

    def end(process: dict) -> None:
        row = _record(11, "exit")
        row["process"], row["event"]["exit"]["stat"] = deepcopy(process), 0
        rows.append(row)

    client = execute(
        _process(11, 8800),
        "SSH_CLIENT",
        kit._client_arguments(Path("/private/tmp") / _CANARY, manifest),
    )
    rows[-1]["event"]["exec"]["env"].append(f"EFORGE_SSH_REFERENCE_TOKEN={manifest.nonce}")
    boot = image(_process(11, 1, 0), "LAUNCHD")
    wrapper = execute(fork(boot, 1200), "WRAPPER")
    daemon = execute(wrapper, "SSHD")
    worker = execute(daemon, "SESSION")
    auth = execute(fork(worker, 1250), "AUTH")
    end(auth)
    child = fork(worker, 1300)
    shell = execute(fork(child, 1400), "ZSH", ["-zsh"])
    marker = execute(
        shell,
        "MARKER",
        [str(Path("/private/tmp") / _CANARY / "ssh-marker"), "--sample", manifest.nonce],
    )
    end(marker)
    end(child)
    end(worker)
    end(client)
    sequences: dict[int, int] = {}
    for i, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"] = sequences.get(kind, 0)
        sequences[kind] = row["seq_num"] + 1
        row["global_seq_num"] = i + 1
    return rows


def _track(rows: list[dict]) -> kit.Tracker:
    tracker = kit.Tracker(_manifest())
    tracker.collecting = True
    for row in rows:
        assert tracker.accept(json.dumps(row).encode()) == []
    return tracker


def test_exact_connection_tree_includes_auth_sibling_and_excludes_other_connections() -> None:
    rows = _chain()
    noise = deepcopy(rows[1])
    noise["event"]["fork"]["child"]["audit_token"].update(pid=9000, pidversion=9900)
    rows.insert(2, noise)
    tracker = _track(rows)
    retained = tracker.retained()
    assert len(retained) == len(rows) - 1
    assert not any(
        kit.reference._decode(raw)
        .get("event", {})
        .get("fork", {})
        .get("child", {})
        .get("audit_token", {})
        .get("pid")
        == 9000
        for raw in retained
    )
    phases = kit.analyze(retained, _manifest(), Path("/private/tmp") / _CANARY)
    assert [phase.role for phase in phases] == [
        "SSH_CLIENT",
        "WRAPPER",
        "SSHD",
        "SESSION",
        "AUTH",
        "ZSH",
        "MARKER",
    ]
    assert phases[0].native_shape == "PASS" and phases[0].entitlement_template == "PASS"
    assert phases[0].entitlement_types == ("ARRAY", "INTEGER")
    assert phases[2].environment_from_previous_exec.comparison == "IDENTICAL"
    assert phases[4].parent_role == "SESSION"
    forks = kit.analyze_forks(retained, _manifest())
    assert [fork.next_child_exec for fork in forks] == ["WRAPPER", "AUTH", "NOT_RETAINED", "ZSH"]
    exits = kit.analyze_exits(retained, _manifest())
    assert [item.role for item in exits] == ["AUTH", "MARKER", "SESSION", "SESSION", "SSH_CLIENT"]
    assert all(item.outcome == "ZERO" for item in exits)
    report = kit.Report(phases=phases)
    assert _CANARY not in report.model_dump_json()
    assert _manifest().nonce not in report.model_dump_json()
    assert "8800" not in report.model_dump_json()
    assert all(phase.last_fd_matches_maximum == "PASS" for phase in phases)


@pytest.mark.parametrize(
    "damage",
    [
        "client_nonce",
        "marker_nonce",
        "client_inode",
        "marker_inode",
        "parent_version",
        "birth",
        "no_root",
    ],
)
def test_ambiguous_or_unproved_endpoints_never_release_records(damage: str) -> None:
    rows = _chain()
    if damage == "client_nonce":
        rows[0]["event"]["exec"]["env"] = ["EFORGE_SSH_REFERENCE_TOKEN=other"]
    elif damage == "marker_nonce":
        rows[-5]["event"]["exec"]["args"][-1] = "a" * 32
    elif damage == "client_inode":
        rows[0]["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] += 1
    elif damage == "marker_inode":
        rows[-5]["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] += 1
    elif damage == "parent_version":
        rows[-5]["process"]["audit_token"]["pidversion"] += 20
    elif damage == "birth":
        rows[-5]["process"]["start_time"] = "2026-10-19T12:00:00Z"
    else:
        del rows[1]
    assert not _track(rows).retained()


def test_integer_entitlement_template_cannot_match_a_boolean() -> None:
    rows = _chain()
    rows[0]["event"]["exec"]["entitlements"]["com.apple.private.amfi.version-restriction"] = True
    phases = kit.analyze(
        [json.dumps(row).encode() for row in rows], _manifest(), Path("/private/tmp") / _CANARY
    )
    assert phases[0].entitlement_template == "FAIL"
    assert phases[0].entitlement_types == ("ARRAY", "BOOLEAN")


@pytest.mark.parametrize(
    "status,expected",
    [
        (0, "ZERO"),
        (256, "EXIT_ONE"),
        (65280, "EXIT_255"),
        (512, "OTHER_EXIT_CODE"),
        (15, "SIGNALLED"),
        ("private", "OTHER"),
    ],
)
def test_exit_dispositions_use_only_fixed_labels(status: object, expected: str) -> None:
    row = _chain()[-1]
    row["event"]["exit"]["stat"] = status
    assert kit.analyze_exits([json.dumps(row).encode()], _manifest())[0].outcome == expected


@pytest.mark.parametrize("which", ["client", "marker"])
def test_duplicate_controlled_exec_is_an_explicit_failure(which: str) -> None:
    rows = _chain()
    rows.append(deepcopy(rows[0 if which == "client" else -5]))
    assert not _track(rows).retained()


def test_sequence_loss_eviction_and_resource_limits_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _chain()
    rows[2]["global_seq_num"] = 0
    assert not _track(rows).sequence_ok
    monkeypatch.setattr(kit, "MAX_ROWS", 2)
    tracker = _track(_chain())
    assert tracker.evicted and not tracker.retained()
    monkeypatch.setattr(kit, "MAX_STREAM", 1)
    with pytest.raises(kit.reference.PrivateError, match="LIMIT"):
        _track(_chain())


def test_marker_exit_requires_exact_execution_and_birth() -> None:
    rows = _chain()
    rows[-4]["process"]["start_time"] = "2026-10-19T12:00:00Z"
    tracker = _track(rows)
    assert tracker.marker_exit is None and not tracker.retained()


def test_pipe_equivalence_uses_fixed_labels_and_never_exports_pipe_identifiers() -> None:
    payload = {
        "fds": [
            {"fd": 0, "fdtype": 2},
            {"fd": 4, "fdtype": 6, "pipe": {"pipe_id": 991234}},
            {"fd": 5, "fdtype": 6, "pipe": {"pipe_id": 991234}},
        ],
        "last_fd": 5,
    }
    descriptors, complete, maximum = kit._descriptors(payload)
    assert complete == maximum == "PASS"
    assert [item.pipe_group for item in descriptors] == ["NOT_PIPE", "A", "A"]
    assert "991234" not in "".join(item.model_dump_json() for item in descriptors)
    payload["fds"][2]["pipe"]["pipe_id"] += 1
    assert kit._descriptors(payload)[0][2].pipe_group == "B"
    pipes: dict[int, str] = {}
    kit._descriptors(payload, pipes)
    assert (
        kit._descriptors({"fds": [payload["fds"][2]], "last_fd": 5}, pipes)[0][0].pipe_group == "B"
    )


@pytest.mark.parametrize(
    "field", ["error", "stage", "step", "collection", "wire_profile", "fork_roles"]
)
def test_report_rejects_arbitrary_native_text(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: [_CANARY] if field == "fork_roles" else _CANARY})


def test_prepare_copies_code_only_and_extends_the_reviewed_hard_stop(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "fresh")
    assert {path.name for path in root.iterdir()} == set(kit.CODE) | {"PRIVATE-RUN.md"}
    assert root.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
    assert "alarm(180);" in (root / "collector_guard.c").read_text()
    assert not (root / "SETUP.json").exists()


def test_setup_and_provenance_use_mocked_native_commands_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = kit.prepare(tmp_path / "fresh")
    monkeypatch.setattr(kit, "__file__", str(root / kit.CODE[0]))
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "invented"))
    monkeypatch.setattr(
        kit.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(
            pw_name=_CANARY, pw_dir=f"/Users/{_CANARY}", pw_uid=501, pw_gid=20
        ),
    )
    manifest = _manifest()
    monkeypatch.setattr(
        kit.support,
        "_installed_image",
        lambda path: manifest.images[
            next(role for role, value in kit.PATHS.items() if str(path) == value)
        ],
    )
    commands = []

    def command(args: list[str], _root: Path) -> None:
        commands.append(args[0])
        if args[0] == "/usr/bin/clang":
            Path(args[-1]).write_bytes(b"invented executable")

    monkeypatch.setattr(kit.reference, "_command", command)
    assert kit.setup().stage == "SETUP_READY"
    assert commands == ["/usr/bin/clang", "/usr/bin/clang", "/usr/bin/codesign"]
    assert kit._manifest(root).username == _CANARY
    (root / "ssh_marker.c").write_bytes(b"changed code")
    with pytest.raises(kit.reference.PrivateError, match="BUILD"):
        kit.capture()


def test_repo_source_cannot_run_setup_capture_connect_or_report() -> None:
    with pytest.raises(kit.reference.PrivateError, match="LOCATION"):
        kit._root()


def test_client_is_loopback_only_config_free_password_only_and_preserves_stdio() -> None:
    args = kit._client_arguments(Path("/private/tmp/invented"), _manifest())
    assert args[-2:] == ["--", "127.0.0.1"]
    for option in (
        "IdentityAgent=none",
        "PubkeyAuthentication=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "PermitLocalCommand=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ControlMaster=no",
        "ControlPath=none",
        "StrictHostKeyChecking=ask",
    ):
        assert option in args
    assert args[1:4] == ["-F", "/dev/null", "-T"]
    source = Path(kit.__file__).read_text()
    assert "os.execve(args[0], args" in source
    assert "ps " not in source and "log stream" not in source


@pytest.mark.parametrize("failure", [None, "collector", "interrupted", "analysis", "cleanup"])
def test_mocked_capture_cleans_up_and_only_persists_proved_rows_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    root = tmp_path / "fresh"
    root.mkdir(mode=0o700)
    manifest = _manifest()
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit, "_manifest", lambda _root: manifest)
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "invented"))
    clock = count()
    monkeypatch.setattr(kit.time, "monotonic", lambda: float(next(clock)))
    commands = []
    closed = []
    guard = SimpleNamespace(stdout=SimpleNamespace(close=lambda: closed.append("stdout")))

    def popen(args: list[str], **_kwargs: object) -> object:
        commands.append(args)
        return guard

    class Pump:
        def __init__(self, _guard: object, tracker: kit.Tracker, files: dict) -> None:
            assert files == {}
            self.tracker = tracker
            self.sent = False
            self.selector = SimpleNamespace(close=lambda: closed.append("selector"))

        def tick(self) -> None:
            if failure == "collector":
                raise kit.reference.PrivateError("COLLECTOR")
            if failure == "interrupted":
                raise KeyboardInterrupt(_CANARY)
            if not self.tracker.ready:
                self.tracker.ready = True
            elif not self.sent:
                for row in _chain():
                    self.tracker.accept(json.dumps(row).encode())
                kit.reference._write(
                    root / "CLIENT-CONTROL.json",
                    json.dumps({"pid": 8800, "nonce": manifest.nonce}).encode(),
                )
                self.sent = True

    monkeypatch.setattr(kit.subprocess, "Popen", popen)
    monkeypatch.setattr(kit.reference, "Pump", Pump)
    monkeypatch.setattr(kit.reference, "_start", lambda *_args: SimpleNamespace(pid=77))
    monkeypatch.setattr(kit.reference, "_stop_probe", lambda _probe: closed.append("probe"))
    monkeypatch.setattr(
        kit.reference,
        "_stop_collector",
        lambda _guard: closed.append("guard") or failure != "cleanup",
    )
    if failure == "analysis":

        def fail(*_args: object) -> None:
            raise ValueError(_CANARY)

        monkeypatch.setattr(kit, "analyze", fail)
    report = kit.capture()
    assert commands == [["/usr/bin/sudo", "-n", str(root / "collector-guard")]]
    assert set(closed) >= {"guard", "stdout", "selector"}
    if failure != "collector" and failure != "interrupted":
        assert "probe" in closed
    assert _CANARY not in report.model_dump_json()
    assert list(root.rglob("ssh-chain-events.jsonl")) == (
        [] if failure else [next(root.glob("run-*")) / "ssh-chain-events.jsonl"]
    )
    assert (
        report.error
        == {
            None: "NONE",
            "collector": "COLLECTOR",
            "interrupted": "INTERRUPTED",
            "analysis": "INTERNAL",
            "cleanup": "COLLECTOR",
        }[failure]
    )
    assert _CANARY not in next(root.rglob("SHAREABLE-REPORT.json")).read_text()


def test_parser_error_never_echoes_the_untrusted_argument(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(kit.sys, "argv", ["private_ssh_startup.py", _CANARY])
    kit.main()
    output = capsys.readouterr()
    assert _CANARY not in output.out + output.err
    assert json.loads(output.out)["error"] == "INPUT"
