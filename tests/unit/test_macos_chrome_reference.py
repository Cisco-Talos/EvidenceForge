# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented records only; no native commands, installed apps, servers or captures."""

import io
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_chrome_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _file, _process, _record

CANARY = "INVENTED_PRIVATE_CHROME_CANARY"
PROFILE = f"/private/tmp/{CANARY}/profile"
HOME = f"/private/tmp/{CANARY}/home"
URL = f"http://127.0.0.1:12345/{CANARY}/"


@pytest.fixture(autouse=True)
def no_live_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Only invented Chrome reference operations are permitted")

    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit, "LocalServer", forbidden)
    monkeypatch.setattr(kit, "installed_images", forbidden)


def _manifest() -> kit.Manifest:
    images = []
    for index, (kind, path, identifier) in enumerate(
        (
            ("MAIN", str(kit.APP / "Contents/MacOS/Google Chrome"), "com.google.Chrome"),
            ("RENDERER", f"/Applications/{CANARY}/Renderer", "com.google.Chrome.helper.renderer"),
            ("GPU", f"/Applications/{CANARY}/GPU", "com.google.Chrome.helper.GPU"),
            ("HELPER", f"/Applications/{CANARY}/Helper", "com.google.Chrome.helper"),
            ("CRASHPAD", f"/Applications/{CANARY}/crashpad", "com.google.Chrome.crashpad_handler"),
            ("XPCPROXY", "/usr/libexec/xpcproxy", "com.apple.xpc.proxy"),
        )
    ):
        images.append(
            kit.Image(
                kind=kind,
                path=path,
                image=kit.reference.Image(device=123, inode=8000 + index, sha256="a" * 64),
                signing_id=identifier,
                team_id=None if kind == "XPCPROXY" else "EQHXZ8M8AV",
                entitlements={"com.apple.security.cs.allow-jit": True}
                if kind in {"RENDERER", "GPU"}
                else {},
            )
        )
    return kit.Manifest(
        os_version="27.0",
        os_build=CANARY,
        uid=501,
        gid=20,
        images=tuple(images),
        marker=kit.reference.Image(device=123, inode=9999, sha256="b" * 64),
        guard_sha256="c" * 64,
        codec_sha256="d" * 64,
        code_sha256={},
        version="155.0.8059.80",
    )


def _chain() -> list[dict]:
    manifest = _manifest()
    rows: list[dict] = []
    boot = _process(11, 1, 0)
    boot["executable"]["path"] = "/sbin/launchd"

    def fork(parent: dict, pid: int) -> dict:
        child = deepcopy(parent)
        child["audit_token"]["pid"] = pid
        child["audit_token"]["pidversion"] = 10000 + pid
        child["parent_audit_token"] = deepcopy(parent["audit_token"])
        child["ppid"] = child["original_ppid"] = parent["audit_token"]["pid"]
        row = _record(11, "fork")
        row["process"], row["event"]["fork"]["child"] = deepcopy(parent), deepcopy(child)
        rows.append(row)
        return child

    def execute(before: dict, kind: str, args: list[str]) -> dict:
        policy = next(image for image in manifest.images if image.kind == kind)
        target = deepcopy(before)
        target["audit_token"]["pidversion"] += 1
        target["executable"] = _file(policy.path)
        target["executable"]["stat"]["st_ino"] = policy.image.inode
        target["signing_id"], target["team_id"] = policy.signing_id, policy.team_id
        target["cdhash"] = f"{policy.image.inode:040x}"
        target["responsible_audit_token"] = deepcopy(target["audit_token"])
        row = _record(11, "exec")
        row["process"] = deepcopy(before)
        row["event"]["exec"].update(
            target=deepcopy(target),
            args=[policy.path, *args],
            env=[f"UNKNOWN={CANARY}"],
            fds=[{"fd": index, "fdtype": 1} for index in range(3)],
            last_fd=2,
            dyld_exec_path=policy.path,
            cwd=_file("/"),
            entitlements=policy.entitlements,
        )
        rows.append(row)
        return target

    def exit_process(process: dict) -> None:
        row = _record(11, "exit")
        row["process"] = deepcopy(process)
        row["event"]["exit"]["stat"] = 0
        rows.append(row)

    launcher = execute(fork(boot, 1200), "XPCPROXY", [CANARY])
    main = execute(
        launcher, "MAIN", [f"--user-data-dir={PROFILE}", *kit.MAIN_FLAGS, "--new-window", URL]
    )
    for pid, kind, args in (
        (1300, "RENDERER", ["--type=renderer", "--renderer-client-id=7"]),
        (1301, "GPU", ["--type=gpu-process", "--gpu-preferences=" + CANARY]),
        (1302, "HELPER", ["--type=utility", "--utility-sub-type=network.mojom.NetworkService"]),
    ):
        target = execute(fork(main, pid), kind, args)
        exit_process(target)
    exit_process(main)
    sequence: dict[int, int] = {}
    for index, row in enumerate(rows):
        kind = row["event_type"]
        row["global_seq_num"] = index + 1
        row["seq_num"] = sequence.get(kind, 0)
        sequence[kind] = row["seq_num"] + 1
    return rows


def _raws(rows: list[dict]) -> list[bytes]:
    return [json.dumps(row).encode() for row in rows]


def _track(rows: list[dict]) -> kit.Tracker:
    tracker = kit.Tracker(_manifest(), PROFILE, URL)
    tracker.collecting = True
    for raw in _raws(rows):
        assert tracker.accept(raw) == []
    return tracker


def test_complete_owned_graph_is_retained_only_after_nonce_browser_exec() -> None:
    rows = _chain()
    tracker = kit.Tracker(_manifest(), PROFILE, URL)
    tracker.collecting = True
    for raw in _raws(rows[:2]):
        tracker.accept(raw)
        assert not tracker.records
    for raw in _raws(rows[2:]):
        tracker.accept(raw)
    assert tracker.records == _raws(rows)
    assert tracker.main_exit and tracker.sequence_ok
    phases = kit.analyze(tracker.records, _manifest(), PROFILE, URL, HOME)
    assert len(phases) == len(rows)
    assert all(phase.native_shape == "PASS" for phase in phases)
    assert all(phase.shape_excluding_entitlements == "PASS" for phase in phases)
    assert {phase.after.role for phase in phases if phase.kind == "EXEC"} == {
        "XPCPROXY",
        "MAIN",
        "RENDERER",
        "GPU",
        "NETWORK",
    }
    assert all(phase.exec_identity_transition == "PASS" for phase in phases if phase.kind == "EXEC")
    rendered = kit.Report(phases=phases).model_dump_json()
    assert CANARY not in rendered and PROFILE not in rendered and URL not in rendered
    assert "EQHXZ8M8AV" not in rendered
    assert '"ROOT"' in rendered
    assert '"installed_signature_agreement":"PASS"' in rendered


@pytest.mark.parametrize(
    "damage", ["profile", "url", "file", "path", "signature", "team", "truncated", "role"]
)
def test_unrelated_or_unproven_main_never_reaches_private_disk(damage: str) -> None:
    rows = _chain()
    payload = rows[2]["event"]["exec"]
    target = payload["target"]
    if damage == "profile":
        payload["args"][1] += "-other"
    elif damage == "url":
        payload["args"][-1] += "other"
    elif damage == "file":
        target["executable"]["stat"]["st_ino"] += 1
    elif damage == "path":
        target["executable"]["path"] += "-other"
        target["executable"]["stat"]["st_ino"] += 1
    elif damage == "signature":
        target["signing_id"] = CANARY
    elif damage == "team":
        target["team_id"] = CANARY
    elif damage == "truncated":
        target["executable"]["path_truncated"] = True
    else:
        payload["args"].append("--type=renderer")
    assert _track(rows).records == []


@pytest.mark.parametrize("damage", ["pid_version", "birth", "file", "hash", "path", "signature"])
def test_pid_only_or_different_loaded_image_cannot_admit_ambient_fork(damage: str) -> None:
    rows = _chain()
    ambient = deepcopy(rows[3])
    process = ambient["process"]
    if damage == "pid_version":
        process["audit_token"]["pidversion"] += 9
    elif damage == "birth":
        process["start_time"] = "2026-01-01T00:00:00Z"
    elif damage == "file":
        process["executable"]["stat"]["st_ino"] += 9
    elif damage == "hash":
        process["cdhash"] = "f" * 40
    elif damage == "path":
        process["executable"]["path"] += CANARY
    else:
        process["signing_id"] = CANARY
    ambient["global_seq_num"] = 1000
    tracker = _track(rows[:3])
    tracker.accept(json.dumps(ambient).encode())
    assert json.dumps(ambient).encode() not in tracker.records


def test_missing_fork_can_use_exact_parent_token_without_fabricating_fork() -> None:
    rows = _chain()
    no_fork = rows[:3] + rows[4:]
    tracker = _track(no_fork)
    assert rows[4]["global_seq_num"] in tracker.retained_sequences
    assert not tracker.sequence_ok
    assert len(tracker.records) == len(no_fork)
    phases = kit.analyze(tracker.records, _manifest(), PROFILE, URL, HOME)
    assert len([phase for phase in phases if phase.kind == "FORK"]) == 3


def test_exact_parent_token_required_for_vendor_helper_without_fork() -> None:
    rows = _chain()
    rows[4]["event"]["exec"]["target"]["parent_audit_token"]["pidversion"] += 10
    tracker = _track(rows[:3] + rows[4:6])
    assert tracker.records == _raws(rows[:3])


def test_unknown_descendant_requires_proved_fork_and_exports_only_other() -> None:
    rows = _chain()
    rows[4]["event"]["exec"]["target"]["signing_id"] = CANARY
    rows[4]["event"]["exec"]["target"]["executable"]["path"] = f"/private/{CANARY}/unknown"
    rows[4]["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] += 100
    tracker = _track(rows[:5])
    assert len(tracker.records) == 5
    phases = kit.analyze(tracker.records, _manifest(), PROFILE, URL, HOME)
    assert phases[-1].after.role == "OTHER"
    assert CANARY not in kit.Report(phases=phases).model_dump_json()
    assert _track(rows[:3] + rows[4:5]).records == _raws(rows[:3])


def test_earlier_impossible_helper_is_not_admitted_by_later_parent_proof() -> None:
    rows = _chain()
    helper = deepcopy(rows[4])
    helper["global_seq_num"] = 0
    tracker = _track([helper, *rows[:3]])
    assert json.dumps(helper).encode() not in tracker.records


def test_readiness_requires_owned_marker_expected_pid_and_zero_exit() -> None:
    tracker = kit.Tracker(_manifest(), PROFILE, URL)
    execute, exit_row = deepcopy(_chain()[2]), deepcopy(_chain()[-1])
    payload = execute["event"]["exec"]
    payload["target"]["executable"]["stat"]["st_ino"] = 9999
    payload["args"] = [f"/private/{CANARY}/ready-marker", "--ready"]
    exit_row["process"] = deepcopy(payload["target"])
    tracker.ready_pids.add(1200)
    tracker.accept(json.dumps(execute).encode())
    assert not tracker.ready
    tracker.accept(json.dumps(exit_row).encode())
    assert tracker.ready and tracker.records == []


@pytest.mark.parametrize("field", ["seq_num", "global_seq_num"])
def test_sequence_gaps_are_never_a_complete_pass(field: str) -> None:
    rows = _chain()
    rows[5][field] += 10
    assert not _track(rows).sequence_ok


def test_bounds_fail_explicitly_and_eviction_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kit, "MAX_ROWS", 4)
    with pytest.raises(kit.reference.PrivateError, match="LIMIT"):
        _track(_chain())
    monkeypatch.setattr(kit, "MAX_ROWS", 256)
    monkeypatch.setattr(kit, "MAX_STREAM", 1)
    with pytest.raises(kit.reference.PrivateError, match="LIMIT"):
        _track(_chain())
    monkeypatch.setattr(kit, "MAX_STREAM", 256 * kit.MAX_LINE)
    monkeypatch.setattr(kit, "MAX_RING_ROWS", 1)
    tracker = _track(_chain()[:3])
    assert tracker.ring_evicted and len(tracker.records) == 1


def test_unknown_entitlement_names_and_values_stay_hidden_and_types_stay_exact() -> None:
    image = _manifest().images[1]
    diagnostic = kit.classify_entitlements(
        {
            "entitlements": {
                "com.apple.security.cs.allow-jit": 1,
                CANARY: CANARY,
            }
        },
        image,
    )
    assert diagnostic.matches_installed_code == "FAIL"
    assert diagnostic.known_booleans[0].value == "OTHER"
    assert diagnostic.other_keys == "PRESENT"
    assert CANARY not in diagnostic.model_dump_json()
    equal = kit.classify_entitlements({"entitlements": image.entitlements}, image)
    assert equal.matches_installed_code == "PASS" and equal.other_keys == "ABSENT"
    empty = kit.classify_entitlements({"entitlements": None}, _manifest().images[0])
    assert empty.matches_installed_code == "PASS" and empty.representation == "NULL"


def test_full_shape_is_distinct_from_shape_excluding_unknown_entitlements() -> None:
    rows = _chain()[:3]
    rows[2]["event"]["exec"]["entitlements"] = {CANARY: {CANARY: CANARY}}
    phase = kit.analyze(_raws(rows), _manifest(), PROFILE, URL, HOME)[-1]
    assert phase.native_shape == "FAIL" and phase.shape_excluding_entitlements == "PASS"
    assert CANARY not in phase.model_dump_json()


def test_argument_values_remain_hidden_but_public_role_and_fd_positions_are_usable() -> None:
    payload = deepcopy(_chain()[4]["event"]["exec"])
    payload["args"] += [
        "--seatbelt-client=5",
        f"--unknown-{CANARY}={CANARY}",
        CANARY,
        "--lang=" + CANARY,
    ]
    result = kit.classify_arguments(payload, PROFILE, URL)
    assert result.other_switches == result.other_positionals == "PRESENT"
    assert next(s for s in result.known if s.name == "seatbelt-client").descriptor_slot == "FD5"
    assert next(s for s in result.known if s.name == "type").value == "RENDERER"
    assert CANARY not in result.model_dump_json()


def test_descriptor_aliases_preserve_pipe_relations_without_pipe_ids() -> None:
    payload = {
        "fds": [
            {"fd": 0, "fdtype": 1},
            {"fd": 4, "fdtype": 6, "pipe": {"pipe_id": 12345}},
            {"fd": 5, "fdtype": 6, "pipe": {"pipe_id": 12345}},
        ],
        "last_fd": 5,
    }
    descriptors, valid, last = kit._descriptors(payload, {})
    assert valid == last == "PASS"
    assert [fd.slot for fd in descriptors] == ["FD0", "FD4", "FD5"]
    assert descriptors[1].pipe == descriptors[2].pipe == "A"
    assert "12345" not in json.dumps([fd.model_dump() for fd in descriptors])


@pytest.mark.parametrize("damage", ["duplicate", "missing_pipe", "invalid_fd", "extent"])
def test_invalid_descriptor_inventories_are_not_accepted(damage: str) -> None:
    payload = {"fds": [{"fd": 0, "fdtype": 1}], "last_fd": 0}
    if damage == "duplicate":
        payload["fds"] *= 2
    elif damage == "missing_pipe":
        payload["fds"][0]["fdtype"] = 6
    elif damage == "invalid_fd":
        payload["fds"][0]["fd"] = -1
    else:
        payload["fds"] *= 65
    assert kit._descriptors(payload, {})[1] == "FAIL"


def test_short_console_output_and_closed_report_schema(capsys: pytest.CaptureFixture[str]) -> None:
    report = kit.Report(phases=kit.analyze(_raws(_chain()), _manifest(), PROFILE, URL, HOME))
    kit._emit(report)
    printed = json.loads(capsys.readouterr().out)
    assert "phases" not in printed and printed["detail_report"] == "SHAREABLE-CHROME-REPORT.json"
    kit._emit(report, full=True)
    assert len(json.loads(capsys.readouterr().out)["phases"]) == len(_chain())
    with pytest.raises(ValidationError):
        kit.Report(error=CANARY)
    with pytest.raises(ValidationError):
        kit.Descriptor(slot=CANARY, kind="VNODE", pipe="NOT_PIPE")


def test_launch_command_selects_one_new_profile_without_debugging_or_sandbox_bypass() -> None:
    command = kit._launch_command(Path(PROFILE), URL)
    assert command[:5] == ["/usr/bin/open", "-n", "-a", str(kit.APP), "--args"]
    assert f"--user-data-dir={PROFILE}" in command and command[-1] == URL
    assert "--use-mock-keychain" in command and "--disable-background-networking" in command
    assert not any("debugging" in argument or argument == "--no-sandbox" for argument in command)


def test_code_only_prepare_is_fresh_and_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "code-only"
    original = kit.reference._outside_git
    monkeypatch.setattr(kit.reference, "_outside_git", lambda _path: None)
    result = kit.prepare(destination)
    assert result == destination
    assert set(path.name for path in result.iterdir()) == {*kit.CODE, "PRIVATE-RUN.md"}
    assert result.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in result.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(destination)
    monkeypatch.setattr(kit.reference, "_outside_git", original)


def test_missing_capture_attestations_fail_without_live_operations(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert kit.main(["capture", "--private-run"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == "INPUT"


def test_fixed_server_routes_serve_no_files_and_ignore_private_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = SimpleNamespace(
        nonce="0" * 32, requests=0, page=False, fetch=False, webgl="NOT_OBSERVED"
    )
    handler = object.__new__(kit.LocalHandler)
    handler.server = server
    handler.wfile = io.BytesIO()
    statuses: list[int] = []
    monkeypatch.setattr(handler, "send_response", statuses.append)
    monkeypatch.setattr(handler, "send_header", lambda *_args: None)
    monkeypatch.setattr(handler, "end_headers", lambda: None)
    handler.path = f"/{server.nonce}/"
    handler.do_GET()
    assert statuses[-1] == 200 and server.page
    assert b"webgl2" in handler.wfile.getvalue()
    handler.path += "probe"
    handler.do_GET()
    assert statuses[-1] == 204 and server.fetch
    handler.path = f"/{server.nonce}/gl-created"
    handler.do_GET()
    assert server.webgl == "CREATED"
    handler.path = f"/{server.nonce}/../../{CANARY}"
    handler.do_GET()
    assert statuses[-1] == 404 and CANARY.encode() not in handler.wfile.getvalue()
    server.requests = 128
    handler.path = f"/{server.nonce}/"
    handler.do_GET()
    assert statuses[-1] == 404


def _fake_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, failure: str = ""
) -> tuple[kit.Report, list[str]]:
    """Exercise the actual controller/files using fake processes, clock and server."""
    manifest = _manifest()
    events: list[str] = []
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        kit.reference, "_preflight", lambda: (manifest.os_version, manifest.os_build)
    )

    def get_manifest(_root: Path, *, installed: bool) -> kit.Manifest:
        events.append("verify_installed" if installed else "verify_offline")
        return manifest

    monkeypatch.setattr(kit, "_manifest", get_manifest)

    class Process:
        pid = 4444
        stdout = io.BytesIO()

        def __init__(self, status: int = 0) -> None:
            self.status = status

        def poll(self) -> int:
            return self.status

    def start_process(args: list[str], **kwargs: object) -> Process:
        assert kwargs["stderr"] == kit.subprocess.DEVNULL
        if args[0] == "/usr/bin/open":
            events.append("open")
            assert str(tmp_path) in str(kwargs["env"])
        else:
            assert args[0:2] == ["/usr/bin/sudo", "-n"]
            events.append("collector")
        return Process(1 if failure == "launch" and args[0] == "/usr/bin/open" else 0)

    monkeypatch.setattr(kit.subprocess, "Popen", start_process)
    monkeypatch.setattr(kit.reference, "_start", lambda *_args: Process())
    monkeypatch.setattr(
        kit.reference, "_stop_probe", lambda _proc: events.append("stop_owned_subprocess")
    )

    def stop_collector(_proc: Process) -> bool:
        events.append("stop_collector")
        return failure != "cleanup"

    monkeypatch.setattr(kit.reference, "_stop_collector", stop_collector)
    ticks = iter(range(10000))
    monkeypatch.setattr(kit.time, "monotonic", lambda: float(next(ticks)))

    class Server:
        server_port = 12345
        page = fetch = True
        webgl = "CREATED"

        def __init__(self, _nonce: str) -> None:
            pass

        def serve_forever(self, **_kwargs: object) -> None:
            pass

        def shutdown(self) -> None:
            events.append("stop_server")

        def server_close(self) -> None:
            events.append("close_server")

    class Thread:
        def __init__(self, **_kwargs: object) -> None:
            self.target = _kwargs["target"]

        def start(self) -> None:
            if self.target.__name__ == "shutdown":
                self.target()

        def join(self, **_kwargs: object) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(kit, "LocalServer", Server)
    monkeypatch.setattr(kit.threading, "Thread", Thread)

    class Pump:
        def __init__(self, _process: Process, tracker: kit.Tracker, _files: dict) -> None:
            self.tracker = tracker
            self.selector = SimpleNamespace(close=lambda: events.append("close_selector"))
            self.sent = False
            self.ticks = 0

        def tick(self) -> None:
            if failure == "collector":
                raise kit.reference.PrivateError("COLLECTOR")
            if not self.tracker.collecting:
                self.tracker.ready = True
                return
            if failure == "interrupt":
                raise KeyboardInterrupt
            rows = _chain()
            rows[2]["event"]["exec"]["args"] = [
                manifest.images[0].path,
                f"--user-data-dir={self.tracker.profile}",
                *kit.MAIN_FLAGS,
                "--new-window",
                self.tracker.url,
            ]
            if not self.sent:
                for raw in _raws(rows[:-1]):
                    self.tracker.accept(raw)
                self.sent = True
            if self.ticks == 5 and failure != "timeout":
                self.tracker.accept(_raws(rows[-1:])[0])
            self.ticks += 1

    monkeypatch.setattr(kit.reference, "Pump", Pump)
    return kit.capture(), events


def test_controller_cleanup_precedes_code_verification_and_shareable_file_is_outer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, events = _fake_capture(tmp_path, monkeypatch)
    assert report.error == "NONE" and report.stage == "COMPLETE"
    assert (
        report.main_exec == report.renderer_exec == report.gpu_exec == report.network_exec == "PASS"
    )
    assert report.collector_cleanup == report.server_cleanup == report.main_exit_seen == "PASS"
    assert events.index("stop_collector") < len(events) - 1
    assert events[-1] == "verify_installed"
    assert events.index("close_server") < len(events) - 1
    assert not (tmp_path / "SESSION-LOCK").exists()
    saved = kit.Report.model_validate_json((tmp_path / "SHAREABLE-CHROME-REPORT.json").read_bytes())
    assert saved == report and CANARY not in saved.model_dump_json()
    assert all(path.stat().st_mode & 0o077 == 0 for path in tmp_path.rglob("*.json*"))
    assert kit.report_existing() == report
    assert events[-1] == "verify_offline"


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("collector", "COLLECTOR"),
        ("launch", "LAUNCH"),
        ("interrupt", "INTERRUPTED"),
        ("timeout", "TIMEOUT"),
        ("cleanup", "COLLECTOR"),
    ],
)
def test_controller_failures_still_stop_collector_server_and_keep_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected: str,
) -> None:
    report, events = _fake_capture(tmp_path, monkeypatch, failure=failure)
    assert report.error == expected and report.stage == "ERROR"
    assert "stop_collector" in events and "stop_server" in events and "close_server" in events
    assert (tmp_path / "SESSION-LOCK").exists()
    assert CANARY not in (tmp_path / "SHAREABLE-CHROME-REPORT.json").read_text()


def test_duplicate_personal_profile_override_is_not_admitted() -> None:
    rows = _chain()
    rows[2]["event"]["exec"]["args"].insert(2, f"--user-data-dir=/{CANARY}/personal-profile")
    assert not _track(rows).records


def test_installed_file_identity_handles_a_different_native_path_spelling() -> None:
    rows = _chain()[:3]
    target = rows[2]["event"]["exec"]["target"]
    target["executable"]["path"] = f"/Applications/{CANARY}/known-file-alias"
    tracker = _track(rows)
    assert len(tracker.records) == 3
    phase = kit.analyze(tracker.records, _manifest(), PROFILE, URL, HOME)[-1]
    assert phase.after.installed_image_agreement == "PASS"
    assert phase.after.installed_path_spelling == "OTHER"
    assert CANARY not in phase.model_dump_json()


@pytest.mark.parametrize("word", ["pid", "pidversion", "birth"])
def test_invalid_helper_replacement_does_not_authenticate_another_execution(word: str) -> None:
    rows = _chain()[:5]
    target = rows[-1]["event"]["exec"]["target"]
    if word == "birth":
        target["start_time"] = "2026-01-01T00:00:00Z"
    else:
        target["audit_token"][word] += 1
    tracker = _track(rows)
    assert len(tracker.records) == 4


def test_native_phase_and_lifetime_counts_do_not_conflate_two_execs_with_two_births() -> None:
    report = kit._analyzed_report(kit.Report(), _raws(_chain()), _manifest(), PROFILE, URL, HOME)
    assert (report.forks_observed, report.execs_observed, report.exits_observed) == (4, 5, 4)
    assert report.exec_lifetimes_without_fork == report.fork_lifetimes_without_exec == 0
    assert report.started_lifetimes_without_exit == 0


def test_vendor_metadata_query_verifies_code_without_opening_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _manifest().images[1]
    monkeypatch.setattr(kit.support, "_installed_image", lambda _path: expected.image)
    commands: list[list[str]] = []

    def output(args: list[str]) -> SimpleNamespace:
        import plistlib

        commands.append(args)
        return SimpleNamespace(
            stdout=plistlib.dumps(expected.entitlements) if "-d" in args else b"",
            stderr=f"Identifier={expected.signing_id}\nTeamIdentifier={expected.team_id}\n".encode(),
        )

    monkeypatch.setattr(kit, "_code_output", output)
    actual = kit._installed(expected.kind, Path(expected.path))
    assert actual == expected
    assert commands[0][0:3] == ["/usr/bin/codesign", "--verify", "--strict"]
    assert "anchor apple generic" in commands[0][-2]
    assert all(command[-1] == expected.path for command in commands)


def test_report_size_limit_is_an_explicit_refusal_not_a_successful_partial_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = kit.Report(phases=kit.analyze(_raws(_chain()), _manifest(), PROFILE, URL, HOME))
    monkeypatch.setattr(kit, "MAX_REPORT_BYTES", 2000)
    bounded, raw = kit._bounded_report(report)
    assert bounded.error == "LIMIT" and bounded.stage == "ERROR" and bounded.phases == ()
    assert CANARY.encode() not in raw
