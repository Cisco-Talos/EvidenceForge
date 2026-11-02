# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented data only; all commands, installed-code queries and collectors are forbidden."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_chrome_review as kit

from tests.unit.test_macos_chrome_reference import CANARY, HOME, PROFILE, URL, _chain, _manifest


@pytest.fixture(autouse=True)
def no_live_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline Chrome review cannot start commands or query installed code")

    monkeypatch.setattr(kit.capture.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.capture.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.capture, "LocalServer", forbidden)
    monkeypatch.setattr(kit.capture, "installed_images", forbidden)
    monkeypatch.setattr(kit.capture.support, "_installed_image", forbidden)
    monkeypatch.setattr(kit.reference, "_preflight", forbidden)
    monkeypatch.setattr(kit.reference, "_write", forbidden)
    monkeypatch.setattr(kit.reference, "_replace", forbidden)


def _analyzed(rows: list[dict]) -> object:
    return kit.capture._analyzed_report(
        kit.capture.Report(),
        [json.dumps(row).encode() for row in rows],
        _manifest(),
        PROFILE,
        URL,
        HOME,
    )


def test_fixed_review_corrects_generic_gpu_without_changing_physical_image() -> None:
    rows = _chain(gpu_image="HELPER")
    original = _analyzed(rows)
    original = original.model_copy(
        update={
            "gpu_exec": "FAIL",
            "phases": tuple(
                phase.model_copy(update={"after": phase.after.model_copy(update={"role": "OTHER"})})
                if phase.kind == "EXEC" and phase.after.role == "GPU"
                else phase
                for phase in original.phases
            ),
        }
    )
    report = kit.analyze(_manifest(), original, rows)
    assert report.original_gpu_exec == "FAIL" and report.corrected_gpu_exec == "PASS"
    gpu = next(item for item in report.executions if item.operational_role == "GPU")
    assert gpu.original_role == "OTHER" and gpu.installed_image == "HELPER"
    assert gpu.known_image_security == gpu.known_image_entitlements == "PASS"
    assert gpu.pid_preserved == gpu.birth_preserved == "PASS"
    assert gpu.changed_version_lifetime_agreement == "PASS"
    assert not report.exceptional_lifetimes
    text = report.model_dump_json()
    assert kit.Report.model_validate_json(text) == report
    for secret in (CANARY, PROFILE, HOME, URL, "EQHXZ8M8AV", "10000", "/Applications"):
        assert secret not in text


@pytest.mark.parametrize(
    ("version", "label", "agreement"),
    [(20000, "INCREASED_WITH_GAP", "PASS"), (1, "DECREASED", "PASS"), (11300, "SAME", "FAIL")],
)
def test_version_relation_is_separate_from_lifetime_and_never_exports_a_number(
    version: int, label: str, agreement: str
) -> None:
    rows = _chain()[:5]
    rows[-1]["event"]["exec"]["target"]["audit_token"]["pidversion"] = version
    result = kit.analyze(_manifest(), _analyzed(rows), rows).executions[-1]
    assert result.version_relation == label
    assert result.changed_version_lifetime_agreement == agreement
    assert result.pid_preserved == result.birth_preserved == "PASS"
    assert str(version) not in result.model_dump_json()


def test_fork_only_intermediary_and_unclosed_child_are_explicit_without_invented_execs() -> None:
    rows = _chain()
    fork_only = deepcopy(rows[3])
    fork_only["event"]["fork"]["child"]["audit_token"]["pid"] = 9001
    fork_only["event"]["fork"]["child"]["audit_token"]["pidversion"] = 20001
    fork_only["global_seq_num"] = 90
    fork_again = deepcopy(fork_only)
    fork_again["process"] = deepcopy(fork_only["event"]["fork"]["child"])
    fork_again["event"]["fork"]["child"]["audit_token"]["pid"] = 9002
    fork_again["event"]["fork"]["child"]["audit_token"]["pidversion"] = 20002
    fork_again["global_seq_num"] = 91
    ending = deepcopy(rows[-1])
    ending["process"] = deepcopy(fork_again["process"])
    ending["global_seq_num"] = 92
    rows += [fork_only, fork_again, ending]
    report = kit.analyze(_manifest(), _analyzed(rows), rows)
    assert len(report.exceptional_lifetimes) == 2
    intermediary, child = report.exceptional_lifetimes
    assert intermediary.fork_observed == intermediary.exit_observed == "PASS"
    assert intermediary.exec_observed == "FAIL" and intermediary.ending == "EXITED"
    assert intermediary.forked_children == (child.first_execution,)
    assert child.fork_observed == "PASS" and child.exit_observed == child.exec_observed == "FAIL"
    assert child.ending == "NO_RETAINED_EXIT"
    assert (
        intermediary.missing_exec_conclusion == child.missing_exec_conclusion == "NOT_ESTABLISHED"
    )
    assert report.discarded_records_recoverable == "NO"


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("/usr/bin/sw_vers", "SW_VERS"),
        ("/usr/sbin/sysctl", "SYSCTL"),
        (f"/private/{CANARY}", "OTHER"),
    ],
)
def test_unqualified_path_comparison_does_not_claim_installed_code_qualification(
    path: str, label: str
) -> None:
    rows = _chain()[:5]
    target = rows[-1]["event"]["exec"]["target"]
    target["executable"]["stat"]["st_ino"] += 100
    target["executable"]["path"] = path
    result = kit.analyze(_manifest(), _analyzed(rows), rows).executions[-1]
    assert result.public_path == label
    assert (
        result.installed_image == "UNQUALIFIED" and result.public_path_is_code_qualification == "NO"
    )
    assert result.known_image_security == result.known_image_entitlements == "INCONCLUSIVE"
    assert CANARY not in result.model_dump_json()


@pytest.mark.parametrize(
    "suffix", ["Aperitif", "Aperitif Renderer", "Aperitif GPU", "Aperitif Alerts"]
)
def test_aperitif_public_path_is_exact_and_version_bound(suffix: str) -> None:
    rows = _chain()[:5]
    process = rows[-1]["event"]["exec"]["target"]
    name = f"Google Chrome Helper ({suffix})"
    path = (
        kit.capture.APP
        / ("Contents/Frameworks/Google Chrome Framework.framework/Versions/155.0.8059.80/Helpers")
        / f"{name}.app/Contents/MacOS/{name}"
    )
    process["executable"]["stat"]["st_ino"] += 100
    process["executable"]["path"] = str(path)
    assert kit._public_path(process, _manifest()) == suffix.upper().replace(" ", "_")
    process["executable"]["path"] = str(path).replace("155.0.8059.80", "100.0.0.0")
    assert kit._public_path(process, _manifest()) == "OTHER"


@pytest.mark.parametrize("value", ["100", "not-a-fd", CANARY, "9" * 15])
def test_descriptor_arguments_compare_large_slots_without_exporting_observed_values(
    value: str,
) -> None:
    rows = _chain()[:5]
    payload = rows[-1]["event"]["exec"]
    payload["args"] += [f"--seatbelt-client={value}"]
    payload["fds"] += [{"fd": 100, "fdtype": 6, "pipe": {"pipe_id": 123456}}]
    descriptor = kit._descriptor_argument(payload, "seatbelt-client")
    assert descriptor.retained_descriptor == ("PASS" if value == "100" else "FAIL")
    assert descriptor.kind == ("PIPE" if value == "100" else "NOT_OBSERVED")
    assert value not in descriptor.model_dump_json()
    payload["args"].append("--seatbelt-client=100")
    assert kit._descriptor_argument(payload, "seatbelt-client").presence == "AMBIGUOUS"


def _saved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "invented"
    root.mkdir(mode=0o700)
    expected: dict[str, str] = {}
    for name in kit.capture.CODE:
        raw = f"trusted invented code {name}".encode()
        (root / name).write_bytes(raw)
        (root / name).chmod(0o600)
        expected[name] = hashlib.sha256(raw).hexdigest()
    for name in ("ready-marker", "collector-guard"):
        (root / name).write_bytes(b"invented control")
        (root / name).chmod(0o600)
    manifest = _manifest().model_copy(
        update={
            "marker": kit.reference._image(root / "ready-marker"),
            "guard_sha256": kit.reference._digest(root / "collector-guard"),
            "codec_sha256": kit.reference._codec_digest(),
            "code_sha256": expected,
        }
    )
    run = root / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    (root / "ACTIVE-RUN").write_text(run.name)
    profile, home, url = (
        str(run / "profile"),
        str(run / "home"),
        "http://127.0.0.1:12345/" + "b" * 32 + "/",
    )
    rows = _chain()
    rows[2]["event"]["exec"]["args"] = [
        arg.replace(PROFILE, profile).replace(URL, url) for arg in rows[2]["event"]["exec"]["args"]
    ]
    raws = [json.dumps(row).encode() for row in rows]
    report = kit.capture._analyzed_report(
        kit.capture.Report(
            stage="COMPLETE",
            step="COMPLETE",
            **{
                key: "PASS"
                for key in (
                    "target_platform",
                    "provenance",
                    "collector_ready",
                    "collector_cleanup",
                    "server_cleanup",
                    "bounded_collection",
                    "sequence_continuity",
                    "main_exit_seen",
                    "controlled_page",
                    "controlled_fetch",
                )
            },
        ),
        raws,
        manifest,
        profile,
        url,
        home,
    )
    for path, raw in (
        (root / "SETUP.json", manifest.model_dump_json().encode()),
        (
            run / "provenance.json",
            json.dumps(
                {
                    "setup": manifest.model_dump(),
                    "profile": profile,
                    "home": home,
                    "url": url,
                }
            ).encode(),
        ),
        (run / "SHAREABLE-CHROME-REPORT.json", report.model_dump_json().encode()),
        (run / "chrome-events.jsonl", b"\n".join(raws) + b"\n"),
    ):
        path.write_bytes(raw)
        path.chmod(0o600)
    (root / "ACTIVE-RUN").chmod(0o600)
    return root, expected


def test_verified_review_reads_only_declared_files_and_changes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, expected = _saved(tmp_path, monkeypatch)
    paths = [path for path in root.rglob("*") if path.is_file()]
    before = {path: path.read_bytes() for path in paths}
    read = kit.reference._read
    opened: set[Path] = set()

    def tracked(path: Path, *args: object) -> bytes:
        assert path in before
        opened.add(path)
        return read(path, *args)

    monkeypatch.setattr(kit.reference, "_read", tracked)
    report = kit.review_existing(root, expected)
    assert report.error == "NONE" and report.original_report_agreement == "PASS"
    assert report.exact_retained_graph == report.original_collection_controls == "PASS"
    assert report.commands == report.collectors == "NOT_STARTED"
    assert report.writes == "NONE" and report.profiles == "NOT_OPENED"
    assert not report.exceptional_lifetimes
    assert {path: path.read_bytes() for path in paths} == before
    assert {path.name for path in opened} == {
        "SETUP.json",
        "ACTIVE-RUN",
        "provenance.json",
        "SHAREABLE-CHROME-REPORT.json",
        "chrome-events.jsonl",
        *kit.capture.CODE,
        "ready-marker",
        "collector-guard",
    }
    assert CANARY not in report.model_dump_json()


@pytest.mark.parametrize(
    "damage",
    ["code", "control", "report", "provenance", "foreign_row", "sequence", "traversal", "symlink"],
)
def test_private_review_rejects_changed_or_unproven_inputs_without_echoing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    root, expected = _saved(tmp_path, monkeypatch)
    run = root / (root / "ACTIVE-RUN").read_text()
    if damage in {"code", "control"}:
        (root / (kit.capture.CODE[0] if damage == "code" else "ready-marker")).write_text(CANARY)
    elif damage == "report":
        path = run / "SHAREABLE-CHROME-REPORT.json"
        value = json.loads(path.read_bytes())
        value["gpu_exec"] = "FAIL"
        path.write_text(json.dumps(value))
    elif damage == "provenance":
        path = run / "provenance.json"
        value = json.loads(path.read_bytes())
        value["home"] = CANARY
        path.write_text(json.dumps(value))
    elif damage in {"foreign_row", "sequence"}:
        path = run / "chrome-events.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        if damage == "foreign_row":
            rows[-1]["process"]["audit_token"]["pidversion"] += 99
        else:
            rows[-1]["global_seq_num"] = 1
        path.write_text("\n".join(json.dumps(row) for row in rows))
    elif damage == "traversal":
        (root / "ACTIVE-RUN").write_text("../" + CANARY)
    else:
        path = run / "chrome-events.jsonl"
        path.rename(run / "hidden")
        path.symlink_to(run / "hidden")
    with pytest.raises((kit.reference.PrivateError, ValueError, OSError)) as error:
        kit.review_existing(root, expected)
    # The CLI suppresses native/parser exception messages.
    assert kit.main(["review-existing", "--private-run"]) == 2
    assert CANARY not in str(error.value) or damage == "symlink"


def test_fixed_schema_rejects_an_observed_string() -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({"purpose": CANARY})


def test_environment_exports_only_known_names_and_comparisons_with_controlled_values() -> None:
    rows = _chain()
    main = rows[2]["event"]["exec"]
    main["env"] += ["OSLogRateLimit=64", f"{CANARY}={CANARY}"]
    payload = rows[4]["event"]["exec"]
    payload["env"] = [
        "PATH=/usr/bin:/bin",
        f"HOME={HOME}",
        "OSLogRateLimit=64",
        f"__CF_USER_TEXT_ENCODING=0x{_manifest().uid:x}:0:0",
        "XPC_FLAGS=0x0",
        f"SECURITYSESSIONID={payload['target']['audit_token']['asid']}",
        "__CFBundleIdentifier=com.google.Chrome",
        "OS_ACTIVITY_MODE=disable",
        "XPC_SERVICE_NAME=application.com.google.Chrome.12345.54321",
        f"{CANARY}={CANARY}",
    ]
    result = kit._environment(payload, _manifest(), {"payload": main, "home": HOME})
    entries = {entry.key: entry.value for entry in result.entries}
    assert result.only_known_keys == "FAIL" and result.duplicate_keys == "ABSENT"
    assert entries["HOME"] == "TEST_HOME" and entries["PATH"] == "CONTROLLED"
    assert entries["OSLogRateLimit"] == "SIXTY_FOUR"
    assert entries["__CF_USER_TEXT_ENCODING"] == "LOCAL_USER_ZERO_ENCODING"
    assert entries["SECURITYSESSIONID"] == "LOCAL_AUDIT_SESSION"
    assert entries["XPC_SERVICE_NAME"] == "CHROME_APP_INSTANCE"
    assert result.from_main_exec.vectors_well_formed == "PASS"
    for secret in (CANARY, HOME, "12345", "54321", "0x1f5:0:0"):
        assert secret not in result.model_dump_json()
    payload["env"] += [f"HOME={CANARY}"]
    duplicate = kit._environment(payload, _manifest(), None)
    assert duplicate.duplicate_keys == "PRESENT"
    assert next(entry.value for entry in duplicate.entries if entry.key == "HOME") == "OTHER"


@pytest.mark.parametrize(
    ("values", "label"),
    [
        (["relauncher"], "RELAUNCHER"),
        ([CANARY], "OTHER"),
        (["renderer", "gpu-process"], "AMBIGUOUS"),
        ([], "ABSENT"),
    ],
)
def test_process_type_is_an_allowlisted_comparison(values: list[str], label: str) -> None:
    payload = _chain()[4]["event"]["exec"]
    payload["args"] = [payload["args"][0], *(f"--type={value}" for value in values)]
    assert kit._process_type(payload) == label


def test_prepare_pins_only_trusted_code_and_does_not_execute_or_open_a_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Preparation writes only fresh code. Review's no-write guard is relaxed here only.
    from scripts import macos_chrome_reference

    monkeypatch.setattr(kit.reference, "_write", macos_chrome_reference.reference._write)
    # The references are independent module instances; capture.prepare has its own writer.
    code_root = macos_chrome_reference.prepare(tmp_path / "code-only")
    result = kit.prepare(tmp_path / "reviewer", capture_code_kit=code_root)
    expected = json.loads((result / "OFFLINE-EXPECTED.json").read_bytes())
    assert set(expected) == set(kit.capture.CODE)
    for name in kit.capture.CODE:
        assert (result / name).read_bytes() == (code_root / name).read_bytes()
        assert hashlib.sha256((result / name).read_bytes()).hexdigest() == expected[name]
    assert (result / "private_chrome_review.py").is_file()
    assert not (result / "SETUP.json").exists() and not (result / "ACTIVE-RUN").exists()
