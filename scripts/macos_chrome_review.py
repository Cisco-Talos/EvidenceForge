# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a fixed-output offline review; reading a capture needs separate permission.

Review uses only the selected bounded capture, its provenance and controlled-kit
metadata. It starts no commands, collectors, apps or queries and writes nothing.
Unknown argument, environment, path and signing values never leave memory.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field


def _load_capture() -> ModuleType:
    path = Path(__file__).resolve().with_name("private_chrome.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_chrome_reference.py")
    spec = importlib.util.spec_from_file_location("_eforge_offline_chrome_capture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


capture = _load_capture()
reference = capture.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type ProcessType = Literal[
    "ABSENT", "RENDERER", "GPU", "UTILITY", "RELAUNCHER", "CRASHPAD_HANDLER", "OTHER", "AMBIGUOUS"
]
type Utility = Literal[
    "ABSENT",
    "NETWORK",
    "STORAGE",
    "AUDIO",
    "TRACING",
    "PROXY_RESOLVER",
    "DATA_DECODER",
    "VIDEO_CAPTURE",
    "ON_DEVICE_MODEL",
    "UNZIPPER",
    "OTHER",
    "AMBIGUOUS",
]
type PublicPath = Literal[
    "INSTALLED_IMAGE",
    "SW_VERS",
    "SYSCTL",
    "UNAME",
    "SYSTEM_PROFILER",
    "SHELL",
    "APERITIF",
    "APERITIF_RENDERER",
    "APERITIF_GPU",
    "APERITIF_ALERTS",
    "ALERTS",
    "APP_MODE_LOADER",
    "SHORTCUT_COPIER",
    "OTHER",
]

# These are independent public template comparisons, never exported observed names.
PROCESS_TYPES: dict[str, ProcessType] = {
    "renderer": "RENDERER",
    "gpu-process": "GPU",
    "utility": "UTILITY",
    "relauncher": "RELAUNCHER",
    "crashpad-handler": "CRASHPAD_HANDLER",
}
UTILITY_TYPES: dict[str, Utility] = {
    "network.mojom.NetworkService": "NETWORK",
    "storage.mojom.StorageService": "STORAGE",
    "audio.mojom.AudioService": "AUDIO",
    "tracing.mojom.TracingService": "TRACING",
    "proxy_resolver.mojom.ProxyResolverFactory": "PROXY_RESOLVER",
    "data_decoder.mojom.DataDecoderService": "DATA_DECODER",
    "video_capture.mojom.VideoCaptureService": "VIDEO_CAPTURE",
    "on_device_model.mojom.OnDeviceModelService": "ON_DEVICE_MODEL",
    "unzip.mojom.Unzipper": "UNZIPPER",
}
SYSTEM_PATHS: dict[str, PublicPath] = {
    "/usr/bin/sw_vers": "SW_VERS",
    "/usr/sbin/sysctl": "SYSCTL",
    "/usr/bin/uname": "UNAME",
    "/usr/sbin/system_profiler": "SYSTEM_PROFILER",
    "/bin/sh": "SHELL",
    "/bin/zsh": "SHELL",
}
ENVIRONMENT_KEYS = (
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "USER",
    "LOGNAME",
    "SHELL",
    "XPC_FLAGS",
    "XPC_SERVICE_NAME",
    "__CF_USER_TEXT_ENCODING",
    "SSH_AUTH_SOCK",
    "COMMAND_MODE",
    "__CFBundleIdentifier",
    "SECURITYSESSIONID",
    "MallocNanoZone",
    "OSLogRateLimit",
    "OS_ACTIVITY_DT_MODE",
    "OS_ACTIVITY_MODE",
    "NSUnbufferedIO",
    "CHROME_CRASHPAD_PIPE_NAME",
    "CHROME_CRASHPAD_HANDLER",
    "CHROME_HEADLESS",
    "CHROME_METRO_CONNECTED",
    "CHROME_VERSION_EXTRA",
)


class EnvironmentEntry(reference.Model):
    key: Literal[*ENVIRONMENT_KEYS]
    value: Literal[
        "CONTROLLED",
        "TEST_HOME",
        "CHROME_MAIN",
        "LOCAL_AUDIT_SESSION",
        "LOCAL_USER_ZERO_ENCODING",
        "ZERO",
        "ONE",
        "HEX_ZERO",
        "HEX_ONE",
        "SIXTY_FOUR",
        "UNIX2003",
        "DISABLE",
        "CHROME_APP_INSTANCE",
        "OTHER",
    ]


class EnvironmentDetails(reference.Model):
    vectors_well_formed: Check
    duplicate_keys: Literal["ABSENT", "PRESENT"]
    only_known_keys: Check
    entries: tuple[EnvironmentEntry, ...] = Field(default=(), max_length=len(ENVIRONMENT_KEYS))
    from_main_exec: reference.EnvironmentDifference | None = None


class DescriptorArgument(reference.Model):
    presence: Literal["ABSENT", "PRESENT", "AMBIGUOUS"] = "ABSENT"
    decimal: Check = "INCONCLUSIVE"
    retained_descriptor: Check = "INCONCLUSIVE"
    kind: Literal["VNODE", "PIPE", "SOCKET", "OTHER", "NOT_OBSERVED"] = "NOT_OBSERVED"


class Execution(reference.Model):
    before: capture.Alias
    after: capture.Alias
    original_role: capture.Role
    operational_role: capture.Role
    installed_image: capture.ImageKind | Literal["UNQUALIFIED"]
    public_path: PublicPath
    public_path_is_code_qualification: Literal["NO"] = "NO"
    pid_preserved: Check
    birth_preserved: Check
    version_relation: Literal["NEXT", "INCREASED_WITH_GAP", "DECREASED", "SAME"]
    changed_version_lifetime_agreement: Check
    process_type: ProcessType
    utility: Utility
    native_shape: Check
    known_image_security: Check
    known_image_entitlements: Check
    seatbelt: DescriptorArgument
    mojo_channel: DescriptorArgument
    environment: capture.Environment | None
    environment_details: EnvironmentDetails


class Lifetime(reference.Model):
    first_execution: capture.Alias
    last_execution: capture.Alias
    fork_observed: Check
    exec_observed: Check
    exit_observed: Check
    forked_children: tuple[capture.Alias, ...] = Field(default=(), max_length=64)
    ending: Literal["EXITED", "NO_RETAINED_EXIT"]
    missing_exec_conclusion: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"


class Report(reference.Model):
    review_version: Literal[1] = 1
    purpose: Literal["CHROME_PROCESS_GRAPH_OFFLINE_REVIEW"] = "CHROME_PROCESS_GRAPH_OFFLINE_REVIEW"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    error: capture.Error = "NONE"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    provenance: Check = "INCONCLUSIVE"
    original_collection_controls: Check = "INCONCLUSIVE"
    exact_retained_graph: Check = "INCONCLUSIVE"
    original_report_agreement: Check = "INCONCLUSIVE"
    original_gpu_exec: Check = "INCONCLUSIVE"
    corrected_gpu_exec: Check = "INCONCLUSIVE"
    executions: tuple[Execution, ...] = Field(default=(), max_length=capture.MAX_ROWS)
    exceptional_lifetimes: tuple[Lifetime, ...] = Field(default=(), max_length=64)
    discarded_records_recoverable: Literal["NO"] = "NO"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    commands: Literal["NOT_STARTED"] = "NOT_STARTED"
    live_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    profiles: Literal["NOT_OPENED"] = "NOT_OPENED"
    writes: Literal["NONE"] = "NONE"


def _model(path: Path, model: type, limit: int = capture.MAX_LINE) -> object:
    raw = reference._read(path, limit)
    reference._decode(raw)
    return model.model_validate_json(raw)


def _verified(root: Path, expected: dict[str, str]) -> tuple[object, object, list[dict]]:
    """Authenticate the original kit and selection without trusting arbitrary reports."""
    reference._outside_git(root)
    reference._directory(root)
    manifest = _model(root / "SETUP.json", capture.Manifest)
    if (
        set(expected) != set(capture.CODE)
        or manifest.code_sha256 != expected
        or any(reference._digest(root / name) != digest for name, digest in expected.items())
        or manifest.marker != reference._image(root / "ready-marker")
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.codec_sha256 != reference._codec_digest()
    ):
        raise reference.PrivateError("BUILD")
    name = reference._read(root / "ACTIVE-RUN", 128).decode("ascii").strip()
    if re.fullmatch(r"run-[0-9a-f]{32}", name) is None:
        raise reference.PrivateError("LOCATION")
    run = root / name
    reference._directory(run)
    provenance = reference._decode(reference._read(run / "provenance.json"))
    profile, home = str(run / "profile"), str(run / "home")
    if (
        set(provenance) != {"setup", "profile", "home", "url"}
        or provenance["setup"] != json.loads(manifest.model_dump_json())
        or provenance["profile"] != profile
        or provenance["home"] != home
        or type(provenance["url"]) is not str
        or re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/[0-9a-f]{32}/", provenance["url"]) is None
    ):
        raise reference.PrivateError("DATA")
    report = _model(run / "SHAREABLE-CHROME-REPORT.json", capture.Report, capture.MAX_REPORT_BYTES)
    if (
        report.error != "NONE"
        or report.stage != "COMPLETE"
        or report.wire_profile != "V11"
        or report.candidate_ring_evicted
        or any(
            getattr(report, key) != "PASS"
            for key in (
                "target_platform",
                "provenance",
                "collector_ready",
                "collector_cleanup",
                "server_cleanup",
                "bounded_collection",
                "sequence_continuity",
                "main_exec",
                "main_exit_seen",
                "controlled_page",
                "controlled_fetch",
            )
        )
    ):
        raise reference.PrivateError("DATA")
    raws = reference._read(
        run / "chrome-events.jsonl", capture.MAX_PRIVATE_BYTES + capture.MAX_ROWS
    ).splitlines()
    if (
        not 1 <= len(raws) <= capture.MAX_ROWS
        or sum(map(len, raws)) > capture.MAX_PRIVATE_BYTES
        or any(not raw or len(raw) > capture.MAX_LINE for raw in raws)
    ):
        raise reference.PrivateError("LIMIT")
    rows = [reference._decode(raw) for raw in raws]
    sequences = [row.get("global_seq_num") for row in rows]
    if any(type(seq) is not int for seq in sequences) or sequences != sorted(set(sequences)):
        raise reference.PrivateError("DATA")
    tracker = capture.Tracker(manifest, profile, provenance["url"])
    tracker.collecting = True
    for raw in raws:
        reference.decode_endpoint_security_record(raw.decode())
        tracker.accept(raw)
    if set(raws) != set(tracker.records) or not tracker.main_exit:
        raise reference.PrivateError("DATA")
    recomputed = capture._analyzed_report(report, raws, manifest, profile, provenance["url"], home)
    if report != recomputed:
        raise reference.PrivateError("DATA")
    return manifest, report, rows


def _switch(payload: dict, name: str) -> list[str]:
    return [
        arg.partition("=")[2]
        for arg in payload.get("args", [])[1:]
        if arg == f"--{name}" or arg.startswith(f"--{name}=")
    ]


def _process_type(payload: dict) -> ProcessType:
    values = _switch(payload, "type")
    if len(values) > 1:
        return "AMBIGUOUS"
    return PROCESS_TYPES.get(values[0], "OTHER") if values else "ABSENT"


def _operational_role(payload: dict, manifest: object) -> str:
    target = payload["target"]
    image = capture._image_policy(target, manifest)
    if image is None or image.kind != "HELPER":
        return capture._role(target, manifest, payload)
    process_type = _process_type(payload)
    if process_type in {"RENDERER", "GPU"}:
        return process_type
    if process_type == "UTILITY":
        return (
            "NETWORK"
            if _switch(payload, "utility-sub-type") == ["network.mojom.NetworkService"]
            else "OTHER_UTILITY"
        )
    return "OTHER"


def _public_path(process: dict, manifest: object) -> PublicPath:
    if capture._image_policy(process, manifest) is not None:
        return "INSTALLED_IMAGE"
    path = process["executable"]["path"]
    if process["executable"]["path_truncated"]:
        return "OTHER"
    if path in SYSTEM_PATHS:
        return SYSTEM_PATHS[path]
    # Exact, version-bound public Chromium bundle layouts, not path-prefix admission.
    helpers = capture.APP / (
        f"Contents/Frameworks/Google Chrome Framework.framework/Versions/{manifest.version}/Helpers"
    )
    candidates: dict[str, PublicPath] = {
        "Aperitif": "APERITIF",
        "Aperitif Renderer": "APERITIF_RENDERER",
        "Aperitif GPU": "APERITIF_GPU",
        "Aperitif Alerts": "APERITIF_ALERTS",
        "Alerts": "ALERTS",
    }
    for suffix, label in candidates.items():
        name = f"Google Chrome Helper ({suffix})"
        if path == str(helpers / f"{name}.app/Contents/MacOS/{name}"):
            return label
    return {
        str(helpers / "app_mode_loader"): "APP_MODE_LOADER",
        str(helpers / "web_app_shortcut_copier"): "SHORTCUT_COPIER",
    }.get(path, "OTHER")


def _descriptor_argument(payload: dict, name: str) -> DescriptorArgument:
    values = _switch(payload, name)
    if not values:
        return DescriptorArgument()
    if len(values) != 1:
        return DescriptorArgument(presence="AMBIGUOUS")
    value = values[0]
    decimal = value.isascii() and value.isdecimal() and len(value) <= 10
    matches = [item for item in payload["fds"] if item["fd"] == int(value)] if decimal else []
    return DescriptorArgument(
        presence="PRESENT",
        decimal=reference._check(decimal),
        retained_descriptor=reference._check(len(matches) == 1),
        kind={1: "VNODE", 2: "SOCKET", 6: "PIPE"}.get(matches[0]["fdtype"], "OTHER")
        if len(matches) == 1
        else "NOT_OBSERVED",
    )


def _environment(payload: dict, manifest: object, main: dict | None) -> EnvironmentDetails:
    pairs = [member.partition("=") for member in payload["env"]]
    if any(not key or separator != "=" for key, separator, _value in pairs):
        raise reference.PrivateError("DATA")
    values = {key: value for key, _separator, value in pairs}
    entries: list[EnvironmentEntry] = []
    for key in ENVIRONMENT_KEYS:
        if key not in values:
            continue
        value = values[key]
        label = "OTHER"
        if key in reference.SAFE_ENV and value == reference.SAFE_ENV[key]:
            label = "CONTROLLED"
        elif key == "HOME" and main is not None and value == main.get("home"):
            label = "TEST_HOME"
        elif key == "__CFBundleIdentifier" and value == "com.google.Chrome":
            label = "CHROME_MAIN"
        elif (
            key == "SECURITYSESSIONID"
            and value.isascii()
            and value.isdecimal()
            and len(value) <= 10
        ):
            if int(value) == reference._token(payload["target"])[6]:
                label = "LOCAL_AUDIT_SESSION"
        elif key == "__CF_USER_TEXT_ENCODING" and value.lower() == f"0x{manifest.uid:x}:0:0":
            label = "LOCAL_USER_ZERO_ENCODING"
        elif key == "XPC_SERVICE_NAME" and re.fullmatch(
            r"application\.com\.google\.Chrome\.[0-9]+\.[0-9]+", value
        ):
            label = "CHROME_APP_INSTANCE"
        elif key in {"XPC_FLAGS", "MallocNanoZone", "OS_ACTIVITY_DT_MODE", "NSUnbufferedIO"}:
            label = {"0": "ZERO", "1": "ONE", "0x0": "HEX_ZERO", "0x1": "HEX_ONE"}.get(
                value, "OTHER"
            )
        elif key == "OSLogRateLimit" and value == "64":
            label = "SIXTY_FOUR"
        elif key == "COMMAND_MODE" and value == "unix2003":
            label = "UNIX2003"
        elif key == "OS_ACTIVITY_MODE" and value == "disable":
            label = "DISABLE"
        entries.append(EnvironmentEntry(key=key, value=label))
    return EnvironmentDetails(
        vectors_well_formed="PASS",
        duplicate_keys="ABSENT" if len(values) == len(pairs) else "PRESENT",
        only_known_keys=reference._check(set(values) <= set(ENVIRONMENT_KEYS)),
        entries=tuple(entries),
        from_main_exec=reference.compare_environment(
            tuple(member.encode() for member in main["payload"]["env"]),
            tuple(member.encode() for member in payload["env"]),
        )
        if main is not None
        else None,
    )


def analyze(manifest: object, report: object, rows: list[dict]) -> Report:
    """Pure classification of an authenticated graph; native values stay in memory."""
    executions: list[Execution] = []
    lives: dict[tuple[int, int], dict[str, object]] = {}
    main_payloads = [
        row["event"]["exec"]
        for row in rows
        if row["event_type"] == 9
        and capture._role(row["event"]["exec"]["target"], manifest) == "MAIN"
    ]
    main = {"payload": main_payloads[0], "home": None} if len(main_payloads) == 1 else None
    if main is not None:
        # HOME was already compared with the controlled test home in the saved report.
        phase = next(
            phase for phase in report.phases if phase.kind == "EXEC" and phase.after.role == "MAIN"
        )
        if phase.environment.home == "TEST_HOME":
            main["home"] = next(
                (
                    entry[5:]
                    for entry in reversed(main_payloads[0]["env"])
                    if entry.startswith("HOME=")
                ),
                None,
            )

    def lifetime(process: dict, alias: str) -> dict[str, object]:
        identity = (reference._token(process)[5], reference._birth(process))
        if identity not in lives:
            lives[identity] = {
                "first": alias,
                "last": alias,
                "fork": False,
                "exec": False,
                "exit": False,
                "children": [],
            }
        return lives[identity]

    for row, phase in zip(rows, report.phases, strict=True):
        before, kind = row["process"], row["event_type"]
        if kind == 11:
            child = row["event"]["fork"]["child"]
            lifetime(child, phase.after.execution)["fork"] = True
            if phase.before.execution != "BOOT":
                lifetime(before, phase.before.execution)["children"].append(phase.after.execution)
        elif kind == 15:
            lifetime(before, phase.before.execution)["exit"] = True
        else:
            payload = row["event"]["exec"]
            target = payload["target"]
            same_life = reference._token(before)[5] == reference._token(target)[
                5
            ] and reference._birth(before) == reference._birth(target)
            life = (
                lifetime(before, phase.before.execution)
                if same_life
                else lifetime(target, phase.after.execution)
            )
            life["exec"], life["last"] = True, phase.after.execution
            bt, tt = reference._token(before), reference._token(target)
            image = capture._image_policy(target, manifest)
            utility = _switch(payload, "utility-sub-type")
            executions.append(
                Execution(
                    before=phase.before.execution,
                    after=phase.after.execution,
                    original_role=phase.after.role,
                    operational_role=_operational_role(payload, manifest),
                    installed_image=image.kind if image else "UNQUALIFIED",
                    public_path=_public_path(target, manifest),
                    pid_preserved=reference._check(bt[5] == tt[5]),
                    birth_preserved=reference._check(
                        reference._birth(before) == reference._birth(target)
                    ),
                    version_relation="SAME"
                    if tt[7] == bt[7]
                    else "NEXT"
                    if tt[7] == bt[7] + 1
                    else "INCREASED_WITH_GAP"
                    if tt[7] > bt[7]
                    else "DECREASED",
                    changed_version_lifetime_agreement=reference._check(
                        bt[5] == tt[5]
                        and bt[7] != tt[7]
                        and reference._birth(before) == reference._birth(target)
                    ),
                    process_type=_process_type(payload),
                    utility="ABSENT"
                    if not utility
                    else "AMBIGUOUS"
                    if len(utility) != 1
                    else UTILITY_TYPES.get(utility[0], "OTHER"),
                    native_shape=phase.native_shape,
                    known_image_security=phase.after.installed_signature_agreement,
                    known_image_entitlements=phase.entitlements.matches_installed_code,
                    seatbelt=_descriptor_argument(payload, "seatbelt-client"),
                    mojo_channel=_descriptor_argument(payload, "mojo-platform-channel-handle"),
                    environment=phase.environment,
                    environment_details=_environment(payload, manifest, main),
                )
            )
    return Report(
        provenance="PASS",
        original_collection_controls="PASS",
        exact_retained_graph="PASS",
        original_report_agreement="PASS",
        original_gpu_exec=report.gpu_exec,
        corrected_gpu_exec=reference._check(
            any(item.operational_role == "GPU" for item in executions)
        ),
        executions=tuple(executions),
        exceptional_lifetimes=tuple(
            Lifetime(
                first_execution=life["first"],
                last_execution=life["last"],
                fork_observed=reference._check(life["fork"]),
                exec_observed=reference._check(life["exec"]),
                exit_observed=reference._check(life["exit"]),
                forked_children=tuple(life["children"]),
                ending="EXITED" if life["exit"] else "NO_RETAINED_EXIT",
            )
            for life in lives.values()
            if not life["exec"] or not life["exit"]
        ),
    )


def review_existing(root: Path, expected: dict[str, str]) -> Report:
    """AUTHORIZED READ ONLY: verify and classify the one selected existing capture."""
    return analyze(*_verified(root, expected))


def prepare(destination: Path | None = None, *, capture_code_kit: Path | None = None) -> Path:
    """Copy code/expected hashes only; an optional trusted code-only copy pins an older kit."""
    root = capture.prepare(destination)
    if capture_code_kit is not None:
        # Do not point this at a private setup/capture. Only these known source files are read.
        for name in capture.CODE:
            shutil.copyfile(capture_code_kit / name, root / name)
            (root / name).chmod(0o600)
    shutil.copyfile(Path(__file__).resolve(), root / "private_chrome_review.py")
    (root / "private_chrome_review.py").chmod(0o600)
    expected = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in capture.CODE
    }
    reference._write(root / "OFFLINE-EXPECTED.json", json.dumps(expected).encode())
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        parser = reference.QuietParser(description=__doc__)
        parser.add_argument("operation", choices=("prepare", "review-existing"))
        parser.add_argument("--private-run", action="store_true")
        parser.add_argument("--source-kit", type=Path)
        parser.add_argument("--capture-code-kit", type=Path)
        args = parser.parse_args(argv)
        if args.operation == "prepare":
            if args.private_run or args.source_kit is not None:
                raise reference.PrivateError("INPUT")
            print(prepare(capture_code_kit=args.capture_code_kit))
            return 0
        if not args.private_run or args.source_kit is None or args.capture_code_kit is not None:
            raise reference.PrivateError("INPUT")
        own_root = Path(__file__).resolve().parent
        reference._outside_git(own_root)
        reference._directory(own_root)
        expected = reference._decode(reference._read(own_root / "OFFLINE-EXPECTED.json"))
        report = review_existing(args.source_kit, expected)
    except reference.PrivateError as error:
        report = Report(error=error.code)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        report = Report(error="DATA")
    print(report.model_dump_json(indent=2), flush=True)
    return 0 if report.error == "NONE" else 2


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: print(
        Report(error="INTERNAL").model_dump_json()
    )
    raise SystemExit(main())
