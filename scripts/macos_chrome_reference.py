# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a HUMAN-ONLY fresh-profile Chrome reference; never collect as an agent.

The agent-safe entry point copies code only. Human setup reads installed code,
not profiles. Human capture streams ambient ES into bounded memory and retains
only a nonce-authenticated browser's exact launch ancestry and descendants.
An agent may run diagnose-code only with explicit approval for that fixed read.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field

from evidenceforge.events.macos_entitlements import freeze_entitlements


def _support() -> ModuleType:
    path = Path(__file__).resolve().with_name("terminal_support.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_terminal_startup_reference.py")
    name = "_eforge_chrome_terminal_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


support = _support()
reference = support.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Role = Literal[
    "MAIN",
    "RENDERER",
    "GPU",
    "NETWORK",
    "OTHER_UTILITY",
    "CRASHPAD",
    "XPCPROXY",
    "LAUNCHD",
    "OTHER",
]
type ImageKind = Literal["MAIN", "RENDERER", "GPU", "HELPER", "CRASHPAD", "XPCPROXY"]
type CodeItem = ImageKind | Literal["APP_INFO", "NONE"]
type CodeCheck = Literal[
    "READ_INFO",
    "VALIDATE_INFO",
    "FILE_HASH",
    "SIGNATURE_VERIFY",
    "SIGNATURE_METADATA",
    "ENTITLEMENTS_DECODE",
    "METADATA_FIELDS",
    "CODE_RECHECK",
    "NONE",
]
type CodeFailure = Literal[
    "MISSING_FILE",
    "SYMLINK",
    "PERMISSION",
    "COMMAND_EXIT",
    "COMMAND_TIMEOUT",
    "POLICY_REJECTED",
    "INVALID_METADATA",
    "IO",
    "NONE",
]
type Error = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "ROOT_USER",
    "PLATFORM",
    "BUILD",
    "APP_MISSING",
    "SESSION_LOCKED",
    "COLLECTOR",
    "LAUNCH",
    "TIMEOUT",
    "LIMIT",
    "DATA",
    "IO",
    "INTERRUPTED",
    "INTERNAL",
]
type Stage = Literal[
    "ERROR", "SETUP_READY", "COLLECTOR_READY", "BROWSER_READY", "QUIT_CHROME", "COMPLETE"
]
type Alias = Literal[
    "P0",
    "P1",
    "P2",
    "P3",
    "P4",
    "P5",
    "P6",
    "P7",
    "P8",
    "P9",
    "P10",
    "P11",
    "P12",
    "P13",
    "P14",
    "P15",
    "P16",
    "P17",
    "P18",
    "P19",
    "P20",
    "P21",
    "P22",
    "P23",
    "P24",
    "P25",
    "P26",
    "P27",
    "P28",
    "P29",
    "P30",
    "P31",
    "P32",
    "P33",
    "P34",
    "P35",
    "P36",
    "P37",
    "P38",
    "P39",
    "P40",
    "P41",
    "P42",
    "P43",
    "P44",
    "P45",
    "P46",
    "P47",
    "P48",
    "P49",
    "P50",
    "P51",
    "P52",
    "P53",
    "P54",
    "P55",
    "P56",
    "P57",
    "P58",
    "P59",
    "P60",
    "P61",
    "P62",
    "P63",
    "BOOT",
    "OTHER",
    "UNSET",
]
ALIASES = tuple(f"P{index}" for index in range(64))
APP = Path("/Applications/Google Chrome.app")
CODE = (
    "private_chrome.py",
    "terminal_support.py",
    "reference_support.py",
    "ready_marker.c",
    "collector_guard.c",
)
MAX_LINE = 1_048_576
MAX_STREAM = 256 * MAX_LINE
MAX_RING_BYTES = 16 * MAX_LINE
MAX_RING_ROWS = 1024
MAX_ROWS = 256
MAX_PRIVATE_BYTES = 32 * MAX_LINE
MAX_REPORT_BYTES = 4 * MAX_LINE
MAIN_FLAGS = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-extensions",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--use-mock-keychain",
    "--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication",
    "--no-proxy-server",
)
# These are public Chromium template keys, not exported observed names/values.
BOOLEAN_ENTITLEMENTS = (
    "com.apple.security.device.audio-input",
    "com.apple.security.device.bluetooth",
    "com.apple.security.device.camera",
    "com.apple.security.device.print",
    "com.apple.security.device.usb",
    "com.apple.security.personal-information.location",
    "com.apple.security.personal-information.photos-library",
    "com.apple.security.cs.allow-jit",
    "com.apple.developer.associated-domains.applinks.read-write",
    "com.apple.developer.web-browser.public-key-credential",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.get-task-allow",
)
KNOWN_SWITCHES = (
    "type",
    "utility-sub-type",
    "user-data-dir",
    "lang",
    "service-sandbox-type",
    "field-trial-handle",
    "enable-features",
    "disable-features",
    "variations-seed-version",
    "seatbelt-client",
    "shared-files",
    "metrics-shmem-handle",
    "trace-process-track-uuid",
    "mojo-platform-channel-handle",
    "renderer-client-id",
    "time-ticks-at-unix-epoch",
    "launch-time-ticks",
    "gpu-preferences",
    "use-angle",
    "string-annotations",
    "no-sandbox",
    "disable-gpu-sandbox",
)
FD_SLOTS = tuple(f"FD{index}" for index in range(64))
type FDSlot = Literal[*FD_SLOTS, "OTHER"]


class Image(reference.Model):
    """Private installed-code snapshot, never serialized into the shareable report."""

    kind: ImageKind
    path: str = Field(min_length=1, max_length=4096)
    image: reference.Image
    signing_id: str = Field(min_length=1, max_length=256)
    team_id: str | None = Field(max_length=256)
    entitlements: dict[str, bool | int | str | list[str]] = Field(max_length=128)


class Manifest(reference.Model):
    kit_version: Literal[3] = 3
    app_signature_policy: Literal["STANDARD_WITH_VENDOR_REQUIREMENT"] = (
        "STANDARD_WITH_VENDOR_REQUIREMENT"
    )
    os_version: str = Field(max_length=128)
    os_build: str = Field(max_length=128)
    uid: int = Field(gt=0, lt=2**32)
    gid: int = Field(ge=0, lt=2**32)
    images: tuple[Image, ...] = Field(min_length=6, max_length=6)
    marker: reference.Image
    guard_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    codec_sha256: str = Field(pattern="^[a-f0-9]{64}$")
    code_sha256: dict[str, str] = Field(max_length=len(CODE))
    version: str = Field(pattern=r"[0-9]+(?:\.[0-9]+){3}")


class EntitlementMember(reference.Model):
    """Only an independently allowlisted key can be emitted."""

    key: Literal[*BOOLEAN_ENTITLEMENTS]
    value: Literal["TRUE", "FALSE", "OTHER"]


class Entitlements(reference.Model):
    representation: Literal["NULL", "OBJECT", "OTHER", "ABSENT"]
    matches_installed_code: Check
    known_booleans: tuple[EntitlementMember, ...] = Field(max_length=len(BOOLEAN_ENTITLEMENTS))
    application_identifier: Literal["ABSENT", "TEAM_AND_BUNDLE", "OTHER"]
    keychain_groups: Literal["ABSENT", "CHROME_PUBLIC_TEMPLATE", "OTHER"]
    other_keys: Literal["ABSENT", "PRESENT"]


class ArgumentSwitch(reference.Model):
    name: Literal[*KNOWN_SWITCHES]
    value: Literal[
        "MAIN",
        "RENDERER",
        "GPU",
        "UTILITY",
        "NETWORK",
        "AUDIO",
        "STORAGE",
        "TEST_PROFILE",
        "DECIMAL",
        "PRESENT",
        "EMPTY",
        "OTHER",
    ]
    descriptor_slot: FDSlot | Literal["NOT_DESCRIPTOR"] = "NOT_DESCRIPTOR"


class Arguments(reference.Model):
    image_argv0: Check
    test_profile: Literal["EXACT", "ABSENT", "OTHER"]
    controlled_url: Literal["PRESENT", "ABSENT"]
    known: tuple[ArgumentSwitch, ...] = Field(max_length=len(KNOWN_SWITCHES))
    other_switches: Literal["ABSENT", "PRESENT"]
    other_positionals: Literal["ABSENT", "PRESENT"]
    duplicate_switches: Literal["ABSENT", "PRESENT"]


class Descriptor(reference.Model):
    slot: FDSlot
    kind: Literal["VNODE", "SOCKET", "PIPE", "OTHER"]
    pipe: Literal[
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "NOT_PIPE",
        "OTHER",
    ]


class Snapshot(reference.Model):
    execution: Alias
    role: Role
    parent: Alias
    responsible: Alias
    responsible_exact_token: Check
    credentials: Literal["LOCAL_USER", "ROOT", "OTHER"]
    audit_user: Literal["LOCAL_USER", "UNATTRIBUTED", "OTHER"]
    audit_session_from_main: Check
    group: Literal["SELF", "PARENT", "MAIN", "BOOT", "OTHER"]
    session: Literal["SELF", "PARENT", "MAIN", "BOOT", "OTHER"]
    tty: Literal["PRESENT", "ABSENT", "UNKNOWN"]
    original_parent_matches_parent: Check
    installed_image_agreement: Check
    installed_signature_agreement: Check
    installed_path_spelling: Literal["EXACT", "OTHER", "UNQUALIFIED_IMAGE"]
    signing_identifier: Literal[
        "CHROME_MAIN", "CHROME_HELPER", "CHROME_RENDERER", "CHROME_GPU", "XPCPROXY", "OTHER"
    ]
    team_identifier: Literal["GOOGLE", "ABSENT", "OTHER"]
    security: reference.NativeSecurityFacts


class Environment(reference.Model):
    from_before_exec: reference.EnvironmentDifference | None = None
    only_known_keys: Check
    home: Literal["ABSENT", "TEST_HOME", "OTHER"]
    path: Literal["ABSENT", "CONTROLLED", "OTHER"]
    xpc_service_name: Literal["ABSENT", "NONEMPTY", "OTHER"]


class Phase(reference.Model):
    kind: Literal["FORK", "EXEC", "EXIT"]
    before: Snapshot
    after: Snapshot | None = None
    native_shape: Check
    shape_excluding_entitlements: Check
    fork_image_preserved: Check = "INCONCLUSIVE"
    fork_parent_token_agreement: Check = "INCONCLUSIVE"
    exec_identity_transition: Check = "INCONCLUSIVE"
    audit_origin_preserved: Check = "INCONCLUSIVE"
    posix_credentials_preserved: Check = "INCONCLUSIVE"
    posix_membership_preserved: Check = "INCONCLUSIVE"
    parentage_preserved: Check = "INCONCLUSIVE"
    arguments: Arguments | None = None
    descriptors: tuple[Descriptor, ...] = Field(default=(), max_length=64)
    fd_inventory_well_formed: Check = "INCONCLUSIVE"
    last_fd_agreement: Check = "INCONCLUSIVE"
    only_standard_descriptors: Check = "INCONCLUSIVE"
    cwd: Literal["ROOT", "TEST_HOME", "TEST_PROFILE", "OTHER", "UNKNOWN"] = "UNKNOWN"
    script_absent: Check = "INCONCLUSIVE"
    dyld_path_matches_target: Check = "INCONCLUSIVE"
    slice: reference.NativeSliceFacts | None = None
    entitlements: Entitlements | None = None
    environment: Environment | None = None
    exit_outcome: Literal["ZERO", "OTHER_STATUS", "SIGNALLED", "UNKNOWN"] | None = None


class Report(reference.Model):
    kit_version: Literal[3] = 3
    app_signature_policy: Literal["STANDARD_WITH_VENDOR_REQUIREMENT"] = (
        "STANDARD_WITH_VENDOR_REQUIREMENT"
    )
    strict_distribution_conformance: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    purpose: Literal["CHROME_MAIN_AND_HELPER_DIAGNOSTIC"] = "CHROME_MAIN_AND_HELPER_DIAGNOSTIC"
    collection: Literal["NONCE_PROFILE_AUTHENTICATED_PROCESS_GRAPH"] = (
        "NONCE_PROFILE_AUTHENTICATED_PROCESS_GRAPH"
    )
    launch_method: Literal["LAUNCHSERVICES_OPEN_NEW_INSTANCE"] = "LAUNCHSERVICES_OPEN_NEW_INSTANCE"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Error = "NONE"
    stage: Stage = "ERROR"
    step: Literal[
        "INPUT",
        "LOCATION",
        "PLATFORM",
        "INSTALLED_CODE",
        "BUILD",
        "VERIFY",
        "COLLECTOR",
        "SERVER",
        "BROWSER",
        "COLLECTION",
        "ANALYSIS",
        "COMPLETE",
    ] = "INPUT"
    target_platform: Check = "INCONCLUSIVE"
    installed_code_item: CodeItem = "NONE"
    installed_code_check: CodeCheck = "NONE"
    installed_code_failure: CodeFailure = "NONE"
    provenance: Check = "INCONCLUSIVE"
    catalog_release: Literal["EXACT_155_0_8059_80", "OTHER", "NOT_CHECKED"] = "NOT_CHECKED"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    server_cleanup: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"
    candidate_ring_evicted: bool = False
    wire_profile: Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    main_exec: Check = "INCONCLUSIVE"
    renderer_exec: Check = "INCONCLUSIVE"
    gpu_exec: Check = "INCONCLUSIVE"
    network_exec: Check = "INCONCLUSIVE"
    main_exit_seen: Check = "INCONCLUSIVE"
    controlled_page: Check = "INCONCLUSIVE"
    controlled_fetch: Check = "INCONCLUSIVE"
    webgl_context: Literal["CREATED", "UNAVAILABLE", "NOT_OBSERVED"] = "NOT_OBSERVED"
    forks_observed: int = Field(default=0, ge=0, le=MAX_ROWS)
    execs_observed: int = Field(default=0, ge=0, le=MAX_ROWS)
    exits_observed: int = Field(default=0, ge=0, le=MAX_ROWS)
    exec_lifetimes_without_fork: int = Field(default=0, ge=0, le=MAX_ROWS)
    fork_lifetimes_without_exec: int = Field(default=0, ge=0, le=MAX_ROWS)
    started_lifetimes_without_exit: int = Field(default=0, ge=0, le=MAX_ROWS)
    phases: tuple[Phase, ...] = Field(default=(), max_length=MAX_ROWS)
    unified_log: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    external_traffic: Literal["NOT_MEASURED"] = "NOT_MEASURED"
    detail_report: Literal["SHAREABLE-CHROME-REPORT.json"] = "SHAREABLE-CHROME-REPORT.json"


class CodeCommandResult(reference.Model):
    """Fixed interpretation only, never command output or exception text."""

    outcome: Literal["PASS", "FAIL", "TIMEOUT", "IO", "LIMIT", "NOT_RUN"] = "NOT_RUN"
    failure: Literal[
        "NONE",
        "REQUIREMENT_REJECTED",
        "REQUIREMENT_SYNTAX",
        "RESOURCE_SEAL",
        "UNSIGNED",
        "BUNDLE_FORMAT",
        "STRICT_EXECUTABLE",
        "SIGNATURE_INVALID",
        "COMMAND_USAGE",
        "OTHER",
    ] = "NONE"


class CodeDiagnosticReport(reference.Model):
    review_version: Literal[1] = 1
    purpose: Literal["CHROME_SIGNING_DIAGNOSTIC"] = "CHROME_SIGNING_DIAGNOSTIC"
    mode: Literal["READ_ONLY_INSTALLED_CODE"] = "READ_ONLY_INSTALLED_CODE"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Error = "NONE"
    main_file_unchanged: Check = "INCONCLUSIVE"
    bundle_basic: CodeCommandResult = Field(default_factory=CodeCommandResult)
    bundle_strict: CodeCommandResult = Field(default_factory=CodeCommandResult)
    bundle_strict_google: CodeCommandResult = Field(default_factory=CodeCommandResult)
    main_leaf_strict_google: CodeCommandResult = Field(default_factory=CodeCommandResult)
    main_leaf_code_google: CodeCommandResult = Field(default_factory=CodeCommandResult)
    metadata: CodeCommandResult = Field(default_factory=CodeCommandResult)
    signing_identifier_template: Check = "INCONCLUSIVE"
    team_identifier_template: Check = "INCONCLUSIVE"
    metadata_executable_binding: Check = "INCONCLUSIVE"
    entitlements_xml: Check = "INCONCLUSIVE"
    entitlements_representation: Literal["XML_OBJECT", "EMPTY", "OTHER", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    entitlements_flat_types: Check = "INCONCLUSIVE"
    native_logs: Literal["NOT_OPENED"] = "NOT_OPENED"
    browser_profiles: Literal["NOT_OPENED"] = "NOT_OPENED"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    apps: Literal["NOT_LAUNCHED"] = "NOT_LAUNCHED"
    helper_files: Literal["NOT_WRITTEN"] = "NOT_WRITTEN"


class DiagnosticError(reference.PrivateError):
    """A closed step label, never exception text."""

    def __init__(self, code: Error, step: str) -> None:
        super().__init__(code)
        self.step = step


class InstalledCodeError(DiagnosticError):
    """Fixed code/check/reason labels; never command text, stderr, paths or values."""

    def __init__(self, code: Error, item: CodeItem, check: CodeCheck, reason: CodeFailure) -> None:
        super().__init__(code, "INSTALLED_CODE")
        self.item, self.check, self.reason = item, check, reason

    def labels(self) -> dict[str, str]:
        return {
            "installed_code_item": self.item,
            "installed_code_check": self.check,
            "installed_code_failure": self.reason,
        }


def _checked[T](item: CodeItem, check: CodeCheck, operation: Callable[[], T]) -> T:
    try:
        return operation()
    except reference.PrivateError as error:
        raise InstalledCodeError(error.code, item, check, "POLICY_REJECTED") from error
    except subprocess.TimeoutExpired as error:
        raise InstalledCodeError("BUILD", item, check, "COMMAND_TIMEOUT") from error
    except subprocess.CalledProcessError as error:
        raise InstalledCodeError("BUILD", item, check, "COMMAND_EXIT") from error
    except OSError as error:
        reason = {
            errno.ENOENT: "MISSING_FILE",
            errno.ELOOP: "SYMLINK",
            errno.EACCES: "PERMISSION",
            errno.EPERM: "PERMISSION",
        }.get(error.errno, "IO")
        raise InstalledCodeError("BUILD", item, check, reason) from error
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        raise InstalledCodeError("BUILD", item, check, "INVALID_METADATA") from error


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy fresh code only; read no installed app or capture."""
    source = Path(__file__).resolve()
    docs = source.parents[1] / "docs/design/macos-workstation-feasibility"
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    reference._outside_git(parent)
    root = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-chrome-kit-", dir=parent))
    )
    if destination:
        root.mkdir(mode=0o700)
    root.chmod(0o700)
    for original, name in (
        (source, CODE[0]),
        (Path(support.__file__), CODE[1]),
        (Path(reference.__file__), CODE[2]),
        (docs / "terminal-startup-reference/terminal_marker.c", CODE[3]),
        (docs / "gui-launch-reference/collector_guard.c", CODE[4]),
        (docs / "chrome-reference/PRIVATE-RUN.md", "PRIVATE-RUN.md"),
    ):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    return root


def _root() -> Path:
    root = Path(__file__).resolve().parent
    reference._outside_git(root)
    reference._directory(root)
    return root


def _public_file(path: Path, limit: int = MAX_LINE) -> bytes:
    """Read installed code metadata only, with descriptor-bound change detection."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in (0, os.getuid())
            or before.st_mode & 0o022
            or not 0 < before.st_size <= limit
        ):
            raise reference.PrivateError("BUILD")
        result = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(result) != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in fields
        ):
            raise reference.PrivateError("BUILD")
    return result


def _code_output(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    """HUMAN ONLY: fixed vendor-code query, no profile access or printed output."""
    result = subprocess.run(
        args,
        env=reference.SAFE_ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        check=True,
    )
    if len(result.stdout) + len(result.stderr) > MAX_LINE:
        raise reference.PrivateError("LIMIT")
    return result


def _verification_command(
    kind: ImageKind,
    target: Path,
    *,
    strict: bool = True,
    requirement: bool = True,
    ignore_resources: bool = False,
) -> list[str]:
    args = ["/usr/bin/codesign", "--verify"]
    if strict:
        args.append("--strict")
    if ignore_resources:
        args.append("--ignore-resources")
    if requirement:
        args.extend(
            [
                "-R",
                '=anchor apple and identifier "com.apple.xpc.proxy"'
                if kind == "XPCPROXY"
                else '=anchor apple generic and certificate leaf[subject.OU] = "EQHXZ8M8AV"',
            ]
        )
    return [*args, str(target)]


def _metadata_command(target: Path) -> list[str]:
    return ["/usr/bin/codesign", "-d", "--verbose=4", "--entitlements", "-", "--xml", str(target)]


def _diagnostic_failure(raw: bytes | str | None) -> CodeCommandResult:
    """Recognize public tool messages in memory; never export unrecognized text."""
    if type(raw) is not bytes or len(raw) > MAX_LINE:
        return CodeCommandResult(outcome="FAIL", failure="OTHER")
    data = raw.lower()
    # These labels describe tool messages, not independent root-cause findings.
    phrases = (
        (b"failed to satisfy", "REQUIREMENT_REJECTED"),
        (b"requirement syntax", "REQUIREMENT_SYNTAX"),
        (b"invalid or corrupted code requirements", "REQUIREMENT_SYNTAX"),
        (b"a sealed resource is missing or invalid", "RESOURCE_SEAL"),
        (b"sealed resource directory", "RESOURCE_SEAL"),
        (b"cannot find sealed resources", "RESOURCE_SEAL"),
        (b"unsealed contents", "RESOURCE_SEAL"),
        (b"resource fork, finder information", "RESOURCE_SEAL"),
        (b"code object is not signed", "UNSIGNED"),
        (b"bundle format", "BUNDLE_FORMAT"),
        (b"main executable failed strict validation", "STRICT_EXECUTABLE"),
        (b"invalid signature", "SIGNATURE_INVALID"),
        (b"code or signature modified", "SIGNATURE_INVALID"),
        (b"usage: codesign", "COMMAND_USAGE"),
        (b"unrecognized option", "COMMAND_USAGE"),
        (b"unknown option", "COMMAND_USAGE"),
    )
    label = next((label for phrase, label in phrases if phrase in data), "OTHER")
    return CodeCommandResult(outcome="FAIL", failure=label)


def _diagnostic_command(
    args: list[str],
) -> tuple[CodeCommandResult, subprocess.CompletedProcess[bytes] | None]:
    try:
        return CodeCommandResult(outcome="PASS"), _code_output(args)
    except subprocess.CalledProcessError as error:
        if any(
            type(value) is bytes and len(value) > MAX_LINE for value in (error.stdout, error.stderr)
        ):
            return CodeCommandResult(outcome="LIMIT"), None
        return _diagnostic_failure(error.stderr), None
    except subprocess.TimeoutExpired:
        return CodeCommandResult(outcome="TIMEOUT"), None
    except OSError:
        return CodeCommandResult(outcome="IO"), None
    except reference.PrivateError:
        return CodeCommandResult(outcome="LIMIT"), None


def diagnose_code() -> CodeDiagnosticReport:
    """Explicit approval or HUMAN ONLY: six fixed code queries; no captures or writes.

    This is diagnostic, not an admission override. It reads no old kit files,
    profiles or native logs, runs no build/probe/collector/app and writes nothing.
    Agents may run only after explicit approval for this installed-code check.
    """
    _root()  # Require a prepared outside-Git copy, without reading a setup or run.
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        return CodeDiagnosticReport(error="ROOT_USER")
    if sys.platform != "darwin":
        return CodeDiagnosticReport(error="PLATFORM")
    path = APP / "Contents/MacOS/Google Chrome"
    image = None
    try:
        image = support._installed_image(path)
    except (OSError, ValueError):
        pass  # The independent command results remain useful; no error text escapes.
    values = {}
    for name, command in (
        ("bundle_basic", _verification_command("MAIN", APP, strict=False, requirement=False)),
        ("bundle_strict", _verification_command("MAIN", APP, requirement=False)),
        ("bundle_strict_google", _verification_command("MAIN", APP)),
        ("main_leaf_strict_google", _verification_command("MAIN", path)),
        ("main_leaf_code_google", _verification_command("MAIN", path, ignore_resources=True)),
    ):
        values[name] = _diagnostic_command(command)[0]
    metadata_status, metadata = _diagnostic_command(_metadata_command(APP))
    values["metadata"] = metadata_status
    if metadata is not None:
        fields: dict[str, bytes] = {}
        for line in metadata.stderr.splitlines():
            key, separator, value = line.partition(b"=")
            if separator and key in {b"Identifier", b"TeamIdentifier", b"Executable"}:
                fields[key.decode("ascii")] = value
        values.update(
            signing_identifier_template=reference._check(
                fields.get("Identifier") == b"com.google.Chrome"
            ),
            team_identifier_template=reference._check(
                fields.get("TeamIdentifier") == b"EQHXZ8M8AV"
            ),
            metadata_executable_binding=reference._check(
                fields.get("Executable") == os.fsencode(path)
            ),
        )
        try:
            entitlements = plistlib.loads(metadata.stdout) if metadata.stdout.strip() else {}
            values["entitlements_representation"] = (
                "EMPTY"
                if not metadata.stdout.strip()
                else (
                    "XML_OBJECT"
                    if type(entitlements) is dict
                    and metadata.stdout.lstrip().startswith((b"<?xml", b"<plist"))
                    else "OTHER"
                )
            )
            values["entitlements_xml"] = (
                "INCONCLUSIVE"
                if not metadata.stdout.strip()
                else reference._check(values["entitlements_representation"] == "XML_OBJECT")
            )
            try:
                freeze_entitlements(entitlements)
                values["entitlements_flat_types"] = "PASS"
            except ValueError:
                values["entitlements_flat_types"] = "FAIL"
        except (ValueError, TypeError, plistlib.InvalidFileException):
            values["entitlements_xml"] = "FAIL"
            values["entitlements_representation"] = "OTHER"
    try:
        values["main_file_unchanged"] = reference._check(
            image is not None and image == support._installed_image(path)
        )
    except (OSError, ValueError):
        values["main_file_unchanged"] = "FAIL"
    return CodeDiagnosticReport(**values)


def _installed(kind: ImageKind, path: Path) -> Image:
    image = _checked(kind, "FILE_HASH", lambda: support._installed_image(path))
    # Chromium signs app bundles as bundles, and standalone tools as executables.
    target = _signing_target(kind, path)
    # A process reference requires valid signed code and the vendor requirement.
    # Extra strict app-distribution checks are separate diagnostic observations.
    _checked(
        kind,
        "SIGNATURE_VERIFY",
        lambda: _code_output(
            _verification_command(
                kind,
                target,
                strict=kind in {"CRASHPAD", "XPCPROXY"},
            )
        ),
    )
    result = _checked(
        kind,
        "SIGNATURE_METADATA",
        lambda: _code_output(_metadata_command(target)),
    )
    entitlements = _checked(
        kind,
        "ENTITLEMENTS_DECODE",
        lambda: plistlib.loads(result.stdout) if result.stdout.strip() else {},
    )

    def metadata_image() -> Image:
        metadata: dict[str, str] = {}
        for line in result.stderr.decode("utf-8", errors="strict").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"Identifier", "TeamIdentifier", "Executable"}:
                if key in metadata:
                    raise ValueError("Duplicate code metadata")
                metadata[key] = value
        if metadata.get("Executable") != str(path):
            raise ValueError("Code metadata does not bind the expected executable")
        if type(entitlements) is not dict:
            raise ValueError("Entitlements require an object")
        return Image(
            kind=kind,
            path=str(path),
            image=image,
            signing_id=metadata["Identifier"],
            team_id=None
            if metadata.get("TeamIdentifier") in (None, "not set")
            else metadata["TeamIdentifier"],
            entitlements=entitlements,
        )

    value = _checked(kind, "METADATA_FIELDS", metadata_image)

    def unchanged() -> None:
        if image != support._installed_image(path):
            raise ValueError("Installed code changed")

    _checked(kind, "CODE_RECHECK", unchanged)
    return value


def _signing_target(kind: ImageKind, path: Path) -> Path:
    if kind in {"CRASHPAD", "XPCPROXY"}:
        return path
    if (
        path.parent.name != "MacOS"
        or path.parent.parent.name != "Contents"
        or path.parents[2].suffix != ".app"
    ):
        raise InstalledCodeError("BUILD", kind, "METADATA_FIELDS", "INVALID_METADATA")
    return path.parents[2]


def installed_images() -> tuple[str, tuple[Image, ...]]:
    """HUMAN ONLY: read fixed installed Chrome code paths; enumerate no profiles."""
    if not APP.is_dir():
        raise reference.PrivateError("APP_MISSING")
    raw = _checked("APP_INFO", "READ_INFO", lambda: _public_file(APP / "Contents/Info.plist"))

    def info_version() -> str:
        info = plistlib.loads(raw)
        if type(info) is not dict:
            raise ValueError("Installed app metadata requires an object")
        version = info.get("CFBundleShortVersionString")
        if (
            info.get("CFBundleIdentifier") != "com.google.Chrome"
            or type(version) is not str
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", version) is None
        ):
            raise ValueError("Unsupported installed code metadata")
        return version

    version = _checked("APP_INFO", "VALIDATE_INFO", info_version)
    base = APP / "Contents/Frameworks/Google Chrome Framework.framework/Versions" / version
    images = [_installed("MAIN", APP / "Contents/MacOS/Google Chrome")]
    for kind, name in (
        ("RENDERER", "Google Chrome Helper (Renderer)"),
        ("GPU", "Google Chrome Helper (GPU)"),
        ("HELPER", "Google Chrome Helper"),
    ):
        images.append(_installed(kind, base / "Helpers" / f"{name}.app/Contents/MacOS" / name))
    images.extend(
        (
            _installed("CRASHPAD", base / "Helpers/chrome_crashpad_handler"),
            _installed("XPCPROXY", Path("/usr/libexec/xpcproxy")),
        )
    )
    return version, tuple(images)


def setup() -> Report:
    """HUMAN ONLY: compile readiness/guard and snapshot code; launch nothing."""
    root = _root()
    version, build = reference._preflight()
    reference._write(root / "SETUP-LOCK", b"SETUP\n")
    try:
        chrome_version, images = installed_images()
    except InstalledCodeError:
        raise
    except (OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        raise DiagnosticError(
            error.code if isinstance(error, reference.PrivateError) else "BUILD", "INSTALLED_CODE"
        ) from error
    for source, output in ((CODE[3], "ready-marker"), (CODE[4], "collector-guard")):
        reference._command(
            [
                "/usr/bin/clang",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(root / source),
                "-o",
                str(root / output),
            ],
            root,
        )
        (root / output).chmod(0o700)
    reference._command(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            str(root / "ready-marker"),
        ],
        root,
    )
    manifest = Manifest(
        os_version=version,
        os_build=build,
        uid=os.getuid(),
        gid=os.getgid(),
        images=images,
        marker=reference._image(root / "ready-marker"),
        guard_sha256=reference._digest(root / "collector-guard"),
        codec_sha256=reference._codec_digest(),
        code_sha256={name: reference._digest(root / name) for name in CODE},
        version=chrome_version,
    )
    reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    return Report(
        stage="SETUP_READY",
        step="COMPLETE",
        target_platform="PASS",
        provenance="PASS",
        catalog_release=_release(manifest),
    )


def _manifest(root: Path, *, installed: bool) -> Manifest:
    manifest = Manifest.model_validate_json(reference._read(root / "SETUP.json"))
    if (
        manifest.marker != reference._image(root / "ready-marker")
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.codec_sha256 != reference._codec_digest()
        or manifest.code_sha256 != {name: reference._digest(root / name) for name in CODE}
        or manifest.uid != os.getuid()
        or manifest.gid != os.getgid()
        or (installed and (manifest.version, manifest.images) != installed_images())
    ):
        raise reference.PrivateError("BUILD")
    return manifest


def _release(manifest: Manifest) -> Literal["EXACT_155_0_8059_80", "OTHER"]:
    return "EXACT_155_0_8059_80" if manifest.version == "155.0.8059.80" else "OTHER"


def _image_policy(process: dict, manifest: Manifest) -> Image | None:
    matches = [
        image
        for image in manifest.images
        if reference._owned(process, image.image)
        and process.get("executable", {}).get("path_truncated") is False
    ]
    return matches[0] if len(matches) == 1 else None


def _signature_agrees(process: dict, image: Image) -> bool:
    return process.get("signing_id") == image.signing_id and process.get("team_id") == image.team_id


def _role(process: dict, manifest: Manifest, payload: dict | None = None) -> Role:
    if (
        reference._token(process)[5] == 1
        and process.get("executable", {}).get("path") == "/sbin/launchd"
    ):
        return "LAUNCHD"
    image = _image_policy(process, manifest)
    if image is None:
        return "OTHER"
    if image.kind != "HELPER":
        return image.kind
    arguments = payload.get("args", []) if payload else []
    if "--type=utility" in arguments:
        return (
            "NETWORK"
            if "--utility-sub-type=network.mojom.NetworkService" in arguments
            else ("OTHER_UTILITY")
        )
    return "OTHER"


def _same(left: dict, right: dict) -> bool:
    return reference._identity(left) == reference._identity(right) and _same_image(left, right)


def _same_image(left: dict, right: dict) -> bool:
    """Compare arbitrary loaded images; the shared launcher comparison is xpcproxy-only."""
    left_file, right_file = left.get("executable", {}), right.get("executable", {})
    left_stat, right_stat = left_file.get("stat", {}), right_file.get("stat", {})
    return (
        all(
            type(left_stat.get(key)) is int and left_stat[key] == right_stat.get(key)
            for key in ("st_dev", "st_ino")
        )
        and left_file.get("path_truncated") is False
        and right_file.get("path_truncated") is False
        and type(left_file.get("path")) is str
        and left_file["path"] == right_file.get("path")
        and type(left.get("cdhash")) is str
        and re.fullmatch(r"[a-fA-F0-9]{40}", left["cdhash"]) is not None
        and all(left.get(key) == right.get(key) for key in ("cdhash", "signing_id", "team_id"))
    )


class Tracker:
    """Bounded ambient ring; only an authenticated browser graph reaches disk."""

    def __init__(self, manifest: Manifest, profile: str, url: str) -> None:
        self.manifest, self.profile, self.url = manifest, profile, url
        self.ready_pids: set[int] = set()
        self.ready_executions: set[tuple[int, int, int]] = set()
        self.ready = False
        self.collecting = False
        self.total = 0
        self.sequence: dict[int, int] = {}
        self.global_sequence = -1
        self.sequence_ok = True
        self.ring: deque[tuple[bytes, dict]] = deque()
        self.ring_bytes = 0
        self.ring_evicted = False
        self.records: list[bytes] = []
        self.retained_bytes = 0
        self.retained_sequences: set[int] = set()
        self.known: dict[tuple[int, int, int], dict] = {}
        self.known_order: dict[tuple[int, int, int], int] = {}
        self.main: dict | None = None
        self.main_exit = False

    def _is_main(self, row: dict) -> bool:
        if row["event_type"] != 9:
            return False
        payload = row["event"].get("exec", {})
        target = payload.get("target", {})
        image = _image_policy(target, self.manifest)
        args = payload.get("args", [])
        expected = [
            f"--user-data-dir={self.profile}",
            *MAIN_FLAGS,
            "--new-window",
            self.url,
        ]
        return (
            image is not None
            and image.kind == "MAIN"
            and _signature_agrees(target, image)
            and type(args) is list
            and all(type(arg) is str for arg in args)
            and [arg for arg in args[1:] if re.fullmatch(r"-psn_[0-9]+_[0-9]+", arg) is None]
            == expected
        )

    def _retain(self, raw: bytes, row: dict) -> None:
        sequence = row["global_seq_num"]
        if sequence in self.retained_sequences:
            return
        if len(self.records) >= MAX_ROWS or self.retained_bytes + len(raw) > MAX_PRIVATE_BYTES:
            raise reference.PrivateError("LIMIT")
        self.retained_sequences.add(sequence)
        self.records.append(raw)
        self.retained_bytes += len(raw)

    def _ancestor(self, before: dict) -> None:
        """Retain only exact xpcproxy exec/fork linked to the nonce browser."""
        matches = [
            (raw, row)
            for raw, row in self.ring
            if row["event_type"] == 9
            and _same(row["event"]["exec"]["target"], before)
            and _role(before, self.manifest) == "XPCPROXY"
        ]
        if len(matches) != 1:
            return
        raw, row = matches[0]
        self.known[reference._identity(before)] = before
        self.known_order[reference._identity(before)] = row["global_seq_num"]
        pre = row["process"]
        for fork_raw, fork in self.ring:
            if fork["event_type"] != 11 or fork["global_seq_num"] >= row["global_seq_num"]:
                continue
            if _same(fork["event"]["fork"]["child"], pre):
                self._retain(fork_raw, fork)
                self.known[reference._identity(pre)] = pre
                self.known_order[reference._identity(pre)] = fork["global_seq_num"]
        self._retain(raw, row)

    def _related(self, raw: bytes, row: dict) -> bool:
        process, kind = row["process"], row["event_type"]
        known = self.known.get(reference._identity(process))
        owned = (
            known is not None
            and _same(known, process)
            and (self.known_order[reference._identity(process)] < row["global_seq_num"])
        )
        if kind == 11 and owned:
            child = row["event"]["fork"]["child"]
            if reference._token(child, "parent_audit_token") != reference._token(process):
                return False
            self.known[reference._identity(child)] = child
            self.known_order[reference._identity(child)] = row["global_seq_num"]
        elif kind == 9:
            target = row["event"]["exec"]["target"]
            before_token, target_token = reference._token(process), reference._token(target)
            if not (
                before_token[5] == target_token[5]
                and target_token[7] == before_token[7] + 1
                and reference._birth(process) == reference._birth(target)
            ):
                return False
            # A missing fork is diagnosed; parent proof may admit a known vendor helper.
            parent = reference._token(target, "parent_audit_token")
            image = _image_policy(target, self.manifest)
            parent_proof = any(
                reference._token(value) == parent
                and self.known_order[identity] < row["global_seq_num"]
                for identity, value in self.known.items()
            )
            if not owned and not (
                image is not None
                and _signature_agrees(target, image)
                and parent_proof
                and reference._token(target)[5] == reference._token(process)[5]
                and reference._birth(target) == reference._birth(process)
            ):
                return False
            self.known[reference._identity(target)] = target
            self.known_order[reference._identity(target)] = row["global_seq_num"]
        elif kind == 15 and owned:
            if self.main is not None and _same(process, self.main):
                self.main_exit = True
        else:
            return False
        if len(self.known) > len(ALIASES):
            raise reference.PrivateError("LIMIT")
        self._retain(raw, row)
        return True

    def accept(self, raw: bytes) -> list:
        """Pump interface; private records are flushed only from the selected graph."""
        self.total += len(raw)
        if self.total > MAX_STREAM:
            raise reference.PrivateError("LIMIT")
        row = reference._decode(raw)
        kind, sequence, global_sequence = (
            row.get("event_type"),
            row.get("seq_num"),
            row.get("global_seq_num"),
        )
        if kind not in (9, 11, 15) or any(
            type(value) is not int or value < 0 for value in (sequence, global_sequence)
        ):
            raise reference.PrivateError("DATA")
        if (
            kind in self.sequence and sequence != self.sequence[kind] + 1
        ) or global_sequence <= self.global_sequence:
            self.sequence_ok = False
        self.sequence[kind], self.global_sequence = sequence, global_sequence
        process = row["process"]
        if kind == 9:
            payload = row["event"]["exec"]
            target = payload["target"]
            if (
                reference._owned(target, self.manifest.marker)
                and reference._token(target)[5] in self.ready_pids
                and payload.get("args", [])[1:] == ["--ready"]
            ):
                self.ready_executions.add(reference._identity(target))
                return []
        elif kind == 15 and reference._identity(process) in self.ready_executions:
            self.ready |= row["event"]["exit"].get("stat") == 0
            return []
        if not self.collecting:
            return []
        self.ring.append((raw, row))
        self.ring_bytes += len(raw)
        while len(self.ring) > MAX_RING_ROWS or self.ring_bytes > MAX_RING_BYTES:
            removed, _ = self.ring.popleft()
            self.ring_bytes -= len(removed)
            self.ring_evicted = True
        if self._is_main(row):
            target = row["event"]["exec"]["target"]
            if self.main is not None and not _same(self.main, target):
                raise reference.PrivateError("DATA")
            self.main = target
            self.known[reference._identity(target)] = target
            self.known_order[reference._identity(target)] = row["global_seq_num"]
            self._ancestor(row["process"])
            self._retain(raw, row)
        if self.main is not None:
            # Replay the bounded in-memory ring to handle previously unproven children.
            for candidate_raw, candidate in self.ring:
                if candidate["global_seq_num"] not in self.retained_sequences:
                    self._related(candidate_raw, candidate)
        return []


def classify_entitlements(payload: dict, image: Image | None) -> Entitlements:
    """Export known public key comparisons only; hide all unknown names and values."""
    value = payload.get("entitlements")
    representation = (
        "ABSENT"
        if "entitlements" not in payload
        else ("NULL" if value is None else "OBJECT" if type(value) is dict else "OTHER")
    )
    data = value if type(value) is dict else {}
    expected_id = f"{image.team_id}.{image.signing_id}" if image else None
    groups = [
        "EQHXZ8M8AV.com.google.common.folsom",
        *(
            f"EQHXZ8M8AV.com.google.Chrome.{suffix}"
            for suffix in (
                "devicetrust",
                "secure-payment-confirmation",
                "unexportable-keys",
                "webauthn",
                "webauthn-uvk",
            )
        ),
    ]
    known = set(BOOLEAN_ENTITLEMENTS) | {
        "com.apple.application-identifier",
        "keychain-access-groups",
    }
    return Entitlements(
        representation=representation,
        matches_installed_code=reference._check(
            json.dumps(data, sort_keys=True) == json.dumps(image.entitlements, sort_keys=True)
            and representation in {"NULL", "OBJECT"}
        )
        if image
        else "INCONCLUSIVE",
        known_booleans=tuple(
            EntitlementMember(
                key=key,
                value="TRUE" if data[key] is True else "FALSE" if data[key] is False else "OTHER",
            )
            for key in BOOLEAN_ENTITLEMENTS
            if key in data
        ),
        application_identifier="ABSENT"
        if "com.apple.application-identifier" not in data
        else (
            "TEAM_AND_BUNDLE"
            if data["com.apple.application-identifier"] == expected_id
            else "OTHER"
        ),
        keychain_groups="ABSENT"
        if "keychain-access-groups" not in data
        else ("CHROME_PUBLIC_TEMPLATE" if data["keychain-access-groups"] == groups else "OTHER"),
        other_keys="PRESENT" if set(data) - known else "ABSENT",
    )


def classify_arguments(payload: dict, profile: str, url: str) -> Arguments:
    args = payload.get("args", [])
    values: dict[str, str] = {}
    duplicate = False
    positionals = False
    for arg in args[1:]:
        if not arg.startswith("--"):
            positionals |= arg != url
            continue
        key, _, value = arg[2:].partition("=")
        duplicate |= key in values
        values[key] = value
    known = []
    for key in KNOWN_SWITCHES:
        if key not in values:
            continue
        value = values[key]
        label = "PRESENT" if value else "EMPTY"
        if key == "type":
            label = {"renderer": "RENDERER", "gpu-process": "GPU", "utility": "UTILITY"}.get(
                value, "OTHER"
            )
        elif key == "utility-sub-type":
            label = {
                "network.mojom.NetworkService": "NETWORK",
                "audio.mojom.AudioService": "AUDIO",
                "storage.mojom.StorageService": "STORAGE",
            }.get(value, "OTHER")
        elif key == "user-data-dir":
            label = "TEST_PROFILE" if value == profile else "OTHER"
        elif value.isascii() and value.isdecimal():
            label = "DECIMAL"
        descriptor = "NOT_DESCRIPTOR"
        if key in {"seatbelt-client", "mojo-platform-channel-handle"}:
            descriptor = (
                FD_SLOTS[int(value)]
                if value.isascii() and value.isdecimal() and (int(value) < len(FD_SLOTS))
                else "OTHER"
            )
        known.append(ArgumentSwitch(name=key, value=label, descriptor_slot=descriptor))
    expected = (
        {flag[2:].partition("=")[0] for flag in MAIN_FLAGS} | set(KNOWN_SWITCHES) | {"new-window"}
    )
    return Arguments(
        image_argv0=reference._check(
            bool(args) and args[0] == payload["target"]["executable"]["path"]
        ),
        test_profile="ABSENT"
        if "user-data-dir" not in values
        else ("EXACT" if values["user-data-dir"] == profile else "OTHER"),
        controlled_url="PRESENT" if url in args else "ABSENT",
        known=tuple(known),
        other_switches="PRESENT" if set(values) - expected else "ABSENT",
        other_positionals="PRESENT" if positionals else "ABSENT",
        duplicate_switches="PRESENT" if duplicate else "ABSENT",
    )


def _descriptors(
    payload: dict, pipes: dict[int, str]
) -> tuple[tuple[Descriptor, ...], Check, Check]:
    fds = payload.get("fds")
    if type(fds) is not list or len(fds) > 64:
        return (), "FAIL", "INCONCLUSIVE"
    slots = set()
    result = []
    for item in fds:
        slot, kind = item.get("fd"), item.get("fdtype")
        if type(slot) is not int or slot < 0 or slot in slots:
            return (), "FAIL", "INCONCLUSIVE"
        slots.add(slot)
        pipe = "NOT_PIPE"
        if kind == 6:
            identity = item.get("pipe", {}).get("pipe_id")
            if type(identity) is not int or not 0 <= identity < 2**64:
                return (), "FAIL", "INCONCLUSIVE"
            pipe = pipes.setdefault(
                identity, "ABCDEFGHIJKLMNOP"[len(pipes)] if len(pipes) < 16 else "OTHER"
            )
        result.append(
            Descriptor(
                slot=FD_SLOTS[slot] if slot < len(FD_SLOTS) else "OTHER",
                kind={1: "VNODE", 2: "SOCKET", 6: "PIPE"}.get(kind, "OTHER"),
                pipe=pipe,
            )
        )
    return tuple(result), "PASS", reference._check(payload.get("last_fd") == max(slots, default=-1))


def analyze(
    raws: list[bytes], manifest: Manifest, profile: str, url: str, home: str
) -> tuple[Phase, ...]:
    """Pure fixed-output analysis; no commands, filesystem reads or native values."""
    if len(raws) > MAX_ROWS or sum(map(len, raws)) > MAX_PRIVATE_BYTES:
        raise reference.PrivateError("LIMIT")
    rows = sorted((reference._decode(raw) for raw in raws), key=lambda row: row["global_seq_num"])
    snapshots: dict[tuple[int, int, int], dict] = {}
    roles: dict[tuple[int, int, int], Role] = {}
    before_env: dict[tuple[int, int, int], list[str]] = {}
    aliases: dict[tuple[int, int, int], str] = {}
    main = None
    for row in rows:
        process, kind = row["process"], row["event_type"]
        for proc, payload in (
            (process, None),
            *(
                ((row["event"]["exec"]["target"], row["event"]["exec"]),)
                if kind == 9
                else ((row["event"]["fork"]["child"], None),)
                if kind == 11
                else ()
            ),
        ):
            identity = reference._identity(proc)
            if reference._token(proc)[5] == 1:
                continue
            if identity not in aliases:
                if len(aliases) == len(ALIASES):
                    raise reference.PrivateError("LIMIT")
                aliases[identity] = ALIASES[len(aliases)]
            snapshots[identity] = proc
            role = _role(proc, manifest, payload)
            if role != "OTHER" or identity not in roles:
                roles[identity] = role
            if payload is not None:
                before_env[identity] = payload["env"]
                if role == "MAIN":
                    main = proc

    def token_alias(token: tuple[int, ...]) -> str:
        if token[5] == 1:
            return "BOOT"
        if all(word == 0 for word in token):
            return "UNSET"
        matches = [
            identity for identity, proc in snapshots.items() if reference._token(proc) == token
        ]
        if len(matches) == 1:
            return aliases[matches[0]]
        same_execution = [
            identity
            for identity, proc in snapshots.items()
            if (reference._token(proc)[5], reference._token(proc)[7]) == (token[5], token[7])
        ]
        return aliases[same_execution[0]] if len(same_execution) == 1 else "OTHER"

    def snapshot(proc: dict) -> Snapshot:
        token = reference._token(proc)
        parent = reference._token(proc, "parent_audit_token")
        responsible = reference._token(proc, "responsible_audit_token")
        image = _image_policy(proc, manifest)

        def membership(value: object) -> str:
            if value == token[5]:
                return "SELF"
            if value == parent[5]:
                return "PARENT"
            if main is not None and value == reference._token(main)[5]:
                return "MAIN"
            return "BOOT" if value == 1 else "OTHER"

        return Snapshot(
            execution="BOOT" if token[5] == 1 else aliases.get(reference._identity(proc), "OTHER"),
            role=roles.get(reference._identity(proc), _role(proc, manifest)),
            parent=token_alias(parent),
            responsible=token_alias(responsible),
            responsible_exact_token=reference._check(
                any(reference._token(value) == responsible for value in snapshots.values())
            ),
            credentials="LOCAL_USER"
            if token[1:5] == (manifest.uid, manifest.gid, manifest.uid, manifest.gid)
            else "ROOT"
            if token[1:5] == (0, 0, 0, 0)
            else "OTHER",
            audit_user="LOCAL_USER"
            if token[0] == manifest.uid
            else ("UNATTRIBUTED" if token[0] == 2**32 - 1 else "OTHER"),
            audit_session_from_main=reference._check(token[6] == reference._token(main)[6])
            if main
            else "INCONCLUSIVE",
            group=membership(proc.get("group_id")),
            session=membership(proc.get("session_id")),
            tty="UNKNOWN" if "tty" not in proc else "ABSENT" if proc["tty"] is None else "PRESENT",
            original_parent_matches_parent=reference._check(proc.get("original_ppid") == parent[5]),
            installed_image_agreement=reference._check(image is not None),
            installed_signature_agreement=reference._check(_signature_agrees(proc, image))
            if image
            else "INCONCLUSIVE",
            installed_path_spelling="UNQUALIFIED_IMAGE"
            if image is None
            else "EXACT"
            if (proc["executable"]["path"] == image.path)
            else "OTHER",
            signing_identifier={
                "com.google.Chrome": "CHROME_MAIN",
                "com.google.Chrome.helper": "CHROME_HELPER",
                "com.google.Chrome.helper.renderer": "CHROME_RENDERER",
                "com.google.Chrome.helper.GPU": "CHROME_GPU",
                "com.apple.xpc.proxy": "XPCPROXY",
            }.get(proc.get("signing_id"), "OTHER"),
            team_identifier="ABSENT"
            if proc.get("team_id") in (None, "")
            else ("GOOGLE" if proc["team_id"] == "EQHXZ8M8AV" else "OTHER"),
            security=reference.inspect_native_security(proc),
        )

    result = []
    pipes: dict[int, str] = {}
    for row in rows:
        kind, before = row["event_type"], row["process"]
        try:
            reference.decode_endpoint_security_record(json.dumps(row))
            native_shape = "PASS"
        except (ValueError, TypeError):
            native_shape = "FAIL"
        values = dict(
            kind={9: "EXEC", 11: "FORK", 15: "EXIT"}[kind],
            before=snapshot(before),
            native_shape=native_shape,
            shape_excluding_entitlements=reference._shape_without_entitlements(row),
        )
        if kind == 11:
            child = row["event"]["fork"]["child"]
            values.update(
                after=snapshot(child),
                fork_image_preserved=reference._check(_same_image(before, child)),
                fork_parent_token_agreement=reference._check(
                    reference._token(child, "parent_audit_token") == reference._token(before)
                ),
            )
        elif kind == 9:
            payload = row["event"]["exec"]
            target = payload["target"]
            fd_values, fd_ok, last_ok = _descriptors(payload, pipes)
            env = {}
            for member in payload["env"]:
                key, separator, value = member.partition("=")
                if separator:
                    env[key] = value
            previous = before_env.get(reference._identity(before))
            cwd = payload.get("cwd", {}).get("path")
            bt, tt = reference._token(before), reference._token(target)
            values.update(
                after=snapshot(target),
                audit_origin_preserved=reference._check((bt[0], bt[6]) == (tt[0], tt[6])),
                posix_credentials_preserved=reference._check(bt[1:5] == tt[1:5]),
                posix_membership_preserved=reference._check(
                    all(before.get(key) == target.get(key) for key in ("group_id", "session_id"))
                ),
                parentage_preserved=reference._check(
                    reference._token(before, "parent_audit_token")
                    == reference._token(target, "parent_audit_token")
                ),
                exec_identity_transition=reference._check(
                    bt[5] == tt[5]
                    and tt[7] == bt[7] + 1
                    and reference._birth(before) == reference._birth(target)
                ),
                arguments=classify_arguments(payload, profile, url),
                descriptors=fd_values,
                fd_inventory_well_formed=fd_ok,
                last_fd_agreement=last_ok,
                only_standard_descriptors=reference._check(
                    {item.get("fd") for item in payload.get("fds", [])} == {0, 1, 2}
                ),
                cwd={"/": "ROOT", home: "TEST_HOME", profile: "TEST_PROFILE"}.get(
                    cwd, "UNKNOWN" if cwd is None else "OTHER"
                ),
                script_absent=reference._check(payload.get("script") is None),
                dyld_path_matches_target=reference._check(
                    payload.get("dyld_exec_path") == target["executable"]["path"]
                ),
                slice=reference.inspect_native_slice(payload),
                entitlements=classify_entitlements(payload, _image_policy(target, manifest)),
                environment=Environment(
                    from_before_exec=reference.compare_environment(
                        tuple(item.encode() for item in previous),
                        tuple(item.encode() for item in payload["env"]),
                    )
                    if previous is not None
                    else None,
                    only_known_keys=reference._check(
                        not set(env)
                        - {
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
                        }
                    ),
                    home="ABSENT"
                    if "HOME" not in env
                    else ("TEST_HOME" if env["HOME"] == home else "OTHER"),
                    path="ABSENT"
                    if "PATH" not in env
                    else ("CONTROLLED" if env["PATH"] == reference.SAFE_ENV["PATH"] else "OTHER"),
                    xpc_service_name="ABSENT"
                    if "XPC_SERVICE_NAME" not in env
                    else ("NONEMPTY" if env["XPC_SERVICE_NAME"] else "OTHER"),
                ),
            )
        else:
            status = row["event"]["exit"].get("stat")
            values["exit_outcome"] = (
                "UNKNOWN"
                if type(status) is not int
                else ("ZERO" if status == 0 else "SIGNALLED" if status & 0x7F else "OTHER_STATUS")
            )
        result.append(Phase(**values))
    return tuple(result)


class LocalServer(HTTPServer):
    """Fixed nonce routes only: no file serving, request logging or submitted data."""

    def __init__(self, nonce: str) -> None:
        self.nonce = nonce
        self.page = False
        self.fetch = False
        self.webgl: Literal["CREATED", "UNAVAILABLE", "NOT_OBSERVED"] = "NOT_OBSERVED"
        self.requests = 0
        super().__init__(("127.0.0.1", 0), LocalHandler)

    def get_request(self) -> tuple:
        request, address = super().get_request()
        request.settimeout(0.5)
        return request, address

    def handle_error(self, _request: object, _client_address: object) -> None:
        pass  # Never print request data or exception details.


class LocalHandler(BaseHTTPRequestHandler):
    """The sole response is invented HTML or a fixed empty fetch result."""

    server: LocalServer

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.server.requests += 1
        base = f"/{self.server.nonce}/"
        body = b""
        status = 404
        if self.server.requests <= 128:
            if self.path == base:
                status = 200
                self.server.page = True
                body = (
                    b"<!doctype html><meta charset=utf-8><title>EvidenceForge Chrome Reference</title>"
                    b"<h1>EvidenceForge private reference</h1><p>Only invented local content.</p>"
                    b"<canvas id=c width=320 height=160></canvas><p id=s>Testing local rendering...</p>"
                    b"<script>const gl=document.getElementById('c').getContext('webgl2');"
                    b"if(gl){gl.clearColor(.1,.5,.3,1);gl.clear(gl.COLOR_BUFFER_BIT);}"
                    b"fetch('probe');fetch(gl?'gl-created':'gl-unavailable');"
                    b"document.getElementById('s').textContent="
                    b"'Reference loaded. Wait for QUIT_CHROME in Terminal, then press Command-Q here.';"
                    b"</script>"
                )
            elif self.path == base + "probe":
                status = 204
                self.server.fetch = True
            elif self.path in (base + "gl-created", base + "gl-unavailable"):
                status = 204
                self.server.webgl = "CREATED" if self.path.endswith("gl-created") else "UNAVAILABLE"
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)


def _emit(report: Report, *, progress: bool = False, full: bool = False) -> None:
    print(
        report.model_dump_json(
            indent=None if progress else 2,
            include={"purpose", "error", "stage"} if progress else None,
            exclude=None if progress or full else {"phases"},
        ),
        flush=True,
    )


def _launch_command(profile: Path, url: str) -> list[str]:
    return [
        "/usr/bin/open",
        "-n",
        "-a",
        str(APP),
        "--args",
        f"--user-data-dir={profile}",
        *MAIN_FLAGS,
        "--new-window",
        url,
    ]


def capture() -> Report:
    """HUMAN ONLY: new isolated profile, loopback page, then manual test-app quit."""
    root = _root()
    platform_version = reference._preflight()
    manifest = _manifest(root, installed=True)
    if platform_version != (manifest.os_version, manifest.os_build):
        raise reference.PrivateError("PLATFORM")
    try:
        reference._write(root / "SESSION-LOCK", b"ACTIVE\n")
    except FileExistsError as error:
        raise reference.PrivateError("SESSION_LOCKED") from error
    run = root / f"run-{uuid.uuid4().hex}"
    run.mkdir(mode=0o700)
    reference._replace(root / "ACTIVE-RUN", (run.name + "\n").encode())
    profile, home = run / "profile", run / "home"
    profile.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    server: LocalServer | None = None
    server_thread: threading.Thread | None = None
    collector: subprocess.Popen[bytes] | None = None
    launcher: subprocess.Popen[bytes] | None = None
    probes: list[subprocess.Popen[bytes]] = []
    pump: reference.Pump | None = None
    tracker: Tracker | None = None
    report = Report(
        target_platform="PASS", provenance="PASS", catalog_release=_release(manifest), step="SERVER"
    )
    cleaned = server_cleaned = False
    try:
        nonce = uuid.uuid4().hex
        server = LocalServer(nonce)
        url = f"http://127.0.0.1:{server.server_port}/{nonce}/"
        reference._write(
            run / "provenance.json",
            json.dumps(
                {
                    "setup": manifest.model_dump(),
                    "profile": str(profile),
                    "home": str(home),
                    "url": url,
                }
            ).encode(),
        )
        server_thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        server_thread.start()
        tracker = Tracker(manifest, str(profile), url)
        report = report.model_copy(update={"step": "COLLECTOR"})
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(root / "collector-guard")],
            env=reference.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        pump = reference.Pump(collector, tracker, {})
        deadline, next_probe = time.monotonic() + 10, 0.0
        while time.monotonic() < deadline and not tracker.ready:
            if time.monotonic() >= next_probe and len(probes) < 8:
                probe = reference._start(root / "ready-marker", "--ready")
                probes.append(probe)
                tracker.ready_pids.add(probe.pid)
                next_probe = time.monotonic() + 1
            pump.tick()
        if not tracker.ready:
            raise reference.PrivateError("COLLECTOR")
        report = report.model_copy(update={"collector_ready": "PASS", "stage": "COLLECTOR_READY"})
        _emit(report, progress=True)
        tracker.collecting = True
        report = report.model_copy(update={"step": "BROWSER"})
        # No inherited shell environment, debugging endpoint, automation or sandbox bypass.
        # LaunchServices may supply its GUI-login environment; that stays private.
        launcher = subprocess.Popen(
            _launch_command(profile, url),
            env={**reference.SAFE_ENV, "HOME": str(home)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        started, quit_prompt = time.monotonic(), False
        deadline = started + 32
        report = report.model_copy(update={"stage": "BROWSER_READY", "step": "COLLECTION"})
        _emit(report, progress=True)
        while time.monotonic() < deadline:
            pump.tick()
            status = launcher.poll()
            if status is not None and status != 0:
                raise reference.PrivateError("LAUNCH")
            if not quit_prompt and server.fetch and time.monotonic() - started >= 5:
                quit_prompt = True
                report = report.model_copy(update={"stage": "QUIT_CHROME"})
                _emit(report, progress=True)
            if tracker.main_exit:
                break
        else:
            raise reference.PrivateError("TIMEOUT")
        report = report.model_copy(
            update={"bounded_collection": "PASS", "stage": "COMPLETE", "step": "COMPLETE"}
        )
    except KeyboardInterrupt:
        report = report.model_copy(update={"error": "INTERRUPTED", "stage": "ERROR"})
    except reference.PrivateError as error:
        report = report.model_copy(update={"error": error.code, "stage": "ERROR"})
    except (OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError):
        report = report.model_copy(update={"error": "INTERNAL", "stage": "ERROR"})
    finally:
        if collector is not None:
            try:
                cleaned = reference._stop_collector(collector)
            except (OSError, subprocess.SubprocessError):
                cleaned = False
        else:
            cleaned = True
        for probe in (*probes, *((launcher,) if launcher else ())):
            try:
                reference._stop_probe(probe)
            except (OSError, subprocess.SubprocessError):
                cleaned = False
        if pump is not None:
            pump.selector.close()
        if collector is not None and collector.stdout is not None:
            collector.stdout.close()
        if server is not None:
            if server_thread is not None:
                # Bound shutdown even if another local client stalls in its headers.
                stopper = threading.Thread(target=server.shutdown, daemon=True)
                stopper.start()
                stopper.join(timeout=2)
                server_thread.join(timeout=1)
            server.server_close()
            server_cleaned = server_thread is None or not server_thread.is_alive()
        else:
            server_cleaned = True
    report = report.model_copy(
        update={
            "collector_cleanup": reference._check(cleaned),
            "server_cleanup": reference._check(server_cleaned),
        }
    )
    try:
        # Installed-code verification runs after all live collection/server cleanup.
        _manifest(root, installed=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report = report.model_copy(
            update={
                "error": "BUILD",
                "stage": "ERROR",
                "step": "VERIFY",
                "provenance": "FAIL",
                **(error.labels() if isinstance(error, InstalledCodeError) else {}),
            }
        )
    if tracker is not None:
        raws = sorted(tracker.records, key=lambda raw: reference._decode(raw)["global_seq_num"])
        reference._write(run / "chrome-events.jsonl", b"".join(raw + b"\n" for raw in raws))
        report = report.model_copy(
            update={
                "main_exit_seen": reference._check(tracker.main_exit),
                "sequence_continuity": reference._check(tracker.sequence_ok)
                if tracker.sequence
                else "INCONCLUSIVE",
                "candidate_ring_evicted": tracker.ring_evicted,
            }
        )
        try:
            report = _analyzed_report(report, raws, manifest, str(profile), url, str(home))
        except (ValueError, KeyError, TypeError, OverflowError):
            report = report.model_copy(
                update={"error": "DATA", "stage": "ERROR", "step": "ANALYSIS"}
            )
    if server is not None:
        report = report.model_copy(
            update={
                "controlled_page": reference._check(server.page),
                "controlled_fetch": reference._check(server.fetch),
                "webgl_context": server.webgl,
            }
        )
    if not (cleaned and server_cleaned):
        report = report.model_copy(update={"error": "COLLECTOR", "stage": "ERROR"})
    report, report_bytes = _bounded_report(report)
    reference._write(run / "SHAREABLE-CHROME-REPORT.json", report_bytes)
    reference._replace(root / "SHAREABLE-CHROME-REPORT.json", report_bytes)
    # Do not kill Chrome using a bare PID or bundle-wide quit. A timeout leaves its lock.
    if cleaned and server_cleaned and (tracker is None or tracker.main_exit):
        (root / "SESSION-LOCK").unlink()
    return report


def _bounded_report(report: Report) -> tuple[Report, bytes]:
    raw = report.model_dump_json(indent=2).encode()
    if len(raw) > MAX_REPORT_BYTES:
        report = report.model_copy(
            update={"error": "LIMIT", "stage": "ERROR", "step": "ANALYSIS", "phases": ()}
        )
        raw = report.model_dump_json(indent=2).encode()
    return report, raw


def _analyzed_report(
    report: Report, raws: list[bytes], manifest: Manifest, profile: str, url: str, home: str
) -> Report:
    phases = analyze(raws, manifest, profile, url, home)
    roles = {phase.after.role for phase in phases if phase.kind == "EXEC" and phase.after}
    rows = [reference._decode(raw) for raw in raws]

    def life(process: dict) -> tuple[int, int]:
        return reference._token(process)[5], reference._birth(process)

    forks = {life(row["event"]["fork"]["child"]) for row in rows if row["event_type"] == 11}
    execs = {life(row["event"]["exec"]["target"]) for row in rows if row["event_type"] == 9}
    exits = {life(row["process"]) for row in rows if row["event_type"] == 15}
    return report.model_copy(
        update={
            "phases": phases,
            "forks_observed": sum(row["event_type"] == 11 for row in rows),
            "execs_observed": sum(row["event_type"] == 9 for row in rows),
            "exits_observed": sum(row["event_type"] == 15 for row in rows),
            "exec_lifetimes_without_fork": len(execs - forks),
            "fork_lifetimes_without_exec": len(forks - execs),
            "started_lifetimes_without_exit": len((forks | execs) - exits),
            "wire_profile": reference._wire_profile(raws),
            **{
                f"{name.lower()}_exec": reference._check(name in roles)
                for name in ("MAIN", "RENDERER", "GPU", "NETWORK")
            },
        }
    )


def report_existing() -> Report:
    """HUMAN ONLY: read the latest bounded run offline; start nothing and write nothing."""
    root = _root()
    manifest = _manifest(root, installed=False)
    name = reference._read(root / "ACTIVE-RUN", 128).decode("ascii").strip()
    if re.fullmatch(r"run-[0-9a-f]{32}", name) is None:
        raise reference.PrivateError("LOCATION")
    run = root / name
    reference._directory(run)
    provenance = reference._decode(reference._read(run / "provenance.json"))
    if provenance["setup"] != json.loads(manifest.model_dump_json()):
        raise reference.PrivateError("BUILD")
    profile, home = str(run / "profile"), str(run / "home")
    if provenance["profile"] != profile or provenance["home"] != home:
        raise reference.PrivateError("LOCATION")
    url = provenance["url"]
    if re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}/[0-9a-f]{32}/", url) is None:
        raise reference.PrivateError("DATA")
    report = Report.model_validate_json(
        reference._read(run / "SHAREABLE-CHROME-REPORT.json", MAX_REPORT_BYTES)
    )
    raws = reference._read(run / "chrome-events.jsonl", MAX_PRIVATE_BYTES + MAX_ROWS).splitlines()
    # Re-authenticate retained data; never use a supplied native row as a report template.
    tracker = Tracker(manifest, profile, url)
    tracker.collecting = True
    for raw in raws:
        tracker.accept(raw)
    if set(raws) != set(tracker.records):
        raise reference.PrivateError("DATA")
    return _bounded_report(_analyzed_report(report, raws, manifest, profile, url, home))[0]


def main(argv: list[str] | None = None) -> int:
    parser = reference.QuietParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    preparing = commands.add_parser("prepare")
    preparing.add_argument("--destination", type=Path)
    for name in ("setup", "capture", "report", "diagnose-code"):
        stage = commands.add_parser(name)
        stage.add_argument("--private-run", action="store_true", required=True)
        if name == "capture":
            stage.add_argument("--chrome-closed", action="store_true", required=True)
            stage.add_argument("--network-disconnected", action="store_true", required=True)
        if name == "report":
            stage.add_argument("--full-report", action="store_true")
    full = False
    try:
        args = parser.parse_args(argv)
        full = args.command == "report" and args.full_report
        if args.command == "prepare":
            print(prepare(args.destination))
            return 0
        if args.command == "diagnose-code":
            result = diagnose_code()
            print(result.model_dump_json(indent=2), flush=True)
            return 0 if result.error == "NONE" else 2
        report = (
            setup()
            if args.command == "setup"
            else capture()
            if args.command == "capture"
            else report_existing()
        )
    except reference.PrivateError as error:
        report = Report(
            error=error.code,
            step=error.step if isinstance(error, DiagnosticError) else "INPUT",
            **(error.labels() if isinstance(error, InstalledCodeError) else {}),
        )
    except KeyboardInterrupt:
        report = Report(error="INTERRUPTED")
    except OSError:
        report = Report(error="IO")
    except (ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError):
        report = Report(error="INTERNAL")
    _emit(report, full=full)
    return 0 if report.error == "NONE" else 2


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: _emit(Report(error="INTERNAL"))
    raise SystemExit(main())
