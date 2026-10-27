# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a HUMAN-ONLY Gatekeeper kit. Agents may prepare and test invented inputs only.

Private operations require human execution or explicit human authorization. Agents may
never see native values or records. Offline shape review needs separate permission to read
retained records locally; it exports fixed labels only and never qualifies native meaning.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import platform
import plistlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import warnings
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import TCPServer
from typing import BinaryIO, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.formats.macos_unified_log import UnifiedLogRecord

logger = logging.getLogger(__name__)
SOURCES = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/gatekeeper-reference"
)
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
CODE_FILES = (
    "private_gatekeeper.py",
    "marker_probe.c",
    "metadata_probe.m",
    "collector_guard.c",
    "PRIVATE-RUN.md",
)
MAX_LINE = 1_048_576
MAX_ARCHIVE = 4_194_304
MAX_RETAINED = 128
MAX_RETAINED_BYTES = 4_194_304
MAX_STREAMED = 100_000
READINESS_SECONDS = 12.0
CAPTURE_SECONDS = 30.0
SERVER_SECONDS = 900.0
WRITERS = ("syspolicyd", "amfid", "taskgated-helper", "runningboardd", "kernel")
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Presence = Literal["PRESENT", "ABSENT", "INCONCLUSIVE"]
type Code = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "ROOT_USER",
    "PLATFORM",
    "BUILD",
    "DATA",
    "DUPLICATE",
    "DELIVERY",
    "QUARANTINE",
    "COLLECTOR",
    "ES_READINESS",
    "UL_READINESS",
    "CONTROL",
    "INTERRUPTED",
    "FILE_MISSING",
    "FILE_ACCESS",
    "FILE_TYPE",
    "FILE_IO",
    "HELPER_OUTPUT",
    "INTERNAL",
]
type VerifyStep = Literal[
    "INPUT",
    "PROVENANCE",
    "PLATFORM",
    "DOWNLOAD_FOLDER",
    "DELIVERY_MARKER",
    "ARCHIVE_CONTENT",
    "APP_BUNDLE",
    "APP_BINARY",
    "APP_METADATA",
    "BINARY_CONTENT",
    "BUNDLE_CONTENT",
    "SIGNATURE",
    "ARCHIVE_QUARANTINE",
    "APP_QUARANTINE",
    "COMPLETE",
]
type Outcome = Literal[
    "NOT_REVIEWED", "BLOCK_ALERT", "CONSENT_PROMPT", "RAN", "CANCELLED", "CRASH_OR_ERROR", "OTHER"
]
type Launch = Literal["NOT_ATTEMPTED", "RETURNED_SUCCESS", "RETURNED_ERROR", "TIMED_OUT"]


class PrivateError(ValueError):
    """Only fixed diagnostic codes; never retain native exception text."""

    def __init__(self, code: Code) -> None:
        self.code = code
        super().__init__(code)


class Report(BaseModel, extra="forbid", frozen=True, strict=True):
    """The only shareable object; every leaf has a fixed vocabulary."""

    kit_version: Literal[2] = 2
    purpose: Literal["GATEKEEPER_REFERENCE_DIAGNOSTIC"] = "GATEKEEPER_REFERENCE_DIAGNOSTIC"
    collection: Literal["LIVE_TEST_ITEM_ONLY"] = "LIVE_TEST_ITEM_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Code = "NONE"
    target_platform: Check = "INCONCLUSIVE"
    provenance: Check = "INCONCLUSIVE"
    browser_delivery: Literal["HUMAN_ATTESTED", "INCONCLUSIVE"] = "INCONCLUSIVE"
    same_executable: Check = "INCONCLUSIVE"
    signature_integrity: Check = "INCONCLUSIVE"
    archive_quarantine: Presence = "INCONCLUSIVE"
    app_quarantine: Presence = "INCONCLUSIVE"
    es_ready: Check = "INCONCLUSIVE"
    unified_log_ready: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    launch_method: Literal["LAUNCHSERVICES_OPEN"] = "LAUNCHSERVICES_OPEN"
    downloaded_launch: Launch = "NOT_ATTEMPTED"
    downloaded_marker: Presence = "INCONCLUSIVE"
    local_control_launch: Launch = "NOT_ATTEMPTED"
    local_control_marker: Presence = "INCONCLUSIVE"
    test_item_policy_records: Literal["OBSERVED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    unified_log_shapes: Check = "INCONCLUSIVE"
    es_exec_records: Literal["OBSERVED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    es_exit_records: Literal["OBSERVED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    es_shapes: Check = "INCONCLUSIVE"
    human_outcome: Outcome = "NOT_REVIEWED"
    denial_conclusion: Literal["NOT_ESTABLISHED", "PRIVATE_REVIEW_CANDIDATE"] = "NOT_ESTABLISHED"


class VerificationReport(BaseModel, extra="forbid", frozen=True, strict=True):
    """Fixed diagnostics for an existing kit, with no record-file access or app launch."""

    kit_version: Literal[2] = 2
    purpose: Literal["GATEKEEPER_DOWNLOAD_VERIFICATION"] = "GATEKEEPER_DOWNLOAD_VERIFICATION"
    operation: Literal["READ_ONLY_VERIFICATION"] = "READ_ONLY_VERIFICATION"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    step: VerifyStep = "INPUT"
    error: Code = "NONE"
    verification: Check = "INCONCLUSIVE"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    server: Literal["NOT_STARTED"] = "NOT_STARTED"
    test_app: Literal["NOT_LAUNCHED"] = "NOT_LAUNCHED"
    native_record_files: Literal["NOT_OPENED"] = "NOT_OPENED"


type KnownULField = Literal[
    "eventType",
    "messageType",
    "timezoneName",
    "timestamp",
    "machTimestamp",
    "bootUUID",
    "processID",
    "userID",
    "threadID",
    "processImagePath",
    "processImageUUID",
    "senderImagePath",
    "senderImageUUID",
    "senderProgramCounter",
    "activityIdentifier",
    "parentActivityIdentifier",
    "traceID",
    "subsystem",
    "category",
    "formatString",
    "eventMessage",
    "source",
    "backtrace",
]
UL_FIELDS: tuple[KnownULField, ...] = (
    "eventType",
    "messageType",
    "timezoneName",
    "timestamp",
    "machTimestamp",
    "bootUUID",
    "processID",
    "userID",
    "threadID",
    "processImagePath",
    "processImageUUID",
    "senderImagePath",
    "senderImageUUID",
    "senderProgramCounter",
    "activityIdentifier",
    "parentActivityIdentifier",
    "traceID",
    "subsystem",
    "category",
    "formatString",
    "eventMessage",
    "source",
    "backtrace",
)
type FieldPresence = Literal["PRESENT_ALL", "ABSENT_ALL", "MIXED", "NOT_OBSERVED"]
type ValueType = Literal[
    "NULL", "BOOLEAN", "INTEGER", "NUMBER", "STRING", "ARRAY", "OBJECT", "MIXED", "NOT_OBSERVED"
]
type FailureKind = Literal["NONE", "MISSING", "TYPE", "VALUE", "UNSUPPORTED", "MULTIPLE"]
type CandidateULField = Literal[
    "processUniqueID",
    "processUniqueIdentifier",
    "processIdentifier",
    "process",
    "sender",
    "logType",
    "size",
    "timeToLive",
    "TTL",
    "creatorActivityIdentifier",
    "creatorProcessUniqueIdentifier",
    "transitionActivityIdentifier",
    "machContinuousTimestamp",
    "continuousNanosecondsSinceBoot",
    "processStartTimestamp",
    "messageFlags",
    "signpostID",
    "signpostName",
    "signpostScope",
    "signpostType",
]
# Predeclared structural probes, not an assertion that these API/export names are
# present or equivalent. No name discovered in a private row is ever exported.
UL_CANDIDATES: tuple[CandidateULField, ...] = (
    "processUniqueID",
    "processUniqueIdentifier",
    "processIdentifier",
    "process",
    "sender",
    "logType",
    "size",
    "timeToLive",
    "TTL",
    "creatorActivityIdentifier",
    "creatorProcessUniqueIdentifier",
    "transitionActivityIdentifier",
    "machContinuousTimestamp",
    "continuousNanosecondsSinceBoot",
    "processStartTimestamp",
    "messageFlags",
    "signpostID",
    "signpostName",
    "signpostScope",
    "signpostType",
)


class ULFieldShape(BaseModel, extra="forbid", frozen=True, strict=True):
    """Only types, presence and fixed failure classes for a predeclared field."""

    presence: FieldPresence = "NOT_OBSERVED"
    value_type: ValueType = "NOT_OBSERVED"
    validation: Check = "INCONCLUSIVE"
    failure_kind: FailureKind = "NONE"


class ShapeReport(BaseModel, extra="forbid", frozen=True, strict=True):
    """Offline shape diagnostics never export discovered keys or native values."""

    review_version: Literal[2] = 2
    purpose: Literal["GATEKEEPER_UL_SHAPE_DIAGNOSTIC"] = "GATEKEEPER_UL_SHAPE_DIAGNOSTIC"
    mode: Literal["OFFLINE_READ_ONLY"] = "OFFLINE_READ_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    message_meaning: Literal["NOT_REVIEWED"] = "NOT_REVIEWED"
    error: Code = "NONE"
    review_complete: Check = "INCONCLUSIVE"
    provenance: Check = "INCONCLUSIVE"
    capture_summary: Check = "INCONCLUSIVE"
    retained_scope: Check = "INCONCLUSIVE"
    unified_log_shapes: Check = "INCONCLUSIVE"
    additional_fields: FieldPresence = "NOT_OBSERVED"
    additional_value_types: ValueType = "NOT_OBSERVED"
    fields: dict[KnownULField, ULFieldShape] = Field(default_factory=dict)
    candidate_fields: dict[CandidateULField, ULFieldShape] = Field(default_factory=dict)
    unrecognized_fields: FieldPresence = "NOT_OBSERVED"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    server: Literal["NOT_STARTED"] = "NOT_STARTED"
    test_app: Literal["NOT_LAUNCHED"] = "NOT_LAUNCHED"


class StoredCapture(Report):
    """Read the fixed v1/v2 acquisition summary without retagging the original."""

    kit_version: Literal[1, 2] = 2

    @field_validator("kit_version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        """Keep booleans distinct from integer kit tags."""
        if type(value) is not int:
            raise ValueError("DATA")
        return value


class Config(BaseModel, extra="forbid", frozen=True, strict=True):
    """Private identifiers belong only to this fresh test item."""

    token: str = Field(pattern=r"^[a-f0-9]{32}$")
    cdhash: str = Field(pattern=r"^[a-f0-9]{40}$")
    os_release: str = Field(pattern=r"^27(?:\.[0-9]+){0,2}$")
    os_build: str = Field(pattern=r"^[0-9]{2,3}[A-Z][0-9A-Za-z]{1,16}$")
    architecture: Literal["arm64"] = "arm64"
    digests: dict[str, str]

    @property
    def app_name(self) -> str:
        return f"EForgeGatekeeperProbe-{self.token}.app"

    @property
    def readiness_tag(self) -> str:
        return f"EFORGE_GATEKEEPER_READY_{self.token}"


def _outside_git(path: Path) -> None:
    if any((p / ".git").exists() or (p / ".git").is_symlink() for p in (path, *path.parents)):
        raise PrivateError("LOCATION")


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy code and instructions only; no native execution or sockets."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    target = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-gatekeeper-kit-", dir=parent))
    )
    if any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/_-."
        for char in str(target)
    ):
        raise PrivateError("LOCATION")
    if destination:
        target.mkdir(mode=0o700)
    for source, name in [
        (Path(__file__).resolve(), "private_gatekeeper.py"),
        *((SOURCES / name, name) for name in CODE_FILES[1:]),
    ]:
        shutil.copyfile(source, target / name)
        (target / name).chmod(0o600)
    return target


def _root() -> Path:
    root = Path(__file__).resolve().parent
    _outside_git(root)
    _directory(root)
    return root


def _directory(path: Path, *, private: bool = True) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & (0o077 if private else 0o022)
    ):
        raise PrivateError("LOCATION")


def _read(path: Path, limit: int = MAX_LINE, *, private: bool = True) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise PrivateError("LOCATION")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise PrivateError("DATA")
        return data


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _preflight() -> None:
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise PrivateError("ROOT_USER")
    if (
        sys.platform != "darwin"
        or platform.machine() != "arm64"
        or platform.mac_ver()[0].split(".")[0] != "27"
    ):
        raise PrivateError("PLATFORM")


def _command(args: list[str], root: Path, *, stderr_output: bool = False) -> bytes:
    try:
        result = subprocess.run(
            args,
            cwd=root,
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if stderr_output else subprocess.PIPE,
            stderr=subprocess.PIPE if stderr_output else subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise PrivateError("BUILD") from error
    data = result.stderr if stderr_output else result.stdout
    if type(data) is not bytes:
        raise PrivateError("HELPER_OUTPUT")
    if len(data) > MAX_LINE:
        raise PrivateError("DATA")
    return data


def _digest(path: Path, *, private: bool = True) -> str:
    return hashlib.sha256(_read(path, MAX_ARCHIVE, private=private)).hexdigest()


def _platform_info(root: Path) -> tuple[str, str]:
    """HUMAN ONLY: retain exact build privately, never in a shared report."""
    release = platform.mac_ver()[0]
    build = _command(["/usr/bin/sw_vers", "-buildVersion"], root).decode("ascii").strip()
    if not re.fullmatch(r"27(?:\.[0-9]+){0,2}", release) or not re.fullmatch(
        r"[0-9]{2,3}[A-Z][0-9A-Za-z]{1,16}", build
    ):
        raise PrivateError("PLATFORM")
    return release, build


def _provenance(root: Path, app_name: str) -> dict[str, str]:
    _directory(root / "private")
    _app_files(root, root / "private/original" / app_name)
    names = (
        *CODE_FILES,
        "private/metadata-probe",
        "private/collector-guard",
        "private/probe.zip",
        f"private/original/{app_name}/Contents/Info.plist",
        f"private/original/{app_name}/Contents/MacOS/Probe",
    )
    return {name: _digest(root / name) for name in names}


def setup() -> None:
    """HUMAN ONLY: build fresh harmless code, ad-hoc sign and archive; never launch."""
    root = _root()
    _preflight()
    print("PRIVATE_STEP_BUILDING; this does not launch the test app", flush=True)
    release, build = _platform_info(root)
    work = root / "private"
    work.mkdir(mode=0o700)
    for name in ("original", "downloads"):
        (work / name).mkdir(mode=0o700)
    token = uuid.uuid4().hex
    app_name = f"EForgeGatekeeperProbe-{token}.app"
    app = work / "original" / app_name
    (app / "Contents/MacOS").mkdir(mode=0o700, parents=True)
    for path in (app, app / "Contents", app / "Contents/MacOS"):
        path.chmod(0o700)
    _write(
        app / "Contents/Info.plist",
        plistlib.dumps(
            {
                "CFBundleIdentifier": f"org.evidenceforge.privateprobe.{token}",
                "CFBundleExecutable": "Probe",
                "CFBundleName": f"EForgeProbe-{token}",
                "CFBundlePackageType": "APPL",
                "CFBundleVersion": "1",
                "LSUIElement": True,
            }
        ),
    )
    _command(
        [
            "/usr/bin/clang",
            "-arch",
            "arm64",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-modules",
            f"-DPROBE_MARKER={json.dumps(str(work / 'marker'))}",
            str(root / "marker_probe.c"),
            "-o",
            str(app / "Contents/MacOS/Probe"),
        ],
        root,
    )
    _command(
        [
            "/usr/bin/clang",
            "-arch",
            "arm64",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-modules",
            str(root / "metadata_probe.m"),
            "-framework",
            "Foundation",
            "-o",
            str(work / "metadata-probe"),
        ],
        root,
    )
    _command(
        [
            "/usr/bin/clang",
            "-arch",
            "arm64",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fno-modules",
            str(root / "collector_guard.c"),
            "-o",
            str(work / "collector-guard"),
        ],
        root,
    )
    (app / "Contents/MacOS/Probe").chmod(0o700)
    (work / "metadata-probe").chmod(0o700)
    (work / "collector-guard").chmod(0o700)
    _command(["/usr/bin/codesign", "--force", "--sign", "-", str(app)], root)
    details = _command(
        ["/usr/bin/codesign", "-d", "--verbose=4", str(app)], root, stderr_output=True
    )
    hashes = re.findall(rb"(?m)^CDHash=([a-f0-9]{40})$", details)
    if len(hashes) != 1:
        raise PrivateError("BUILD")
    # codesign may add files with ordinary read permissions; the enclosing kit is private.
    _command(
        [
            "/usr/bin/ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app),
            str(work / "probe.zip"),
        ],
        root,
    )
    (work / "probe.zip").chmod(0o600)
    config = Config(
        token=token,
        cdhash=hashes[0].decode("ascii"),
        os_release=release,
        os_build=build,
        digests=_provenance(root, app_name),
    )
    _write(work / "config.json", config.model_dump_json().encode())


def _config(root: Path) -> Config:
    _directory(root / "private")
    config = Config.model_validate_json(_read(root / "private/config.json"))
    if config.digests != _provenance(root, config.app_name):
        raise PrivateError("DATA")
    return config


def response(
    method: str,
    target: str,
    host: str,
    origin: str | None,
    *,
    port: int,
    token: str,
    archive: bytes,
) -> tuple[int, dict[str, str], bytes]:
    """Pure delivery policy: one static page/archive, no listing, echo or CORS."""
    if (
        method not in {"GET", "HEAD"}
        or host != f"127.0.0.1:{port}"
        or origin not in {None, f"http://127.0.0.1:{port}"}
        or target not in {f"/{token}/", f"/{token}/probe.zip"}
    ):
        return 404, {"Content-Length": "0", "Connection": "close"}, b""
    page = target == f"/{token}/"
    content = (
        (
            b'<!doctype html><meta charset="utf-8"><title>Private Gatekeeper test</title>'
            b"<p>Right-click the link and choose Download Linked File As to save into "
            b"the private folder printed in your terminal.</p>"
            b'<p><a href="probe.zip" download="probe.zip">Download test ZIP</a></p>'
            b"<p>Extract with Archive Utility. Do not launch the app yet.</p>"
        )
        if page
        else archive
    )
    headers = {
        "Content-Type": "text/html; charset=utf-8" if page else "application/zip",
        "Content-Length": str(len(content)),
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Connection": "close",
    }
    if page:
        headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; form-action 'none'"
        )
    else:
        headers["Content-Disposition"] = 'attachment; filename="probe.zip"'
    return 200, headers, content if method == "GET" else b""


def serve() -> None:
    """HUMAN ONLY: serve the sole archive on loopback for at most 15 minutes."""
    root = _root()
    _preflight()
    config = _config(root)
    archive = _read(root / "private/probe.zip", MAX_ARCHIVE)

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(2)
            super().setup()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

        def send_error(
            self, _code: int, _message: str | None = None, _explain: str | None = None
        ) -> None:
            self.send_response_only(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def do_GET(self) -> None:
            code, headers, body = response(
                self.command,
                self.path,
                self.headers.get("Host", ""),
                self.headers.get("Origin"),
                port=self.server.server_address[1],
                token=config.token,
                archive=archive,
            )
            self.send_response_only(code)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            if code == 200 and self.command == "GET" and self.path == f"/{config.token}/probe.zip":
                try:
                    _write(root / "private/delivered", b"ARCHIVE_SERVED\n")
                except FileExistsError:
                    pass

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_POST(self) -> None:
            self.do_GET()

        def do_PUT(self) -> None:
            self.do_GET()

        def do_DELETE(self) -> None:
            self.do_GET()

        def do_OPTIONS(self) -> None:
            self.do_GET()

    class QuietServer(HTTPServer):
        def server_bind(self) -> None:
            # Avoid HTTPServer's reverse-DNS lookup; this listener is loopback only.
            TCPServer.server_bind(self)
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

        def handle_error(self, _request: object, _client_address: object) -> None:
            pass

    with QuietServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 1
        print(
            f"PRIVATE_DOWNLOAD_URL=http://127.0.0.1:{server.server_address[1]}/{config.token}/",
            flush=True,
        )
        print(f"PRIVATE_SAVE_FOLDER={root / 'private/downloads'}", flush=True)
        print("PRIVATE_SERVER_ACTIVE_15_MINUTES; Ctrl+C stops it; no access logs", flush=True)
        deadline = time.monotonic() + SERVER_SECONDS
        while time.monotonic() < deadline:
            server.handle_request()


def _app_files(
    root: Path, app: Path, *, on_step: Callable[[VerifyStep], None] = lambda _step: None
) -> tuple[Path, Path]:
    on_step("APP_BUNDLE")
    if not app.is_relative_to(root / "private"):
        raise PrivateError("LOCATION")
    for path in (app.parent, app, app / "Contents", app / "Contents/MacOS"):
        _directory(path, private=False)
    binary, info = app / "Contents/MacOS/Probe", app / "Contents/Info.plist"
    on_step("APP_BINARY")
    _read(binary, MAX_ARCHIVE, private=False)
    on_step("APP_METADATA")
    _read(info, private=False)
    return binary, info


def _quarantine(root: Path, path: Path) -> Presence:
    result = _command([str(root / "private/metadata-probe"), "quarantine", str(path)], root).strip()
    if result not in {b"PRESENT", b"ABSENT"}:
        raise PrivateError("QUARANTINE")
    return "PRESENT" if result == b"PRESENT" else "ABSENT"


def _download(
    root: Path, config: Config, *, on_step: Callable[[VerifyStep], None] = lambda _step: None
) -> tuple[Path, Report]:
    work = root / "private"
    on_step("DOWNLOAD_FOLDER")
    _directory(work / "downloads")
    on_step("DELIVERY_MARKER")
    if _read(work / "delivered", 64) != b"ARCHIVE_SERVED\n":
        raise PrivateError("DELIVERY")
    archive = work / "downloads/probe.zip"
    on_step("ARCHIVE_CONTENT")
    if _digest(archive, private=False) != config.digests["private/probe.zip"]:
        raise PrivateError("DELIVERY")
    app = work / "downloads" / config.app_name
    binary, info = _app_files(root, app, on_step=on_step)
    original = work / "original" / config.app_name
    on_step("BINARY_CONTENT")
    if _digest(binary, private=False) != _digest(original / "Contents/MacOS/Probe"):
        raise PrivateError("DELIVERY")
    on_step("BUNDLE_CONTENT")
    if _digest(info, private=False) != _digest(original / "Contents/Info.plist"):
        raise PrivateError("DELIVERY")
    on_step("SIGNATURE")
    _command(["/usr/bin/codesign", "--verify", "--strict", "--deep", str(app)], root)
    on_step("ARCHIVE_QUARANTINE")
    zip_quarantine = _quarantine(root, archive)
    if zip_quarantine != "PRESENT":
        raise PrivateError("QUARANTINE")
    on_step("APP_QUARANTINE")
    app_quarantine = _quarantine(root, app)
    if app_quarantine != "PRESENT":
        raise PrivateError("QUARANTINE")
    on_step("COMPLETE")
    return app, Report(
        target_platform="PASS",
        provenance="PASS",
        browser_delivery="HUMAN_ATTESTED",
        same_executable="PASS",
        signature_integrity="PASS",
        archive_quarantine=zip_quarantine,
        app_quarantine=app_quarantine,
    )


def _filesystem_code(error: OSError) -> Code:
    """Classify by exception type alone; never interpolate paths or system error text."""
    if isinstance(error, FileNotFoundError):
        return "FILE_MISSING"
    if isinstance(error, PermissionError):
        return "FILE_ACCESS"
    if isinstance(error, (NotADirectoryError, IsADirectoryError)):
        return "FILE_TYPE"
    return "FILE_IO"


def _hidden_existing_root() -> Path:
    if not sys.stdin.isatty():
        raise PrivateError("INPUT")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass(
                "Existing private kit folder (hidden; not its private subfolder): "
            )
    except (getpass.GetPassWarning, EOFError) as error:
        raise PrivateError("INPUT") from error
    path = Path(value)
    if not value or len(value) > 4096 or not path.is_absolute():
        raise PrivateError("INPUT")
    return path


def diagnose(existing: Path) -> VerificationReport:
    """HUMAN ONLY: replay read-only checks against an existing kit; write nothing.

    Only signature verification and the provenance-verified quarantine helper can
    run. No server, collector, test app, build, log reader or directory search runs.
    """
    current: VerifyStep = "INPUT"

    def step(value: VerifyStep) -> None:
        nonlocal current
        current = value

    try:
        _root()  # The diagnostic itself must be a prepared code copy outside Git.
        _preflight()
        _directory(existing)
        target = existing.resolve(strict=True)
        _outside_git(target)
        step("PROVENANCE")
        config = _config(target)
        step("PLATFORM")
        if _platform_info(target) != (config.os_release, config.os_build):
            raise PrivateError("PLATFORM")
        _download(target, config, on_step=step)
        return VerificationReport(step="COMPLETE", verification="PASS")
    except PrivateError as error:
        code = error.code
    except OSError as error:
        code = _filesystem_code(error)
    except (ValidationError, UnicodeError, RecursionError, KeyError):
        code = "DATA"
    except (TypeError, ValueError, subprocess.SubprocessError):
        code = "INTERNAL"
    return VerificationReport(step=current, error=code, verification="FAIL")


def _presence(values: list[bool]) -> FieldPresence:
    if not values:
        return "NOT_OBSERVED"
    return "PRESENT_ALL" if all(values) else "ABSENT_ALL" if not any(values) else "MIXED"


def _value_type(value: object) -> ValueType:
    if value is None:
        return "NULL"
    return {
        bool: "BOOLEAN",
        int: "INTEGER",
        float: "NUMBER",
        str: "STRING",
        list: "ARRAY",
        dict: "OBJECT",
    }[type(value)]


def _value_types(values: list[object]) -> ValueType:
    kinds = {_value_type(value) for value in values}
    return "NOT_OBSERVED" if not kinds else next(iter(kinds)) if len(kinds) == 1 else "MIXED"


def _failure_kind(kind: str) -> FailureKind:
    if kind == "missing":
        return "MISSING"
    if kind in {"extra_forbidden", "literal_error"}:
        return "UNSUPPORTED"
    return "TYPE" if kind.endswith("_type") or kind == "none_required" else "VALUE"


def _ul_shape_report(records: list[bytes]) -> ShapeReport:
    """Classify known fields without copying validation text, keys or input values."""
    rows = [_decode(raw) for raw in records]
    failures: dict[KnownULField, list[FailureKind]] = {name: [] for name in UL_FIELDS}
    valid: list[bool] = []
    for raw in records:
        try:
            UnifiedLogRecord.model_validate_json(raw)
            valid.append(True)
        except ValidationError as error:
            valid.append(False)
            # Error locations may contain private extra-field names. They never leave
            # this loop: only a match against the predeclared top-level aliases does.
            for item in error.errors(include_input=False, include_context=False, include_url=False):
                location = item["loc"]
                for name in UL_FIELDS:
                    if location and location[0] == name:
                        failures[name].append(_failure_kind(item["type"]))
                        break
    fields: dict[KnownULField, ULFieldShape] = {}
    for name in UL_FIELDS:
        kinds = set(failures[name])
        present = [name in row for row in rows]
        fields[name] = ULFieldShape(
            presence=_presence(present),
            value_type=_value_types([row[name] for row in rows if name in row]),
            validation="FAIL" if kinds else "PASS" if any(present) else "INCONCLUSIVE",
            failure_kind="NONE"
            if not kinds
            else next(iter(kinds))
            if len(kinds) == 1
            else "MULTIPLE",
        )
    extras = [{name: value for name, value in row.items() if name not in UL_FIELDS} for row in rows]
    candidates = {
        name: ULFieldShape(
            presence=_presence([name in row for row in rows]),
            value_type=_value_types([row[name] for row in rows if name in row]),
        )
        for name in UL_CANDIDATES
    }
    return ShapeReport(
        review_complete="PASS",
        provenance="PASS",
        capture_summary="PASS",
        retained_scope="PASS",
        unified_log_shapes=_shape(valid),
        additional_fields=_presence([bool(extra) for extra in extras]),
        additional_value_types=_value_types(
            [value for extra in extras for value in extra.values()]
        ),
        fields=fields,
        candidate_fields=candidates,
        unrecognized_fields=_presence(
            [any(name not in UL_CANDIDATES for name in extra) for extra in extras]
        ),
    )


def _shape_inputs(existing: Path) -> list[bytes]:
    """Verify private provenance, bounds and test-item correlation before any review."""
    _root()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise PrivateError("ROOT_USER")
    _directory(existing)
    target = existing.resolve(strict=True)
    _outside_git(target)
    config = _config(target)
    stored = StoredCapture.model_validate_json(_read(target / "private/capture.json"))
    if (
        stored.error != "NONE"
        or stored.provenance != "PASS"
        or stored.target_platform != "PASS"
        or stored.bounded_collection != "PASS"
        or stored.collector_cleanup != "PASS"
        or stored.test_item_policy_records != "OBSERVED"
    ):
        raise PrivateError("CONTROL")
    data = _read(target / "private/test-ul.jsonl", MAX_RETAINED_BYTES)
    records = data.splitlines()
    if not records or len(records) > MAX_RETAINED or not data.endswith(b"\n"):
        raise PrivateError("DATA")
    for raw in records:
        try:
            row = _decode(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise PrivateError("DATA") from None
        pending: list[tuple[object, int]] = [(row, 1)]
        while pending:
            value, depth = pending.pop()
            if depth > 32:
                raise PrivateError("DATA")
            if type(value) is dict:
                pending.extend((item, depth + 1) for item in value.values())
            elif type(value) is list:
                pending.extend((item, depth + 1) for item in value)
        writer, message = row.get("processImagePath"), row.get("eventMessage")
        if (
            type(writer) is not str
            or writer.rsplit("/", 1)[-1] not in WRITERS
            or type(message) is not str
            or not (config.app_name in message or config.cdhash in message)
        ):
            raise PrivateError("DATA")
    return records


def inspect_field_names(existing: Path) -> None:
    """HUMAN ONLY: show bounded extra schema names on a private terminal, never values.

    This deliberately differs from the agent-safe fixed report. The human must review
    these names for sensitive content before choosing whether to share any of them.
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PrivateError("INPUT")
    records = _shape_inputs(existing)
    names = sorted({name for raw in records for name in _decode(raw) if name not in UL_FIELDS})
    if len(names) > 32 or any(
        not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) for name in names
    ):
        raise PrivateError("DATA")
    print("PRIVATE_FIELD_NAMES_ONLY; inspect privately before sharing any technical schema names")
    print(json.dumps(names, ensure_ascii=True))


def review_shapes(existing: Path) -> ShapeReport:
    """OFFLINE: read only bounded test rows; explicit permission is needed for agent use.

    No subprocess, network access, app launch, capture mutation, message interpretation,
    error text or native value output is used. Original kit provenance is checked locally.
    """
    try:
        return _ul_shape_report(_shape_inputs(existing))
    except PrivateError as error:
        code = error.code
    except OSError as error:
        code = _filesystem_code(error)
    except (ValidationError, UnicodeError, RecursionError):
        code = "DATA"
    except (ValueError, TypeError, KeyError):
        code = "INTERNAL"
    return ShapeReport(error=code)


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateError("DATA")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise PrivateError("DATA")


def _decode(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_LINE:
        raise PrivateError("DATA")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    if type(value) is not dict:
        raise PrivateError("DATA")
    return value


def _identity(process: object) -> tuple[int, int, str] | None:
    if type(process) is not dict:
        return None
    token, start = process.get("audit_token"), process.get("start_time")
    if type(token) is not dict or type(start) is not str or len(start) > 128:
        return None
    pid, version = token.get("pid"), token.get("pidversion")
    if any(type(value) is not int or not 0 <= value < 2**32 for value in (pid, version)):
        return None
    return pid, version, start


class Tracker:
    """Bounded private correlation. Never expose records, paths or native identities."""

    def __init__(self, config: Config, helper: Path) -> None:
        self.config, self.helper = config, helper
        self.ready_pids: set[int] = set()
        self.ready_exec: set[tuple[int, int, str]] = set()
        self.es_ready = False
        self.ul_ready = False
        self.started = False
        self.identities: set[tuple[int, int, str]] = set()
        self.retained = {"ul": 0, "es": 0}
        self.retained_bytes = {"ul": 0, "es": 0}
        self.streamed = 0
        self.ul_valid: list[bool] = []
        self.es_valid: list[bool] = []
        self.exec_seen = False
        self.exit_seen = False

    def predicate(self) -> str:
        writers = " OR ".join(f'process == "{writer}"' for writer in WRITERS)
        return f'(process == "metadata-probe" AND eventMessage == "{self.config.readiness_tag}") OR (({writers}) AND (eventMessage CONTAINS "{self.config.app_name}" OR eventMessage CONTAINS "{self.config.cdhash}"))'

    def accept(self, source: str, raw: bytes) -> bool:
        self.streamed += 1
        if self.streamed > MAX_STREAMED:
            raise PrivateError("DATA")
        try:
            row = _decode(raw)
        except (ValueError, UnicodeError, RecursionError):
            return False
        if source == "ul":
            message, writer = row.get("eventMessage"), row.get("processImagePath")
            if type(message) is not str or type(writer) is not str:
                return False
            if message == self.config.readiness_tag and writer == str(self.helper):
                self.ul_ready = True
                return False
            if (
                not self.started
                or writer.rsplit("/", 1)[-1] not in WRITERS
                or not (self.config.app_name in message or self.config.cdhash in message)
            ):
                return False
            try:
                UnifiedLogRecord.model_validate_json(raw)
                valid = True
            except ValidationError:
                valid = False
            self.ul_valid.append(valid)
        else:
            kind = row.get("event_type")
            event = row.get("event")
            if type(event) is not dict or kind not in {9, 15}:
                return False
            payload = event.get("exec") if kind == 9 else None
            target = payload.get("target") if type(payload) is dict else row.get("process")
            identity = _identity(target)
            if identity is None or type(target) is not dict:
                return False
            executable = target.get("executable")
            path = executable.get("path") if type(executable) is dict else None
            if not self.started:
                if kind == 9 and path == str(self.helper) and identity[0] in self.ready_pids:
                    self.ready_exec.add(identity)
                elif kind == 15 and identity in self.ready_exec:
                    self.es_ready = True
                return False
            suffix = f"/{self.config.app_name}/Contents/MacOS/Probe"
            own_image = (
                type(path) is str
                and path.endswith(suffix)
                and target.get("cdhash") == self.config.cdhash
            )
            if kind == 9 and own_image:
                self.identities.add(identity)
                self.exec_seen = True
            elif kind == 15 and (identity in self.identities or own_image):
                self.exit_seen = True
            else:
                return False
            try:
                decode_endpoint_security_record(raw)
                valid = True
            except (ValueError, TypeError, ValidationError):
                valid = False
            self.es_valid.append(valid)
        self.retained[source] += 1
        self.retained_bytes[source] += len(raw) + 1
        if self.retained[source] > MAX_RETAINED or self.retained_bytes[source] > MAX_RETAINED_BYTES:
            raise PrivateError("DATA")
        return True


def _marker(path: Path) -> Presence:
    if not path.exists() and not path.is_symlink():
        return "ABSENT"
    if _read(path, 64) != b"EXECUTED\n":
        raise PrivateError("DATA")
    return "PRESENT"


def _launch_status(process: subprocess.Popen[bytes]) -> Launch:
    return (
        "TIMED_OUT"
        if process.poll() is None
        else "RETURNED_SUCCESS"
        if process.returncode == 0
        else "RETURNED_ERROR"
    )


def _stop(process: subprocess.Popen[bytes], *, privileged: bool = False) -> bool:
    """Stop an owned child; the root guard independently bounds privileged lifetime."""
    try:
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
            except PermissionError:
                if not privileged:
                    return False
                subprocess.run(
                    ["/usr/bin/sudo", "-n", "/bin/kill", "-INT", str(process.pid)],
                    env=SAFE_ENV,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                if privileged:
                    return False
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                return False
        return process.returncode in (0, -signal.SIGINT, 128 + signal.SIGINT)
    except (OSError, subprocess.SubprocessError):
        return False


def _shape(values: list[bool]) -> Check:
    return "INCONCLUSIVE" if not values else "PASS" if all(values) else "FAIL"


def _collect(root: Path, app: Path, config: Config, report: Report) -> Report:
    work, helper = root / "private", root / "private/metadata-probe"
    tracker = Tracker(config, helper)
    processes: list[subprocess.Popen[bytes]] = []
    probes: list[subprocess.Popen[bytes]] = []
    launch: subprocess.Popen[bytes] | None = None
    cleanup = True
    complete = False
    streams: dict[str, BinaryIO] = {}
    try:
        for source, args in (
            (
                "ul",
                [
                    "/usr/bin/log",
                    "stream",
                    "--style",
                    "ndjson",
                    "--level",
                    "debug",
                    "--predicate",
                    tracker.predicate(),
                ],
            ),
            ("es", ["/usr/bin/sudo", "-n", str(work / "collector-guard")]),
        ):
            process = subprocess.Popen(
                args,
                cwd=work,
                env=SAFE_ENV,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                start_new_session=False,
            )
            processes.append(process)
            assert process.stdout is not None
            streams[source] = process.stdout
        with selectors.DefaultSelector() as selector:
            for source, stream in streams.items():
                selector.register(stream, selectors.EVENT_READ, source)
            buffers = {source: b"" for source in streams}
            deadline, next_probe = time.monotonic() + READINESS_SECONDS, 0.0
            while time.monotonic() < deadline and not (tracker.es_ready and tracker.ul_ready):
                if any(process.poll() is not None for process in processes):
                    raise PrivateError("COLLECTOR")
                if time.monotonic() >= next_probe and len(probes) < 8:
                    probe = subprocess.Popen(
                        [str(helper), "ready", config.readiness_tag],
                        cwd=work,
                        env=SAFE_ENV,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    probes.append(probe)
                    tracker.ready_pids.add(probe.pid)
                    next_probe = time.monotonic() + 1
                _pump(selector, buffers, tracker, {})
            if not (tracker.es_ready and tracker.ul_ready):
                raise PrivateError("ES_READINESS" if not tracker.es_ready else "UL_READINESS")
            print("PRIVATE_STEP_COLLECTORS_READY", flush=True)
            files: dict[str, BinaryIO] = {}
            try:
                for source in streams:
                    fd = os.open(
                        work / f"test-{source}.jsonl",
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    files[source] = os.fdopen(fd, "wb")
                tracker.started = True
                print(
                    "PRIVATE_STEP_TEST_LAUNCH; acknowledge a block with OK/Done; do not override",
                    flush=True,
                )
                launch = subprocess.Popen(
                    ["/usr/bin/open", "-n", "-W", str(app)],
                    cwd=work,
                    env=SAFE_ENV,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + CAPTURE_SECONDS
                while time.monotonic() < deadline:
                    if any(process.poll() is not None for process in processes):
                        raise PrivateError("COLLECTOR")
                    _pump(selector, buffers, tracker, files)
                complete = not any(buffer.strip() for buffer in buffers.values())
            finally:
                for stream in files.values():
                    stream.close()
    finally:
        for index, process in enumerate(processes):
            try:
                cleanup &= _stop(process, privileged=index == 1)
            finally:
                if process.stdout is not None:
                    process.stdout.close()
        for probe in probes:
            if probe.poll() is None:
                probe.kill()
            probe.wait(timeout=3)
        if launch is not None and launch.poll() is None:
            # This terminates only our open helper, never an unknown app PID.
            status = "TIMED_OUT"
            launch.terminate()
            launch.wait(timeout=3)
        else:
            status = "NOT_ATTEMPTED" if launch is None else _launch_status(launch)
    return report.model_copy(
        update={
            "es_ready": "PASS",
            "unified_log_ready": "PASS",
            "bounded_collection": "PASS" if complete else "FAIL",
            "collector_cleanup": "PASS" if cleanup else "FAIL",
            "downloaded_launch": status,
            "downloaded_marker": _marker(work / "marker"),
            "test_item_policy_records": "OBSERVED" if tracker.retained["ul"] else "NOT_OBSERVED",
            "unified_log_shapes": _shape(tracker.ul_valid),
            "es_exec_records": "OBSERVED" if tracker.exec_seen else "NOT_OBSERVED",
            "es_exit_records": "OBSERVED" if tracker.exit_seen else "NOT_OBSERVED",
            "es_shapes": _shape(tracker.es_valid),
        }
    )


def _pump(
    selector: selectors.BaseSelector,
    buffers: dict[str, bytes],
    tracker: Tracker,
    files: dict[str, BinaryIO],
) -> None:
    for key, _mask in selector.select(timeout=0.1):
        source = key.data
        chunk = os.read(key.fd, 65536)
        if not chunk:
            raise PrivateError("COLLECTOR")
        buffers[source] += chunk
        while b"\n" in buffers[source]:
            line, buffers[source] = buffers[source].split(b"\n", 1)
            if line.strip() and tracker.accept(source, line) and source in files:
                files[source].write(line + b"\n")
        if len(buffers[source]) > MAX_LINE:
            raise PrivateError("DATA")


def capture(*, browser_download: bool) -> Report:
    """HUMAN ONLY: acquire new test-item records, never historical logs."""
    root = _root()
    _preflight()
    config = _config(root)
    if not browser_download:
        raise PrivateError("DELIVERY")
    if _platform_info(root) != (config.os_release, config.os_build):
        raise PrivateError("PLATFORM")
    print("PRIVATE_STEP_VERIFYING_DOWNLOAD", flush=True)
    if any(
        (root / "private" / name).exists() or (root / "private" / name).is_symlink()
        for name in ("capture-started", "capture.json", "test-ul.jsonl", "test-es.jsonl", "marker")
    ):
        raise PrivateError("DUPLICATE")
    app, report = _download(
        root, config, on_step=lambda step: print(f"PRIVATE_VERIFY_{step}", flush=True)
    )
    _write(root / "private/capture-started", b"CAPTURE_STARTED\n")
    print("PRIVATE_STEP_STARTING_COLLECTORS; readiness is bounded to 12 seconds", flush=True)
    result = _collect(root, app, config, report)
    _write(root / "private/capture.json", result.model_dump_json().encode())
    return result


def control() -> Report:
    """HUMAN ONLY: run the original local control after the download attempt."""
    root = _root()
    _preflight()
    config = _config(root)
    if _platform_info(root) != (config.os_release, config.os_build):
        raise PrivateError("PLATFORM")
    work = root / "private"
    report = Report.model_validate_json(_read(work / "capture.json"))
    if report.collector_cleanup != "PASS" or report.downloaded_launch == "TIMED_OUT":
        raise PrivateError("CONTROL")
    if any(
        (work / name).exists() or (work / name).is_symlink()
        for name in ("control-started", "control.json", "test-marker", "control-marker")
    ):
        raise PrivateError("DUPLICATE")
    if _marker(work / "marker") != report.downloaded_marker:
        raise PrivateError("CONTROL")
    _write(work / "control-started", b"CONTROL_STARTED\n")
    print("PRIVATE_STEP_LOCAL_CONTROL", flush=True)
    app = work / "original" / config.app_name
    _app_files(root, app)
    if _quarantine(root, app) != "ABSENT":
        raise PrivateError("QUARANTINE")
    if _marker(work / "marker") == "PRESENT":
        (work / "marker").rename(work / "test-marker")
    process = subprocess.Popen(
        ["/usr/bin/open", "-n", "-W", str(app)],
        cwd=work,
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        process.wait(timeout=15)
        status = _launch_status(process)
    except subprocess.TimeoutExpired:
        status = "TIMED_OUT"
        process.terminate()
        process.wait(timeout=3)
    marker = _marker(work / "marker")
    if marker == "PRESENT":
        (work / "marker").rename(work / "control-marker")
    result = report.model_copy(
        update={"local_control_launch": status, "local_control_marker": marker}
    )
    _write(work / "control.json", result.model_dump_json().encode())
    return result


def report(outcome: Outcome) -> Report:
    """HUMAN ONLY: report fixed comparisons, never open or print retained native rows."""
    root = _root()
    _preflight()
    _config(root)
    control_path = root / "private/control.json"
    summary = (
        control_path
        if control_path.exists() or control_path.is_symlink()
        else root / "private/capture.json"
    )
    result = Report.model_validate_json(_read(summary))
    candidate = (
        outcome == "BLOCK_ALERT"
        and result.error == "NONE"
        and result.target_platform == "PASS"
        and result.provenance == "PASS"
        and result.browser_delivery == "HUMAN_ATTESTED"
        and result.same_executable == "PASS"
        and result.signature_integrity == "PASS"
        and result.archive_quarantine == "PRESENT"
        and result.app_quarantine == "PRESENT"
        and result.es_ready == "PASS"
        and result.unified_log_ready == "PASS"
        and result.downloaded_launch in {"RETURNED_ERROR", "RETURNED_SUCCESS"}
        and result.downloaded_marker == "ABSENT"
        and result.local_control_launch == "RETURNED_SUCCESS"
        and result.local_control_marker == "PRESENT"
        and result.test_item_policy_records == "OBSERVED"
        and result.bounded_collection == "PASS"
        and result.collector_cleanup == "PASS"
        and result.unified_log_shapes == "PASS"
        and result.es_shapes != "FAIL"
    )
    return result.model_copy(
        update={
            "human_outcome": outcome,
            "denial_conclusion": "PRIVATE_REVIEW_CANDIDATE" if candidate else "NOT_ESTABLISHED",
        }
    )


class QuietParser(argparse.ArgumentParser):
    """Do not echo input, paths or exception diagnostics."""

    def error(self, _message: str) -> None:
        raise PrivateError("INPUT")


def main(argv: list[str] | None = None) -> int:
    """Expose agent-safe copying and explicitly human-only operations."""
    parser = QuietParser(prog="private-gatekeeper")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    stage = commands.add_parser("prepare")
    stage.add_argument("--destination", type=Path)
    for name in (
        "setup",
        "serve",
        "capture",
        "control",
        "report",
        "diagnose",
        "review-shapes",
        "inspect-field-names",
    ):
        child = commands.add_parser(name)
        child.add_argument("--private-run", action="store_true", required=True)
        if name in {"review-shapes", "inspect-field-names"}:
            child.add_argument("--existing-kit", type=Path)
        if name == "capture":
            child.add_argument("--browser-download", action="store_true", required=True)
        if name == "report":
            child.add_argument(
                "--outcome",
                choices=(
                    "BLOCK_ALERT",
                    "CONSENT_PROMPT",
                    "RAN",
                    "CANCELLED",
                    "CRASH_OR_ERROR",
                    "OTHER",
                ),
                required=True,
            )
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
        elif args.command == "setup":
            setup()
            print("PRIVATE_SETUP_READY; use serve next; do not launch the app yet")
        elif args.command == "serve":
            serve()
        elif args.command == "diagnose":
            _root()
            verification = diagnose(_hidden_existing_root())
            print(verification.model_dump_json(indent=2))
            return 0 if verification.error == "NONE" else 2
        elif args.command == "review-shapes":
            shapes = review_shapes(args.existing_kit or _hidden_existing_root())
            print(shapes.model_dump_json(indent=2))
            return 0 if shapes.error == "NONE" else 2
        elif args.command == "inspect-field-names":
            inspect_field_names(args.existing_kit or _hidden_existing_root())
        else:
            result = (
                capture(browser_download=args.browser_download)
                if args.command == "capture"
                else control()
                if args.command == "control"
                else report(args.outcome)
            )
            print(result.model_dump_json(indent=2))
        return 0
    except PrivateError as error:
        result = Report(error=error.code)
    except FileExistsError:
        result = Report(error="DUPLICATE")
    except KeyboardInterrupt:
        if getattr(locals().get("args"), "command", None) == "serve":
            print("PRIVATE_SERVER_STOPPED")
            return 0
        result = Report(error="INTERRUPTED")
    except (ValidationError, UnicodeError, RecursionError):
        result = Report(error="DATA")
    except OSError as error:
        result = Report(error=_filesystem_code(error))
    except (ValueError, TypeError, KeyError, subprocess.SubprocessError):
        result = Report(error="INTERNAL")
    print(result.model_dump_json(indent=2))
    return 2


def _private_exception_hook(_kind: object, _value: object, _traceback: object) -> None:
    os.write(2, b"GATEKEEPER_PRIVATE_INTERNAL_ERROR\n")


if __name__ == "__main__":
    sys.excepthook = _private_exception_hook
    raise SystemExit(main())
