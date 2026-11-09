# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Human-only ULF companion to the authenticated SSH reference.

Ambient SSH input stays in bounded memory. Only records in closed, ES-authenticated
server execution windows may reach private disk. Reports expose fixed comparisons.
This module does not read files, query live processes or collect on import.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evidenceforge.formats.macos_unified_log import UnifiedLogRecord

type Role = Literal["WRAPPER", "SSHD", "SESSION", "AUTH"]
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Sender = Literal["MAIN_IMAGE", "SYSTEM_ASL", "SYSTEM_TRACE", "PAM", "OTHER"]
MAX_BYTES, MAX_STREAM, MAX_ROWS, MAX_LINE = 8 * 1_048_576, 64 * 1_048_576, 2048, 128 * 1024
SAFE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ExecutionWindow(Model):
    """Private selected PID/image interval; never included in the shareable report."""

    pid: int = Field(strict=True, gt=1)
    image: str
    role: Role
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def finite_execution(self) -> Self:
        if (
            self.start.utcoffset() is None
            or self.end.utcoffset() is None
            or self.start >= self.end
            or not self.image.startswith("/")
            or "\0" in self.image
        ):
            raise ValueError("ULF_BINDING")
        return self


class Messages(Model):
    accepted_local_password: int = Field(default=0, ge=0)
    accepted_local_pam: int = Field(default=0, ge=0)
    pam_open: int = Field(default=0, ge=0)
    pam_close: int = Field(default=0, ge=0)
    disconnected_local: int = Field(default=0, ge=0)
    other_controlled: int = Field(default=0, ge=0)


class Summary(Model):
    kit_version: Literal[1, 2] = 2
    purpose: Literal["SSH_UNIFIED_LOG_DIAGNOSTIC"] = "SSH_UNIFIED_LOG_DIAGNOSTIC"
    collection: Literal["ES_AUTHENTICATED_SERVER_EXECUTION_WINDOWS"] = (
        "ES_AUTHENTICATED_SERVER_EXECUTION_WINDOWS"
    )
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    readiness_scope: Literal["OWN_PROCESS_MARKER_ONLY"] = "OWN_PROCESS_MARKER_ONLY"
    reference_result: Literal["NO_MATCHING_ROWS", "RECORDS_REQUIRE_REVIEW"] = "NO_MATCHING_ROWS"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    execution_binding: Check = "INCONCLUSIVE"
    retained_rows: int = Field(default=0, ge=0, le=256)
    shape_scope: Literal["LOG_EVENT_ROWS_ONLY"] = "LOG_EVENT_ROWS_ONLY"
    log_event_rows: int = Field(default=0, ge=0, le=256)
    other_event_rows: int = Field(default=0, ge=0, le=256)
    invalid_log_rows: int = Field(default=0, ge=0, le=256)
    classified_log_rows: int = Field(default=0, ge=0, le=256)
    native_shapes: Check = "INCONCLUSIVE"
    ring_evicted: bool = False
    roles: tuple[Role, ...] = ()
    senders: tuple[Sender, ...] = ()
    static_formats: tuple[Literal["PUBLIC_C_STRING", "C_STRING", "OTHER"], ...] = ()
    message_types: tuple[Literal["Default", "Info", "Debug", "Error", "Fault"], ...] = ()
    message_redaction: Literal["PRESENT_ALL", "ABSENT_ALL", "MIXED", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    subsystem_presence: Literal["EMPTY", "PRESENT", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    category_presence: Literal["EMPTY", "PRESENT", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    messages: Messages = Field(default_factory=Messages)


def _time(value: object, *, unified: bool = False) -> datetime:
    if type(value) is not str or len(value) > 64:
        raise ValueError("ULF_BINDING")
    result = (
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f%z")
        if unified
        else datetime.fromisoformat(value)
    )
    if result.utcoffset() is None:
        raise ValueError("ULF_BINDING")
    return result.astimezone(UTC)


def execution_windows(
    rows: list[dict],
    *,
    identity: Callable[[dict], tuple[int, int, int]],
    role_of: Callable[[dict], str],
) -> tuple[ExecutionWindow, ...]:
    """Bind only closed selected server executions; exclude launchd, clients and shells."""
    active: dict[int, tuple[tuple[int, int, int], dict, datetime]] = {}
    windows: list[ExecutionWindow] = []

    def close(process: dict, at: datetime) -> None:
        key = identity(process)
        prior = active.pop(key[0], None)
        if prior is None:
            return
        if prior[0] != key or at < prior[2]:
            raise ValueError("ULF_BINDING")
        role = role_of(prior[1])
        if role in {"WRAPPER", "SSHD", "SESSION", "AUTH"} and at > prior[2]:
            windows.append(
                ExecutionWindow.model_validate(
                    {
                        "pid": key[0],
                        "image": prior[1]["executable"]["path"],
                        "role": role,
                        "start": prior[2],
                        "end": at,
                    }
                )
            )

    for row in rows:
        kind, at = row.get("event_type"), _time(row.get("time"))
        if kind == 9:
            close(row["process"], at)
            target = row["event"]["exec"]["target"]
        elif kind == 11:
            target = row["event"]["fork"]["child"]
        elif kind == 15:
            close(row["process"], at)
            continue
        else:
            raise ValueError("ULF_BINDING")
        key = identity(target)
        if role_of(target) in {"WRAPPER", "SSHD", "SESSION", "AUTH"}:
            if key[0] in active:
                raise ValueError("ULF_BINDING")
            active[key[0]] = key, target, at
    if not windows or len(windows) > 64:
        raise ValueError("ULF_BINDING")
    return tuple(windows)


def select_rows(rows: list[dict], windows: tuple[ExecutionWindow, ...]) -> list[dict]:
    """Use exact PID, image and a half-open execution interval before retaining any row."""
    selected: list[dict] = []
    for row in rows:
        pid = row.get("processID")
        if type(pid) is not int or pid <= 1:
            continue
        try:
            at = _time(row.get("timestamp"), unified=True)
        except ValueError:
            continue
        matches = [
            w
            for w in windows
            if w.pid == pid and w.image == row.get("processImagePath") and w.start <= at < w.end
        ]
        if len(matches) > 1:
            raise ValueError("ULF_BINDING")
        if matches:
            selected.append(row)
            if len(selected) > 256:
                raise ValueError("ULF_LIMIT")
    return selected


def summarize(rows: list[dict], windows: tuple[ExecutionWindow, ...], username: str) -> Summary:
    """Classify observed templates/relationships without exporting text, names or IDs."""
    selected = select_rows(rows, windows)
    base = Summary(
        execution_binding="PASS",
        retained_rows=len(selected),
        reference_result="RECORDS_REQUIRE_REVIEW" if selected else "NO_MATCHING_ROWS",
    )
    parsed: list[UnifiedLogRecord] = []
    invalid = 0
    logs = [row for row in selected if row.get("eventType") == "logEvent"]
    for row in logs:
        try:
            parsed.append(UnifiedLogRecord.model_validate_json(json.dumps(row)))
        except ValueError:
            invalid += 1
    base = base.model_copy(
        update={
            "log_event_rows": len(logs),
            "other_event_rows": len(selected) - len(logs),
            "invalid_log_rows": invalid,
            "classified_log_rows": len(parsed),
            "native_shapes": "FAIL" if invalid else "PASS" if logs else "INCONCLUSIVE",
        }
    )
    if not parsed:
        return base
    counts = {name: 0 for name in Messages.model_fields}
    senders: set[Sender] = set()
    roles: set[Role] = set()
    formats: set[str] = set()
    for row in parsed:
        roles.update(
            w.role
            for w in windows
            if w.pid == row.process_id
            and w.image == row.process_image_path
            and w.start <= row.event_time < w.end
        )
        senders.add(
            "MAIN_IMAGE"
            if row.sender_image_path == row.process_image_path
            else "SYSTEM_ASL"
            if row.sender_image_path == "/usr/lib/system/libsystem_asl.dylib"
            else "SYSTEM_TRACE"
            if row.sender_image_path == "/usr/lib/system/libsystem_trace.dylib"
            else "PAM"
            if row.sender_image_path == "/usr/lib/libpam.2.dylib"
            else "OTHER"
        )
        formats.add(
            "PUBLIC_C_STRING"
            if row.format_string == "%{public}s"
            else "C_STRING"
            if row.format_string == "%s"
            else "OTHER"
        )
        message = row.event_message
        key = "other_controlled"
        for method, family in (
            ("password", "accepted_local_password"),
            ("keyboard-interactive/pam", "accepted_local_pam"),
        ):
            if re.fullmatch(
                rf"Accepted {re.escape(method)} for {re.escape(username)} from 127\.0\.0\.1 port [0-9]+ ssh2",
                message,
            ):
                key = family
        if "pam_sm_open_session" in message:
            key = "pam_open"
        elif "pam_sm_close_session" in message:
            key = "pam_close"
        elif message.startswith("Disconnected from user " + username + " 127.0.0.1 port "):
            key = "disconnected_local"
        counts[key] += 1

    def presence(values: set[bool]) -> str:
        return "MIXED" if len(values) == 2 else "PRESENT" if True in values else "EMPTY"

    return Summary.model_validate(
        base.model_dump()
        | {
            "roles": tuple(sorted(roles)),
            "senders": tuple(sorted(senders)),
            "static_formats": tuple(sorted(formats)),
            "messages": counts,
            "subsystem_presence": presence({bool(row.subsystem) for row in parsed}),
            "category_presence": presence({bool(row.category) for row in parsed}),
            "message_types": tuple(sorted({row.message_type for row in parsed})),
            "message_redaction": (
                "PRESENT_ALL"
                if all("<private>" in row.event_message for row in parsed)
                else "ABSENT_ALL"
                if all("<private>" not in row.event_message for row in parsed)
                else "MIXED"
            ),
        }
    )


class Collector:
    """Bounded live reader, invoked only by the human-run capture path."""

    def __init__(self, root: Path, nonce: str) -> None:
        if type(nonce) is not str or re.fullmatch(r"[a-f0-9]{32}", nonce) is None:
            raise ValueError("ULF_BINDING")
        marker = str(root / "ssh-marker")
        self.marker_image = marker
        self.marker = "EFORGE_SSH_ULF_READY " + nonce
        self.ready = self.evicted = False
        self.total = self.size = 0
        self.buffer = b""
        self.rows: deque[tuple[int, dict]] = deque()
        # Paths are prepared controlled paths, not discovered from native records.
        predicate = (
            'process IN {"sshd-keygen-wrapper","sshd","sshd-session","sshd-auth"} '
            f'OR (process == "ssh-marker" AND eventMessage == "{self.marker}")'
        )
        self.selector = selectors.DefaultSelector()
        try:
            self.process = subprocess.Popen(
                [
                    "/usr/bin/log",
                    "stream",
                    "--style",
                    "ndjson",
                    "--level",
                    "info",
                    "--predicate",
                    predicate,
                ],
                env=SAFE_ENV,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            if self.process.stdout is None:
                raise ValueError("ULF_COLLECTOR")
            os.set_blocking(self.process.stdout.fileno(), False)
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except (OSError, ValueError, RuntimeError, KeyboardInterrupt):
            if hasattr(self, "process"):
                self.stop()
            else:
                self.selector.close()
            raise

    def accept(self, raw: bytes) -> None:
        """Retain ambient input in memory only until selected ES scope authenticates it."""
        self.total += len(raw)
        if len(raw) > MAX_LINE or self.total > MAX_STREAM:
            raise ValueError("ULF_LIMIT")
        try:
            row = json.loads(raw)
        except (ValueError, UnicodeError):
            return
        if not isinstance(row, dict):
            return
        if (
            row.get("eventMessage") == self.marker
            and row.get("processImagePath") == self.marker_image
        ):
            self.ready = True
            return
        self.rows.append((len(raw), row))
        self.size += len(raw)
        while len(self.rows) > MAX_ROWS or self.size > MAX_BYTES:
            size, _row = self.rows.popleft()
            self.size -= size
            self.evicted = True

    def tick(self) -> None:
        if self.process.poll() is not None:
            raise ValueError("ULF_COLLECTOR")
        if not self.selector.select(0):
            return
        assert self.process.stdout is not None
        chunk = os.read(self.process.stdout.fileno(), 65536)
        if not chunk:
            raise ValueError("ULF_COLLECTOR")
        self.buffer += chunk
        while b"\n" in self.buffer:
            raw, self.buffer = self.buffer.split(b"\n", 1)
            self.accept(raw)
        if len(self.buffer) > MAX_LINE:
            raise ValueError("ULF_LIMIT")

    def stop(self) -> bool:
        """Stop only this normal-user collector; return no observed process data."""
        cleaned = True
        try:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
                cleaned = False
        finally:
            self.selector.close()
            if self.process.stdout is not None:
                self.process.stdout.close()
        return cleaned
