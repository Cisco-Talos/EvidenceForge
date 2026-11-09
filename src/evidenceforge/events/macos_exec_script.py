# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit shebang-execution linkage, separate from an interpreter's arguments."""

import shlex
from dataclasses import dataclass
from typing import Annotated

from pydantic import Field

from evidenceforge.events.content_identity import LocalArtifactVersionRecord

ScriptReferenceText = Annotated[str, Field(strict=True, min_length=1)]


@dataclass(frozen=True, slots=True)
class MacosExecScript:
    """Known script absence or one exact runtime script used by this execution.

    None on ProcessIdentity means unknown; an empty instance means explicitly
    no shebang script. A positive reference records caller-established shebang
    execution, never a filename suffix or an argument to an interpreter. The
    loaded interpreter remains the execution's separate executable_version.
    """

    hostname: ScriptReferenceText | None = None
    artifact_version_id: ScriptReferenceText | None = None
    content_id: ScriptReferenceText | None = None
    native_path: ScriptReferenceText | None = None

    def __post_init__(self) -> None:
        values = (self.hostname, self.artifact_version_id, self.content_id, self.native_path)
        if all(value is None for value in values):
            return
        if any(type(value) is not str or not value.strip() or "\0" in value for value in values):
            raise ValueError(
                "Mac script reference requires complete exact file identity or absence"
            )
        if not self.native_path.startswith("/"):
            raise ValueError("Mac script reference requires an absolute modeled file path")

    @classmethod
    def from_runtime_record(cls, record: LocalArtifactVersionRecord) -> "MacosExecScript":
        """Bind a caller-established script execution to its existing non-Mach-O file."""
        if type(record) is not LocalArtifactVersionRecord:
            raise ValueError("Mac script requires an exact runtime file record")
        record.__post_init__()
        if record.artifact.platform != "macos" or record.binary is not None:
            raise ValueError("Mac script requires a Mac file distinct from its loaded interpreter")
        return cls(
            record.artifact.hostname,
            record.artifact.artifact_version_id,
            record.content.content_id,
            record.artifact.native_path,
        )


def validate_macos_exec_script(
    value: MacosExecScript | None, *, platform: str, hostname: str
) -> None:
    """Validate host/platform ownership without resolving a current path or inspecting bytes."""
    if value is None:
        return
    if platform != "macos" or type(value) is not MacosExecScript:
        raise ValueError("Mac script execution requires an exact macOS reference")
    value.__post_init__()
    if value.hostname is not None and value.hostname.casefold() != hostname.casefold():
        raise ValueError("Mac script execution belongs to another host")


@dataclass(frozen=True, slots=True)
class MacosShebangExecutionIntent:
    """Explicit kernel-script execution intent, distinct from ``shell file``.

    The modeled file owner supplies the shebang interpreter and its literal
    optional arguments. Neither file bytes, suffixes nor display commands are
    inspected. The ordinary process action owns retention and publication.
    """

    script: MacosExecScript
    interpreter: str
    interpreter_arguments: tuple[str, ...] = ()
    script_arguments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.script) is not MacosExecScript
            or self.script.artifact_version_id is None
            or type(self.interpreter) is not str
            or not self.interpreter.startswith("/")
            or "\0" in self.interpreter
            or type(self.interpreter_arguments) is not tuple
            or type(self.script_arguments) is not tuple
            or any(
                type(item) is not str or "\0" in item
                for item in (*self.interpreter_arguments, *self.script_arguments)
            )
        ):
            raise ValueError(
                "Shebang intent requires exact retained script and literal interpreter argv"
            )
        self.script.__post_init__()

    @property
    def arguments(self) -> tuple[str, ...]:
        """Construct kernel-owned interpreter argv from this explicit intent."""
        self.__post_init__()
        return (
            self.interpreter,
            *self.interpreter_arguments,
            self.script.native_path,
            *self.script_arguments,
        )

    @property
    def command_line(self) -> str:
        """Display the exact produced argv without parsing a shell command."""
        return shlex.join(self.arguments)
