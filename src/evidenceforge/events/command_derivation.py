# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Recorded derivation from an authored command to the native process command line.

Authored process steps are written as shell programs or tool invocations. The
process an OS actually executes can differ: the shell removes quotes and
redirections, a shell program runs under ``sh -c``, launch contracts add
arguments, and service hosts replace their invocation. Generation records each
applied rule here, in order, so ground truth can verify the native command by
replaying the same rules instead of demanding byte equality with the authored text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

from evidenceforge.models.exceptions import EvidenceForgeError

CommandDerivationRule = Literal[
    "placeholder_substitution",
    "posix_shell_argv",
    "posix_shell_program",
    "catalog_direct_exec",
    "windows_process_normalization",
    "macos_launch_descriptor",
]
COMMAND_DERIVATION_RULES: frozenset[str] = frozenset(get_args(CommandDerivationRule))
MAX_COMMAND_DERIVATION_STEPS = 8


class CommandDerivationError(EvidenceForgeError):
    """A recorded command derivation is malformed or cannot be replayed."""


@dataclass(frozen=True, slots=True)
class CommandDerivationStep:
    """One applied rule and the inputs needed to replay it exactly."""

    rule: CommandDerivationRule
    parameters: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Reject rules outside the reviewed derivation vocabulary."""
        if self.rule not in COMMAND_DERIVATION_RULES:
            raise CommandDerivationError(f"Unknown command derivation rule: {self.rule!r}")

    def parameter(self, name: str) -> str:
        """Return one required replay parameter."""
        for key, value in self.parameters:
            if key == name:
                return value
        raise CommandDerivationError(f"Command derivation step {self.rule} lacks {name!r}")


@dataclass(frozen=True, slots=True)
class CommandDerivation:
    """The authored command and the ordered rules that produced the native command."""

    authored_command_line: str
    steps: tuple[CommandDerivationStep, ...] = ()

    def __post_init__(self) -> None:
        """Keep the record bounded and append-only in meaning."""
        if len(self.steps) > MAX_COMMAND_DERIVATION_STEPS:
            raise CommandDerivationError("Command derivations are limited to eight steps")

    def then(self, before: str, after: str, step: CommandDerivationStep) -> CommandDerivation:
        """Return this derivation with ``step`` appended when it changed the command."""
        if before == after:
            return self
        return CommandDerivation(self.authored_command_line, (*self.steps, step))

    def to_facts(self) -> dict[str, object]:
        """Return the JSON ground-truth projection of this derivation."""
        return {
            "authored_command_line": self.authored_command_line,
            "steps": [
                {"rule": step.rule, "parameters": dict(step.parameters)} for step in self.steps
            ],
        }

    @classmethod
    def from_facts(cls, value: object) -> CommandDerivation:
        """Rebuild a derivation from its ground-truth projection, rejecting malformed input."""
        if not isinstance(value, dict) or not isinstance(value.get("authored_command_line"), str):
            raise CommandDerivationError("Command derivation facts lack an authored command")
        steps = value.get("steps")
        if not isinstance(steps, list):
            raise CommandDerivationError("Command derivation facts lack ordered steps")
        parsed: list[CommandDerivationStep] = []
        for item in steps:
            parameters = item.get("parameters") if isinstance(item, dict) else None
            if not isinstance(parameters, dict) or not all(
                isinstance(key, str) and isinstance(entry, str) for key, entry in parameters.items()
            ):
                raise CommandDerivationError("Command derivation step parameters are malformed")
            parsed.append(CommandDerivationStep(item.get("rule"), tuple(parameters.items())))
        return cls(value["authored_command_line"], tuple(parsed))
