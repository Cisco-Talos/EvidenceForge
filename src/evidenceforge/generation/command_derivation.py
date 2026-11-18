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

"""Authored-to-native command rules shared by process generation and ground truth.

Each rule is the single implementation generation uses to transform a command, and
the function ground truth replays to verify a recorded derivation. Rules are pure:
every input beyond the command itself is recorded as a step parameter.
"""

from __future__ import annotations

import shlex

from evidenceforge.events.command_derivation import (
    CommandDerivation,
    CommandDerivationError,
    CommandDerivationRule,
    CommandDerivationStep,
)


def posix_shell_argv(command: str, *, image: str, username: str) -> str:
    """Return the exec argv display the shell produces for the command's first process.

    Quotes are removed, redirections dropped and home shortcuts expanded. A command
    whose first process is not ``image`` is left unchanged.
    """
    from evidenceforge.generation.activity.generator import _linux_command_process_from_shell

    inferred = _linux_command_process_from_shell(command, username=username)
    if inferred is None or inferred[0].rsplit("/", 1)[-1] != image.rsplit("/", 1)[-1]:
        return command
    return inferred[1]


def posix_shell_program(command: str, *, image: str) -> str:
    """Return the ``<shell> -c`` invocation that runs a shell program under ``image``."""
    from evidenceforge.generation.engine.storyline_helpers.process import (
        _linux_shell_process_command_line,
    )

    return _linux_shell_process_command_line(image, command) or command


def catalog_direct_exec(command: str, *, image: str) -> str:
    """Return the canonical direct-exec serialization of a catalog launch."""
    from evidenceforge.generation.activity.direct_exec import catalog_direct_exec_arguments

    return shlex.join(catalog_direct_exec_arguments(image, command))


def windows_process_normalization(command: str, *, image: str) -> str:
    """Return the command Windows actually runs for a script or service-host image."""
    from evidenceforge.generation.activity.process_helpers import normalize_process_command

    return normalize_process_command(image, command, os_category="windows", hostname="")[1]


def macos_launch_descriptor(command: str, *, image: str, argument: str) -> str:
    """Return the literal helper argv with a launch-contract argument appended."""
    from evidenceforge.generation.activity.direct_exec import literal_shell_child_arguments

    arguments = literal_shell_child_arguments(image, command)
    if arguments is None:
        raise CommandDerivationError("Mac launch descriptor requires a literal helper argv")
    return shlex.join((*arguments, argument))


def apply_command_derivation_step(command: str, step: CommandDerivationStep) -> str:
    """Apply one recorded rule to ``command`` using only its recorded parameters."""
    if step.rule == "placeholder_substitution":
        return command.replace(step.parameter("placeholder"), step.parameter("value"))
    if step.rule == "posix_shell_argv":
        return posix_shell_argv(
            command, image=step.parameter("image"), username=step.parameter("username")
        )
    if step.rule == "posix_shell_program":
        return posix_shell_program(command, image=step.parameter("image"))
    if step.rule == "catalog_direct_exec":
        return catalog_direct_exec(command, image=step.parameter("image"))
    if step.rule == "windows_process_normalization":
        return windows_process_normalization(command, image=step.parameter("image"))
    if step.rule == "macos_launch_descriptor":
        return macos_launch_descriptor(
            command, image=step.parameter("image"), argument=step.parameter("argument")
        )
    raise CommandDerivationError(f"Unsupported command derivation rule: {step.rule}")


def replay_command_derivation(derivation: CommandDerivation) -> str:
    """Return the native command produced by replaying every recorded rule in order."""
    command = derivation.authored_command_line
    for step in derivation.steps:
        command = apply_command_derivation_step(command, step)
    return command


def step(rule: CommandDerivationRule, **parameters: str) -> CommandDerivationStep:
    """Build a derivation step with sorted, string-valued parameters."""
    return CommandDerivationStep(rule, tuple(sorted(parameters.items())))
