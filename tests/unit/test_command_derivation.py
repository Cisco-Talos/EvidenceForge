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

"""Recorded authored-to-native command derivations replay exactly and fail closed."""

import pytest

from evidenceforge.evaluation.ground_truth_agreement import _derived_command_agrees
from evidenceforge.events.command_derivation import (
    CommandDerivation,
    CommandDerivationError,
    CommandDerivationStep,
)
from evidenceforge.generation.command_derivation import (
    posix_shell_argv,
    posix_shell_program,
    replay_command_derivation,
    step,
)


def _derive(authored: str, image: str, username: str = "root") -> CommandDerivation:
    derivation = CommandDerivation(authored)
    argv = posix_shell_argv(authored, image=image, username=username)
    derivation = derivation.then(
        authored, argv, step("posix_shell_argv", image=image, username=username)
    )
    program = posix_shell_program(argv, image=image)
    return derivation.then(argv, program, step("posix_shell_program", image=image))


@pytest.mark.parametrize(
    ("authored", "image", "native"),
    [
        (
            "find /opt/ehr -name '*credential*' -maxdepth 3",
            "/usr/bin/find",
            "find /opt/ehr -name *credential* -maxdepth 3",
        ),
        (
            "mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql",
            "/usr/bin/mysqldump",
            "mysqldump --single-transaction ehr patients insurance_claims",
        ),
        (
            "history -c && cat /dev/null > ~/.bash_history",
            "/bin/bash",
            "bash -c 'history -c && cat /dev/null > ~/.bash_history'",
        ),
    ],
)
def test_posix_derivation_replays_to_native_argv(authored: str, image: str, native: str) -> None:
    derivation = _derive(authored, image)

    assert derivation.steps
    assert replay_command_derivation(derivation) == native
    assert _derived_command_agrees(
        authored, {"command_line": native, "command_derivation": derivation.to_facts()}
    )


def test_unchanged_command_records_no_steps() -> None:
    derivation = _derive("cat /etc/hosts", "/usr/bin/cat")

    assert derivation.steps == ()


def test_windows_service_normalization_replays() -> None:
    authored = "PSEXESVC.exe -accepteula"
    derivation = CommandDerivation(authored).then(
        authored,
        r"C:\Windows\PSEXESVC.exe",
        step("windows_process_normalization", image=r"C:\Windows\System32\PSEXESVC.exe"),
    )

    assert replay_command_derivation(derivation) == r"C:\Windows\PSEXESVC.exe"


def test_macos_launch_descriptor_appends_contract_argument() -> None:
    image = "/Applications/Demo.app/Contents/MacOS/Demo Helper"
    authored = f"'{image}' --type=renderer"
    derivation = CommandDerivation(authored).then(
        authored,
        f"'{image}' --type=renderer --seatbelt-client=3",
        step("macos_launch_descriptor", image=image, argument="--seatbelt-client=3"),
    )

    assert replay_command_derivation(derivation) == f"'{image}' --type=renderer --seatbelt-client=3"


def test_evaluator_rejects_unrecorded_or_mismatched_derivations() -> None:
    authored = "find /opt -name '*.key'"
    derivation = _derive(authored, "/usr/bin/find")
    facts = derivation.to_facts()

    assert not _derived_command_agrees(authored, {"command_line": "find /opt -name x"})
    assert not _derived_command_agrees(
        "find /srv -name '*.key'",
        {"command_line": "find /opt -name *.key", "command_derivation": facts},
    )
    assert not _derived_command_agrees(
        authored, {"command_line": "find /opt -name other", "command_derivation": facts}
    )
    assert not _derived_command_agrees(
        authored, {"command_line": "find /opt -name *.key", "command_derivation": {"steps": []}}
    )


def test_derivation_rejects_unknown_rules_and_round_trips_facts() -> None:
    with pytest.raises(CommandDerivationError):
        CommandDerivationStep("rewrite_anything")  # type: ignore[arg-type]
    derivation = _derive("find / -name '*.pem'", "/usr/bin/find")

    assert CommandDerivation.from_facts(derivation.to_facts()) == derivation
