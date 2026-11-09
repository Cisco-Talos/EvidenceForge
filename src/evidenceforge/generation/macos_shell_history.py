# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""History eligibility from canonical shell invocation and stdin facts."""

import logging

logger = logging.getLogger(__name__)


def interactive_history_shell(
    image: str, arguments: tuple[str, ...] | None, *, stdin_is_terminal: bool | None
) -> bool:
    """Admit bounded stdin/login invocations, including explicit non-PTY interactive mode.

    Login mode alone does not imply interactive mode. Unknown options, scripts,
    command-string execution and unknown invocation facts remain unqualified.
    """
    if image not in {"/bin/zsh", "/bin/bash"} or not arguments:
        return False
    name = image.rsplit("/", 1)[-1]
    if arguments[0] not in {image, name, f"-{name}"}:
        return False
    interactive = stdin_is_terminal is True
    for option in arguments[1:]:
        if option == "--login" or image == "/bin/bash" and option in {"--norc", "--noprofile"}:
            continue
        if option == "--interactive":
            interactive = True
            continue
        if len(option) < 2 or option[0] not in {"-", "+"}:
            return False
        for flag in option[1:]:
            if flag == "i":
                interactive = option[0] == "-"
            elif flag not in {"l", "f", "s"} and not (image == "/bin/zsh" and flag == "d"):
                return False
    return interactive
