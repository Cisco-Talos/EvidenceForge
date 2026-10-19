# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit argv for bounded catalog roles that execute directly without a shell."""

import shlex

from evidenceforge.events.identity import validate_process_arguments
from evidenceforge.models.exceptions import StateError


def catalog_direct_exec_arguments(image: str, command: str) -> tuple[str, ...]:
    """Decode a literal direct-exec template, preserving canonical quoting.

    Only callers that own a direct-exec catalog role may use this adapter. It
    does not infer argv for arbitrary authored commands or shell expressions.
    The catalog's double-quoted executable prefix is accepted; all remaining
    argument spelling must match the canonical serialization. No expansion or
    host environment lookup occurs.
    """
    if (
        type(image) is not str
        or not image.startswith("/")
        or image == "/"
        or "\0" in image
        or type(command) is not str
        or not command
        or "\0" in command
        or len(command) > 65536
    ):
        raise StateError("Direct-exec catalog requires a bounded literal command and exact image")
    quoted_image = f'"{image}"'
    if '"' not in image and command.startswith(quoted_image):
        command = shlex.quote(image) + command[len(quoted_image) :]
    try:
        arguments = tuple(shlex.split(command, posix=True))
        validate_process_arguments(arguments, command_line=command)
    except ValueError as error:
        raise StateError("Direct-exec catalog requires canonical literal argv") from error
    if arguments[0] != image:
        raise StateError("Direct-exec argv must name its exact executable")
    return arguments
