# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared account eligibility for generated and authored shell-history evidence."""

NONINTERACTIVE_BASH_USERS: set[str] = {"apache", "www-data", "nginx", "httpd", "tomcat"}


def is_noninteractive_bash_user(username: str) -> bool:
    """Return whether the account is excluded from interactive shell history."""
    return username.lower() in NONINTERACTIVE_BASH_USERS


def validate_zsh_history_command(command: object) -> str:
    """Require the implemented single-line ASCII EXTENDED_HISTORY command profile."""
    if (
        not isinstance(command, str)
        or not command
        or any(character in command for character in ("\n", "\r", "\x00"))
    ):
        raise ValueError("zsh_history requires one nonempty, single-line command")
    if command.endswith("\\"):
        raise ValueError("zsh_history multiline continuations are not implemented")
    if not command.isascii():
        raise ValueError("zsh_history metafied non-ASCII commands are not implemented")
    return command
