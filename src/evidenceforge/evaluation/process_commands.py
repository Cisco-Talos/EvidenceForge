"""Compare literal POSIX invocations without interpreting shell programs."""

from __future__ import annotations

import shlex


def literal_posix_arguments(command: str) -> list[str] | None:
    """Return literal arguments, or None when shell interpretation is required."""
    quote: str | None = None
    escaped = False
    for character in command:
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if character in {"$", "`", "\n", "\r", "\x00"}:
            return None
        if quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character in "|&;<>()*?[]~#!{}":
            return None
    try:
        arguments = shlex.split(command, posix=True) if not quote and not escaped else None
        if arguments and "=" in arguments[0] and arguments[0].partition("=")[0].isidentifier():
            return None
        return arguments
    except ValueError:
        return None


def process_commands_agree(authored: str, actual: str, os_category: str) -> bool:
    """Accept equivalent literal POSIX argv; keep other syntax byte-exact."""
    if authored == actual:
        return True
    if os_category not in {"linux", "macos"}:
        return False
    expected = literal_posix_arguments(authored)
    return expected is not None and expected == literal_posix_arguments(actual)
