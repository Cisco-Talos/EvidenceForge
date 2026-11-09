# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared DNS TXT wire-character-string partitioning."""


def dns_txt_character_strings(answer: str) -> tuple[str, ...]:
    """Partition modeled UTF-8 TXT content into at-most-255-byte strings.

    Preserve character boundaries so both wire sizing and native text projection
    describe the same strings. Empty content is one zero-length string.
    """
    strings: list[str] = []
    current: list[str] = []
    size = 0
    for character in answer:
        width = len(character.encode("utf-8"))
        if size + width > 255:
            strings.append("".join(current))
            current = []
            size = 0
        current.append(character)
        size += width
    strings.append("".join(current))
    return tuple(strings)
