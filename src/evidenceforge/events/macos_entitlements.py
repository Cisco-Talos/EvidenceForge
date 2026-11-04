# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable bounded entitlement values, separate from source-profile admission."""

from __future__ import annotations

from typing import NamedTuple

type EntitlementValue = bool | int | str | tuple[str, ...] | EntitlementObject
type FrozenEntitlements = tuple[tuple[str, EntitlementValue], ...]
type NativeEntitlementValue = bool | int | str | list[str] | dict[str, NativeEntitlementValue]


class EntitlementObject(NamedTuple):
    """Distinguish an immutable nested dictionary from a string array, including empty ones."""

    entries: FrozenEntitlements


def validate_entitlements(entries: object) -> FrozenEntitlements:
    """Validate exact property values with shared depth, node and UTF-8 bounds."""
    nodes = 0
    extent = 0

    def visit(entries: object, depth: int) -> None:
        nonlocal nodes, extent
        if depth > 8:
            raise ValueError("Entitlement object exceeds its nesting bound")
        if type(entries) is not tuple or len(entries) > 128:
            raise ValueError("Entitlements require 0-128 immutable entries")
        keys: set[str] = set()
        nodes += 1
        for entry in entries:
            if (
                type(entry) is not tuple
                or len(entry) != 2
                or type(entry[0]) is not str
                or not entry[0].strip()
                or len(entry[0]) > 512
                or "\0" in entry[0]
                or entry[0] in keys
            ):
                raise ValueError("Entitlements require distinct bounded text keys")
            key, value = entry
            keys.add(key)
            extent += len(key.encode("utf-8"))
            nodes += 1
            if type(value) is EntitlementObject:
                visit(value.entries, depth + 1)
            else:
                if (
                    type(value) not in (bool, int, str, tuple)
                    or (type(value) is tuple and len(value) > 128)
                    or (type(value) is int and not -(2**63) <= value < 2**63)
                ):
                    raise ValueError("Entitlement values require exact bounded property types")
                strings = (value,) if type(value) is str else value if type(value) is tuple else ()
                for item in strings:
                    if type(item) is not str or len(item) > 16384 or "\0" in item:
                        raise ValueError("Entitlement text requires bounded exact strings")
                    extent += len(item.encode("utf-8"))
                nodes += len(value) if type(value) is tuple else 0
            if nodes > 4096 or extent > 1_048_576:
                raise ValueError("Entitlement object exceeds its aggregate node or text bound")

    visit(entries, 0)
    return entries


def freeze_entitlements(value: object) -> FrozenEntitlements:
    """Detach an explicit source/config dictionary, preserving native member order."""
    if type(value) is not dict:
        raise ValueError("Entitlements require an explicit dictionary")

    def detach(value: dict, depth: int) -> FrozenEntitlements:
        if depth > 8:
            raise ValueError("Entitlement object exceeds its nesting bound")
        return tuple(
            (
                key,
                EntitlementObject(detach(item, depth + 1))
                if type(item) is dict
                else tuple(item)
                if type(item) in (list, tuple)
                else item,
            )
            for key, item in value.items()
        )

    return validate_entitlements(detach(value, 0))


def native_entitlements(entries: FrozenEntitlements) -> dict[str, NativeEntitlementValue]:
    """Render arrays as native JSON lists without exposing mutable canonical values."""
    return {
        key: native_entitlements(value.entries)
        if type(value) is EntitlementObject
        else list(value)
        if type(value) is tuple
        else value
        for key, value in entries
    }


def canonical_entitlements(entries: FrozenEntitlements) -> FrozenEntitlements:
    """Normalize dictionary order for release identity without changing array order or types."""
    validate_entitlements(entries)
    return tuple(
        (key, EntitlementObject(canonical_entitlements(value.entries)))
        if type(value) is EntitlementObject
        else (key, value)
        for key, value in sorted(entries)
    )
