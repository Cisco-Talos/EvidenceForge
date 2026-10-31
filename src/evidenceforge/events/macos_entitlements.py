# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable bounded entitlement values, separate from source-profile admission."""

type EntitlementValue = bool | int | str | tuple[str, ...]
type FrozenEntitlements = tuple[tuple[str, EntitlementValue], ...]


def validate_entitlements(entries: object) -> FrozenEntitlements:
    """Validate the reviewed flat object without retaining mutable or coerced data."""
    if type(entries) is not tuple or len(entries) > 128:
        raise ValueError("Entitlements require 0-128 immutable entries")
    keys: set[str] = set()
    nodes = 1
    extent = 0
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
        if (
            type(value) not in (bool, int, str, tuple)
            or (type(value) is tuple and len(value) > 128)
            or (type(value) is int and not -(2**63) <= value < 2**63)
        ):
            raise ValueError(
                "Entitlement values require exact Booleans, signed 64-bit integers, strings or string arrays"
            )
        strings = (value,) if type(value) is str else value if type(value) is tuple else ()
        for item in strings:
            if type(item) is not str or len(item) > 16384 or "\0" in item:
                raise ValueError("Entitlement text requires bounded exact strings")
            extent += len(item.encode("utf-8"))
            if extent > 1_048_576:
                raise ValueError("Entitlement object exceeds its aggregate text bound")
        nodes += len(value) if type(value) is tuple else 0
        if nodes > 4096 or extent > 1_048_576:
            raise ValueError("Entitlement object exceeds its aggregate node or text bound")
    return entries


def freeze_entitlements(value: object) -> FrozenEntitlements:
    """Detach an explicit source/config dictionary, preserving native member order."""
    if type(value) is not dict:
        raise ValueError("Entitlements require an explicit dictionary")
    return validate_entitlements(
        tuple(
            (key, tuple(item) if type(item) in (list, tuple) else item)
            for key, item in value.items()
        )
    )


def native_entitlements(entries: FrozenEntitlements) -> dict[str, bool | int | str | list[str]]:
    """Render arrays as native JSON lists without exposing mutable canonical values."""
    return {key: list(value) if type(value) is tuple else value for key, value in entries}
