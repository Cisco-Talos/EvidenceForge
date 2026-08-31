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

"""Immutable exact indexes for deployment and content identities.

The registry compiles already-resolved identities into compact primary and
secondary indexes. It has no mutation API and retains no executable or file
payloads. Runtime resolution is always by an exact semantic key or an exact
host-native path; basename or fleet-wide path guessing is intentionally absent.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import ntpath
import posixpath
import random
import re
import secrets
import sys
import zlib
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Hashable, Iterable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from copy import copy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from itertools import islice
from threading import Condition, Lock, RLock, get_ident
from typing import Generic, TypeVar, cast
from weakref import ReferenceType, WeakValueDictionary, ref

from evidenceforge.events.content_identity import (
    ApplicationProfileCanonicalKey,
    ApplicationProfileIdentity,
    Architecture,
    BinaryReleaseCanonicalKey,
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    CompiledServiceDeploymentIdentity,
    CompiledTaskDeploymentIdentity,
    ContentDigests,
    FileContentIdentity,
    FileVersionCanonicalKey,
    InstallationCanonicalKey,
    InstallationScope,
    InstalledSoftwareReleaseCanonicalKey,
    InstalledSoftwareReleaseIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactCanonicalKey,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
    PeVersionInfo,
    Platform,
    RuntimeServiceDeploymentIdentity,
    ServiceDeploymentIdentity,
    SoftwareInstallationIdentity,
    UserProfileCanonicalKey,
    UserProfileIdentity,
    canonical_native_path,
)
from evidenceforge.generation.indexes import (
    CompactIndexedStore,
    IndexMetrics,
    ReferenceLeaseIndex,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")

_PLATFORMS = {"windows", "linux", "macos"}
_ARCHITECTURES = {"x86", "x64", "arm64", "neutral"}
_DEFAULT_ARTIFACT_RETENTION = timedelta(hours=48)
_DEFAULT_ARTIFACT_CAPACITY = 100_000
_DEFAULT_ARTIFACT_SHARDS = 64
_DEFAULT_ARTIFACT_PREPARED_BYTE_CAPACITY = 512 * 1_024 * 1_024
_PRIMARY_COMPACTION_BUDGET = 4_096
_COMPACT_HANDLE_BITS = 32
_COMPACT_HANDLE_LIMIT = (1 << _COMPACT_HANDLE_BITS) - 1
_ARTIFACT_PLATFORM_CODES: dict[Platform, int] = {"windows": 0, "linux": 1, "macos": 2}
_ARTIFACT_PLATFORMS: tuple[Platform, ...] = ("windows", "linux", "macos")
_EMPTY_ARTIFACT_DEADLINE = -1
_EMPTY_ARTIFACT_SLOT = 0
_TOMBSTONE_ARTIFACT_SLOT = (1 << 32) - 1
_ARTIFACT_DIGEST_BYTES = 16
_ARTIFACT_INLINE_PAYLOAD_BYTES = 128
_ARTIFACT_BUCKET_TAG = 1 << 31


def _normalize_platform(platform: str) -> Platform:
    value = platform.strip().casefold()
    if value not in _PLATFORMS:
        raise ValueError(f"platform must be one of {sorted(_PLATFORMS)}")
    return cast(Platform, value)


def _normalize_architecture(architecture: str) -> Architecture:
    value = architecture.strip().casefold()
    if value not in _ARCHITECTURES:
        raise ValueError(f"architecture must be one of {sorted(_ARCHITECTURES)}")
    return cast(Architecture, value)


def _architecture_is_compatible(
    host_architecture: Architecture,
    artifact_architecture: Architecture,
) -> bool:
    """Return whether an exact or architecture-neutral artifact can run on a host."""

    return artifact_architecture in {host_architecture, "neutral"}


def _owned_graph_size(value: object, seen: set[int] | None = None) -> int:
    """Estimate one registry-owned object graph without following code globals.

    Container backing reported by :func:`sys.getsizeof` is counted once. Packed
    primitive arrays and byte strings already include their element backing, so
    they are terminal nodes. Functions, classes, and other opaque runtime
    objects are also terminal nodes; following their globals would attribute
    process-wide state to a scenario-scoped registry.
    """

    if seen is None:
        seen = set()
    identity = id(value)
    if identity in seen:
        return 0
    seen.add(identity)
    retained = sys.getsizeof(value)
    if isinstance(value, (str, bytes, bytearray, memoryview, array)):
        return retained
    if isinstance(value, dict):
        return retained + sum(
            _owned_graph_size(key, seen) + _owned_graph_size(item, seen)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return retained + sum(_owned_graph_size(item, seen) for item in value)
    instance_values = getattr(value, "__dict__", None)
    if isinstance(instance_values, dict):
        retained += _owned_graph_size(instance_values, seen)
    for owner in type(value).__mro__:
        slots = owner.__dict__.get("__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if slot in {"__dict__", "__weakref__"}:
                continue
            try:
                slot_value = getattr(value, slot)
            except AttributeError:
                continue
            retained += _owned_graph_size(slot_value, seen)
    return retained


class _PlatformStringInterner:
    """Assign compact global handles without composite platform/string tuple keys."""

    __slots__ = ("_handles", "_next_handle", "_values")

    def __init__(self) -> None:
        self._handles: dict[Platform, dict[str, int]] = {}
        self._next_handle = 1
        self._values: list[str] = []

    def intern(self, platform: Platform, value: str) -> int:
        """Return the stable handle for one exact platform-native string."""

        bucket = self._handles.setdefault(platform, {})
        handle = bucket.get(value)
        if handle is not None:
            return handle
        if self._next_handle > _COMPACT_HANDLE_LIMIT:
            raise StateError("binary path interner exceeded its 32-bit handle capacity")
        handle = self._next_handle
        self._next_handle += 1
        bucket[value] = handle
        self._values.append(value)
        return handle

    def find(self, platform: Platform, value: str) -> int | None:
        """Return an existing handle without allocating during lookup."""

        return self._handles.get(platform, {}).get(value)

    def __len__(self) -> int:
        return self._next_handle - 1

    def value(self, handle: int) -> str:
        """Return the interned value for one compact handle."""

        if handle <= 0 or handle >= self._next_handle:
            raise KeyError(handle)
        return self._values[handle - 1]

    def estimated_bytes(self) -> int:
        """Return a structural byte estimate during an explicit census."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._handles)
            + sys.getsizeof(self._values)
            + sum(sys.getsizeof(bucket) for bucket in self._handles.values())
            + sum(
                sys.getsizeof(value) + sys.getsizeof(handle)
                for bucket in self._handles.values()
                for value, handle in bucket.items()
            )
        )


def _packed_binary_path_key(
    host_handle: int,
    principal_handle: int,
    native_path_handle: int,
) -> int:
    """Pack three bounded handles into one collision-free integer dictionary key."""

    if any(
        handle < 0 or handle > _COMPACT_HANDLE_LIMIT
        for handle in (host_handle, principal_handle, native_path_handle)
    ):
        raise StateError("binary path binding handle exceeds its 32-bit packed field")
    return (
        (host_handle << (_COMPACT_HANDLE_BITS * 2))
        | (principal_handle << _COMPACT_HANDLE_BITS)
        | native_path_handle
    )


def _packed_binary_binding(installation_handle: int, release_handle: int) -> int:
    """Pack an installation/release handle pair without a per-binding tuple."""

    if any(
        handle < 0 or handle > _COMPACT_HANDLE_LIMIT
        for handle in (installation_handle, release_handle)
    ):
        raise StateError("binary path target handle exceeds its 32-bit packed field")
    return (installation_handle << _COMPACT_HANDLE_BITS) | release_handle


def _unpack_binary_binding(binding: int) -> tuple[int, int]:
    """Return installation and release handles from one packed target."""

    return binding >> _COMPACT_HANDLE_BITS, binding & _COMPACT_HANDLE_LIMIT


def _normalize_hostname(hostname: str) -> str:
    value = hostname.strip().casefold()
    if not value:
        raise ValueError("hostname must not be empty")
    return value


def _normalize_principal(principal: str, platform: Platform) -> str:
    value = principal.strip()
    return value.casefold() if platform == "windows" else value


def _normalize_name(value: str, field_name: str, *, casefold: bool = False) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized.casefold() if casefold else normalized


def _artifact_name(path: str, platform: Platform) -> str:
    if platform == "windows":
        return ntpath.basename(path.replace("/", "\\")).casefold()
    return posixpath.basename(path)


def _has_posix_path_backslash(path: str, platform: Platform) -> bool:
    """Return whether POSIX would treat a retained backslash as literal path data."""

    return platform != "windows" and "\\" in path


def _canonical_software_installation(
    source: object,
) -> SoftwareInstallationIdentity:
    """Return a detached exact installation and authenticate its derived ID."""

    if type(source) is not SoftwareInstallationIdentity:
        raise ValueError("installations must contain exact SoftwareInstallationIdentity values")
    field_names = (
        "hostname",
        "application_id",
        "release_id",
        "platform",
        "scope",
        "principal",
        "user_profile_id",
        "installation_slot",
        "install_root",
    )
    values = tuple(object.__getattribute__(source, name) for name in field_names)
    image_paths = object.__getattribute__(source, "image_paths")
    installation_id = object.__getattribute__(source, "installation_id")
    if any(type(value) is not str for value in (*values, installation_id)):
        raise ValueError("installation fields and installation_id must be exact str values")
    if type(image_paths) is not tuple or any(type(path) is not str for path in image_paths):
        raise ValueError("installation image_paths must be an exact tuple of exact str values")
    canonical = SoftwareInstallationIdentity(
        hostname=values[0],
        application_id=values[1],
        release_id=values[2],
        platform=cast(Platform, values[3]),
        scope=cast(InstallationScope, values[4]),
        principal=values[5],
        user_profile_id=values[6],
        installation_slot=values[7],
        install_root=values[8],
        image_paths=image_paths,
    )
    canonical_values = tuple(object.__getattribute__(canonical, name) for name in field_names)
    if values != canonical_values or installation_id != canonical.installation_id:
        raise ValueError("installation fields must agree with its canonical derived identity")
    return canonical


def _canonical_local_artifact_identity(source: object) -> LocalArtifactIdentity:
    """Return one detached exact artifact after authenticating both derived IDs."""

    if type(source) is not LocalArtifactIdentity:
        raise StateError("local artifact publication requires an exact identity value")
    field_names = (
        "hostname",
        "principal",
        "platform",
        "user_profile_id",
        "application_profile_id",
        "application_id",
        "family",
        "source_object_id",
        "native_path",
        "content_id",
        "slot",
    )
    values = tuple(object.__getattribute__(source, name) for name in field_names)
    version = object.__getattribute__(source, "version")
    artifact_id = object.__getattribute__(source, "artifact_id")
    artifact_version_id = object.__getattribute__(source, "artifact_version_id")
    if any(type(value) is not str for value in (*values, artifact_id, artifact_version_id)):
        raise StateError("local artifact fields and derived IDs must be exact str values")
    if type(version) is not int:
        raise StateError("local artifact version must be an exact int")
    canonical = LocalArtifactIdentity(
        hostname=values[0],
        principal=values[1],
        platform=cast(Platform, values[2]),
        user_profile_id=values[3],
        application_profile_id=values[4],
        application_id=values[5],
        family=values[6],
        source_object_id=values[7],
        native_path=values[8],
        content_id=values[9],
        slot=values[10],
        version=version,
    )
    canonical_values = tuple(object.__getattribute__(canonical, name) for name in field_names)
    if (
        values != canonical_values
        or artifact_id != canonical.artifact_id
        or artifact_version_id != canonical.artifact_version_id
    ):
        raise StateError("local artifact fields must agree with its canonical derived identity")
    return canonical


def _application_presentation_principal(
    descriptor: CompiledApplicationDescriptor,
    installation: SoftwareInstallationIdentity,
    user_profile: UserProfileIdentity,
) -> str:
    """Derive exact rendered principal bytes from immutable deployment truth."""

    image_template = descriptor.image_path
    if "{username}" in image_template:
        if descriptor.platform == "windows":
            normalized_template = image_template.replace("/", "\\")
            normalized_image = installation.image_paths[0].replace("/", "\\")
            component_pattern = r"[^\\]+"
            flags = re.IGNORECASE
        else:
            normalized_template = image_template
            normalized_image = installation.image_paths[0]
            component_pattern = r"[^/]+"
            flags = 0
        template_parts = normalized_template.split("{username}")
        pattern = re.escape(template_parts[0]) + f"(?P<username>{component_pattern})"
        for template_part in template_parts[1:-1]:
            pattern += re.escape(template_part) + r"(?P=username)"
        pattern += re.escape(template_parts[-1])
        match = re.fullmatch(pattern, normalized_image, flags=flags)
        if match is None:
            raise ValueError(
                "compiled application descriptor image must match the installation "
                "primary executable"
            )
        presentation_principal = match.group("username")
    elif descriptor.uses_username:
        profile_root = user_profile.profile_root.rstrip(
            "/\\" if descriptor.platform == "windows" else "/"
        )
        presentation_principal = (
            ntpath.basename(profile_root.replace("/", "\\"))
            if descriptor.platform == "windows"
            else posixpath.basename(profile_root)
        )
        if not presentation_principal:
            raise ValueError(
                "compiled application command username requires an exact user profile root"
            )
    else:
        presentation_principal = user_profile.principal
    if _normalize_principal(presentation_principal, descriptor.platform) != user_profile.principal:
        raise ValueError(
            "compiled application presentation principal must match its user profile owner"
        )
    return presentation_principal


def _stable_semantic_id(prefix: str, namespace: str, key: tuple[object, ...]) -> str:
    payload = json.dumps([namespace, *key], ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:32]}"


def _normalized_unique_ids(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    normalized = tuple(_normalize_name(value, field_name) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{field_name} contains duplicate identities")
    return tuple(sorted(normalized))


def _normalized_unique_names(values: tuple[str, ...], field_name: str) -> tuple[str, ...]:
    normalized = tuple(
        sorted({_normalize_name(value, field_name, casefold=True) for value in values})
    )
    if len(normalized) != len(values):
        raise ValueError(f"{field_name} contains duplicate names")
    return normalized


def _insert_unique(
    store: CompactIndexedStore[K, V],
    key: K,
    value: V,
    label: str,
) -> int:
    if key in store:
        raise ValueError(f"duplicate {label} canonical key: {key!r}")
    store[key] = value
    return store.handle_for(key)


def _require_unique_index(
    store: CompactIndexedStore[K, V],
    index_name: str,
    indexed_value: Hashable,
    label: str,
) -> None:
    if store.count(index_name, indexed_value):
        raise ValueError(f"duplicate {label}: {indexed_value!r}")


_PACKED_INDEX_EMPTY_DIGEST = (1 << 64) - 1
_PACKED_INDEX_EMPTY_HANDLE = (1 << 32) - 1
_PACKED_INDEX_BUCKET_TAG = 1 << 31
_PACKED_IDENTITY_COMPAT_LIMIT = 10_000
_APPLICATION_COMMAND_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_MAX_COMPILED_COMMAND_EXECUTABLES = 1_024
_MAX_APPLICATION_COMMAND_EXPANSIONS = 1_024
_MAX_APPLICATION_COMMAND_LENGTH = 65_536
_MAX_APPLICATION_COMMAND_PARAMETER_POOLS = 128
_MAX_APPLICATION_COMMAND_PARAMETER_VALUES = 4_096
_MAX_APPLICATION_COMMAND_TEMPLATES = 256
_MAX_APPLICATION_DESCRIPTOR_CATEGORIES = 256
_MAX_APPLICATION_DESCRIPTOR_TEXT_BYTES = 1_048_576
_MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT = 16_384
_MAX_APPLICATION_DESCRIPTOR_REGISTRY_TEXT_BYTES = 16_777_216


def _packed_index_key(value: Hashable) -> bytes:
    """Encode the supported exact immutable-index key shapes without ambiguity."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _packed_index_digest(value: bytes) -> int:
    digest = int.from_bytes(
        hashlib.blake2b(value, digest_size=8, person=b"ef-deploy-idx").digest(),
        "big",
    )
    return digest if digest != _PACKED_INDEX_EMPTY_DIGEST else digest - 1


class _PackedAppendRows:
    """Append-only variable byte rows with one contiguous immutable backing blob."""

    __slots__ = ("_data", "_offsets", "_sealed")

    def __init__(self) -> None:
        self._data: bytearray | bytes = bytearray()
        self._offsets = array("Q")
        self._sealed = False

    def __len__(self) -> int:
        return len(self._offsets)

    def append(self, row: bytes) -> int:
        if self._sealed:
            raise StateError("packed immutable rows are already sealed")
        handle = len(self._offsets)
        if handle >= _PACKED_INDEX_EMPTY_HANDLE:
            raise StateError("packed immutable rows exceeded 32-bit handle capacity")
        self._offsets.append(len(self._data))
        cast(bytearray, self._data).extend(row)
        return handle

    def seal(self) -> None:
        """Drop mutable bytearray spare capacity after compilation."""

        if self._sealed:
            return
        self._data = bytes(self._data)
        self._sealed = True

    def get(self, handle: int) -> bytes:
        if handle < 0 or handle >= len(self._offsets):
            raise KeyError(handle)
        start = self._offsets[handle]
        stop = self._offsets[handle + 1] if handle + 1 < len(self._offsets) else len(self._data)
        return self._data[start:stop]

    def estimated_bytes(self) -> int:
        return sys.getsizeof(self) + sys.getsizeof(self._data) + sys.getsizeof(self._offsets)


class _PackedDigestGroupIndex:
    """Exact equality routes with packed singleton locators and promoted skew links.

    The hot route retains only a 64-bit digest and a 32-bit locator. Every hit is
    collision-checked against the canonical row. The sparse collision map is
    allocated only if two different exact keys share the same digest.
    """

    __slots__ = (
        "_bucket_counts",
        "_bucket_heads",
        "_bucket_tails",
        "_collisions",
        "_count",
        "_digests",
        "_group_keys",
        "_locators",
        "_max_bucket_size",
        "_next",
    )

    def __init__(self) -> None:
        self._digests = array("Q", [_PACKED_INDEX_EMPTY_DIGEST]) * 8
        self._locators = array("I", [0]) * 8
        self._count = 0
        self._bucket_heads = array("I")
        self._bucket_tails = array("I")
        self._bucket_counts = array("I")
        self._next = array("I")
        self._group_keys: dict[int, bytes] = {}
        self._collisions: dict[bytes, int] | None = None
        self._max_bucket_size = 0

    def __len__(self) -> int:
        return self._count + (0 if self._collisions is None else len(self._collisions))

    @staticmethod
    def _representative(locator: int, bucket_heads: array[int]) -> int:
        if locator & _PACKED_INDEX_BUCKET_TAG:
            return bucket_heads[locator & ~_PACKED_INDEX_BUCKET_TAG]
        return locator - 1

    def _find_slot(self, digest: int) -> tuple[int, bool]:
        position = digest & (len(self._digests) - 1)
        while True:
            retained = self._digests[position]
            if retained == _PACKED_INDEX_EMPTY_DIGEST:
                return position, False
            if retained == digest:
                return position, True
            position = (position + 1) & (len(self._digests) - 1)

    def _resize(self) -> None:
        prior_digests = self._digests
        prior_locators = self._locators
        self._digests = array("Q", [_PACKED_INDEX_EMPTY_DIGEST]) * (len(prior_digests) * 2)
        self._locators = array("I", [0]) * len(self._digests)
        for position, digest in enumerate(prior_digests):
            if digest == _PACKED_INDEX_EMPTY_DIGEST:
                continue
            target, _found = self._find_slot(digest)
            self._digests[target] = digest
            self._locators[target] = prior_locators[position]

    def _ensure_next(self, handle: int) -> None:
        missing = handle + 1 - len(self._next)
        if missing > 0:
            self._next.extend(array("I", [_PACKED_INDEX_EMPTY_HANDLE]) * missing)

    def _promote(self, first: int, second: int) -> int:
        bucket_id = len(self._bucket_heads)
        if bucket_id >= _PACKED_INDEX_BUCKET_TAG:
            raise StateError("packed immutable index exhausted promoted bucket IDs")
        self._ensure_next(max(first, second))
        self._next[first] = second
        self._next[second] = _PACKED_INDEX_EMPTY_HANDLE
        self._bucket_heads.append(first)
        self._bucket_tails.append(second)
        self._bucket_counts.append(2)
        self._max_bucket_size = max(self._max_bucket_size, 2)
        return _PACKED_INDEX_BUCKET_TAG | bucket_id

    def _append(self, locator: int, handle: int) -> int:
        if not locator & _PACKED_INDEX_BUCKET_TAG:
            return self._promote(locator - 1, handle)
        bucket_id = locator & ~_PACKED_INDEX_BUCKET_TAG
        tail = self._bucket_tails[bucket_id]
        self._ensure_next(handle)
        self._next[tail] = handle
        self._next[handle] = _PACKED_INDEX_EMPTY_HANDLE
        self._bucket_tails[bucket_id] = handle
        self._bucket_counts[bucket_id] += 1
        self._max_bucket_size = max(self._max_bucket_size, self._bucket_counts[bucket_id])
        return locator

    def add(
        self,
        key: bytes,
        handle: int,
        key_at: Callable[[int], bytes],
    ) -> None:
        if handle >= _PACKED_INDEX_BUCKET_TAG:
            raise StateError("packed immutable index exceeded 31-bit handle capacity")
        digest = _packed_index_digest(key)
        position, found = self._find_slot(digest)
        if not found and (self._count + 1) * 4 > len(self._digests) * 3:
            self._resize()
            position, found = self._find_slot(digest)
        if not found:
            self._digests[position] = digest
            self._locators[position] = handle + 1
            self._count += 1
            self._max_bucket_size = max(self._max_bucket_size, 1)
            return
        locator = self._locators[position]
        representative = self._representative(locator, self._bucket_heads)
        canonical_group_key = self._group_keys.get(digest)
        if canonical_group_key is None:
            canonical_group_key = key_at(representative)
        if canonical_group_key == key:
            self._group_keys[digest] = key
            self._locators[position] = self._append(locator, handle)
            return
        collisions = self._collisions
        if collisions is None:
            collisions = {}
            self._collisions = collisions
        collision_locator = collisions.get(key)
        if collision_locator is None:
            collisions[key] = handle + 1
            self._max_bucket_size = max(self._max_bucket_size, 1)
        else:
            collisions[key] = self._append(collision_locator, handle)

    def _locator(
        self,
        key: bytes,
        key_at: Callable[[int], bytes],
    ) -> int | None:
        position, found = self._find_slot(_packed_index_digest(key))
        if not found:
            return None
        locator = self._locators[position]
        representative = self._representative(locator, self._bucket_heads)
        canonical_group_key = self._group_keys.get(_packed_index_digest(key))
        if canonical_group_key is None:
            canonical_group_key = key_at(representative)
        if canonical_group_key == key:
            return locator
        return None if self._collisions is None else self._collisions.get(key)

    def iter_handles(
        self,
        key: bytes,
        key_at: Callable[[int], bytes],
    ) -> Iterator[int]:
        locator = self._locator(key, key_at)
        if locator is None:
            return
        if not locator & _PACKED_INDEX_BUCKET_TAG:
            yield locator - 1
            return
        bucket_id = locator & ~_PACKED_INDEX_BUCKET_TAG
        handle = self._bucket_heads[bucket_id]
        while handle != _PACKED_INDEX_EMPTY_HANDLE:
            yield handle
            handle = self._next[handle]

    def count(self, key: bytes, key_at: Callable[[int], bytes]) -> int:
        locator = self._locator(key, key_at)
        if locator is None:
            return 0
        if not locator & _PACKED_INDEX_BUCKET_TAG:
            return 1
        return self._bucket_counts[locator & ~_PACKED_INDEX_BUCKET_TAG]

    def page(
        self,
        key: bytes,
        key_at: Callable[[int], bytes],
        *,
        after_handle: int | None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        handles = self.iter_handles(key, key_at)
        found_cursor = after_handle is None
        page: list[int] = []
        for handle in handles:
            if not found_cursor:
                found_cursor = handle == after_handle
                continue
            page.append(handle)
            if len(page) > limit:
                return tuple(page[:limit]), page[limit - 1]
        if not found_cursor:
            raise KeyError(after_handle)
        return tuple(page), None

    @property
    def max_bucket_size(self) -> int:
        return self._max_bucket_size

    def estimated_bytes(self) -> int:
        retained = sum(
            sys.getsizeof(value)
            for value in (
                self,
                self._digests,
                self._locators,
                self._bucket_heads,
                self._bucket_tails,
                self._bucket_counts,
                self._next,
                self._group_keys,
                self._collisions,
            )
        )
        if self._collisions:
            retained += sum(
                sys.getsizeof(key) + sys.getsizeof(locator)
                for key, locator in self._collisions.items()
            )
        retained += sum(
            sys.getsizeof(digest) + sys.getsizeof(key) for digest, key in self._group_keys.items()
        )
        return retained


class _PackedFrozenIndexedStore(Generic[K, V]):
    """Immutable value rows with exact packed primary and secondary routes."""

    __slots__ = (
        "_compat_values",
        "_decoded_cache",
        "_decoded_cache_capacity",
        "_high_water_mark",
        "_indexers",
        "_indexes",
        "_preserve_identity_limit",
        "_pack",
        "_primary",
        "_primary_key",
        "_preserve_identity",
        "_rows",
        "_unpack",
    )

    def __init__(
        self,
        *,
        pack: Callable[[V], bytes],
        unpack: Callable[[bytes], V],
        primary_key: Callable[[V], K],
        preserve_identity: bool = False,
        preserve_identity_limit: int | None = _PACKED_IDENTITY_COMPAT_LIMIT,
        decoded_cache_capacity: int = 1_024,
        **indexers: Callable[[V], Hashable],
    ) -> None:
        self._pack = pack
        self._unpack = unpack
        self._primary_key = primary_key
        self._preserve_identity = preserve_identity
        if preserve_identity_limit is not None and (
            type(preserve_identity_limit) is not int or preserve_identity_limit < 0
        ):
            raise ValueError("preserve_identity_limit must be a non-negative exact int or None")
        self._preserve_identity_limit = preserve_identity_limit
        self._decoded_cache_capacity = decoded_cache_capacity
        self._decoded_cache: dict[int, V] = {}
        self._indexers = indexers
        self._rows = _PackedAppendRows()
        self._compat_values: list[V] | None = [] if preserve_identity else None
        self._primary = _PackedDigestGroupIndex()
        self._indexes = {name: _PackedDigestGroupIndex() for name in indexers}
        self._high_water_mark = 0

    def __len__(self) -> int:
        return len(self._rows)

    def __iter__(self) -> Iterator[K]:
        for handle in range(len(self)):
            yield self._primary_key(self.get_by_handle(handle))

    def _primary_key_at(self, handle: int) -> bytes:
        return _packed_index_key(self._primary_key(self.get_by_handle(handle)))

    def _index_key_at(self, index_name: str, handle: int) -> bytes:
        return _packed_index_key(self._indexers[index_name](self.get_by_handle(handle)))

    def __contains__(self, key: object) -> bool:
        try:
            self.handle_for(cast(K, key))
        except (KeyError, TypeError, ValueError):
            return False
        return True

    def __getitem__(self, key: K) -> V:
        return self.get_by_handle(self.handle_for(key))

    def __setitem__(self, key: K, value: V) -> None:
        if key in self:
            raise ValueError(f"duplicate packed immutable canonical key: {key!r}")
        handle = self._rows.append(self._pack(value))
        compatibility_values = self._compat_values
        if compatibility_values is not None:
            compatibility_values.append(value)
        canonical_key = _packed_index_key(key)
        self._primary.add(canonical_key, handle, self._primary_key_at)
        for name, extractor in self._indexers.items():
            indexed_key = _packed_index_key(extractor(value))
            self._indexes[name].add(
                indexed_key,
                handle,
                lambda candidate, index_name=name: self._index_key_at(index_name, candidate),
            )
        self._high_water_mark = max(self._high_water_mark, len(self))

    def seal(self) -> None:
        self._rows.seal()
        self._decoded_cache.clear()
        self._decoded_cache_capacity = 0
        if not self._preserve_identity or (
            self._preserve_identity_limit is not None and len(self) > self._preserve_identity_limit
        ):
            self._compat_values = None

    def get(self, key: K, default: V | None = None) -> V | None:
        try:
            return self[key]
        except KeyError:
            return default

    def handle_for(self, key: K) -> int:
        encoded = _packed_index_key(key)
        return self._handle_for_encoded(encoded)

    def _handle_for_encoded(self, encoded: bytes) -> int:
        handle = next(self._primary.iter_handles(encoded, self._primary_key_at), None)
        if handle is None:
            raise KeyError(encoded)
        return handle

    def get_by_handle(self, handle: int) -> V:
        compatibility_values = self._compat_values
        if compatibility_values is not None:
            if handle < 0 or handle >= len(compatibility_values):
                raise KeyError(handle)
            return compatibility_values[handle]
        cached = self._decoded_cache.get(handle)
        if cached is not None:
            return cached
        value = self._unpack(self._rows.get(handle))
        if self._decoded_cache_capacity:
            if len(self._decoded_cache) >= self._decoded_cache_capacity:
                del self._decoded_cache[next(iter(self._decoded_cache))]
            self._decoded_cache[handle] = value
        return value

    def _index(self, index_name: str) -> _PackedDigestGroupIndex:
        try:
            return self._indexes[index_name]
        except KeyError:
            raise KeyError(f"unknown packed immutable index {index_name!r}") from None

    def _index_handles(self, index_name: str, indexed_value: Hashable) -> Iterator[int]:
        index = self._index(index_name)
        encoded = _packed_index_key(indexed_value)
        yield from index.iter_handles(
            encoded,
            lambda handle: self._index_key_at(index_name, handle),
        )

    def find_iter(self, index_name: str, indexed_value: Hashable) -> Iterator[V]:
        for handle in self._index_handles(index_name, indexed_value):
            yield self.get_by_handle(handle)

    def find_one(self, index_name: str, indexed_value: Hashable) -> V | None:
        return next(self.find_iter(index_name, indexed_value), None)

    def count(self, index_name: str, indexed_value: Hashable) -> int:
        index = self._index(index_name)
        encoded = _packed_index_key(indexed_value)
        return index.count(encoded, lambda handle: self._index_key_at(index_name, handle))

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        if limit <= 0:
            raise ValueError("packed immutable page limit must be positive")
        index = self._index(index_name)
        encoded = _packed_index_key(indexed_value)
        return index.page(
            encoded,
            lambda handle: self._index_key_at(index_name, handle),
            after_handle=after_handle,
            limit=limit,
        )

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        retained_identity_entries = self.retained_identity_entries
        index_bytes = self._primary.estimated_bytes() + sum(
            index.estimated_bytes() for index in self._indexes.values()
        )
        return IndexMetrics(
            live_entries=len(self),
            backing_entries=len(self) + retained_identity_entries,
            allocated_slots=len(self) + retained_identity_entries,
            secondary_buckets=sum(len(index) for index in self._indexes.values()),
            max_bucket_size=max(
                (index.max_bucket_size for index in self._indexes.values()),
                default=0,
            ),
            high_water_mark=self._high_water_mark + retained_identity_entries,
            estimated_bytes=(
                sys.getsizeof(self)
                + self._rows.estimated_bytes()
                + index_bytes
                + sys.getsizeof(self._indexes)
                + _owned_graph_size(self._decoded_cache)
                + (0 if self._compat_values is None else _owned_graph_size(self._compat_values))
                if estimate_bytes
                else 0
            ),
            primary_map_entries=len(self._primary),
            primary_map_backing_bytes=self._primary.estimated_bytes(),
        )

    @property
    def retained_identity_entries(self) -> int:
        """Return owner snapshots retained in addition to canonical packed rows."""

        return 0 if self._compat_values is None else len(self._compat_values)

    def estimated_bytes(self) -> int:
        return self.metrics(estimate_bytes=True).estimated_bytes

    def estimated_index_bytes(self) -> int:
        """Return packed primary/secondary route backing, excluding canonical rows."""

        return (
            sys.getsizeof(self)
            + sys.getsizeof(self._indexes)
            + self._primary.estimated_bytes()
            + sum(index.estimated_bytes() for index in self._indexes.values())
        )


_EMPTY_INSTALLATION_HANDLE = (1 << 32) - 1


class _PackedInstallationStore:
    """Dense immutable-installation columns with on-demand frozen reconstruction."""

    __slots__ = (
        "_applications",
        "_host_first",
        "_host_interner",
        "_host_overflow",
        "_host_second",
        "_hosts",
        "_id_handles",
        "_image_path_ordinals",
        "_image_paths",
        "_image_paths_by_value",
        "_max_host_bucket_size",
        "_platforms",
        "_product_ordinals",
        "_principals",
        "_profile_ordinals",
        "_releases",
        "_root_ordinals",
        "_scope_codes",
        "_slot_ordinals",
        "_string_ordinals",
        "_strings",
    )

    def __init__(self, host_interner: _PlatformStringInterner) -> None:
        self._host_interner = host_interner
        self._id_handles: dict[int, int] = {}
        self._strings: list[str] = []
        self._string_ordinals: dict[str, int] = {}
        self._image_paths: list[tuple[str, ...]] = []
        self._image_paths_by_value: dict[tuple[str, ...], int] = {}
        self._max_host_bucket_size = 0
        self._hosts = array("I")
        self._applications = array("I")
        self._releases = array("I")
        self._product_ordinals = array("I")
        self._principals = array("I")
        self._profile_ordinals = array("I")
        self._slot_ordinals = array("I")
        self._root_ordinals = array("I")
        self._image_path_ordinals = array("I")
        self._platforms = array("B")
        self._scope_codes = array("B")
        self._host_first = array("I", [_EMPTY_INSTALLATION_HANDLE])
        self._host_second = array("I", [_EMPTY_INSTALLATION_HANDLE])
        self._host_overflow: dict[int, array[int]] = {}

    @staticmethod
    def _id_key(installation_id: str) -> int | None:
        prefix = "installation-"
        if not installation_id.startswith(prefix):
            return None
        digest = installation_id[len(prefix) :]
        if len(digest) != 32:
            return None
        try:
            return int(digest, 16)
        except ValueError:
            return None

    def _intern_string(self, value: str) -> int:
        ordinal = self._string_ordinals.get(value)
        if ordinal is not None:
            return ordinal
        ordinal = len(self._strings)
        self._strings.append(value)
        self._string_ordinals[value] = ordinal
        return ordinal

    def _intern_image_paths(self, value: tuple[str, ...]) -> int:
        ordinal = self._image_paths_by_value.get(value)
        if ordinal is not None:
            return ordinal
        ordinal = len(self._image_paths)
        self._image_paths.append(value)
        self._image_paths_by_value[value] = ordinal
        return ordinal

    def add(self, value: SoftwareInstallationIdentity, product_id: str) -> int:
        """Append one normalized installation and return its dense handle."""

        id_key = self._id_key(value.installation_id)
        if id_key is None:  # pragma: no cover - identity constructor guarantees this
            raise ValueError("installation_id is not canonical")
        if id_key in self._id_handles:
            raise ValueError(
                f"duplicate software installation canonical key: {value.canonical_key!r}"
            )
        handle = len(self._hosts)
        if handle >= _EMPTY_INSTALLATION_HANDLE:
            raise StateError("installation store exceeded its 32-bit handle capacity")
        host_handle = self._host_interner.intern(value.platform, value.hostname)
        while len(self._host_first) <= host_handle:
            self._host_first.append(_EMPTY_INSTALLATION_HANDLE)
            self._host_second.append(_EMPTY_INSTALLATION_HANDLE)
        first = self._host_first[host_handle]
        if first == _EMPTY_INSTALLATION_HANDLE:
            self._host_first[host_handle] = handle
            self._max_host_bucket_size = max(self._max_host_bucket_size, 1)
        elif self._host_second[host_handle] == _EMPTY_INSTALLATION_HANDLE:
            self._host_second[host_handle] = handle
            self._max_host_bucket_size = max(self._max_host_bucket_size, 2)
        else:
            bucket = self._host_overflow.get(host_handle)
            if bucket is None:
                bucket = array("I", (first, self._host_second[host_handle]))
                self._host_overflow[host_handle] = bucket
            bucket.append(handle)
            self._max_host_bucket_size = max(self._max_host_bucket_size, len(bucket))

        self._id_handles[id_key] = handle
        self._hosts.append(host_handle)
        self._applications.append(self._intern_string(value.application_id))
        self._releases.append(self._intern_string(value.release_id))
        self._product_ordinals.append(self._intern_string(product_id))
        self._principals.append(self._intern_string(value.principal))
        self._profile_ordinals.append(self._intern_string(value.user_profile_id))
        self._slot_ordinals.append(self._intern_string(value.installation_slot))
        self._root_ordinals.append(self._intern_string(value.install_root))
        self._image_path_ordinals.append(self._intern_image_paths(value.image_paths))
        self._platforms.append(("windows", "linux", "macos").index(value.platform))
        self._scope_codes.append(int(value.scope == "user"))
        return handle

    def __len__(self) -> int:
        return len(self._hosts)

    def __contains__(self, canonical_key: InstallationCanonicalKey) -> bool:
        installation_id = _stable_semantic_id(
            "installation",
            "software-installation",
            canonical_key,
        )
        id_key = self._id_key(installation_id)
        return id_key is not None and id_key in self._id_handles

    def handle_for(self, canonical_key: InstallationCanonicalKey) -> int:
        installation_id = _stable_semantic_id(
            "installation",
            "software-installation",
            canonical_key,
        )
        id_key = self._id_key(installation_id)
        if id_key is None or id_key not in self._id_handles:
            raise KeyError(canonical_key)
        return self._id_handles[id_key]

    def get_by_handle(self, handle: int) -> SoftwareInstallationIdentity:
        if handle < 0 or handle >= len(self):
            raise KeyError(handle)
        identity = object.__new__(SoftwareInstallationIdentity)
        platform = ("windows", "linux", "macos")[self._platforms[handle]]
        object.__setattr__(identity, "hostname", self._host_interner.value(self._hosts[handle]))
        object.__setattr__(identity, "application_id", self._strings[self._applications[handle]])
        object.__setattr__(identity, "release_id", self._strings[self._releases[handle]])
        object.__setattr__(identity, "platform", platform)
        object.__setattr__(identity, "scope", "user" if self._scope_codes[handle] else "machine")
        object.__setattr__(identity, "principal", self._strings[self._principals[handle]])
        object.__setattr__(
            identity,
            "user_profile_id",
            self._strings[self._profile_ordinals[handle]],
        )
        object.__setattr__(
            identity,
            "installation_slot",
            self._strings[self._slot_ordinals[handle]],
        )
        object.__setattr__(identity, "install_root", self._strings[self._root_ordinals[handle]])
        object.__setattr__(
            identity,
            "image_paths",
            self._image_paths[self._image_path_ordinals[handle]],
        )
        object.__setattr__(
            identity,
            "installation_id",
            _stable_semantic_id("installation", "software-installation", identity.canonical_key),
        )
        return identity

    def get(self, canonical_key: InstallationCanonicalKey) -> SoftwareInstallationIdentity | None:
        try:
            return self.get_by_handle(self.handle_for(canonical_key))
        except KeyError:
            return None

    def product_id_by_handle(self, handle: int) -> str:
        """Return the exact product identity without reconstructing an installation."""

        if handle < 0 or handle >= len(self):
            raise KeyError(handle)
        return self._strings[self._product_ordinals[handle]]

    def _host_handles(self, host_handle: int) -> Iterator[int]:
        if host_handle >= len(self._host_first):
            return
        overflow = self._host_overflow.get(host_handle)
        if overflow is not None:
            yield from overflow
            return
        first = self._host_first[host_handle]
        if first != _EMPTY_INSTALLATION_HANDLE:
            yield first
        second = self._host_second[host_handle]
        if second != _EMPTY_INSTALLATION_HANDLE:
            yield second

    def _handles_for_hostname(self, hostname: str) -> Iterator[int]:
        for platform in ("windows", "linux", "macos"):
            host_handle = self._host_interner.find(platform, hostname)
            if host_handle is not None:
                yield from self._host_handles(host_handle)

    def _iter_handles(self, index_name: str, indexed_value: Hashable) -> Iterator[int]:
        if index_name == "installation_id":
            id_key = self._id_key(str(indexed_value))
            handle = None if id_key is None else self._id_handles.get(id_key)
            if handle is not None:
                yield handle
            return
        if index_name == "host":
            yield from self._handles_for_hostname(str(indexed_value))
            return
        if index_name == "audience":
            hostname, platform, principal = cast(tuple[str, Platform, str], indexed_value)
            host_handle = self._host_interner.find(platform, hostname)
            handles: Iterator[int] = (
                iter(()) if host_handle is None else self._host_handles(host_handle)
            )
            for handle in handles:
                if self._strings[self._principals[handle]] == principal:
                    yield handle
            return
        hostname, expected = cast(tuple[str, str], indexed_value)
        handles = self._handles_for_hostname(hostname)
        ordinals = {
            "host_application": self._applications,
            "host_product": self._product_ordinals,
            "host_release": self._releases,
        }.get(index_name)
        if ordinals is None:
            raise KeyError(index_name)
        for handle in handles:
            if self._strings[ordinals[handle]] == expected:
                yield handle

    def find_iter(
        self,
        index_name: str,
        indexed_value: Hashable,
    ) -> Iterator[SoftwareInstallationIdentity]:
        for handle in self._iter_handles(index_name, indexed_value):
            yield self.get_by_handle(handle)

    def find_one(
        self,
        index_name: str,
        indexed_value: Hashable,
    ) -> SoftwareInstallationIdentity | None:
        return next(self.find_iter(index_name, indexed_value), None)

    def count(self, index_name: str, indexed_value: Hashable) -> int:
        return sum(1 for _handle in self._iter_handles(index_name, indexed_value))

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        if limit <= 0:
            raise ValueError("packed installation page limit must be positive")
        page: list[int] = []
        found_cursor = after_handle is None
        iterator = self._iter_handles(index_name, indexed_value)
        for handle in iterator:
            if not found_cursor:
                found_cursor = handle == after_handle
                continue
            page.append(handle)
            if len(page) > limit:
                return tuple(page[:limit]), page[limit - 1]
        if not found_cursor:
            raise KeyError(after_handle)
        return tuple(page), None

    def estimated_index_bytes(self) -> int:
        """Return retained exact-route/interner bytes, excluding packed row values."""

        return (
            sys.getsizeof(self._id_handles)
            + sum(
                sys.getsizeof(key) + sys.getsizeof(handle)
                for key, handle in self._id_handles.items()
            )
            + sys.getsizeof(self._string_ordinals)
            + sum(sys.getsizeof(ordinal) for ordinal in self._string_ordinals.values())
            + sys.getsizeof(self._image_paths_by_value)
            + sum(sys.getsizeof(ordinal) for ordinal in self._image_paths_by_value.values())
            + sys.getsizeof(self._host_first)
            + sys.getsizeof(self._host_second)
            + sys.getsizeof(self._host_overflow)
            + sum(
                sys.getsizeof(host_handle) + sys.getsizeof(bucket)
                for host_handle, bucket in self._host_overflow.items()
            )
        )

    def estimated_bytes(self) -> int:
        """Return packed installation rows plus exact route backing once."""

        return (
            sys.getsizeof(self)
            + self.estimated_index_bytes()
            + sum(
                sys.getsizeof(value)
                for value in (
                    self._strings,
                    self._image_paths,
                    self._hosts,
                    self._applications,
                    self._releases,
                    self._product_ordinals,
                    self._principals,
                    self._profile_ordinals,
                    self._slot_ordinals,
                    self._root_ordinals,
                    self._image_path_ordinals,
                    self._platforms,
                    self._scope_codes,
                )
            )
            + sum(sys.getsizeof(value) for value in self._strings)
            + sum(
                sys.getsizeof(paths) + sum(sys.getsizeof(path) for path in paths)
                for paths in self._image_paths
            )
        )

    @property
    def max_host_bucket_size(self) -> int:
        """Return the largest exact host installation bucket in constant time."""

        return self._max_host_bucket_size


def _unique_handles(values: tuple[int, ...], field_name: str) -> tuple[int, ...]:
    if any(value < 0 for value in values):
        raise ValueError(f"{field_name} cannot contain negative handles")
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} contains duplicate handles")
    return values


@dataclass(frozen=True, slots=True)
class HostDeploymentSpec:
    """Semantic input used to compile one immutable host deployment."""

    hostname: str
    roles: tuple[str, ...]
    platform: Platform
    os_build: str
    architecture: Architecture
    installation_ids: tuple[str, ...] = ()
    service_ids: tuple[str, ...] = ()
    task_ids: tuple[str, ...] = ()
    module_content_ids: tuple[str, ...] = ()
    deployment_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Normalize set-like fields and derive an order-independent deployment ID."""

        object.__setattr__(self, "hostname", _normalize_hostname(self.hostname))
        object.__setattr__(self, "roles", _normalized_unique_names(self.roles, "roles"))
        object.__setattr__(self, "platform", _normalize_platform(self.platform))
        object.__setattr__(self, "os_build", _normalize_name(self.os_build, "os_build"))
        object.__setattr__(
            self,
            "architecture",
            _normalize_architecture(self.architecture),
        )
        for field_name in (
            "installation_ids",
            "service_ids",
            "task_ids",
            "module_content_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalized_unique_ids(tuple(getattr(self, field_name)), field_name),
            )
        semantic_key: tuple[object, ...] = (
            self.hostname,
            self.roles,
            self.platform,
            self.os_build,
            self.architecture,
            tuple(sorted(self.installation_ids)),
            tuple(sorted(self.service_ids)),
            tuple(sorted(self.task_ids)),
            tuple(sorted(self.module_content_ids)),
        )
        object.__setattr__(
            self,
            "deployment_id",
            _stable_semantic_id("host-deployment", "host-deployment", semantic_key),
        )


@dataclass(frozen=True, slots=True)
class HostDeployment:
    """Compiled host capability state containing compact registry handles only."""

    deployment_id: str
    hostname: str
    roles: tuple[str, ...]
    platform: Platform
    os_build: str
    architecture: Architecture
    installation_handles: tuple[int, ...] = ()
    service_handles: tuple[int, ...] = ()
    task_handles: tuple[int, ...] = ()
    module_handles: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed compiled deployments and duplicate capabilities."""

        object.__setattr__(
            self, "deployment_id", _normalize_name(self.deployment_id, "deployment_id")
        )
        object.__setattr__(self, "hostname", _normalize_hostname(self.hostname))
        object.__setattr__(self, "roles", _normalized_unique_names(self.roles, "roles"))
        object.__setattr__(self, "platform", _normalize_platform(self.platform))
        object.__setattr__(self, "os_build", _normalize_name(self.os_build, "os_build"))
        object.__setattr__(self, "architecture", _normalize_architecture(self.architecture))
        for field_name in (
            "installation_handles",
            "service_handles",
            "task_handles",
            "module_handles",
        ):
            object.__setattr__(
                self,
                field_name,
                _unique_handles(tuple(getattr(self, field_name)), field_name),
            )


@dataclass(frozen=True, slots=True)
class UserApplicationAssignmentSpec:
    """Semantic persona/application intersection compiled for one user profile."""

    hostname: str
    principal: str
    platform: Platform
    user_profile_id: str
    application_profile_id: str
    persona: str
    eligible_categories: tuple[str, ...]
    intensity: float
    selection_weight: int | None = None
    selection_ordinal: int = 0
    assignment_id: str = field(init=False)

    def __post_init__(self) -> None:
        """Normalize the exact assignment and reject empty persona intersections."""

        platform = _normalize_platform(self.platform)
        intensity = float(self.intensity)
        if not math.isfinite(intensity) or intensity <= 0:
            raise ValueError("intensity must be a finite positive multiplier")
        selection_weight = (
            max(1, int(round(intensity * 10)))
            if self.selection_weight is None
            else int(self.selection_weight)
        )
        if selection_weight <= 0:
            raise ValueError("selection_weight must be positive")
        if type(self.selection_ordinal) is not int or self.selection_ordinal < 0:
            raise ValueError("selection_ordinal must be a non-negative exact int")
        object.__setattr__(self, "hostname", _normalize_hostname(self.hostname))
        object.__setattr__(self, "principal", _normalize_principal(self.principal, platform))
        if not self.principal:
            raise ValueError("principal must not be empty")
        object.__setattr__(self, "platform", platform)
        object.__setattr__(
            self,
            "user_profile_id",
            _normalize_name(self.user_profile_id, "user_profile_id"),
        )
        object.__setattr__(
            self,
            "application_profile_id",
            _normalize_name(self.application_profile_id, "application_profile_id"),
        )
        object.__setattr__(self, "persona", _normalize_name(self.persona, "persona", casefold=True))
        categories = _normalized_unique_names(self.eligible_categories, "eligible_categories")
        if not categories:
            raise ValueError("eligible_categories must describe a non-empty persona intersection")
        object.__setattr__(self, "eligible_categories", categories)
        object.__setattr__(self, "intensity", intensity)
        object.__setattr__(self, "selection_weight", selection_weight)
        semantic_key: tuple[object, ...] = (
            self.hostname,
            self.principal,
            self.platform,
            self.user_profile_id,
            self.application_profile_id,
            self.persona,
            self.eligible_categories,
            format(self.intensity, ".12g"),
            self.selection_weight,
        )
        object.__setattr__(
            self,
            "assignment_id",
            _stable_semantic_id("user-application", "user-application-assignment", semantic_key),
        )


@dataclass(frozen=True, slots=True)
class UserApplicationAssignment:
    """Compiled one-application intersection, never a copied host inventory."""

    assignment_id: str
    hostname: str
    principal: str
    materialization_principal: str
    platform: Platform
    user_profile_id: str
    application_profile_id: str
    application_id: str
    product_id: str
    release_id: str
    persona: str
    eligible_categories: tuple[str, ...]
    intensity: float
    host_deployment_handle: int
    user_profile_handle: int
    installation_handle: int
    application_profile_handle: int
    selection_weight: int = 10
    selection_ordinal: int = 0

    def __post_init__(self) -> None:
        """Validate the compact compiled assignment shape."""

        platform = _normalize_platform(self.platform)
        object.__setattr__(
            self, "assignment_id", _normalize_name(self.assignment_id, "assignment_id")
        )
        object.__setattr__(self, "hostname", _normalize_hostname(self.hostname))
        principal = _normalize_principal(self.principal, platform)
        materialization_principal = _normalize_name(
            self.materialization_principal,
            "materialization_principal",
        )
        if _normalize_principal(materialization_principal, platform) != principal:
            raise ValueError(
                "materialization_principal must identify the canonical assignment principal"
            )
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "materialization_principal", materialization_principal)
        object.__setattr__(self, "platform", platform)
        for field_name in (
            "user_profile_id",
            "application_profile_id",
            "application_id",
            "product_id",
            "release_id",
            "persona",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_name(
                    getattr(self, field_name),
                    field_name,
                    casefold=field_name in {"application_id", "product_id", "persona"},
                ),
            )
        categories = _normalized_unique_names(self.eligible_categories, "eligible_categories")
        if not categories:
            raise ValueError("eligible_categories must not be empty")
        object.__setattr__(self, "eligible_categories", categories)
        if not math.isfinite(self.intensity) or self.intensity <= 0:
            raise ValueError("intensity must be a finite positive multiplier")
        if self.selection_weight <= 0:
            raise ValueError("selection_weight must be positive")
        if type(self.selection_ordinal) is not int or self.selection_ordinal < 0:
            raise ValueError("selection_ordinal must be a non-negative exact int")
        for field_name in (
            "host_deployment_handle",
            "user_profile_handle",
            "installation_handle",
            "application_profile_handle",
        ):
            if getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} cannot be negative")


def _split_compiled_command_executable(
    command_line: str,
    platform: Platform,
) -> tuple[str, str]:
    """Parse the actual first executable token without an image fallback."""

    stripped = command_line.strip()
    if not stripped:
        raise ValueError("compiled application command template must not be empty")
    if platform == "windows" and stripped[0] == '"':
        closing_quote = stripped.find('"', 1)
        if closing_quote < 1:
            raise ValueError("compiled application command template has an unclosed quote")
        executable = stripped[1:closing_quote]
        tail = stripped[closing_quote + 1 :]
        if tail and not tail[0].isspace():
            raise ValueError("compiled application command executable quote must end its token")
        return executable, tail.lstrip()
    if platform == "windows":
        absolute = re.match(
            r"^([A-Za-z]:[\\/].*?\.(?:exe|cmd|bat|com))(?=\s|$)",
            stripped,
            flags=re.IGNORECASE,
        )
        if absolute is not None:
            return absolute.group(1), stripped[absolute.end() :].lstrip()
        parts = stripped.split(maxsplit=1)
        return parts[0], parts[1] if len(parts) == 2 else ""
    return _split_posix_command_executable(stripped)


def _split_posix_command_executable(command_line: str) -> tuple[str, str]:
    """Return the first POSIX shell word and its exact unconsumed remainder."""

    executable: list[str] = []
    quote = ""
    position = 0
    while position < len(command_line):
        character = command_line[position]
        if not quote:
            if character.isspace():
                break
            if character in {'"', "'"}:
                quote = character
            elif character == "\\":
                position += 1
                if position >= len(command_line):
                    raise ValueError("compiled application command template has invalid quoting")
                executable.append(command_line[position])
            else:
                executable.append(character)
        elif character == quote:
            quote = ""
        elif quote == '"' and character == "\\":
            position += 1
            if position >= len(command_line):
                raise ValueError("compiled application command template has invalid quoting")
            escaped = command_line[position]
            if escaped not in {"$", "`", '"', "\\", "\n"}:
                executable.append("\\")
            executable.append(escaped)
        else:
            executable.append(character)
        position += 1
    if quote:
        raise ValueError("compiled application command template has invalid quoting")
    if not executable:
        raise ValueError("compiled application command template must name an executable")
    return "".join(executable), command_line[position:].lstrip()


def _compiled_command_executables(
    command_line: str,
    platform: Platform,
    parameter_pools: dict[str, tuple[str, ...]],
    *,
    resolving: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Resolve every scoped first-token alternative for binary-parity validation."""

    candidates: list[str] = []
    for candidate in _iter_compiled_command_executables(
        command_line,
        platform,
        parameter_pools,
        resolving=resolving,
    ):
        if len(candidates) >= _MAX_COMPILED_COMMAND_EXECUTABLES:
            raise ValueError(
                "compiled application command executable alternatives exceed the bounded limit"
            )
        candidates.append(candidate)
    return tuple(candidates)


def _iter_compiled_command_executables(
    command_line: str,
    platform: Platform,
    parameter_pools: dict[str, tuple[str, ...]],
    *,
    resolving: tuple[str, ...],
) -> Iterator[str]:
    """Yield actual executable alternatives while the public helper enforces its bound."""

    executable, remainder = _split_compiled_command_executable(command_line, platform)
    placeholder = _APPLICATION_COMMAND_PLACEHOLDER.fullmatch(executable)
    if placeholder is not None:
        name = placeholder.group(1)
        values = parameter_pools.get(name)
        if not values:
            raise ValueError(
                "compiled application command executable placeholder "
                f"{executable!r} has no scoped parameter pool"
            )
        if name in resolving:  # pragma: no cover - descriptor cycle validation owns this
            raise ValueError("compiled application command executable placeholder is cyclic")
        for value in values:
            yield from _iter_compiled_command_executables(
                value,
                platform,
                parameter_pools,
                resolving=(*resolving, name),
            )
        return
    embedded_placeholders = {
        match.group(1) for match in _APPLICATION_COMMAND_PLACEHOLDER.finditer(executable)
    }
    if embedded_placeholders - {"username"}:
        raise ValueError(
            "compiled application command executable contains an unsupported embedded placeholder"
        )
    if platform == "windows" and _artifact_name(executable, platform) in {
        "cmd",
        "cmd.exe",
    }:
        wrapper = re.match(r"^/(?:c|k)(?:\s+|$)(.*)$", remainder, flags=re.IGNORECASE)
        if wrapper is None or not wrapper.group(1).strip():
            raise ValueError("compiled cmd.exe command template must name its wrapped executable")
        yield from _iter_compiled_command_executables(
            wrapper.group(1),
            platform,
            parameter_pools,
            resolving=resolving,
        )
        return
    yield executable


def _command_executable_matches(
    command_executable: str,
    declared_image: str,
    platform: Platform,
) -> bool:
    """Return whether an actual command executable denotes the declared image."""

    if platform != "windows" and "\\" in command_executable:
        return False
    command_drive, _command_tail = (
        ntpath.splitdrive(command_executable) if platform == "windows" else ("", "")
    )
    has_path = bool(command_drive) or any(
        separator in command_executable
        for separator in (("/", "\\") if platform == "windows" else ("/",))
    )
    if has_path:
        if platform == "windows":
            return canonical_native_path(command_executable, platform) == canonical_native_path(
                declared_image,
                platform,
            )
        return posixpath.normpath(command_executable) == posixpath.normpath(declared_image)
    command_name = _artifact_name(command_executable, platform)
    declared_name = _artifact_name(declared_image, platform)
    if command_name == declared_name:
        return True
    if platform != "windows":
        return False
    extensions = frozenset({".exe", ".cmd", ".bat", ".com"})
    _command_stem, command_extension = ntpath.splitext(command_name)
    declared_stem, declared_extension = ntpath.splitext(declared_name)
    if command_extension and command_extension not in extensions:
        return False
    if declared_extension and declared_extension not in extensions:
        return False
    if command_extension:
        return False
    return bool(declared_extension) and command_name == declared_stem


def _validate_application_command_expansion_bounds(
    command_templates: tuple[str, ...],
    parameter_pools: tuple[tuple[str, tuple[str, ...]], ...],
    *,
    literal_replacements: tuple[tuple[str, str], ...] = (),
) -> None:
    """Reject cyclic or explosively expanding scoped command parameters."""

    pools = dict(parameter_pools)
    pool_names = frozenset(pools)
    replacements = dict(literal_replacements)
    placeholder_count_cache: dict[str, tuple[tuple[str, int], ...]] = {}

    def placeholder_counts(value: str) -> tuple[tuple[str, int], ...]:
        cached = placeholder_count_cache.get(value)
        if cached is not None:
            return cached
        counts: dict[str, int] = {}
        for match in _APPLICATION_COMMAND_PLACEHOLDER.finditer(value):
            name = match.group(1)
            counts[name] = counts.get(name, 0) + 1
        result = tuple(sorted(counts.items()))
        placeholder_count_cache[value] = result
        return result

    dependencies = {
        name: {
            dependency
            for value in values
            for dependency, _count in placeholder_counts(value)
            if dependency in pool_names
        }
        for name, values in pools.items()
    }
    states: dict[str, int] = {}

    def visit(name: str, trail: tuple[str, ...]) -> None:
        state = states.get(name, 0)
        if state == 1:
            cycle_start = trail.index(name)
            cycle = (*trail[cycle_start:], name)
            raise ValueError("command_parameter_pools contains a cycle: " + " -> ".join(cycle))
        if state == 2:
            return
        states[name] = 1
        for dependency in sorted(dependencies[name]):
            visit(dependency, (*trail, name))
        states[name] = 2

    for name in sorted(pool_names):
        visit(name, ())

    expansion_costs: dict[str, int] = {}
    expanded_lengths: dict[str, int] = {}

    def text_expansion_cost(value: str) -> int:
        cost = 0
        for name, count in placeholder_counts(value):
            if name in replacements:
                cost += count
            elif name in pool_names:
                cost += count * pool_expansion_cost(name)
        return cost

    def pool_expansion_cost(name: str) -> int:
        cached = expansion_costs.get(name)
        if cached is not None:
            return cached
        cost = 1 + max((text_expansion_cost(value) for value in pools[name]), default=0)
        expansion_costs[name] = cost
        return cost

    def text_expanded_length(value: str) -> int:
        length = len(value)
        for name, count in placeholder_counts(value):
            placeholder = "{" + name + "}"
            replacement = replacements.get(name)
            if replacement is not None:
                length += count * (len(replacement) - len(placeholder))
            elif name in pool_names:
                length += count * (pool_expanded_length(name) - len(placeholder))
        return length

    def pool_expanded_length(name: str) -> int:
        cached = expanded_lengths.get(name)
        if cached is not None:
            return cached
        length = max((text_expanded_length(value) for value in pools[name]), default=0)
        expanded_lengths[name] = length
        return length

    for command_template in command_templates:
        expansions = text_expansion_cost(command_template)
        if expansions > _MAX_APPLICATION_COMMAND_EXPANSIONS:
            raise ValueError(
                "compiled application command expansion exceeds the bounded replacement limit"
            )
        if text_expanded_length(command_template) > _MAX_APPLICATION_COMMAND_LENGTH:
            raise ValueError(
                "compiled application command expansion exceeds the bounded output length"
            )


def _require_exact_application_descriptor_graph(
    *,
    application_id: object,
    platform: object,
    image_path: object,
    command_templates: object,
    categories: object,
    command_parameter_pools: object,
    singleton_per_session: object,
    selection_ordinal: object,
) -> None:
    """Reject callback-capable descriptor values before any virtual operation."""

    for field_name, value in (
        ("application_id", application_id),
        ("platform", platform),
        ("image_path", image_path),
    ):
        if type(value) is not str:
            raise ValueError(f"{field_name} must be an exact str")
    if type(command_templates) is not tuple:
        raise ValueError("command_templates must be an exact tuple")
    if len(command_templates) > _MAX_APPLICATION_COMMAND_TEMPLATES:
        raise ValueError("compiled application command_templates exceeds the bounded limit")
    if any(type(value) is not str for value in command_templates):
        raise ValueError("command_templates must contain exact str values")
    if type(categories) is not tuple:
        raise ValueError("categories must be an exact tuple")
    if len(categories) > _MAX_APPLICATION_DESCRIPTOR_CATEGORIES:
        raise ValueError("compiled application categories exceeds the bounded limit")
    if any(type(value) is not str for value in categories):
        raise ValueError("categories must contain exact str values")
    if type(command_parameter_pools) is not tuple:
        raise ValueError("command_parameter_pools must be an exact tuple")
    if len(command_parameter_pools) > _MAX_APPLICATION_COMMAND_PARAMETER_POOLS:
        raise ValueError("command_parameter_pools exceeds the bounded pool limit")
    parameter_value_count = 0
    for pool in command_parameter_pools:
        if type(pool) is not tuple or len(pool) != 2:
            raise ValueError("command_parameter_pools entries must be exact name/value tuples")
        name = pool[0]
        values = pool[1]
        if type(name) is not str:
            raise ValueError("command_parameter_pool names must be exact str values")
        if type(values) is not tuple:
            raise ValueError("command_parameter_pool values must be exact tuples")
        parameter_value_count += len(values)
        if parameter_value_count > _MAX_APPLICATION_COMMAND_PARAMETER_VALUES:
            raise ValueError("command_parameter_pools exceeds the bounded value limit")
        if any(type(value) is not str for value in values):
            raise ValueError("command_parameter_pool values must contain exact str values")
    if type(singleton_per_session) is not bool:
        raise ValueError("singleton_per_session must be an exact bool")
    if type(selection_ordinal) is not int or selection_ordinal < 0:
        raise ValueError("selection_ordinal must be a non-negative exact int")


@dataclass(frozen=True, slots=True)
class CompiledApplicationDescriptor:
    """Immutable runtime descriptor for one compiled application platform."""

    application_id: str
    platform: Platform
    image_path: str
    command_templates: tuple[str, ...]
    categories: tuple[str, ...]
    command_parameter_pools: tuple[tuple[str, tuple[str, ...]], ...] = ()
    singleton_per_session: bool = False
    selection_ordinal: int = 0
    executable: str = field(init=False)
    command_parameter_pool_names: tuple[str, ...] = field(init=False, repr=False)
    uses_username: bool = field(init=False, repr=False)
    retained_text_bytes: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize immutable command truth and reject incomplete descriptors."""

        _require_exact_application_descriptor_graph(
            application_id=self.application_id,
            platform=self.platform,
            image_path=self.image_path,
            command_templates=self.command_templates,
            categories=self.categories,
            command_parameter_pools=self.command_parameter_pools,
            singleton_per_session=self.singleton_per_session,
            selection_ordinal=self.selection_ordinal,
        )
        platform = _normalize_platform(self.platform)
        application_id = _normalize_name(
            self.application_id,
            "application_id",
            casefold=True,
        )
        image_path = _normalize_name(self.image_path, "image_path")
        if platform != "windows" and "\\" in image_path:
            raise ValueError("compiled POSIX application image_path cannot contain backslashes")
        image_placeholders = {
            match.group(1) for match in _APPLICATION_COMMAND_PLACEHOLDER.finditer(image_path)
        }
        if image_placeholders - {"username"}:
            raise ValueError("compiled application image_path may contain only {username}")
        image_basename = (
            ntpath.basename(image_path.replace("/", "\\"))
            if platform == "windows"
            else posixpath.basename(image_path)
        )
        if _APPLICATION_COMMAND_PLACEHOLDER.search(image_basename) is not None:
            raise ValueError(
                "compiled application image_path executable basename cannot contain {username}"
            )
        retained_text_bytes = len(application_id.encode("utf-8")) + len(image_path.encode("utf-8"))
        if retained_text_bytes > _MAX_APPLICATION_DESCRIPTOR_TEXT_BYTES:
            raise ValueError("compiled application descriptor exceeds its bounded text budget")

        def charge_text(value: str) -> None:
            nonlocal retained_text_bytes
            retained_text_bytes += len(value.encode("utf-8"))
            if retained_text_bytes > _MAX_APPLICATION_DESCRIPTOR_TEXT_BYTES:
                raise ValueError("compiled application descriptor exceeds its bounded text budget")

        normalized_templates: list[str] = []
        for raw_template in self.command_templates:
            if len(normalized_templates) >= _MAX_APPLICATION_COMMAND_TEMPLATES:
                raise ValueError("compiled application command_templates exceeds the bounded limit")
            template = _normalize_name(raw_template, "command_template")
            if len(template) > _MAX_APPLICATION_COMMAND_LENGTH:
                raise ValueError("compiled application command template exceeds the bounded length")
            charge_text(template)
            normalized_templates.append(template)
        command_templates = tuple(normalized_templates)
        if not command_templates:
            raise ValueError("compiled application command_templates must not be empty")
        normalized_categories: list[str] = []
        seen_categories: set[str] = set()
        for raw_category in self.categories:
            if len(normalized_categories) >= _MAX_APPLICATION_DESCRIPTOR_CATEGORIES:
                raise ValueError("compiled application categories exceeds the bounded limit")
            category = _normalize_name(raw_category, "categories", casefold=True)
            if category in seen_categories:
                raise ValueError("categories contains duplicate names")
            charge_text(category)
            normalized_categories.append(category)
            seen_categories.add(category)
        categories = tuple(sorted(normalized_categories))
        if not categories:
            raise ValueError("compiled application categories must not be empty")
        parameter_pools: list[tuple[str, tuple[str, ...]]] = []
        seen_pool_names: set[str] = set()
        parameter_value_count = 0
        for raw_name, raw_values in self.command_parameter_pools:
            if len(parameter_pools) >= _MAX_APPLICATION_COMMAND_PARAMETER_POOLS:
                raise ValueError("command_parameter_pools exceeds the bounded pool limit")
            name = _normalize_name(raw_name, "command_parameter_pool name")
            if _APPLICATION_COMMAND_PLACEHOLDER.fullmatch("{" + name + "}") is None:
                raise ValueError("command_parameter_pool names must match [A-Za-z_][A-Za-z0-9_]*")
            charge_text(name)
            if name == "username":
                raise ValueError("command_parameter_pools cannot redefine reserved name 'username'")
            if name in seen_pool_names:
                raise ValueError(f"command_parameter_pools contains duplicate name {name!r}")
            normalized_values: list[str] = []
            for raw_value in raw_values:
                parameter_value_count += 1
                if parameter_value_count > _MAX_APPLICATION_COMMAND_PARAMETER_VALUES:
                    raise ValueError("command_parameter_pools exceeds the bounded value limit")
                value = _normalize_name(raw_value, f"command_parameter_pools[{name!r}]")
                if len(value) > _MAX_APPLICATION_COMMAND_LENGTH:
                    raise ValueError(
                        "compiled application command expansion exceeds the bounded output length"
                    )
                charge_text(value)
                normalized_values.append(value)
            values = tuple(normalized_values)
            if not values:
                raise ValueError(f"command_parameter_pools[{name!r}] must not be empty")
            seen_pool_names.add(name)
            parameter_pools.append((name, values))
        if type(self.singleton_per_session) is not bool:
            raise ValueError("singleton_per_session must be an exact bool")
        if type(self.selection_ordinal) is not int or self.selection_ordinal < 0:
            raise ValueError("selection_ordinal must be a non-negative exact int")
        command_parameter_pools = tuple(sorted(parameter_pools, key=lambda item: item[0]))
        _validate_application_command_expansion_bounds(
            command_templates,
            command_parameter_pools,
        )
        parameter_pool_values = dict(command_parameter_pools)
        for command_template in command_templates:
            mismatched = next(
                (
                    executable
                    for executable in _compiled_command_executables(
                        command_template,
                        platform,
                        parameter_pool_values,
                    )
                    if not _command_executable_matches(
                        executable,
                        image_path,
                        platform,
                    )
                ),
                None,
            )
            if mismatched is not None:
                raise ValueError(
                    f"application {application_id!r} command template launches "
                    f"{mismatched!r}, not its declared image {image_path!r}"
                )
        object.__setattr__(self, "application_id", application_id)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "image_path", image_path)
        object.__setattr__(self, "command_templates", command_templates)
        object.__setattr__(self, "categories", categories)
        object.__setattr__(
            self,
            "command_parameter_pools",
            command_parameter_pools,
        )
        object.__setattr__(
            self,
            "command_parameter_pool_names",
            tuple(name for name, _values in command_parameter_pools),
        )
        object.__setattr__(
            self,
            "uses_username",
            "username" in image_placeholders
            or any(
                match.group(1) == "username"
                for value in (
                    *command_templates,
                    *(
                        pool_value
                        for _pool_name, pool_values in command_parameter_pools
                        for pool_value in pool_values
                    ),
                )
                for match in _APPLICATION_COMMAND_PLACEHOLDER.finditer(value)
            ),
        )
        object.__setattr__(self, "executable", _artifact_name(image_path, platform))
        object.__setattr__(self, "retained_text_bytes", retained_text_bytes)

    @property
    def canonical_key(self) -> tuple[str, Platform]:
        """Return the exact application/platform descriptor lookup key."""

        return self.application_id, self.platform

    def _command_parameter_values(self, name: str) -> tuple[str, ...] | None:
        """Return one exact scoped pool without copying or scanning pool values."""

        position = bisect_left(self.command_parameter_pool_names, name)
        if (
            position >= len(self.command_parameter_pool_names)
            or self.command_parameter_pool_names[position] != name
        ):
            return None
        return self.command_parameter_pools[position][1]


@dataclass(frozen=True, slots=True)
class DeploymentRegistryCensus:
    """Compact cardinality snapshot for the immutable registry."""

    binary_releases: int
    installed_software_releases: int
    installations: int
    user_profiles: int
    application_profiles: int
    application_descriptors: int
    application_executable_bindings: int
    file_versions: int
    local_artifact_versions: int
    binary_path_bindings: int
    local_artifact_path_bindings: int


@dataclass(frozen=True, slots=True)
class BinaryPathIndexCensus:
    """Structural cardinality and optional byte estimate for exact binary paths."""

    bindings: int
    interned_hosts: int
    interned_principals: int
    interned_native_paths: int
    packed_integer_keys: int
    packed_integer_targets: int
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class DeploymentCompilationCensus:
    """Cardinality snapshot for host deployment and assignment compilation."""

    host_deployments: int
    user_application_assignments: int
    interned_services: int
    interned_tasks: int
    assignment_category_buckets: int = 0
    assignment_category_links: int = 0
    browser_affinities: int = 0


@dataclass(frozen=True, slots=True)
class AssignmentCategoryIndexCensus:
    """Constant-time shape and optional retained-byte estimate for assignment routing."""

    buckets: int
    links: int
    max_bucket_size: int
    browser_affinities: int
    exact_selection_candidates: int
    lookup_candidates_inspected: int
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class DeploymentContentScaleCensus:
    """Public immutable deployment/content contribution to mixed scale gates.

    ``physical_records`` is the exact canonical-row denominator. It counts one
    retained row for every release, installation, profile, compiled application
    descriptor, file version, local artifact descriptor, host deployment, user
    assignment, service identity, and task identity. Owner-private application
    descriptor/assignment snapshots and relationship/index bindings are reported
    as backing separately and are never added to that denominator.
    """

    logical_records: int
    physical_records: int
    live_entries: int
    retained_entries: int
    backing_entries: int
    stale_entries: int
    leased_entries: int
    high_water_mark: int
    binary_releases: int
    installed_software_releases: int
    installations: int
    user_profiles: int
    application_profiles: int
    application_descriptors: int
    application_descriptor_owner_snapshots: int
    file_versions: int
    local_artifact_versions: int
    host_deployments: int
    user_application_assignments: int
    user_application_assignment_owner_snapshots: int
    service_identities: int
    task_identities: int
    binary_path_bindings: int
    local_artifact_path_bindings: int
    application_executable_bindings: int
    assignment_category_bindings: int
    host_installation_bindings: int
    host_service_bindings: int
    host_task_bindings: int
    host_module_bindings: int
    relationship_bindings: int
    maximum_bucket_size: int
    lookup_candidates_inspected: int
    estimated_bytes: int
    estimated_index_bytes: int


class DeploymentGroupPageCursor:
    """Opaque cursor for a bounded immutable deployment-registry group page."""

    __slots__ = (
        "_after_handle",
        "_group_name",
        "_queries",
        "_query_position",
        "_registry_token",
    )

    def __init__(
        self,
        *,
        registry_token: int,
        group_name: str,
        queries: tuple[tuple[str, Hashable], ...],
        query_position: int,
        after_handle: int | None,
    ) -> None:
        self._registry_token = registry_token
        self._group_name = group_name
        self._queries = queries
        self._query_position = query_position
        self._after_handle = after_handle


@dataclass(frozen=True, slots=True)
class LocalArtifactRegistryCensus:
    """Bounded local-artifact registry retention and index cardinalities.

    ``estimated_bytes`` is the total retained structural estimate: packed
    canonical artifact rows plus their primary/equality indexes, deadline and
    lease state, and sparse cross-shard routes.  ``estimated_index_bytes`` is a
    backward-compatible alias for that same total; historically this registry
    reported its packed row store together with indexes under the index label.
    The components are mutually exclusive in the sum, so route and row backing
    are not double counted.
    """

    live_versions: int
    backing_slots: int
    high_water_mark: int
    leased_versions: int
    active_leases: int
    pending_expiry: int
    prepared_publications: int
    claimed_publications: int
    reserved_slots: int
    capacity: int
    shards: int
    route_entries: int
    route_backing_bytes: int
    estimated_store_bytes: int
    estimated_deadline_bytes: int
    estimated_evictable_deadline_bytes: int
    estimated_lease_bytes: int
    estimated_prepared_bytes: int
    estimated_index_bytes: int
    estimated_bytes: int
    primary_map_entries: int
    primary_map_backing_bytes: int
    primary_compaction_pending: bool
    primary_compaction_rotations: int
    primary_compaction_work: int
    primary_compaction_seconds: float
    prepared_retained_members: int = 0
    prepared_member_capacity: int = 0
    prepared_retained_bytes: int = 0
    prepared_byte_capacity: int = 0
    prepared_capability_locators: int = 0
    committing_publications: int = 0


class LocalArtifactCapacityError(StateError):
    """A bounded artifact registry cannot admit another unleased version."""


class LocalArtifactVersionPageCursor:
    """Opaque registry- and mutation-fenced cursor for one artifact history query."""

    __slots__ = (
        "_after_handle",
        "_indexed_value",
        "_index_name",
        "_mutation_versions",
        "_registry_token",
        "_shard_id",
    )

    def __init__(
        self,
        *,
        registry_token: int,
        index_name: str,
        indexed_value: Hashable,
        mutation_versions: tuple[int, ...],
        shard_id: int,
        after_handle: int | None,
    ) -> None:
        self._registry_token = registry_token
        self._index_name = index_name
        self._indexed_value = indexed_value
        self._mutation_versions = mutation_versions
        self._shard_id = shard_id
        self._after_handle = after_handle


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LocalArtifactPublishToken:
    """Capacity- and identity-reserved local-artifact publication token.

    A token retains metadata but no file payload bytes. The registry retains a
    separately reconstructed canonical record so caller mutation cannot alter
    either commit truth or reservation cleanup.
    """

    record: LocalArtifactVersionRecord
    observed_at: datetime
    retained_until: datetime
    lease_owner: str = ""
    lease_until: datetime | None = None
    _registry_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _shard_id: int = field(repr=False, default=0)
    _existing_handle: int | None = field(repr=False, default=None)
    _integrity: str = field(repr=False, default="")

    @property
    def publication_token(self) -> str:
        """Return the opaque registry-authenticated publication proof."""

        return self._integrity


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LocalArtifactPublicationReceipt:
    """Authenticated proof binding one preparation to its committed handle."""

    reservation_id: int
    artifact_version_id: str
    shard_id: int
    handle: int
    publication_token: str
    record_digest: str
    _registry_token: int = field(repr=False, default=0)
    _integrity: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over this committed publication."""

        return self._integrity

    @property
    def packed_locator(self) -> int:
        """Return the stable shard-qualified committed store locator."""

        return _pack_artifact_locator(self.shard_id, self.handle)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LocalArtifactPublicationGroupReceipt:
    """Authenticated ordered proof for one all-or-zero artifact publication group."""

    receipts: tuple[LocalArtifactPublicationReceipt, ...]
    publication_tokens: tuple[str, ...]
    _registry_token: int = field(repr=False, default=0)
    _integrity: str = field(repr=False, default="")

    @property
    def group_token(self) -> str:
        """Return the opaque keyed proof over the ordered member receipts."""

        return self._integrity

    @property
    def handles(self) -> tuple[int, ...]:
        """Return committed packed handles in preparation order."""

        return tuple(receipt.handle for receipt in self.receipts)


@dataclass(slots=True)
class _LocalArtifactPreparedReservation:
    """Registry-owned locator and immutable preparation preimage."""

    token_ref: ReferenceType[LocalArtifactPublishToken]
    token_id: int
    reservation_id: int
    canonical_token: LocalArtifactPublishToken
    record_digest: str
    retained_bytes: int
    reserved_handle: int | None = None
    backing_released: bool = False
    claimed_by: int | None = None
    committing: bool = False
    commit_ref: (
        ReferenceType[LocalArtifactPreparedCommit | LocalArtifactPreparedGroupCommit] | None
    ) = None
    commit_id: int | None = None
    commit_plan: _LocalArtifactPreparedCommitPlan | None = None
    group_receipt: LocalArtifactPublicationGroupReceipt | None = None


@dataclass(slots=True)
class _LocalArtifactLeaseSavepoint:
    """Preallocated pair-local state used to undo one lease acquisition."""

    pair: tuple[str, str]
    pair_present: bool = False
    prior_deadline: float | None = None
    prior_item: bool | None = None
    prior_order: int | None = None
    prior_version: int | None = None
    prior_next_order: int = 0
    prior_high_water: int = 0
    prior_leased_key_count: int = 0
    prior_store_high_water: int = 0
    prior_store_primary_peak: int = 0
    prior_store_slots: int = 0


@dataclass(slots=True)
class _LocalArtifactPreparedRollbackSavepoint:
    """Preallocated rollback state populated at the first commit mutation."""

    lease: _LocalArtifactLeaseSavepoint | None = None
    captured: bool = False
    prior_deadline_us: int = _EMPTY_ARTIFACT_DEADLINE
    prior_pending_expiry: bool = False
    prior_mutation_version: int = 0
    prior_live_count: int = 0
    prior_high_water_mark: int = 0
    prior_store_next_handle: int = 0
    prior_store_high_water: int = 0
    prior_store_compaction_rotations: int = 0
    prior_store_compaction_work: int = 0
    prior_deadline_generation: int = 0
    prior_deadline_order: int = 0
    prior_deadline_live: int = 0
    prior_deadline_high_water: int = 0
    prior_deadline_order_counter: int = 0
    prior_route_high_water: int = 0


@dataclass(frozen=True, slots=True)
class _LocalArtifactPreparedCommitPlan:
    """Fully precomputed primitive tail and preallocated rollback state."""

    expected_handle: int
    packed_payload: bytes
    retained_deadline: float
    lease_deadline: float | None
    receipt: LocalArtifactPublicationReceipt
    prior_payload: bytes | None
    route: _ArtifactRouteShard | None
    route_key: bytes | None
    packed_route_locator: int | None
    rollback: _LocalArtifactPreparedRollbackSavepoint


class LocalArtifactPreparedCommit:
    """One rollback-capable artifact-first commit valid only in its context.

    Entering the owning context claims the reservation under the artifact
    registry locks, then releases every artifact lock before yielding this
    capability. A composite coordinator first claims and authenticates every
    owner, then invokes this artifact commit while State, lifecycle, audit,
    intent, and timing owners remain uncommitted. An artifact-tail exception
    restores exact local state so the other claimed contexts can cancel; only
    a successful artifact receipt permits their certified primitive commits.
    """

    __slots__ = (
        "_active",
        "_committed",
        "_claimant_thread_id",
        "_expected_receipt",
        "_handle",
        "_publication_token",
        "_receipt",
        "_registry",
        "__weakref__",
    )

    def __init__(
        self,
        registry: LocalArtifactVersionRegistry,
        publication_token: str | LocalArtifactPublishToken,
        claimant_thread_id: int | None = None,
        expected_receipt: LocalArtifactPublicationReceipt | None = None,
    ) -> None:
        self._registry = registry
        # Preserve the former public constructor shape without granting a
        # caller-built object authority: the registry's exact object locator is
        # still required by every commit. Registry claims pass frozen primitives.
        self._publication_token = (
            publication_token.publication_token
            if type(publication_token) is LocalArtifactPublishToken
            else publication_token
        )
        self._claimant_thread_id = get_ident() if claimant_thread_id is None else claimant_thread_id
        self._expected_receipt = expected_receipt
        self._active = True
        self._committed = False
        self._handle: int | None = None
        self._receipt: LocalArtifactPublicationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact prepared publication committed."""

        return self._committed

    @property
    def handle(self) -> int | None:
        """Return the committed packed handle, if any."""

        return self._handle

    @property
    def publication_token(self) -> str:
        """Return the frozen preparation proof claimed by this transaction."""

        return self._publication_token

    @property
    def receipt(self) -> LocalArtifactPublicationReceipt | None:
        """Return the authenticated committed receipt, if available."""

        return self._receipt

    @property
    def expected_receipt(self) -> LocalArtifactPublicationReceipt | None:
        """Return the precomputed authenticated receipt for this exact claim."""

        return self._expected_receipt

    def commit_no_fail(self) -> LocalArtifactPublicationReceipt:
        """Publish the artifact-first tail and return its authenticated receipt."""

        if not self._active:
            raise StateError("local artifact prepared commit is no longer active")
        if self._committed:
            raise StateError("local artifact prepared publication was already committed")
        if get_ident() != self._claimant_thread_id:
            raise StateError(
                "local artifact prepared publication must commit on its claiming thread"
            )
        self._receipt = self._registry._commit_claimed(self)
        self._handle = self._receipt.handle
        self._committed = True
        return self._receipt

    def commit(self) -> int:
        """Compatibility API returning the packed handle after a no-fail commit."""

        return self.commit_no_fail().handle

    def _close(self) -> None:
        self._active = False


class LocalArtifactPreparedGroupCommit:
    """Exact same-thread capability for one all-or-zero artifact publication group."""

    __slots__ = (
        "_active",
        "_claimant_thread_id",
        "_committed",
        "_expected_receipt",
        "_publication_tokens",
        "_receipt",
        "_registry",
        "__weakref__",
    )

    def __init__(
        self,
        registry: LocalArtifactVersionRegistry,
        publication_tokens: tuple[str, ...],
        claimant_thread_id: int,
        expected_receipt: LocalArtifactPublicationGroupReceipt,
    ) -> None:
        self._registry = registry
        self._publication_tokens = publication_tokens
        self._claimant_thread_id = claimant_thread_id
        self._expected_receipt = expected_receipt
        self._active = True
        self._committed = False
        self._receipt: LocalArtifactPublicationGroupReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether every exact group member committed."""

        return self._committed

    @property
    def publication_tokens(self) -> tuple[str, ...]:
        """Return frozen preparation proofs in caller-supplied order."""

        return self._publication_tokens

    @property
    def receipt(self) -> LocalArtifactPublicationGroupReceipt | None:
        """Return the authenticated ordered group receipt after commit."""

        return self._receipt

    @property
    def expected_receipt(self) -> LocalArtifactPublicationGroupReceipt:
        """Return the precomputed authenticated ordered group receipt."""

        return self._expected_receipt

    def commit_no_fail(self) -> LocalArtifactPublicationGroupReceipt:
        """Publish every member atomically and return one ordered receipt."""

        if not self._active:
            raise StateError("local artifact prepared group commit is no longer active")
        if self._committed:
            raise StateError("local artifact prepared publication group was already committed")
        if get_ident() != self._claimant_thread_id:
            raise StateError(
                "local artifact prepared publication group must commit on its claiming thread"
            )
        self._receipt = self._registry._commit_claimed_group(self)
        self._committed = True
        return self._receipt

    def commit(self) -> tuple[int, ...]:
        """Compatibility projection returning committed handles in input order."""

        return self.commit_no_fail().handles

    def _close(self) -> None:
        self._active = False


class _ArtifactRegistryGate:
    """Allow disjoint shard mutations while giving watermarks exclusive admission."""

    __slots__ = ("_condition", "_readers", "_waiting_writers", "_writer")

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter a shared mutation section with watermark preference."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Enter the exclusive watermark section."""

        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


def _semantic_artifact_digest(value: str, prefix: str) -> bytes | None:
    """Return the exact 128-bit suffix of one canonical semantic identifier."""

    if not value.startswith(prefix):
        return None
    suffix = value[len(prefix) :]
    if len(suffix) != _ARTIFACT_DIGEST_BYTES * 2:
        return None
    try:
        return bytes.fromhex(suffix)
    except ValueError:
        return None


def _artifact_text_digest(value: str) -> bytes:
    """Return a stable lookup fingerprint; callers still verify exact payload bytes."""

    return hashlib.blake2b(value.encode("utf-8"), digest_size=_ARTIFACT_DIGEST_BYTES).digest()


def _artifact_probe_start(digest: bytes, mask: int) -> int:
    return int.from_bytes(digest[:8], "little") & mask


def _artifact_table_capacity(entries: int) -> int:
    capacity = 8
    while entries * 3 >= capacity * 2:
        capacity *= 2
    return capacity


def _pack_artifact_payload(
    artifact: LocalArtifactIdentity,
    record: LocalArtifactVersionRecord | None = None,
) -> bytes:
    """Pack every non-ID field into one bounded compressed allocation."""

    content_fields: tuple[object, ...] | None = None
    binary_fields: tuple[object, ...] | None = None
    if record is not None:
        if record.artifact != artifact:
            raise ValueError("local artifact record must describe the published artifact")
        content = record.content
        content_fields = (
            content.file_object_id,
            content.version,
            content.size_bytes,
            content.mime_type,
            content.seed_ref,
        )
        if record.binary is not None:
            version_info = record.binary.pe_version_info
            binary_fields = (
                record.binary.architecture,
                record.binary.artifact_name,
                None
                if version_info is None
                else (
                    version_info.file_version,
                    version_info.description,
                    version_info.product,
                    version_info.company,
                    version_info.original_filename,
                ),
            )
    encoded = json.dumps(
        (
            artifact.hostname,
            artifact.principal,
            artifact.user_profile_id,
            artifact.application_profile_id,
            artifact.application_id,
            artifact.family,
            artifact.source_object_id,
            artifact.native_path,
            artifact.content_id,
            artifact.slot,
            artifact.version,
            content_fields,
            binary_fields,
        ),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return zlib.compress(encoded, level=1)


def _local_artifact_record_primitive(record: object) -> tuple[object, ...]:
    """Return a callback-free primitive snapshot or reject a malformed record."""

    if type(record) is not LocalArtifactVersionRecord:
        raise StateError("local artifact publication record has an invalid type")
    artifact = record.artifact
    content = record.content
    binary = record.binary
    if type(artifact) is not LocalArtifactIdentity or type(content) is not FileContentIdentity:
        raise StateError("local artifact publication record has malformed identities")
    artifact_text = (
        artifact.hostname,
        artifact.principal,
        artifact.platform,
        artifact.user_profile_id,
        artifact.application_profile_id,
        artifact.application_id,
        artifact.family,
        artifact.source_object_id,
        artifact.native_path,
        artifact.content_id,
        artifact.slot,
        artifact.artifact_id,
        artifact.artifact_version_id,
    )
    content_text = (
        content.file_object_id,
        content.mime_type,
        content.seed_ref,
        content.file_version_id,
        content.content_id,
    )
    if any(type(value) is not str for value in (*artifact_text, *content_text)):
        raise StateError("local artifact publication record contains malformed text")
    if _has_posix_path_backslash(artifact.native_path, artifact.platform):
        raise StateError("POSIX local artifact native_path cannot contain backslashes")
    if (
        type(artifact.version) is not int
        or artifact.version < 1
        or type(content.version) is not int
        or content.version < 1
        or type(content.size_bytes) is not int
        or content.size_bytes < 0
    ):
        raise StateError("local artifact publication record contains malformed numbers")
    digests = content.digests
    if type(digests) is not ContentDigests:
        raise StateError("local artifact publication record contains malformed digests")
    digest_values = (digests.md5, digests.sha1, digests.sha256, digests.imphash)
    if any(type(value) is not str for value in digest_values):
        raise StateError("local artifact publication record contains malformed digests")

    binary_values: tuple[object, ...] | None = None
    if binary is not None:
        if type(binary) is not LocalArtifactBinaryIdentity:
            raise StateError("local artifact publication record contains a malformed binary")
        binary_digests = binary.digests
        if type(binary_digests) is not ContentDigests:
            raise StateError("local artifact publication binary contains malformed digests")
        binary_digest_values = (
            binary_digests.md5,
            binary_digests.sha1,
            binary_digests.sha256,
            binary_digests.imphash,
        )
        binary_text = (
            binary.artifact_version_id,
            binary.content_id,
            binary.platform,
            binary.architecture,
            binary.artifact_name,
            binary.identity_kind,
            *binary_digest_values,
        )
        if any(type(value) is not str for value in binary_text):
            raise StateError("local artifact publication binary contains malformed text")
        version_info_values: tuple[str, ...] | None = None
        if binary.pe_version_info is not None:
            version_info = binary.pe_version_info
            if type(version_info) is not PeVersionInfo:
                raise StateError("local artifact publication binary has malformed version info")
            version_info_values = (
                version_info.file_version,
                version_info.description,
                version_info.product,
                version_info.company,
                version_info.original_filename,
            )
            if any(type(value) is not str for value in version_info_values):
                raise StateError(
                    "local artifact publication binary has malformed version-info text"
                )
        binary_values = (*binary_text, version_info_values)

    return (
        artifact_text,
        artifact.version,
        content_text,
        content.version,
        content.size_bytes,
        digest_values,
        binary_values,
    )


def _canonical_local_artifact_record(record: object) -> LocalArtifactVersionRecord:
    """Copy one validated record into an independent registry-owned snapshot."""

    primitive = _local_artifact_record_primitive(record)
    assert type(record) is LocalArtifactVersionRecord
    canonical_artifact = _canonical_local_artifact_identity(record.artifact)
    canonical_content = replace(record.content)
    canonical_binary: LocalArtifactBinaryIdentity | None = None
    if record.binary is not None:
        version_info = record.binary.pe_version_info
        canonical_binary = replace(
            record.binary,
            digests=replace(record.binary.digests),
            pe_version_info=None if version_info is None else replace(version_info),
        )
    canonical = LocalArtifactVersionRecord(
        artifact=canonical_artifact,
        content=canonical_content,
        binary=canonical_binary,
    )
    if _local_artifact_record_primitive(canonical) != primitive:
        raise StateError("local artifact publication record is not canonically self-consistent")
    return canonical


def _local_artifact_record_preimage(record: object) -> bytes:
    """Serialize the complete exact record into a stable integrity preimage."""

    return json.dumps(
        _local_artifact_record_primitive(record),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _local_artifact_publish_token_preimage(token: LocalArtifactPublishToken) -> bytes:
    """Validate and serialize every caller-visible and private token field."""

    if type(token) is not LocalArtifactPublishToken:
        raise StateError("local artifact publish token has an invalid type")
    if (
        type(token.observed_at) is not datetime
        or token.observed_at.tzinfo is not UTC
        or type(token.retained_until) is not datetime
        or token.retained_until.tzinfo is not UTC
        or (
            token.lease_until is not None
            and (type(token.lease_until) is not datetime or token.lease_until.tzinfo is not UTC)
        )
        or type(token.lease_owner) is not str
        or type(token._registry_token) is not int
        or type(token._reservation_id) is not int
        or token._reservation_id <= 0
        or type(token._shard_id) is not int
        or token._shard_id < 0
        or (
            token._existing_handle is not None
            and (type(token._existing_handle) is not int or token._existing_handle < 0)
        )
        or type(token._integrity) is not str
    ):
        raise StateError("local artifact publish token contains malformed fields")
    return json.dumps(
        (
            "local-artifact-prepared-publication-v1",
            _local_artifact_record_primitive(token.record),
            token.observed_at.isoformat(),
            token.retained_until.isoformat(),
            token.lease_owner,
            None if token.lease_until is None else token.lease_until.isoformat(),
            token._registry_token,
            token._reservation_id,
            token._shard_id,
            token._existing_handle,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _local_artifact_publish_token_integrity(
    secret: bytes,
    token: LocalArtifactPublishToken,
) -> str:
    """Return the registry/reservation identity for a trusted publication token."""

    del secret
    return f"artifact-token:{token._registry_token:x}:{token._reservation_id:x}"


def _local_artifact_receipt_preimage(receipt: LocalArtifactPublicationReceipt) -> bytes:
    """Validate and serialize one committed publication receipt."""

    if type(receipt) is not LocalArtifactPublicationReceipt:
        raise StateError("local artifact publication receipt has an invalid type")
    if (
        type(receipt.reservation_id) is not int
        or receipt.reservation_id <= 0
        or type(receipt.artifact_version_id) is not str
        or not receipt.artifact_version_id
        or type(receipt.shard_id) is not int
        or receipt.shard_id < 0
        or type(receipt.handle) is not int
        or receipt.handle < 0
        or type(receipt.publication_token) is not str
        or not receipt.publication_token
        or type(receipt.record_digest) is not str
        or type(receipt._registry_token) is not int
        or type(receipt._integrity) is not str
    ):
        raise StateError("local artifact publication receipt contains malformed fields")
    return json.dumps(
        (
            "local-artifact-publication-receipt-v1",
            receipt.reservation_id,
            receipt.artifact_version_id,
            receipt.shard_id,
            receipt.handle,
            receipt.publication_token,
            receipt.record_digest,
            receipt._registry_token,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _local_artifact_receipt_integrity(
    secret: bytes,
    receipt: LocalArtifactPublicationReceipt,
) -> str:
    """Return the registry/reservation identity for a trusted publication receipt."""

    del secret
    return f"artifact-receipt:{receipt._registry_token:x}:{receipt.reservation_id:x}"


def _local_artifact_group_receipt_preimage(
    receipt: LocalArtifactPublicationGroupReceipt,
) -> bytes:
    """Validate and serialize one ordered publication-group receipt."""

    if type(receipt) is not LocalArtifactPublicationGroupReceipt:
        raise StateError("local artifact publication group receipt has an invalid type")
    if (
        type(receipt.receipts) is not tuple
        or not receipt.receipts
        or type(receipt.publication_tokens) is not tuple
        or len(receipt.receipts) != len(receipt.publication_tokens)
        or type(receipt._registry_token) is not int
        or type(receipt._integrity) is not str
    ):
        raise StateError("local artifact publication group receipt contains malformed fields")
    members: list[tuple[str, str]] = []
    for member, publication_token in zip(
        receipt.receipts,
        receipt.publication_tokens,
        strict=True,
    ):
        if type(publication_token) is not str or not publication_token:
            raise StateError("local artifact publication group receipt contains a malformed token")
        member_preimage = _local_artifact_receipt_preimage(member).decode("utf-8")
        if member.publication_token != publication_token:
            raise StateError("local artifact publication group receipt member order is invalid")
        members.append((member_preimage, member._integrity))
    return json.dumps(
        (
            "local-artifact-publication-group-receipt-v1",
            members,
            receipt.publication_tokens,
            receipt._registry_token,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _local_artifact_group_receipt_integrity(
    secret: bytes,
    receipt: LocalArtifactPublicationGroupReceipt,
) -> str:
    """Return the registry/object identity for a trusted publication group."""

    del secret
    return f"artifact-group:{receipt._registry_token:x}:{id(receipt):x}"


def _artifact_payload_field(payload: bytes, field_index: int) -> str:
    value = json.loads(zlib.decompress(payload))[field_index]
    if not isinstance(value, str):  # pragma: no cover - indexed fields are strings
        raise StateError("local artifact packed index field is not text")
    return value


def _unpack_artifact_payload(payload: bytes) -> tuple[object, ...]:
    """Decode one packed artifact payload."""

    values = json.loads(zlib.decompress(payload))
    if not isinstance(values, list):  # pragma: no cover - internal payload invariant
        raise StateError("local artifact payload is not a packed list")
    return tuple(values)


class _PackedPrimaryIndex:
    """Exact 128-bit key index retaining only primitive handle slots."""

    __slots__ = ("_high_water", "_live", "_slots", "_tombstones")

    def __init__(self, capacity: int = 0) -> None:
        self._slots = array("I", [_EMPTY_ARTIFACT_SLOT]) * _artifact_table_capacity(capacity)
        self._live = 0
        self._tombstones = 0
        self._high_water = 0

    def __len__(self) -> int:
        return self._live

    @property
    def backing_bytes(self) -> int:
        return sys.getsizeof(self._slots)

    def _locate(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
    ) -> tuple[int, bool]:
        mask = len(self._slots) - 1
        slot = _artifact_probe_start(digest, mask)
        first_tombstone = -1
        while True:
            encoded = self._slots[slot]
            if encoded == _EMPTY_ARTIFACT_SLOT:
                return (first_tombstone if first_tombstone >= 0 else slot), False
            if encoded == _TOMBSTONE_ARTIFACT_SLOT:
                if first_tombstone < 0:
                    first_tombstone = slot
            else:
                handle = encoded - 1
                if digest_for_handle(handle) == digest:
                    return slot, True
            slot = (slot + 1) & mask

    def get(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
    ) -> int | None:
        slot, found = self._locate(digest, digest_for_handle)
        return self._slots[slot] - 1 if found else None

    def add(
        self,
        digest: bytes,
        handle: int,
        digest_for_handle: Callable[[int], bytes],
    ) -> None:
        if handle >= _TOMBSTONE_ARTIFACT_SLOT - 1:
            raise StateError("local artifact store exhausted compact primary handles")
        if (self._live + self._tombstones + 1) * 3 >= len(self._slots) * 2:
            target = (
                len(self._slots) * 2
                if (self._live + 1) * 3 >= len(self._slots) * 2
                else len(self._slots)
            )
            self._rebuild(target, digest_for_handle)
        slot, found = self._locate(digest, digest_for_handle)
        if found:
            raise ValueError("duplicate local artifact version identity")
        if self._slots[slot] == _TOMBSTONE_ARTIFACT_SLOT:
            self._tombstones -= 1
        self._slots[slot] = handle + 1
        self._live += 1
        self._high_water = max(self._high_water, self._live)

    def remove(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
    ) -> bool:
        slot, found = self._locate(digest, digest_for_handle)
        if not found:
            return False
        self._slots[slot] = _TOMBSTONE_ARTIFACT_SLOT
        self._live -= 1
        self._tombstones += 1
        return True

    def compact(self, digest_for_handle: Callable[[int], bytes], *, force: bool = False) -> int:
        minimum = 8
        while self._live * 3 >= minimum * 2:
            minimum *= 2
        amplified = self._tombstones > max(64, self._live) or len(self._slots) > minimum * 2
        if not force and not amplified:
            return 0
        work = self._live
        self._rebuild(minimum, digest_for_handle)
        return work

    def _rebuild(self, capacity: int, digest_for_handle: Callable[[int], bytes]) -> None:
        old_slots = self._slots
        self._slots = array("I", [_EMPTY_ARTIFACT_SLOT]) * max(8, capacity)
        self._live = 0
        self._tombstones = 0
        for encoded in old_slots:
            if encoded in {_EMPTY_ARTIFACT_SLOT, _TOMBSTONE_ARTIFACT_SLOT}:
                continue
            handle = encoded - 1
            digest = digest_for_handle(handle)
            slot, found = self._locate(digest, digest_for_handle)
            if found:  # pragma: no cover - primary semantic IDs are unique
                raise StateError("duplicate artifact version during primary compaction")
            self._slots[slot] = encoded
            self._live += 1

    def estimated_bytes(self) -> int:
        return sys.getsizeof(self) + sys.getsizeof(self._slots)


class _PackedInlineEqualityGroups:
    """Exact equality groups with singleton handles inline in one OA table."""

    __slots__ = (
        "_bucket_counts",
        "_bucket_heads",
        "_bucket_size_counts",
        "_bucket_tails",
        "_free_bucket_ids",
        "_handle_capacity",
        "_high_water",
        "_live_groups",
        "_max_bucket_size",
        "_minimum_table_capacity",
        "_next",
        "_previous",
        "_slots",
        "_tombstones",
    )

    def __init__(self, capacity: int = 0) -> None:
        table_capacity = _artifact_table_capacity(capacity)
        self._slots = array("I", [_EMPTY_ARTIFACT_SLOT]) * table_capacity
        self._minimum_table_capacity = table_capacity
        self._handle_capacity = capacity
        self._bucket_heads = array("I")
        self._bucket_tails = array("I")
        self._bucket_counts = array("I")
        self._free_bucket_ids = array("I")
        self._previous = array("I")
        self._next = array("I")
        self._live_groups = 0
        self._tombstones = 0
        self._high_water = 0
        self._bucket_size_counts: dict[int, int] = {}
        self._max_bucket_size = 0

    def __len__(self) -> int:
        return self._live_groups

    @property
    def max_bucket_size(self) -> int:
        return self._max_bucket_size

    @staticmethod
    def _is_bucket(encoded: int) -> bool:
        return encoded >= _ARTIFACT_BUCKET_TAG and encoded != _TOMBSTONE_ARTIFACT_SLOT

    def _representative(self, encoded: int) -> int:
        if not self._is_bucket(encoded):
            return encoded - 1
        bucket_id = (encoded & (_ARTIFACT_BUCKET_TAG - 1)) - 1
        return self._bucket_heads[bucket_id] - 1

    def _adjust_size(self, old_size: int, new_size: int) -> None:
        if old_size:
            remaining = self._bucket_size_counts[old_size] - 1
            if remaining:
                self._bucket_size_counts[old_size] = remaining
            else:
                del self._bucket_size_counts[old_size]
        if new_size:
            self._bucket_size_counts[new_size] = self._bucket_size_counts.get(new_size, 0) + 1
        self._max_bucket_size = max(self._bucket_size_counts, default=0)

    def _ensure_links(self) -> None:
        if self._next:
            return
        self._previous = array("I", [0]) * self._handle_capacity
        self._next = array("I", [0]) * self._handle_capacity

    def _new_bucket(self, head: int, tail: int, count: int) -> int:
        if self._free_bucket_ids:
            bucket_id = self._free_bucket_ids.pop()
            self._bucket_heads[bucket_id] = head + 1
            self._bucket_tails[bucket_id] = tail + 1
            self._bucket_counts[bucket_id] = count
        else:
            bucket_id = len(self._bucket_heads)
            if bucket_id >= _ARTIFACT_BUCKET_TAG - 2:
                raise StateError("local artifact equality index exhausted promoted buckets")
            self._bucket_heads.append(head + 1)
            self._bucket_tails.append(tail + 1)
            self._bucket_counts.append(count)
        return bucket_id

    def _release_bucket(self, bucket_id: int) -> None:
        self._bucket_heads[bucket_id] = 0
        self._bucket_tails[bucket_id] = 0
        self._bucket_counts[bucket_id] = 0
        self._free_bucket_ids.append(bucket_id)

    def _locate(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
    ) -> tuple[int, bool]:
        mask = len(self._slots) - 1
        slot = _artifact_probe_start(digest, mask)
        first_tombstone = -1
        while True:
            encoded = self._slots[slot]
            if encoded == _EMPTY_ARTIFACT_SLOT:
                return (first_tombstone if first_tombstone >= 0 else slot), False
            if encoded == _TOMBSTONE_ARTIFACT_SLOT:
                if first_tombstone < 0:
                    first_tombstone = slot
            else:
                handle = self._representative(encoded)
                if digest_for_handle(handle) == digest and equals_handle(handle):
                    return slot, True
            slot = (slot + 1) & mask

    def add(
        self,
        digest: bytes,
        handle: int,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
    ) -> None:
        if handle + 1 >= _ARTIFACT_BUCKET_TAG:
            raise StateError("local artifact equality index exhausted inline handles")
        if (self._live_groups + self._tombstones + 1) * 3 >= len(self._slots) * 2:
            target = (
                len(self._slots) * 2
                if (self._live_groups + 1) * 3 >= len(self._slots) * 2
                else len(self._slots)
            )
            self._rebuild(target, digest_for_handle)
        slot, found = self._locate(digest, digest_for_handle, equals_handle)
        if not found:
            if self._slots[slot] == _TOMBSTONE_ARTIFACT_SLOT:
                self._tombstones -= 1
            self._slots[slot] = handle + 1
            self._live_groups += 1
            self._high_water = max(self._high_water, self._live_groups)
            self._adjust_size(0, 1)
            return
        encoded = self._slots[slot]
        if not self._is_bucket(encoded):
            self._ensure_links()
            existing = encoded - 1
            bucket_id = self._new_bucket(existing, handle, 2)
            self._next[existing] = handle + 1
            self._previous[handle] = existing + 1
            self._slots[slot] = _ARTIFACT_BUCKET_TAG | (bucket_id + 1)
            self._adjust_size(1, 2)
            return
        bucket_id = (encoded & (_ARTIFACT_BUCKET_TAG - 1)) - 1
        prior_count = self._bucket_counts[bucket_id]
        tail = self._bucket_tails[bucket_id] - 1
        self._next[tail] = handle + 1
        self._previous[handle] = tail + 1
        self._bucket_tails[bucket_id] = handle + 1
        self._bucket_counts[bucket_id] = prior_count + 1
        self._adjust_size(prior_count, prior_count + 1)

    def remove(
        self,
        digest: bytes,
        handle: int,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
    ) -> bool:
        slot, found = self._locate(digest, digest_for_handle, equals_handle)
        if not found:
            return False
        encoded = self._slots[slot]
        if not self._is_bucket(encoded):
            if encoded - 1 != handle:
                return False
            self._slots[slot] = _TOMBSTONE_ARTIFACT_SLOT
            self._live_groups -= 1
            self._tombstones += 1
            self._adjust_size(1, 0)
            return True
        bucket_id = (encoded & (_ARTIFACT_BUCKET_TAG - 1)) - 1
        previous_encoded = self._previous[handle]
        next_encoded = self._next[handle]
        if previous_encoded:
            self._next[previous_encoded - 1] = next_encoded
        else:
            self._bucket_heads[bucket_id] = next_encoded
        if next_encoded:
            self._previous[next_encoded - 1] = previous_encoded
        else:
            self._bucket_tails[bucket_id] = previous_encoded
        self._previous[handle] = 0
        self._next[handle] = 0
        prior_count = self._bucket_counts[bucket_id]
        new_count = prior_count - 1
        self._bucket_counts[bucket_id] = new_count
        self._adjust_size(prior_count, new_count)
        if new_count == 1:
            remaining = self._bucket_heads[bucket_id] - 1
            self._previous[remaining] = 0
            self._next[remaining] = 0
            self._slots[slot] = remaining + 1
            self._release_bucket(bucket_id)
        return True

    def count(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
    ) -> int:
        slot, found = self._locate(digest, digest_for_handle, equals_handle)
        if not found:
            return 0
        encoded = self._slots[slot]
        if not self._is_bucket(encoded):
            return 1
        return self._bucket_counts[(encoded & (_ARTIFACT_BUCKET_TAG - 1)) - 1]

    def iter_handles(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
    ) -> Iterator[int]:
        slot, found = self._locate(digest, digest_for_handle, equals_handle)
        if not found:
            return
        encoded = self._slots[slot]
        if not self._is_bucket(encoded):
            yield encoded - 1
            return
        bucket_id = (encoded & (_ARTIFACT_BUCKET_TAG - 1)) - 1
        encoded = self._bucket_heads[bucket_id]
        while encoded:
            handle = encoded - 1
            yield handle
            encoded = self._next[handle]

    def page(
        self,
        digest: bytes,
        digest_for_handle: Callable[[int], bytes],
        equals_handle: Callable[[int], bool],
        *,
        after_handle: int | None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        slot, found = self._locate(digest, digest_for_handle, equals_handle)
        if not found:
            return (), None
        stored = self._slots[slot]
        if after_handle is not None and (
            after_handle < 0
            or after_handle >= self._handle_capacity
            or digest_for_handle(after_handle) != digest
            or not equals_handle(after_handle)
        ):
            raise KeyError(f"stale compact artifact page cursor {after_handle}")
        if not self._is_bucket(stored):
            handle = stored - 1
            if after_handle is None:
                return (handle,), None
            if after_handle != handle:
                raise KeyError(f"stale compact artifact page cursor {after_handle}")
            return (), None
        bucket_id = (stored & (_ARTIFACT_BUCKET_TAG - 1)) - 1
        encoded = (
            self._bucket_heads[bucket_id] if after_handle is None else self._next[after_handle]
        )
        page: list[int] = []
        while encoded and len(page) < limit:
            handle = encoded - 1
            page.append(handle)
            encoded = self._next[handle]
        cursor = page[-1] if page and encoded else None
        return tuple(page), cursor

    def compact(self, digest_for_handle: Callable[[int], bytes], *, force: bool = False) -> int:
        amplified = self._tombstones > max(64, self._live_groups)
        if not force and not amplified:
            return 0
        work = self._live_groups
        self._rebuild(self._minimum_table_capacity, digest_for_handle)
        if force and not self._live_groups:
            self._bucket_heads = array("I")
            self._bucket_tails = array("I")
            self._bucket_counts = array("I")
            self._free_bucket_ids = array("I")
            self._previous = array("I")
            self._next = array("I")
            self._bucket_size_counts = {}
            self._max_bucket_size = 0
        return work

    def _rebuild(self, capacity: int, digest_for_handle: Callable[[int], bytes]) -> None:
        old_slots = self._slots
        self._slots = array("I", [_EMPTY_ARTIFACT_SLOT]) * max(
            self._minimum_table_capacity,
            capacity,
        )
        self._live_groups = 0
        self._tombstones = 0
        mask = len(self._slots) - 1
        for encoded in old_slots:
            if encoded in {_EMPTY_ARTIFACT_SLOT, _TOMBSTONE_ARTIFACT_SLOT}:
                continue
            digest = digest_for_handle(self._representative(encoded))
            slot = _artifact_probe_start(digest, mask)
            while self._slots[slot] != _EMPTY_ARTIFACT_SLOT:
                slot = (slot + 1) & mask
            self._slots[slot] = encoded
            self._live_groups += 1

    def estimated_bytes(self) -> int:
        return sum(
            sys.getsizeof(value)
            for value in (
                self,
                self._slots,
                self._bucket_heads,
                self._bucket_tails,
                self._bucket_counts,
                self._free_bucket_ids,
                self._previous,
                self._next,
                self._bucket_size_counts,
            )
        )


class _PackedArtifactStore:
    """Primitive-column artifact storage with lazy frozen-value reconstruction."""

    __slots__ = (
        "_active",
        "_application_profile_index",
        "_artifact_digests",
        "_artifact_index",
        "_compaction_rotations",
        "_compaction_work",
        "_content_index",
        "_execution_path_index",
        "_free_handle_count",
        "_free_handle_positions",
        "_free_handles",
        "_high_water",
        "_live",
        "_next_handle",
        "_payload_arena",
        "_payload_lengths",
        "_payload_overflow",
        "_platforms",
        "_primary",
        "_release_pending",
        "_reserved",
        "_version_digests",
    )

    _FIELD_APPLICATION_PROFILE = 3
    _FIELD_CONTENT = 8
    _FIELD_HOSTNAME = 0
    _FIELD_PRINCIPAL = 1
    _FIELD_USER_PROFILE = 2
    _FIELD_NATIVE_PATH = 7
    _FIELD_VERSION = 10

    def __init__(self, capacity: int) -> None:
        self._active = bytearray(capacity)
        self._payload_arena = bytearray(capacity * _ARTIFACT_INLINE_PAYLOAD_BYTES)
        self._payload_lengths = array("I", [0]) * capacity
        self._payload_overflow: dict[int, bytes] = {}
        self._platforms = array("B", [0]) * capacity
        self._artifact_digests = bytearray(capacity * _ARTIFACT_DIGEST_BYTES)
        self._version_digests = bytearray(capacity * _ARTIFACT_DIGEST_BYTES)
        self._free_handle_positions = array("I", [_TOMBSTONE_ARTIFACT_SLOT]) * capacity
        self._free_handles = array("I", [0]) * capacity
        self._free_handle_count = 0
        self._primary = _PackedPrimaryIndex(capacity)
        self._release_pending = bytearray(capacity)
        self._reserved = bytearray(capacity)
        self._artifact_index = _PackedInlineEqualityGroups(capacity)
        self._application_profile_index = _PackedInlineEqualityGroups(capacity)
        self._content_index = _PackedInlineEqualityGroups(capacity)
        self._execution_path_index = _PackedInlineEqualityGroups(capacity)
        self._live = 0
        self._next_handle = 0
        self._high_water = 0
        self._compaction_rotations = 0
        self._compaction_work = 0

    def __len__(self) -> int:
        return self._live

    def __bool__(self) -> bool:
        return self._live > 0

    @staticmethod
    def _write_digest(column: bytearray, handle: int, digest: bytes) -> None:
        offset = handle * _ARTIFACT_DIGEST_BYTES
        column[offset : offset + _ARTIFACT_DIGEST_BYTES] = digest

    @staticmethod
    def _read_digest(column: bytearray, handle: int) -> bytes:
        offset = handle * _ARTIFACT_DIGEST_BYTES
        return bytes(column[offset : offset + _ARTIFACT_DIGEST_BYTES])

    def _artifact_digest(self, handle: int) -> bytes:
        return self._read_digest(self._artifact_digests, handle)

    def _version_digest(self, handle: int) -> bytes:
        return self._read_digest(self._version_digests, handle)

    def _payload(self, handle: int) -> bytes:
        if not self.is_live_handle(handle):
            raise KeyError(handle)
        payload_length = self._payload_lengths[handle]
        if payload_length > _ARTIFACT_INLINE_PAYLOAD_BYTES:
            return self._payload_overflow[handle]
        offset = handle * _ARTIFACT_INLINE_PAYLOAD_BYTES
        return bytes(self._payload_arena[offset : offset + payload_length])

    def _store_payload(self, handle: int, payload: bytes) -> None:
        payload_length = len(payload)
        if payload_length > _COMPACT_HANDLE_LIMIT:
            raise ValueError("local artifact packed payload exceeds 32-bit storage limit")
        if payload_length <= _ARTIFACT_INLINE_PAYLOAD_BYTES:
            offset = handle * _ARTIFACT_INLINE_PAYLOAD_BYTES
            self._payload_arena[offset : offset + payload_length] = payload
            self._payload_overflow.pop(handle, None)
        else:
            self._payload_overflow[handle] = payload
        self._payload_lengths[handle] = payload_length

    def _field(self, handle: int, field_index: int) -> str:
        return _artifact_payload_field(self._payload(handle), field_index)

    def _application_profile_digest(self, handle: int) -> bytes:
        return _artifact_text_digest(self._field(handle, self._FIELD_APPLICATION_PROFILE))

    def _content_digest(self, handle: int) -> bytes:
        return _artifact_text_digest(self._field(handle, self._FIELD_CONTENT))

    def _execution_path_key(self, handle: int) -> str:
        platform = _ARTIFACT_PLATFORMS[self._platforms[handle]]
        native_path = self._field(handle, self._FIELD_NATIVE_PATH)
        if _has_posix_path_backslash(native_path, platform):  # pragma: no cover - admission guard
            raise StateError("POSIX local artifact native_path cannot contain backslashes")
        return "\0".join(
            (
                self._field(handle, self._FIELD_HOSTNAME),
                self._field(handle, self._FIELD_PRINCIPAL),
                platform,
                canonical_native_path(native_path, platform),
            )
        )

    def _execution_path_digest(self, handle: int) -> bytes:
        return _artifact_text_digest(self._execution_path_key(handle))

    def insert(
        self,
        artifact: LocalArtifactIdentity,
        record: LocalArtifactVersionRecord | None = None,
        *,
        packed_payload: bytes | None = None,
    ) -> int:
        """Insert one immutable artifact into reusable primitive columns."""

        handle = self.reserve_handle()
        try:
            self.insert_reserved(
                handle,
                artifact,
                record,
                packed_payload=packed_payload,
            )
        except BaseException:
            self.release_reserved_handle(handle)
            raise
        self.consume_reserved_handle(handle)
        return handle

    def reserve_handle(self) -> int:
        """Reserve one exact inactive handle without publishing any index row."""

        if self._free_handle_count:
            self._free_handle_count -= 1
            handle = int(self._free_handles[self._free_handle_count])
            self._free_handle_positions[handle] = _TOMBSTONE_ARTIFACT_SLOT
        else:
            handle = self._next_handle
            if handle >= len(self._payload_lengths):
                raise StateError("local artifact store exceeded its compiled shard capacity")
            self._next_handle += 1
        if self._active[handle] or self._reserved[handle]:  # pragma: no cover - allocator invariant
            raise StateError("local artifact store selected an occupied reserved handle")
        self._reserved[handle] = 1
        return handle

    def _append_free_handle(self, handle: int) -> None:
        """Append one unique free handle and record its constant-time position."""

        if self._free_handle_positions[handle] != _TOMBSTONE_ARTIFACT_SLOT:
            raise StateError("local artifact handle was returned to the free pool twice")
        if self._free_handle_count >= len(self._free_handles):
            raise StateError("local artifact free-handle pool exceeded shard capacity")
        self._free_handle_positions[handle] = self._free_handle_count
        self._free_handles[self._free_handle_count] = handle
        self._free_handle_count += 1

    def _remove_free_handle(self, handle: int) -> None:
        """Remove one exact free handle without scanning the allocator stack."""

        position = self._free_handle_positions[handle]
        if position == _TOMBSTONE_ARTIFACT_SLOT or position >= self._free_handle_count:
            raise StateError("local artifact free-handle position is stale")
        self._free_handle_count -= 1
        final = int(self._free_handles[self._free_handle_count])
        self._free_handle_positions[handle] = _TOMBSTONE_ARTIFACT_SLOT
        if position < self._free_handle_count:
            self._free_handles[position] = final
            self._free_handle_positions[final] = position

    def _free_handle_is_recorded(self, handle: int) -> bool:
        """Return whether one inactive handle is exactly present in the free pool."""

        position = self._free_handle_positions[handle]
        return (
            position != _TOMBSTONE_ARTIFACT_SLOT
            and position < self._free_handle_count
            and self._free_handles[position] == handle
        )

    def reserved_release_is_complete(self, handle: int, *, was_live: bool) -> bool:
        """Return whether one reserved-handle transition reached its terminal state."""

        if was_live:
            return self.is_live_handle(handle) and not self._reserved[handle]
        return (
            not self.is_live_handle(handle)
            and not self._reserved[handle]
            and not self._release_pending[handle]
            and (handle >= self._next_handle or self._free_handle_is_recorded(handle))
        )

    def consume_reserved_handle(self, handle: int) -> None:
        """Release reservation ownership after its handle became canonical."""

        if not self._reserved[handle] or not self._active[handle]:
            raise StateError("local artifact handle reservation was not committed")
        self._reserved[handle] = 0

    def release_reserved_handle(self, handle: int) -> None:
        """Return one inactive reserved handle through a resumable bounded transition."""

        if self._active[handle]:
            raise StateError("local artifact handle reservation is not releasable")
        if self._reserved[handle]:
            self._release_pending[handle] = 1
            self._reserved[handle] = 0
        elif not self._release_pending[handle]:
            if self.reserved_release_is_complete(handle, was_live=False):
                return
            raise StateError("local artifact handle reservation is not releasable")

        # These primitive-column resets are idempotent. The pending marker
        # remains installed until allocator ownership is terminal, allowing a
        # caller retaining the exact reservation to resume after BaseException.
        self._payload_lengths[handle] = 0
        self._payload_overflow.pop(handle, None)
        self._platforms[handle] = 0
        self._write_digest(self._artifact_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)
        self._write_digest(self._version_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)

        if handle < self._next_handle - 1:
            if not self._free_handle_is_recorded(handle):
                try:
                    self._append_free_handle(handle)
                except BaseException:
                    if self._free_handle_is_recorded(handle):
                        self._release_pending[handle] = 0
                    raise
            self._release_pending[handle] = 0
            return

        if handle == self._next_handle - 1:
            self._next_handle -= 1

        # Resume tail compaction after a prior failure even when the original
        # handle is already beyond ``_next_handle``. A candidate marker closes
        # the after-remove/before-frontier gap without an unbounded side map.
        while self._next_handle:
            candidate = self._next_handle - 1
            if self._active[candidate] or self._reserved[candidate]:
                break
            candidate_is_free = self._free_handle_is_recorded(candidate)
            if not candidate_is_free and self._release_pending[candidate] != 2:
                break
            self._release_pending[candidate] = 2
            try:
                if candidate_is_free:
                    self._remove_free_handle(candidate)
            except BaseException:
                if not self._free_handle_is_recorded(candidate):
                    self._next_handle -= 1
                    self._release_pending[candidate] = 0
                raise
            else:
                self._next_handle -= 1
                self._release_pending[candidate] = 0
        self._release_pending[handle] = 0

    def insert_reserved(
        self,
        handle: int,
        artifact: LocalArtifactIdentity,
        record: LocalArtifactVersionRecord | None = None,
        *,
        packed_payload: bytes | None = None,
    ) -> None:
        """Publish one reserved handle with rollback-safe index installation."""

        if _has_posix_path_backslash(artifact.native_path, artifact.platform):
            raise StateError("POSIX local artifact native_path cannot contain backslashes")
        artifact_digest = _semantic_artifact_digest(artifact.artifact_id, "artifact-")
        version_digest = _semantic_artifact_digest(
            artifact.artifact_version_id,
            "artifact-version-",
        )
        if (
            artifact_digest is None or version_digest is None
        ):  # pragma: no cover - identity invariant
            raise StateError("local artifact semantic IDs are not canonical 128-bit identifiers")
        payload = (
            _pack_artifact_payload(artifact, record) if packed_payload is None else packed_payload
        )
        if (
            type(handle) is not int
            or handle < 0
            or handle >= self._next_handle
            or not self._reserved[handle]
            or self._active[handle]
        ):
            raise StateError("local artifact insertion requires an exact reserved handle")
        prior_high_water = self._high_water
        application_digest = _artifact_text_digest(artifact.application_profile_id)
        content_digest = _artifact_text_digest(artifact.content_id)
        execution_path_key = "\0".join(
            (
                artifact.hostname,
                artifact.principal,
                artifact.platform,
                canonical_native_path(artifact.native_path, artifact.platform),
            )
        )
        execution_digest = _artifact_text_digest(execution_path_key)

        def artifact_equals(candidate: int) -> bool:
            return self._artifact_digest(candidate) == artifact_digest

        def application_equals(candidate: int) -> bool:
            return (
                self._field(candidate, self._FIELD_APPLICATION_PROFILE)
                == artifact.application_profile_id
            )

        def content_equals(candidate: int) -> bool:
            return self._field(candidate, self._FIELD_CONTENT) == artifact.content_id

        def execution_equals(candidate: int) -> bool:
            return self._execution_path_key(candidate) == execution_path_key

        started: list[
            tuple[
                _PackedPrimaryIndex | _PackedInlineEqualityGroups,
                bytes,
                Callable[[int], bytes],
                Callable[[int], bool] | None,
            ]
        ] = []
        try:
            self._store_payload(handle, payload)
            self._platforms[handle] = _ARTIFACT_PLATFORM_CODES[artifact.platform]
            self._write_digest(self._artifact_digests, handle, artifact_digest)
            self._write_digest(self._version_digests, handle, version_digest)
            # The shard lock excludes readers while indexes are installed. Marking
            # the staged columns active lets exact index callbacks inspect them;
            # every escaping failure clears the flag before the lock is released.
            self._active[handle] = 1

            started.append((self._primary, version_digest, self._version_digest, None))
            self._primary.add(version_digest, handle, self._version_digest)
            started.append(
                (
                    self._artifact_index,
                    artifact_digest,
                    self._artifact_digest,
                    artifact_equals,
                )
            )
            self._artifact_index.add(
                artifact_digest,
                handle,
                self._artifact_digest,
                cast(Callable[[int], bool], started[-1][3]),
            )
            started.append(
                (
                    self._application_profile_index,
                    application_digest,
                    self._application_profile_digest,
                    application_equals,
                )
            )
            self._application_profile_index.add(
                application_digest,
                handle,
                self._application_profile_digest,
                application_equals,
            )
            started.append(
                (
                    self._content_index,
                    content_digest,
                    self._content_digest,
                    content_equals,
                )
            )
            self._content_index.add(
                content_digest,
                handle,
                self._content_digest,
                content_equals,
            )
            started.append(
                (
                    self._execution_path_index,
                    execution_digest,
                    self._execution_path_digest,
                    execution_equals,
                )
            )
            self._execution_path_index.add(
                execution_digest,
                handle,
                self._execution_path_digest,
                execution_equals,
            )
        except BaseException:
            for index, digest, digest_for_handle, equals_handle in reversed(started):
                if type(index) is _PackedPrimaryIndex:
                    index.remove(digest, digest_for_handle)
                else:
                    index.remove(
                        digest,
                        handle,
                        digest_for_handle,
                        cast(Callable[[int], bool], equals_handle),
                    )
            self._primary.compact(self._version_digest, force=True)
            self._artifact_index.compact(self._artifact_digest, force=True)
            self._application_profile_index.compact(
                self._application_profile_digest,
                force=True,
            )
            self._content_index.compact(self._content_digest, force=True)
            self._execution_path_index.compact(self._execution_path_digest, force=True)
            self._payload_lengths[handle] = 0
            self._payload_overflow.pop(handle, None)
            if not self._payload_overflow:
                self._payload_overflow = {}
            self._platforms[handle] = 0
            self._write_digest(self._artifact_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)
            self._write_digest(self._version_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)
            self._active[handle] = 0
            self._high_water = prior_high_water
            raise
        self._live += 1
        self._high_water = max(self._high_water, self._live)

    def next_insert_handle(self) -> int:
        """Return the exact handle the next locked insertion will consume."""

        if self._free_handle_count:
            return int(self._free_handles[self._free_handle_count - 1])
        if self._next_handle >= len(self._payload_lengths):
            raise StateError("local artifact store exceeded its compiled shard capacity")
        return self._next_handle

    def delete(self, handle: int) -> LocalArtifactIdentity:
        """Delete one live handle and return its reconstructed immutable value."""

        artifact = self.get_by_handle(handle)
        artifact_digest = self._artifact_digest(handle)
        version_digest = self._version_digest(handle)
        application_profile = self._field(handle, self._FIELD_APPLICATION_PROFILE)
        content = self._field(handle, self._FIELD_CONTENT)
        execution_path_key = self._execution_path_key(handle)
        self._primary.remove(version_digest, self._version_digest)
        self._artifact_index.remove(
            artifact_digest,
            handle,
            self._artifact_digest,
            lambda candidate: self._artifact_digest(candidate) == artifact_digest,
        )
        self._application_profile_index.remove(
            _artifact_text_digest(application_profile),
            handle,
            self._application_profile_digest,
            lambda candidate: (
                self._field(candidate, self._FIELD_APPLICATION_PROFILE) == application_profile
            ),
        )
        self._content_index.remove(
            _artifact_text_digest(content),
            handle,
            self._content_digest,
            lambda candidate: self._field(candidate, self._FIELD_CONTENT) == content,
        )
        self._execution_path_index.remove(
            _artifact_text_digest(execution_path_key),
            handle,
            self._execution_path_digest,
            lambda candidate: self._execution_path_key(candidate) == execution_path_key,
        )
        self._payload_lengths[handle] = 0
        self._payload_overflow.pop(handle, None)
        self._platforms[handle] = 0
        self._write_digest(self._artifact_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)
        self._write_digest(self._version_digests, handle, b"\0" * _ARTIFACT_DIGEST_BYTES)
        self._active[handle] = 0
        self._append_free_handle(handle)
        self._live -= 1
        return artifact

    def rollback_reserved_insert(self, handle: int) -> None:
        """Remove a committed reserved row while retaining its allocator claim."""

        if not self._reserved[handle] or not self._active[handle]:
            return
        self.delete(handle)
        self._remove_free_handle(handle)
        self.compact_primary(force=True)

    def is_live_handle(self, handle: int) -> bool:
        """Return whether one compact handle currently owns an artifact."""

        return 0 <= handle < self._next_handle and bool(self._active[handle])

    def find_version_handle(self, artifact_version_id: str) -> int | None:
        """Return the exact local handle for one canonical version ID."""

        digest = _semantic_artifact_digest(artifact_version_id, "artifact-version-")
        if digest is None:
            return None
        return self._primary.get(digest, self._version_digest)

    def get_by_handle(self, handle: int) -> LocalArtifactIdentity:
        payload = self._payload(handle)
        values = _unpack_artifact_payload(payload)
        (
            hostname,
            principal,
            user_profile_id,
            application_profile_id,
            application_id,
            family,
            source_object_id,
            native_path,
            content_id,
            slot,
            version_text,
        ) = values[:11]
        artifact = object.__new__(LocalArtifactIdentity)
        for name, value in (
            ("hostname", hostname),
            ("principal", principal),
            ("platform", _ARTIFACT_PLATFORMS[self._platforms[handle]]),
            ("user_profile_id", user_profile_id),
            ("application_profile_id", application_profile_id),
            ("application_id", application_id),
            ("family", family),
            ("source_object_id", source_object_id),
            ("native_path", native_path),
            ("content_id", content_id),
            ("slot", slot),
            ("version", int(version_text)),
            ("artifact_id", f"artifact-{self._artifact_digest(handle).hex()}"),
            ("artifact_version_id", f"artifact-version-{self._version_digest(handle).hex()}"),
        ):
            object.__setattr__(artifact, name, value)
        return artifact

    def get_record_by_handle(self, handle: int) -> LocalArtifactVersionRecord | None:
        """Return canonical runtime content linked to one live artifact handle."""

        values = _unpack_artifact_payload(self._payload(handle))
        if len(values) < 13 or values[11] is None:
            return None
        content_values = values[11]
        if not isinstance(content_values, list) or len(content_values) != 5:
            raise StateError("local artifact content descriptor is malformed")
        content = FileContentIdentity(
            file_object_id=str(content_values[0]),
            version=int(content_values[1]),
            size_bytes=int(content_values[2]),
            mime_type=str(content_values[3]),
            seed_ref=str(content_values[4]),
        )
        artifact = self.get_by_handle(handle)
        binary_values = values[12]
        binary = None
        if binary_values is not None:
            if not isinstance(binary_values, list) or len(binary_values) != 3:
                raise StateError("local artifact binary descriptor is malformed")
            version_values = binary_values[2]
            version_info = None
            if version_values is not None:
                if not isinstance(version_values, list) or len(version_values) != 5:
                    raise StateError("local artifact PE version descriptor is malformed")
                version_info = PeVersionInfo(
                    file_version=str(version_values[0]),
                    description=str(version_values[1]),
                    product=str(version_values[2]),
                    company=str(version_values[3]),
                    original_filename=str(version_values[4]),
                )
            binary = LocalArtifactBinaryIdentity(
                artifact_version_id=artifact.artifact_version_id,
                content_id=content.content_id,
                digests=content.digests,
                platform=artifact.platform,
                architecture=cast(Architecture, str(binary_values[0])),
                artifact_name=str(binary_values[1]),
                pe_version_info=version_info,
            )
        return LocalArtifactVersionRecord(
            artifact=artifact,
            content=content,
            binary=binary,
        )

    def bind_record(
        self,
        handle: int,
        record: LocalArtifactVersionRecord,
        *,
        packed_payload: bytes | None = None,
    ) -> None:
        """Attach a prevalidated content record to an existing exact artifact."""

        current = self.get_by_handle(handle)
        if current != record.artifact:
            raise ValueError("local artifact record conflicts with the retained artifact identity")
        existing = self.get_record_by_handle(handle)
        if existing is not None and existing != record:
            raise ValueError("local artifact version already has different content descriptors")
        if existing is None:
            payload = (
                _pack_artifact_payload(current, record)
                if packed_payload is None
                else packed_payload
            )
            self._store_payload(handle, payload)

    def artifact_version_id(self, handle: int) -> str:
        """Reconstruct one semantic version ID without materializing the full value."""

        if not self.is_live_handle(handle):
            raise KeyError(handle)
        return f"artifact-version-{self._version_digest(handle).hex()}"

    def _query(
        self,
        index_name: str,
        indexed_value: Hashable,
    ) -> tuple[
        _PackedInlineEqualityGroups,
        bytes,
        Callable[[int], bytes],
        Callable[[int], bool],
    ]:
        value = str(indexed_value)
        if index_name == "artifact_object":
            digest = _semantic_artifact_digest(value, "artifact-")
            if digest is None:
                digest = _artifact_text_digest(f"invalid-artifact-id\0{value}")
            return (
                self._artifact_index,
                digest,
                self._artifact_digest,
                lambda handle: self._artifact_digest(handle) == digest,
            )
        digest = _artifact_text_digest(value)
        if index_name == "application_profile":
            return (
                self._application_profile_index,
                digest,
                self._application_profile_digest,
                lambda handle: self._field(handle, self._FIELD_APPLICATION_PROFILE) == value,
            )
        if index_name == "content":
            return (
                self._content_index,
                digest,
                self._content_digest,
                lambda handle: self._field(handle, self._FIELD_CONTENT) == value,
            )
        if index_name == "execution_path":
            return (
                self._execution_path_index,
                digest,
                self._execution_path_digest,
                lambda handle: self._execution_path_key(handle) == value,
            )
        raise KeyError(f"unknown packed artifact index {index_name!r}")

    def find_iter(
        self, index_name: str, indexed_value: Hashable
    ) -> Iterator[LocalArtifactIdentity]:
        index, digest, digest_for_handle, equals_handle = self._query(index_name, indexed_value)
        for handle in index.iter_handles(digest, digest_for_handle, equals_handle):
            yield self.get_by_handle(handle)

    def find_record_iter(
        self,
        index_name: str,
        indexed_value: Hashable,
    ) -> Iterator[LocalArtifactVersionRecord]:
        """Yield canonical records for one exact equality-index value."""

        index, digest, digest_for_handle, equals_handle = self._query(index_name, indexed_value)
        for handle in index.iter_handles(digest, digest_for_handle, equals_handle):
            record = self.get_record_by_handle(handle)
            if record is not None:
                yield record

    def count(self, index_name: str, indexed_value: Hashable) -> int:
        index, digest, digest_for_handle, equals_handle = self._query(index_name, indexed_value)
        return index.count(digest, digest_for_handle, equals_handle)

    def find_handle_page(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        after_handle: int | None = None,
        limit: int,
    ) -> tuple[tuple[int, ...], int | None]:
        if limit <= 0:
            raise ValueError("artifact history page limit must be positive")
        index, digest, digest_for_handle, equals_handle = self._query(index_name, indexed_value)
        return index.page(
            digest,
            digest_for_handle,
            equals_handle,
            after_handle=after_handle,
            limit=limit,
        )

    def compact_primary(self, *, force: bool = False) -> int:
        """Compact per-shard primary and equality tables at a watermark boundary."""

        work = 0
        live_overflow = len(self._payload_overflow)
        if force or sys.getsizeof(self._payload_overflow) > max(4_096, live_overflow * 128):
            self._payload_overflow = dict(self._payload_overflow)
            work += live_overflow
        work += self._primary.compact(self._version_digest, force=force)
        work += self._artifact_index.compact(self._artifact_digest, force=force)
        work += self._application_profile_index.compact(
            self._application_profile_digest,
            force=force,
        )
        work += self._content_index.compact(self._content_digest, force=force)
        work += self._execution_path_index.compact(
            self._execution_path_digest,
            force=force,
        )
        if work:
            self._compaction_rotations += 1
            self._compaction_work += work
        return work

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        indexes = (
            self._artifact_index,
            self._application_profile_index,
            self._content_index,
            self._execution_path_index,
        )
        estimated = 0
        if estimate_bytes:
            estimated = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._active,
                    self._payload_arena,
                    self._payload_lengths,
                    self._payload_overflow,
                    self._platforms,
                    self._artifact_digests,
                    self._version_digests,
                    self._free_handles,
                    self._free_handle_positions,
                    self._release_pending,
                    self._reserved,
                )
            )
            estimated += self._primary.estimated_bytes()
            estimated += sum(index.estimated_bytes() for index in indexes)
            estimated += sum(
                sys.getsizeof(handle) + sys.getsizeof(payload)
                for handle, payload in self._payload_overflow.items()
            )
        return IndexMetrics(
            live_entries=self._live,
            backing_entries=self._next_handle,
            stale_entries=self._free_handle_count,
            allocated_slots=len(self._payload_lengths),
            secondary_buckets=sum(len(index) for index in indexes),
            max_bucket_size=max((index.max_bucket_size for index in indexes), default=0),
            high_water_mark=self._high_water,
            estimated_bytes=estimated,
            primary_map_entries=len(self._primary),
            primary_map_backing_bytes=self._primary.backing_bytes,
            primary_compaction_rotations=self._compaction_rotations,
            primary_compaction_work=self._compaction_work,
        )


class _CompactArtifactDeadlines:
    """Primitive deadline columns and a four-column allocation-stable min heap."""

    __slots__ = (
        "_deadlines",
        "_generations",
        "_heap_deadlines",
        "_heap_generations",
        "_heap_handles",
        "_heap_orders",
        "_heap_size",
        "_high_water",
        "_live",
        "_order_counter",
        "_orders",
    )

    def __init__(self, capacity: int = 0) -> None:
        self._deadlines = array("q", [_EMPTY_ARTIFACT_DEADLINE]) * capacity
        self._generations = array("I", [0]) * capacity
        self._orders = array("Q", [0]) * capacity
        self._heap_deadlines = array("q", [0]) * capacity
        self._heap_orders = array("Q", [0]) * capacity
        self._heap_handles = array("I", [0]) * capacity
        self._heap_generations = array("I", [0]) * capacity
        self._heap_size = 0
        self._live = 0
        self._high_water = 0
        self._order_counter = 0

    def __len__(self) -> int:
        return self._heap_size

    def deadline(self, handle: int) -> float | None:
        if handle < 0 or handle >= len(self._deadlines):
            return None
        deadline_us = self._deadlines[handle]
        return None if deadline_us == _EMPTY_ARTIFACT_DEADLINE else deadline_us / 1_000_000

    def _ensure_handle(self, handle: int) -> None:
        while len(self._deadlines) <= handle:
            self._deadlines.append(_EMPTY_ARTIFACT_DEADLINE)
            self._generations.append(0)
            self._orders.append(0)

    def _less(self, left: int, right: int) -> bool:
        return (self._heap_deadlines[left], self._heap_orders[left]) < (
            self._heap_deadlines[right],
            self._heap_orders[right],
        )

    def _swap(self, left: int, right: int) -> None:
        for column in (
            self._heap_deadlines,
            self._heap_orders,
            self._heap_handles,
            self._heap_generations,
        ):
            column[left], column[right] = column[right], column[left]

    def _heap_push(self, entry: tuple[int, int, int, int]) -> None:
        deadline_us, order, handle, generation = entry
        if self._heap_size == len(self._heap_deadlines):
            growth = max(8, len(self._heap_deadlines))
            self._heap_deadlines.extend(array("q", [0]) * growth)
            self._heap_orders.extend(array("Q", [0]) * growth)
            self._heap_handles.extend(array("I", [0]) * growth)
            self._heap_generations.extend(array("I", [0]) * growth)
        current = self._heap_size
        self._heap_size += 1
        self._heap_deadlines[current] = deadline_us
        self._heap_orders[current] = order
        self._heap_handles[current] = handle
        self._heap_generations[current] = generation
        while current:
            parent = (current - 1) // 2
            if not self._less(current, parent):
                break
            self._swap(current, parent)
            current = parent

    def _heap_pop(self) -> tuple[int, int, int, int]:
        result = (
            self._heap_deadlines[0],
            self._heap_orders[0],
            self._heap_handles[0],
            self._heap_generations[0],
        )
        last = self._heap_size - 1
        if last:
            self._heap_deadlines[0] = self._heap_deadlines[last]
            self._heap_orders[0] = self._heap_orders[last]
            self._heap_handles[0] = self._heap_handles[last]
            self._heap_generations[0] = self._heap_generations[last]
        self._heap_size -= 1
        current = 0
        while current < self._heap_size:
            left = current * 2 + 1
            if left >= self._heap_size:
                break
            right = left + 1
            child = right if right < self._heap_size and self._less(right, left) else left
            if not self._less(child, current):
                break
            self._swap(current, child)
            current = child
        return result

    def set(self, handle: int, deadline: float) -> None:
        self.validate_set(handle, deadline)
        self._ensure_handle(handle)
        if self._deadlines[handle] == _EMPTY_ARTIFACT_DEADLINE:
            self._live += 1
            self._high_water = max(self._high_water, self._live)
        deadline_us = int(round(deadline * 1_000_000))
        generation = self._generations[handle] + 1
        if generation > _COMPACT_HANDLE_LIMIT:
            raise StateError("local artifact deadline generation exhausted 32 bits")
        self._order_counter += 1
        if self._order_counter > (1 << 64) - 1:
            raise StateError("local artifact deadline insertion order exhausted 64 bits")
        self._generations[handle] = generation
        self._deadlines[handle] = deadline_us
        self._orders[handle] = self._order_counter
        self._heap_push((deadline_us, self._order_counter, handle, generation))

    def validate_set(self, handle: int, deadline: float) -> None:
        """Preflight one deadline update without mutating heap or columns."""

        if type(handle) is not int or handle < 0 or handle > _COMPACT_HANDLE_LIMIT:
            raise StateError("local artifact deadline handle exceeds 32 bits")
        if not math.isfinite(deadline):
            raise StateError("local artifact deadline must be finite")
        generation = 1 if handle >= len(self._generations) else self._generations[handle] + 1
        if generation > _COMPACT_HANDLE_LIMIT:
            raise StateError("local artifact deadline generation exhausted 32 bits")
        if self._order_counter >= (1 << 64) - 1:
            raise StateError("local artifact deadline insertion order exhausted 64 bits")
        deadline_us = int(round(deadline * 1_000_000))
        if not -(1 << 63) <= deadline_us < (1 << 63):
            raise StateError("local artifact deadline exceeds signed 64-bit microseconds")

    def pop(self, handle: int, default: bool | None = None) -> bool | None:
        if (
            handle < 0
            or handle >= len(self._deadlines)
            or self._deadlines[handle] == _EMPTY_ARTIFACT_DEADLINE
        ):
            return default
        self._deadlines[handle] = _EMPTY_ARTIFACT_DEADLINE
        self._orders[handle] = 0
        self._live -= 1
        return True

    @staticmethod
    def _entry_fields(entry: tuple[int, int, int, int]) -> tuple[int, int, int]:
        deadline_us, _order, handle, generation = entry
        return deadline_us, generation, handle

    def pop_earliest(self) -> tuple[int, int, int, int] | None:
        while self._heap_size:
            entry = self._heap_pop()
            deadline_us, order, handle, generation = entry
            if (
                handle < len(self._deadlines)
                and self._deadlines[handle] == deadline_us
                and self._generations[handle] == generation
                and self._orders[handle] == order
            ):
                return entry
        return None

    def restore(self, entry: tuple[int, int, int, int]) -> None:
        self._heap_push(entry)

    def expire_before(self, cutoff: float, *, inclusive: bool = False) -> list[int]:
        expired: list[int] = []
        cutoff_us = int(round(cutoff * 1_000_000))
        while self._heap_size:
            deadline_us = self._heap_deadlines[0]
            if deadline_us > cutoff_us or (deadline_us == cutoff_us and not inclusive):
                break
            entry = self.pop_earliest()
            if entry is None:
                break
            deadline_us, _generation, handle = self._entry_fields(entry)
            if deadline_us > cutoff_us or (deadline_us == cutoff_us and not inclusive):
                self.restore(entry)
                break
            if self.pop(handle) is not None:
                expired.append(handle)
        return expired

    def compact(self, *, force: bool = False) -> int:
        """Drop stale heap rows with work bounded by one owner shard."""

        if not force and self._heap_size <= max(self._live * 2, self._live + 64):
            return 0
        work = self._heap_size
        capacity = len(self._deadlines)
        self._heap_deadlines = array("q", [0]) * capacity
        self._heap_orders = array("Q", [0]) * capacity
        self._heap_handles = array("I", [0]) * capacity
        self._heap_generations = array("I", [0]) * capacity
        self._heap_size = 0
        for handle, deadline_us in enumerate(self._deadlines):
            if deadline_us == _EMPTY_ARTIFACT_DEADLINE:
                continue
            self._heap_push(
                (
                    deadline_us,
                    self._orders[handle],
                    handle,
                    self._generations[handle],
                )
            )
        return work

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        estimated = 0
        if estimate_bytes:
            estimated = sum(
                sys.getsizeof(value)
                for value in (
                    self,
                    self._deadlines,
                    self._generations,
                    self._orders,
                    self._heap_deadlines,
                    self._heap_orders,
                    self._heap_handles,
                    self._heap_generations,
                )
            )
        return IndexMetrics(
            live_entries=self._live,
            backing_entries=self._heap_size,
            stale_entries=max(0, self._heap_size - self._live),
            allocated_slots=len(self._deadlines),
            high_water_mark=self._high_water,
            estimated_bytes=estimated,
        )


class _LocalArtifactShard:
    """One stable artifact-version ownership shard with caller-owned locking."""

    __slots__ = (
        "deadlines",
        "leases",
        "lock",
        "mutation_version",
        "pending_expiry",
        "shard_id",
        "store",
    )

    def __init__(self, shard_id: int, capacity: int) -> None:
        self.shard_id = shard_id
        self.lock = RLock()
        self.store = _PackedArtifactStore(capacity)
        self.deadlines = _CompactArtifactDeadlines(capacity)
        self.leases: ReferenceLeaseIndex[str, str] = ReferenceLeaseIndex()
        self.pending_expiry: set[str] = set()
        self.mutation_version = 0


class _ArtifactRouteShard:
    """One bounded route partition from compact version ID to packed locator."""

    __slots__ = ("high_water", "lock", "routes")

    def __init__(self) -> None:
        self.lock = RLock()
        self.routes: dict[bytes, int] = {}
        self.high_water = 0


def _pack_artifact_locator(shard_id: int, handle: int) -> int:
    """Pack one bounded owner shard and local artifact handle."""

    if any(value < 0 or value > _COMPACT_HANDLE_LIMIT for value in (shard_id, handle)):
        raise StateError("local artifact locator exceeds its 32-bit packed fields")
    return (shard_id << _COMPACT_HANDLE_BITS) | handle


def _unpack_artifact_locator(locator: int) -> tuple[int, int]:
    """Return owner shard and local handle from one packed locator."""

    return locator >> _COMPACT_HANDLE_BITS, locator & _COMPACT_HANDLE_LIMIT


def _aggregate_index_metrics(metrics: Iterable[IndexMetrics]) -> IndexMetrics:
    """Combine a fixed shard set without losing primary-map compaction telemetry."""

    values = tuple(metrics)
    return IndexMetrics(
        live_entries=sum(metric.live_entries for metric in values),
        backing_entries=sum(metric.backing_entries for metric in values),
        stale_entries=sum(metric.stale_entries for metric in values),
        allocated_slots=sum(metric.allocated_slots for metric in values),
        secondary_buckets=sum(metric.secondary_buckets for metric in values),
        max_bucket_size=max((metric.max_bucket_size for metric in values), default=0),
        high_water_mark=sum(metric.high_water_mark for metric in values),
        lookup_candidates_inspected=sum(metric.lookup_candidates_inspected for metric in values),
        compaction_work=sum(metric.compaction_work for metric in values),
        compaction_seconds=sum(metric.compaction_seconds for metric in values),
        estimated_bytes=sum(metric.estimated_bytes for metric in values),
        primary_map_entries=sum(metric.primary_map_entries for metric in values),
        primary_map_backing_bytes=sum(metric.primary_map_backing_bytes for metric in values),
        primary_compaction_pending=any(metric.primary_compaction_pending for metric in values),
        primary_compaction_rotations=sum(metric.primary_compaction_rotations for metric in values),
        primary_compaction_work=sum(metric.primary_compaction_work for metric in values),
        primary_compaction_seconds=sum(metric.primary_compaction_seconds for metric in values),
    )


def _json_row(values: tuple[object, ...]) -> bytes:
    return json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _pack_binary_release(value: BinaryReleaseIdentity) -> bytes:
    pe = value.pe_version_info
    return _json_row(
        (
            value.key.product_id,
            value.key.version,
            value.key.build,
            value.key.architecture,
            value.key.platform,
            value.key.artifact_name,
            value.key.variant,
            None
            if pe is None
            else (
                pe.file_version,
                pe.description,
                pe.product,
                pe.company,
                pe.original_filename,
            ),
            value.release_id,
            value.content_id,
            value.digests.md5,
            value.digests.sha1,
            value.digests.sha256,
            value.digests.imphash,
        )
    )


def _unpack_binary_release(row: bytes) -> BinaryReleaseIdentity:
    values = cast(list[object], json.loads(row))
    pe_values = cast(list[str] | None, values[7])
    key = object.__new__(BinaryReleaseKey)
    for field_name, value in zip(
        ("product_id", "version", "build", "architecture", "platform", "artifact_name", "variant"),
        values[:7],
        strict=True,
    ):
        object.__setattr__(key, field_name, value)
    pe: PeVersionInfo | None = None
    if pe_values is not None:
        pe = object.__new__(PeVersionInfo)
        for field_name, value in zip(
            ("file_version", "description", "product", "company", "original_filename"),
            pe_values,
            strict=True,
        ):
            object.__setattr__(pe, field_name, value)
    digests = object.__new__(ContentDigests)
    for field_name, value in zip(
        ("md5", "sha1", "sha256", "imphash"),
        values[10:14],
        strict=True,
    ):
        object.__setattr__(digests, field_name, value)
    identity = object.__new__(BinaryReleaseIdentity)
    object.__setattr__(identity, "key", key)
    object.__setattr__(identity, "pe_version_info", pe)
    object.__setattr__(identity, "release_id", values[8])
    object.__setattr__(identity, "content_id", values[9])
    object.__setattr__(identity, "digests", digests)
    object.__setattr__(identity, "identity_kind", "installed_release")
    return identity


def _pack_installed_release(value: InstalledSoftwareReleaseIdentity) -> bytes:
    return _json_row(
        (
            value.product_id,
            value.name,
            value.publisher,
            value.version,
            value.build,
            value.architecture,
            value.platform,
            value.scope,
        )
    )


def _unpack_installed_release(row: bytes) -> InstalledSoftwareReleaseIdentity:
    values = cast(list[str], json.loads(row))
    return InstalledSoftwareReleaseIdentity(
        product_id=values[0],
        name=values[1],
        publisher=values[2],
        version=values[3],
        build=values[4],
        architecture=cast(Architecture, values[5]),
        platform=cast(Platform, values[6]),
        scope=cast(str, values[7]),
    )


def _pack_user_profile(value: UserProfileIdentity) -> bytes:
    return _json_row(
        (
            value.hostname,
            value.principal,
            value.platform,
            value.profile_name,
            value.profile_root,
        )
    )


def _unpack_user_profile(row: bytes) -> UserProfileIdentity:
    values = cast(list[str], json.loads(row))
    return UserProfileIdentity(
        hostname=values[0],
        principal=values[1],
        platform=cast(Platform, values[2]),
        profile_name=values[3],
        profile_root=values[4],
    )


def _pack_application_profile(value: ApplicationProfileIdentity) -> bytes:
    return _json_row(
        (
            value.hostname,
            value.principal,
            value.platform,
            value.user_profile_id,
            value.installation_id,
            value.application_id,
            value.profile_name,
            value.profile_root,
        )
    )


def _unpack_application_profile(row: bytes) -> ApplicationProfileIdentity:
    values = cast(list[str], json.loads(row))
    return ApplicationProfileIdentity(
        hostname=values[0],
        principal=values[1],
        platform=cast(Platform, values[2]),
        user_profile_id=values[3],
        installation_id=values[4],
        application_id=values[5],
        profile_name=values[6],
        profile_root=values[7],
    )


def _pack_application_descriptor(value: CompiledApplicationDescriptor) -> bytes:
    return _json_row(
        (
            value.application_id,
            value.platform,
            value.image_path,
            value.command_templates,
            value.categories,
            value.command_parameter_pools,
            value.singleton_per_session,
            value.selection_ordinal,
        )
    )


def _unpack_application_descriptor(row: bytes) -> CompiledApplicationDescriptor:
    values = cast(list[object], json.loads(row))
    return CompiledApplicationDescriptor(
        application_id=cast(str, values[0]),
        platform=cast(Platform, values[1]),
        image_path=cast(str, values[2]),
        command_templates=tuple(cast(list[str], values[3])),
        categories=tuple(cast(list[str], values[4])),
        command_parameter_pools=tuple(
            (cast(str, pool[0]), tuple(cast(list[str], pool[1])))
            for pool in cast(list[list[object]], values[5])
        ),
        singleton_per_session=cast(bool, values[6]),
        selection_ordinal=cast(int, values[7]),
    )


def _pack_file_content(value: FileContentIdentity) -> bytes:
    return _json_row(
        (
            value.file_object_id,
            value.version,
            value.size_bytes,
            value.mime_type,
            value.seed_ref,
        )
    )


def _unpack_file_content(row: bytes) -> FileContentIdentity:
    values = cast(list[object], json.loads(row))
    return FileContentIdentity(
        file_object_id=cast(str, values[0]),
        version=cast(int, values[1]),
        size_bytes=cast(int, values[2]),
        mime_type=cast(str, values[3]),
        seed_ref=cast(str, values[4]),
    )


def _pack_local_artifact(value: LocalArtifactIdentity) -> bytes:
    return _json_row(
        (
            value.hostname,
            value.principal,
            value.platform,
            value.user_profile_id,
            value.application_profile_id,
            value.application_id,
            value.family,
            value.source_object_id,
            value.native_path,
            value.content_id,
            value.slot,
            value.version,
        )
    )


def _unpack_local_artifact(row: bytes) -> LocalArtifactIdentity:
    values = cast(list[object], json.loads(row))
    return LocalArtifactIdentity(
        hostname=cast(str, values[0]),
        principal=cast(str, values[1]),
        platform=cast(Platform, values[2]),
        user_profile_id=cast(str, values[3]),
        application_profile_id=cast(str, values[4]),
        application_id=cast(str, values[5]),
        family=cast(str, values[6]),
        source_object_id=cast(str, values[7]),
        native_path=cast(str, values[8]),
        content_id=cast(str, values[9]),
        slot=cast(str, values[10]),
        version=cast(int, values[11]),
    )


def _pack_host_deployment(value: HostDeployment) -> bytes:
    return _json_row(
        (
            value.deployment_id,
            value.hostname,
            value.roles,
            value.platform,
            value.os_build,
            value.architecture,
            value.installation_handles,
            value.service_handles,
            value.task_handles,
            value.module_handles,
        )
    )


def _unpack_host_deployment(row: bytes) -> HostDeployment:
    values = cast(list[object], json.loads(row))
    return HostDeployment(
        deployment_id=cast(str, values[0]),
        hostname=cast(str, values[1]),
        roles=tuple(cast(list[str], values[2])),
        platform=cast(Platform, values[3]),
        os_build=cast(str, values[4]),
        architecture=cast(Architecture, values[5]),
        installation_handles=tuple(cast(list[int], values[6])),
        service_handles=tuple(cast(list[int], values[7])),
        task_handles=tuple(cast(list[int], values[8])),
        module_handles=tuple(cast(list[int], values[9])),
    )


def _pack_user_assignment(value: UserApplicationAssignment) -> bytes:
    return _json_row(
        (
            value.assignment_id,
            value.hostname,
            value.principal,
            value.materialization_principal,
            value.platform,
            value.user_profile_id,
            value.application_profile_id,
            value.application_id,
            value.product_id,
            value.release_id,
            value.persona,
            value.eligible_categories,
            value.intensity,
            value.host_deployment_handle,
            value.user_profile_handle,
            value.installation_handle,
            value.application_profile_handle,
            value.selection_weight,
            value.selection_ordinal,
        )
    )


def _unpack_user_assignment(row: bytes) -> UserApplicationAssignment:
    """Reconstruct a canonical assignment from a registry-owned trusted row.

    Rows enter this store only after ``UserApplicationAssignment`` validation and
    are immutable after sealing.  Runtime owner lookups therefore must not rerun
    normalization or validation for every generated event.
    """

    values = cast(list[object], json.loads(row))
    assignment = object.__new__(UserApplicationAssignment)
    for field_name, value in zip(
        (
            "assignment_id",
            "hostname",
            "principal",
            "materialization_principal",
            "platform",
            "user_profile_id",
            "application_profile_id",
            "application_id",
            "product_id",
            "release_id",
            "persona",
        ),
        values[:11],
        strict=True,
    ):
        object.__setattr__(assignment, field_name, value)
    object.__setattr__(assignment, "eligible_categories", tuple(cast(list[str], values[11])))
    for field_name, value in zip(
        (
            "intensity",
            "host_deployment_handle",
            "user_profile_handle",
            "installation_handle",
            "application_profile_handle",
            "selection_weight",
            "selection_ordinal",
        ),
        values[12:],
        strict=True,
    ):
        object.__setattr__(assignment, field_name, value)
    return assignment


class DeploymentContentRegistry:
    """Scenario-scoped immutable deployment and content identity registry."""

    __slots__ = (
        "_application_descriptor_ids_by_executable",
        "_application_descriptors",
        "_application_executable_links",
        "_application_executable_max_bucket",
        "_application_profiles",
        "_assignment_category_cumulative_weights",
        "_assignment_category_handles",
        "_assignment_category_links",
        "_assignment_category_lookup_candidates",
        "_assignment_category_max_bucket",
        "_binary_host_handles",
        "_binary_native_path_handles",
        "_binary_path_index",
        "_binary_principal_handles",
        "_browser_affinity_positions",
        "_file_contents",
        "_host_installation_links",
        "_host_module_links",
        "_host_deployments",
        "_host_service_links",
        "_host_task_links",
        "_installations",
        "_installed_software_releases",
        "_local_artifact_path_index",
        "_local_artifacts",
        "_releases",
        "_scale_estimated_bytes",
        "_scale_estimated_index_bytes",
        "_services",
        "_tasks",
        "_user_assignments",
        "_user_profiles",
    )

    def __init__(
        self,
        *,
        binary_releases: Iterable[BinaryReleaseIdentity] = (),
        installed_software_releases: Iterable[InstalledSoftwareReleaseIdentity] = (),
        user_profiles: Iterable[UserProfileIdentity] = (),
        installations: Iterable[SoftwareInstallationIdentity] = (),
        application_profiles: Iterable[ApplicationProfileIdentity] = (),
        application_descriptors: Iterable[CompiledApplicationDescriptor] = (),
        host_deployments: Iterable[HostDeploymentSpec] = (),
        user_application_assignments: Iterable[UserApplicationAssignmentSpec] = (),
        file_contents: Iterable[FileContentIdentity] = (),
        local_artifacts: Iterable[LocalArtifactIdentity] = (),
    ) -> None:
        """Compile immutable identities into exact compact indexes."""

        preserve_release_identity = isinstance(binary_releases, Sequence)
        preserve_installed_release_identity = isinstance(
            installed_software_releases,
            Sequence,
        )
        preserve_user_profile_identity = isinstance(user_profiles, Sequence)
        preserve_application_profile_identity = isinstance(application_profiles, Sequence)
        preserve_host_deployment_identity = isinstance(host_deployments, Sequence)
        preserve_assignment_identity = isinstance(user_application_assignments, Sequence)
        preserve_file_content_identity = isinstance(file_contents, Sequence)
        self._releases = _PackedFrozenIndexedStore[
            BinaryReleaseCanonicalKey, BinaryReleaseIdentity
        ](
            pack=_pack_binary_release,
            unpack=_unpack_binary_release,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=preserve_release_identity,
            content_id=lambda item: item.content_id,
            release_id=lambda item: item.release_id,
            release_artifact=lambda item: (item.release_id, item.key.artifact_name),
        )
        self._installed_software_releases = _PackedFrozenIndexedStore[
            InstalledSoftwareReleaseCanonicalKey,
            InstalledSoftwareReleaseIdentity,
        ](
            pack=_pack_installed_release,
            unpack=_unpack_installed_release,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=preserve_installed_release_identity,
            release_id=lambda item: item.release_id,
            product_id=lambda item: item.product_id,
            placement=lambda item: (item.platform, item.architecture, item.scope),
            placement_product=lambda item: (
                item.platform,
                item.architecture,
                item.scope,
                item.product_id,
            ),
        )
        self._user_profiles = _PackedFrozenIndexedStore[
            UserProfileCanonicalKey, UserProfileIdentity
        ](
            pack=_pack_user_profile,
            unpack=_unpack_user_profile,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=preserve_user_profile_identity,
            profile_id=lambda item: item.profile_id,
            host=lambda item: item.hostname,
            host_principal=lambda item: (item.hostname, item.principal),
        )
        self._binary_host_handles = _PlatformStringInterner()
        self._binary_principal_handles = _PlatformStringInterner()
        self._binary_native_path_handles = _PlatformStringInterner()
        self._installations = _PackedInstallationStore(self._binary_host_handles)
        self._application_profiles = _PackedFrozenIndexedStore[
            ApplicationProfileCanonicalKey, ApplicationProfileIdentity
        ](
            pack=_pack_application_profile,
            unpack=_unpack_application_profile,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=preserve_application_profile_identity,
            application_profile_id=lambda item: item.application_profile_id,
            user_profile=lambda item: item.user_profile_id,
            installation=lambda item: item.installation_id,
        )
        self._application_descriptors = _PackedFrozenIndexedStore[
            tuple[str, Platform], CompiledApplicationDescriptor
        ](
            pack=_pack_application_descriptor,
            unpack=_unpack_application_descriptor,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=True,
            preserve_identity_limit=None,
        )
        self._application_descriptor_ids_by_executable: dict[
            tuple[Platform, str], tuple[str, ...]
        ] = {}
        self._application_executable_links = 0
        self._application_executable_max_bucket = 0
        self._file_contents = _PackedFrozenIndexedStore[
            FileVersionCanonicalKey, FileContentIdentity
        ](
            pack=_pack_file_content,
            unpack=_unpack_file_content,
            primary_key=lambda item: item.canonical_key,
            preserve_identity=preserve_file_content_identity,
            content_id=lambda item: item.content_id,
            file_version_id=lambda item: item.file_version_id,
            file_object=lambda item: item.file_object_id,
        )
        self._local_artifacts = _PackedFrozenIndexedStore[
            LocalArtifactCanonicalKey, LocalArtifactIdentity
        ](
            pack=_pack_local_artifact,
            unpack=_unpack_local_artifact,
            primary_key=lambda item: item.canonical_key,
            artifact_version_id=lambda item: item.artifact_version_id,
            artifact_object=lambda item: item.artifact_id,
            application_profile=lambda item: item.application_profile_id,
        )
        self._services = _PackedFrozenIndexedStore[str, str](
            pack=lambda value: value.encode("utf-8"),
            unpack=lambda row: row.decode("utf-8"),
            primary_key=lambda value: value,
        )
        self._tasks = _PackedFrozenIndexedStore[str, str](
            pack=lambda value: value.encode("utf-8"),
            unpack=lambda row: row.decode("utf-8"),
            primary_key=lambda value: value,
        )
        self._host_deployments = _PackedFrozenIndexedStore[str, HostDeployment](
            pack=_pack_host_deployment,
            unpack=_unpack_host_deployment,
            primary_key=lambda item: item.hostname,
            preserve_identity=preserve_host_deployment_identity,
            deployment_id=lambda item: item.deployment_id,
            platform=lambda item: item.platform,
        )
        self._user_assignments = _PackedFrozenIndexedStore[str, UserApplicationAssignment](
            pack=_pack_user_assignment,
            unpack=_unpack_user_assignment,
            primary_key=lambda item: item.assignment_id,
            preserve_identity=preserve_assignment_identity,
            profile=lambda item: item.user_profile_id,
            profile_application=lambda item: (
                item.user_profile_id,
                item.application_profile_id,
            ),
            profile_application_id=lambda item: (
                item.user_profile_id,
                item.application_id,
            ),
            host_product=lambda item: (item.hostname, item.product_id),
            host_release=lambda item: (item.hostname, item.release_id),
            persona=lambda item: item.persona,
        )
        self._assignment_category_handles: dict[tuple[str, str], array[int]] = {}
        self._assignment_category_cumulative_weights: dict[tuple[str, str], array[int]] = {}
        self._browser_affinity_positions: dict[str, int] = {}
        self._assignment_category_links = 0
        self._assignment_category_lookup_candidates = 0
        self._assignment_category_max_bucket = 0
        self._host_installation_links = 0
        self._host_service_links = 0
        self._host_task_links = 0
        self._host_module_links = 0
        self._scale_estimated_index_bytes = 0
        self._scale_estimated_bytes = 0
        self._binary_path_index: dict[int, int] = {}
        self._local_artifact_path_index = _PackedDigestGroupIndex()

        self._compile_releases(binary_releases)
        self._compile_installed_software_releases(installed_software_releases)
        self._installed_software_releases.seal()
        self._compile_user_profiles(user_profiles)
        self._compile_installations(installations)
        self._compile_application_profiles(application_profiles)
        self._compile_application_descriptors(application_descriptors)
        self._compile_host_deployments(host_deployments)
        self._releases.seal()
        self._services.seal()
        self._tasks.seal()
        self._compile_user_application_assignments(user_application_assignments)
        self._seal_user_application_assignment_indexes()
        self._host_deployments.seal()
        self._user_assignments.seal()
        self._compile_file_contents(file_contents)
        self._compile_local_artifacts(local_artifacts)
        for store in (
            self._releases,
            self._installed_software_releases,
            self._user_profiles,
            self._application_profiles,
            self._application_descriptors,
            self._file_contents,
            self._local_artifacts,
            self._host_deployments,
            self._user_assignments,
        ):
            store.seal()
        self._scale_estimated_index_bytes = self._estimate_scale_index_bytes()
        self._scale_estimated_bytes = self._estimate_scale_retained_bytes()
        self._scale_estimated_index_bytes = min(
            self._scale_estimated_index_bytes,
            self._scale_estimated_bytes,
        )

    def _estimate_scale_retained_bytes(self) -> int:
        """Return an explicit constant-time sum of registry-owned packed backing."""

        packed_stores = (
            self._releases,
            self._installed_software_releases,
            self._user_profiles,
            self._application_profiles,
            self._application_descriptors,
            self._file_contents,
            self._local_artifacts,
            self._host_deployments,
            self._user_assignments,
        )
        return (
            sum(store.estimated_bytes() for store in packed_stores)
            + self._installations.estimated_bytes()
            + self._services.estimated_bytes()
            + self._tasks.estimated_bytes()
            + self.binary_path_index_census(estimate_bytes=True).estimated_bytes
            + self.assignment_category_index_census(estimate_bytes=True).estimated_bytes
            + _owned_graph_size(self._application_descriptor_ids_by_executable)
            + self._local_artifact_path_index.estimated_bytes()
        )

    def _estimate_scale_index_bytes(self) -> int:
        """Compute the immutable registry's retained exact-index estimate once."""

        packed_stores = (
            self._releases,
            self._installed_software_releases,
            self._user_profiles,
            self._application_profiles,
            self._application_descriptors,
            self._file_contents,
            self._local_artifacts,
            self._host_deployments,
            self._user_assignments,
        )
        return (
            sum(store.estimated_index_bytes() for store in packed_stores)
            + self._services.estimated_index_bytes()
            + self._tasks.estimated_index_bytes()
            + self._installations.estimated_index_bytes()
            + self.binary_path_index_census(estimate_bytes=True).estimated_bytes
            + self.assignment_category_index_census(estimate_bytes=True).estimated_bytes
            + _owned_graph_size(self._application_descriptor_ids_by_executable)
            + self._local_artifact_path_index.estimated_bytes()
        )

    def _iter_group(
        self,
        store: CompactIndexedStore[K, V],
        queries: tuple[tuple[str, Hashable], ...],
    ) -> Iterator[V]:
        for index_name, indexed_value in queries:
            yield from store.find_iter(index_name, indexed_value)

    def _count_group(
        self,
        store: CompactIndexedStore[K, V],
        queries: tuple[tuple[str, Hashable], ...],
    ) -> int:
        return sum(store.count(index_name, indexed_value) for index_name, indexed_value in queries)

    def _page_group(
        self,
        store: CompactIndexedStore[K, V],
        group_name: str,
        queries: tuple[tuple[str, Hashable], ...],
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None,
    ) -> tuple[tuple[V, ...], DeploymentGroupPageCursor | None]:
        if limit <= 0:
            raise ValueError("deployment group page limit must be positive")
        if cursor is None:
            query_position = 0
            after_handle = None
        elif (
            cursor._registry_token != id(self)
            or cursor._group_name != group_name
            or cursor._queries != queries
        ):
            raise ValueError("deployment group page cursor belongs to another query")
        else:
            query_position = cursor._query_position
            after_handle = cursor._after_handle

        page: list[V] = []
        next_position: int | None = None
        next_after_handle: int | None = None
        while query_position < len(queries) and len(page) < limit:
            index_name, indexed_value = queries[query_position]
            handles, next_handle = store.find_handle_page(
                index_name,
                indexed_value,
                after_handle=after_handle,
                limit=limit - len(page),
            )
            page.extend(store.get_by_handle(handle) for handle in handles)
            if next_handle is not None:
                next_position = query_position
                next_after_handle = next_handle
                break
            query_position += 1
            after_handle = None

        if len(page) == limit and next_position is None:
            while query_position < len(queries):
                index_name, indexed_value = queries[query_position]
                if store.count(index_name, indexed_value):
                    next_position = query_position
                    break
                query_position += 1
        next_cursor = None
        if next_position is not None:
            next_cursor = DeploymentGroupPageCursor(
                registry_token=id(self),
                group_name=group_name,
                queries=queries,
                query_position=next_position,
                after_handle=next_after_handle,
            )
        return tuple(page), next_cursor

    def _page_handle_group(
        self,
        store: CompactIndexedStore[K, V],
        handles: tuple[int, ...],
        group_name: str,
        query: Hashable,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None,
    ) -> tuple[tuple[V, ...], DeploymentGroupPageCursor | None]:
        if limit <= 0:
            raise ValueError("deployment group page limit must be positive")
        queries = (("handles", query),)
        if cursor is None:
            start = 0
        elif (
            cursor._registry_token != id(self)
            or cursor._group_name != group_name
            or cursor._queries != queries
        ):
            raise ValueError("deployment group page cursor belongs to another query")
        else:
            start = cursor._after_handle or 0
        stop = min(start + limit, len(handles))
        page = tuple(store.get_by_handle(handle) for handle in handles[start:stop])
        next_cursor = None
        if stop < len(handles):
            next_cursor = DeploymentGroupPageCursor(
                registry_token=id(self),
                group_name=group_name,
                queries=queries,
                query_position=0,
                after_handle=stop,
            )
        return page, next_cursor

    def _compile_releases(self, releases: Iterable[BinaryReleaseIdentity]) -> None:
        for release in releases:
            _require_unique_index(
                self._releases,
                "content_id",
                release.content_id,
                "binary content_id",
            )
            release_artifact_key = (release.release_id, release.key.artifact_name)
            _require_unique_index(
                self._releases,
                "release_artifact",
                release_artifact_key,
                "release artifact",
            )
            _insert_unique(
                self._releases,
                release.canonical_key,
                release,
                "binary release",
            )

    def _compile_installed_software_releases(
        self,
        releases: Iterable[InstalledSoftwareReleaseIdentity],
    ) -> None:
        for release in releases:
            _require_unique_index(
                self._installed_software_releases,
                "release_id",
                release.release_id,
                "installed software release_id",
            )
            _insert_unique(
                self._installed_software_releases,
                release.canonical_key,
                release,
                "installed software release",
            )

    def _compile_user_profiles(self, profiles: Iterable[UserProfileIdentity]) -> None:
        for profile in profiles:
            _require_unique_index(
                self._user_profiles,
                "profile_id",
                profile.profile_id,
                "user profile_id",
            )
            _insert_unique(
                self._user_profiles,
                profile.canonical_key,
                profile,
                "user profile",
            )

    def _compile_installations(
        self,
        installations: Iterable[SoftwareInstallationIdentity],
    ) -> None:
        for source in installations:
            installation = _canonical_software_installation(source)
            if installation.platform != "windows" and any(
                "\\" in image_path for image_path in installation.image_paths
            ):
                raise ValueError(
                    "compiled POSIX application installation image_paths cannot contain backslashes"
                )
            release_artifacts = tuple(
                self._releases.find_iter("release_id", installation.release_id)
            )
            if not release_artifacts:
                raise ValueError(
                    f"installation {installation.installation_id!r} references unknown "
                    f"release_id {installation.release_id!r}"
                )
            if any(item.key.platform != installation.platform for item in release_artifacts):
                raise ValueError(
                    "installation platform must match every referenced release artifact"
                )
            if installation.scope == "user":
                user_profile = self.user_profile_by_id(installation.user_profile_id)
                if user_profile is None:
                    raise ValueError(
                        f"installation references unknown user profile "
                        f"{installation.user_profile_id!r}"
                    )
                if (
                    user_profile.hostname != installation.hostname
                    or user_profile.principal != installation.principal
                    or user_profile.platform != installation.platform
                ):
                    raise ValueError("user-scoped installation must match its owning user profile")

            product_ids = {artifact.key.product_id for artifact in release_artifacts}
            if len(product_ids) != 1:
                raise ValueError("one release_id cannot span multiple product identities")
            installation_handle = self._installations.add(
                installation,
                next(iter(product_ids)),
            )
            host_handle = self._binary_host_handles.find(
                installation.platform,
                installation.hostname,
            )
            if host_handle is None:  # pragma: no cover - packed store interns the host
                raise AssertionError("installation host was not interned")
            principal_handle = (
                self._binary_principal_handles.intern(
                    installation.platform,
                    installation.principal,
                )
                if installation.principal
                else 0
            )
            for path, normalized_path in zip(
                installation.image_paths,
                installation.normalized_image_paths,
                strict=True,
            ):
                release_artifact_key = (
                    installation.release_id,
                    _artifact_name(path, installation.platform),
                )
                release_artifact = self._releases.find_one(
                    "release_artifact",
                    release_artifact_key,
                )
                if release_artifact is None:
                    raise ValueError(
                        f"installation path {path!r} has no exact artifact in release "
                        f"{installation.release_id!r}"
                    )
                release_handle = self._releases.handle_for(release_artifact.canonical_key)
                native_path_handle = self._binary_native_path_handles.intern(
                    installation.platform,
                    normalized_path,
                )
                path_key = _packed_binary_path_key(
                    host_handle,
                    principal_handle,
                    native_path_handle,
                )
                existing_binding = self._binary_path_index.get(path_key)
                if existing_binding is not None:
                    _existing_installation_handle, existing_release_handle = _unpack_binary_binding(
                        existing_binding
                    )
                    if existing_release_handle == release_handle:
                        # Multiple logical catalog applications can be entry points to the
                        # same physical executable (for example ``python -m pip`` and
                        # ``python -m pytest``). Preserve each application installation and
                        # profile, but compile only one exact path-to-content binding.
                        continue
                    raise ValueError(
                        "duplicate installation path binding for exact host, principal, and "
                        f"native path: {installation.hostname!r}, "
                        f"{installation.principal!r}, {normalized_path!r}"
                    )
                self._binary_path_index[path_key] = _packed_binary_binding(
                    installation_handle,
                    release_handle,
                )

    def _compile_application_profiles(
        self,
        profiles: Iterable[ApplicationProfileIdentity],
    ) -> None:
        for profile in profiles:
            user_profile = self.user_profile_by_id(profile.user_profile_id)
            installation = self.installation_by_id(profile.installation_id)
            if user_profile is None:
                raise ValueError(
                    f"application profile references unknown user profile "
                    f"{profile.user_profile_id!r}"
                )
            if installation is None:
                raise ValueError(
                    f"application profile references unknown installation "
                    f"{profile.installation_id!r}"
                )
            expected_principal = _normalize_principal(profile.principal, user_profile.platform)
            if (
                profile.hostname != user_profile.hostname
                or profile.platform != user_profile.platform
                or expected_principal != user_profile.principal
                or profile.application_id != installation.application_id
                or installation.hostname != user_profile.hostname
            ):
                raise ValueError(
                    "application profile host, principal, and application must match its owners"
                )
            if installation.scope == "user" and (
                installation.principal != user_profile.principal
                or installation.user_profile_id != user_profile.profile_id
            ):
                raise ValueError("application profile cannot use another user's installation")

            _require_unique_index(
                self._application_profiles,
                "application_profile_id",
                profile.application_profile_id,
                "application_profile_id",
            )
            _insert_unique(
                self._application_profiles,
                profile.canonical_key,
                profile,
                "application profile",
            )

    def _compile_application_descriptors(
        self,
        descriptors: Iterable[CompiledApplicationDescriptor],
    ) -> None:
        """Compile exact application/platform command and executable truth."""

        routes: dict[tuple[Platform, str], list[tuple[int, str]]] = {}
        descriptor_count = 0
        retained_text_bytes = 0
        for source in descriptors:
            if type(source) is not CompiledApplicationDescriptor:
                raise ValueError(
                    "application_descriptors must contain exact "
                    "CompiledApplicationDescriptor values"
                )
            descriptor_count += 1
            if descriptor_count > _MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT:
                raise ValueError("application_descriptors exceeds the bounded registry count")
            descriptor = CompiledApplicationDescriptor(
                application_id=source.application_id,
                platform=source.platform,
                image_path=source.image_path,
                command_templates=source.command_templates,
                categories=source.categories,
                command_parameter_pools=source.command_parameter_pools,
                singleton_per_session=source.singleton_per_session,
                selection_ordinal=source.selection_ordinal,
            )
            retained_text_bytes += descriptor.retained_text_bytes
            if retained_text_bytes > _MAX_APPLICATION_DESCRIPTOR_REGISTRY_TEXT_BYTES:
                raise ValueError("application_descriptors exceeds the bounded registry text budget")
            _insert_unique(
                self._application_descriptors,
                descriptor.canonical_key,
                descriptor,
                "compiled application descriptor",
            )
            routes.setdefault((descriptor.platform, descriptor.executable), []).append(
                (descriptor.selection_ordinal, descriptor.application_id)
            )
        self._application_descriptor_ids_by_executable = {
            key: tuple(
                application_id
                for _ordinal, application_id in sorted(
                    values,
                    key=lambda value: (value[0], value[1]),
                )
            )
            for key, values in routes.items()
        }
        self._application_executable_links = sum(
            len(application_ids)
            for application_ids in self._application_descriptor_ids_by_executable.values()
        )
        self._application_executable_max_bucket = max(
            (
                len(application_ids)
                for application_ids in self._application_descriptor_ids_by_executable.values()
            ),
            default=0,
        )

    def _compile_host_deployments(self, specs: Iterable[HostDeploymentSpec]) -> None:
        for spec in specs:
            installation_handles: list[int] = []
            for installation_id in spec.installation_ids:
                installation = self.installation_by_id(installation_id)
                if installation is None:
                    raise ValueError(
                        f"host deployment references unknown installation {installation_id!r}"
                    )
                if installation.hostname != spec.hostname or installation.platform != spec.platform:
                    raise ValueError(
                        "host deployment can contain only installations on the same host/platform"
                    )
                release_artifacts = self._releases.find_iter(
                    "release_id",
                    installation.release_id,
                )
                if any(
                    not _architecture_is_compatible(spec.architecture, artifact.key.architecture)
                    for artifact in release_artifacts
                ):
                    raise ValueError(
                        "host deployment installation architecture must be compatible with "
                        "the host architecture"
                    )
                installation_handles.append(
                    self._installations.handle_for(installation.canonical_key)
                )

            service_handles = tuple(
                self._intern_capability(self._services, service_id)
                for service_id in spec.service_ids
            )
            task_handles = tuple(
                self._intern_capability(self._tasks, task_id) for task_id in spec.task_ids
            )
            module_handles: list[int] = []
            for content_id in spec.module_content_ids:
                module = self.binary_release_by_content_id(content_id)
                if module is None:
                    raise ValueError(
                        f"host deployment references unknown module content_id {content_id!r}"
                    )
                if module.key.platform != spec.platform:
                    raise ValueError("host deployment module platform must match the host platform")
                if not _architecture_is_compatible(spec.architecture, module.key.architecture):
                    raise ValueError(
                        "host deployment module architecture must be compatible with the host "
                        "architecture"
                    )
                module_handles.append(self._releases.handle_for(module.canonical_key))

            deployment = HostDeployment(
                deployment_id=spec.deployment_id,
                hostname=spec.hostname,
                roles=spec.roles,
                platform=spec.platform,
                os_build=spec.os_build,
                architecture=spec.architecture,
                installation_handles=tuple(installation_handles),
                service_handles=service_handles,
                task_handles=task_handles,
                module_handles=tuple(module_handles),
            )
            _require_unique_index(
                self._host_deployments,
                "deployment_id",
                deployment.deployment_id,
                "host deployment_id",
            )
            _insert_unique(
                self._host_deployments,
                deployment.hostname,
                deployment,
                "host deployment",
            )
            self._host_installation_links += len(deployment.installation_handles)
            self._host_service_links += len(deployment.service_handles)
            self._host_task_links += len(deployment.task_handles)
            self._host_module_links += len(deployment.module_handles)

    @staticmethod
    def _intern_capability(store: CompactIndexedStore[str, str], identity: str) -> int:
        existing = store.get(identity)
        if existing is None:
            store[identity] = identity
        return store.handle_for(identity)

    def _compile_user_application_assignments(
        self,
        specs: Iterable[UserApplicationAssignmentSpec],
    ) -> None:
        command_bound_cache: dict[tuple[tuple[str, Platform], int], bool] = {}
        for spec in specs:
            deployment = self.host_deployment(spec.hostname)
            user_profile = self.user_profile_by_id(spec.user_profile_id)
            application_profile = self.application_profile_by_id(spec.application_profile_id)
            if deployment is None:
                raise ValueError(
                    f"user application assignment references uncompiled host {spec.hostname!r}"
                )
            if user_profile is None or application_profile is None:
                raise ValueError(
                    "user application assignment references an unknown user/application profile"
                )
            installation = self.installation_by_id(application_profile.installation_id)
            if installation is None:  # pragma: no cover - protected by profile compilation
                raise ValueError("application profile references an unknown installation")
            materialization_principal = user_profile.principal
            if len(self._application_descriptors):
                descriptor = self._owned_application_descriptor(
                    application_profile.application_id,
                    spec.platform,
                )
                if descriptor is None:
                    raise ValueError(
                        "user application assignment references an unknown compiled "
                        f"application descriptor: {application_profile.application_id!r}, "
                        f"{spec.platform!r}"
                    )
                if spec.selection_ordinal != descriptor.selection_ordinal:
                    raise ValueError(
                        "user application assignment selection_ordinal must match its "
                        "compiled application descriptor"
                    )
                materialization_principal = _application_presentation_principal(
                    descriptor,
                    installation,
                    user_profile,
                )
                expected_image = descriptor.image_path.replace(
                    "{username}",
                    materialization_principal,
                )
                if spec.platform == "windows":
                    image_matches = canonical_native_path(
                        expected_image,
                        spec.platform,
                    ) == canonical_native_path(
                        installation.image_paths[0],
                        spec.platform,
                    )
                else:
                    image_matches = posixpath.normpath(expected_image) == posixpath.normpath(
                        installation.image_paths[0]
                    )
                if not image_matches:
                    raise ValueError(
                        "compiled application descriptor image must match the installation "
                        "primary executable"
                    )
                if descriptor.categories != spec.eligible_categories:
                    raise ValueError(
                        "compiled application descriptor categories must match the user "
                        "application assignment"
                    )
                bound_key = (descriptor.canonical_key, len(materialization_principal))
                command_is_bounded = command_bound_cache.get(bound_key)
                if command_is_bounded is None:
                    try:
                        _validate_application_command_expansion_bounds(
                            descriptor.command_templates,
                            descriptor.command_parameter_pools,
                            literal_replacements=(("username", materialization_principal),),
                        )
                    except ValueError:
                        command_is_bounded = False
                    else:
                        command_is_bounded = True
                    command_bound_cache[bound_key] = command_is_bounded
                if not command_is_bounded:
                    raise ValueError(
                        "compiled application command cannot be materialized for its assigned "
                        "principal within the bounded output contract"
                    )
            expected_principal = _normalize_principal(spec.principal, user_profile.platform)
            if (
                deployment.platform != spec.platform
                or deployment.hostname != user_profile.hostname
                or user_profile.hostname != spec.hostname
                or user_profile.principal != expected_principal
                or application_profile.user_profile_id != user_profile.profile_id
            ):
                raise ValueError(
                    "user application assignment host, principal, and profile must agree"
                )
            installation_handle = self._installations.handle_for(installation.canonical_key)
            if installation_handle not in deployment.installation_handles:
                raise ValueError(
                    "user application assignment must reference an installation in the host "
                    "deployment"
                )
            product_id = self._installations.product_id_by_handle(installation_handle)

            assignment = UserApplicationAssignment(
                assignment_id=spec.assignment_id,
                hostname=spec.hostname,
                principal=spec.principal,
                materialization_principal=materialization_principal,
                platform=spec.platform,
                user_profile_id=user_profile.profile_id,
                application_profile_id=application_profile.application_profile_id,
                application_id=application_profile.application_id,
                product_id=product_id,
                release_id=installation.release_id,
                persona=spec.persona,
                eligible_categories=spec.eligible_categories,
                intensity=spec.intensity,
                host_deployment_handle=self._host_deployments.handle_for(deployment.hostname),
                user_profile_handle=self._user_profiles.handle_for(user_profile.canonical_key),
                installation_handle=installation_handle,
                application_profile_handle=self._application_profiles.handle_for(
                    application_profile.canonical_key
                ),
                selection_weight=cast(int, spec.selection_weight),
                selection_ordinal=spec.selection_ordinal,
            )
            _require_unique_index(
                self._user_assignments,
                "profile_application",
                (assignment.user_profile_id, assignment.application_profile_id),
                "user/profile application assignment",
            )
            _insert_unique(
                self._user_assignments,
                assignment.assignment_id,
                assignment,
                "user application assignment",
            )
            assignment_handle = self._user_assignments.handle_for(assignment.assignment_id)
            for category in assignment.eligible_categories:
                key = (assignment.user_profile_id, category)
                handles = self._assignment_category_handles.get(key)
                if handles is None:
                    handles = array("I")
                    self._assignment_category_handles[key] = handles
                handles.append(assignment_handle)

    def _seal_user_application_assignment_indexes(self) -> None:
        """Sort compact category routes and compile weighted/browser selection metadata."""

        links = 0
        max_bucket = 0
        for key, handles in tuple(self._assignment_category_handles.items()):
            ordered_handles = array(
                "I",
                sorted(
                    handles,
                    key=lambda handle: (
                        self._user_assignments.get_by_handle(handle).selection_ordinal,
                        self._user_assignments.get_by_handle(handle).application_id,
                    ),
                ),
            )
            self._assignment_category_handles[key] = ordered_handles
            cumulative = array("Q")
            total = 0
            for handle in ordered_handles:
                total += self._user_assignments.get_by_handle(handle).selection_weight
                cumulative.append(total)
            self._assignment_category_cumulative_weights[key] = cumulative
            links += len(ordered_handles)
            max_bucket = max(max_bucket, len(ordered_handles))

        self._assignment_category_links = links
        self._assignment_category_max_bucket = max_bucket
        for (profile_id, category), handles in self._assignment_category_handles.items():
            if category != "browser" or not handles:
                continue
            first = self._user_assignments.get_by_handle(handles[0])
            self._browser_affinity_positions[profile_id] = _stable_seed(
                f"browser:{first.hostname}:{first.principal}:{first.user_profile_id}"
            ) % len(handles)

    def _compile_file_contents(self, contents: Iterable[FileContentIdentity]) -> None:
        for content in contents:
            canonical_descriptor = self._file_contents.find_one(
                "content_id",
                content.content_id,
            )
            if canonical_descriptor is not None and (
                canonical_descriptor.digests != content.digests
                or canonical_descriptor.size_bytes != content.size_bytes
                or canonical_descriptor.mime_type != content.mime_type
            ):
                raise ValueError(
                    f"content_id {content.content_id!r} has contradictory file size, MIME, "
                    "or digest descriptors"
                )
            _require_unique_index(
                self._file_contents,
                "file_version_id",
                content.file_version_id,
                "file_version_id",
            )
            _insert_unique(
                self._file_contents,
                content.canonical_key,
                content,
                "file content version",
            )

    def _compile_local_artifacts(self, artifacts: Iterable[LocalArtifactIdentity]) -> None:
        for source in artifacts:
            try:
                artifact = _canonical_local_artifact_identity(source)
            except StateError as exc:
                raise ValueError(str(exc)) from None
            if _has_posix_path_backslash(artifact.native_path, artifact.platform):
                raise ValueError("POSIX local artifact native_path cannot contain backslashes")
            application_profile = self.application_profile_by_id(artifact.application_profile_id)
            user_profile = self.user_profile_by_id(artifact.user_profile_id)
            if application_profile is None or user_profile is None:
                raise ValueError("local artifact references an unknown application or user profile")
            expected_principal = _normalize_principal(artifact.principal, user_profile.platform)
            if (
                artifact.hostname != user_profile.hostname
                or expected_principal != user_profile.principal
                or artifact.platform != user_profile.platform
                or artifact.application_id != application_profile.application_id
                or artifact.user_profile_id != application_profile.user_profile_id
            ):
                raise ValueError("local artifact ownership must match its application profile")
            if artifact.content_id and not self._known_content_id(artifact.content_id):
                raise ValueError(
                    f"local artifact references unknown content_id {artifact.content_id!r}"
                )

            _require_unique_index(
                self._local_artifacts,
                "artifact_version_id",
                artifact.artifact_version_id,
                "artifact_version_id",
            )
            artifact_handle = _insert_unique(
                self._local_artifacts,
                artifact.canonical_key,
                artifact,
                "local artifact version",
            )
            path_key = (
                artifact.platform,
                artifact.user_profile_id,
                artifact.application_profile_id,
                artifact.normalized_native_path,
                artifact.version,
            )
            encoded_path_key = _packed_index_key(path_key)
            if self._local_artifact_path_index.count(
                encoded_path_key,
                self._local_artifact_path_key_at,
            ):
                raise ValueError(f"duplicate local artifact path binding: {path_key!r}")
            self._local_artifact_path_index.add(
                encoded_path_key,
                artifact_handle,
                self._local_artifact_path_key_at,
            )

    def _local_artifact_path_key_at(self, handle: int) -> bytes:
        artifact = self._local_artifacts.get_by_handle(handle)
        return _packed_index_key(
            (
                artifact.platform,
                artifact.user_profile_id,
                artifact.application_profile_id,
                artifact.normalized_native_path,
                artifact.version,
            )
        )

    def _known_content_id(self, content_id: str) -> bool:
        return (
            self._releases.count("content_id", content_id) > 0
            or self._file_contents.count("content_id", content_id) > 0
        )

    def binary_release(
        self,
        key: BinaryReleaseKey | BinaryReleaseCanonicalKey,
    ) -> BinaryReleaseIdentity | None:
        """Return an exact binary artifact by its path-independent release key."""

        canonical_key = key.canonical_key if isinstance(key, BinaryReleaseKey) else key
        return self._releases.get(canonical_key)

    def binary_release_by_content_id(self, content_id: str) -> BinaryReleaseIdentity | None:
        """Return the unique binary artifact for an exact content ID."""

        return self._releases.find_one("content_id", content_id.strip())

    def binary_artifacts_for_release(self, release_id: str) -> tuple[BinaryReleaseIdentity, ...]:
        """Compatibility wrapper materializing one release's artifact group."""

        return tuple(self.iter_binary_artifacts_for_release(release_id))

    def iter_binary_artifacts_for_release(
        self,
        release_id: str,
    ) -> Iterator[BinaryReleaseIdentity]:
        """Iterate executable/module artifacts in one exact product release."""

        yield from self._releases.find_iter("release_id", release_id.strip())

    def count_binary_artifacts_for_release(self, release_id: str) -> int:
        """Return the artifact count for one exact product release."""

        return self._releases.count("release_id", release_id.strip())

    def page_binary_artifacts_for_release(
        self,
        release_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[BinaryReleaseIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of artifacts in an exact product release."""

        queries = (("release_id", release_id.strip()),)
        return self._page_group(
            self._releases,
            "binary_artifacts_for_release",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def installed_software_release_by_id(
        self,
        release_id: str,
    ) -> InstalledSoftwareReleaseIdentity | None:
        """Return one exact path-free installed-software release."""

        return self._installed_software_releases.find_one("release_id", release_id.strip())

    def _host_installed_software_queries(
        self,
        hostname: str,
        *,
        product_id: str | None = None,
    ) -> tuple[tuple[str, Hashable], ...]:
        deployment = self.host_deployment(hostname)
        if deployment is None:
            return ()
        architectures = tuple(dict.fromkeys((deployment.architecture, "neutral")))
        if product_id is None:
            return tuple(
                ("placement", (deployment.platform, architecture, "machine"))
                for architecture in architectures
            )
        product = _normalize_name(product_id, "product_id", casefold=True)
        return tuple(
            (
                "placement_product",
                (deployment.platform, architecture, "machine", product),
            )
            for architecture in architectures
        )

    def iter_installed_software_on_host(
        self,
        hostname: str,
    ) -> Iterator[InstalledSoftwareReleaseIdentity]:
        """Iterate exact architecture-compatible machine inventory descriptors."""

        yield from self._iter_group(
            self._installed_software_releases,
            self._host_installed_software_queries(hostname),
        )

    def count_installed_software_on_host(self, hostname: str) -> int:
        """Return the exact path-free installed-software count for one host."""

        return self._count_group(
            self._installed_software_releases,
            self._host_installed_software_queries(hostname),
        )

    def installed_software_on_host_at(
        self,
        hostname: str,
        ordinal: int,
    ) -> InstalledSoftwareReleaseIdentity | None:
        """Return one exact host-compatible release by stable stream ordinal."""

        if ordinal < 0:
            raise ValueError("installed software ordinal must be non-negative")
        for position, release in enumerate(self.iter_installed_software_on_host(hostname)):
            if position == ordinal:
                return release
        return None

    def page_installed_software_on_host(
        self,
        hostname: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[InstalledSoftwareReleaseIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of exact path-free host inventory descriptors."""

        normalized_host = _normalize_hostname(hostname)
        return self._page_group(
            self._installed_software_releases,
            "installed_software_on_host",
            self._host_installed_software_queries(normalized_host),
            limit=limit,
            cursor=cursor,
        )

    def installed_software_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> InstalledSoftwareReleaseIdentity | None:
        """Return one exact compatible installed product, failing on ambiguity."""

        candidates = tuple(
            self._iter_group(
                self._installed_software_releases,
                self._host_installed_software_queries(hostname, product_id=product_id),
            )
        )
        if len(candidates) > 1:
            raise ValueError(
                f"installed software product {product_id!r} has ambiguous host architecture"
            )
        return candidates[0] if candidates else None

    def user_profile_by_id(self, profile_id: str) -> UserProfileIdentity | None:
        """Return one exact user profile by its canonical ID."""

        return self._user_profiles.find_one("profile_id", profile_id.strip())

    def user_profile_for(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
        profile_name: str = "default",
    ) -> UserProfileIdentity | None:
        """Return an exact host/principal/platform profile without scanning."""

        normalized_platform = _normalize_platform(platform)
        key: UserProfileCanonicalKey = (
            _normalize_hostname(hostname),
            _normalize_principal(principal, normalized_platform),
            normalized_platform,
            _normalize_name(
                profile_name,
                "profile_name",
                casefold=normalized_platform == "windows",
            ),
        )
        return self._user_profiles.get(key)

    def installation_by_id(self, installation_id: str) -> SoftwareInstallationIdentity | None:
        """Return one exact software installation by canonical ID."""

        return self._installations.find_one("installation_id", installation_id.strip())

    def installations_on_host(self, hostname: str) -> tuple[SoftwareInstallationIdentity, ...]:
        """Compatibility wrapper materializing one exact host inventory."""

        return tuple(self.iter_installations_on_host(hostname))

    def iter_installations_on_host(
        self,
        hostname: str,
    ) -> Iterator[SoftwareInstallationIdentity]:
        """Iterate the fixed installation inventory for one exact host."""

        yield from self._installations.find_iter("host", _normalize_hostname(hostname))

    def count_installations_on_host(self, hostname: str) -> int:
        """Return the installation count for one exact host."""

        return self._installations.count("host", _normalize_hostname(hostname))

    def page_installations_on_host(
        self,
        hostname: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[SoftwareInstallationIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of an exact host installation inventory."""

        queries = (("host", _normalize_hostname(hostname)),)
        return self._page_group(
            self._installations,
            "installations_on_host",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def installations_for_principal(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
    ) -> tuple[SoftwareInstallationIdentity, ...]:
        """Compatibility wrapper materializing machine plus user installations."""

        return tuple(self.iter_installations_for_principal(hostname, principal, platform))

    def _principal_installation_queries(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
    ) -> tuple[tuple[str, Hashable], ...]:
        normalized_platform = _normalize_platform(platform)
        host = _normalize_hostname(hostname)
        user = _normalize_principal(principal, normalized_platform)
        queries: tuple[tuple[str, Hashable], ...] = (("audience", (host, normalized_platform, "")),)
        if user:
            queries += (("audience", (host, normalized_platform, user)),)
        return queries

    def iter_installations_for_principal(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
    ) -> Iterator[SoftwareInstallationIdentity]:
        """Iterate machine-wide plus exact user-scoped installations."""

        yield from self._iter_group(
            self._installations,
            self._principal_installation_queries(hostname, principal, platform),
        )

    def count_installations_for_principal(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
    ) -> int:
        """Return machine plus user-scoped installation count."""

        return self._count_group(
            self._installations,
            self._principal_installation_queries(hostname, principal, platform),
        )

    def page_installations_for_principal(
        self,
        hostname: str,
        principal: str,
        platform: Platform,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[SoftwareInstallationIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded machine-plus-user installation page."""

        queries = self._principal_installation_queries(hostname, principal, platform)
        return self._page_group(
            self._installations,
            "installations_for_principal",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def installations_for_application(
        self,
        hostname: str,
        application_id: str,
    ) -> tuple[SoftwareInstallationIdentity, ...]:
        """Compatibility wrapper materializing one host/application group."""

        return tuple(self.iter_installations_for_application(hostname, application_id))

    def _host_application_key(self, hostname: str, application_id: str) -> tuple[str, str]:
        return (
            _normalize_hostname(hostname),
            _normalize_name(application_id, "application_id", casefold=True),
        )

    def iter_installations_for_application(
        self,
        hostname: str,
        application_id: str,
    ) -> Iterator[SoftwareInstallationIdentity]:
        """Iterate exact host-local installations for one application ID."""

        yield from self._installations.find_iter(
            "host_application",
            self._host_application_key(hostname, application_id),
        )

    def count_installations_for_application(self, hostname: str, application_id: str) -> int:
        """Return exact host/application installation count."""

        return self._installations.count(
            "host_application",
            self._host_application_key(hostname, application_id),
        )

    def page_installations_for_application(
        self,
        hostname: str,
        application_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[SoftwareInstallationIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded exact host/application installation page."""

        queries = (("host_application", self._host_application_key(hostname, application_id)),)
        return self._page_group(
            self._installations,
            "installations_for_application",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def installations_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> tuple[SoftwareInstallationIdentity, ...]:
        """Compatibility wrapper materializing one host/product installation group."""

        return tuple(self.iter_installations_for_product(hostname, product_id))

    def _host_product_key(self, hostname: str, product_id: str) -> tuple[str, str]:
        return (
            _normalize_hostname(hostname),
            _normalize_name(product_id, "product_id", casefold=True),
        )

    def iter_installations_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> Iterator[SoftwareInstallationIdentity]:
        """Iterate installations on one host for an exact product identity."""

        key = self._host_product_key(hostname, product_id)
        yield from self._installations.find_iter("host_product", key)

    def count_installations_for_product(self, hostname: str, product_id: str) -> int:
        """Return exact host/product installation count."""

        return self._installations.count(
            "host_product",
            self._host_product_key(hostname, product_id),
        )

    def page_installations_for_product(
        self,
        hostname: str,
        product_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[SoftwareInstallationIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded exact host/product installation page."""

        key = self._host_product_key(hostname, product_id)
        return self._page_group(
            self._installations,
            "installations_for_product",
            (("host_product", key),),
            limit=limit,
            cursor=cursor,
        )

    def installations_for_release(
        self,
        hostname: str,
        release_id: str,
    ) -> tuple[SoftwareInstallationIdentity, ...]:
        """Compatibility wrapper materializing one host/release installation group."""

        return tuple(self.iter_installations_for_release(hostname, release_id))

    def _host_release_key(self, hostname: str, release_id: str) -> tuple[str, str]:
        return (
            _normalize_hostname(hostname),
            _normalize_name(release_id, "release_id"),
        )

    def iter_installations_for_release(
        self,
        hostname: str,
        release_id: str,
    ) -> Iterator[SoftwareInstallationIdentity]:
        """Iterate installations on one host for one exact product release."""

        yield from self._installations.find_iter(
            "host_release",
            self._host_release_key(hostname, release_id),
        )

    def count_installations_for_release(self, hostname: str, release_id: str) -> int:
        """Return exact host/release installation count."""

        return self._installations.count(
            "host_release",
            self._host_release_key(hostname, release_id),
        )

    def page_installations_for_release(
        self,
        hostname: str,
        release_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[SoftwareInstallationIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded exact host/release installation page."""

        queries = (("host_release", self._host_release_key(hostname, release_id)),)
        return self._page_group(
            self._installations,
            "installations_for_release",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def installation_for_image(
        self,
        hostname: str,
        image_path: str,
        platform: Platform,
        *,
        principal: str = "",
    ) -> SoftwareInstallationIdentity | None:
        """Resolve an exact installed image path, preferring the named user's scope."""

        binding = self._binary_path_binding(hostname, image_path, platform, principal)
        return self._installations.get_by_handle(binding[0]) if binding is not None else None

    def resolve_binary(
        self,
        hostname: str,
        image_path: str,
        platform: Platform,
        *,
        principal: str = "",
    ) -> BinaryReleaseIdentity | None:
        """Resolve content identity from one exact installed path.

        This method never falls back to an executable basename outside the
        already-selected installation and product release.
        """

        binding = self._binary_path_binding(hostname, image_path, platform, principal)
        return self._releases.get_by_handle(binding[1]) if binding is not None else None

    def _binary_path_binding(
        self,
        hostname: str,
        image_path: str,
        platform: Platform,
        principal: str,
    ) -> tuple[int, int] | None:
        normalized_platform = _normalize_platform(platform)
        if _has_posix_path_backslash(image_path, normalized_platform):
            return None
        host = _normalize_hostname(hostname)
        user = _normalize_principal(principal, normalized_platform)
        path = canonical_native_path(image_path, normalized_platform)
        host_handle = self._binary_host_handles.find(normalized_platform, host)
        native_path_handle = self._binary_native_path_handles.find(normalized_platform, path)
        if host_handle is None or native_path_handle is None:
            return None
        if user:
            principal_handle = self._binary_principal_handles.find(normalized_platform, user)
            if principal_handle is not None:
                user_binding = self._binary_path_index.get(
                    _packed_binary_path_key(
                        host_handle,
                        principal_handle,
                        native_path_handle,
                    )
                )
                if user_binding is not None:
                    return _unpack_binary_binding(user_binding)
        machine_binding = self._binary_path_index.get(
            _packed_binary_path_key(host_handle, 0, native_path_handle)
        )
        return _unpack_binary_binding(machine_binding) if machine_binding is not None else None

    def application_profile_by_id(
        self,
        application_profile_id: str,
    ) -> ApplicationProfileIdentity | None:
        """Return one exact application profile by canonical ID."""

        return self._application_profiles.find_one(
            "application_profile_id",
            application_profile_id.strip(),
        )

    def application_profile_for(
        self,
        user_profile_id: str,
        installation_id: str,
        application_id: str,
        profile_name: str = "default",
    ) -> ApplicationProfileIdentity | None:
        """Return one exact application profile without scanning other profiles."""

        user_profile = self.user_profile_by_id(user_profile_id)
        if user_profile is None:
            return None
        key: ApplicationProfileCanonicalKey = (
            user_profile.hostname,
            user_profile.principal,
            user_profile.platform,
            user_profile.profile_id,
            installation_id.strip(),
            _normalize_name(application_id, "application_id", casefold=True),
            _normalize_name(
                profile_name,
                "profile_name",
                casefold=user_profile.platform == "windows",
            ),
        )
        return self._application_profiles.get(key)

    def application_profiles_for_user_profile(
        self,
        user_profile_id: str,
    ) -> tuple[ApplicationProfileIdentity, ...]:
        """Compatibility wrapper materializing one user's application profiles."""

        return tuple(self.iter_application_profiles_for_user_profile(user_profile_id))

    def iter_application_profiles_for_user_profile(
        self,
        user_profile_id: str,
    ) -> Iterator[ApplicationProfileIdentity]:
        """Iterate exact application profiles attached to one user profile."""

        yield from self._application_profiles.find_iter("user_profile", user_profile_id.strip())

    def count_application_profiles_for_user_profile(self, user_profile_id: str) -> int:
        """Return exact application-profile count for one user profile."""

        return self._application_profiles.count("user_profile", user_profile_id.strip())

    def page_application_profiles_for_user_profile(
        self,
        user_profile_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[ApplicationProfileIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of a user's application profiles."""

        queries = (("user_profile", user_profile_id.strip()),)
        return self._page_group(
            self._application_profiles,
            "application_profiles_for_user_profile",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def application_profiles_for_installation(
        self,
        installation_id: str,
    ) -> tuple[ApplicationProfileIdentity, ...]:
        """Compatibility wrapper materializing one installation's profiles."""

        return tuple(self.iter_application_profiles_for_installation(installation_id))

    def iter_application_profiles_for_installation(
        self,
        installation_id: str,
    ) -> Iterator[ApplicationProfileIdentity]:
        """Iterate exact application profiles attached to one installation."""

        yield from self._application_profiles.find_iter("installation", installation_id.strip())

    def count_application_profiles_for_installation(self, installation_id: str) -> int:
        """Return exact application-profile count for one installation."""

        return self._application_profiles.count("installation", installation_id.strip())

    def page_application_profiles_for_installation(
        self,
        installation_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[ApplicationProfileIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of an installation's application profiles."""

        queries = (("installation", installation_id.strip()),)
        return self._page_group(
            self._application_profiles,
            "application_profiles_for_installation",
            queries,
            limit=limit,
            cursor=cursor,
        )

    def application_descriptor(
        self,
        application_id: str,
        platform: Platform,
    ) -> CompiledApplicationDescriptor | None:
        """Return one detached exact application/platform descriptor."""

        descriptor = self._owned_application_descriptor(application_id, platform)
        return None if descriptor is None else copy(descriptor)

    def _owned_application_descriptor(
        self,
        application_id: str,
        platform: Platform,
    ) -> CompiledApplicationDescriptor | None:
        """Return one owner-private canonical descriptor for runtime use."""

        key = (
            _normalize_name(application_id, "application_id", casefold=True),
            _normalize_platform(platform),
        )
        return self._application_descriptors.get(key)

    def application_ids_for_executable(
        self,
        platform: Platform,
        executable: str,
    ) -> tuple[str, ...]:
        """Return the retained stable IDs for one exact executable basename."""

        normalized_platform = _normalize_platform(platform)
        normalized_executable = _normalize_name(executable, "executable")
        if normalized_platform != "windows" and "\\" in normalized_executable:
            return ()
        return self._application_descriptor_ids_by_executable.get(
            (
                normalized_platform,
                _artifact_name(normalized_executable, normalized_platform),
            ),
            (),
        )

    def application_descriptor_for_assignment(
        self,
        assignment: UserApplicationAssignment,
    ) -> CompiledApplicationDescriptor | None:
        """Resolve descriptor truth for one exact assignment without a profile scan."""

        resolved = self._application_runtime_for_assignment(assignment)
        return None if resolved is None else copy(resolved[1])

    def _application_runtime_for_assignment(
        self,
        assignment: UserApplicationAssignment,
    ) -> (
        tuple[
            UserApplicationAssignment,
            CompiledApplicationDescriptor,
            SoftwareInstallationIdentity,
        ]
        | None
    ):
        """Authenticate and resolve one registry-owned assignment relationship."""

        registered = self._owned_user_application_assignment(assignment.assignment_id)
        if registered is None or registered != assignment:
            return None
        descriptor = self._owned_application_descriptor(
            registered.application_id,
            registered.platform,
        )
        installation = self.installation_by_handle(registered.installation_handle)
        if (
            descriptor is None
            or installation is None
            or installation.application_id != registered.application_id
            or installation.platform != registered.platform
            or installation.hostname != registered.hostname
            or installation.release_id != registered.release_id
            or not installation.image_paths
        ):
            return None
        if installation.scope == "user" and (
            installation.principal != registered.principal
            or installation.user_profile_id != registered.user_profile_id
        ):
            return None
        return registered, descriptor, installation

    def application_executable_for_assignment(
        self,
        assignment: UserApplicationAssignment,
    ) -> str | None:
        """Return the compiler-owned primary executable for one assignment."""

        resolved = self._application_runtime_for_assignment(assignment)
        if resolved is None:
            return None
        registered, descriptor, installation = resolved
        image_path = installation.image_paths[0]
        if _artifact_name(image_path, registered.platform) != descriptor.executable:
            return None
        return image_path

    def materialize_application_command(
        self,
        rng: random.Random,
        assignment: UserApplicationAssignment,
        *,
        username: str = "",
        category: str | None = None,
    ) -> tuple[str, str] | None:
        """Materialize one exact assignment from immutable compiled command truth."""

        resolved = self._application_runtime_for_assignment(assignment)
        if resolved is None:
            return None
        registered, descriptor, installation = resolved
        image_path = installation.image_paths[0]
        if _artifact_name(image_path, registered.platform) != descriptor.executable:
            return None
        if category is not None:
            normalized_category = _normalize_name(category, "category", casefold=True)
            if (
                normalized_category not in descriptor.categories
                or normalized_category not in registered.eligible_categories
            ):
                return None
        if username:
            normalized_username = _normalize_principal(username, registered.platform)
            if normalized_username != registered.principal:
                return None
        output: list[str] = []
        stack: list[tuple[str, str]] = [("text", rng.choice(descriptor.command_templates))]
        while stack:
            kind, value = stack.pop()
            if kind == "literal":
                output.append(value)
                continue
            if kind == "placeholder":
                name = value[1:-1]
                if name == "username":
                    output.append(registered.materialization_principal)
                    continue
                values = descriptor._command_parameter_values(name)
                if values is None:
                    output.append(value)
                else:
                    stack.append(("text", rng.choice(values)))
                continue
            segments: list[tuple[str, str]] = []
            cursor = 0
            for match in _APPLICATION_COMMAND_PLACEHOLDER.finditer(value):
                if match.start() > cursor:
                    segments.append(("literal", value[cursor : match.start()]))
                segments.append(("placeholder", match.group(0)))
                cursor = match.end()
            if cursor < len(value):
                segments.append(("literal", value[cursor:]))
            for segment_kind, segment_value in reversed(segments):
                stack.append((segment_kind, segment_value))
        return image_path, "".join(output)

    def host_deployment(self, hostname: str) -> HostDeployment | None:
        """Return the immutable compiled deployment for one exact host."""

        return self._host_deployments.get(_normalize_hostname(hostname))

    def host_deployment_by_id(self, deployment_id: str) -> HostDeployment | None:
        """Return a compiled host deployment by exact semantic ID."""

        return self._host_deployments.find_one("deployment_id", deployment_id.strip())

    def host_architecture(self, hostname: str) -> Architecture | None:
        """Return the exact compiler-resolved architecture for one modeled host."""

        deployment = self.host_deployment(hostname)
        return None if deployment is None else deployment.architecture

    def installation_by_handle(self, handle: int) -> SoftwareInstallationIdentity | None:
        """Resolve one live compact installation handle."""

        try:
            return self._installations.get_by_handle(handle)
        except KeyError:
            return None

    def service_identity_by_handle(self, handle: int) -> str | None:
        """Resolve one interned service identity from a host deployment handle."""

        try:
            return self._services.get_by_handle(handle)
        except KeyError:
            return None

    def host_service_handle(self, hostname: str, service_id: str) -> int | None:
        """Return the exact compact service handle only when deployed on the host."""

        deployment = self.host_deployment(hostname)
        identity = service_id.strip()
        if deployment is None or not identity or identity not in self._services:
            return None
        handle = self._services.handle_for(identity)
        return handle if handle in deployment.service_handles else None

    def host_service(self, hostname: str, service_id: str) -> str | None:
        """Resolve one exact deployed service identity without a catalog scan."""

        handle = self.host_service_handle(hostname, service_id)
        return None if handle is None else self._services.get_by_handle(handle)

    def compiled_service_deployment_identity(
        self,
        hostname: str,
        service_id: str,
    ) -> CompiledServiceDeploymentIdentity | None:
        """Return a typed exact view only for a compiler-admitted host service."""

        exact_id = self.host_service(hostname, service_id)
        if exact_id is None:
            return None
        return CompiledServiceDeploymentIdentity(hostname=hostname, service_id=exact_id)

    def runtime_service_deployment_identity(
        self,
        *,
        hostname: str,
        canonical_name: str,
        action_id: str,
    ) -> RuntimeServiceDeploymentIdentity:
        """Build one runtime-only service identity after exact collision validation.

        Runtime service deployments are intentionally not inserted into this
        immutable compiler registry. The lifecycle registry owns their bounded
        runtime state after prepared publication.
        """

        identity = RuntimeServiceDeploymentIdentity(
            hostname=hostname,
            canonical_name=canonical_name,
            action_id=action_id,
        )
        if self.host_deployment(identity.hostname) is None:
            raise ValueError(
                "runtime service deployment requires an exact compiled host deployment"
            )
        if identity.canonical_id in self._services:
            raise ValueError(
                "runtime service deployment identity collides with a compiler-owned service ID"
            )
        return identity

    def admits_service_deployment_identity(self, identity: ServiceDeploymentIdentity) -> bool:
        """Return whether an exact typed service identity is valid for this registry."""

        if isinstance(identity, CompiledServiceDeploymentIdentity):
            compiled = self.compiled_service_deployment_identity(
                identity.hostname,
                identity.service_id,
            )
            return compiled == identity
        return (
            self.host_deployment(identity.hostname) is not None
            and identity.canonical_id not in self._services
        )

    def iter_host_services(self, hostname: str) -> Iterator[str]:
        """Iterate the compact deployed service set for one host."""

        deployment = self.host_deployment(hostname)
        if deployment is None:
            return
        for handle in deployment.service_handles:
            yield self._services.get_by_handle(handle)

    def count_host_services(self, hostname: str) -> int:
        """Return the exact deployed service count for one host."""

        deployment = self.host_deployment(hostname)
        return 0 if deployment is None else len(deployment.service_handles)

    def page_host_services(
        self,
        hostname: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[str, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of exact deployed service identities."""

        normalized_host = _normalize_hostname(hostname)
        deployment = self.host_deployment(normalized_host)
        handles = () if deployment is None else deployment.service_handles
        return self._page_handle_group(
            self._services,
            handles,
            "host_services",
            normalized_host,
            limit=limit,
            cursor=cursor,
        )

    def task_identity_by_handle(self, handle: int) -> str | None:
        """Resolve one interned scheduled-task identity from a deployment handle."""

        try:
            return self._tasks.get_by_handle(handle)
        except KeyError:
            return None

    def host_task_handle(self, hostname: str, task_id: str) -> int | None:
        """Return the exact compact task handle only when deployed on the host."""

        deployment = self.host_deployment(hostname)
        identity = task_id.strip()
        if deployment is None or not identity or identity not in self._tasks:
            return None
        handle = self._tasks.handle_for(identity)
        return handle if handle in deployment.task_handles else None

    def host_task(self, hostname: str, task_id: str) -> str | None:
        """Resolve one exact deployed task identity without a catalog scan."""

        handle = self.host_task_handle(hostname, task_id)
        return None if handle is None else self._tasks.get_by_handle(handle)

    def compiled_task_deployment_identity(
        self,
        hostname: str,
        task_id: str,
    ) -> CompiledTaskDeploymentIdentity | None:
        """Return a typed exact view only for a compiler-admitted host task."""

        exact_id = self.host_task(hostname, task_id)
        if exact_id is None:
            return None
        return CompiledTaskDeploymentIdentity(hostname=hostname, task_id=exact_id)

    def iter_host_tasks(self, hostname: str) -> Iterator[str]:
        """Iterate the compact deployed scheduled-task set for one host."""

        deployment = self.host_deployment(hostname)
        if deployment is None:
            return
        for handle in deployment.task_handles:
            yield self._tasks.get_by_handle(handle)

    def count_host_tasks(self, hostname: str) -> int:
        """Return the exact deployed scheduled-task count for one host."""

        deployment = self.host_deployment(hostname)
        return 0 if deployment is None else len(deployment.task_handles)

    def page_host_tasks(
        self,
        hostname: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[str, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of exact deployed task identities."""

        normalized_host = _normalize_hostname(hostname)
        deployment = self.host_deployment(normalized_host)
        handles = () if deployment is None else deployment.task_handles
        return self._page_handle_group(
            self._tasks,
            handles,
            "host_tasks",
            normalized_host,
            limit=limit,
            cursor=cursor,
        )

    def module_identity_by_handle(self, handle: int) -> BinaryReleaseIdentity | None:
        """Resolve one installed module-content handle."""

        try:
            return self._releases.get_by_handle(handle)
        except KeyError:
            return None

    def host_module_handle(self, hostname: str, content_id: str) -> int | None:
        """Return an exact module handle only when admitted by the host deployment."""

        deployment = self.host_deployment(hostname)
        module = self.binary_release_by_content_id(content_id)
        if deployment is None or module is None:
            return None
        handle = self._releases.handle_for(module.canonical_key)
        return handle if handle in deployment.module_handles else None

    def host_module(self, hostname: str, content_id: str) -> BinaryReleaseIdentity | None:
        """Resolve one exact deployed module without scanning release inventories."""

        handle = self.host_module_handle(hostname, content_id)
        return None if handle is None else self._releases.get_by_handle(handle)

    def iter_host_modules(self, hostname: str) -> Iterator[BinaryReleaseIdentity]:
        """Iterate exact module identities admitted by one host deployment."""

        deployment = self.host_deployment(hostname)
        if deployment is None:
            return
        for handle in deployment.module_handles:
            yield self._releases.get_by_handle(handle)

    def count_host_modules(self, hostname: str) -> int:
        """Return the exact admitted module count for one host."""

        deployment = self.host_deployment(hostname)
        return 0 if deployment is None else len(deployment.module_handles)

    def page_host_modules(
        self,
        hostname: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[BinaryReleaseIdentity, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of exact admitted module identities."""

        normalized_host = _normalize_hostname(hostname)
        deployment = self.host_deployment(normalized_host)
        handles = () if deployment is None else deployment.module_handles
        return self._page_handle_group(
            self._releases,
            handles,
            "host_modules",
            normalized_host,
            limit=limit,
            cursor=cursor,
        )

    def user_application_assignment(
        self,
        assignment_id: str,
    ) -> UserApplicationAssignment | None:
        """Return one detached exact compiled persona/application intersection."""

        assignment = self._owned_user_application_assignment(assignment_id)
        return None if assignment is None else copy(assignment)

    def _owned_user_application_assignment(
        self,
        assignment_id: str,
    ) -> UserApplicationAssignment | None:
        """Return one owner-private canonical assignment for runtime authentication."""

        return self._user_assignments.get(assignment_id.strip())

    def user_application_assignment_for_profile(
        self,
        user_profile_id: str,
        application_profile_id: str,
    ) -> UserApplicationAssignment | None:
        """Return one exact profile/application intersection."""

        assignment = self._user_assignments.find_one(
            "profile_application",
            (user_profile_id.strip(), application_profile_id.strip()),
        )
        return None if assignment is None else copy(assignment)

    def _owned_user_application_assignment_for_application(
        self,
        user_profile_id: str,
        application_id: str,
    ) -> UserApplicationAssignment | None:
        """Return one owner-private exact profile/application assignment."""

        assignment = self._user_assignments.find_one(
            "profile_application_id",
            (
                user_profile_id.strip(),
                _normalize_name(application_id, "application_id", casefold=True),
            ),
        )
        if assignment is not None:
            self._assignment_category_lookup_candidates += 1
        return assignment

    def user_application_assignment_for_application(
        self,
        user_profile_id: str,
        application_id: str,
    ) -> UserApplicationAssignment | None:
        """Return one exact installed/eligible application for a user profile."""

        assignment = self._owned_user_application_assignment_for_application(
            user_profile_id,
            application_id,
        )
        return None if assignment is None else copy(assignment)

    @staticmethod
    def _profile_category_key(
        user_profile_id: str,
        category: str,
    ) -> tuple[str, str]:
        return (
            _normalize_name(user_profile_id, "user_profile_id"),
            _normalize_name(category, "category", casefold=True),
        )

    def iter_user_application_assignments_for_category(
        self,
        user_profile_id: str,
        category: str,
    ) -> Iterator[UserApplicationAssignment]:
        """Iterate the exact compact profile/category assignment route."""

        key = self._profile_category_key(user_profile_id, category)
        for handle in self._assignment_category_handles.get(key, ()):
            yield copy(self._user_assignments.get_by_handle(handle))

    def count_user_application_assignments_for_category(
        self,
        user_profile_id: str,
        category: str,
    ) -> int:
        """Return profile/category candidate count without reconstructing assignments."""

        return len(
            self._assignment_category_handles.get(
                self._profile_category_key(user_profile_id, category),
                (),
            )
        )

    def user_application_assignment_for_category_at(
        self,
        user_profile_id: str,
        category: str,
        ordinal: int,
    ) -> UserApplicationAssignment | None:
        """Return one category assignment by stable catalog ordinal."""

        if ordinal < 0:
            raise ValueError("assignment category ordinal must be non-negative")
        handles = self._assignment_category_handles.get(
            self._profile_category_key(user_profile_id, category),
            (),
        )
        if ordinal >= len(handles):
            return None
        return copy(self._user_assignments.get_by_handle(handles[ordinal]))

    def select_user_application_assignment_for_category(
        self,
        user_profile_id: str,
        category: str,
        *,
        unit_interval: float,
    ) -> UserApplicationAssignment | None:
        """Select one weighted candidate from a caller-owned deterministic RNG draw."""

        if not math.isfinite(unit_interval) or not 0.0 <= unit_interval < 1.0:
            raise ValueError("unit_interval must be finite and in [0, 1)")
        key = self._profile_category_key(user_profile_id, category)
        handles = self._assignment_category_handles.get(key)
        cumulative = self._assignment_category_cumulative_weights.get(key)
        if not handles or not cumulative:
            return None
        target = unit_interval * cumulative[-1]
        position = min(len(handles) - 1, bisect_right(cumulative, target))
        self._assignment_category_lookup_candidates += 1
        return copy(self._user_assignments.get_by_handle(handles[position]))

    def select_user_application_assignment_for_applications(
        self,
        user_profile_id: str,
        application_ids: Iterable[str],
        *,
        unit_interval: float,
    ) -> UserApplicationAssignment | None:
        """Select among an ordered exact application-ID subset without a profile scan."""

        if not math.isfinite(unit_interval) or not 0.0 <= unit_interval < 1.0:
            raise ValueError("unit_interval must be finite and in [0, 1)")
        profile_id = _normalize_name(user_profile_id, "user_profile_id")
        ordered_ids = tuple(
            dict.fromkeys(
                _normalize_name(application_id, "application_id", casefold=True)
                for application_id in application_ids
            )
        )
        total = 0
        for application_id in ordered_ids:
            assignment = self._owned_user_application_assignment_for_application(
                profile_id,
                application_id,
            )
            if assignment is not None:
                total += assignment.selection_weight
        if total <= 0:
            return None
        target = unit_interval * total
        cumulative = 0
        last: UserApplicationAssignment | None = None
        for application_id in ordered_ids:
            assignment = self._owned_user_application_assignment_for_application(
                profile_id,
                application_id,
            )
            if assignment is None:
                continue
            last = assignment
            cumulative += assignment.selection_weight
            if target < cumulative:
                return copy(assignment)
        return (
            None if last is None else copy(last)
        )  # pragma: no cover - floating boundary guarded by unit interval

    def page_user_application_assignments_for_category(
        self,
        user_profile_id: str,
        category: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[UserApplicationAssignment, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded stable page of exact profile/category assignments."""

        if limit <= 0:
            raise ValueError("deployment group page limit must be positive")
        key = self._profile_category_key(user_profile_id, category)
        queries: tuple[tuple[str, Hashable], ...] = (("profile_category", key),)
        group_name = "user_application_assignments_for_category"
        if cursor is None:
            offset = 0
        elif (
            cursor._registry_token != id(self)
            or cursor._group_name != group_name
            or cursor._queries != queries
        ):
            raise ValueError("deployment group page cursor belongs to another query")
        else:
            offset = cursor._after_handle or 0
        handles = self._assignment_category_handles.get(key, ())
        end = min(len(handles), offset + limit)
        page = tuple(
            copy(self._user_assignments.get_by_handle(handles[position]))
            for position in range(offset, end)
        )
        next_cursor = (
            DeploymentGroupPageCursor(
                registry_token=id(self),
                group_name=group_name,
                queries=queries,
                query_position=0,
                after_handle=end,
            )
            if end < len(handles)
            else None
        )
        return page, next_cursor

    def preferred_browser_assignment(
        self,
        user_profile_id: str,
    ) -> UserApplicationAssignment | None:
        """Return the compiled scenario-scoped browser affinity for one profile."""

        profile_id = user_profile_id.strip()
        position = self._browser_affinity_positions.get(profile_id)
        handles = self._assignment_category_handles.get((profile_id, "browser"), ())
        if position is None or position >= len(handles):
            return None
        self._assignment_category_lookup_candidates += 1
        return copy(self._user_assignments.get_by_handle(handles[position]))

    def browser_alternative_assignment_at(
        self,
        user_profile_id: str,
        preferred_assignment_id: str,
        ordinal: int,
    ) -> UserApplicationAssignment | None:
        """Return one stable non-preferred browser without materializing its bucket."""

        if ordinal < 0:
            raise ValueError("browser alternative ordinal must be non-negative")
        handles = self._assignment_category_handles.get(
            self._profile_category_key(user_profile_id, "browser"),
            (),
        )
        preferred_position = self._browser_affinity_positions.get(user_profile_id.strip())
        if preferred_position is None or ordinal >= max(0, len(handles) - 1):
            return None
        preferred = self._user_assignments.get_by_handle(handles[preferred_position])
        if preferred.assignment_id != preferred_assignment_id.strip():
            return None
        position = ordinal if ordinal < preferred_position else ordinal + 1
        self._assignment_category_lookup_candidates += 1
        return copy(self._user_assignments.get_by_handle(handles[position]))

    def user_application_assignments_for_profile(
        self,
        user_profile_id: str,
    ) -> tuple[UserApplicationAssignment, ...]:
        """Compatibility wrapper materializing one profile's assignments."""

        return tuple(self.iter_user_application_assignments_for_profile(user_profile_id))

    def iter_user_application_assignments_for_profile(
        self,
        user_profile_id: str,
    ) -> Iterator[UserApplicationAssignment]:
        """Iterate persona-eligible applications for one exact user profile."""

        for assignment in self._user_assignments.find_iter("profile", user_profile_id.strip()):
            yield copy(assignment)

    def count_user_application_assignments_for_profile(self, user_profile_id: str) -> int:
        """Return exact assignment count for one user profile."""

        return self._user_assignments.count("profile", user_profile_id.strip())

    def page_user_application_assignments_for_profile(
        self,
        user_profile_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[UserApplicationAssignment, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded page of assignments for one user profile."""

        queries = (("profile", user_profile_id.strip()),)
        page, next_cursor = self._page_group(
            self._user_assignments,
            "user_application_assignments_for_profile",
            queries,
            limit=limit,
            cursor=cursor,
        )
        return tuple(copy(assignment) for assignment in page), next_cursor

    def user_application_assignments_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> tuple[UserApplicationAssignment, ...]:
        """Compatibility wrapper materializing exact host/product assignments."""

        return tuple(self.iter_user_application_assignments_for_product(hostname, product_id))

    def iter_user_application_assignments_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> Iterator[UserApplicationAssignment]:
        """Iterate exact host/user intersections for one product identity."""

        for assignment in self._user_assignments.find_iter(
            "host_product",
            self._host_product_key(hostname, product_id),
        ):
            yield copy(assignment)

    def count_user_application_assignments_for_product(
        self,
        hostname: str,
        product_id: str,
    ) -> int:
        """Return exact host/product assignment count."""

        return self._user_assignments.count(
            "host_product",
            self._host_product_key(hostname, product_id),
        )

    def page_user_application_assignments_for_product(
        self,
        hostname: str,
        product_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[UserApplicationAssignment, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded exact host/product assignment page."""

        queries = (("host_product", self._host_product_key(hostname, product_id)),)
        page, next_cursor = self._page_group(
            self._user_assignments,
            "user_application_assignments_for_product",
            queries,
            limit=limit,
            cursor=cursor,
        )
        return tuple(copy(assignment) for assignment in page), next_cursor

    def user_application_assignments_for_release(
        self,
        hostname: str,
        release_id: str,
    ) -> tuple[UserApplicationAssignment, ...]:
        """Compatibility wrapper materializing exact host/release assignments."""

        return tuple(self.iter_user_application_assignments_for_release(hostname, release_id))

    def iter_user_application_assignments_for_release(
        self,
        hostname: str,
        release_id: str,
    ) -> Iterator[UserApplicationAssignment]:
        """Iterate exact host/user intersections for one product release."""

        for assignment in self._user_assignments.find_iter(
            "host_release",
            self._host_release_key(hostname, release_id),
        ):
            yield copy(assignment)

    def count_user_application_assignments_for_release(
        self,
        hostname: str,
        release_id: str,
    ) -> int:
        """Return exact host/release assignment count."""

        return self._user_assignments.count(
            "host_release",
            self._host_release_key(hostname, release_id),
        )

    def page_user_application_assignments_for_release(
        self,
        hostname: str,
        release_id: str,
        *,
        limit: int,
        cursor: DeploymentGroupPageCursor | None = None,
    ) -> tuple[tuple[UserApplicationAssignment, ...], DeploymentGroupPageCursor | None]:
        """Return one bounded exact host/release assignment page."""

        queries = (("host_release", self._host_release_key(hostname, release_id)),)
        page, next_cursor = self._page_group(
            self._user_assignments,
            "user_application_assignments_for_release",
            queries,
            limit=limit,
            cursor=cursor,
        )
        return tuple(copy(assignment) for assignment in page), next_cursor

    def file_content(
        self,
        file_object_id: str,
        version: int,
    ) -> FileContentIdentity | None:
        """Return the exact content metadata for a file-object version."""

        return self._file_contents.get((file_object_id.strip(), version))

    def file_content_by_id(self, content_id: str) -> FileContentIdentity | None:
        """Return file content by exact content ID when it is registered."""

        return self._file_contents.find_one("content_id", content_id.strip())

    def local_artifact(
        self,
        artifact_id: str,
        version: int,
    ) -> LocalArtifactIdentity | None:
        """Return one exact local artifact object version."""

        version_id = _stable_semantic_id(
            "artifact-version",
            "local-artifact-version",
            (artifact_id.strip(), version),
        )
        return self._local_artifacts.find_one("artifact_version_id", version_id)

    def local_artifact_by_version_id(
        self,
        artifact_version_id: str,
    ) -> LocalArtifactIdentity | None:
        """Return one exact local artifact by its version ID."""

        return self._local_artifacts.find_one(
            "artifact_version_id",
            artifact_version_id.strip(),
        )

    def local_artifact_for_path(
        self,
        user_profile_id: str,
        application_profile_id: str,
        native_path: str,
        platform: Platform,
        version: int,
    ) -> LocalArtifactIdentity | None:
        """Return one exact application/profile/path/version artifact binding."""

        normalized_platform = _normalize_platform(platform)
        if _has_posix_path_backslash(native_path, normalized_platform):
            return None
        path_key = (
            normalized_platform,
            user_profile_id.strip(),
            application_profile_id.strip(),
            canonical_native_path(native_path, normalized_platform),
            version,
        )
        handle = next(
            self._local_artifact_path_index.iter_handles(
                _packed_index_key(path_key),
                self._local_artifact_path_key_at,
            ),
            None,
        )
        return self._local_artifacts.get_by_handle(handle) if handle is not None else None

    def census(self) -> DeploymentRegistryCensus:
        """Return structural counts without traversing registry values."""

        return DeploymentRegistryCensus(
            binary_releases=len(self._releases),
            installed_software_releases=len(self._installed_software_releases),
            installations=len(self._installations),
            user_profiles=len(self._user_profiles),
            application_profiles=len(self._application_profiles),
            application_descriptors=len(self._application_descriptors),
            application_executable_bindings=self._application_executable_links,
            file_versions=len(self._file_contents),
            local_artifact_versions=len(self._local_artifacts),
            binary_path_bindings=len(self._binary_path_index),
            local_artifact_path_bindings=len(self._local_artifact_path_index),
        )

    def binary_path_index_census(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> BinaryPathIndexCensus:
        """Return compact path-index structure, optionally traversing it for byte estimates."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self._binary_path_index)
                + sum(
                    sys.getsizeof(key) + sys.getsizeof(binding)
                    for key, binding in self._binary_path_index.items()
                )
                + self._binary_host_handles.estimated_bytes()
                + self._binary_principal_handles.estimated_bytes()
                + self._binary_native_path_handles.estimated_bytes()
            )
        return BinaryPathIndexCensus(
            bindings=len(self._binary_path_index),
            interned_hosts=len(self._binary_host_handles),
            interned_principals=len(self._binary_principal_handles),
            interned_native_paths=len(self._binary_native_path_handles),
            packed_integer_keys=len(self._binary_path_index),
            packed_integer_targets=len(self._binary_path_index),
            estimated_bytes=estimated_bytes,
        )

    def deployment_census(self) -> DeploymentCompilationCensus:
        """Return host-deployment and assignment compilation cardinalities."""

        return DeploymentCompilationCensus(
            host_deployments=len(self._host_deployments),
            user_application_assignments=len(self._user_assignments),
            interned_services=len(self._services),
            interned_tasks=len(self._tasks),
            assignment_category_buckets=len(self._assignment_category_handles),
            assignment_category_links=self._assignment_category_links,
            browser_affinities=len(self._browser_affinity_positions),
        )

    def assignment_category_index_census(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> AssignmentCategoryIndexCensus:
        """Return category-route shape, traversing backing only for explicit byte estimates."""

        estimated_bytes = 0
        if estimate_bytes:
            estimated_bytes = (
                sys.getsizeof(self._assignment_category_handles)
                + sys.getsizeof(self._assignment_category_cumulative_weights)
                + sys.getsizeof(self._browser_affinity_positions)
                + sum(
                    sys.getsizeof(key) + sys.getsizeof(handles)
                    for key, handles in self._assignment_category_handles.items()
                )
                + sum(
                    sys.getsizeof(key) + sys.getsizeof(weights)
                    for key, weights in self._assignment_category_cumulative_weights.items()
                )
                + sum(
                    sys.getsizeof(profile_id) + sys.getsizeof(position)
                    for profile_id, position in self._browser_affinity_positions.items()
                )
            )
        return AssignmentCategoryIndexCensus(
            buckets=len(self._assignment_category_handles),
            links=self._assignment_category_links,
            max_bucket_size=self._assignment_category_max_bucket,
            browser_affinities=len(self._browser_affinity_positions),
            exact_selection_candidates=1 if self._assignment_category_links else 0,
            lookup_candidates_inspected=self._assignment_category_lookup_candidates,
            estimated_bytes=estimated_bytes,
        )

    def scale_census(self) -> DeploymentContentScaleCensus:
        """Return the immutable deployment/content mixed-workload contribution.

        All cardinalities and retained-byte estimates were sealed at compile
        time. Calling this method never scans canonical rows, relationship
        buckets, or registry values.
        """

        registry = self.census()
        deployment = self.deployment_census()
        physical_records = (
            registry.binary_releases
            + registry.installed_software_releases
            + registry.installations
            + registry.user_profiles
            + registry.application_profiles
            + registry.application_descriptors
            + registry.file_versions
            + registry.local_artifact_versions
            + deployment.host_deployments
            + deployment.user_application_assignments
            + deployment.interned_services
            + deployment.interned_tasks
        )
        relationship_bindings = (
            registry.binary_path_bindings
            + registry.local_artifact_path_bindings
            + registry.application_executable_bindings
            + deployment.assignment_category_links
            + self._host_installation_links
            + self._host_service_links
            + self._host_task_links
            + self._host_module_links
        )
        application_descriptor_owner_snapshots = (
            self._application_descriptors.retained_identity_entries
        )
        user_application_assignment_owner_snapshots = (
            self._user_assignments.retained_identity_entries
        )
        retained_entries = (
            physical_records
            + application_descriptor_owner_snapshots
            + user_application_assignment_owner_snapshots
        )
        stores = (
            self._releases,
            self._installed_software_releases,
            self._user_profiles,
            self._application_profiles,
            self._application_descriptors,
            self._file_contents,
            self._local_artifacts,
            self._services,
            self._tasks,
            self._host_deployments,
            self._user_assignments,
        )
        store_metrics = tuple(store.metrics() for store in stores)
        return DeploymentContentScaleCensus(
            logical_records=physical_records,
            physical_records=physical_records,
            live_entries=physical_records,
            retained_entries=retained_entries,
            backing_entries=retained_entries + relationship_bindings,
            stale_entries=0,
            leased_entries=0,
            high_water_mark=retained_entries,
            binary_releases=registry.binary_releases,
            installed_software_releases=registry.installed_software_releases,
            installations=registry.installations,
            user_profiles=registry.user_profiles,
            application_profiles=registry.application_profiles,
            application_descriptors=registry.application_descriptors,
            application_descriptor_owner_snapshots=application_descriptor_owner_snapshots,
            file_versions=registry.file_versions,
            local_artifact_versions=registry.local_artifact_versions,
            host_deployments=deployment.host_deployments,
            user_application_assignments=deployment.user_application_assignments,
            user_application_assignment_owner_snapshots=(
                user_application_assignment_owner_snapshots
            ),
            service_identities=deployment.interned_services,
            task_identities=deployment.interned_tasks,
            binary_path_bindings=registry.binary_path_bindings,
            local_artifact_path_bindings=registry.local_artifact_path_bindings,
            application_executable_bindings=(registry.application_executable_bindings),
            assignment_category_bindings=deployment.assignment_category_links,
            host_installation_bindings=self._host_installation_links,
            host_service_bindings=self._host_service_links,
            host_task_bindings=self._host_task_links,
            host_module_bindings=self._host_module_links,
            relationship_bindings=relationship_bindings,
            maximum_bucket_size=max(
                self._assignment_category_max_bucket,
                self._application_executable_max_bucket,
                self._installations.max_host_bucket_size,
                *(metric.max_bucket_size for metric in store_metrics),
            ),
            lookup_candidates_inspected=(
                self._assignment_category_lookup_candidates
                + sum(metric.lookup_candidates_inspected for metric in store_metrics)
            ),
            estimated_bytes=self._scale_estimated_bytes,
            estimated_index_bytes=self._scale_estimated_index_bytes,
        )


class LocalArtifactVersionRegistry:
    """Bounded mutable retention for high-volume local artifact versions.

    Deployment configuration remains immutable in
    :class:`DeploymentContentRegistry`. Runtime cache/file versions live here,
    expire by watermark, and may be held only by explicit owner leases.
    """

    __slots__ = (
        "_capacity",
        "_capacity_lock",
        "_claimed_reservations",
        "_committing_reservations",
        "_eviction_cursor",
        "_gate",
        "_high_water_mark",
        "_live_count",
        "_next_reservation_id",
        "_prepared_byte_capacity",
        "_prepared_capability_locators",
        "_prepared_commit_locators",
        "_prepared_counts",
        "_prepared_retained_bytes",
        "_prepared_reservations",
        "_prepared_secret",
        "_prepared_versions",
        "_publication_group_receipts",
        "_publication_group_receipt_locators",
        "_publication_receipts",
        "_publication_receipt_locators",
        "_retention",
        "_route_compaction_cursor",
        "_routes",
        "_shard_capacities",
        "_shard_count",
        "_shards",
        "_watermark",
    )

    def __init__(
        self,
        *,
        capacity: int = _DEFAULT_ARTIFACT_CAPACITY,
        retention: timedelta = _DEFAULT_ARTIFACT_RETENTION,
        shard_count: int = _DEFAULT_ARTIFACT_SHARDS,
        prepared_byte_capacity: int = _DEFAULT_ARTIFACT_PREPARED_BYTE_CAPACITY,
    ) -> None:
        """Create a bounded artifact registry with an explicit retention horizon."""

        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        if shard_count < 1:
            raise ValueError("shard_count must be at least 1")
        if prepared_byte_capacity < 1:
            raise ValueError("prepared_byte_capacity must be at least 1")
        self._capacity = capacity
        self._retention = retention
        self._prepared_byte_capacity = prepared_byte_capacity
        # Tiny test/embedded registries keep at least four backing slots per
        # owner lane so a short version history does not spill solely because
        # the configured shard count exceeds useful capacity.
        self._shard_count = min(shard_count, max(1, capacity // 4))
        base_capacity, remainder = divmod(capacity, self._shard_count)
        self._shard_capacities = tuple(
            base_capacity + (1 if shard_id < remainder else 0)
            for shard_id in range(self._shard_count)
        )
        self._shards = tuple(
            _LocalArtifactShard(shard_id, self._shard_capacities[shard_id])
            for shard_id in range(self._shard_count)
        )
        self._routes = tuple(_ArtifactRouteShard() for _ in range(self._shard_count))
        self._gate = _ArtifactRegistryGate()
        self._capacity_lock = RLock()
        self._claimed_reservations: set[int] = set()
        self._committing_reservations: set[int] = set()
        self._live_count = 0
        self._high_water_mark = 0
        self._next_reservation_id = 1
        self._prepared_capability_locators: dict[int, int] = {}
        self._prepared_commit_locators: dict[int, tuple[int, ...]] = {}
        self._prepared_counts = [0] * self._shard_count
        self._prepared_reservations: dict[int, _LocalArtifactPreparedReservation] = {}
        self._prepared_retained_bytes = 0
        self._prepared_secret = secrets.token_bytes(32)
        self._prepared_versions: dict[str, int] = {}
        self._publication_receipts: WeakValueDictionary[int, LocalArtifactPublicationReceipt] = (
            WeakValueDictionary()
        )
        self._publication_group_receipts: WeakValueDictionary[
            int, LocalArtifactPublicationGroupReceipt
        ] = WeakValueDictionary()
        self._publication_receipt_locators: dict[int, int] = {}
        self._publication_group_receipt_locators: dict[int, tuple[int, ...]] = {}
        self._eviction_cursor = 0
        self._route_compaction_cursor = 0
        self._watermark: datetime | None = None

    def __len__(self) -> int:
        with self._capacity_lock:
            return self._live_count

    def _shard_id_for(self, identity: str) -> int:
        digest = hashlib.sha256(f"local-artifact-shard\0{identity}".encode()).digest()
        return int.from_bytes(digest[:8], "big") % self._shard_count

    def _probe_shards(self, identity: str) -> Iterator[_LocalArtifactShard]:
        """Yield every bounded shard once, starting at an identity-stable owner."""

        first = self._shard_id_for(identity)
        for offset in range(self._shard_count):
            yield self._shards[(first + offset) % self._shard_count]

    def _route_partition(self, artifact_version_id: str) -> _ArtifactRouteShard:
        return self._routes[self._shard_id_for(artifact_version_id)]

    def _existing_locator(
        self,
        artifact_version_id: str,
    ) -> tuple[_LocalArtifactShard, int] | None:
        """Resolve one exact home or sparse-spill route without scanning shards."""

        route_key = _semantic_artifact_digest(artifact_version_id, "artifact-version-")
        if route_key is None:
            return None
        route = self._route_partition(artifact_version_id)
        with route.lock:
            locator = route.routes.get(route_key)
        if locator is not None:
            shard_id, handle = _unpack_artifact_locator(locator)
            if shard_id >= self._shard_count:  # pragma: no cover - packed route invariant
                raise StateError("local artifact route references an invalid shard")
            return self._shards[shard_id], handle
        home = self._shards[self._shard_id_for(artifact_version_id)]
        with home.lock:
            handle = home.store.find_version_handle(artifact_version_id)
        return None if handle is None else (home, handle)

    def _existing_shard(self, artifact_version_id: str) -> _LocalArtifactShard | None:
        """Compatibility probe returning the exact routed owner shard."""

        located = self._existing_locator(artifact_version_id)
        return None if located is None else located[0]

    def _set_route(self, artifact_version_id: str, shard_id: int, handle: int) -> None:
        if shard_id == self._shard_id_for(artifact_version_id):
            return
        route = self._route_partition(artifact_version_id)
        route_key = _semantic_artifact_digest(artifact_version_id, "artifact-version-")
        if route_key is None:  # pragma: no cover - identity invariant
            raise StateError("local artifact route key is not a canonical semantic ID")
        with route.lock:
            route.routes[route_key] = _pack_artifact_locator(shard_id, handle)
            route.high_water = max(route.high_water, len(route.routes))

    def _remove_route(
        self,
        artifact_version_id: str,
        *,
        shard_id: int,
        handle: int,
    ) -> None:
        if shard_id == self._shard_id_for(artifact_version_id):
            return
        route = self._route_partition(artifact_version_id)
        route_key = _semantic_artifact_digest(artifact_version_id, "artifact-version-")
        if route_key is None:  # pragma: no cover - identity invariant
            return
        expected = _pack_artifact_locator(shard_id, handle)
        with route.lock:
            if route.routes.get(route_key) == expected:
                route.routes.pop(route_key)

    @property
    def watermark(self) -> datetime | None:
        """Return the latest canonical retention watermark."""

        with self._capacity_lock:
            return self._watermark

    def _require_after_watermark_locked(
        self,
        value: datetime,
        field_name: str,
        *,
        allow_boundary: bool,
    ) -> None:
        """Fence state writes against the sealed half-open history."""

        if self._watermark is None:
            return
        is_late = value < self._watermark or (value == self._watermark and not allow_boundary)
        if is_late:
            relation = "at or before" if not allow_boundary else "before"
            raise StateError(
                f"{field_name} cannot be {relation} the current artifact watermark "
                f"{self._watermark.isoformat()}"
            )

    def _version_has_claimed_preparation_locked(self, artifact_version_id: str) -> bool:
        reservation_id = self._prepared_versions.get(artifact_version_id)
        return reservation_id is not None and reservation_id in self._claimed_reservations

    def prepare_publish_version(
        self,
        record: LocalArtifactVersionRecord,
        observed_at: datetime,
        *,
        retention: timedelta | None = None,
        lease_owner: str = "",
        lease_until: datetime | None = None,
    ) -> LocalArtifactPublishToken:
        """Reserve one exact record publication before external state allocation.

        Preparation validates and packs the complete immutable value, reserves a
        concrete shard slot (or an existing exact version), and fences competing
        publication/eviction of that version. It does not make the record
        visible. A caller must subsequently enter :meth:`prepared_publication`
        before mutating its coupled lifecycle/StateManager transaction.
        """

        if not isinstance(record, LocalArtifactVersionRecord):
            raise TypeError("record must be a LocalArtifactVersionRecord")
        normalized_event_time = ensure_utc(observed_at)
        event_time = datetime(
            normalized_event_time.year,
            normalized_event_time.month,
            normalized_event_time.day,
            normalized_event_time.hour,
            normalized_event_time.minute,
            normalized_event_time.second,
            normalized_event_time.microsecond,
            tzinfo=UTC,
            fold=normalized_event_time.fold,
        )
        effective_retention = retention or self._retention
        if effective_retention <= timedelta(0):
            raise ValueError("artifact retention must be positive")
        retained_until = event_time + effective_retention
        owner_id = lease_owner.strip()
        normalized_lease_until: datetime | None = None
        if lease_until is not None:
            lease_time = ensure_utc(lease_until)
            normalized_lease_until = datetime(
                lease_time.year,
                lease_time.month,
                lease_time.day,
                lease_time.hour,
                lease_time.minute,
                lease_time.second,
                lease_time.microsecond,
                tzinfo=UTC,
                fold=lease_time.fold,
            )
        if bool(owner_id) != (normalized_lease_until is not None):
            raise ValueError("artifact lease_owner and lease_until must be supplied together")
        if normalized_lease_until is not None and normalized_lease_until <= retained_until:
            raise StateError(
                "artifact lease deadline must extend beyond the artifact retention deadline"
            )

        # Force all value validation and payload encoding before capacity or
        # an external lifecycle transaction is reserved.
        public_record = _canonical_local_artifact_record(record)
        canonical_record = _canonical_local_artifact_record(public_record)
        _pack_artifact_payload(canonical_record.artifact, canonical_record)
        version_id = canonical_record.artifact.artifact_version_id
        with self._gate.mutation(), self._capacity_lock:
            self._require_after_watermark_locked(
                event_time,
                "artifact observed_at",
                allow_boundary=True,
            )
            if len(self._prepared_reservations) >= self._capacity:
                raise LocalArtifactCapacityError(
                    "artifact registry has no free slot: prepared-publication member capacity "
                    "is exhausted; commit, cancel, or prune an unclaimed preparation before "
                    "retrying"
                )
            if version_id in self._prepared_versions:
                raise StateError(
                    f"artifact version {version_id!r} already has a prepared publication"
                )
            located = self._existing_locator(version_id)
            existing_handle: int | None = None
            if located is not None:
                shard, existing_handle = located
                with shard.lock:
                    if (
                        not shard.store.is_live_handle(existing_handle)
                        or shard.store.artifact_version_id(existing_handle) != version_id
                    ):
                        located = None
                    else:
                        current = shard.store.get_by_handle(existing_handle)
                        current_record = shard.store.get_record_by_handle(existing_handle)
                        if current != canonical_record.artifact or (
                            current_record is not None and current_record != canonical_record
                        ):
                            raise ValueError(
                                f"artifact version {version_id!r} was already published with "
                                "different identity or content"
                            )
                        current_deadline = shard.deadlines.deadline(existing_handle)
                        if current_deadline is not None:
                            retained_until = max(
                                retained_until,
                                datetime.fromtimestamp(current_deadline, tz=event_time.tzinfo),
                            )
                            if (
                                normalized_lease_until is not None
                                and normalized_lease_until <= retained_until
                            ):
                                raise StateError(
                                    "artifact lease deadline must extend beyond the retained "
                                    "artifact deadline"
                                )
            if located is None:
                existing_handle = None
                shard = self._reserve_prepared_capacity_slot_locked(
                    canonical_record.artifact.artifact_id
                )

            reservation_id = self._next_reservation_id
            token = LocalArtifactPublishToken(
                record=public_record,
                observed_at=event_time,
                retained_until=retained_until,
                lease_owner=owner_id,
                lease_until=normalized_lease_until,
                _registry_token=id(self),
                _reservation_id=reservation_id,
                _shard_id=shard.shard_id,
                _existing_handle=existing_handle,
            )
            token = replace(
                token, _integrity=hashlib.sha256(f"artifact:{reservation_id}".encode()).hexdigest()
            )
            canonical_token = replace(token, record=canonical_record)
            canonical_preimage = _local_artifact_publish_token_preimage(canonical_token)
            retained_bytes = len(canonical_preimage)
            if retained_bytes > self._prepared_byte_capacity:
                raise LocalArtifactCapacityError(
                    "artifact prepared-publication request-byte capacity exceeded: "
                    f"{retained_bytes} > {self._prepared_byte_capacity}"
                )
            if self._prepared_retained_bytes + retained_bytes > self._prepared_byte_capacity:
                raise LocalArtifactCapacityError(
                    "artifact prepared-publication retained-byte capacity is exhausted; commit, "
                    "cancel, or prune an unclaimed preparation before retrying"
                )
            # Complete every fallible capability allocation before reserving a
            # backing handle or changing any preparation census.
            token_reference = ref(token)
            record_digest = hashlib.sha256(
                _local_artifact_record_preimage(canonical_record)
            ).hexdigest()
            reserved_handle: int | None = None
            try:
                if existing_handle is None:
                    with shard.lock:
                        reserved_handle = shard.store.reserve_handle()
                reservation = _LocalArtifactPreparedReservation(
                    token_ref=token_reference,
                    token_id=id(token),
                    reservation_id=reservation_id,
                    canonical_token=canonical_token,
                    record_digest=record_digest,
                    retained_bytes=retained_bytes,
                    reserved_handle=reserved_handle,
                )
            except BaseException:
                if reserved_handle is not None:
                    with shard.lock:
                        shard.store.release_reserved_handle(reserved_handle)
                raise
            count_installed = False
            bytes_installed = False
            try:
                self._prepared_reservations[reservation_id] = reservation
                self._prepared_capability_locators[id(token)] = reservation_id
                self._prepared_versions[version_id] = reservation_id
                if existing_handle is None:
                    self._prepared_counts[shard.shard_id] += 1
                    count_installed = True
                self._prepared_retained_bytes += retained_bytes
                bytes_installed = True
                self._next_reservation_id += 1
            except BaseException:
                self._prepared_reservations.pop(reservation_id, None)
                self._prepared_capability_locators.pop(id(token), None)
                if self._prepared_versions.get(version_id) == reservation_id:
                    self._prepared_versions.pop(version_id, None)
                if existing_handle is None:
                    if count_installed:
                        self._prepared_counts[shard.shard_id] -= 1
                    if reserved_handle is not None:
                        with shard.lock:
                            shard.store.release_reserved_handle(reserved_handle)
                if bytes_installed:
                    self._prepared_retained_bytes -= retained_bytes
                if not self._prepared_reservations:
                    self._prepared_reservations = {}
                    self._prepared_capability_locators = {}
                    self._prepared_versions = {}
                raise
            return token

    def _reserve_prepared_capacity_slot_locked(self, artifact_id: str) -> _LocalArtifactShard:
        """Reserve only genuinely free backing; preparation never evicts visible state."""

        for shard in self._probe_shards(artifact_id):
            with shard.lock:
                occupied = len(shard.store) + self._prepared_counts[shard.shard_id]
                if occupied < self._shard_capacities[shard.shard_id]:
                    return shard
        raise LocalArtifactCapacityError(
            "artifact registry has no free slot for an allocation-free prepared publication"
        )

    def _active_prepared_locked(
        self,
        token: LocalArtifactPublishToken,
    ) -> _LocalArtifactPreparedReservation:
        if type(token) is not LocalArtifactPublishToken:
            raise StateError("local artifact publish token has an invalid type")
        reservation_id = self._prepared_capability_locators.get(id(token))
        if reservation_id is None:
            raise StateError("local artifact publish token is stale or already consumed")
        active = self._prepared_reservations.get(reservation_id)
        if active is None or active.token_ref() is not token:
            self._prepared_capability_locators.pop(id(token), None)
            raise StateError("local artifact publish token is stale or already consumed")
        return active

    def _release_prepared_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
        *,
        allow_committing: bool = False,
        preserve_commit_locator: bool = False,
    ) -> bool:
        """Release reservation metadata while the capacity lock is held."""

        if reservation.committing and not allow_committing:
            return False
        if self._prepared_reservations.get(reservation.reservation_id) is not reservation:
            return False
        token = reservation.canonical_token
        version_id = token.record.artifact.artifact_version_id
        if self._prepared_retained_bytes < reservation.retained_bytes:
            raise StateError("local artifact prepared retained-byte census is inconsistent")
        remaining_retained_bytes = self._prepared_retained_bytes - reservation.retained_bytes
        remaining_prepared_count: int | None = None
        empty_state: (
            tuple[
                dict[int, _LocalArtifactPreparedReservation],
                dict[int, int],
                dict[int, tuple[int, ...]],
                dict[str, int],
                set[int],
                set[int],
            ]
            | None
        ) = None
        if len(self._prepared_reservations) == 1:
            # Allocate replacement containers before the first backing mutation
            # so locator-last metadata cleanup contains no allocating step.
            empty_state = ({}, {}, {}, {}, set(), set())

        backing_error: BaseException | None = None
        if token._existing_handle is None:
            if reservation.reserved_handle is None:  # pragma: no cover - reservation invariant
                raise StateError("local artifact reservation lost its exact backing handle")
            if self._prepared_counts[token._shard_id] <= 0:
                raise StateError("local artifact prepared slot census is inconsistent")
            remaining_prepared_count = self._prepared_counts[token._shard_id] - 1
            shard = self._shards[token._shard_id]
            with shard.lock:
                handle = reservation.reserved_handle
                if not reservation.backing_released:
                    was_live = shard.store.is_live_handle(handle)
                    try:
                        if was_live:
                            if shard.store._reserved[handle]:
                                shard.store.consume_reserved_handle(handle)
                            elif self._prepared_backing_release_completed(
                                shard.store,
                                handle,
                                was_live=True,
                            ):
                                reservation.backing_released = True
                            else:  # pragma: no cover - store ownership invariant
                                raise StateError(
                                    "local artifact committed backing release is incomplete"
                                )
                        elif shard.store._reserved[handle]:
                            shard.store.release_reserved_handle(handle)
                        elif self._prepared_backing_release_completed(
                            shard.store,
                            handle,
                            was_live=False,
                        ):
                            reservation.backing_released = True
                        else:
                            shard.store.release_reserved_handle(handle)
                    except BaseException as error:
                        if not self._prepared_backing_release_completed(
                            shard.store,
                            handle,
                            was_live=was_live,
                        ):
                            raise
                        reservation.backing_released = True
                        backing_error = error
                    else:
                        reservation.backing_released = True

        # The backing primitive is complete. All following operations are
        # fixed-size built-in mutations; trusted locators disappear last.
        if token._existing_handle is None:
            if remaining_prepared_count is None:  # pragma: no cover - branch invariant
                raise StateError("local artifact prepared slot release lost its census")
            self._prepared_counts[token._shard_id] = remaining_prepared_count
        self._prepared_retained_bytes = remaining_retained_bytes
        if self._prepared_versions.get(version_id) == reservation.reservation_id:
            self._prepared_versions.pop(version_id)
        self._claimed_reservations.discard(reservation.reservation_id)
        self._committing_reservations.discard(reservation.reservation_id)
        self._prepared_capability_locators.pop(reservation.token_id, None)
        if reservation.commit_plan is not None:
            self._publication_receipt_locators.pop(id(reservation.commit_plan.receipt), None)
        if reservation.group_receipt is not None:
            self._publication_group_receipt_locators.pop(id(reservation.group_receipt), None)
        if reservation.commit_id is not None and not preserve_commit_locator:
            self._prepared_commit_locators.pop(reservation.commit_id, None)
        self._prepared_reservations.pop(reservation.reservation_id, None)
        if empty_state is not None:
            (
                self._prepared_reservations,
                self._prepared_capability_locators,
                self._prepared_commit_locators,
                self._prepared_versions,
                self._claimed_reservations,
                self._committing_reservations,
            ) = empty_state
            self._prepared_retained_bytes = 0
        if backing_error is not None:
            raise backing_error
        return True

    @staticmethod
    def _prepared_backing_release_completed(
        store: _PackedArtifactStore,
        handle: int,
        *,
        was_live: bool,
    ) -> bool:
        """Return whether one reserved-handle primitive completed before raising."""

        return store.reserved_release_is_complete(handle, was_live=was_live)

    def _pending_after_prepared_release_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
    ) -> tuple[_LocalArtifactShard, str] | None:
        """Return a due visible version unblocked by releasing a reservation."""

        token = reservation.canonical_token
        if token._existing_handle is None:
            return None
        shard = self._shards[token._shard_id]
        version_id = token.record.artifact.artifact_version_id
        with shard.lock:
            if self._reconcile_unleased_version_locked(shard, version_id):
                return shard, version_id
        return None

    def _prune_prepared_publications_locked(self) -> int:
        """Release ownerless or watermark-stale unclaimed reservations."""

        released = 0
        for reservation_id in tuple(self._prepared_reservations):
            reservation = self._prepared_reservations.get(reservation_id)
            if reservation is None or reservation_id in self._claimed_reservations:
                continue
            owner_is_gone = reservation.token_ref() is None
            observed_at = reservation.canonical_token.observed_at
            watermark_is_stale = self._watermark is not None and observed_at < self._watermark
            if not owner_is_gone and not watermark_is_stale:
                continue
            self._release_prepared_locked(reservation)
            pending = self._pending_after_prepared_release_locked(reservation)
            if pending is not None:
                self._evict_pending_version(*pending)
            released += 1
        return released

    def prune_prepared_publications(self) -> int:
        """Release ownerless or watermark-stale unclaimed publication capabilities."""

        with self._gate.mutation(), self._capacity_lock:
            return self._prune_prepared_publications_locked()

    def authenticates_prepared_publication(self, token: object) -> bool:
        """Totally authenticate one exact active prepared-publication capability."""

        if type(token) is not LocalArtifactPublishToken:
            return False
        with self._capacity_lock:
            try:
                self._active_prepared_locked(token)
            except (
                AssertionError,
                AttributeError,
                OverflowError,
                RecursionError,
                StateError,
                TypeError,
                ValueError,
            ):
                return False
            return True

    def authenticates_publication_receipt(
        self,
        receipt: object,
        *,
        publication_token: str | None = None,
    ) -> bool:
        """Totally authenticate one committed publication receipt and optional binding."""

        if type(receipt) is not LocalArtifactPublicationReceipt:
            return False
        return bool(
            (
                self._publication_receipts.get(id(receipt)) is receipt
                or (
                    (reservation_id := self._publication_receipt_locators.get(id(receipt)))
                    is not None
                    and (reservation := self._prepared_reservations.get(reservation_id)) is not None
                    and reservation.commit_plan is not None
                    and reservation.commit_plan.receipt is receipt
                )
            )
            and (publication_token is None or receipt.publication_token == publication_token)
        )

    def authenticates_publication_group_receipt(
        self,
        receipt: object,
        *,
        publication_tokens: tuple[str, ...] | None = None,
    ) -> bool:
        """Totally authenticate an ordered group receipt and optional token binding."""

        if type(receipt) is not LocalArtifactPublicationGroupReceipt:
            return False
        return bool(
            (
                self._publication_group_receipts.get(id(receipt)) is receipt
                or (
                    (reservation_ids := self._publication_group_receipt_locators.get(id(receipt)))
                    is not None
                    and all(
                        (reservation := self._prepared_reservations.get(reservation_id)) is not None
                        and reservation.group_receipt is receipt
                        for reservation_id in reservation_ids
                    )
                )
            )
            and (publication_tokens is None or receipt.publication_tokens == publication_tokens)
        )

    def cancel_prepared(self, token: object) -> bool:
        """Cancel one uncommitted reservation without publishing any record."""

        pending: list[tuple[_LocalArtifactShard, str]] = []
        cleanup_errors: list[BaseException] = []
        intact = False
        with self._gate.mutation(), self._capacity_lock:
            if type(token) is not LocalArtifactPublishToken:
                return False
            reservation_id = self._prepared_capability_locators.get(id(token))
            reservation = (
                None if reservation_id is None else self._prepared_reservations.get(reservation_id)
            )
            if reservation is None:
                return False
            if reservation.token_ref() is not token:
                if reservation.token_ref() is None:
                    cleanup_errors.extend(
                        self._release_failed_claim_locked((reservation,), pending)
                    )
                else:
                    self._prepared_capability_locators.pop(id(token), None)
                intact = False
            elif reservation.reservation_id in self._claimed_reservations:
                return False
            else:
                try:
                    self._active_prepared_locked(token)
                except (
                    AssertionError,
                    AttributeError,
                    OverflowError,
                    RecursionError,
                    StateError,
                    TypeError,
                    ValueError,
                ):
                    intact = False
                else:
                    intact = True
                cleanup_errors.extend(self._release_failed_claim_locked((reservation,), pending))
        cleanup_errors.extend(self._evict_failed_claim_pending(pending))
        if cleanup_errors:
            primary = cleanup_errors[0]
            for cleanup_error in cleanup_errors[1:]:
                primary.add_note(
                    "local artifact cancellation cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary
        return intact

    @contextmanager
    def prepared_publication(
        self,
        token: LocalArtifactPublishToken,
    ) -> Iterator[LocalArtifactPreparedCommit]:
        """Claim a coupled transaction and yield its artifact-first capability.

        Claiming is a short artifact-only critical section. No artifact lock is
        retained while the caller claims and authenticates the other owners.
        The caller invokes ``commit_no_fail()`` before any irreversible external
        owner commit. An artifact exception restores local state; a stale token,
        context exception, or omitted commit cancels the claim and publishes
        nothing.
        """

        transaction = self._claim_prepared(token)
        try:
            yield transaction
        except BaseException as primary_error:
            # Registry state, not caller-mutable transaction projections, is
            # authoritative for cleanup. A committed reservation is already
            # absent; every other claimed reservation is released here.
            try:
                self._cancel_claimed(transaction)
            except BaseException as cleanup_error:
                primary_error.add_note(
                    "local artifact claim cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            try:
                transaction._close()
            except BaseException as close_error:  # pragma: no cover - primitive assignment
                primary_error.add_note(
                    "local artifact capability close also raised "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            cleanup_error: BaseException | None = None
            try:
                self._cancel_claimed(transaction)
            except BaseException as error:
                cleanup_error = error
            try:
                transaction._close()
            except BaseException as close_error:  # pragma: no cover - primitive assignment
                if cleanup_error is not None:
                    cleanup_error.add_note(
                        "local artifact capability close also raised "
                        f"{type(close_error).__name__}: {close_error}"
                    )
                else:
                    raise
            if cleanup_error is not None:
                raise cleanup_error

    @contextmanager
    def prepared_publication_group(
        self,
        tokens: Sequence[LocalArtifactPublishToken],
    ) -> Iterator[LocalArtifactPreparedGroupCommit]:
        """Claim a nonempty ordered token group and yield its all-or-zero commit."""

        token_tuple = tuple(islice(tokens, self._capacity + 1))
        if len(token_tuple) > self._capacity:
            raise LocalArtifactCapacityError(
                "local artifact publication group exceeds the registry member capacity"
            )
        transaction = self._claim_prepared_group(token_tuple)
        try:
            yield transaction
        except BaseException as primary_error:
            try:
                self._cancel_claimed_group(transaction)
            except BaseException as cleanup_error:
                primary_error.add_note(
                    "local artifact group cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            try:
                transaction._close()
            except BaseException as close_error:  # pragma: no cover - primitive assignment
                primary_error.add_note(
                    "local artifact group capability close also raised "
                    f"{type(close_error).__name__}: {close_error}"
                )
            raise
        else:
            cleanup_error: BaseException | None = None
            try:
                self._cancel_claimed_group(transaction)
            except BaseException as error:
                cleanup_error = error
            try:
                transaction._close()
            except BaseException as close_error:  # pragma: no cover - primitive assignment
                if cleanup_error is not None:
                    cleanup_error.add_note(
                        "local artifact group capability close also raised "
                        f"{type(close_error).__name__}: {close_error}"
                    )
                else:
                    raise
            if cleanup_error is not None:
                raise cleanup_error

    def _release_failed_claim_locked(
        self,
        reservations: Sequence[_LocalArtifactPreparedReservation],
        pending: list[tuple[_LocalArtifactShard, str]],
    ) -> tuple[BaseException, ...]:
        """Best-effort every failed pre-yield group release and retain cleanup errors."""

        failures: list[BaseException] = []
        released_ids: set[int] = set()
        for reservation in reversed(reservations):
            try:
                self._release_prepared_locked(reservation)
            except BaseException as error:
                failures.append(error)
            if self._prepared_reservations.get(reservation.reservation_id) is not reservation:
                released_ids.add(reservation.reservation_id)
                try:
                    due = self._pending_after_prepared_release_locked(reservation)
                    if due is not None:
                        pending.append(due)
                except BaseException as error:
                    failures.append(error)

        # A one-shot cleanup fault before mutation must not strand a claim that
        # has no context-manager finalizer yet. Retry only exact live members.
        for reservation in reversed(reservations):
            if self._prepared_reservations.get(reservation.reservation_id) is not reservation:
                continue
            try:
                self._release_prepared_locked(reservation)
            except BaseException as error:
                failures.append(error)
            if (
                self._prepared_reservations.get(reservation.reservation_id) is not reservation
                and reservation.reservation_id not in released_ids
            ):
                released_ids.add(reservation.reservation_id)
                try:
                    due = self._pending_after_prepared_release_locked(reservation)
                    if due is not None:
                        pending.append(due)
                except BaseException as error:
                    failures.append(error)
        return tuple(failures)

    def _evict_failed_claim_pending(
        self,
        pending: Sequence[tuple[_LocalArtifactShard, str]],
    ) -> tuple[BaseException, ...]:
        """Attempt every due eviction and retry one-shot cleanup faults once."""

        failures: list[BaseException] = []
        retry: list[tuple[_LocalArtifactShard, str]] = []
        for shard, version_id in pending:
            try:
                self._evict_pending_version(shard, version_id)
            except BaseException as error:
                failures.append(error)
                retry.append((shard, version_id))
        for shard, version_id in retry:
            try:
                self._evict_pending_version(shard, version_id)
            except BaseException as error:
                failures.append(error)
        return tuple(failures)

    def _claim_prepared_group(
        self,
        tokens: tuple[LocalArtifactPublishToken, ...],
    ) -> LocalArtifactPreparedGroupCommit:
        """Authenticate and claim every ordered group member under one registry boundary."""

        if not tokens:
            raise ValueError("local artifact publication group must contain at least one token")
        if len(tokens) > self._capacity:
            raise LocalArtifactCapacityError(
                "local artifact publication group exceeds the registry member capacity"
            )
        if any(type(token) is not LocalArtifactPublishToken for token in tokens):
            raise TypeError("local artifact publication group tokens must be exact publish tokens")
        token_ids = tuple(id(token) for token in tokens)
        if len(set(token_ids)) != len(token_ids):
            raise StateError("local artifact publication group contains a duplicate token")

        pending: list[tuple[_LocalArtifactShard, str]] = []
        transaction: LocalArtifactPreparedGroupCommit | None = None
        claimant_thread_id = get_ident()
        primary_error: BaseException | None = None
        try:
            with self._gate.mutation(), self._capacity_lock:
                reservations: list[_LocalArtifactPreparedReservation] = []
                for token in tokens:
                    reservation_id = self._prepared_capability_locators.get(id(token))
                    reservation = (
                        None
                        if reservation_id is None
                        else self._prepared_reservations.get(reservation_id)
                    )
                    if reservation is None or reservation.token_ref() is not token:
                        raise StateError("local artifact publication group contains a stale token")
                    if reservation.reservation_id in self._claimed_reservations:
                        raise StateError(
                            "local artifact publication group contains an already claimed token"
                        )
                    reservations.append(reservation)
                reservation_ids = tuple(reservation.reservation_id for reservation in reservations)
                if len(set(reservation_ids)) != len(reservation_ids):
                    raise StateError(
                        "local artifact publication group resolves duplicate reservations"
                    )
                if (
                    sum(reservation.retained_bytes for reservation in reservations)
                    > self._prepared_byte_capacity
                ):
                    raise LocalArtifactCapacityError(
                        "local artifact publication group exceeds retained-byte capacity"
                    )

                plans: list[_LocalArtifactPreparedCommitPlan] = []
                try:
                    for token, reservation in zip(tokens, reservations, strict=True):
                        self._active_prepared_locked(token)
                        self._require_after_watermark_locked(
                            reservation.canonical_token.observed_at,
                            "artifact observed_at",
                            allow_boundary=True,
                        )
                        trusted_token = reservation.canonical_token
                        shard = self._shards[trusted_token._shard_id]
                        with shard.lock:
                            if trusted_token._existing_handle is not None and (
                                not shard.store.is_live_handle(trusted_token._existing_handle)
                                or shard.store.artifact_version_id(trusted_token._existing_handle)
                                != trusted_token.record.artifact.artifact_version_id
                            ):
                                raise StateError(
                                    "prepared local artifact group member was invalidated"
                                )
                            plans.append(self._prepare_claimed_commit_locked(reservation, shard))
                    publication_tokens = tuple(
                        reservation.canonical_token.publication_token
                        for reservation in reservations
                    )
                    group_receipt = LocalArtifactPublicationGroupReceipt(
                        receipts=tuple(plan.receipt for plan in plans),
                        publication_tokens=publication_tokens,
                        _registry_token=id(self),
                    )
                    group_receipt = replace(
                        group_receipt,
                        _integrity=hashlib.sha256(
                            "\0".join(publication_tokens).encode()
                        ).hexdigest(),
                    )
                    self._publication_group_receipt_locators[id(group_receipt)] = reservation_ids
                    transaction = LocalArtifactPreparedGroupCommit(
                        self,
                        publication_tokens,
                        claimant_thread_id,
                        group_receipt,
                    )
                    transaction_reference = ref(transaction)
                except BaseException as error:
                    for cleanup_error in self._release_failed_claim_locked(
                        reservations,
                        pending,
                    ):
                        error.add_note(
                            "local artifact group claim cleanup also raised "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                    raise

                try:
                    for reservation, plan in zip(reservations, plans, strict=True):
                        self._claimed_reservations.add(reservation.reservation_id)
                        reservation.claimed_by = claimant_thread_id
                        reservation.commit_ref = transaction_reference
                        reservation.commit_id = id(transaction)
                        reservation.commit_plan = plan
                        reservation.group_receipt = group_receipt
                    self._prepared_commit_locators[id(transaction)] = reservation_ids
                except BaseException as error:
                    self._prepared_commit_locators.pop(id(transaction), None)
                    for reservation in reservations:
                        self._claimed_reservations.discard(reservation.reservation_id)
                        reservation.claimed_by = None
                        reservation.commit_ref = None
                        reservation.commit_id = None
                        reservation.commit_plan = None
                        reservation.group_receipt = None
                    for cleanup_error in self._release_failed_claim_locked(
                        reservations,
                        pending,
                    ):
                        error.add_note(
                            "local artifact group claim cleanup also raised "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                    raise
        except BaseException as error:
            primary_error = error

        eviction_errors = self._evict_failed_claim_pending(pending)
        if primary_error is not None:
            for cleanup_error in eviction_errors:
                primary_error.add_note(
                    "local artifact group pending-eviction cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary_error
        if eviction_errors:
            primary_eviction_error = eviction_errors[0]
            for cleanup_error in eviction_errors[1:]:
                primary_eviction_error.add_note(
                    "local artifact group pending-eviction cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary_eviction_error
        if transaction is None:  # pragma: no cover - successful claim invariant
            raise StateError("local artifact group claim produced no commit capability")
        return transaction

    def _claim_prepared(
        self,
        token: LocalArtifactPublishToken,
    ) -> LocalArtifactPreparedCommit:
        """Validate and claim one token without retaining locks across the caller."""

        pending: list[tuple[_LocalArtifactShard, str]] = []
        transaction: LocalArtifactPreparedCommit | None = None
        claimant_thread_id = get_ident()
        primary_error: BaseException | None = None
        try:
            with self._gate.mutation(), self._capacity_lock:
                reservation_id = self._prepared_capability_locators.get(id(token))
                reservation = (
                    None
                    if reservation_id is None
                    else self._prepared_reservations.get(reservation_id)
                )
                if reservation is None or reservation.token_ref() is not token:
                    raise StateError("local artifact publish token is stale or already consumed")
                if reservation.reservation_id in self._claimed_reservations:
                    raise StateError("local artifact publish token is already claimed")
                try:
                    self._active_prepared_locked(token)
                    self._require_after_watermark_locked(
                        reservation.canonical_token.observed_at,
                        "artifact observed_at",
                        allow_boundary=True,
                    )
                    trusted_token = reservation.canonical_token
                    shard = self._shards[trusted_token._shard_id]
                    with shard.lock:
                        if trusted_token._existing_handle is not None and (
                            not shard.store.is_live_handle(trusted_token._existing_handle)
                            or shard.store.artifact_version_id(trusted_token._existing_handle)
                            != trusted_token.record.artifact.artifact_version_id
                        ):
                            raise StateError("prepared local artifact version was invalidated")
                        commit_plan = self._prepare_claimed_commit_locked(reservation, shard)
                    transaction = LocalArtifactPreparedCommit(
                        self,
                        trusted_token.publication_token,
                        claimant_thread_id,
                        commit_plan.receipt,
                    )
                    transaction_reference = ref(transaction)
                except BaseException as error:
                    for cleanup_error in self._release_failed_claim_locked(
                        (reservation,),
                        pending,
                    ):
                        error.add_note(
                            "local artifact claim cleanup also raised "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                    raise
                try:
                    self._claimed_reservations.add(reservation.reservation_id)
                    reservation.claimed_by = claimant_thread_id
                    reservation.commit_ref = transaction_reference
                    reservation.commit_id = id(transaction)
                    reservation.commit_plan = commit_plan
                    self._prepared_commit_locators[id(transaction)] = (reservation.reservation_id,)
                except BaseException as error:
                    self._prepared_commit_locators.pop(id(transaction), None)
                    self._claimed_reservations.discard(reservation.reservation_id)
                    reservation.claimed_by = None
                    reservation.commit_ref = None
                    reservation.commit_id = None
                    reservation.commit_plan = None
                    for cleanup_error in self._release_failed_claim_locked(
                        (reservation,),
                        pending,
                    ):
                        error.add_note(
                            "local artifact claim cleanup also raised "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
                    raise
        except BaseException as error:
            primary_error = error

        eviction_errors = self._evict_failed_claim_pending(pending)
        if primary_error is not None:
            for cleanup_error in eviction_errors:
                primary_error.add_note(
                    "local artifact claim pending-eviction cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary_error
        if eviction_errors:
            primary_eviction_error = eviction_errors[0]
            for cleanup_error in eviction_errors[1:]:
                primary_eviction_error.add_note(
                    "local artifact claim pending-eviction cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary_eviction_error
        if transaction is None:  # pragma: no cover - successful claim invariant
            raise StateError("local artifact prepared claim produced no commit capability")
        return transaction

    def _active_claimed_commit_locked(
        self,
        transaction: LocalArtifactPreparedCommit,
    ) -> _LocalArtifactPreparedReservation:
        """Resolve one exact context-only commit capability without caller token fields."""

        if type(transaction) is not LocalArtifactPreparedCommit:
            raise StateError("local artifact prepared commit has an invalid type")
        reservation_ids = self._prepared_commit_locators.get(id(transaction))
        reservation_id = (
            None if reservation_ids is None or len(reservation_ids) != 1 else reservation_ids[0]
        )
        reservation = (
            None if reservation_id is None else self._prepared_reservations.get(reservation_id)
        )
        if (
            reservation is None
            or reservation.commit_ref is None
            or reservation.commit_ref() is not transaction
        ):
            raise StateError("local artifact prepared commit is stale or already consumed")
        if reservation.reservation_id not in self._claimed_reservations:
            raise StateError("local artifact publish token is not claimed")
        return reservation

    def _active_claimed_group_locked(
        self,
        transaction: LocalArtifactPreparedGroupCommit,
    ) -> tuple[_LocalArtifactPreparedReservation, ...]:
        """Resolve one exact group capability entirely through registry-owned locators."""

        if type(transaction) is not LocalArtifactPreparedGroupCommit:
            raise StateError("local artifact prepared group commit has an invalid type")
        reservation_ids = self._prepared_commit_locators.get(id(transaction))
        if reservation_ids is None or not reservation_ids:
            raise StateError("local artifact prepared group commit is stale or already consumed")
        reservations: list[_LocalArtifactPreparedReservation] = []
        for reservation_id in reservation_ids:
            reservation = self._prepared_reservations.get(reservation_id)
            if (
                reservation is None
                or reservation.commit_ref is None
                or reservation.commit_ref() is not transaction
                or reservation.reservation_id not in self._claimed_reservations
            ):
                raise StateError(
                    "local artifact prepared group commit is stale or already consumed"
                )
            reservations.append(reservation)
        return tuple(reservations)

    def _remaining_claimed_group_locked(
        self,
        transaction: LocalArtifactPreparedGroupCommit,
    ) -> tuple[_LocalArtifactPreparedReservation, ...]:
        """Resolve the still-live suffix of a group during failure cleanup."""

        if type(transaction) is not LocalArtifactPreparedGroupCommit:
            raise StateError("local artifact prepared group commit has an invalid type")
        reservation_ids = self._prepared_commit_locators.get(id(transaction))
        if reservation_ids is None:
            return ()
        remaining: list[_LocalArtifactPreparedReservation] = []
        for reservation_id in reservation_ids:
            reservation = self._prepared_reservations.get(reservation_id)
            if reservation is None:
                continue
            if (
                reservation.commit_ref is None
                or reservation.commit_ref() is not transaction
                or reservation.reservation_id not in self._claimed_reservations
            ):
                raise StateError("local artifact prepared group cleanup locator is invalid")
            remaining.append(reservation)
        return tuple(remaining)

    def _cancel_claimed(self, transaction: LocalArtifactPreparedCommit) -> None:
        """Release an owned claim after its external transaction aborts."""

        pending: list[tuple[_LocalArtifactShard, str]] = []
        failures: list[BaseException] = []
        with self._gate.mutation(), self._capacity_lock:
            try:
                reservation = self._active_claimed_commit_locked(transaction)
            except StateError:
                return
            if reservation.claimed_by != get_ident():
                raise StateError(
                    "local artifact prepared publication must cancel on its claiming thread"
                )
            if reservation.committing:
                return
            failures.extend(self._release_failed_claim_locked((reservation,), pending))
        failures.extend(self._evict_failed_claim_pending(pending))
        if failures:
            primary = failures[0]
            for cleanup_error in failures[1:]:
                primary.add_note(
                    "local artifact claim cancellation also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary

    def _cancel_claimed_group(self, transaction: LocalArtifactPreparedGroupCommit) -> None:
        """Release every member of an uncommitted exact group claim."""

        pending: list[tuple[_LocalArtifactShard, str]] = []
        failures: list[BaseException] = []
        released_ids: set[int] = set()
        with self._gate.mutation(), self._capacity_lock:
            reservations = self._remaining_claimed_group_locked(transaction)
            if not reservations:
                self._prepared_commit_locators.pop(id(transaction), None)
                return
            if any(reservation.claimed_by != get_ident() for reservation in reservations):
                raise StateError(
                    "local artifact prepared publication group must cancel on its claiming thread"
                )
            if any(reservation.committing for reservation in reservations):
                return
            for reservation in reversed(reservations):
                try:
                    self._release_prepared_locked(
                        reservation,
                        preserve_commit_locator=True,
                    )
                except BaseException as error:
                    failures.append(error)
                if self._prepared_reservations.get(reservation.reservation_id) is not reservation:
                    released_ids.add(reservation.reservation_id)
                    due = self._pending_after_prepared_release_locked(reservation)
                    if due is not None:
                        pending.append(due)

            # A one-shot cleanup fault must not strand the group merely because
            # it fired before the member release. Retry only still-live members.
            remaining = self._remaining_claimed_group_locked(transaction)
            for reservation in reversed(remaining):
                try:
                    self._release_prepared_locked(
                        reservation,
                        preserve_commit_locator=True,
                    )
                except BaseException as error:
                    failures.append(error)
                if (
                    self._prepared_reservations.get(reservation.reservation_id) is not reservation
                    and reservation.reservation_id not in released_ids
                ):
                    released_ids.add(reservation.reservation_id)
                    due = self._pending_after_prepared_release_locked(reservation)
                    if due is not None:
                        pending.append(due)
            if not self._remaining_claimed_group_locked(transaction):
                self._prepared_commit_locators.pop(id(transaction), None)
        for shard, version_id in pending:
            self._evict_pending_version(shard, version_id)
        if failures:
            primary = failures[0]
            for cleanup_error in failures[1:]:
                primary.add_note(
                    "local artifact group cleanup also raised "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
            raise primary

    def _commit_claimed(
        self,
        transaction: LocalArtifactPreparedCommit,
    ) -> LocalArtifactPublicationReceipt:
        """Commit a claimed reservation in one short artifact-only critical section."""

        with self._gate.mutation(), self._capacity_lock:
            reservation = self._active_claimed_commit_locked(transaction)
            if reservation.claimed_by != get_ident():
                raise StateError(
                    "local artifact prepared publication must commit on its claiming thread"
                )
            if reservation.committing:
                raise StateError("local artifact prepared publication is already committing")
            shard = self._shards[reservation.canonical_token._shard_id]
            with shard.lock:
                plan = reservation.commit_plan
                if plan is None:
                    raise StateError("local artifact prepared commit lost its sealed plan")
                if (
                    transaction._expected_receipt is not plan.receipt
                    or type(transaction._publication_token) is not str
                    or transaction._publication_token != plan.receipt.publication_token
                    or plan.receipt.publication_token
                    != reservation.canonical_token.publication_token
                ):
                    raise StateError("local artifact prepared receipt integrity validation failed")
                reservation.committing = True
                self._committing_reservations.add(reservation.reservation_id)
                try:
                    self._capture_prepared_rollback_locked(reservation, plan, shard)
                    receipt = self._commit_prepared_locked(reservation, plan)
                    if not self._release_prepared_locked(
                        reservation,
                        allow_committing=True,
                    ):
                        raise StateError(
                            "local artifact committed reservation could not be finalized"
                        )
                except BaseException as error:
                    rollback_errors = self._rollback_prepared_commit_locked(
                        reservation,
                        plan,
                        shard,
                    )
                    released = (
                        self._prepared_reservations.get(reservation.reservation_id)
                        is not reservation
                    )
                    if not released:
                        try:
                            released = self._release_prepared_locked(
                                reservation,
                                allow_committing=True,
                            )
                        except BaseException as cleanup_error:
                            rollback_errors += (cleanup_error,)
                            released = False
                    for rollback_error in rollback_errors:
                        error.add_note(
                            "local artifact rollback cleanup also raised "
                            f"{type(rollback_error).__name__}: {rollback_error}"
                        )
                    if released:
                        pending = self._pending_after_prepared_release_locked(reservation)
                        if pending is not None:
                            self._evict_pending_version(*pending)
                    raise
                self._publication_receipts[id(receipt)] = receipt
                return receipt

    def _commit_claimed_group(
        self,
        transaction: LocalArtifactPreparedGroupCommit,
    ) -> LocalArtifactPublicationGroupReceipt:
        """Commit every claimed group member under one reversible artifact boundary."""

        with self._gate.mutation(), self._capacity_lock:
            reservations = self._active_claimed_group_locked(transaction)
            if any(reservation.claimed_by != get_ident() for reservation in reservations):
                raise StateError(
                    "local artifact prepared publication group must commit on its claiming thread"
                )
            if any(reservation.committing for reservation in reservations):
                raise StateError("local artifact prepared publication group is already committing")

            group_receipt = reservations[0].group_receipt
            if group_receipt is None or any(
                reservation.group_receipt is not group_receipt for reservation in reservations
            ):
                raise StateError("local artifact prepared publication group lost its receipt")
            if (
                transaction._expected_receipt is not group_receipt
                or transaction._publication_tokens is not group_receipt.publication_tokens
            ):
                raise StateError(
                    "local artifact prepared publication group receipt integrity validation failed"
                )
            entries: list[
                tuple[
                    _LocalArtifactPreparedReservation,
                    _LocalArtifactPreparedCommitPlan,
                    _LocalArtifactShard,
                ]
            ] = []
            for reservation in reservations:
                plan = reservation.commit_plan
                if plan is None:
                    raise StateError("local artifact prepared group member lost its sealed plan")
                entries.append(
                    (
                        reservation,
                        plan,
                        self._shards[reservation.canonical_token._shard_id],
                    )
                )
            shard_ids = tuple(sorted({shard.shard_id for _, _, shard in entries}))
            touched = 0
            with ExitStack() as locks:
                for shard_id in shard_ids:
                    locks.enter_context(self._shards[shard_id].lock)
                for reservation in reservations:
                    reservation.committing = True
                    self._committing_reservations.add(reservation.reservation_id)
                try:
                    for reservation, plan, shard in entries:
                        self._capture_prepared_rollback_locked(reservation, plan, shard)
                        touched += 1
                        self._commit_prepared_locked(reservation, plan)
                    for reservation in reversed(reservations):
                        if not self._release_prepared_locked(
                            reservation,
                            allow_committing=True,
                            preserve_commit_locator=True,
                        ):
                            raise StateError(
                                "local artifact committed group member could not be finalized"
                            )
                except BaseException as error:
                    rollback_errors: list[BaseException] = []
                    for index in range(touched - 1, -1, -1):
                        reservation, plan, shard = entries[index]
                        rollback_errors.extend(
                            self._rollback_prepared_commit_locked(
                                reservation,
                                plan,
                                shard,
                            )
                        )
                    released_reservations: list[_LocalArtifactPreparedReservation] = []
                    for reservation in reversed(reservations):
                        if (
                            self._prepared_reservations.get(reservation.reservation_id)
                            is not reservation
                        ):
                            released_reservations.append(reservation)
                            continue
                        try:
                            if self._release_prepared_locked(
                                reservation,
                                allow_committing=True,
                                preserve_commit_locator=True,
                            ):
                                released_reservations.append(reservation)
                        except BaseException as cleanup_error:
                            rollback_errors.append(cleanup_error)
                    for released in released_reservations:
                        try:
                            pending = self._pending_after_prepared_release_locked(released)
                            if pending is not None:
                                self._evict_pending_version(*pending)
                        except BaseException as cleanup_error:
                            rollback_errors.append(cleanup_error)
                    for rollback_error in rollback_errors:
                        error.add_note(
                            "local artifact group rollback cleanup also raised "
                            f"{type(rollback_error).__name__}: {rollback_error}"
                        )
                    if not any(
                        self._prepared_reservations.get(reservation.reservation_id) is reservation
                        for reservation in reservations
                    ):
                        self._prepared_commit_locators.pop(id(transaction), None)
                    else:
                        for reservation in reservations:
                            if (
                                self._prepared_reservations.get(reservation.reservation_id)
                                is reservation
                            ):
                                reservation.committing = False
                                self._committing_reservations.discard(reservation.reservation_id)
                    raise
                self._prepared_commit_locators.pop(id(transaction), None)
                for member in group_receipt.receipts:
                    self._publication_receipts[id(member)] = member
                self._publication_group_receipts[id(group_receipt)] = group_receipt
            return group_receipt

    def _prepare_claimed_commit_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
        shard: _LocalArtifactShard,
    ) -> _LocalArtifactPreparedCommitPlan:
        """Precompute every expected-fallible tail primitive before publication."""

        token = reservation.canonical_token
        version_id = token.record.artifact.artifact_version_id
        existing_handle = token._existing_handle
        expected_handle = (
            reservation.reserved_handle if existing_handle is None else existing_handle
        )
        if expected_handle is None:  # pragma: no cover - reservation invariant
            raise StateError("prepared local artifact reservation lost its exact handle")
        prior_payload: bytes | None = None
        route: _ArtifactRouteShard | None = None
        route_key: bytes | None = None
        packed_route_locator: int | None = None
        if existing_handle is not None:
            if (
                not shard.store.is_live_handle(existing_handle)
                or shard.store.artifact_version_id(existing_handle) != version_id
                or shard.store.get_by_handle(existing_handle) != token.record.artifact
            ):
                raise StateError("prepared local artifact version was invalidated")
            existing_record = shard.store.get_record_by_handle(existing_handle)
            if existing_record is not None and existing_record != token.record:
                raise StateError("prepared local artifact content changed before commit")
            prior_payload = shard.store._payload(existing_handle)
        else:
            route_key = _semantic_artifact_digest(version_id, "artifact-version-")
            if route_key is None:
                raise StateError("prepared local artifact route key is not canonical")
            packed_route_locator = _pack_artifact_locator(shard.shard_id, expected_handle)
            if shard.shard_id == self._shard_id_for(version_id):
                route_key = None
                packed_route_locator = None
            else:
                route = self._route_partition(version_id)

        packed_payload = _pack_artifact_payload(token.record.artifact, token.record)
        retained_deadline = token.retained_until.timestamp()
        if not math.isfinite(retained_deadline):
            raise StateError("prepared local artifact retention deadline must be finite")
        prior_deadline = shard.deadlines.deadline(expected_handle)
        final_deadline = (
            retained_deadline if prior_deadline is None else max(retained_deadline, prior_deadline)
        )
        shard.deadlines.validate_set(expected_handle, final_deadline)

        lease_deadline: float | None = None
        lease_savepoint: _LocalArtifactLeaseSavepoint | None = None
        if token.lease_until is not None:
            lease_deadline = token.lease_until.timestamp()
            if not math.isfinite(lease_deadline):
                raise StateError("prepared local artifact lease deadline must be finite")
            lease_pair = (version_id, token.lease_owner)
            hash(lease_pair)
            lease_savepoint = _LocalArtifactLeaseSavepoint(pair=lease_pair)

        receipt = LocalArtifactPublicationReceipt(
            reservation_id=reservation.reservation_id,
            artifact_version_id=version_id,
            shard_id=token._shard_id,
            handle=expected_handle,
            publication_token=token.publication_token,
            record_digest=reservation.record_digest,
            _registry_token=id(self),
        )
        receipt = replace(receipt, _integrity=token.publication_token)
        self._publication_receipt_locators[id(receipt)] = reservation.reservation_id
        return _LocalArtifactPreparedCommitPlan(
            expected_handle=expected_handle,
            packed_payload=packed_payload,
            retained_deadline=final_deadline,
            lease_deadline=lease_deadline,
            receipt=receipt,
            prior_payload=prior_payload,
            route=route,
            route_key=route_key,
            packed_route_locator=packed_route_locator,
            rollback=_LocalArtifactPreparedRollbackSavepoint(lease=lease_savepoint),
        )

    def _capture_prepared_rollback_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
        shard: _LocalArtifactShard,
    ) -> None:
        """Capture post-interleaving rollback frontiers immediately before mutation."""

        rollback = plan.rollback
        if rollback.captured:
            raise StateError("local artifact prepared rollback savepoint was already captured")
        token = reservation.canonical_token
        version_id = token.record.artifact.artifact_version_id
        handle = plan.expected_handle
        deadlines = shard.deadlines
        rollback.prior_deadline_us = deadlines._deadlines[handle]
        rollback.prior_pending_expiry = version_id in shard.pending_expiry
        rollback.prior_mutation_version = shard.mutation_version
        rollback.prior_live_count = self._live_count
        rollback.prior_high_water_mark = self._high_water_mark
        rollback.prior_store_next_handle = shard.store._next_handle
        rollback.prior_store_high_water = shard.store._high_water
        rollback.prior_store_compaction_rotations = shard.store._compaction_rotations
        rollback.prior_store_compaction_work = shard.store._compaction_work
        rollback.prior_deadline_generation = deadlines._generations[handle]
        rollback.prior_deadline_order = deadlines._orders[handle]
        rollback.prior_deadline_live = deadlines._live
        rollback.prior_deadline_high_water = deadlines._high_water
        rollback.prior_deadline_order_counter = deadlines._order_counter
        if plan.route is not None:
            with plan.route.lock:
                rollback.prior_route_high_water = plan.route.high_water

        lease = rollback.lease
        if lease is not None:
            lease_store = shard.leases._leases
            expirations = shard.leases._expirations
            pair = lease.pair
            lease.pair_present = pair in lease_store
            lease.prior_deadline = expirations._deadlines.get(pair)
            lease.prior_item = expirations._items.get(pair)
            lease.prior_order = expirations._orders.get(pair)
            lease.prior_version = expirations._versions.get(pair)
            lease.prior_next_order = expirations._next_order
            lease.prior_high_water = expirations._high_water_mark
            lease.prior_leased_key_count = shard.leases._leased_key_count
            lease.prior_store_high_water = lease_store._high_water_mark
            lease.prior_store_primary_peak = lease_store._primary_peak_entries
            lease.prior_store_slots = len(lease_store._slot_values)
        rollback.captured = True

    def _rollback_prepared_commit_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
        shard: _LocalArtifactShard,
    ) -> tuple[BaseException, ...]:
        """Restore every tail component and return any cleanup-only failures."""

        token = reservation.canonical_token
        version_id = token.record.artifact.artifact_version_id
        rollback = plan.rollback
        failures: list[BaseException] = []
        if not rollback.captured:
            return ()
        reservation_is_active = (
            self._prepared_reservations.get(reservation.reservation_id) is reservation
        )

        try:
            if token._existing_handle is None:
                if (
                    shard.store.is_live_handle(plan.expected_handle)
                    and not shard.store._reserved[plan.expected_handle]
                ):
                    # Successful reservation cleanup may have consumed the
                    # allocator claim immediately before an injected failure.
                    shard.store._reserved[plan.expected_handle] = 1
                shard.store.rollback_reserved_insert(plan.expected_handle)
                if (
                    plan.route is not None
                    and plan.route_key is not None
                    and plan.packed_route_locator is not None
                ):
                    with plan.route.lock:
                        if plan.route.routes.get(plan.route_key) == plan.packed_route_locator:
                            plan.route.routes.pop(plan.route_key)
                        plan.route.high_water = rollback.prior_route_high_water
                        if not plan.route.routes:
                            plan.route.routes = {}
            else:
                if plan.prior_payload is None:  # pragma: no cover - existing-handle invariant
                    raise StateError("prepared local artifact rollback lost its prior payload")
                shard.store._store_payload(plan.expected_handle, plan.prior_payload)
            self._live_count = rollback.prior_live_count
            self._high_water_mark = rollback.prior_high_water_mark
            shard.store._high_water = rollback.prior_store_high_water
            shard.store._compaction_rotations = rollback.prior_store_compaction_rotations
            shard.store._compaction_work = rollback.prior_store_compaction_work
            if rollback.prior_pending_expiry:
                shard.pending_expiry.add(version_id)
            else:
                shard.pending_expiry.discard(version_id)
            shard.mutation_version = rollback.prior_mutation_version
        except BaseException as error:
            failures.append(error)

        try:
            deadlines = shard.deadlines
            deadlines._deadlines[plan.expected_handle] = rollback.prior_deadline_us
            deadlines._generations[plan.expected_handle] = rollback.prior_deadline_generation
            deadlines._orders[plan.expected_handle] = rollback.prior_deadline_order
            deadlines._live = rollback.prior_deadline_live
            deadlines._high_water = rollback.prior_deadline_high_water
            deadlines._order_counter = rollback.prior_deadline_order_counter
            deadlines.compact(force=True)
        except BaseException as error:
            failures.append(error)

        try:
            if rollback.lease is not None:
                self._restore_prepared_lease_locked(shard, rollback.lease)
        except BaseException as error:
            failures.append(error)

        if not reservation_is_active and token._existing_handle is None:
            try:
                if shard.store._reserved[plan.expected_handle] and not shard.store.is_live_handle(
                    plan.expected_handle
                ):
                    shard.store.release_reserved_handle(plan.expected_handle)
            except BaseException as error:
                failures.append(error)

        return tuple(failures)

    @staticmethod
    def _restore_prepared_lease_locked(
        shard: _LocalArtifactShard,
        savepoint: _LocalArtifactLeaseSavepoint,
    ) -> None:
        """Restore one lease pair without traversing caller-controlled capability fields."""

        leases = shard.leases
        lease_store = leases._leases
        expirations = leases._expirations
        pair = savepoint.pair

        inserted_handle: int | None = None
        if not savepoint.pair_present and pair in lease_store:
            inserted_handle = lease_store.handle_for(pair)
            lease_store.pop(pair)
        if (
            inserted_handle is not None
            and inserted_handle == len(lease_store._slot_values) - 1
            and len(lease_store._slot_values) > savepoint.prior_store_slots
        ):
            if lease_store._free_handles[-1] != inserted_handle:
                raise StateError("local artifact lease rollback lost its inserted free handle")
            lease_store._free_handles.pop()
            lease_store._slot_keys.pop()
            lease_store._slot_values.pop()
        leases._leased_key_count = savepoint.prior_leased_key_count
        lease_store._high_water_mark = savepoint.prior_store_high_water
        lease_store._primary_peak_entries = savepoint.prior_store_primary_peak

        prior_version = savepoint.prior_version
        expirations._heap = [
            entry
            for entry in expirations._heap
            if entry[3] != pair or (prior_version is not None and entry[2] <= prior_version)
        ]
        heapq.heapify(expirations._heap)
        if expirations._retired_heap is not None:
            expirations._retired_heap = [
                entry
                for entry in expirations._retired_heap
                if entry[3] != pair or (prior_version is not None and entry[2] <= prior_version)
            ]
            heapq.heapify(expirations._retired_heap)
            if not expirations._retired_heap:
                expirations._retired_heap = None

        if savepoint.prior_item is None:
            expirations._items.pop(pair, None)
        else:
            expirations._items[pair] = savepoint.prior_item
        if savepoint.prior_deadline is None:
            expirations._deadlines.pop(pair, None)
        else:
            expirations._deadlines[pair] = savepoint.prior_deadline
        if savepoint.prior_order is None:
            expirations._orders.pop(pair, None)
        else:
            expirations._orders[pair] = savepoint.prior_order
        if savepoint.prior_version is None:
            expirations._versions.pop(pair, None)
        else:
            expirations._versions[pair] = savepoint.prior_version
        expirations._next_order = savepoint.prior_next_order
        expirations._high_water_mark = savepoint.prior_high_water

        if not lease_store:
            shard.leases = ReferenceLeaseIndex()

    def _commit_prepared_locked(
        self,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        """Commit one claimed token while gate, capacity, and owner locks are held."""

        token = reservation.canonical_token
        shard = self._shards[token._shard_id]
        shard.deadlines.set(plan.expected_handle, plan.retained_deadline)
        if plan.lease_deadline is not None:
            shard.leases.acquire(
                token.record.artifact.artifact_version_id,
                token.lease_owner,
                deadline=plan.lease_deadline,
            )
        if token._existing_handle is None:
            if (
                plan.route is not None
                and plan.route_key is not None
                and plan.packed_route_locator is not None
            ):
                with plan.route.lock:
                    plan.route.routes[plan.route_key] = plan.packed_route_locator
                    plan.route.high_water = max(
                        plan.route.high_water,
                        len(plan.route.routes),
                    )
            shard.store.insert_reserved(
                plan.expected_handle,
                token.record.artifact,
                token.record,
                packed_payload=plan.packed_payload,
            )
            self._live_count += 1
            self._high_water_mark = max(self._high_water_mark, self._live_count)
        else:
            shard.store.bind_record(
                plan.expected_handle,
                token.record,
                packed_payload=plan.packed_payload,
            )
        shard.pending_expiry.discard(token.record.artifact.artifact_version_id)
        shard.mutation_version += 1
        return plan.receipt

    def publish_version(
        self,
        record: LocalArtifactVersionRecord,
        observed_at: datetime,
        *,
        retention: timedelta | None = None,
    ) -> int:
        """Prepare and immediately publish one canonical runtime artifact record."""

        token = self.prepare_publish_version(
            record,
            observed_at,
            retention=retention,
        )
        with self.prepared_publication(token) as publication:
            return publication.commit()

    def publish(
        self,
        artifact: LocalArtifactIdentity,
        observed_at: datetime,
        *,
        retention: timedelta | None = None,
    ) -> int:
        """Publish or refresh one immutable artifact version and return its handle."""

        canonical_artifact = _canonical_local_artifact_identity(artifact)
        if _has_posix_path_backslash(canonical_artifact.native_path, canonical_artifact.platform):
            raise StateError("POSIX local artifact native_path cannot contain backslashes")
        event_time = ensure_utc(observed_at)
        effective_retention = retention or self._retention
        if effective_retention <= timedelta(0):
            raise ValueError("artifact retention must be positive")
        deadline = (event_time + effective_retention).timestamp()
        version_id = canonical_artifact.artifact_version_id
        with self._gate.mutation():
            self._require_after_watermark_locked(
                event_time,
                "artifact observed_at",
                allow_boundary=True,
            )
            with self._capacity_lock:
                if version_id in self._prepared_versions:
                    raise StateError(
                        f"artifact version {version_id!r} has an active prepared publication"
                    )
            located = self._existing_locator(version_id)
            if located is not None:
                shard, handle = located
                with shard.lock:
                    if (
                        shard.store.is_live_handle(handle)
                        and shard.store.artifact_version_id(handle) == version_id
                    ):
                        return self._publish_locked(shard, handle, canonical_artifact, deadline)
            with self._capacity_lock:
                if version_id in self._prepared_versions:
                    raise StateError(
                        f"artifact version {version_id!r} has an active prepared publication"
                    )
                located = self._existing_locator(version_id)
                if located is not None:
                    shard, handle = located
                    with shard.lock:
                        if (
                            shard.store.is_live_handle(handle)
                            and shard.store.artifact_version_id(handle) == version_id
                        ):
                            return self._publish_locked(
                                shard,
                                handle,
                                canonical_artifact,
                                deadline,
                            )
                routing_identity = (
                    canonical_artifact.artifact_id
                    if self._capacity < 1_024
                    else canonical_artifact.artifact_version_id
                )
                shard = self._reserve_capacity_slot_locked(routing_identity)
                with shard.lock:
                    self._live_count += 1
                    self._high_water_mark = max(self._high_water_mark, self._live_count)
                    return self._publish_locked(shard, None, canonical_artifact, deadline)

    def _publish_locked(
        self,
        shard: _LocalArtifactShard,
        handle: int | None,
        artifact: LocalArtifactIdentity,
        deadline: float,
        *,
        record: LocalArtifactVersionRecord | None = None,
        packed_payload: bytes | None = None,
    ) -> int:
        """Commit one artifact publish while holding its stable owner shard."""

        version_id = artifact.artifact_version_id
        if handle is not None:
            current = shard.store.get_by_handle(handle)
            if current != artifact:
                raise ValueError(
                    f"artifact version {version_id!r} was already published with different identity"
                )
            if record is not None:
                shard.store.bind_record(handle, record, packed_payload=packed_payload)
        else:
            handle = shard.store.insert(
                artifact,
                record,
                packed_payload=packed_payload,
            )
            self._set_route(version_id, shard.shard_id, handle)
        current_deadline = shard.deadlines.deadline(handle)
        retained_until = (
            max(deadline, current_deadline) if current_deadline is not None else deadline
        )
        shard.deadlines.set(handle, retained_until)
        shard.pending_expiry.discard(version_id)
        shard.mutation_version += 1
        return handle

    def get(self, artifact_version_id: str) -> LocalArtifactIdentity | None:
        """Return one retained artifact version by exact ID."""

        version_id = artifact_version_id.strip()
        located = self._existing_locator(version_id)
        if located is None:
            return None
        shard, handle = located
        with shard.lock:
            if not shard.store.is_live_handle(handle):
                return None
            if shard.store.artifact_version_id(handle) != version_id:
                return None
            return shard.store.get_by_handle(handle)

    def resolve_version(
        self,
        artifact_version_id: str,
    ) -> LocalArtifactVersionRecord | None:
        """Return exact retained content/binary truth for one artifact version."""

        version_id = artifact_version_id.strip()
        located = self._existing_locator(version_id)
        if located is None:
            return None
        shard, handle = located
        with shard.lock:
            if (
                not shard.store.is_live_handle(handle)
                or shard.store.artifact_version_id(handle) != version_id
            ):
                return None
            return shard.store.get_record_by_handle(handle)

    def get_version(self, artifact_id: str, version: int) -> LocalArtifactIdentity | None:
        """Return one exact object/version pair without scanning artifact history."""

        version_id = _stable_semantic_id(
            "artifact-version",
            "local-artifact-version",
            (artifact_id.strip(), version),
        )
        return self.get(version_id)

    def iter_versions_for_object(
        self,
        artifact_id: str,
        *,
        page_size: int = 256,
    ) -> Iterator[LocalArtifactIdentity]:
        """Iterate one object's versions in bounded pages."""

        yield from self._iter_versions("artifact_object", artifact_id.strip(), page_size)

    def page_versions_for_object(
        self,
        artifact_id: str,
        *,
        limit: int,
        cursor: LocalArtifactVersionPageCursor | None = None,
    ) -> tuple[
        tuple[LocalArtifactIdentity, ...],
        LocalArtifactVersionPageCursor | None,
    ]:
        """Return one bounded page of versions for an exact local object."""

        return self._page_versions(
            "artifact_object",
            artifact_id.strip(),
            limit=limit,
            cursor=cursor,
        )

    def count_versions_for_object(self, artifact_id: str) -> int:
        """Return retained version count for one exact local object."""

        return self._count_versions("artifact_object", artifact_id.strip())

    def iter_versions_for_application_profile(
        self,
        application_profile_id: str,
        *,
        page_size: int = 256,
    ) -> Iterator[LocalArtifactIdentity]:
        """Iterate retained versions for one application profile in bounded pages."""

        yield from self._iter_versions(
            "application_profile",
            application_profile_id.strip(),
            page_size,
        )

    def page_versions_for_application_profile(
        self,
        application_profile_id: str,
        *,
        limit: int,
        cursor: LocalArtifactVersionPageCursor | None = None,
    ) -> tuple[
        tuple[LocalArtifactIdentity, ...],
        LocalArtifactVersionPageCursor | None,
    ]:
        """Return one bounded page owned by an exact application profile."""

        return self._page_versions(
            "application_profile",
            application_profile_id.strip(),
            limit=limit,
            cursor=cursor,
        )

    def count_versions_for_application_profile(self, application_profile_id: str) -> int:
        """Return retained version count for one exact application profile."""

        return self._count_versions("application_profile", application_profile_id.strip())

    def iter_versions_for_content(
        self,
        content_id: str,
        *,
        page_size: int = 256,
    ) -> Iterator[LocalArtifactIdentity]:
        """Iterate retained observations of one content identity in bounded pages."""

        yield from self._iter_versions("content", content_id.strip(), page_size)

    def page_versions_for_content(
        self,
        content_id: str,
        *,
        limit: int,
        cursor: LocalArtifactVersionPageCursor | None = None,
    ) -> tuple[
        tuple[LocalArtifactIdentity, ...],
        LocalArtifactVersionPageCursor | None,
    ]:
        """Return one bounded page for an exact content identity."""

        return self._page_versions(
            "content",
            content_id.strip(),
            limit=limit,
            cursor=cursor,
        )

    def count_versions_for_content(self, content_id: str) -> int:
        """Return retained observation count for one exact content identity."""

        return self._count_versions("content", content_id.strip())

    def _count_versions(self, index_name: str, indexed_value: Hashable) -> int:
        total = 0
        for shard in self._shards:
            with shard.lock:
                total += shard.store.count(index_name, indexed_value)
        return total

    @contextmanager
    def _all_shards_locked(self) -> Iterator[None]:
        for shard in self._shards:
            shard.lock.acquire()
        try:
            yield
        finally:
            for shard in reversed(self._shards):
                shard.lock.release()

    def _iter_versions(
        self,
        index_name: str,
        indexed_value: Hashable,
        page_size: int,
    ) -> Iterator[LocalArtifactIdentity]:
        if page_size <= 0:
            raise ValueError("artifact history page_size must be positive")
        cursor: LocalArtifactVersionPageCursor | None = None
        while True:
            page, cursor = self._page_versions(
                index_name,
                indexed_value,
                limit=page_size,
                cursor=cursor,
            )
            yield from page
            if cursor is None:
                return

    def _page_versions(
        self,
        index_name: str,
        indexed_value: Hashable,
        *,
        limit: int,
        cursor: LocalArtifactVersionPageCursor | None,
    ) -> tuple[
        tuple[LocalArtifactIdentity, ...],
        LocalArtifactVersionPageCursor | None,
    ]:
        if limit <= 0:
            raise ValueError("artifact history page limit must be positive")
        with self._all_shards_locked():
            mutation_versions = tuple(shard.mutation_version for shard in self._shards)
            if cursor is None:
                shard_id = 0
                after_handle = None
            elif (
                cursor._registry_token != id(self)
                or cursor._index_name != index_name
                or cursor._indexed_value != indexed_value
            ):
                raise StateError("artifact history page cursor belongs to another query")
            else:
                shard_id = cursor._shard_id
                after_handle = cursor._after_handle
            if cursor is not None and cursor._mutation_versions != mutation_versions:
                raise StateError("artifact history page cursor was invalidated by mutation")
            page: list[LocalArtifactIdentity] = []
            next_shard_id: int | None = None
            next_after_handle: int | None = None
            while shard_id < self._shard_count and len(page) < limit:
                shard = self._shards[shard_id]
                try:
                    handles, next_handle = shard.store.find_handle_page(
                        index_name,
                        indexed_value,
                        after_handle=after_handle,
                        limit=limit - len(page),
                    )
                except KeyError as exc:
                    raise StateError("artifact history page cursor is stale") from exc
                page.extend(shard.store.get_by_handle(handle) for handle in handles)
                if next_handle is not None:
                    next_shard_id = shard_id
                    next_after_handle = next_handle
                    break
                shard_id += 1
                after_handle = None

            if len(page) == limit and next_shard_id is None:
                while shard_id < self._shard_count:
                    if self._shards[shard_id].store.count(index_name, indexed_value):
                        next_shard_id = shard_id
                        break
                    shard_id += 1
            next_cursor = None
            if next_shard_id is not None:
                next_cursor = LocalArtifactVersionPageCursor(
                    registry_token=id(self),
                    index_name=index_name,
                    indexed_value=indexed_value,
                    mutation_versions=mutation_versions,
                    shard_id=next_shard_id,
                    after_handle=next_after_handle,
                )
            return tuple(page), next_cursor

    def get_for_path(
        self,
        user_profile_id: str,
        application_profile_id: str,
        native_path: str,
        platform: Platform,
        version: int,
    ) -> LocalArtifactIdentity | None:
        """Return one exact retained profile/path/version binding."""

        normalized_platform = _normalize_platform(platform)
        if _has_posix_path_backslash(native_path, normalized_platform):
            return None
        normalized_path = canonical_native_path(native_path, normalized_platform)
        user_profile = user_profile_id.strip()
        application_profile = application_profile_id.strip()
        for shard in self._shards:
            with shard.lock:
                for artifact in shard.store.find_iter(
                    "application_profile",
                    application_profile,
                ):
                    if (
                        artifact.platform == normalized_platform
                        and artifact.user_profile_id == user_profile
                        and artifact.normalized_native_path == normalized_path
                        and artifact.version == version
                    ):
                        return artifact
        return None

    def resolve_record_for_execution_path(
        self,
        hostname: str,
        principal: str,
        native_path: str,
        platform: Platform,
    ) -> LocalArtifactVersionRecord | None:
        """Resolve the newest retained record for one exact execution placement.

        Runtime executable admission uses the host, principal, platform, and
        canonical native path together. The equality index returns only exact
        collision-verified candidates; a deterministic version/semantic-ID
        maximum resolves the uncommon case where multiple retained versions
        temporarily occupy the same path.
        """

        normalized_platform = _normalize_platform(platform)
        if _has_posix_path_backslash(native_path, normalized_platform):
            return None
        key = "\0".join(
            (
                _normalize_hostname(hostname),
                _normalize_principal(principal, normalized_platform),
                normalized_platform,
                canonical_native_path(native_path, normalized_platform),
            )
        )
        resolved: LocalArtifactVersionRecord | None = None
        for shard in self._shards:
            with shard.lock:
                for candidate in shard.store.find_record_iter("execution_path", key):
                    if resolved is None or (
                        candidate.artifact.version,
                        candidate.artifact.artifact_version_id,
                    ) > (
                        resolved.artifact.version,
                        resolved.artifact.artifact_version_id,
                    ):
                        resolved = candidate
        return resolved

    def resolve_binary_for_path(
        self,
        hostname: str,
        principal: str,
        native_path: str,
        platform: Platform,
    ) -> LocalArtifactBinaryIdentity | None:
        """Return exact local executable truth for one runtime placement."""

        record = self.resolve_record_for_execution_path(
            hostname,
            principal,
            native_path,
            platform,
        )
        return None if record is None else record.binary

    def acquire_lease(
        self,
        artifact_version_id: str,
        owner: str,
        until: datetime,
    ) -> None:
        """Retain an artifact version for one explicit owner until a deadline."""

        version_id = _normalize_name(artifact_version_id, "artifact_version_id")
        owner_id = _normalize_name(owner, "owner")
        lease_until = ensure_utc(until)
        deadline = lease_until.timestamp()
        with self._gate.mutation(), self._capacity_lock:
            if self._version_has_claimed_preparation_locked(version_id):
                raise StateError(
                    "artifact lease cannot change during an active claimed publication"
                )
            located = self._existing_locator(version_id)
            if located is None:
                raise KeyError(version_id)
            shard, handle = located
            with shard.lock:
                if (
                    not shard.store.is_live_handle(handle)
                    or shard.store.artifact_version_id(handle) != version_id
                ):
                    raise KeyError(version_id)
                self._require_after_watermark_locked(
                    lease_until,
                    "artifact lease deadline",
                    allow_boundary=False,
                )
                artifact_deadline = shard.deadlines.deadline(handle)
                if artifact_deadline is not None and deadline <= artifact_deadline:
                    raise StateError(
                        "artifact lease deadline must extend beyond the artifact retention deadline"
                    )
                shard.leases.acquire(version_id, owner_id, deadline=deadline)

    def release_lease(self, artifact_version_id: str, owner: str) -> bool:
        """Release one exact lease and evict an already-due unreferenced version."""

        version_id = artifact_version_id.strip()
        needs_eviction = False
        shard: _LocalArtifactShard | None = None
        released = False
        with self._gate.mutation(), self._capacity_lock:
            if self._version_has_claimed_preparation_locked(version_id):
                raise StateError(
                    "artifact lease cannot change during an active claimed publication"
                )
            located = self._existing_locator(version_id)
            if located is not None:
                shard, handle = located
                with shard.lock:
                    if (
                        shard.store.is_live_handle(handle)
                        and shard.store.artifact_version_id(handle) == version_id
                    ):
                        released = shard.leases.release(version_id, owner.strip())
                    if released:
                        needs_eviction = self._reconcile_unleased_version_locked(
                            shard,
                            version_id,
                        )
        if needs_eviction and shard is not None:
            self._evict_pending_version(shard, version_id)
        return released

    def release_owner(self, owner: str) -> tuple[str, ...]:
        """Release every lease held by one owner and reconcile due versions."""

        owner_id = owner.strip()
        released: list[str] = []
        pending: list[tuple[_LocalArtifactShard, str]] = []
        with self._gate.mutation(), self._capacity_lock:
            for shard in self._shards:
                with shard.lock:
                    owner_versions = tuple(shard.leases.keys_for_owner(owner_id))
                    shard_released = tuple(
                        version_id
                        for version_id in owner_versions
                        if not self._version_has_claimed_preparation_locked(version_id)
                        and shard.leases.release(version_id, owner_id)
                    )
                    released.extend(shard_released)
                    for version_id in shard_released:
                        if self._reconcile_unleased_version_locked(shard, version_id):
                            pending.append((shard, version_id))
            for shard, version_id in pending:
                self._evict_pending_version(shard, version_id)
        return tuple(released)

    def advance_watermark(self, watermark: datetime) -> tuple[LocalArtifactIdentity, ...]:
        """Expire due leases and artifact versions at a monotonic canonical watermark."""

        cutoff = ensure_utc(watermark)
        with self._gate.watermark(), self._capacity_lock, self._all_shards_locked():
            if self._watermark is not None and cutoff < self._watermark:
                raise ValueError("artifact registry watermark cannot move backwards")
            if self._claimed_reservations and cutoff != self._watermark:
                raise StateError(
                    "artifact registry watermark cannot advance during an active claimed "
                    "publication"
                )
            cutoff_timestamp = cutoff.timestamp()
            evicted: list[LocalArtifactIdentity] = []
            for shard in self._shards:
                expired_leases = shard.leases.expire_before(
                    cutoff_timestamp,
                    inclusive=True,
                )
                lease_candidates = tuple(
                    dict.fromkeys(version_id for version_id, _owner in expired_leases)
                )
                expired_deadlines = shard.deadlines.expire_before(
                    cutoff_timestamp,
                    inclusive=True,
                )
                for handle in expired_deadlines:
                    if not shard.store.is_live_handle(handle):
                        continue
                    version_id = shard.store.artifact_version_id(handle)
                    if version_id in self._prepared_versions or shard.leases.is_leased(version_id):
                        shard.pending_expiry.add(version_id)
                        continue
                    artifact = self._evict_locked(shard, version_id, handle=handle)
                    if artifact is not None:
                        evicted.append(artifact)
                for version_id in lease_candidates:
                    if (
                        version_id not in shard.pending_expiry
                        or version_id in self._prepared_versions
                        or shard.leases.is_leased(version_id)
                    ):
                        continue
                    artifact = self._evict_locked(shard, version_id)
                    if artifact is not None:
                        evicted.append(artifact)
            self._live_count -= len(evicted)
            self._watermark = cutoff
            self._compact_primary_locked()
            return tuple(evicted)

    def _compact_primary_locked(self) -> None:
        """Compact one bounded owner partition at each watermark boundary."""

        shard_id = self._route_compaction_cursor
        shard = self._shards[shard_id]
        shard.store.compact_primary()
        shard.deadlines.compact()
        route = self._routes[shard_id]
        with route.lock:
            live = len(route.routes)
            amplified = route.high_water >= 4_096 and route.high_water > max(
                live * 2,
                live + _PRIMARY_COMPACTION_BUDGET,
            )
            if amplified:
                route.routes = dict(route.routes)
                route.high_water = live
        self._route_compaction_cursor = (shard_id + 1) % self._shard_count

    def _reserve_capacity_slot_locked(self, artifact_id: str) -> _LocalArtifactShard:
        """Choose one bounded owner/spill shard without mutating on failed admission."""

        for shard in self._probe_shards(artifact_id):
            with shard.lock:
                if (
                    len(shard.store) + self._prepared_counts[shard.shard_id]
                    < self._shard_capacities[shard.shard_id]
                ):
                    return shard
        for shard in self._probe_shards(artifact_id):
            with shard.lock:
                if self._evict_one_from_shard_locked(shard):
                    self._eviction_cursor = (shard.shard_id + 1) % self._shard_count
                    return shard
        raise LocalArtifactCapacityError(
            "artifact registry is at capacity and all retained versions are explicitly leased"
        )

    def _evict_one_from_shard_locked(self, shard: _LocalArtifactShard) -> bool:
        leased_entries: list[int] = []
        while True:
            entry = shard.deadlines.pop_earliest()
            if entry is None:
                break
            _deadline_us, _generation, handle = shard.deadlines._entry_fields(entry)
            if not shard.store.is_live_handle(handle):
                continue
            version_id = shard.store.artifact_version_id(handle)
            if version_id in self._prepared_versions or shard.leases.is_leased(version_id):
                leased_entries.append(entry)
                continue
            if self._evict_locked(shard, version_id, handle=handle) is not None:
                self._live_count -= 1
                for leased_entry in leased_entries:
                    shard.deadlines.restore(leased_entry)
                return True
        for leased_entry in leased_entries:
            shard.deadlines.restore(leased_entry)
        return False

    @staticmethod
    def _reconcile_unleased_version_locked(
        shard: _LocalArtifactShard,
        artifact_version_id: str,
    ) -> bool:
        if shard.leases.is_leased(artifact_version_id):
            return False
        if artifact_version_id in shard.pending_expiry:
            return True
        return False

    def _evict_pending_version(
        self,
        shard: _LocalArtifactShard,
        artifact_version_id: str,
    ) -> LocalArtifactIdentity | None:
        with self._capacity_lock, shard.lock:
            if (
                artifact_version_id not in shard.pending_expiry
                or artifact_version_id in self._prepared_versions
                or shard.leases.is_leased(artifact_version_id)
            ):
                return None
            artifact = self._evict_locked(shard, artifact_version_id)
            if artifact is not None:
                self._live_count -= 1
            return artifact

    def _evict_locked(
        self,
        shard: _LocalArtifactShard,
        artifact_version_id: str,
        *,
        handle: int | None = None,
    ) -> LocalArtifactIdentity | None:
        if handle is None:
            located = self._existing_locator(artifact_version_id)
            if located is None or located[0] is not shard:
                return None
            handle = located[1]
        if (
            not shard.store.is_live_handle(handle)
            or shard.store.artifact_version_id(handle) != artifact_version_id
        ):
            return None
        shard.deadlines.pop(handle, None)
        shard.pending_expiry.discard(artifact_version_id)
        artifact = shard.store.delete(handle)
        self._remove_route(
            artifact_version_id,
            shard_id=shard.shard_id,
            handle=handle,
        )
        shard.mutation_version += 1
        return artifact

    def index_metrics(
        self,
        *,
        estimate_bytes: bool = False,
    ) -> tuple[IndexMetrics, IndexMetrics, IndexMetrics]:
        """Return primary, deadline, and lease metrics with optional byte traversal."""

        with self._all_shards_locked():
            store_metrics = _aggregate_index_metrics(
                shard.store.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
            )
            route_entries, route_backing_bytes, route_estimated_bytes = self._route_metrics(
                estimate_bytes=estimate_bytes
            )
            store_metrics = replace(
                store_metrics,
                estimated_bytes=store_metrics.estimated_bytes + route_estimated_bytes,
                primary_map_entries=route_entries,
                primary_map_backing_bytes=route_backing_bytes,
            )
            return (
                store_metrics,
                _aggregate_index_metrics(
                    shard.deadlines.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
                ),
                _aggregate_index_metrics(
                    shard.leases.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
                ),
            )

    def _route_metrics(self, *, estimate_bytes: bool) -> tuple[int, int, int]:
        """Return constant-partition route cardinality, backing, and explicit estimate."""

        entries = 0
        backing_bytes = 0
        estimated_bytes = 0
        for route in self._routes:
            with route.lock:
                entries += len(route.routes)
                route_backing = sys.getsizeof(route.routes)
                backing_bytes += route_backing
                if estimate_bytes:
                    estimated_bytes += route_backing + sum(
                        sys.getsizeof(key) + sys.getsizeof(locator)
                        for key, locator in route.routes.items()
                    )
        return entries, backing_bytes, estimated_bytes

    def census(self, *, estimate_bytes: bool = False) -> LocalArtifactRegistryCensus:
        """Return bounded cardinalities, optionally traversing indexes for byte estimates."""

        with self._capacity_lock, self._all_shards_locked():
            store_metrics = _aggregate_index_metrics(
                shard.store.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
            )
            deadline_metrics = _aggregate_index_metrics(
                shard.deadlines.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
            )
            evictable_bytes = 0
            lease_metrics = _aggregate_index_metrics(
                shard.leases.metrics(estimate_bytes=estimate_bytes) for shard in self._shards
            )
            route_entries, route_backing_bytes, route_estimated_bytes = self._route_metrics(
                estimate_bytes=estimate_bytes
            )
            prepared_bytes = 0
            if estimate_bytes:
                prepared_bytes = (
                    sys.getsizeof(self._prepared_counts)
                    + sys.getsizeof(self._prepared_capability_locators)
                    + sys.getsizeof(self._prepared_commit_locators)
                    + sys.getsizeof(self._prepared_reservations)
                    + sys.getsizeof(self._prepared_versions)
                    + sys.getsizeof(self._claimed_reservations)
                    + sys.getsizeof(self._committing_reservations)
                    + sum(sys.getsizeof(count) for count in self._prepared_counts)
                    + sum(
                        sys.getsizeof(reservation_id) + _owned_graph_size(reservation)
                        for reservation_id, reservation in self._prepared_reservations.items()
                    )
                    + sum(
                        sys.getsizeof(token_id) + sys.getsizeof(reservation_id)
                        for token_id, reservation_id in self._prepared_capability_locators.items()
                    )
                    + sum(
                        sys.getsizeof(commit_id) + sys.getsizeof(reservation_id)
                        for commit_id, reservation_id in self._prepared_commit_locators.items()
                    )
                    + sum(
                        sys.getsizeof(version_id) + sys.getsizeof(reservation_id)
                        for version_id, reservation_id in self._prepared_versions.items()
                    )
                    + sum(
                        sys.getsizeof(reservation_id)
                        for reservation_id in self._claimed_reservations
                    )
                    + sum(
                        sys.getsizeof(reservation_id)
                        for reservation_id in self._committing_reservations
                    )
                )
            estimated_bytes = (
                store_metrics.estimated_bytes
                + deadline_metrics.estimated_bytes
                + evictable_bytes
                + lease_metrics.estimated_bytes
                + route_estimated_bytes
                + prepared_bytes
            )
            return LocalArtifactRegistryCensus(
                live_versions=self._live_count,
                backing_slots=store_metrics.backing_entries,
                high_water_mark=self._high_water_mark,
                leased_versions=sum(shard.leases.leased_key_count for shard in self._shards),
                active_leases=lease_metrics.live_entries,
                pending_expiry=sum(len(shard.pending_expiry) for shard in self._shards),
                prepared_publications=len(self._prepared_reservations),
                claimed_publications=len(self._claimed_reservations),
                reserved_slots=sum(self._prepared_counts),
                capacity=self._capacity,
                shards=self._shard_count,
                route_entries=route_entries,
                route_backing_bytes=route_backing_bytes,
                estimated_store_bytes=store_metrics.estimated_bytes,
                estimated_deadline_bytes=deadline_metrics.estimated_bytes,
                estimated_evictable_deadline_bytes=evictable_bytes,
                estimated_lease_bytes=lease_metrics.estimated_bytes,
                estimated_prepared_bytes=prepared_bytes,
                estimated_index_bytes=estimated_bytes,
                estimated_bytes=estimated_bytes,
                primary_map_entries=route_entries,
                primary_map_backing_bytes=route_backing_bytes,
                primary_compaction_pending=store_metrics.primary_compaction_pending,
                primary_compaction_rotations=store_metrics.primary_compaction_rotations,
                primary_compaction_work=store_metrics.primary_compaction_work,
                primary_compaction_seconds=store_metrics.primary_compaction_seconds,
                prepared_retained_members=len(self._prepared_reservations),
                prepared_member_capacity=self._capacity,
                prepared_retained_bytes=self._prepared_retained_bytes,
                prepared_byte_capacity=self._prepared_byte_capacity,
                prepared_capability_locators=(
                    len(self._prepared_capability_locators) + len(self._prepared_commit_locators)
                ),
                committing_publications=len(self._committing_reservations),
            )


__all__ = [
    "AssignmentCategoryIndexCensus",
    "BinaryPathIndexCensus",
    "DeploymentCompilationCensus",
    "DeploymentContentRegistry",
    "DeploymentContentScaleCensus",
    "DeploymentGroupPageCursor",
    "DeploymentRegistryCensus",
    "HostDeployment",
    "HostDeploymentSpec",
    "LocalArtifactCapacityError",
    "LocalArtifactPreparedCommit",
    "LocalArtifactPreparedGroupCommit",
    "LocalArtifactPublicationGroupReceipt",
    "LocalArtifactPublicationReceipt",
    "LocalArtifactPublishToken",
    "LocalArtifactRegistryCensus",
    "LocalArtifactVersionPageCursor",
    "LocalArtifactVersionRegistry",
    "UserApplicationAssignment",
    "UserApplicationAssignmentSpec",
]
