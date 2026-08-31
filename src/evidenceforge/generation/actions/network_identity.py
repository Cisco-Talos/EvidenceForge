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

"""Callback-free bounded identity encoding for canonical network requests."""

from __future__ import annotations

import hashlib
from dataclasses import (
    _FIELD,
    _FIELD_CLASSVAR,
    _FIELD_INITVAR,
    Field,
    _DataclassParams,
)
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from itertools import islice
from types import (
    GetSetDescriptorType,
    MappingProxyType,
    MemberDescriptorType,
)
from zoneinfo import ZoneInfo

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from evidenceforge.events import content_identity as _content_identity
from evidenceforge.events import contexts as _contexts
from evidenceforge.events import cryptography as _cryptography
from evidenceforge.events import network as _network
from evidenceforge.events import proxy as _proxy
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import stable_uuid

_NETWORK_CONNECTION_IDENTITY_EXCLUDED_FIELDS = frozenset(
    {
        "deferred_session_authority",
        "identity_capture",
        "persistent_smb_application_intent",
        "persistent_smb_file_mutation_journal",
        "persistent_smb_terminal_authority",
        "persistent_smb_terminal_continuation",
        "prepared_application_token",
        "explicit_proxy_open_preparation",
        "explicit_proxy_request_preparation",
    }
)

# These limits bound every public ``Any`` graph before a stable ID is produced.
# Depth treats the request root as zero. Nodes count every traversed occurrence,
# while memoization prevents a shared acyclic subgraph from being expanded twice.
_IDENTITY_MAX_DEPTH = 64
_IDENTITY_MAX_CONTAINER_MEMBERS = 4_096
_IDENTITY_MAX_NODES = 16_384
_IDENTITY_MAX_SCALAR_BYTES = 256 * 1024
_IDENTITY_MAX_ENCODED_BYTES = 1024 * 1024
# Type namespaces are public metadata too. Snapshot and charge each distinct
# namespace once so a wide graph cannot multiply repeated MRO scans into an
# unbounded amount of callback-surface inspection or CPU work.
_IDENTITY_MAX_TYPE_METADATA_MEMBERS = 16_384

_IDENTITY_SCHEMA = b"evidenceforge-network-identity-v4"
_IDENTITY_DIGEST_BYTES = hashlib.sha256().digest_size
_IDENTITY_ATOM_PREFIX_BYTES = 8
_IDENTITY_DIGEST_ATOM_BYTES = _IDENTITY_ATOM_PREFIX_BYTES + _IDENTITY_DIGEST_BYTES
_IDENTITY_TEXT_CHUNK_CHARACTERS = 4_096
_IDENTITY_BINARY_CHUNK_BYTES = 4_096
_IDENTITY_ERROR_LOCATION_CHARACTERS = 256
_TYPE_DICT_DESCRIPTOR = type.__dict__["__dict__"]
_TYPE_MRO_DESCRIPTOR = type.__dict__["__mro__"]
_IDENTITY_MISSING = object()

# A caller-defined type cannot receive a process-independent exact identity token
# without either invoking caller code or accepting nominal-name collisions. Stable
# request identity therefore accepts exact builtins and the exact source-reviewed
# value classes reachable from the 1e8 NetworkConnectionRequest model only.
_IDENTITY_EXACT_SCALAR_LABELS = (
    (bool, "builtins", "bool"),
    (int, "builtins", "int"),
    (float, "builtins", "float"),
    (str, "builtins", "str"),
    (bytes, "builtins", "bytes"),
    (bytearray, "builtins", "bytearray"),
    (date, "datetime", "date"),
    (datetime, "datetime", "datetime"),
    (timedelta, "datetime", "timedelta"),
)
_IDENTITY_EXACT_CONTAINER_LABELS = (
    (tuple, "builtins", "tuple"),
    (list, "builtins", "list"),
    (dict, "builtins", "dict"),
    (set, "builtins", "set"),
    (frozenset, "builtins", "frozenset"),
)
_IDENTITY_TRUSTED_DATACLASS_LABELS = (
    (_contexts.DnsContext, "evidenceforge.events.contexts", "DnsContext"),
    (_contexts.EmailContext, "evidenceforge.events.contexts", "EmailContext"),
    (_contexts.FileTransferContext, "evidenceforge.events.contexts", "FileTransferContext"),
    (_contexts.FirewallContext, "evidenceforge.events.contexts", "FirewallContext"),
    (_contexts.HttpContext, "evidenceforge.events.contexts", "HttpContext"),
    (
        _contexts.HttpEntityPartContext,
        "evidenceforge.events.contexts",
        "HttpEntityPartContext",
    ),
    (
        _contexts.HttpMultipartEntityContext,
        "evidenceforge.events.contexts",
        "HttpMultipartEntityContext",
    ),
    (
        _contexts.HttpRequestEntityContext,
        "evidenceforge.events.contexts",
        "HttpRequestEntityContext",
    ),
    (_contexts.HttpWireSpanContext, "evidenceforge.events.contexts", "HttpWireSpanContext"),
    (_contexts.IdsAlertPlan, "evidenceforge.events.contexts", "IdsAlertPlan"),
    (
        _contexts.IdsAlertPolicyContext,
        "evidenceforge.events.contexts",
        "IdsAlertPolicyContext",
    ),
    (
        _contexts.IdsDetectionFilterContext,
        "evidenceforge.events.contexts",
        "IdsDetectionFilterContext",
    ),
    (
        _contexts.IdsEventFilterContext,
        "evidenceforge.events.contexts",
        "IdsEventFilterContext",
    ),
    (_contexts.OcspContext, "evidenceforge.events.contexts", "OcspContext"),
    (_contexts.PeContext, "evidenceforge.events.contexts", "PeContext"),
    (_contexts.ProcessContext, "evidenceforge.events.contexts", "ProcessContext"),
    (
        _contexts.ProcessTargetSecurityContext,
        "evidenceforge.events.contexts",
        "ProcessTargetSecurityContext",
    ),
    (_contexts.ProxyContext, "evidenceforge.events.contexts", "ProxyContext"),
    (_contexts.SmtpContext, "evidenceforge.events.contexts", "SmtpContext"),
    (_contexts.SslContext, "evidenceforge.events.contexts", "SslContext"),
    (_contexts.X509Context, "evidenceforge.events.contexts", "X509Context"),
    (
        _cryptography.CertificateAuthorityMaterial,
        "evidenceforge.events.cryptography",
        "CertificateAuthorityMaterial",
    ),
    (
        _cryptography.CertificateIdentityPlan,
        "evidenceforge.events.cryptography",
        "CertificateIdentityPlan",
    ),
    (
        _cryptography.OcspTransactionPlan,
        "evidenceforge.events.cryptography",
        "OcspTransactionPlan",
    ),
    (
        _cryptography.TlsCertificatePresentationPlan,
        "evidenceforge.events.cryptography",
        "TlsCertificatePresentationPlan",
    ),
    (_network.SignaturePredicate, "evidenceforge.events.network", "SignaturePredicate"),
    (_proxy.ProxyTransactionPlan, "evidenceforge.events.proxy", "ProxyTransactionPlan"),
    (
        _content_identity.BinaryReleaseIdentity,
        "evidenceforge.events.content_identity",
        "BinaryReleaseIdentity",
    ),
    (
        _content_identity.BinaryReleaseKey,
        "evidenceforge.events.content_identity",
        "BinaryReleaseKey",
    ),
    (
        _content_identity.ContentDigests,
        "evidenceforge.events.content_identity",
        "ContentDigests",
    ),
    (
        _content_identity.LocalArtifactBinaryIdentity,
        "evidenceforge.events.content_identity",
        "LocalArtifactBinaryIdentity",
    ),
    (
        _content_identity.PeVersionInfo,
        "evidenceforge.events.content_identity",
        "PeVersionInfo",
    ),
    (
        _content_identity.UnresolvedBinaryIdentity,
        "evidenceforge.events.content_identity",
        "UnresolvedBinaryIdentity",
    ),
    (
        _content_identity.VirtualKernelBinaryIdentity,
        "evidenceforge.events.content_identity",
        "VirtualKernelBinaryIdentity",
    ),
)
_IDENTITY_TRUSTED_PYDANTIC_LABELS = ((System, "evidenceforge.models.scenario", "System"),)
_IDENTITY_ROOT_LABEL = (
    "evidenceforge.generation.actions.network_connection",
    "NetworkConnectionRequest",
)
_IDENTITY_ROOT_TYPE: type[object] | None = None
_IDENTITY_ROOT_POLICY: tuple[object, ...] | None = None
_TRUSTED_IDENTITY_TYPE_INSPECTOR: _IdentityTypeInspector | None = None
_TRUSTED_PYDANTIC_DIGEST_CACHE_CAPACITY = 8_192
_TRUSTED_PYDANTIC_DIGESTS: dict[int, tuple[BaseModel, bytes]] = {}
_TRUSTED_SCALAR_DIGEST_CACHE_CAPACITY = 8_192
_TRUSTED_SCALAR_DIGESTS: dict[tuple[type[object], object], bytes] = {}


def _identity_import_raw_attribute(value_type: type[object], name: str) -> object:
    """Read one trusted class attribute without a caller-controlled keyed lookup."""

    value_mro = _TYPE_MRO_DESCRIPTOR.__get__(value_type, type(value_type))
    for member in value_mro:
        namespace = _TYPE_DICT_DESCRIPTOR.__get__(member, type(member))
        for index, (namespace_key, namespace_value) in enumerate(MappingProxyType.items(namespace)):
            if index >= _IDENTITY_MAX_CONTAINER_MEMBERS:
                raise ValueError("Trusted network identity type namespace exceeds its limit")
            if type(namespace_key) is not str:
                raise TypeError("Trusted network identity type has a non-string namespace key")
            if str.__eq__(namespace_key, name):
                return namespace_value
    return _IDENTITY_MISSING


def _identity_capture_dataclass_policy(
    value_type: type[object],
    module_name: str,
    qualified_name: str,
) -> tuple[object, ...]:
    """Capture immutable source-reviewed dataclass metadata during module import."""

    raw_fields = _identity_import_raw_attribute(value_type, "__dataclass_fields__")
    raw_params = _identity_import_raw_attribute(value_type, "__dataclass_params__")
    if type(raw_fields) is not dict or type(raw_params) is not _DataclassParams:
        raise TypeError("Trusted network identity dataclass metadata is invalid")
    field_policy: list[tuple[str, Field[object], bool, object, object]] = []
    for index, (field_name, data_field) in enumerate(dict.items(raw_fields)):
        if index >= _IDENTITY_MAX_CONTAINER_MEMBERS:
            raise ValueError("Trusted network identity dataclass metadata exceeds its limit")
        if (
            type(field_name) is not str
            or type(data_field) is not Field
            or type(data_field.name) is not str
            or not str.__eq__(data_field.name, field_name)
            or type(data_field.compare) is not bool
        ):
            raise TypeError("Trusted network identity dataclass field metadata is invalid")
        field_kind = data_field._field_type
        if (
            field_kind is not _FIELD
            and field_kind is not _FIELD_CLASSVAR
            and field_kind is not _FIELD_INITVAR
        ):
            raise TypeError("Trusted network identity dataclass field kind is invalid")
        field_policy.append(
            (
                field_name,
                data_field,
                data_field.compare,
                field_kind,
                _identity_import_raw_attribute(value_type, field_name),
            )
        )
    equality_enabled = _DataclassParams.eq.__get__(raw_params, _DataclassParams)
    if type(equality_enabled) is not bool or equality_enabled is not True:
        raise TypeError("Trusted network identity dataclass must enable equality")
    return (
        value_type,
        module_name,
        qualified_name,
        _identity_import_raw_attribute(value_type, "__eq__"),
        _identity_import_raw_attribute(value_type, "__ne__"),
        raw_params,
        tuple(field_policy),
    )


def _identity_capture_pydantic_policy(
    value_type: type[BaseModel],
    module_name: str,
    qualified_name: str,
) -> tuple[object, ...]:
    """Capture immutable source-reviewed Pydantic metadata during module import."""

    raw_fields = _identity_import_raw_attribute(value_type, "__pydantic_fields__")
    raw_private_attributes = _identity_import_raw_attribute(value_type, "__private_attributes__")
    if type(raw_fields) is not dict or type(raw_private_attributes) is not dict:
        raise TypeError("Trusted network identity Pydantic metadata is invalid")
    if dict.__len__(raw_private_attributes) != 0:
        raise TypeError("Trusted network identity Pydantic type cannot declare private fields")
    field_policy: list[tuple[str, FieldInfo]] = []
    for index, (field_name, field_info) in enumerate(dict.items(raw_fields)):
        if index >= _IDENTITY_MAX_CONTAINER_MEMBERS:
            raise ValueError("Trusted network identity Pydantic metadata exceeds its limit")
        if type(field_name) is not str or type(field_info) is not FieldInfo:
            raise TypeError("Trusted network identity Pydantic field metadata is invalid")
        field_policy.append((field_name, field_info))
    return (
        value_type,
        module_name,
        qualified_name,
        _identity_import_raw_attribute(value_type, "__eq__"),
        _identity_import_raw_attribute(value_type, "__ne__"),
        tuple(field_policy),
        _identity_import_raw_attribute(value_type, "__dict__"),
        _identity_import_raw_attribute(value_type, "__pydantic_extra__"),
        _identity_import_raw_attribute(value_type, "__pydantic_private__"),
    )


_IDENTITY_TRUSTED_DATACLASS_POLICIES = tuple(
    _identity_capture_dataclass_policy(*label) for label in _IDENTITY_TRUSTED_DATACLASS_LABELS
)
_IDENTITY_TRUSTED_PYDANTIC_POLICIES = tuple(
    _identity_capture_pydantic_policy(*label) for label in _IDENTITY_TRUSTED_PYDANTIC_LABELS
)
_IDENTITY_STATIC_LABELS = (
    *_IDENTITY_EXACT_SCALAR_LABELS,
    *_IDENTITY_EXACT_CONTAINER_LABELS,
    *_IDENTITY_TRUSTED_DATACLASS_LABELS,
    *_IDENTITY_TRUSTED_PYDANTIC_LABELS,
)
_IDENTITY_LABELS_BY_ID = {
    id(value_type): (value_type, module_name, qualified_name)
    for value_type, module_name, qualified_name in _IDENTITY_STATIC_LABELS
}
_IDENTITY_DATACLASS_POLICIES_BY_ID = {
    id(policy[0]): (policy[0], policy) for policy in _IDENTITY_TRUSTED_DATACLASS_POLICIES
}
_IDENTITY_PYDANTIC_POLICIES_BY_ID = {
    id(policy[0]): (policy[0], policy) for policy in _IDENTITY_TRUSTED_PYDANTIC_POLICIES
}
_identity_inspection_types: dict[int, type[object]] = {}
for _identity_value_type, _module_name, _qualified_name in _IDENTITY_STATIC_LABELS:
    for _identity_mro_member in _TYPE_MRO_DESCRIPTOR.__get__(
        _identity_value_type,
        type(_identity_value_type),
    ):
        dict.__setitem__(
            _identity_inspection_types,
            id(_identity_mro_member),
            _identity_mro_member,
        )
for _identity_extra_type in (type(None), timezone, tzinfo, ZoneInfo):
    dict.__setitem__(
        _identity_inspection_types,
        id(_identity_extra_type),
        _identity_extra_type,
    )
_IDENTITY_STATIC_INSPECTION_TYPES_BY_ID = _identity_inspection_types
del _identity_extra_type
del _identity_inspection_types
del _identity_mro_member
del _identity_value_type
del _module_name
del _qualified_name


def _register_network_request_type(request_type: type[object]) -> None:
    """Register the exact request class once while its defining module imports."""

    global _IDENTITY_ROOT_POLICY, _IDENTITY_ROOT_TYPE, _TRUSTED_IDENTITY_TYPE_INSPECTOR
    if _IDENTITY_ROOT_TYPE is not None:
        if request_type is not _IDENTITY_ROOT_TYPE:
            raise TypeError("Network connection identity request type is already registered")
        return
    if type(request_type) is not type:
        raise TypeError("Network connection identity requires an exact request class")
    _IDENTITY_ROOT_TYPE = request_type
    _IDENTITY_ROOT_POLICY = _identity_capture_dataclass_policy(
        request_type,
        *_IDENTITY_ROOT_LABEL,
    )
    inspector = _IdentityTypeInspector()
    for policy in (*_IDENTITY_TRUSTED_DATACLASS_POLICIES, _IDENTITY_ROOT_POLICY):
        inspector.dataclass_fields(policy[0], ())  # type: ignore[arg-type]
    for policy in _IDENTITY_TRUSTED_PYDANTIC_POLICIES:
        inspector.pydantic_fields(policy[0], ())  # type: ignore[arg-type]
    _TRUSTED_IDENTITY_TYPE_INSPECTOR = inspector


def _identity_location(path: tuple[str, ...]) -> str:
    """Return a bounded callback-free spelling of one public field path."""

    if not path:
        return "<root>"
    remaining = _IDENTITY_ERROR_LOCATION_CHARACTERS
    parts: list[str] = []
    for segment in path:
        if remaining <= 0:
            parts.append("…")
            break
        segment_length = str.__len__(segment)
        take = min(segment_length, remaining)
        parts.append(str.__getitem__(segment, slice(0, take)))
        remaining -= take
        if take != segment_length:
            parts.append("…")
            break
        remaining -= 1
    return ".".join(parts)


class _IdentityTypeInspector:
    """Snapshot bounded raw type facts once without caller-controlled lookup."""

    def __init__(self) -> None:
        self._mros: dict[int, tuple[type[object], tuple[type, ...]]] = {}
        self._namespaces: dict[int, tuple[type[object], dict[str, object]]] = {}
        self._dataclass_fields: dict[
            int,
            tuple[type[object], tuple[tuple[str, bool], ...] | None],
        ] = {}
        self._pydantic_fields: dict[int, tuple[type[object], tuple[str, ...]]] = {}
        self._metadata_members = 0
        self._metadata_characters = 0

    def _authenticate_type(self, value_type: type[object], path: tuple[str, ...]) -> None:
        """Permit only exact source-captured types and their exact base classes."""

        trusted_type = dict.get(_IDENTITY_STATIC_INSPECTION_TYPES_BY_ID, id(value_type))
        if trusted_type is value_type or value_type is _IDENTITY_ROOT_TYPE:
            return
        raise TypeError(
            "Network connection identity contains an unsupported semantic type "
            f"at {_identity_location(path)}"
        )

    def _charge_metadata(self, member_count: int, path: tuple[str, ...]) -> None:
        """Charge one distinct metadata snapshot before validating or copying it."""

        if self._metadata_members + member_count > _IDENTITY_MAX_TYPE_METADATA_MEMBERS:
            raise ValueError(
                "Network connection identity type metadata exceeds the maximum of "
                f"{_IDENTITY_MAX_TYPE_METADATA_MEMBERS} members at {_identity_location(path)}"
            )
        self._metadata_members += member_count

    def _charge_metadata_text(self, value: str, path: tuple[str, ...]) -> None:
        """Bound metadata names before dynamic policy validation or copying."""

        character_count = str.__len__(value)
        if character_count > _IDENTITY_MAX_SCALAR_BYTES:
            raise ValueError(
                "Network connection identity type metadata name exceeds the maximum scalar "
                f"size of {_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
            )
        if self._metadata_characters + character_count > _IDENTITY_MAX_ENCODED_BYTES:
            raise ValueError(
                "Network connection identity type metadata names exceed the maximum aggregate "
                f"size of {_IDENTITY_MAX_ENCODED_BYTES} characters at "
                f"{_identity_location(path)}"
            )
        self._metadata_characters += character_count

    def mro(self, value_type: type[object], path: tuple[str, ...]) -> tuple[type, ...]:
        """Return one cached, authenticated MRO through the trusted type descriptor."""

        self._authenticate_type(value_type, path)
        cached = dict.get(self._mros, id(value_type))
        if cached is not None and tuple.__getitem__(cached, 0) is value_type:
            return tuple.__getitem__(cached, 1)
        value_mro = _TYPE_MRO_DESCRIPTOR.__get__(value_type, type(value_type))
        if type(value_mro) is not tuple:
            raise TypeError(
                "Network connection identity contains an unsupported semantic type hierarchy "
                f"at {_identity_location(path)}"
            )
        if tuple.__len__(value_mro) > _IDENTITY_MAX_DEPTH:
            raise ValueError(
                "Network connection identity type hierarchy exceeds the maximum depth of "
                f"{_IDENTITY_MAX_DEPTH} at {_identity_location(path)}"
            )
        for index in range(tuple.__len__(value_mro)):
            member = tuple.__getitem__(value_mro, index)
            self._authenticate_type(member, path)
        dict.__setitem__(self._mros, id(value_type), (value_type, value_mro))
        return value_mro

    def namespace(
        self,
        value_type: type[object],
        path: tuple[str, ...],
    ) -> dict[str, object]:
        """Return one immutable-to-callers snapshot of an authenticated namespace."""

        self.mro(value_type, path)
        cached = dict.get(self._namespaces, id(value_type))
        if cached is not None and tuple.__getitem__(cached, 0) is value_type:
            return tuple.__getitem__(cached, 1)
        namespace = _TYPE_DICT_DESCRIPTOR.__get__(value_type, type(value_type))
        if type(namespace) is not MappingProxyType:
            raise TypeError(
                "Network connection identity contains an unsupported semantic type namespace "
                f"at {_identity_location(path)}"
            )
        try:
            namespace_items = tuple(
                islice(
                    MappingProxyType.items(namespace),
                    _IDENTITY_MAX_CONTAINER_MEMBERS + 1,
                )
            )
        except RuntimeError as exc:
            raise TypeError(
                "Network connection identity type namespace changed during inspection "
                f"at {_identity_location(path)}"
            ) from exc
        member_count = tuple.__len__(namespace_items)
        if member_count > _IDENTITY_MAX_CONTAINER_MEMBERS:
            raise ValueError(
                "Network connection identity type namespace exceeds the maximum of "
                f"{_IDENTITY_MAX_CONTAINER_MEMBERS} members at {_identity_location(path)}"
            )
        live_count = MappingProxyType.__len__(namespace)
        if member_count != live_count:
            raise TypeError(
                "Network connection identity type namespace changed during inspection "
                f"at {_identity_location(path)}"
            )
        self._charge_metadata(member_count, path)
        snapshot: dict[str, object] = {}
        for namespace_key, namespace_value in namespace_items:
            if type(namespace_key) is not str:
                raise TypeError(
                    "Network connection identity type namespace contains a non-string key "
                    f"at {_identity_location(path)}"
                )
            self._charge_metadata_text(namespace_key, path)
            dict.__setitem__(snapshot, namespace_key, namespace_value)
        dict.__setitem__(self._namespaces, id(value_type), (value_type, snapshot))
        return snapshot

    def raw_attribute(
        self,
        value_type: type[object],
        name: str,
        path: tuple[str, ...],
    ) -> object:
        """Return an inherited attribute from cached raw namespace snapshots."""

        for member in self.mro(value_type, path):
            namespace = self.namespace(member, path)
            value = dict.get(namespace, name, _IDENTITY_MISSING)
            if value is not _IDENTITY_MISSING:
                return value
        return _IDENTITY_MISSING

    def metadata(
        self,
        value_type: type[object],
        path: tuple[str, ...],
    ) -> tuple[str, str]:
        """Return the immutable exact-type label captured from reviewed source."""

        label = dict.get(_IDENTITY_LABELS_BY_ID, id(value_type))
        if label is not None and tuple.__getitem__(label, 0) is value_type:
            return tuple.__getitem__(label, 1), tuple.__getitem__(label, 2)
        if value_type is _IDENTITY_ROOT_TYPE:
            return _IDENTITY_ROOT_LABEL
        raise TypeError(
            "Network connection identity contains an unsupported semantic type "
            f"at {_identity_location(path)}"
        )

    @staticmethod
    def dataclass_policy(value_type: type[object]) -> tuple[object, ...] | None:
        """Return a source-captured dataclass policy by exact type identity."""

        entry = dict.get(_IDENTITY_DATACLASS_POLICIES_BY_ID, id(value_type))
        if entry is not None and tuple.__getitem__(entry, 0) is value_type:
            return tuple.__getitem__(entry, 1)
        if value_type is _IDENTITY_ROOT_TYPE:
            return _IDENTITY_ROOT_POLICY
        return None

    @staticmethod
    def pydantic_policy(value_type: type[object]) -> tuple[object, ...] | None:
        """Return a source-captured Pydantic policy by exact type identity."""

        entry = dict.get(_IDENTITY_PYDANTIC_POLICIES_BY_ID, id(value_type))
        if entry is not None and tuple.__getitem__(entry, 0) is value_type:
            return tuple.__getitem__(entry, 1)
        return None

    def dataclass_fields(
        self,
        value_type: type[object],
        path: tuple[str, ...],
    ) -> tuple[tuple[str, bool], ...] | None:
        """Return one cached snapshot of equality-bearing dataclass field policy."""

        policy = self.dataclass_policy(value_type)
        if policy is None:
            return None
        self.mro(value_type, path)
        cached = dict.get(self._dataclass_fields, id(value_type), _IDENTITY_MISSING)
        if cached is not _IDENTITY_MISSING:
            if tuple.__getitem__(cached, 0) is value_type:  # type: ignore[arg-type]
                return tuple.__getitem__(cached, 1)  # type: ignore[arg-type,return-value]
        raw_fields = self.raw_attribute(value_type, "__dataclass_fields__", path)
        if type(raw_fields) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported dataclass metadata "
                f"at {_identity_location(path)}"
            )
        raw_field_snapshot = _identity_dict_snapshot(raw_fields, path)
        field_count = tuple.__len__(raw_field_snapshot)
        self._charge_metadata(field_count, path)
        expected_fields = policy[6]
        if type(expected_fields) is not tuple or field_count != tuple.__len__(expected_fields):
            raise TypeError(
                "Network connection identity dataclass metadata changed after registration "
                f"at {_identity_location(path)}"
            )
        public_fields: list[tuple[str, bool]] = []
        try:
            for index, (field_name, data_field) in enumerate(raw_field_snapshot):
                expected = tuple.__getitem__(expected_fields, index)
                expected_name = tuple.__getitem__(expected, 0)
                expected_field = tuple.__getitem__(expected, 1)
                expected_compare = tuple.__getitem__(expected, 2)
                expected_kind = tuple.__getitem__(expected, 3)
                expected_backing = tuple.__getitem__(expected, 4)
                if (
                    type(field_name) is not str
                    or type(data_field) is not Field
                    or type(data_field.name) is not str
                    or not str.__eq__(data_field.name, field_name)
                ):
                    raise TypeError(
                        "Network connection identity contains unsupported dataclass field "
                        f"metadata at {_identity_location(path)}"
                    )
                self._charge_metadata_text(field_name, path)
                compare = data_field.compare
                if type(compare) is not bool:
                    raise TypeError(
                        "Network connection identity dataclass compare flag must be an exact "
                        f"bool at {_identity_location((*path, field_name))}"
                    )
                field_kind = data_field._field_type
                if (
                    field_kind is not _FIELD
                    and field_kind is not _FIELD_CLASSVAR
                    and field_kind is not _FIELD_INITVAR
                ):
                    raise TypeError(
                        "Network connection identity contains unsupported dataclass field "
                        f"metadata at {_identity_location(path)}"
                    )
                if (
                    not str.__eq__(field_name, expected_name)
                    or data_field is not expected_field
                    or compare is not expected_compare
                    or field_kind is not expected_kind
                    or self.raw_attribute(value_type, field_name, path) is not expected_backing
                ):
                    raise TypeError(
                        "Network connection identity dataclass metadata changed after "
                        f"registration at {_identity_location(path)}"
                    )
                if field_kind is _FIELD:
                    public_fields.append((field_name, compare))
        except RuntimeError as exc:
            raise TypeError(
                "Network connection identity dataclass metadata changed during inspection "
                f"at {_identity_location(path)}"
            ) from exc
        _identity_dict_snapshot_matches(raw_fields, raw_field_snapshot, path)
        raw_params = self.raw_attribute(value_type, "__dataclass_params__", path)
        if type(raw_params) is not _DataclassParams or raw_params is not policy[5]:
            raise TypeError(
                "Network connection identity contains unsupported dataclass policy metadata "
                f"at {_identity_location(path)}"
            )
        equality_enabled = _DataclassParams.eq.__get__(raw_params, _DataclassParams)
        if type(equality_enabled) is not bool:
            raise TypeError(
                "Network connection identity dataclass equality flag must be an exact bool "
                f"at {_identity_location(path)}"
            )
        if equality_enabled is not True:
            raise TypeError(
                "Network connection identity dataclass generated equality must be enabled "
                f"at {_identity_location(path)}"
            )
        if (
            self.raw_attribute(value_type, "__eq__", path) is not policy[3]
            or self.raw_attribute(value_type, "__ne__", path) is not policy[4]
        ):
            raise TypeError(
                "Network connection identity dataclass equality implementation changed after "
                f"registration at {_identity_location(path)}"
            )
        snapshot = tuple(public_fields)
        dict.__setitem__(self._dataclass_fields, id(value_type), (value_type, snapshot))
        return snapshot

    def pydantic_fields(
        self,
        value_type: type[object],
        path: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Return one cached snapshot of every declared Pydantic field name."""

        policy = self.pydantic_policy(value_type)
        if policy is None:
            raise TypeError(
                "Network connection identity contains an unsupported Pydantic type "
                f"at {_identity_location(path)}"
            )
        self.metadata(value_type, path)
        cached = dict.get(self._pydantic_fields, id(value_type))
        if cached is not None and tuple.__getitem__(cached, 0) is value_type:
            return tuple.__getitem__(cached, 1)
        raw_fields = self.raw_attribute(value_type, "__pydantic_fields__", path)
        if type(raw_fields) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported Pydantic field metadata "
                f"at {_identity_location(path)}"
            )
        raw_field_snapshot = _identity_dict_snapshot(raw_fields, path)
        field_count = tuple.__len__(raw_field_snapshot)
        self._charge_metadata(field_count, path)
        expected_fields = policy[5]
        if type(expected_fields) is not tuple or field_count != tuple.__len__(expected_fields):
            raise TypeError(
                "Network connection identity Pydantic metadata changed after registration "
                f"at {_identity_location(path)}"
            )
        names: list[str] = []
        try:
            for index, (field_name, field_info) in enumerate(raw_field_snapshot):
                expected = tuple.__getitem__(expected_fields, index)
                if type(field_name) is not str or type(field_info) is not FieldInfo:
                    raise TypeError(
                        "Network connection identity contains unsupported Pydantic field "
                        f"metadata at {_identity_location(path)}"
                    )
                if not str.__eq__(
                    field_name, tuple.__getitem__(expected, 0)
                ) or field_info is not tuple.__getitem__(expected, 1):
                    raise TypeError(
                        "Network connection identity Pydantic metadata changed after "
                        f"registration at {_identity_location(path)}"
                    )
                self._charge_metadata_text(field_name, path)
                names.append(field_name)
        except RuntimeError as exc:
            raise TypeError(
                "Network connection identity Pydantic metadata changed during inspection "
                f"at {_identity_location(path)}"
            ) from exc
        _identity_dict_snapshot_matches(raw_fields, raw_field_snapshot, path)
        raw_equality = self.raw_attribute(value_type, "__eq__", path)
        raw_not_equal = self.raw_attribute(value_type, "__ne__", path)
        if raw_equality is not policy[3] or raw_not_equal is not policy[4]:
            raise TypeError(
                "Network connection identity Pydantic equality implementation is unsupported "
                f"at {_identity_location(path)}"
            )
        if (
            self.raw_attribute(value_type, "__dict__", path) is not policy[6]
            or self.raw_attribute(value_type, "__pydantic_extra__", path) is not policy[7]
            or self.raw_attribute(value_type, "__pydantic_private__", path) is not policy[8]
        ):
            raise TypeError(
                "Network connection identity Pydantic storage policy changed after "
                f"registration at {_identity_location(path)}"
            )
        raw_private_attributes = self.raw_attribute(value_type, "__private_attributes__", path)
        if type(raw_private_attributes) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported Pydantic private metadata "
                f"at {_identity_location(path)}"
            )
        private_count = dict.__len__(raw_private_attributes)
        self._charge_metadata(private_count, path)
        if private_count != 0:
            raise TypeError(
                "Network connection identity cannot encode Pydantic private attributes "
                f"at {_identity_location(path)}"
            )
        snapshot = tuple(names)
        dict.__setitem__(self._pydantic_fields, id(value_type), (value_type, snapshot))
        return snapshot


def _identity_utf8_bytes(value: str, path: tuple[str, ...]) -> bytes:
    """Encode exact string storage in bounded chunks without calling overrides."""

    if type(value) is not str:
        raise TypeError(
            "Network connection identity contains unsupported text storage "
            f"at {_identity_location(path)}"
        )
    character_count = str.__len__(value)
    if character_count > _IDENTITY_MAX_SCALAR_BYTES:
        raise ValueError(
            "Network connection identity exceeds the maximum scalar size of "
            f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
        )
    encoded = bytearray()
    for start in range(0, character_count, _IDENTITY_TEXT_CHUNK_CHARACTERS):
        chunk = str.__getitem__(
            value,
            slice(start, min(start + _IDENTITY_TEXT_CHUNK_CHARACTERS, character_count)),
        )
        try:
            encoded_chunk = str.encode(chunk, "utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "Network connection identity text must contain valid UTF-8 scalar values "
                f"at {_identity_location(path)}"
            ) from exc
        if len(encoded) + len(encoded_chunk) > _IDENTITY_MAX_SCALAR_BYTES:
            raise ValueError(
                "Network connection identity exceeds the maximum scalar size of "
                f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
            )
        bytearray.extend(encoded, encoded_chunk)
    return bytes(encoded)


def _identity_mutation_error(path: tuple[str, ...], storage_name: str) -> ValueError:
    """Return the controlled error used for an unstable mutable snapshot."""

    return ValueError(
        f"Network connection identity {storage_name} changed during identity encoding "
        f"at {_identity_location(path)}"
    )


def _identity_list_snapshot(
    value: list[object],
    path: tuple[str, ...],
) -> list[object]:
    """Take one cap-plus-one exact-list snapshot and authenticate its length."""

    snapshot = list.__getitem__(value, slice(0, _IDENTITY_MAX_CONTAINER_MEMBERS + 1))
    snapshot_count = list.__len__(snapshot)
    if snapshot_count > _IDENTITY_MAX_CONTAINER_MEMBERS:
        raise ValueError(
            "Network connection identity container exceeds the maximum of "
            f"{_IDENTITY_MAX_CONTAINER_MEMBERS} members at {_identity_location(path)}"
        )
    live_count = list.__len__(value)
    if snapshot_count != live_count:
        raise _identity_mutation_error(path, "list")
    return snapshot


def _identity_list_snapshot_matches(
    value: list[object],
    snapshot: list[object],
    path: tuple[str, ...],
) -> None:
    """Require a second bounded list snapshot with the same exact object references."""

    current = _identity_list_snapshot(value, path)
    member_count = list.__len__(snapshot)
    if list.__len__(current) != member_count:
        raise _identity_mutation_error(path, "list")
    for index in range(member_count):
        if list.__getitem__(current, index) is not list.__getitem__(snapshot, index):
            raise _identity_mutation_error(path, "list")


def _identity_dict_snapshot(
    value: dict[object, object],
    path: tuple[str, ...],
) -> tuple[tuple[object, object], ...]:
    """Take one bounded C-level exact-dict snapshot while the GIL is held."""

    try:
        snapshot = tuple(islice(dict.items(value), _IDENTITY_MAX_CONTAINER_MEMBERS + 1))
    except RuntimeError as exc:
        raise _identity_mutation_error(path, "dict") from exc

    snapshot_count = tuple.__len__(snapshot)
    if snapshot_count > _IDENTITY_MAX_CONTAINER_MEMBERS:
        raise ValueError(
            "Network connection identity container exceeds the maximum of "
            f"{_IDENTITY_MAX_CONTAINER_MEMBERS} members at {_identity_location(path)}"
        )
    live_count = dict.__len__(value)
    if snapshot_count != live_count:
        raise _identity_mutation_error(path, "dict")
    return snapshot


def _identity_dict_snapshot_matches(
    value: dict[object, object],
    snapshot: tuple[tuple[object, object], ...],
    path: tuple[str, ...],
) -> None:
    """Require a second bounded dict snapshot with identical key/value references."""

    current = _identity_dict_snapshot(value, path)
    member_count = tuple.__len__(snapshot)
    if tuple.__len__(current) != member_count:
        raise _identity_mutation_error(path, "dict")
    for index in range(member_count):
        expected_item = tuple.__getitem__(snapshot, index)
        current_item = tuple.__getitem__(current, index)
        if tuple.__getitem__(current_item, 0) is not tuple.__getitem__(
            expected_item, 0
        ) or tuple.__getitem__(current_item, 1) is not tuple.__getitem__(expected_item, 1):
            raise _identity_mutation_error(path, "dict")


def _identity_set_snapshot(
    value: set[object],
    path: tuple[str, ...],
) -> tuple[object, ...]:
    """Take one bounded C-level exact-set snapshot while the GIL is held."""

    try:
        snapshot = tuple(islice(set.__iter__(value), _IDENTITY_MAX_CONTAINER_MEMBERS + 1))
    except RuntimeError as exc:
        raise _identity_mutation_error(path, "set") from exc

    snapshot_count = tuple.__len__(snapshot)
    if snapshot_count > _IDENTITY_MAX_CONTAINER_MEMBERS:
        raise ValueError(
            "Network connection identity container exceeds the maximum of "
            f"{_IDENTITY_MAX_CONTAINER_MEMBERS} members at {_identity_location(path)}"
        )
    live_count = set.__len__(value)
    if snapshot_count != live_count:
        raise _identity_mutation_error(path, "set")
    return snapshot


def _identity_set_snapshot_matches(
    value: set[object],
    snapshot: tuple[object, ...],
    path: tuple[str, ...],
) -> None:
    """Require a second bounded set snapshot with the same iteration references."""

    current = _identity_set_snapshot(value, path)
    member_count = tuple.__len__(snapshot)
    if tuple.__len__(current) != member_count:
        raise _identity_mutation_error(path, "set")
    for index in range(member_count):
        if tuple.__getitem__(current, index) is not tuple.__getitem__(snapshot, index):
            raise _identity_mutation_error(path, "set")


def _identity_bytearray_snapshot_matches(
    view: memoryview,
    snapshot: bytes,
    path: tuple[str, ...],
) -> None:
    """Compare a pinned bytearray to its snapshot without a second full-size copy."""

    byte_count = bytes.__len__(snapshot)
    for start in range(0, byte_count, _IDENTITY_BINARY_CHUNK_BYTES):
        stop = min(start + _IDENTITY_BINARY_CHUNK_BYTES, byte_count)
        current_view = memoryview.__getitem__(view, slice(start, stop))
        try:
            current_chunk = memoryview.tobytes(current_view)
        finally:
            memoryview.release(current_view)
        expected_chunk = bytes.__getitem__(snapshot, slice(start, stop))
        if not bytes.__eq__(current_chunk, expected_chunk):
            raise _identity_mutation_error(path, "bytearray")


def _identity_instance_dict(
    inspector: _IdentityTypeInspector,
    value: object,
    value_mro: tuple[type, ...],
    path: tuple[str, ...],
) -> dict[object, object] | None:
    """Return raw instance storage through an authenticated built-in descriptor."""

    for member in value_mro:
        namespace = inspector.namespace(member, path)
        descriptor = dict.get(namespace, "__dict__", _IDENTITY_MISSING)
        if type(descriptor) is not GetSetDescriptorType:
            continue
        try:
            instance_values = descriptor.__get__(value, type(value))
        except AttributeError:
            continue
        if type(instance_values) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported instance storage "
                f"at {_identity_location(path)}"
            )
        return instance_values
    return None


def _identity_validate_string_keyed_storage(
    values: dict[object, object],
    path: tuple[str, ...],
    storage_name: str,
) -> dict[str, object]:
    """Return a bounded raw-storage snapshot after authenticating every key."""

    items = _identity_dict_snapshot(values, path)
    snapshot: dict[str, object] = {}
    for key, item in items:
        if type(key) is not str:
            raise TypeError(
                f"Network connection identity {storage_name} contains a non-string key "
                f"at {_identity_location(path)}"
            )
        dict.__setitem__(snapshot, key, item)
    return snapshot


def _identity_dataclass_field_value(
    inspector: _IdentityTypeInspector,
    value: object,
    value_mro: tuple[type, ...],
    field_name: str,
    instance_values: dict[object, object] | None,
    path: tuple[str, ...],
) -> object:
    """Read one dataclass field from raw storage without dynamic attribute access."""

    raw_class_value = _IDENTITY_MISSING
    for member in value_mro:
        namespace = inspector.namespace(member, path)
        raw_class_value = dict.get(namespace, field_name, _IDENTITY_MISSING)
        if raw_class_value is not _IDENTITY_MISSING:
            break
    raw_class_type = type(raw_class_value)
    if raw_class_type is MemberDescriptorType or raw_class_type is GetSetDescriptorType:
        try:
            return raw_class_value.__get__(value, type(value))
        except AttributeError as exc:
            raise TypeError(
                "Network connection identity dataclass field has no stored value "
                f"at {_identity_location(path)}"
            ) from exc
    if raw_class_value is not _IDENTITY_MISSING:
        raw_get = inspector.raw_attribute(type(raw_class_value), "__get__", path)
        raw_set = inspector.raw_attribute(type(raw_class_value), "__set__", path)
        raw_delete = inspector.raw_attribute(type(raw_class_value), "__delete__", path)
        if (
            raw_get is not _IDENTITY_MISSING
            or raw_set is not _IDENTITY_MISSING
            or raw_delete is not _IDENTITY_MISSING
        ):
            raise TypeError(
                "Network connection identity dataclass field uses a callback-capable descriptor "
                f"at {_identity_location(path)}"
            )
    if instance_values is not None and field_name in instance_values:
        return dict.__getitem__(instance_values, field_name)
    if raw_class_value is not _IDENTITY_MISSING:
        return raw_class_value
    raise TypeError(
        "Network connection identity dataclass field has no stored value "
        f"at {_identity_location(path)}"
    )


def _identity_pydantic_extras(
    inspector: _IdentityTypeInspector,
    value: BaseModel,
    value_mro: tuple[type, ...],
    path: tuple[str, ...],
) -> tuple[dict[object, object] | None, dict[str, object] | None]:
    """Return live and bounded-snapshot Pydantic extras without model dispatch."""

    for member in value_mro:
        namespace = inspector.namespace(member, path)
        descriptor = dict.get(namespace, "__pydantic_extra__", _IDENTITY_MISSING)
        if type(descriptor) is not MemberDescriptorType:
            continue
        try:
            extras = descriptor.__get__(value, type(value))
        except AttributeError as exc:
            raise TypeError(
                "Network connection identity Pydantic extra storage is missing "
                f"at {_identity_location(path)}"
            ) from exc
        if extras is not None and type(extras) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported Pydantic extra storage "
                f"at {_identity_location(path)}"
            )
        if extras is None:
            return None, None
        snapshot = _identity_validate_string_keyed_storage(
            extras,
            path,
            "Pydantic extra storage",
        )
        if dict.__len__(snapshot) == 0:
            return extras, None
        return extras, snapshot
    raise TypeError(
        "Network connection identity cannot locate Pydantic extra storage "
        f"at {_identity_location(path)}"
    )


def _identity_reject_pydantic_private_storage(
    inspector: _IdentityTypeInspector,
    value: BaseModel,
    value_mro: tuple[type, ...],
    path: tuple[str, ...],
) -> None:
    """Reject raw private model state that public field identity cannot represent."""

    for member in value_mro:
        namespace = inspector.namespace(member, path)
        descriptor = dict.get(namespace, "__pydantic_private__", _IDENTITY_MISSING)
        if type(descriptor) is not MemberDescriptorType:
            continue
        try:
            private_values = descriptor.__get__(value, type(value))
        except AttributeError as exc:
            raise TypeError(
                "Network connection identity Pydantic private storage is missing "
                f"at {_identity_location(path)}"
            ) from exc
        if private_values is None:
            return
        if type(private_values) is not dict:
            raise TypeError(
                "Network connection identity contains unsupported Pydantic private storage "
                f"at {_identity_location(path)}"
            )
        _identity_validate_string_keyed_storage(
            private_values,
            path,
            "Pydantic private storage",
        )
        raise TypeError(
            "Network connection identity cannot encode Pydantic private attributes "
            f"at {_identity_location(path)}"
        )
    raise TypeError(
        "Network connection identity cannot locate Pydantic private storage "
        f"at {_identity_location(path)}"
    )


def _identity_pydantic_field_value(
    instance_values: dict[object, object],
    field_name: str,
    path: tuple[str, ...],
) -> object:
    """Return one declared model value or reject incomplete raw model storage."""

    if field_name not in instance_values:
        raise TypeError(
            "Network connection identity Pydantic field has no stored value "
            f"at {_identity_location(path)}"
        )
    return dict.__getitem__(instance_values, field_name)


def _identity_validate_pydantic_field_storage(
    instance_values: dict[object, object],
    field_names: tuple[str, ...],
    path: tuple[str, ...],
) -> None:
    """Reject undeclared instance shadows that Pydantic equality can observe."""

    if dict.__len__(instance_values) != tuple.__len__(field_names):
        raise TypeError(
            "Network connection identity Pydantic field storage contains undeclared state "
            f"at {_identity_location(path)}"
        )
    for stored_name in dict.__iter__(instance_values):
        if not any(str.__eq__(stored_name, field_name) for field_name in field_names):
            raise TypeError(
                "Network connection identity Pydantic field storage contains undeclared state "
                f"at {_identity_location(path)}"
            )


def _identity_datetime_value(
    value: datetime,
    path: tuple[str, ...],
) -> tuple[str, str]:
    """Return callback-free awareness and timezone-canonical datetime spellings."""

    year = datetime.year.__get__(value, datetime)
    month = datetime.month.__get__(value, datetime)
    day = datetime.day.__get__(value, datetime)
    hour = datetime.hour.__get__(value, datetime)
    minute = datetime.minute.__get__(value, datetime)
    second = datetime.second.__get__(value, datetime)
    microsecond = datetime.microsecond.__get__(value, datetime)
    fold = datetime.fold.__get__(value, datetime)
    timezone_value = datetime.tzinfo.__get__(value, datetime)
    local_value = datetime(
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
        fold=fold,
    )
    if timezone_value is None:
        return "naive", datetime.isoformat(local_value, timespec="microseconds")
    try:
        if type(timezone_value) is timezone:
            offset = timezone.utcoffset(timezone_value, None)
            if offset is None:
                raise ValueError(
                    "Network connection identity timezone has no UTC offset at "
                    f"{_identity_location(path)}"
                )
            utc_value = local_value - offset
        elif type(timezone_value) is ZoneInfo:
            aware_value = datetime.replace(local_value, tzinfo=timezone_value)
            offset = ZoneInfo.utcoffset(timezone_value, aware_value)
            if offset is None:
                raise ValueError(
                    "Network connection identity timezone has no UTC offset at "
                    f"{_identity_location(path)}"
                )
            utc_value = local_value - offset
        else:
            raise TypeError(
                "Network connection identity contains unsupported callback-capable timezone "
                f"at {_identity_location(path)}"
            )
    except OverflowError as exc:
        raise ValueError(
            "Network connection identity timezone normalization falls outside the supported "
            f"datetime range at {_identity_location(path)}"
        ) from exc
    aware_utc_value = datetime.replace(utc_value, tzinfo=UTC)
    return "aware", datetime.isoformat(aware_utc_value, timespec="microseconds")


class _IdentityDigestWriter:
    """Incrementally hash one length-delimited frame under the aggregate byte cap."""

    def __init__(
        self,
        encoder: _CanonicalIdentityEncoder,
        path: tuple[str, ...],
    ) -> None:
        self._encoder = encoder
        self._path = path
        self._hasher = hashlib.sha256()

    def atom(self, payload: bytes) -> None:
        """Hash one exact byte atom after charging its full framed size."""

        payload_size = bytes.__len__(payload)
        if not self._encoder._trusted_engine:
            self._encoder._charge_encoded(_IDENTITY_ATOM_PREFIX_BYTES + payload_size, self._path)
        self._hasher.update(payload_size.to_bytes(_IDENTITY_ATOM_PREFIX_BYTES, "big"))
        self._hasher.update(payload)

    def finish(self) -> bytes:
        """Return the completed full-width frame digest."""

        return self._hasher.digest()


class _CanonicalIdentityEncoder:
    """Build bounded Merkle-style identity digests without caller dispatch."""

    def __init__(
        self,
        *,
        type_inspector: _IdentityTypeInspector | None = None,
        trusted_engine: bool = False,
    ) -> None:
        self._types = type_inspector if type_inspector is not None else _IdentityTypeInspector()
        self._trusted_engine = trusted_engine
        self._active: dict[int, object] = {}
        self._memo: dict[int, tuple[object, bytes]] = {}
        self._nodes = 0
        self._encoded_bytes = 0

    def _visit(self, depth: int, path: tuple[str, ...]) -> None:
        """Charge one occurrence before accessing or copying its value."""

        if self._trusted_engine:
            return
        if depth > _IDENTITY_MAX_DEPTH:
            raise ValueError(
                "Network connection identity exceeds the maximum depth of "
                f"{_IDENTITY_MAX_DEPTH} at {_identity_location(path)}"
            )
        if self._nodes >= _IDENTITY_MAX_NODES:
            raise ValueError(
                "Network connection identity exceeds the maximum of "
                f"{_IDENTITY_MAX_NODES} traversed nodes at {_identity_location(path)}"
            )
        self._nodes += 1

    def _ensure_members(self, member_count: int, path: tuple[str, ...]) -> None:
        """Reject oversized containers before snapshot allocation."""

        if self._trusted_engine:
            return
        if member_count > _IDENTITY_MAX_CONTAINER_MEMBERS:
            raise ValueError(
                "Network connection identity container exceeds the maximum of "
                f"{_IDENTITY_MAX_CONTAINER_MEMBERS} members at {_identity_location(path)}"
            )

    def _ensure_child_nodes(self, child_count: int, path: tuple[str, ...]) -> None:
        """Reject a container that cannot fit its immediate child occurrences."""

        if self._trusted_engine:
            return
        if self._nodes + child_count > _IDENTITY_MAX_NODES:
            raise ValueError(
                "Network connection identity exceeds the maximum of "
                f"{_IDENTITY_MAX_NODES} traversed nodes at {_identity_location(path)}"
            )

    def _ensure_encoded(self, byte_count: int, path: tuple[str, ...]) -> None:
        """Reject known future frame bytes before container snapshot allocation."""

        if self._trusted_engine:
            return
        if self._encoded_bytes + byte_count > _IDENTITY_MAX_ENCODED_BYTES:
            raise ValueError(
                "Network connection identity exceeds the maximum encoded size of "
                f"{_IDENTITY_MAX_ENCODED_BYTES} bytes at {_identity_location(path)}"
            )

    def _charge_encoded(self, byte_count: int, path: tuple[str, ...]) -> None:
        """Charge exact canonical frame bytes before hashing them."""

        self._ensure_encoded(byte_count, path)
        self._encoded_bytes += byte_count

    def _utf8_bytes(self, value: str, path: tuple[str, ...]) -> bytes:
        """Encode trusted engine text directly or enforce the public bounded path."""

        if self._trusted_engine:
            return str.encode(value, "utf-8", "strict")
        return _identity_utf8_bytes(value, path)

    def _trusted_scalar_digest(self, value: object) -> bytes | None:
        """Return a shared digest for an exact immutable engine scalar when present."""

        if not self._trusted_engine or type(value) not in {type(None), bool, int, str, bytes}:
            return None
        return _TRUSTED_SCALAR_DIGESTS.get((type(value), value))

    def _retain_trusted_scalar_digest(self, value: object, digest: bytes) -> None:
        """Bound and retain one exact immutable engine scalar digest."""

        if not self._trusted_engine or type(value) not in {type(None), bool, int, str, bytes}:
            return
        if len(_TRUSTED_SCALAR_DIGESTS) >= _TRUSTED_SCALAR_DIGEST_CACHE_CAPACITY:
            _TRUSTED_SCALAR_DIGESTS.clear()
        _TRUSTED_SCALAR_DIGESTS[(type(value), value)] = digest

    def _writer(
        self,
        tag: bytes,
        value: object,
        path: tuple[str, ...],
    ) -> _IdentityDigestWriter:
        """Start one schema- and concrete-type-delimited digest frame."""

        module_name, qualified_name = self._types.metadata(type(value), path)
        writer = _IdentityDigestWriter(self, path)
        writer.atom(_IDENTITY_SCHEMA)
        writer.atom(tag)
        writer.atom(self._utf8_bytes(module_name, path))
        writer.atom(self._utf8_bytes(qualified_name, path))
        return writer

    def _scalar_writer(
        self,
        tag: bytes,
        value: object,
        payload: bytes,
        path: tuple[str, ...],
    ) -> bytes:
        """Hash one concrete scalar and memoize the completed digest."""

        writer = self._writer(tag, value, path)
        writer.atom(payload)
        digest = writer.finish()
        self._memoize(value, digest)
        self._retain_trusted_scalar_digest(value, digest)
        return digest

    def _memoize(self, value: object, digest: bytes) -> None:
        """Retain the encoded object so CPython ID reuse cannot forge a cache hit."""

        dict.__setitem__(self._memo, id(value), (value, digest))

    def _cached_digest(self, value: object) -> bytes | None:
        """Return a digest only for the same strongly retained object."""

        entry = dict.get(self._memo, id(value))
        if entry is None or tuple.__getitem__(entry, 0) is not value:
            return None
        return tuple.__getitem__(entry, 1)

    def _enter_composite(self, value: object, path: tuple[str, ...]) -> None:
        """Mark a composite gray or reject a recursive edge."""

        value_id = id(value)
        if value_id in self._active:
            raise ValueError(
                "Network connection identity cannot contain recursive value at "
                f"{_identity_location(path)}"
            )
        dict.__setitem__(self._active, value_id, value)

    def _leave_composite(self, value: object) -> None:
        """Remove one strongly retained gray object after its frame finishes."""

        dict.__delitem__(self._active, id(value))

    def _encode_dataclass(
        self,
        value: object,
        value_mro: tuple[type, ...],
        data_fields: tuple[tuple[str, bool], ...],
        depth: int,
        path: tuple[str, ...],
    ) -> bytes:
        """Encode equality-bearing dataclass fields before builtin base payloads."""

        semantic_fields = tuple(
            field_name for field_name, compare in data_fields if compare is True
        )
        self._ensure_members(len(semantic_fields), path)
        self._ensure_child_nodes(len(semantic_fields), path)
        self._ensure_encoded(len(semantic_fields) * _IDENTITY_DIGEST_ATOM_BYTES, path)
        self._enter_composite(value, path)
        try:
            live_instance_values = _identity_instance_dict(self._types, value, value_mro, path)
            instance_values = live_instance_values
            if live_instance_values is not None:
                instance_values = _identity_validate_string_keyed_storage(
                    live_instance_values,
                    path,
                    "dataclass instance storage",
                )
            writer = self._writer(b"dataclass", value, path)
            writer.atom(len(semantic_fields).to_bytes(8, "big"))
            for field_name in semantic_fields:
                field_path = (*path, field_name)
                writer.atom(self._utf8_bytes(field_name, field_path))
                field_value = _identity_dataclass_field_value(
                    self._types,
                    value,
                    value_mro,
                    field_name,
                    instance_values,
                    field_path,
                )
                writer.atom(self._encode(field_value, depth + 1, field_path))
            digest = writer.finish()
            if live_instance_values is not None and instance_values is not None:
                _identity_dict_snapshot_matches(
                    live_instance_values,
                    _identity_dict_snapshot(instance_values, path),
                    path,
                )
        finally:
            self._leave_composite(value)
        self._memoize(value, digest)
        return digest

    def _encode_pydantic(
        self,
        value: BaseModel,
        value_mro: tuple[type, ...],
        depth: int,
        path: tuple[str, ...],
    ) -> bytes:
        """Encode every raw declared field and public extra without validators."""

        field_names = self._types.pydantic_fields(type(value), path)
        self._ensure_child_nodes(len(field_names) + 1, path)
        self._ensure_encoded((len(field_names) + 1) * _IDENTITY_DIGEST_ATOM_BYTES, path)
        self._enter_composite(value, path)
        try:
            live_instance_values = _identity_instance_dict(self._types, value, value_mro, path)
            if live_instance_values is None:
                raise TypeError(
                    "Network connection identity cannot locate Pydantic field storage "
                    f"at {_identity_location(path)}"
                )
            instance_values = _identity_validate_string_keyed_storage(
                live_instance_values,
                path,
                "Pydantic field storage",
            )
            _identity_validate_pydantic_field_storage(instance_values, field_names, path)
            _identity_reject_pydantic_private_storage(
                self._types,
                value,
                value_mro,
                path,
            )
            writer = self._writer(b"pydantic", value, path)
            writer.atom(len(field_names).to_bytes(8, "big"))
            for field_name in field_names:
                field_path = (*path, field_name)
                writer.atom(self._utf8_bytes(field_name, field_path))
                field_value = _identity_pydantic_field_value(
                    instance_values,
                    field_name,
                    field_path,
                )
                writer.atom(self._encode(field_value, depth + 1, field_path))
            extras_path = (*path, "<pydantic-extra>")
            live_extras, extras = _identity_pydantic_extras(
                self._types,
                value,
                value_mro,
                extras_path,
            )
            writer.atom(self._encode(extras, depth + 1, extras_path))
            digest = writer.finish()
            if live_extras is not None:
                expected_extras = extras if extras is not None else {}
                _identity_dict_snapshot_matches(
                    live_extras,
                    _identity_dict_snapshot(expected_extras, extras_path),
                    extras_path,
                )
            _identity_dict_snapshot_matches(
                live_instance_values,
                _identity_dict_snapshot(instance_values, path),
                path,
            )
        finally:
            self._leave_composite(value)
        self._memoize(value, digest)
        return digest

    def _encode_sequence(
        self,
        tag: bytes,
        value: object,
        snapshot: tuple[object, ...] | list[object],
        depth: int,
        path: tuple[str, ...],
    ) -> bytes:
        """Encode one already bounded ordered-container snapshot."""

        self._enter_composite(value, path)
        try:
            writer = self._writer(tag, value, path)
            writer.atom(len(snapshot).to_bytes(8, "big"))
            for index, item in enumerate(snapshot):
                writer.atom(self._encode(item, depth + 1, (*path, f"[{index}]")))
            digest = writer.finish()
            if type(value) is list:
                _identity_list_snapshot_matches(value, snapshot, path)  # type: ignore[arg-type]
        finally:
            self._leave_composite(value)
        self._memoize(value, digest)
        return digest

    def _encode_mapping(
        self,
        value: dict[object, object],
        snapshot: tuple[tuple[object, object], ...],
        depth: int,
        path: tuple[str, ...],
    ) -> bytes:
        """Encode one mapping snapshot in canonical key/value digest order."""

        self._enter_composite(value, path)
        try:
            encoded_items: list[tuple[bytes, bytes]] = []
            for index, (key, item) in enumerate(snapshot):
                encoded_items.append(
                    (
                        self._encode(key, depth + 1, (*path, f"<key:{index}>")),
                        self._encode(item, depth + 1, (*path, f"<value:{index}>")),
                    )
                )
            encoded_items.sort()
            writer = self._writer(b"mapping", value, path)
            writer.atom(len(encoded_items).to_bytes(8, "big"))
            for key_digest, value_digest in encoded_items:
                writer.atom(key_digest)
                writer.atom(value_digest)
            digest = writer.finish()
            _identity_dict_snapshot_matches(value, snapshot, path)
        finally:
            self._leave_composite(value)
        self._memoize(value, digest)
        return digest

    def _encode_set(
        self,
        value: object,
        snapshot: tuple[object, ...] | list[object],
        depth: int,
        path: tuple[str, ...],
    ) -> bytes:
        """Encode one set snapshot in canonical child-digest order."""

        self._enter_composite(value, path)
        try:
            item_digests = [
                self._encode(item, depth + 1, (*path, "<set-item>")) for item in snapshot
            ]
            item_digests.sort()
            writer = self._writer(b"set", value, path)
            writer.atom(len(item_digests).to_bytes(8, "big"))
            for item_digest in item_digests:
                writer.atom(item_digest)
            digest = writer.finish()
            if type(value) is set:
                _identity_set_snapshot_matches(value, snapshot, path)  # type: ignore[arg-type]
        finally:
            self._leave_composite(value)
        self._memoize(value, digest)
        return digest

    def _encode(self, value: object, depth: int, path: tuple[str, ...]) -> bytes:
        """Encode one occurrence after enforcing all callback and resource boundaries."""

        self._visit(depth, path)
        value_id = id(value)
        if value_id in self._active:
            raise ValueError(
                "Network connection identity cannot contain recursive value at "
                f"{_identity_location(path)}"
            )
        cached = self._cached_digest(value)
        if cached is not None:
            return cached
        shared_scalar = self._trusted_scalar_digest(value)
        if shared_scalar is not None:
            self._memoize(value, shared_scalar)
            return shared_scalar
        if value is None:
            writer = _IdentityDigestWriter(self, path)
            writer.atom(_IDENTITY_SCHEMA)
            writer.atom(b"none")
            digest = writer.finish()
            self._memoize(value, digest)
            self._retain_trusted_scalar_digest(value, digest)
            return digest

        value_type = type(value)
        if self._types.dataclass_policy(value_type) is not None:
            value_mro = self._types.mro(value_type, path)
            data_fields = self._types.dataclass_fields(value_type, path)
            if data_fields is None:
                raise TypeError(
                    "Network connection identity trusted dataclass metadata is missing "
                    f"at {_identity_location(path)}"
                )
            return self._encode_dataclass(value, value_mro, data_fields, depth, path)
        if self._types.pydantic_policy(value_type) is not None:
            if self._trusted_engine:
                shared = _TRUSTED_PYDANTIC_DIGESTS.get(value_id)
                if shared is not None and shared[0] is value:
                    digest = shared[1]
                    self._memoize(value, digest)
                    return digest
            value_mro = self._types.mro(value_type, path)
            digest = self._encode_pydantic(value, value_mro, depth, path)  # type: ignore[arg-type]
            if self._trusted_engine:
                if len(_TRUSTED_PYDANTIC_DIGESTS) >= _TRUSTED_PYDANTIC_DIGEST_CACHE_CAPACITY:
                    _TRUSTED_PYDANTIC_DIGESTS.clear()
                _TRUSTED_PYDANTIC_DIGESTS[value_id] = (value, digest)  # type: ignore[assignment]
            return digest

        if value_type is bool:
            return self._scalar_writer(b"bool", value, b"1" if value else b"0", path)
        if value_type is datetime:
            awareness, canonical_value = _identity_datetime_value(  # type: ignore[arg-type]
                value,
                path,
            )
            writer = self._writer(b"datetime", value, path)
            writer.atom(self._utf8_bytes(awareness, path))
            writer.atom(self._utf8_bytes(canonical_value, path))
            digest = writer.finish()
            self._memoize(value, digest)
            return digest
        if value_type is date:
            return self._scalar_writer(
                b"date",
                value,
                self._utf8_bytes(date.isoformat(value), path),  # type: ignore[arg-type]
                path,
            )
        if value_type is timedelta:
            writer = self._writer(b"timedelta", value, path)
            for component in (
                timedelta.days.__get__(value, timedelta),
                timedelta.seconds.__get__(value, timedelta),
                timedelta.microseconds.__get__(value, timedelta),
            ):
                writer.atom(str.encode(int.__repr__(component), "ascii"))
            digest = writer.finish()
            self._memoize(value, digest)
            return digest
        if value_type is str:
            character_count = str.__len__(value)  # type: ignore[arg-type]
            if character_count > _IDENTITY_MAX_SCALAR_BYTES:
                raise ValueError(
                    "Network connection identity exceeds the maximum scalar size of "
                    f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
                )
            snapshot = str.__str__(value)  # type: ignore[arg-type]
            if type(snapshot) is not str:
                raise TypeError(
                    "Network connection identity contains unsupported string storage "
                    f"at {_identity_location(path)}"
                )
            return self._scalar_writer(
                b"str",
                value,
                self._utf8_bytes(snapshot, path),
                path,
            )
        if value_type is bytes:
            byte_count = bytes.__len__(value)  # type: ignore[arg-type]
            if byte_count > _IDENTITY_MAX_SCALAR_BYTES:
                raise ValueError(
                    "Network connection identity exceeds the maximum scalar size of "
                    f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
                )
            snapshot = bytes.__getitem__(value, slice(None))  # type: ignore[arg-type]
            return self._scalar_writer(b"bytes", value, snapshot, path)
        if value_type is bytearray:
            view = memoryview(value)
            try:
                byte_count = memoryview.nbytes.__get__(view, memoryview)
                if byte_count > _IDENTITY_MAX_SCALAR_BYTES:
                    raise ValueError(
                        "Network connection identity exceeds the maximum scalar size of "
                        f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
                    )
                snapshot = memoryview.tobytes(view)
                if bytes.__len__(snapshot) != byte_count:
                    raise _identity_mutation_error(path, "bytearray")
                writer = self._writer(b"bytearray", value, path)
                writer.atom(snapshot)
                digest = writer.finish()
                _identity_bytearray_snapshot_matches(view, snapshot, path)
            finally:
                memoryview.release(view)
            self._memoize(value, digest)
            return digest
        if value_type is int:
            magnitude_bytes = (int.bit_length(value) + 7) // 8  # type: ignore[arg-type]
            if magnitude_bytes > _IDENTITY_MAX_SCALAR_BYTES:
                raise ValueError(
                    "Network connection identity exceeds the maximum scalar size of "
                    f"{_IDENTITY_MAX_SCALAR_BYTES} bytes at {_identity_location(path)}"
                )
            negative = int.__lt__(value, 0)  # type: ignore[arg-type]
            magnitude = int.__abs__(value)  # type: ignore[arg-type]
            writer = self._writer(b"int", value, path)
            writer.atom(b"-" if negative else b"+")
            writer.atom(int.to_bytes(magnitude, magnitude_bytes, "big"))
            digest = writer.finish()
            self._memoize(value, digest)
            return digest
        if value_type is float:
            float_value = float.hex(value)  # type: ignore[arg-type]
            if float_value in {"nan", "inf", "-inf"}:
                raise ValueError(
                    f"Network connection identity float at {_identity_location(path)} must be finite"
                )
            if str.__eq__(float_value, "-0x0.0p+0"):
                float_value = "0x0.0p+0"
            return self._scalar_writer(
                b"float",
                value,
                self._utf8_bytes(float_value, path),
                path,
            )

        if value_type is tuple:
            member_count = tuple.__len__(value)  # type: ignore[arg-type]
            self._ensure_members(member_count, path)
            self._ensure_child_nodes(member_count, path)
            self._ensure_encoded(member_count * _IDENTITY_DIGEST_ATOM_BYTES, path)
            snapshot = tuple.__getitem__(value, slice(None))  # type: ignore[arg-type]
            return self._encode_sequence(b"tuple", value, snapshot, depth, path)
        if value_type is list:
            snapshot = _identity_list_snapshot(value, path)  # type: ignore[arg-type]
            member_count = list.__len__(snapshot)
            self._ensure_members(member_count, path)
            self._ensure_child_nodes(member_count, path)
            self._ensure_encoded(member_count * _IDENTITY_DIGEST_ATOM_BYTES, path)
            return self._encode_sequence(b"list", value, snapshot, depth, path)
        if value_type is dict:
            snapshot = _identity_dict_snapshot(value, path)  # type: ignore[arg-type]
            member_count = tuple.__len__(snapshot)
            self._ensure_members(member_count, path)
            self._ensure_child_nodes(member_count * 2, path)
            self._ensure_encoded(member_count * _IDENTITY_DIGEST_ATOM_BYTES * 2, path)
            return self._encode_mapping(value, snapshot, depth, path)  # type: ignore[arg-type]
        if value_type is set:
            snapshot = _identity_set_snapshot(value, path)  # type: ignore[arg-type]
            member_count = tuple.__len__(snapshot)
            self._ensure_members(member_count, path)
            self._ensure_child_nodes(member_count, path)
            self._ensure_encoded(member_count * _IDENTITY_DIGEST_ATOM_BYTES, path)
            return self._encode_set(value, snapshot, depth, path)
        if value_type is frozenset:
            member_count = frozenset.__len__(value)  # type: ignore[arg-type]
            self._ensure_members(member_count, path)
            self._ensure_child_nodes(member_count, path)
            self._ensure_encoded(member_count * _IDENTITY_DIGEST_ATOM_BYTES, path)
            snapshot = tuple(frozenset.__iter__(value))  # type: ignore[arg-type]
            return self._encode_set(value, snapshot, depth, path)

        raise TypeError(
            "Network connection identity contains an unsupported semantic type at "
            f"{_identity_location(path)}"
        )

    def encode_request(
        self,
        request: object,
        expected_type: type[object],
    ) -> tuple[bytes, tuple[tuple[str, bytes], ...]]:
        """Encode one exact request root and return its field digest projection."""

        if (
            _IDENTITY_ROOT_TYPE is None
            or _IDENTITY_ROOT_POLICY is None
            or expected_type is not _IDENTITY_ROOT_TYPE
            or type(request) is not _IDENTITY_ROOT_TYPE
        ):
            raise TypeError("Network connection identity requires an exact request type")
        self._visit(0, ())
        request_mro = self._types.mro(expected_type, ())
        request_fields = self._types.dataclass_fields(expected_type, ())
        if request_fields is None:
            raise TypeError("Network connection identity requires a dataclass request type")
        excluded_fields = {field_name for field_name, compare in request_fields if compare is False}
        if excluded_fields != _NETWORK_CONNECTION_IDENTITY_EXCLUDED_FIELDS:
            raise TypeError(
                "Network connection identity request metadata does not match its excluded-field "
                "contract"
            )
        semantic_fields = tuple(
            field_name for field_name, compare in request_fields if compare is True
        )
        self._ensure_members(len(semantic_fields), ())
        self._ensure_child_nodes(len(semantic_fields), ())
        self._ensure_encoded(len(semantic_fields) * _IDENTITY_DIGEST_ATOM_BYTES, ())
        self._enter_composite(request, ())
        projection: list[tuple[str, bytes]] = []
        try:
            live_instance_values = _identity_instance_dict(self._types, request, request_mro, ())
            instance_values = live_instance_values
            if live_instance_values is not None:
                instance_values = _identity_validate_string_keyed_storage(
                    live_instance_values,
                    (),
                    "request instance storage",
                )
            writer = self._writer(b"network-request", request, ())
            writer.atom(len(semantic_fields).to_bytes(8, "big"))
            for field_name in semantic_fields:
                field_path = (field_name,)
                writer.atom(self._utf8_bytes(field_name, field_path))
                field_value = _identity_dataclass_field_value(
                    self._types,
                    request,
                    request_mro,
                    field_name,
                    instance_values,
                    field_path,
                )
                field_digest = self._encode(field_value, 1, field_path)
                writer.atom(field_digest)
                projection.append((field_name, field_digest))
            digest = writer.finish()
            if live_instance_values is not None and instance_values is not None:
                _identity_dict_snapshot_matches(
                    live_instance_values,
                    _identity_dict_snapshot(instance_values, ()),
                    (),
                )
        finally:
            self._leave_composite(request)
        self._memoize(request, digest)
        return digest, tuple(projection)


def _network_request_identity_fields(
    request: object,
    expected_type: type[object],
) -> tuple[tuple[str, bytes], ...]:
    """Return every canonical semantic request field and its full digest."""

    try:
        _digest, projection = _CanonicalIdentityEncoder().encode_request(request, expected_type)
    except RecursionError as exc:
        raise ValueError(
            f"Network connection identity exceeds the maximum depth of {_IDENTITY_MAX_DEPTH}"
        ) from exc
    return projection


def _network_request_stable_id(request: object, expected_type: type[object]) -> str:
    """Return one full-width deterministic identifier for a complete network intent."""

    inspector = _TRUSTED_IDENTITY_TYPE_INSPECTOR
    if inspector is None:
        raise RuntimeError("Network connection identity request type is not registered")
    try:
        identity_digest, _projection = _CanonicalIdentityEncoder(
            type_inspector=inspector,
        ).encode_request(
            request,
            expected_type,
        )
    except RecursionError as exc:
        raise ValueError(
            f"Network connection identity exceeds the maximum depth of {_IDENTITY_MAX_DEPTH}"
        ) from exc
    except OverflowError as exc:
        raise ValueError("Network connection identity arithmetic exceeds supported bounds") from exc
    return f"network-connection-{stable_uuid('network-connection', 'v4', identity_digest.hex())}"


def _trusted_network_request_stable_id(request: object, expected_type: type[object]) -> str:
    """Return the same stable ID using import-captured trusted engine metadata."""

    inspector = _TRUSTED_IDENTITY_TYPE_INSPECTOR
    if inspector is None:
        raise RuntimeError("Network connection identity request type is not registered")
    try:
        identity_digest, _projection = _CanonicalIdentityEncoder(
            type_inspector=inspector,
            trusted_engine=True,
        ).encode_request(
            request,
            expected_type,
        )
    except RecursionError as exc:
        raise ValueError(
            f"Network connection identity exceeds the maximum depth of {_IDENTITY_MAX_DEPTH}"
        ) from exc
    except OverflowError as exc:
        raise ValueError("Network connection identity arithmetic exceeds supported bounds") from exc
    return f"network-connection-{stable_uuid('network-connection', 'v4', identity_digest.hex())}"
