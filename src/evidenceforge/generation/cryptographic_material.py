# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic standards-valid public cryptographic material registry."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import random
import re
import secrets
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, fields
from threading import RLock
from typing import Any, Literal, Self
from weakref import ReferenceType, WeakValueDictionary, ref

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from evidenceforge.events.cryptography import (
    CertificateAuthorityMaterial,
    CertificateIdentityPlan,
    CertificateKeyType,
    DkimKeyPlan,
    OcspCertificateStatus,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed

_EC_ORDERS = {
    256: int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
    384: int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
}

_TlsMaterialFamily = Literal["public_key", "authority", "certificate"]
_TlsMaterialKey = tuple[Any, ...]
_TlsMaterialPoint = tuple[_TlsMaterialFamily, _TlsMaterialKey]
_TlsMaterialValue = bytes | CertificateAuthorityMaterial | CertificateIdentityPlan

# The reviewed production cap counts semantic material points (public keys,
# authorities, and certificates), not TLS sessions.  Passing ``None`` retains
# the legacy unlimited behavior exactly.  Finite owners also bound each point
# and their aggregate logical bytes without evicting scenario-lifetime IDs.
_MAX_TLS_MATERIAL_POINT_RETAINED_BYTES = 1_048_576
_MAX_TLS_MATERIAL_OWNER_RETAINED_BYTES = 1_073_741_824
_MAX_TLS_PREPARATION_OWNER_RETAINED_BYTES = 2_147_483_648
_MAX_DKIM_KEY_RETAINED_BYTES = 1_048_576
_MAX_DKIM_KEY_OWNER_RETAINED_BYTES = 1_073_741_824
_TLS_PREPARATION_BASE_RETAINED_BYTES = 512
_TLS_PREPARATION_POINT_RETAINED_BYTES = 1_024 + (2 * _MAX_TLS_MATERIAL_POINT_RETAINED_BYTES)
_DEFAULT_TLS_MATERIAL_CAPACITY = 100_000
_MAX_TLS_PREPARATION_ID = (1 << 64) - 1
_MAX_TLS_MATERIAL_POINT_GENERATION = (1 << 64) - 1


class CryptographicMaterialCapacityError(StateError):
    """Raised when finite TLS material owner capacity would be exceeded."""


@dataclass(frozen=True, slots=True)
class _TlsMaterialPointPatch:
    """One exact absent-to-present TLS material mutation."""

    family: _TlsMaterialFamily
    key: _TlsMaterialKey
    expected_generation: int
    expected_value_digest: str
    value_digest: str
    value: _TlsMaterialValue

    @property
    def point(self) -> _TlsMaterialPoint:
        """Return the exact registry point reserved by this patch."""

        return self.family, self.key


@dataclass(frozen=True, slots=True)
class _TlsMaterialPublication:
    """One fully validated absent-to-present canonical mutation."""

    family: _TlsMaterialFamily
    key: _TlsMaterialKey
    value: _TlsMaterialValue
    reservation_id: int | None
    generation: int
    prior_state_component: int
    next_state_component: int
    retained_bytes: int
    prior_retained_bytes: int

    @property
    def point(self) -> _TlsMaterialPoint:
        """Return the exact registry point published by this plan."""

        return self.family, self.key


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CryptographicMaterialPreparationToken:
    """Opaque one-shot capability for a prepared TLS material overlay."""

    preparation_id: int
    overlay_digest: str
    public_key_writes: int
    authority_writes: int
    certificate_writes: int
    _registry_token: int = field(repr=False, default=0)
    _patches: tuple[_TlsMaterialPointPatch, ...] = field(repr=False, default=())
    _integrity_token: str = field(repr=False, default="")

    @property
    def publication_token(self) -> str:
        """Return the opaque registry-authenticated preparation proof."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class _CryptographicMaterialPreparationCapability:
    """Registry-owned locator and immutable deep preparation preimage."""

    token_id: int
    preparation_id: int
    integrity_token: str
    overlay_digest: str
    public_key_writes: int
    authority_writes: int
    certificate_writes: int
    patches: tuple[_TlsMaterialPointPatch, ...]
    points: tuple[_TlsMaterialPoint, ...]


@dataclass(frozen=True, slots=True, weakref_slot=True)
class CryptographicMaterialPreparationReceipt:
    """Authenticated proof that one TLS-only overlay committed."""

    preparation_id: int
    publication_token: str
    overlay_digest: str
    committed_digest: str
    public_key_writes: int
    authority_writes: int
    certificate_writes: int
    _registry_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")
    _preparation_token: CryptographicMaterialPreparationToken | None = field(
        repr=False,
        compare=False,
        default=None,
    )

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over this committed result."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class CryptographicMaterialPreparationCensus:
    """Bounded structural counters for TLS preparation diagnostics."""

    public_keys: int
    authorities: int
    certificates: int
    live_point_generations: int
    tombstone_generations: int
    prepared_overlays: int
    claimed_overlays: int
    reserved_points: int


@dataclass(frozen=True, slots=True)
class CryptographicMaterialPointCapacityCensus:
    """Material-point bounds plus complete auxiliary-retention accounting.

    The four legacy ``uncapped_*`` fields remain as compatibility mirrors.  DKIM
    values mirror the bounded counters and OCSP values remain zero because status
    is recomputed without registry retention.
    """

    material_point_capacity: int | None
    material_preparation_capacity: int | None
    material_byte_capacity: int | None
    material_preparation_byte_capacity: int | None
    live_material_points: int
    tombstone_material_points: int
    reserved_new_material_points: int
    retained_material_points: int
    material_point_high_water: int
    retained_material_bytes: int
    reserved_material_bytes: int
    material_byte_high_water: int
    material_point_generation_high_water: int
    material_point_generation_capacity: int | None
    retained_material_preparation_bytes: int
    material_preparation_high_water: int
    material_preparation_byte_high_water: int
    material_preparation_id_watermark: int
    material_preparation_id_capacity: int | None
    uncapped_dkim_key_entries: int
    uncapped_dkim_key_estimated_bytes: int
    uncapped_ocsp_status_entries: int
    uncapped_ocsp_status_estimated_bytes: int
    dkim_key_capacity: int | None = None
    dkim_key_byte_capacity: int | None = None
    retained_dkim_key_entries: int = 0
    retained_dkim_key_estimated_bytes: int = 0
    dkim_key_high_water: int = 0
    dkim_key_byte_high_water: int = 0
    ocsp_status_capacity: int = 0
    ocsp_status_byte_capacity: int = 0
    retained_ocsp_status_entries: int = 0
    retained_ocsp_status_estimated_bytes: int = 0


def _tls_material_value_digest(value: _TlsMaterialValue) -> str:
    """Return a stable collision-resistant digest for one immutable value."""

    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


def _tls_material_tree_retained_bytes(value: object) -> int:
    """Return a callback-free upper estimate for one validated immutable tree."""

    if value is None:
        return 16
    if type(value) is bool:
        return 32
    if type(value) is int:
        return 32 + max(0, (value.bit_length() + 7) // 8)
    if type(value) is float:
        return 32
    if type(value) is str:
        return 64 + (4 * len(value))
    if type(value) is bytes:
        return 64 + len(value)
    if type(value) is tuple:
        return (
            64 + (8 * len(value)) + sum(_tls_material_tree_retained_bytes(item) for item in value)
        )
    if type(value) in {
        CertificateAuthorityMaterial,
        CertificateIdentityPlan,
        DkimKeyPlan,
    }:
        members = fields(value)
        return (
            64
            + (8 * len(members))
            + sum(
                _tls_material_tree_retained_bytes(getattr(value, member.name)) for member in members
            )
        )
    raise StateError("TLS material retained-byte accounting received an invalid value")


def _tls_material_live_point_retained_bytes(
    point: _TlsMaterialPoint,
    value: _TlsMaterialValue,
) -> int:
    """Return the logical retained bytes for one canonical live point."""

    return 128 + _tls_material_tree_retained_bytes(point) + _tls_material_tree_retained_bytes(value)


def _tls_material_tombstone_retained_bytes(point: _TlsMaterialPoint) -> int:
    """Return the logical retained bytes for one ABA-safe tombstone."""

    return 128 + _tls_material_tree_retained_bytes(point)


def _tls_auxiliary_entry_estimated_bytes(key: object, value: object) -> int:
    """Return a callback-free logical-byte estimate for one auxiliary row."""

    return 128 + _tls_material_tree_retained_bytes(key) + _tls_material_tree_retained_bytes(value)


def _detached_dkim_key_plan(value: DkimKeyPlan) -> DkimKeyPlan:
    """Return a detached exact-field DKIM wrapper without invoking public hooks."""

    snapshot = object.__new__(DkimKeyPlan)
    for member in fields(DkimKeyPlan):
        object.__setattr__(
            snapshot,
            member.name,
            object.__getattribute__(value, member.name),
        )
    return snapshot


def _dkim_key_state_component(
    cache_key: tuple[str, str, int],
    value: DkimKeyPlan,
) -> int:
    """Return the order-independent state component for one validated wrapper."""

    canonical = (
        cache_key,
        value.domain,
        value.selector,
        value.public_key_spki_der,
        value.public_key_base64,
        value.key_size,
        value.exponent,
    )
    return _tls_material_state_component("dkim-key-wrapper-v1", canonical)


def _validate_tls_material_key(key: _TlsMaterialKey) -> None:
    """Reject caller-tampered keys with unstable representation behavior."""

    if type(key) is not tuple:
        raise StateError("TLS material preparation point key must be a canonical tuple")
    pending: list[object] = list(key)
    while pending:
        item = pending.pop()
        if type(item) in {str, int, bool, bytes}:
            continue
        if type(item) is tuple:
            pending.extend(item)
            continue
        raise StateError("TLS material preparation point key contains an invalid value")


def _validate_tls_material_value_tree(value: object, *, active: set[int] | None = None) -> None:
    """Reject nested caller-defined representation or copy behavior."""

    if active is None:
        active = set()
    if value is None or type(value) in {str, int, float, bool, bytes}:
        return
    identity = id(value)
    if identity in active:
        raise StateError("TLS material preparation values cannot contain reference cycles")
    active.add(identity)
    try:
        if type(value) is tuple:
            for item in value:
                _validate_tls_material_value_tree(item, active=active)
            return
        if type(value) in {CertificateAuthorityMaterial, CertificateIdentityPlan}:
            for member in fields(value):
                _validate_tls_material_value_tree(getattr(value, member.name), active=active)
            return
        raise StateError("TLS material preparation contains an invalid nested value")
    finally:
        active.remove(identity)


def _validate_tls_material_patch(patch: _TlsMaterialPointPatch) -> None:
    """Validate one exact staged patch before it enters an authenticated snapshot."""

    if type(patch) is not _TlsMaterialPointPatch:
        raise StateError("TLS material preparation contains an invalid patch type")
    if type(patch.family) is not str or patch.family not in {
        "public_key",
        "authority",
        "certificate",
    }:
        raise StateError("TLS material preparation contains an invalid point family")
    _validate_tls_material_key(patch.key)
    if type(patch.expected_generation) is not int or patch.expected_generation < 0:
        raise StateError("TLS material preparation contains an invalid point generation")
    if type(patch.expected_value_digest) is not str or type(patch.value_digest) is not str:
        raise StateError("TLS material preparation contains an invalid point digest")
    expected_type = {
        "public_key": bytes,
        "authority": CertificateAuthorityMaterial,
        "certificate": CertificateIdentityPlan,
    }[patch.family]
    if type(patch.value) is not expected_type:
        raise StateError(f"TLS material {patch.family} patch contains an invalid value type")
    _validate_tls_material_value_tree(patch.value)
    actual_digest = _tls_material_value_digest(patch.value)
    if actual_digest != patch.value_digest:
        raise StateError("TLS material staged value changed before preparation seal")


def _validate_tls_material_patch_binding(
    registry: CryptographicMaterialRegistry,
    patch: _TlsMaterialPointPatch,
) -> None:
    """Prove a staged value was derived for its exact semantic point key."""

    key = patch.key
    try:
        if patch.family == "public_key":
            identity, key_type, key_size = key
            expected: _TlsMaterialValue = registry._build_public_key_spki(
                identity,
                normalized_type=key_type,
                normalized_size=key_size,
            )
        elif patch.family == "authority":
            subject_name, issuer_name, key_type, key_size = key
            spki = registry._build_public_key_spki(
                f"certificate_authority:{subject_name}",
                normalized_type=key_type,
                normalized_size=key_size,
            )
            expected = registry._build_authority_material(
                subject_name=subject_name,
                issuer_name=issuer_name,
                normalized_type=key_type,
                normalized_size=key_size,
                spki=spki,
            )
        else:
            (
                backend_identity,
                subject_name,
                issuer_name,
                not_valid_before,
                not_valid_after,
                key_type,
                key_size,
                signature_algorithm,
                san_dns,
                basic_constraints_ca,
                host_certificate,
                client_certificate,
            ) = key
            spki = registry._build_public_key_spki(
                f"certificate:{backend_identity}:{subject_name}",
                normalized_type=key_type,
                normalized_size=key_size,
            )
            expected = registry._build_certificate_identity(
                cache_key=key,
                backend_identity=backend_identity,
                subject_name=subject_name,
                issuer_name=issuer_name,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                normalized_type=key_type,
                normalized_size=key_size,
                signature_algorithm=signature_algorithm,
                normalized_sans=san_dns,
                basic_constraints_ca=basic_constraints_ca,
                host_certificate=host_certificate,
                client_certificate=client_certificate,
                spki=spki,
            )
    except (TypeError, ValueError) as exc:
        raise StateError("TLS material preparation point key has an invalid schema") from exc
    if patch.value != expected:
        raise StateError("TLS material staged value does not match its semantic point key")


def _canonical_tls_material_patches(
    registry: CryptographicMaterialRegistry,
    patches: tuple[_TlsMaterialPointPatch, ...],
) -> tuple[_TlsMaterialPointPatch, ...]:
    """Create and validate the sole registry-owned deep patch preimage."""

    seen: set[_TlsMaterialPoint] = set()
    for patch in patches:
        _validate_tls_material_patch(patch)
        if patch.point in seen:
            raise StateError("TLS material preparation contains a duplicate point")
        seen.add(patch.point)
    for patch in patches:
        _validate_tls_material_patch_binding(registry, patch)
    try:
        snapshot = deepcopy(patches)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("TLS material preparation cannot freeze its staged values") from exc
    seen.clear()
    for patch in snapshot:
        _validate_tls_material_patch(patch)
        if patch.point in seen:
            raise StateError("TLS material preparation contains a duplicate point")
        seen.add(patch.point)
    for patch in snapshot:
        _validate_tls_material_patch_binding(registry, patch)
    return snapshot


def _tls_material_state_component(label: str, value: Any) -> int:
    """Return one order-independent 256-bit incremental state component."""

    return int.from_bytes(
        hashlib.sha256(repr((label, value)).encode("utf-8")).digest(),
        "big",
    )


def _tls_material_overlay_digest(patches: tuple[_TlsMaterialPointPatch, ...]) -> str:
    """Bind every point precondition and immutable staged value."""

    canonical = tuple(
        (
            patch.family,
            patch.key,
            patch.expected_generation,
            patch.expected_value_digest,
            patch.value_digest,
            patch.value,
        )
        for patch in patches
    )
    return hashlib.sha256(repr(canonical).encode("utf-8")).hexdigest()


def _tls_material_preparation_integrity_token(
    authority_secret: bytes,
    token: CryptographicMaterialPreparationToken,
) -> str:
    """Authenticate all public fields and the full private patch preimage."""

    del authority_secret
    return f"tls-material:{token._registry_token:x}:{token.preparation_id:x}"


def _validated_tls_material_preparation_integrity_token(
    authority_secret: bytes,
    token: CryptographicMaterialPreparationToken,
) -> str:
    """Return preparation integrity or reject malformed caller-owned fields."""

    if (
        type(token.preparation_id) is not int
        or token.preparation_id <= 0
        or type(token.overlay_digest) is not str
        or type(token.public_key_writes) is not int
        or token.public_key_writes < 0
        or type(token.authority_writes) is not int
        or token.authority_writes < 0
        or type(token.certificate_writes) is not int
        or token.certificate_writes < 0
        or type(token._registry_token) is not int
        or type(token._patches) is not tuple
        or type(token._integrity_token) is not str
    ):
        raise StateError("TLS material preparation token contains malformed fields")
    try:
        for patch in token._patches:
            _validate_tls_material_patch(patch)
        return _tls_material_preparation_integrity_token(authority_secret, token)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("TLS material preparation token contains malformed fields") from exc


def _tls_material_receipt_integrity_token(
    authority_secret: bytes,
    receipt: CryptographicMaterialPreparationReceipt,
) -> str:
    """Authenticate exact preparation and committed point-version membership."""

    del authority_secret
    return f"tls-material-receipt:{receipt._registry_token:x}:{receipt.preparation_id:x}"


def _validated_tls_material_receipt_integrity_token(
    authority_secret: bytes,
    receipt: CryptographicMaterialPreparationReceipt,
) -> str:
    """Return receipt integrity or reject malformed caller-owned fields."""

    if (
        type(receipt.preparation_id) is not int
        or receipt.preparation_id <= 0
        or type(receipt.publication_token) is not str
        or type(receipt.overlay_digest) is not str
        or type(receipt.committed_digest) is not str
        or type(receipt.public_key_writes) is not int
        or receipt.public_key_writes < 0
        or type(receipt.authority_writes) is not int
        or receipt.authority_writes < 0
        or type(receipt.certificate_writes) is not int
        or receipt.certificate_writes < 0
        or type(receipt._registry_token) is not int
        or type(receipt._integrity_token) is not str
    ):
        raise StateError("TLS material preparation receipt contains malformed fields")
    try:
        return _tls_material_receipt_integrity_token(authority_secret, receipt)
    except (AttributeError, TypeError, ValueError) as exc:
        raise StateError("TLS material preparation receipt contains malformed fields") from exc


def _distinguished_name_der(name: str) -> bytes:
    """Return DER for the project's readable comma-and-space DN convention."""

    normalized = re.sub(r",\s+", ",", name.strip())
    return x509.Name.from_rfc4514_string(normalized).public_bytes()


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return a DER length and the offset of its value."""

    if offset >= len(data):
        raise ValueError("Truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    octets = first & 0x7F
    if octets == 0 or octets > 4 or offset + octets > len(data):
        raise ValueError("Invalid DER length encoding")
    return int.from_bytes(data[offset : offset + octets], "big"), offset + octets


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return a DER tag, value, and next offset."""

    if offset >= len(data):
        raise ValueError("Truncated DER element")
    tag = data[offset]
    length, value_offset = _read_der_length(data, offset + 1)
    next_offset = value_offset + length
    if next_offset > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[value_offset:next_offset], next_offset


def subject_public_key_bitstring(spki_der: bytes) -> bytes:
    """Extract the RFC 6960 subjectPublicKey bits from SubjectPublicKeyInfo DER."""

    outer_tag, outer_value, outer_end = _read_der_tlv(spki_der, 0)
    if outer_tag != 0x30 or outer_end != len(spki_der):
        raise ValueError("SubjectPublicKeyInfo must be one DER sequence")
    algorithm_tag, _algorithm_value, key_offset = _read_der_tlv(outer_value, 0)
    if algorithm_tag != 0x30:
        raise ValueError("SubjectPublicKeyInfo algorithm must be a DER sequence")
    key_tag, key_value, key_end = _read_der_tlv(outer_value, key_offset)
    if key_tag != 0x03 or key_end != len(outer_value) or not key_value:
        raise ValueError("SubjectPublicKeyInfo must end with one BIT STRING")
    if key_value[0] != 0:
        raise ValueError("Only octet-aligned subject public keys are supported")
    return key_value[1:]


def certificate_serial_number(seed: str) -> str:
    """Return a stable positive serial using the configured RFC 5280 length profile."""

    from evidenceforge.config.schemas import TLS_SERIAL_LENGTH_MAX_WEIGHT
    from evidenceforge.generation.activity.tls_realism import serial_number_config

    configured_lengths = serial_number_config().get("byte_lengths", [])
    weighted_lengths: dict[int, int] = {}
    for entry in configured_lengths:
        if not isinstance(entry, dict):
            continue
        try:
            byte_length = int(entry.get("bytes", 0))
            weight = int(entry.get("weight", 0))
        except (OverflowError, TypeError, ValueError):
            continue
        if 1 <= byte_length <= 20 and 0 < weight <= TLS_SERIAL_LENGTH_MAX_WEIGHT:
            weighted_lengths[byte_length] = min(
                weighted_lengths.get(byte_length, 0) + weight,
                TLS_SERIAL_LENGTH_MAX_WEIGHT,
            )
    if weighted_lengths:
        lengths = list(weighted_lengths)
        weights = list(weighted_lengths.values())
    else:
        lengths = [8, 9, 10, 12, 16, 18, 20]
        weights = [8, 6, 6, 14, 40, 12, 14]
    length_rng = random.Random(_stable_seed(f"crypto_serial_length:{seed}"))
    byte_length = length_rng.choices(lengths, weights=weights, k=1)[0]
    digest = hashlib.shake_256(f"crypto_serial_value:{seed}".encode()).digest(byte_length)
    serial = int.from_bytes(digest, "big") >> 1
    return f"{max(1, serial):0{byte_length * 2}X}"


class CryptographicMaterialRegistry:
    """Resolve deterministic public material once and reuse it across all consumers."""

    def __init__(
        self,
        *,
        tls_material_capacity: int | None = _DEFAULT_TLS_MATERIAL_CAPACITY,
    ) -> None:
        if tls_material_capacity is not None and (
            type(tls_material_capacity) is not int
            or tls_material_capacity <= 0
            or tls_material_capacity > _MAX_TLS_PREPARATION_ID
        ):
            raise ValueError(
                "TLS material capacity must be None or a positive exact integer at most 2^64 - 1"
            )
        self._public_keys: dict[tuple[str, CertificateKeyType, int], bytes] = {}
        self._authorities: dict[
            tuple[str, str, CertificateKeyType, int], CertificateAuthorityMaterial
        ] = {}
        self._certificates: dict[tuple[Any, ...], CertificateIdentityPlan] = {}
        self._dkim_keys: dict[tuple[str, str, int], DkimKeyPlan] = {}
        self._dkim_key_estimated_bytes = 0
        self._dkim_key_high_water = 0
        self._dkim_key_byte_high_water = 0
        self._dkim_key_state_xor = 0
        self._tls_material_lock = RLock()
        self._tls_preparation_secret = secrets.token_bytes(32)
        self._next_tls_preparation_id = 1
        self._tls_point_generations: dict[_TlsMaterialPoint, int] = {}
        # Deletes are not part of today's public TLS registry contract.  The
        # separate tombstone map nevertheless preserves the last generation if
        # a future bounded-retention policy removes a point, preventing ABA
        # without changing the preparation token format.
        self._tls_point_tombstones: dict[_TlsMaterialPoint, int] = {}
        self._tls_point_reservations: dict[_TlsMaterialPoint, int] = {}
        self._tls_prepared_tokens: dict[
            int,
            CryptographicMaterialPreparationToken
            | ReferenceType[CryptographicMaterialPreparationToken],
        ] = {}
        self._tls_prepared_capabilities: dict[int, _CryptographicMaterialPreparationCapability] = {}
        self._tls_committed_receipts: WeakValueDictionary[
            int, CryptographicMaterialPreparationReceipt
        ] = WeakValueDictionary()
        self._tls_claimed_preparations: set[int] = set()
        self._tls_claimed_transactions: dict[
            int,
            CryptographicMaterialPreparedCommit
            | ReferenceType[CryptographicMaterialPreparedCommit],
        ] = {}
        self._tls_dead_preparations: deque[tuple[int, int]] = deque()
        self._tls_dead_claims: deque[tuple[int, int]] = deque()
        self._tls_canonical_state_xor = 0
        self._tls_prepared_state_xor = 0
        self._tls_reservation_state_xor = 0
        self._tls_claimed_state_xor = 0
        self._tls_prepared_state_components: dict[int, int] = {}
        self._tls_reservation_state_components: dict[_TlsMaterialPoint, int] = {}
        self._tls_claimed_state_components: dict[int, int] = {}
        self._tls_material_capacity = tls_material_capacity
        self._tls_new_slot_reservations: set[_TlsMaterialPoint] = set()
        self._tls_reservation_byte_deltas: dict[_TlsMaterialPoint, int] = {}
        self._tls_point_retained_bytes: dict[_TlsMaterialPoint, int] = {}
        self._tls_retained_material_bytes = 0
        self._tls_reserved_material_bytes = 0
        self._tls_preparation_retained_bytes: dict[int, int] = {}
        self._tls_retained_preparation_bytes = 0
        self._tls_material_high_water_points = 0
        self._tls_material_high_water_bytes = 0
        self._tls_material_generation_high_water = 0
        self._tls_preparation_high_water_overlays = 0
        self._tls_preparation_high_water_bytes = 0

    @property
    def tls_material_point_capacity(self) -> int | None:
        """Return the scenario-lifetime public-key/authority/certificate point cap."""

        return self._tls_material_capacity

    @property
    def tls_material_capacity(self) -> int | None:
        """Compatibility alias for :attr:`tls_material_point_capacity`."""

        return self.tls_material_point_capacity

    @property
    def dkim_key_capacity(self) -> int | None:
        """Return the bounded DKIM-wrapper cache capacity.

        The wrapper cache follows the TLS point capacity so the default owner is
        fully bounded while explicit ``tls_material_capacity=None`` preserves the
        legacy unlimited constructor mode.
        """

        return self._tls_material_capacity

    def _dkim_key_byte_capacity(self) -> int | None:
        """Return the derived logical byte cap for retained DKIM wrappers."""

        capacity = self._tls_material_capacity
        if capacity is None:
            return None
        return min(
            capacity * _MAX_DKIM_KEY_RETAINED_BYTES,
            _MAX_DKIM_KEY_OWNER_RETAINED_BYTES,
        )

    def _tls_live_material_points_locked(self) -> int:
        """Return exact canonical TLS material cardinality in constant time."""

        return len(self._public_keys) + len(self._authorities) + len(self._certificates)

    def _tls_retained_material_slots_locked(self) -> int:
        """Return unique live, tombstone, and virgin-reservation slots."""

        return (
            self._tls_live_material_points_locked()
            + len(self._tls_point_tombstones)
            + len(self._tls_new_slot_reservations)
        )

    def _tls_material_byte_capacity(self) -> int | None:
        """Return the derived logical byte cap for canonical material."""

        if self._tls_material_capacity is None:
            return None
        return min(
            self._tls_material_capacity * _MAX_TLS_MATERIAL_POINT_RETAINED_BYTES,
            _MAX_TLS_MATERIAL_OWNER_RETAINED_BYTES,
        )

    def _tls_preparation_byte_capacity(self) -> int | None:
        """Return the derived logical byte cap for active preparation snapshots."""

        if self._tls_material_capacity is None:
            return None
        return min(
            self._tls_material_capacity
            * (_TLS_PREPARATION_BASE_RETAINED_BYTES + _TLS_PREPARATION_POINT_RETAINED_BYTES),
            _MAX_TLS_PREPARATION_OWNER_RETAINED_BYTES,
        )

    def _tls_preparation_retained_size_locked(
        self,
        patches: tuple[_TlsMaterialPointPatch, ...],
    ) -> int:
        """Return a bounded upper estimate for both retained patch snapshots."""

        retained_bytes = _TLS_PREPARATION_BASE_RETAINED_BYTES
        for patch in patches:
            point_bytes = _tls_material_live_point_retained_bytes(patch.point, patch.value)
            if point_bytes > _MAX_TLS_MATERIAL_POINT_RETAINED_BYTES:
                raise CryptographicMaterialCapacityError(
                    "TLS material point retained-byte capacity exceeded: "
                    f"{point_bytes} > {_MAX_TLS_MATERIAL_POINT_RETAINED_BYTES}"
                )
            retained_bytes += 1_024 + (2 * point_bytes)
        return retained_bytes

    def _require_tls_material_capacity_locked(
        self,
        materials: tuple[tuple[_TlsMaterialPoint, _TlsMaterialValue], ...],
        *,
        reservation_id: int | None = None,
    ) -> tuple[tuple[_TlsMaterialPoint, ...], dict[_TlsMaterialPoint, int]]:
        """Preflight exact new slots and byte deltas without owner mutation."""

        if self._tls_material_capacity is None:
            return (), {}
        new_slot_points: list[_TlsMaterialPoint] = []
        byte_deltas: dict[_TlsMaterialPoint, int] = {}
        seen: set[_TlsMaterialPoint] = set()
        for point, proposed_value in materials:
            if point in seen:
                continue
            seen.add(point)
            family, key = point
            reserved_by = self._tls_point_reservations.get(point)
            if reserved_by is not None and reserved_by != reservation_id:
                raise StateError(f"TLS material point {family}:{key!r} is reserved")
            existing = self._tls_material_value_locked(family, key)
            if existing is not None:
                if existing != proposed_value:
                    raise StateError(f"TLS material point {family}:{key!r} changed unexpectedly")
                continue
            if self._tls_point_generation_locked(point) >= _MAX_TLS_MATERIAL_POINT_GENERATION:
                raise CryptographicMaterialCapacityError(
                    "TLS material point generation capacity is exhausted"
                )
            live_bytes = _tls_material_live_point_retained_bytes(point, proposed_value)
            if live_bytes > _MAX_TLS_MATERIAL_POINT_RETAINED_BYTES:
                raise CryptographicMaterialCapacityError(
                    "TLS material point retained-byte capacity exceeded: "
                    f"{live_bytes} > {_MAX_TLS_MATERIAL_POINT_RETAINED_BYTES}"
                )
            current_bytes = self._tls_point_retained_bytes.get(point, 0)
            if point not in self._tls_point_tombstones:
                if point not in self._tls_new_slot_reservations:
                    new_slot_points.append(point)
            byte_deltas[point] = max(0, live_bytes - current_bytes)

        retained_slots = self._tls_retained_material_slots_locked()
        if len(new_slot_points) > self._tls_material_capacity - retained_slots:
            raise CryptographicMaterialCapacityError(
                "TLS material retained-key capacity exceeded: "
                f"{retained_slots + len(new_slot_points)} > {self._tls_material_capacity}"
            )
        material_byte_capacity = self._tls_material_byte_capacity()
        assert material_byte_capacity is not None
        additional_bytes = sum(byte_deltas.values())
        retained_bytes = self._tls_retained_material_bytes + self._tls_reserved_material_bytes
        if additional_bytes > material_byte_capacity - retained_bytes:
            raise CryptographicMaterialCapacityError(
                "TLS material retained-byte capacity exceeded: "
                f"{retained_bytes + additional_bytes} > {material_byte_capacity}"
            )
        return tuple(new_slot_points), byte_deltas

    def _update_tls_capacity_high_water_locked(self) -> None:
        """Advance finite owner high-water marks inside their hard bounds."""

        if self._tls_material_capacity is None:
            return
        retained_slots = self._tls_retained_material_slots_locked()
        retained_bytes = self._tls_retained_material_bytes + self._tls_reserved_material_bytes
        self._tls_material_high_water_points = max(
            self._tls_material_high_water_points,
            retained_slots,
        )
        self._tls_material_high_water_bytes = max(
            self._tls_material_high_water_bytes,
            retained_bytes,
        )
        self._tls_preparation_high_water_overlays = max(
            self._tls_preparation_high_water_overlays,
            len(self._tls_prepared_tokens),
        )
        self._tls_preparation_high_water_bytes = max(
            self._tls_preparation_high_water_bytes,
            self._tls_retained_preparation_bytes,
        )

    def _tls_active_preparation_token_locked(
        self,
        preparation_id: int,
    ) -> CryptographicMaterialPreparationToken | None:
        """Resolve the strong unlimited token or finite weak public identity."""

        retained = self._tls_prepared_tokens.get(preparation_id)
        if retained is None:
            return None
        if type(retained) is CryptographicMaterialPreparationToken:
            return retained
        return retained()

    def _tls_active_claim_transaction_locked(
        self,
        preparation_id: int,
    ) -> CryptographicMaterialPreparedCommit | None:
        """Resolve the strong unlimited or weak finite claim transaction."""

        retained = self._tls_claimed_transactions.get(preparation_id)
        if retained is None:
            return None
        if type(retained) is CryptographicMaterialPreparedCommit:
            return retained
        return retained()

    def _tls_capability_for_exact_token_locked(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> _CryptographicMaterialPreparationCapability | None:
        """Locate one exact live public token without relying on reusable object IDs."""

        if type(token) is not CryptographicMaterialPreparationToken:
            return None
        preparation_id = token.preparation_id
        if type(preparation_id) is int and preparation_id > 0:
            active = self._tls_active_preparation_token_locked(preparation_id)
            capability = self._tls_prepared_capabilities.get(preparation_id)
            if active is token and capability is not None and capability.token_id == id(token):
                return capability
        # Exceptional cleanup for an exact token whose public preparation ID
        # was caller-mutated after seal. Normal valid-token lookup is O(1).
        for candidate_id in self._tls_prepared_tokens:
            if self._tls_active_preparation_token_locked(candidate_id) is not token:
                continue
            capability = self._tls_prepared_capabilities.get(candidate_id)
            if capability is not None and capability.token_id == id(token):
                return capability
        return None

    def _reap_abandoned_tls_preparations_locked(self) -> None:
        """Release finite reservations whose public token or claim was collected."""

        if self._tls_material_capacity is None:
            return
        while self._tls_dead_claims:
            preparation_id, _transaction_id = self._tls_dead_claims.popleft()
            retained = self._tls_claimed_transactions.get(preparation_id)
            if retained is None or type(retained) is CryptographicMaterialPreparedCommit:
                continue
            if retained() is not None:
                continue
            capability = self._tls_prepared_capabilities.get(preparation_id)
            if capability is not None:
                CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)
        while self._tls_dead_preparations:
            preparation_id, token_id = self._tls_dead_preparations.popleft()
            retained = self._tls_prepared_tokens.get(preparation_id)
            if retained is None or type(retained) is CryptographicMaterialPreparationToken:
                continue
            if retained() is not None:
                continue
            capability = self._tls_prepared_capabilities.get(preparation_id)
            if capability is not None and capability.token_id == token_id:
                CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)

    def _tls_material_value_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
    ) -> _TlsMaterialValue | None:
        """Return one exact canonical TLS value while the registry lock is held."""

        if family == "public_key":
            return self._public_keys.get(key)  # type: ignore[arg-type]
        if family == "authority":
            return self._authorities.get(key)  # type: ignore[arg-type]
        return self._certificates.get(key)

    def _tls_point_generation_locked(self, point: _TlsMaterialPoint) -> int:
        """Return a live generation or the retained deletion tombstone."""

        return self._tls_point_generations.get(
            point,
            self._tls_point_tombstones.get(point, 0),
        )

    def _tls_point_state_component_locked(
        self,
        point: _TlsMaterialPoint,
        value: _TlsMaterialValue | None,
        generation: int,
    ) -> int:
        """Return a live/tombstone state component, or zero for virgin absence."""

        if generation <= 0:
            return 0
        return _tls_material_state_component(
            "tls-canonical-point-v1",
            (
                point,
                generation,
                value is not None,
                "" if value is None else _tls_material_value_digest(value),
            ),
        )

    def _prepare_tls_material_publication_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        value: _TlsMaterialValue,
        *,
        reservation_id: int | None = None,
    ) -> int | _TlsMaterialPublication:
        """Validate and fully derive one publication before owner mutation."""

        point = (family, key)
        reserved_by = self._tls_point_reservations.get(point)
        if reserved_by is not None and reserved_by != reservation_id:
            raise StateError(f"TLS material point {family}:{key!r} has a prepared mutation")
        existing = self._tls_material_value_locked(family, key)
        if existing is not None:
            if existing != value:
                raise StateError(f"TLS material point {family}:{key!r} changed unexpectedly")
            return self._tls_point_generation_locked(point)
        if family == "public_key":
            if not isinstance(value, bytes):
                raise StateError("TLS public-key point requires bytes")
        elif family == "authority":
            if not isinstance(value, CertificateAuthorityMaterial):
                raise StateError("TLS authority point requires authority material")
        elif not isinstance(value, CertificateIdentityPlan):
            raise StateError("TLS certificate point requires a certificate identity")
        capacity_live_bytes = 0
        prior_retained_bytes = 0
        if self._tls_material_capacity is not None:
            capacity_live_bytes = _tls_material_live_point_retained_bytes(point, value)
            prior_retained_bytes = self._tls_point_retained_bytes.get(point, 0)
            if reservation_id is None:
                self._require_tls_material_capacity_locked(((point, value),))
            else:
                reserved_delta = self._tls_reservation_byte_deltas.get(point, 0)
                if capacity_live_bytes > prior_retained_bytes + reserved_delta:
                    raise StateError("TLS material preparation lost its retained-byte reservation")
        prior_generation = self._tls_point_generation_locked(point)
        if (
            self._tls_material_capacity is not None
            and prior_generation >= _MAX_TLS_MATERIAL_POINT_GENERATION
        ):
            raise CryptographicMaterialCapacityError(
                "TLS material point generation capacity is exhausted"
            )
        prior_component = CryptographicMaterialRegistry._tls_point_state_component_locked(
            self,
            point,
            None,
            prior_generation,
        )
        generation = prior_generation + 1
        next_component = CryptographicMaterialRegistry._tls_point_state_component_locked(
            self,
            point,
            value,
            generation,
        )
        return _TlsMaterialPublication(
            family=family,
            key=key,
            value=value,
            reservation_id=reservation_id,
            generation=generation,
            prior_state_component=prior_component,
            next_state_component=next_component,
            retained_bytes=capacity_live_bytes,
            prior_retained_bytes=prior_retained_bytes,
        )

    def _apply_tls_material_publications_locked(
        self,
        publications: tuple[_TlsMaterialPublication, ...],
    ) -> tuple[int, ...]:
        """Apply fully derived publications in one non-dispatching mutation tail."""

        points = tuple(publication.point for publication in publications)
        if len(set(points)) != len(points):
            raise StateError("TLS material publication batch contains a duplicate point")
        for publication in publications:
            family = publication.family
            key = publication.key
            value = publication.value
            point = publication.point
            if family == "public_key":
                self._public_keys[key] = value  # type: ignore[assignment,index]
            elif family == "authority":
                self._authorities[key] = value  # type: ignore[assignment,index]
            else:
                self._certificates[key] = value  # type: ignore[assignment]
            self._tls_point_generations[point] = publication.generation
            self._tls_point_tombstones.pop(point, None)
            self._tls_canonical_state_xor ^= publication.prior_state_component
            self._tls_canonical_state_xor ^= publication.next_state_component
            if self._tls_material_capacity is None:
                continue
            self._tls_material_generation_high_water = max(
                self._tls_material_generation_high_water,
                publication.generation,
            )
            self._tls_retained_material_bytes += (
                publication.retained_bytes - publication.prior_retained_bytes
            )
            self._tls_point_retained_bytes[point] = publication.retained_bytes
            if publication.reservation_id is not None:
                self._tls_new_slot_reservations.discard(point)
                reserved_delta = self._tls_reservation_byte_deltas.pop(point, 0)
                self._tls_reserved_material_bytes -= reserved_delta
        if self._tls_material_capacity is not None:
            CryptographicMaterialRegistry._update_tls_capacity_high_water_locked(self)
        return tuple(publication.generation for publication in publications)

    def _publish_tls_material_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        value: _TlsMaterialValue,
        *,
        reservation_id: int | None = None,
    ) -> int:
        """Publish one absent point and advance its exact generation."""

        prepared = CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
            self,
            family,
            key,
            value,
            reservation_id=reservation_id,
        )
        if type(prepared) is int:
            return prepared
        return CryptographicMaterialRegistry._apply_tls_material_publications_locked(
            self,
            (prepared,),
        )[0]

    def _delete_tls_material_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
    ) -> bool:
        """Delete one point while retaining an ABA-safe generation tombstone."""

        point = (family, key)
        if point in self._tls_point_reservations:
            raise StateError(f"TLS material point {family}:{key!r} has a prepared mutation")
        if self._tls_material_value_locked(family, key) is None:
            return False
        value = self._tls_material_value_locked(family, key)
        assert value is not None
        prior_generation = self._tls_point_generation_locked(point)
        if (
            self._tls_material_capacity is not None
            and prior_generation >= _MAX_TLS_MATERIAL_POINT_GENERATION
        ):
            raise CryptographicMaterialCapacityError(
                "TLS material point generation capacity is exhausted"
            )
        prior_component = CryptographicMaterialRegistry._tls_point_state_component_locked(
            self,
            point,
            value,
            prior_generation,
        )
        generation = prior_generation + 1
        next_component = CryptographicMaterialRegistry._tls_point_state_component_locked(
            self,
            point,
            None,
            generation,
        )
        prior_retained_bytes = 0
        tombstone_bytes = 0
        if self._tls_material_capacity is not None:
            prior_retained_bytes = self._tls_point_retained_bytes[point]
            tombstone_bytes = _tls_material_tombstone_retained_bytes(point)
        if family == "public_key":
            self._public_keys.pop(key)  # type: ignore[arg-type]
        elif family == "authority":
            self._authorities.pop(key)  # type: ignore[arg-type]
        else:
            self._certificates.pop(key)
        self._tls_point_generations.pop(point, None)
        self._tls_point_tombstones[point] = generation
        self._tls_canonical_state_xor ^= prior_component
        self._tls_canonical_state_xor ^= next_component
        if self._tls_material_capacity is not None:
            self._tls_material_generation_high_water = max(
                self._tls_material_generation_high_water,
                generation,
            )
            self._tls_point_retained_bytes[point] = tombstone_bytes
            self._tls_retained_material_bytes += tombstone_bytes - prior_retained_bytes
        return True

    def _tls_material_snapshot(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
    ) -> tuple[_TlsMaterialValue | None, int, str]:
        """Return one immutable canonical point snapshot for an overlay read."""

        with self._tls_material_lock:
            value = self._tls_material_value_locked(family, key)
            generation = self._tls_point_generation_locked((family, key))
            digest = "" if value is None else _tls_material_value_digest(value)
            return deepcopy(value), generation, digest

    def begin_tls_preparation(
        self,
        *,
        owner: object | None = None,
    ) -> CryptographicMaterialPreparation:
        """Begin one isolated read-through TLS material overlay."""

        return CryptographicMaterialPreparation(self, owner=owner)

    def tls_preparation_census(self) -> CryptographicMaterialPreparationCensus:
        """Return exact canonical and transient TLS preparation counts."""

        with self._tls_material_lock:
            self._reap_abandoned_tls_preparations_locked()
            return CryptographicMaterialPreparationCensus(
                public_keys=len(self._public_keys),
                authorities=len(self._authorities),
                certificates=len(self._certificates),
                live_point_generations=len(self._tls_point_generations),
                tombstone_generations=len(self._tls_point_tombstones),
                prepared_overlays=len(self._tls_prepared_tokens),
                claimed_overlays=len(self._tls_claimed_preparations),
                reserved_points=len(self._tls_point_reservations),
            )

    def census(self) -> CryptographicMaterialPreparationCensus:
        """Return the exact TLS material/preparation census."""

        return self.tls_preparation_census()

    def tls_material_point_capacity_census(self) -> CryptographicMaterialPointCapacityCensus:
        """Return complete constant-time material and auxiliary-retention accounting."""

        with self._tls_material_lock:
            self._reap_abandoned_tls_preparations_locked()
            capacity = self._tls_material_capacity
            dkim_byte_capacity = CryptographicMaterialRegistry._dkim_key_byte_capacity(self)
            return CryptographicMaterialPointCapacityCensus(
                material_point_capacity=capacity,
                material_preparation_capacity=capacity,
                material_byte_capacity=self._tls_material_byte_capacity(),
                material_preparation_byte_capacity=self._tls_preparation_byte_capacity(),
                live_material_points=self._tls_live_material_points_locked(),
                tombstone_material_points=len(self._tls_point_tombstones),
                reserved_new_material_points=len(self._tls_new_slot_reservations),
                retained_material_points=self._tls_retained_material_slots_locked(),
                material_point_high_water=self._tls_material_high_water_points,
                retained_material_bytes=self._tls_retained_material_bytes,
                reserved_material_bytes=self._tls_reserved_material_bytes,
                material_byte_high_water=self._tls_material_high_water_bytes,
                material_point_generation_high_water=self._tls_material_generation_high_water,
                material_point_generation_capacity=(
                    _MAX_TLS_MATERIAL_POINT_GENERATION if capacity is not None else None
                ),
                retained_material_preparation_bytes=self._tls_retained_preparation_bytes,
                material_preparation_high_water=self._tls_preparation_high_water_overlays,
                material_preparation_byte_high_water=self._tls_preparation_high_water_bytes,
                material_preparation_id_watermark=(
                    _MAX_TLS_PREPARATION_ID
                    if capacity is not None and self._next_tls_preparation_id == 0
                    else self._next_tls_preparation_id - 1
                ),
                material_preparation_id_capacity=(
                    _MAX_TLS_PREPARATION_ID if capacity is not None else None
                ),
                uncapped_dkim_key_entries=len(self._dkim_keys),
                uncapped_dkim_key_estimated_bytes=self._dkim_key_estimated_bytes,
                uncapped_ocsp_status_entries=0,
                uncapped_ocsp_status_estimated_bytes=0,
                dkim_key_capacity=capacity,
                dkim_key_byte_capacity=dkim_byte_capacity,
                retained_dkim_key_entries=len(self._dkim_keys),
                retained_dkim_key_estimated_bytes=self._dkim_key_estimated_bytes,
                dkim_key_high_water=self._dkim_key_high_water,
                dkim_key_byte_high_water=self._dkim_key_byte_high_water,
                ocsp_status_capacity=0,
                ocsp_status_byte_capacity=0,
                retained_ocsp_status_entries=0,
                retained_ocsp_status_estimated_bytes=0,
            )

    def state_digest(self) -> str:
        """Return an incremental digest of canonical and transient TLS registry state."""

        with self._tls_material_lock:
            self._reap_abandoned_tls_preparations_locked()
            canonical: tuple[Any, ...] = (
                "cryptographic-material-registry-state-v1",
                self._tls_canonical_state_xor,
                self._tls_prepared_state_xor,
                self._tls_reservation_state_xor,
                self._tls_claimed_state_xor,
                len(self._public_keys),
                len(self._authorities),
                len(self._certificates),
                len(self._tls_point_generations),
                len(self._tls_point_tombstones),
                len(self._tls_prepared_tokens),
                len(self._tls_claimed_preparations),
                len(self._tls_point_reservations),
            )
            if self._dkim_keys:
                canonical += (
                    "bounded-dkim-key-wrapper-v1",
                    self._dkim_key_state_xor,
                    len(self._dkim_keys),
                    self._dkim_key_estimated_bytes,
                )
            if self._tls_material_capacity is not None:
                canonical += (
                    "finite-tls-material-capacity-v1",
                    self._tls_material_capacity,
                    len(self._tls_new_slot_reservations),
                    self._tls_retained_material_bytes,
                    self._tls_reserved_material_bytes,
                    self._tls_retained_preparation_bytes,
                )
            return hashlib.sha256(repr(canonical).encode("utf-8")).hexdigest()

    def authenticates_tls_preparation_token(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> bool:
        """Return whether one intact preparation token is active here."""

        if type(token) is not CryptographicMaterialPreparationToken:
            return False
        with self._tls_material_lock:
            try:
                self._active_tls_preparation_locked(token)
            except StateError:
                return False
            return True

    def authenticates_tls_preparation_receipt(
        self,
        receipt: CryptographicMaterialPreparationReceipt,
        *,
        token: CryptographicMaterialPreparationToken | None = None,
    ) -> bool:
        """Return whether this registry issued the exact committed receipt."""

        if type(receipt) is not CryptographicMaterialPreparationReceipt:
            return False
        with self._tls_material_lock:
            if self._tls_committed_receipts.get(id(receipt)) is not receipt:
                return False
        if token is None:
            return True
        return token is receipt._preparation_token

    def _active_tls_preparation_locked(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> _CryptographicMaterialPreparationCapability:
        """Return the registry-owned capability for an intact active token."""

        self._reap_abandoned_tls_preparations_locked()
        if type(token) is not CryptographicMaterialPreparationToken:
            raise StateError("TLS material preparation token has an invalid type")
        capability = self._tls_capability_for_exact_token_locked(token)
        if capability is None:
            if type(token._registry_token) is not int:
                raise StateError("TLS material preparation token integrity validation failed")
            if token._registry_token != id(self):
                raise StateError("TLS material preparation token belongs to another registry")
            raise StateError("TLS material preparation token is stale or already consumed")
        active = self._tls_active_preparation_token_locked(capability.preparation_id)
        if active is not token:
            raise StateError("TLS material preparation token is stale or already consumed")
        return capability

    def _release_tls_preparation_locked(
        self,
        capability: _CryptographicMaterialPreparationCapability,
    ) -> None:
        """Release reservations from the registry-owned immutable locator."""

        preparation_id = capability.preparation_id
        active = self._tls_prepared_tokens.get(preparation_id)
        retained = self._tls_prepared_capabilities.get(preparation_id)
        if active is None or retained is not capability:
            return
        if preparation_id not in self._tls_prepared_state_components:
            raise StateError("TLS material preparation lost its prepared state component")
        prepared_component = self._tls_prepared_state_components[preparation_id]
        claimed_component = self._tls_claimed_state_components.get(preparation_id)
        reservation_components: list[tuple[_TlsMaterialPoint, int]] = []
        for point in capability.points:
            if self._tls_point_reservations.get(point) != preparation_id:
                continue
            if point not in self._tls_reservation_state_components:
                raise StateError("TLS material preparation lost a reservation state component")
            reservation_components.append((point, self._tls_reservation_state_components[point]))
        if preparation_id in self._tls_claimed_preparations and claimed_component is None:
            raise StateError("TLS material preparation lost its claimed state component")

        self._tls_prepared_tokens.pop(preparation_id)
        self._tls_prepared_capabilities.pop(preparation_id)
        self._tls_prepared_state_components.pop(preparation_id)
        self._tls_prepared_state_xor ^= prepared_component
        if self._tls_material_capacity is not None:
            preparation_bytes = self._tls_preparation_retained_bytes.pop(
                preparation_id,
                0,
            )
            self._tls_retained_preparation_bytes -= preparation_bytes
        if preparation_id in self._tls_claimed_preparations:
            assert claimed_component is not None
            self._tls_claimed_state_components.pop(preparation_id)
            self._tls_claimed_state_xor ^= claimed_component
            self._tls_claimed_preparations.discard(preparation_id)
        self._tls_claimed_transactions.pop(preparation_id, None)
        for point, reservation_component in reservation_components:
            if self._tls_point_reservations.get(point) == preparation_id:
                if self._tls_material_capacity is not None:
                    self._tls_new_slot_reservations.discard(point)
                    reserved_delta = self._tls_reservation_byte_deltas.pop(point, 0)
                    self._tls_reserved_material_bytes -= reserved_delta
                self._tls_point_reservations.pop(point)
                self._tls_reservation_state_components.pop(point)
                self._tls_reservation_state_xor ^= reservation_component
        if not self._tls_prepared_tokens:
            self._tls_prepared_tokens.clear()
            self._tls_prepared_capabilities.clear()
            self._tls_claimed_preparations.clear()
            self._tls_claimed_transactions.clear()
            self._tls_point_reservations.clear()
            self._tls_prepared_state_components.clear()
            self._tls_reservation_state_components.clear()
            self._tls_claimed_state_components.clear()
            self._tls_prepared_state_xor = 0
            self._tls_reservation_state_xor = 0
            self._tls_claimed_state_xor = 0
            self._tls_new_slot_reservations.clear()
            self._tls_reservation_byte_deltas.clear()
            self._tls_preparation_retained_bytes.clear()
            self._tls_dead_preparations.clear()
            self._tls_dead_claims.clear()
            self._tls_reserved_material_bytes = 0
            self._tls_retained_preparation_bytes = 0

    def _validate_tls_preparation_locked(
        self,
        capability: _CryptographicMaterialPreparationCapability,
    ) -> None:
        """Revalidate exact point generations and immutable preimages."""

        for patch in capability.patches:
            point = patch.point
            if self._tls_point_reservations.get(point) != capability.preparation_id:
                raise StateError("TLS material preparation lost an exact point reservation")
            value = self._tls_material_value_locked(patch.family, patch.key)
            digest = "" if value is None else _tls_material_value_digest(value)
            if (
                self._tls_point_generation_locked(point) != patch.expected_generation
                or digest != patch.expected_value_digest
            ):
                raise StateError("TLS material preparation point generation changed")

    def _seal_tls_preparation(
        self,
        patches: tuple[_TlsMaterialPointPatch, ...],
    ) -> CryptographicMaterialPreparationToken:
        """Reserve all staged points and issue one authenticated token."""

        trusted_patches = _canonical_tls_material_patches(self, patches)
        with self._tls_material_lock:
            self._reap_abandoned_tls_preparations_locked()
            retained: list[_TlsMaterialPointPatch] = []
            for patch in trusted_patches:
                point = patch.point
                value = self._tls_material_value_locked(patch.family, patch.key)
                generation = self._tls_point_generation_locked(point)
                digest = "" if value is None else _tls_material_value_digest(value)
                if generation != patch.expected_generation or digest != patch.expected_value_digest:
                    raise StateError("TLS material preparation point changed before seal")
                if value is not None:
                    if digest != patch.value_digest:
                        raise StateError("TLS material preparation conflicts with canonical value")
                    continue
                if point in self._tls_point_reservations:
                    raise StateError(f"TLS material point {patch.family}:{patch.key!r} is reserved")
                retained.append(patch)

            final_patches = tuple(retained)
            reserved_new_points: tuple[_TlsMaterialPoint, ...] = ()
            reserved_byte_deltas: dict[_TlsMaterialPoint, int] = {}
            preparation_retained_bytes = 0
            if self._tls_material_capacity is not None:
                if len(self._tls_prepared_tokens) >= self._tls_material_capacity:
                    raise CryptographicMaterialCapacityError(
                        "TLS material preparation capacity is exhausted"
                    )
                reserved_new_points, reserved_byte_deltas = (
                    self._require_tls_material_capacity_locked(
                        tuple((patch.point, patch.value) for patch in final_patches)
                    )
                )
                preparation_retained_bytes = self._tls_preparation_retained_size_locked(
                    final_patches
                )
                preparation_byte_capacity = self._tls_preparation_byte_capacity()
                assert preparation_byte_capacity is not None
                if (
                    self._tls_retained_preparation_bytes + preparation_retained_bytes
                    > preparation_byte_capacity
                ):
                    raise CryptographicMaterialCapacityError(
                        "TLS material preparation retained-byte capacity is exhausted"
                    )
                if self._next_tls_preparation_id == 0:
                    raise CryptographicMaterialCapacityError(
                        "TLS material preparation identity capacity is exhausted"
                    )
            preparation_id = self._next_tls_preparation_id
            overlay_digest = hashlib.sha256(f"tls-material:{preparation_id}".encode()).hexdigest()
            token = CryptographicMaterialPreparationToken(
                preparation_id=preparation_id,
                overlay_digest=overlay_digest,
                public_key_writes=sum(patch.family == "public_key" for patch in final_patches),
                authority_writes=sum(patch.family == "authority" for patch in final_patches),
                certificate_writes=sum(patch.family == "certificate" for patch in final_patches),
                _registry_token=id(self),
                _patches=final_patches,
                _integrity_token=overlay_digest,
            )
            capability = _CryptographicMaterialPreparationCapability(
                token_id=id(token),
                preparation_id=preparation_id,
                integrity_token=token.publication_token,
                overlay_digest=overlay_digest,
                public_key_writes=token.public_key_writes,
                authority_writes=token.authority_writes,
                certificate_writes=token.certificate_writes,
                patches=final_patches,
                points=tuple(patch.point for patch in final_patches),
            )
            prepared_component = _tls_material_state_component(
                "tls-prepared-capability-v1",
                capability,
            )
            reservation_components = tuple(
                (
                    point,
                    _tls_material_state_component(
                        "tls-point-reservation-v1",
                        (point, preparation_id),
                    ),
                )
                for point in capability.points
            )
            if self._tls_material_capacity is None:
                retained_public_token: (
                    CryptographicMaterialPreparationToken
                    | ReferenceType[CryptographicMaterialPreparationToken]
                ) = token
                next_preparation_id = preparation_id + 1
            else:
                dead_preparations = self._tls_dead_preparations

                def token_collected(
                    _token_reference: ReferenceType[CryptographicMaterialPreparationToken],
                    *,
                    dead: deque[tuple[int, int]] = dead_preparations,
                    expired_preparation_id: int = preparation_id,
                    expired_token_id: int = id(token),
                ) -> None:
                    dead.append((expired_preparation_id, expired_token_id))

                retained_public_token = ref(token, token_collected)
                next_preparation_id = (
                    0 if preparation_id == _MAX_TLS_PREPARATION_ID else preparation_id + 1
                )

            self._tls_prepared_tokens[preparation_id] = retained_public_token
            self._tls_prepared_capabilities[preparation_id] = capability
            self._tls_prepared_state_components[preparation_id] = prepared_component
            self._tls_prepared_state_xor ^= prepared_component
            for point, reservation_component in reservation_components:
                self._tls_point_reservations[point] = preparation_id
                self._tls_reservation_state_components[point] = reservation_component
                self._tls_reservation_state_xor ^= reservation_component
            if self._tls_material_capacity is not None:
                self._tls_new_slot_reservations.update(reserved_new_points)
                self._tls_reservation_byte_deltas.update(reserved_byte_deltas)
                self._tls_reserved_material_bytes += sum(reserved_byte_deltas.values())
                self._tls_preparation_retained_bytes[preparation_id] = preparation_retained_bytes
                self._tls_retained_preparation_bytes += preparation_retained_bytes
                CryptographicMaterialRegistry._update_tls_capacity_high_water_locked(self)
            self._next_tls_preparation_id = next_preparation_id
            return token

    def cancel_tls_preparation(self, token: CryptographicMaterialPreparationToken) -> bool:
        """Cancel one unclaimed overlay without publishing canonical material."""

        with self._tls_material_lock:
            capability = self._tls_capability_for_exact_token_locked(token)
            if capability is None:
                return False
            if capability.preparation_id in self._tls_claimed_preparations:
                return False
            try:
                capability = self._active_tls_preparation_locked(token)
            except StateError:
                CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)
                raise
            CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)
            return True

    def _claim_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
        transaction: CryptographicMaterialPreparedCommit,
    ) -> None:
        """Claim and validate one overlay in a short registry-only section."""

        with self._tls_material_lock:
            if (
                type(transaction) is not CryptographicMaterialPreparedCommit
                or transaction._registry is not self
                or transaction._token is not token
            ):
                raise StateError("TLS material prepared commit has an invalid owner binding")
            capability = self._tls_capability_for_exact_token_locked(token)
            if (
                capability is not None
                and capability.preparation_id in self._tls_claimed_preparations
            ):
                raise StateError("TLS material preparation token is already claimed")
            try:
                capability = self._active_tls_preparation_locked(token)
            except StateError:
                if capability is not None:
                    CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)
                raise
            self._validate_tls_preparation_locked(capability)
            self._active_tls_preparation_locked(token)
            claimed_component = _tls_material_state_component(
                "tls-claimed-preparation-v1",
                capability.preparation_id,
            )
            if self._tls_material_capacity is None:
                retained_transaction: (
                    CryptographicMaterialPreparedCommit
                    | ReferenceType[CryptographicMaterialPreparedCommit]
                ) = transaction
            else:
                dead_claims = self._tls_dead_claims

                def transaction_collected(
                    _transaction_reference: ReferenceType[CryptographicMaterialPreparedCommit],
                    *,
                    dead: deque[tuple[int, int]] = dead_claims,
                    expired_preparation_id: int = capability.preparation_id,
                    expired_transaction_id: int = id(transaction),
                ) -> None:
                    dead.append((expired_preparation_id, expired_transaction_id))

                retained_transaction = ref(
                    transaction,
                    transaction_collected,
                )

            self._tls_claimed_transactions[capability.preparation_id] = retained_transaction
            self._tls_claimed_preparations.add(capability.preparation_id)
            self._tls_claimed_state_components[capability.preparation_id] = claimed_component
            self._tls_claimed_state_xor ^= claimed_component

    def _cancel_claimed_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
        transaction: CryptographicMaterialPreparedCommit,
    ) -> None:
        """Release an uncommitted claim after its external composite aborts."""

        with self._tls_material_lock:
            capability = self._tls_capability_for_exact_token_locked(token)
            if capability is None:
                return
            try:
                self._active_tls_preparation_locked(token)
            except StateError:
                CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)
                return
            if capability.preparation_id not in self._tls_claimed_preparations:
                raise StateError("TLS material preparation token is not claimed")
            if (
                self._tls_active_claim_transaction_locked(capability.preparation_id)
                is not transaction
            ):
                raise StateError("TLS material prepared commit is not the claim owner")
            CryptographicMaterialRegistry._release_tls_preparation_locked(self, capability)

    @contextmanager
    def prepared_tls_material(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> Iterator[CryptographicMaterialPreparedCommit]:
        """Claim one overlay without retaining the registry lock externally."""

        transaction = CryptographicMaterialPreparedCommit(self, token)
        CryptographicMaterialRegistry._claim_tls_preparation(self, token, transaction)
        try:
            yield transaction
        finally:
            try:
                CryptographicMaterialRegistry._cancel_claimed_tls_preparation(
                    self,
                    token,
                    transaction,
                )
            finally:
                CryptographicMaterialPreparedCommit._close(transaction)

    def _commit_claimed_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
        transaction: CryptographicMaterialPreparedCommit,
    ) -> CryptographicMaterialPreparationReceipt:
        """Apply already-validated point writes and sign their exact versions."""

        with self._tls_material_lock:
            capability = self._tls_capability_for_exact_token_locked(token)
            if (
                capability is None
                or self._tls_active_preparation_token_locked(capability.preparation_id) is not token
            ):
                raise StateError("TLS material preparation token is stale or already consumed")
            if capability.preparation_id not in self._tls_claimed_preparations:
                raise StateError("TLS material preparation token is not claimed")
            if (
                self._tls_active_claim_transaction_locked(capability.preparation_id)
                is not transaction
            ):
                raise StateError("TLS material prepared commit is not the claim owner")
            publications: list[_TlsMaterialPublication] = []
            committed_points: list[tuple[_TlsMaterialFamily, _TlsMaterialKey, int, str]] = []
            for patch in capability.patches:
                prepared = CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
                    self,
                    patch.family,
                    patch.key,
                    patch.value,
                    reservation_id=capability.preparation_id,
                )
                if type(prepared) is int:
                    generation = prepared
                else:
                    publications.append(prepared)
                    generation = prepared.generation
                committed_points.append((patch.family, patch.key, generation, patch.value_digest))
            committed_digest = hashlib.sha256(
                repr(tuple(committed_points)).encode("utf-8")
            ).hexdigest()
            receipt = CryptographicMaterialPreparationReceipt(
                preparation_id=capability.preparation_id,
                publication_token=capability.integrity_token,
                overlay_digest=capability.overlay_digest,
                committed_digest=committed_digest,
                public_key_writes=capability.public_key_writes,
                authority_writes=capability.authority_writes,
                certificate_writes=capability.certificate_writes,
                _registry_token=id(self),
                _integrity_token=committed_digest,
                _preparation_token=token,
            )
            self._tls_committed_receipts[id(receipt)] = receipt
            CryptographicMaterialRegistry._apply_tls_material_publications_locked(
                self,
                tuple(publications),
            )
            CryptographicMaterialRegistry._release_tls_preparation_locked(
                self,
                capability,
            )
            return receipt

    @staticmethod
    def _normalize_key_profile(
        key_type: str,
        key_size: int,
    ) -> tuple[CertificateKeyType, int]:
        normalized_type: CertificateKeyType = "ecdsa" if key_type.lower() == "ecdsa" else "rsa"
        if normalized_type == "rsa":
            normalized_size = min(
                (2048, 3072, 4096), key=lambda candidate: abs(candidate - key_size)
            )
        else:
            normalized_size = 384 if key_size >= 384 else 256
        return normalized_type, normalized_size

    def public_key_spki(
        self,
        identity: str,
        *,
        key_type: str,
        key_size: int,
    ) -> bytes:
        """Return deterministic, parseable SubjectPublicKeyInfo DER."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        cache_key = (identity, normalized_type, normalized_size)
        with self._tls_material_lock:
            if self._tls_material_capacity is not None:
                self._reap_abandoned_tls_preparations_locked()
            cached = self._public_keys.get(cache_key)
            if cached is not None:
                return cached
            point: _TlsMaterialPoint = ("public_key", cache_key)
            if point in self._tls_point_reservations:
                raise StateError(f"TLS material point public_key:{cache_key!r} is reserved")
            spki = self._build_public_key_spki(
                identity,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
            )
            self._publish_tls_material_locked("public_key", cache_key, spki)
            return spki

    @staticmethod
    def _build_public_key_spki(
        identity: str,
        *,
        normalized_type: CertificateKeyType,
        normalized_size: int,
    ) -> bytes:
        """Build deterministic, parseable SubjectPublicKeyInfo DER without mutation."""

        seed = f"cryptographic_public_key:{identity}:{normalized_type}:{normalized_size}"
        if normalized_type == "rsa":
            modulus = bytearray(hashlib.shake_256(seed.encode()).digest(normalized_size // 8))
            modulus[0] |= 0x80
            modulus[-1] |= 0x01
            public_key = rsa.RSAPublicNumbers(65537, int.from_bytes(modulus, "big")).public_key()
        else:
            order = _EC_ORDERS[normalized_size]
            scalar_bytes = hashlib.sha512(seed.encode()).digest()
            scalar = (int.from_bytes(scalar_bytes, "big") % (order - 1)) + 1
            curve = ec.SECP384R1() if normalized_size == 384 else ec.SECP256R1()
            public_key = ec.derive_private_key(scalar, curve).public_key()
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded = serialization.load_der_public_key(spki)
        if (
            loaded.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            != spki
        ):
            raise ValueError("Cryptographic public-key DER failed round-trip validation")
        subject_public_key_bitstring(spki)
        return spki

    def resolve_authority(
        self,
        *,
        subject_name: str,
        issuer_name: str,
        key_type: str,
        key_size: int,
    ) -> CertificateAuthorityMaterial:
        """Return stable public identity material for a certificate authority."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        cache_key = (subject_name, issuer_name, normalized_type, normalized_size)
        with self._tls_material_lock:
            if self._tls_material_capacity is not None:
                self._reap_abandoned_tls_preparations_locked()
            cached = self._authorities.get(cache_key)
            if cached is not None:
                return deepcopy(cached)
            point: _TlsMaterialPoint = ("authority", cache_key)
            if point in self._tls_point_reservations:
                raise StateError(f"TLS material point authority:{cache_key!r} is reserved")
            if self._tls_material_capacity is not None:
                public_key_cache_key = (
                    f"certificate_authority:{subject_name}",
                    normalized_type,
                    normalized_size,
                )
                public_key_point: _TlsMaterialPoint = ("public_key", public_key_cache_key)
                if public_key_point in self._tls_point_reservations:
                    raise StateError(
                        f"TLS material point public_key:{public_key_cache_key!r} is reserved"
                    )
                spki = self._public_keys.get(public_key_cache_key)
                publish_public_key = spki is None
                if spki is None:
                    spki = self._build_public_key_spki(
                        f"certificate_authority:{subject_name}",
                        normalized_type=normalized_type,
                        normalized_size=normalized_size,
                    )
                authority = self._build_authority_material(
                    subject_name=subject_name,
                    issuer_name=issuer_name,
                    normalized_type=normalized_type,
                    normalized_size=normalized_size,
                    spki=spki,
                )
                self._require_tls_material_capacity_locked(
                    ((public_key_point, spki), (point, authority))
                )
                publications: list[_TlsMaterialPublication] = []
                if publish_public_key:
                    prepared_public_key = (
                        CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
                            self,
                            "public_key",
                            public_key_cache_key,
                            spki,
                        )
                    )
                    if type(prepared_public_key) is int:
                        raise StateError("TLS authority public-key prerequisite changed")
                    publications.append(prepared_public_key)
                prepared_authority = (
                    CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
                        self,
                        "authority",
                        cache_key,
                        authority,
                    )
                )
                if type(prepared_authority) is int:
                    raise StateError("TLS authority point changed before publication")
                publications.append(prepared_authority)
                CryptographicMaterialRegistry._apply_tls_material_publications_locked(
                    self,
                    tuple(publications),
                )
                return deepcopy(authority)
            spki = self.public_key_spki(
                f"certificate_authority:{subject_name}",
                key_type=normalized_type,
                key_size=normalized_size,
            )
            authority = self._build_authority_material(
                subject_name=subject_name,
                issuer_name=issuer_name,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
                spki=spki,
            )
            self._publish_tls_material_locked("authority", cache_key, authority)
            return deepcopy(authority)

    @staticmethod
    def _build_authority_material(
        *,
        subject_name: str,
        issuer_name: str,
        normalized_type: CertificateKeyType,
        normalized_size: int,
        spki: bytes,
    ) -> CertificateAuthorityMaterial:
        """Build one immutable authority value without registry mutation."""

        try:
            subject_name_der = _distinguished_name_der(subject_name)
        except ValueError as exc:
            raise ValueError(f"Invalid certificate-authority name {subject_name!r}: {exc}") from exc
        return CertificateAuthorityMaterial(
            subject_name=subject_name,
            issuer_name=issuer_name,
            subject_name_der=subject_name_der,
            public_key_spki_der=spki,
            public_key_bitstring=subject_public_key_bitstring(spki),
            key_type=normalized_type,
            key_size=normalized_size,
        )

    def resolve_certificate(
        self,
        *,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        key_type: str,
        key_size: int,
        signature_algorithm: str,
        san_dns: tuple[str, ...] = (),
        basic_constraints_ca: bool = False,
        host_certificate: bool = True,
        client_certificate: bool = False,
    ) -> CertificateIdentityPlan:
        """Return one stable certificate identity with parseable public-key material."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        normalized_sans = tuple(dict.fromkeys(name.rstrip(".").lower() for name in san_dns if name))
        cache_key = (
            backend_identity,
            subject_name,
            issuer_name,
            not_valid_before,
            not_valid_after,
            normalized_type,
            normalized_size,
            signature_algorithm,
            normalized_sans,
            basic_constraints_ca,
            host_certificate,
            client_certificate,
        )
        with self._tls_material_lock:
            if self._tls_material_capacity is not None:
                self._reap_abandoned_tls_preparations_locked()
            cached = self._certificates.get(cache_key)
            if cached is not None:
                return deepcopy(cached)
            point: _TlsMaterialPoint = ("certificate", cache_key)
            if point in self._tls_point_reservations:
                raise StateError(f"TLS material point certificate:{cache_key!r} is reserved")
            if self._tls_material_capacity is not None:
                public_key_cache_key = (
                    f"certificate:{backend_identity}:{subject_name}",
                    normalized_type,
                    normalized_size,
                )
                public_key_point: _TlsMaterialPoint = ("public_key", public_key_cache_key)
                if public_key_point in self._tls_point_reservations:
                    raise StateError(
                        f"TLS material point public_key:{public_key_cache_key!r} is reserved"
                    )
                spki = self._public_keys.get(public_key_cache_key)
                publish_public_key = spki is None
                if spki is None:
                    spki = self._build_public_key_spki(
                        f"certificate:{backend_identity}:{subject_name}",
                        normalized_type=normalized_type,
                        normalized_size=normalized_size,
                    )
                certificate = self._build_certificate_identity(
                    cache_key=cache_key,
                    backend_identity=backend_identity,
                    subject_name=subject_name,
                    issuer_name=issuer_name,
                    not_valid_before=not_valid_before,
                    not_valid_after=not_valid_after,
                    normalized_type=normalized_type,
                    normalized_size=normalized_size,
                    signature_algorithm=signature_algorithm,
                    normalized_sans=normalized_sans,
                    basic_constraints_ca=basic_constraints_ca,
                    host_certificate=host_certificate,
                    client_certificate=client_certificate,
                    spki=spki,
                )
                self._require_tls_material_capacity_locked(
                    ((public_key_point, spki), (point, certificate))
                )
                publications: list[_TlsMaterialPublication] = []
                if publish_public_key:
                    prepared_public_key = (
                        CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
                            self,
                            "public_key",
                            public_key_cache_key,
                            spki,
                        )
                    )
                    if type(prepared_public_key) is int:
                        raise StateError("TLS certificate public-key prerequisite changed")
                    publications.append(prepared_public_key)
                prepared_certificate = (
                    CryptographicMaterialRegistry._prepare_tls_material_publication_locked(
                        self,
                        "certificate",
                        cache_key,
                        certificate,
                    )
                )
                if type(prepared_certificate) is int:
                    raise StateError("TLS certificate point changed before publication")
                publications.append(prepared_certificate)
                CryptographicMaterialRegistry._apply_tls_material_publications_locked(
                    self,
                    tuple(publications),
                )
                return deepcopy(certificate)
            spki = self.public_key_spki(
                f"certificate:{backend_identity}:{subject_name}",
                key_type=normalized_type,
                key_size=normalized_size,
            )
            certificate = self._build_certificate_identity(
                cache_key=cache_key,
                backend_identity=backend_identity,
                subject_name=subject_name,
                issuer_name=issuer_name,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
                signature_algorithm=signature_algorithm,
                normalized_sans=normalized_sans,
                basic_constraints_ca=basic_constraints_ca,
                host_certificate=host_certificate,
                client_certificate=client_certificate,
                spki=spki,
            )
            self._publish_tls_material_locked("certificate", cache_key, certificate)
            return deepcopy(certificate)

    @staticmethod
    def _build_certificate_identity(
        *,
        cache_key: _TlsMaterialKey,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        normalized_type: CertificateKeyType,
        normalized_size: int,
        signature_algorithm: str,
        normalized_sans: tuple[str, ...],
        basic_constraints_ca: bool,
        host_certificate: bool,
        client_certificate: bool,
        spki: bytes,
    ) -> CertificateIdentityPlan:
        """Build one immutable certificate identity without registry mutation."""

        identity_seed = "|".join(str(part) for part in cache_key)
        serial_number = certificate_serial_number(identity_seed)
        fingerprint = hashlib.sha1(
            b"certificate_identity\x00" + identity_seed.encode() + b"\x00" + spki,
            usedforsecurity=False,
        ).hexdigest()
        return CertificateIdentityPlan(
            backend_identity=backend_identity,
            subject_name=subject_name,
            issuer_name=issuer_name,
            serial_number=serial_number,
            fingerprint=fingerprint,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            public_key_spki_der=spki,
            key_type=normalized_type,
            key_size=normalized_size,
            signature_algorithm=signature_algorithm,
            san_dns=normalized_sans,
            basic_constraints_ca=basic_constraints_ca,
            host_certificate=host_certificate,
            client_certificate=client_certificate,
        )

    def resolve_dkim_key(
        self,
        domain: str,
        selector: str,
        *,
        key_size: int = 2048,
    ) -> DkimKeyPlan:
        """Return one selector-stable RSA SubjectPublicKeyInfo identity."""

        normalized_domain = domain.rstrip(".").lower()
        normalized_selector = selector.rstrip(".").lower()
        if not normalized_domain or not normalized_selector:
            raise ValueError("DKIM key planning requires non-empty domain and selector identities")
        normalized_size = 3072 if key_size >= 3072 else 2048
        cache_key = (normalized_domain, normalized_selector, normalized_size)
        with self._tls_material_lock:
            cached = self._dkim_keys.get(cache_key)
        if cached is not None:
            return _detached_dkim_key_plan(cached)
        spki = self.public_key_spki(
            f"dkim:{normalized_domain}:{normalized_selector}",
            key_type="rsa",
            key_size=normalized_size,
        )
        loaded = serialization.load_der_public_key(spki)
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ValueError("DKIM registry produced a non-RSA public key")
        numbers = loaded.public_numbers()
        if loaded.key_size != normalized_size or numbers.e != 65537:
            raise ValueError("DKIM registry produced an invalid RSA size or exponent")
        plan = DkimKeyPlan(
            domain=normalized_domain,
            selector=normalized_selector,
            public_key_spki_der=spki,
            public_key_base64=base64.b64encode(spki).decode("ascii"),
            key_size=normalized_size,
            exponent=numbers.e,
        )
        estimated_bytes = _tls_auxiliary_entry_estimated_bytes(cache_key, plan)
        state_component = _dkim_key_state_component(cache_key, plan)
        detached = _detached_dkim_key_plan(plan)
        with self._tls_material_lock:
            cached = self._dkim_keys.get(cache_key)
            if cached is not None:
                return detached
            capacity = self._tls_material_capacity
            byte_capacity = CryptographicMaterialRegistry._dkim_key_byte_capacity(self)
            if capacity is not None and (
                len(self._dkim_keys) >= capacity
                or estimated_bytes > _MAX_DKIM_KEY_RETAINED_BYTES
                or byte_capacity is None
                or estimated_bytes > byte_capacity - self._dkim_key_estimated_bytes
            ):
                return detached
            next_estimated_bytes = self._dkim_key_estimated_bytes + estimated_bytes
            next_state_xor = self._dkim_key_state_xor ^ state_component
            next_high_water = max(self._dkim_key_high_water, len(self._dkim_keys) + 1)
            next_byte_high_water = max(
                self._dkim_key_byte_high_water,
                next_estimated_bytes,
            )
            self._dkim_keys[cache_key] = plan
            self._dkim_key_estimated_bytes = next_estimated_bytes
            self._dkim_key_state_xor = next_state_xor
            self._dkim_key_high_water = next_high_water
            self._dkim_key_byte_high_water = next_byte_high_water
            return detached

    def resolve_ocsp_status(
        self,
        certificate: CertificateIdentityPlan,
        profiles: list[dict[str, Any]],
    ) -> tuple[OcspCertificateStatus, str | None]:
        """Deterministically recompute the durable status assigned to one certificate.

        The result depends only on immutable certificate identity and the exact
        matching profile.  Retaining a second copy therefore adds no semantic
        value and formerly allowed profile-identity churn to grow without bound.
        """

        matching = [
            profile
            for profile in profiles
            if any(
                fnmatch.fnmatch(certificate.subject_name.removeprefix("CN="), str(pattern))
                or fnmatch.fnmatch(certificate.subject_name, str(pattern))
                for pattern in profile.get("certificate_patterns", [])
            )
        ]
        matching.sort(
            key=lambda profile: all(
                str(pattern) == "*" for pattern in profile.get("certificate_patterns", [])
            )
        )
        profile = matching[0] if matching else None
        if profile is None:
            return "good", None
        weights = profile.get("status_weights", {})
        ordered: tuple[OcspCertificateStatus, ...] = ("good", "unknown", "revoked")
        numeric_weights = tuple(max(0, int(weights.get(status, 0))) for status in ordered)
        if sum(numeric_weights) <= 0:
            return "good", None
        reasons = tuple(str(reason) for reason in profile.get("revocation_reasons", []) if reason)
        profile_identity = (
            str(profile.get("name", "")),
            tuple(str(pattern) for pattern in profile.get("certificate_patterns", [])),
            numeric_weights,
            reasons,
        )
        rng = random.Random(
            _stable_seed(
                "ocsp_certificate_status:"
                f"{profile_identity}:{certificate.fingerprint}:{certificate.serial_number}"
            )
        )
        status = rng.choices(ordered, weights=numeric_weights, k=1)[0]
        if status == "revoked":
            if not reasons:
                raise ValueError("Revoked OCSP profiles require at least one revocation reason")
            result = (status, rng.choice(reasons))
        else:
            result = (status, None)
        return result


class CryptographicMaterialPreparedCommit:
    """No-fail TLS material commit capability valid inside one claim context."""

    __slots__ = ("_active", "_committed", "_receipt", "_registry", "_token", "__weakref__")

    def __init__(
        self,
        registry: CryptographicMaterialRegistry,
        token: CryptographicMaterialPreparationToken,
    ) -> None:
        self._registry = registry
        self._token = token
        self._active = True
        self._committed = False
        self._receipt: CryptographicMaterialPreparationReceipt | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claim committed."""

        return self._committed

    @property
    def receipt(self) -> CryptographicMaterialPreparationReceipt | None:
        """Return the authenticated committed receipt, if available."""

        return self._receipt

    def __copy__(self) -> Self:
        """Reject aliases of this exact context-bound commit capability."""

        raise StateError("TLS material prepared commit capabilities cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> Self:
        """Reject deep aliases of this exact context-bound commit capability."""

        raise StateError("TLS material prepared commit capabilities cannot be copied")

    def commit_no_fail(self) -> CryptographicMaterialPreparationReceipt:
        """Publish the validated point writes as the final transaction step."""

        if not self._active:
            raise StateError("TLS material prepared commit is no longer active")
        if self._committed:
            raise StateError("TLS material preparation was already committed")
        self._receipt = self._registry._commit_claimed_tls_preparation(self._token, self)
        self._committed = True
        return self._receipt

    def commit(self) -> CryptographicMaterialPreparationReceipt:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


class CryptographicMaterialPreparation:
    """Read-through point-COW overlay for one physical TLS transport."""

    __slots__ = (
        "_cancelled",
        "_lock",
        "_owner",
        "_patches",
        "_registry",
        "_retained_bytes",
        "_sealed_token",
    )

    def __init__(
        self,
        registry: CryptographicMaterialRegistry,
        *,
        owner: object | None = None,
    ) -> None:
        self._registry = registry
        self._lock = RLock()
        self._owner = owner
        self._patches: dict[_TlsMaterialPoint, _TlsMaterialPointPatch] = {}
        self._retained_bytes = 0
        self._sealed_token: CryptographicMaterialPreparationToken | None = None
        self._cancelled = False

    def _require_open(self) -> None:
        """Reject mutation after seal or cancellation."""

        if self._cancelled:
            raise StateError("TLS material preparation was cancelled")
        if self._sealed_token is not None:
            raise StateError("TLS material preparation was already sealed")

    def __copy__(self) -> Self:
        """Reject aliases with independent seal/cancel flags over shared patches."""

        raise StateError("TLS material preparations cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> Self:
        """Reject deep aliases of this mutable preparation boundary."""

        raise StateError("TLS material preparations cannot be copied")

    def _resolve_or_stage(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        builder: Callable[[], _TlsMaterialValue],
    ) -> _TlsMaterialValue:
        """Resolve canonical state or stage one deterministic absent-point write."""

        with self._lock:
            return self._resolve_or_stage_locked(family, key, builder)

    def _resolve_or_stage_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        builder: Callable[[], _TlsMaterialValue],
    ) -> _TlsMaterialValue:
        """Resolve or stage while holding this preparation's re-entrant lock."""

        self._require_open()
        point = (family, key)
        staged = self._patches.get(point)
        if staged is not None:
            return staged.value
        value, generation, digest = self._registry._tls_material_snapshot(family, key)
        if value is not None:
            return value
        capacity = self._registry.tls_material_capacity
        if capacity is not None:
            if len(self._patches) >= capacity:
                raise CryptographicMaterialCapacityError(
                    "TLS material preparation exceeds the retained-key capacity"
                )
            prior_patch_count = len(self._patches)
            prior_retained_bytes = self._retained_bytes
            completed = False
            try:
                prepared_value = builder()
                current, current_generation, current_digest = self._registry._tls_material_snapshot(
                    family, key
                )
                if current is not None:
                    if current != prepared_value:
                        raise StateError(
                            "TLS material point changed to a conflicting canonical value"
                        )
                    return current
                if current_generation != generation or current_digest != digest:
                    raise StateError("TLS material point generation changed during preparation")
                if len(self._patches) >= capacity:
                    raise CryptographicMaterialCapacityError(
                        "TLS material preparation exceeds the retained-key capacity"
                    )
                patch = _TlsMaterialPointPatch(
                    family=family,
                    key=key,
                    expected_generation=generation,
                    expected_value_digest=digest,
                    value_digest=_tls_material_value_digest(prepared_value),
                    value=prepared_value,
                )
                retained_bytes = _tls_material_live_point_retained_bytes(point, prepared_value)
                if retained_bytes > _MAX_TLS_MATERIAL_POINT_RETAINED_BYTES:
                    raise CryptographicMaterialCapacityError(
                        "TLS material point retained-byte capacity exceeded: "
                        f"{retained_bytes} > {_MAX_TLS_MATERIAL_POINT_RETAINED_BYTES}"
                    )
                material_byte_capacity = self._registry._tls_material_byte_capacity()
                assert material_byte_capacity is not None
                if self._retained_bytes + retained_bytes > material_byte_capacity:
                    raise CryptographicMaterialCapacityError(
                        "TLS material preparation retained-byte capacity is exhausted"
                    )
                self._patches[point] = patch
                self._retained_bytes += retained_bytes
                completed = True
                return prepared_value
            finally:
                if not completed:
                    while len(self._patches) > prior_patch_count:
                        self._patches.popitem()
                    self._retained_bytes = prior_retained_bytes
        prepared_value: _TlsMaterialValue = builder()
        current, current_generation, current_digest = self._registry._tls_material_snapshot(
            family,
            key,
        )
        if current is not None:
            if current != prepared_value:
                raise StateError("TLS material point changed to a conflicting canonical value")
            return current
        if current_generation != generation or current_digest != digest:
            raise StateError("TLS material point generation changed during preparation")
        patch = _TlsMaterialPointPatch(
            family=family,
            key=key,
            expected_generation=generation,
            expected_value_digest=digest,
            value_digest=_tls_material_value_digest(prepared_value),
            value=prepared_value,
        )
        self._patches[point] = patch
        return prepared_value

    def public_key_spki(
        self,
        identity: str,
        *,
        key_type: str,
        key_size: int,
    ) -> bytes:
        """Resolve deterministic SPKI DER through this private overlay."""

        normalized_type, normalized_size = self._registry._normalize_key_profile(
            key_type,
            key_size,
        )
        key = (identity, normalized_type, normalized_size)
        value = self._resolve_or_stage(
            "public_key",
            key,
            lambda: self._registry._build_public_key_spki(
                identity,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
            ),
        )
        if not isinstance(value, bytes):
            raise StateError("TLS public-key overlay resolved an invalid value")
        return value

    def resolve_authority(
        self,
        *,
        subject_name: str,
        issuer_name: str,
        key_type: str,
        key_size: int,
    ) -> CertificateAuthorityMaterial:
        """Resolve authority material without publishing canonical registry state."""

        normalized_type, normalized_size = self._registry._normalize_key_profile(
            key_type,
            key_size,
        )
        key = (subject_name, issuer_name, normalized_type, normalized_size)

        def build() -> CertificateAuthorityMaterial:
            spki = self.public_key_spki(
                f"certificate_authority:{subject_name}",
                key_type=normalized_type,
                key_size=normalized_size,
            )
            return self._registry._build_authority_material(
                subject_name=subject_name,
                issuer_name=issuer_name,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
                spki=spki,
            )

        value = self._resolve_or_stage("authority", key, build)
        if not isinstance(value, CertificateAuthorityMaterial):
            raise StateError("TLS authority overlay resolved an invalid value")
        return value

    def resolve_certificate(
        self,
        *,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        key_type: str,
        key_size: int,
        signature_algorithm: str,
        san_dns: tuple[str, ...] = (),
        basic_constraints_ca: bool = False,
        host_certificate: bool = True,
        client_certificate: bool = False,
    ) -> CertificateIdentityPlan:
        """Resolve a certificate identity through this private overlay."""

        normalized_type, normalized_size = self._registry._normalize_key_profile(
            key_type,
            key_size,
        )
        normalized_sans = tuple(dict.fromkeys(name.rstrip(".").lower() for name in san_dns if name))
        key = (
            backend_identity,
            subject_name,
            issuer_name,
            not_valid_before,
            not_valid_after,
            normalized_type,
            normalized_size,
            signature_algorithm,
            normalized_sans,
            basic_constraints_ca,
            host_certificate,
            client_certificate,
        )

        def build() -> CertificateIdentityPlan:
            spki = self.public_key_spki(
                f"certificate:{backend_identity}:{subject_name}",
                key_type=normalized_type,
                key_size=normalized_size,
            )
            return self._registry._build_certificate_identity(
                cache_key=key,
                backend_identity=backend_identity,
                subject_name=subject_name,
                issuer_name=issuer_name,
                not_valid_before=not_valid_before,
                not_valid_after=not_valid_after,
                normalized_type=normalized_type,
                normalized_size=normalized_size,
                signature_algorithm=signature_algorithm,
                normalized_sans=normalized_sans,
                basic_constraints_ca=basic_constraints_ca,
                host_certificate=host_certificate,
                client_certificate=client_certificate,
                spki=spki,
            )

        value = self._resolve_or_stage("certificate", key, build)
        if not isinstance(value, CertificateIdentityPlan):
            raise StateError("TLS certificate overlay resolved an invalid value")
        return value

    def seal(
        self,
        *,
        owner: object | None = None,
    ) -> CryptographicMaterialPreparationToken:
        """Reserve every staged point and return one idempotent opaque token."""

        with self._lock:
            if owner is not self._owner:
                raise StateError("TLS material preparation is owned by another composite")
            if self._cancelled:
                raise StateError("TLS material preparation was cancelled")
            if self._sealed_token is not None:
                return self._sealed_token
            patches = tuple(
                self._patches[point]
                for point in sorted(self._patches, key=lambda candidate: repr(candidate))
            )
            self._sealed_token = self._registry._seal_tls_preparation(patches)
            return self._sealed_token

    def cancel(self, *, owner: object | None = None) -> bool:
        """Cancel this overlay or its unclaimed sealed reservation."""

        with self._lock:
            if owner is not self._owner:
                raise StateError("TLS material preparation is owned by another composite")
            if self._cancelled:
                return False
            if self._sealed_token is None:
                self._patches.clear()
                self._retained_bytes = 0
                self._cancelled = True
                return True
            try:
                cancelled = self._registry.cancel_tls_preparation(self._sealed_token)
            except StateError:
                self._patches.clear()
                self._retained_bytes = 0
                self._cancelled = True
                raise
            if cancelled:
                self._patches.clear()
                self._retained_bytes = 0
                self._cancelled = True
            return cancelled


_SHARED_REGISTRY = CryptographicMaterialRegistry()


def shared_cryptographic_material_registry() -> CryptographicMaterialRegistry:
    """Return the process-wide registry used by source-independent DNS helpers."""

    return _SHARED_REGISTRY
