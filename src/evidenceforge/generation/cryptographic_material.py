# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic standards-valid public cryptographic material registry."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import random
import re
import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, fields, replace
from threading import RLock
from typing import Any, Literal

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
    trusted_token: CryptographicMaterialPreparationToken
    points: tuple[_TlsMaterialPoint, ...]


@dataclass(frozen=True, slots=True)
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


def _tls_material_value_digest(value: _TlsMaterialValue) -> str:
    """Return a stable collision-resistant digest for one immutable value."""

    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


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
    if not hmac.compare_digest(actual_digest, patch.value_digest):
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

    canonical = repr(
        (
            "cryptographic-material-tls-preparation-v1",
            token.preparation_id,
            token.overlay_digest,
            token.public_key_writes,
            token.authority_writes,
            token.certificate_writes,
            token._registry_token,
            token._patches,
        )
    ).encode("utf-8")
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


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

    canonical = repr(
        (
            "cryptographic-material-tls-preparation-receipt-v1",
            receipt.preparation_id,
            receipt.publication_token,
            receipt.overlay_digest,
            receipt.committed_digest,
            receipt.public_key_writes,
            receipt.authority_writes,
            receipt.certificate_writes,
            receipt._registry_token,
        )
    ).encode("utf-8")
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


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

    def __init__(self) -> None:
        self._public_keys: dict[tuple[str, CertificateKeyType, int], bytes] = {}
        self._authorities: dict[
            tuple[str, str, CertificateKeyType, int], CertificateAuthorityMaterial
        ] = {}
        self._certificates: dict[tuple[Any, ...], CertificateIdentityPlan] = {}
        self._dkim_keys: dict[tuple[str, str, int], DkimKeyPlan] = {}
        self._ocsp_statuses: dict[
            tuple[str, str, tuple[Any, ...]], tuple[OcspCertificateStatus, str | None]
        ] = {}
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
        self._tls_prepared_tokens: dict[int, CryptographicMaterialPreparationToken] = {}
        self._tls_prepared_capabilities: dict[int, _CryptographicMaterialPreparationCapability] = {}
        self._tls_claimed_preparations: set[int] = set()
        self._tls_canonical_state_xor = 0
        self._tls_prepared_state_xor = 0
        self._tls_reservation_state_xor = 0
        self._tls_claimed_state_xor = 0

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

    def _publish_tls_material_locked(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        value: _TlsMaterialValue,
        *,
        reservation_id: int | None = None,
    ) -> int:
        """Publish one absent point and advance its exact generation."""

        point = (family, key)
        reserved_by = self._tls_point_reservations.get(point)
        if reserved_by is not None and reserved_by != reservation_id:
            raise StateError(f"TLS material point {family}:{key!r} has a prepared mutation")
        existing = self._tls_material_value_locked(family, key)
        if existing is not None:
            if existing != value:
                raise StateError(f"TLS material point {family}:{key!r} changed unexpectedly")
            return self._tls_point_generation_locked(point)
        prior_generation = self._tls_point_generation_locked(point)
        prior_component = self._tls_point_state_component_locked(
            point,
            None,
            prior_generation,
        )
        generation = prior_generation + 1
        if family == "public_key":
            if not isinstance(value, bytes):
                raise StateError("TLS public-key point requires bytes")
            self._public_keys[key] = value  # type: ignore[index]
        elif family == "authority":
            if not isinstance(value, CertificateAuthorityMaterial):
                raise StateError("TLS authority point requires authority material")
            self._authorities[key] = value  # type: ignore[index]
        else:
            if not isinstance(value, CertificateIdentityPlan):
                raise StateError("TLS certificate point requires a certificate identity")
            self._certificates[key] = value
        self._tls_point_generations[point] = generation
        self._tls_point_tombstones.pop(point, None)
        self._tls_canonical_state_xor ^= prior_component
        self._tls_canonical_state_xor ^= self._tls_point_state_component_locked(
            point,
            value,
            generation,
        )
        return generation

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
        prior_component = self._tls_point_state_component_locked(
            point,
            value,
            prior_generation,
        )
        if family == "public_key":
            self._public_keys.pop(key)  # type: ignore[arg-type]
        elif family == "authority":
            self._authorities.pop(key)  # type: ignore[arg-type]
        else:
            self._certificates.pop(key)
        generation = prior_generation + 1
        self._tls_point_generations.pop(point, None)
        self._tls_point_tombstones[point] = generation
        self._tls_canonical_state_xor ^= prior_component
        self._tls_canonical_state_xor ^= self._tls_point_state_component_locked(
            point,
            None,
            generation,
        )
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
        """Return the constant-time TLS material/preparation census."""

        return self.tls_preparation_census()

    def state_digest(self) -> str:
        """Return an O(1) digest of canonical and transient TLS registry state."""

        with self._tls_material_lock:
            canonical = (
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
        if receipt._registry_token != id(self):
            return False
        try:
            expected = _validated_tls_material_receipt_integrity_token(
                self._tls_preparation_secret,
                receipt,
            )
        except StateError:
            return False
        if not hmac.compare_digest(receipt._integrity_token, expected):
            return False
        if token is None:
            return True
        if type(token) is not CryptographicMaterialPreparationToken:
            return False
        try:
            expected_token = _validated_tls_material_preparation_integrity_token(
                self._tls_preparation_secret,
                token,
            )
        except StateError:
            return False
        return (
            hmac.compare_digest(token._integrity_token, expected_token)
            and hmac.compare_digest(receipt.publication_token, token.publication_token)
            and receipt.preparation_id == token.preparation_id
            and hmac.compare_digest(receipt.overlay_digest, token.overlay_digest)
            and receipt.public_key_writes == token.public_key_writes
            and receipt.authority_writes == token.authority_writes
            and receipt.certificate_writes == token.certificate_writes
        )

    def _active_tls_preparation_locked(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> _CryptographicMaterialPreparationCapability:
        """Return the registry-owned capability for an intact active token."""

        if type(token) is not CryptographicMaterialPreparationToken:
            raise StateError("TLS material preparation token has an invalid type")
        capability = self._tls_prepared_capabilities.get(id(token))
        if capability is None:
            if token._registry_token != id(self):
                raise StateError("TLS material preparation token belongs to another registry")
            raise StateError("TLS material preparation token is stale or already consumed")
        active = self._tls_prepared_tokens.get(capability.preparation_id)
        if active is not token:
            raise StateError("TLS material preparation token is stale or already consumed")
        try:
            expected = _validated_tls_material_preparation_integrity_token(
                self._tls_preparation_secret,
                token,
            )
        except StateError as exc:
            raise StateError("TLS material preparation token integrity validation failed") from exc
        if not hmac.compare_digest(token._integrity_token, capability.integrity_token) or not (
            hmac.compare_digest(expected, capability.integrity_token)
        ):
            raise StateError("TLS material preparation token integrity validation failed")
        return capability

    def _release_tls_preparation_locked(
        self,
        capability: _CryptographicMaterialPreparationCapability,
    ) -> None:
        """Release reservations from the registry-owned immutable locator."""

        active = self._tls_prepared_tokens.pop(capability.preparation_id, None)
        retained = self._tls_prepared_capabilities.pop(capability.token_id, None)
        if active is None or retained is not capability:
            return
        self._tls_prepared_state_xor ^= _tls_material_state_component(
            "tls-prepared-capability-v1",
            capability,
        )
        if capability.preparation_id in self._tls_claimed_preparations:
            self._tls_claimed_state_xor ^= _tls_material_state_component(
                "tls-claimed-preparation-v1",
                capability.preparation_id,
            )
            self._tls_claimed_preparations.discard(capability.preparation_id)
        for point in capability.points:
            if self._tls_point_reservations.get(point) == capability.preparation_id:
                self._tls_point_reservations.pop(point)
                self._tls_reservation_state_xor ^= _tls_material_state_component(
                    "tls-point-reservation-v1",
                    (point, capability.preparation_id),
                )
        if not self._tls_prepared_tokens:
            self._tls_prepared_tokens.clear()
            self._tls_prepared_capabilities.clear()
            self._tls_claimed_preparations.clear()
            self._tls_point_reservations.clear()
            self._tls_prepared_state_xor = 0
            self._tls_reservation_state_xor = 0
            self._tls_claimed_state_xor = 0

    def _validate_tls_preparation_locked(
        self,
        capability: _CryptographicMaterialPreparationCapability,
    ) -> None:
        """Revalidate exact point generations and immutable preimages."""

        for patch in capability.trusted_token._patches:
            point = patch.point
            if self._tls_point_reservations.get(point) != capability.preparation_id:
                raise StateError("TLS material preparation lost an exact point reservation")
            value = self._tls_material_value_locked(patch.family, patch.key)
            digest = "" if value is None else _tls_material_value_digest(value)
            if self._tls_point_generation_locked(
                point
            ) != patch.expected_generation or not hmac.compare_digest(
                digest, patch.expected_value_digest
            ):
                raise StateError("TLS material preparation point generation changed")

    def _seal_tls_preparation(
        self,
        patches: tuple[_TlsMaterialPointPatch, ...],
    ) -> CryptographicMaterialPreparationToken:
        """Reserve all staged points and issue one authenticated token."""

        trusted_patches = _canonical_tls_material_patches(self, patches)
        with self._tls_material_lock:
            retained: list[_TlsMaterialPointPatch] = []
            for patch in trusted_patches:
                point = patch.point
                value = self._tls_material_value_locked(patch.family, patch.key)
                generation = self._tls_point_generation_locked(point)
                digest = "" if value is None else _tls_material_value_digest(value)
                if generation != patch.expected_generation or not hmac.compare_digest(
                    digest,
                    patch.expected_value_digest,
                ):
                    raise StateError("TLS material preparation point changed before seal")
                if value is not None:
                    if not hmac.compare_digest(digest, patch.value_digest):
                        raise StateError("TLS material preparation conflicts with canonical value")
                    continue
                if point in self._tls_point_reservations:
                    raise StateError(f"TLS material point {patch.family}:{patch.key!r} is reserved")
                retained.append(patch)

            final_patches = tuple(retained)
            public_patches = deepcopy(final_patches)
            for patch in public_patches:
                _validate_tls_material_patch(patch)
            preparation_id = self._next_tls_preparation_id
            self._next_tls_preparation_id += 1
            overlay_digest = _tls_material_overlay_digest(final_patches)
            token = CryptographicMaterialPreparationToken(
                preparation_id=preparation_id,
                overlay_digest=overlay_digest,
                public_key_writes=sum(patch.family == "public_key" for patch in final_patches),
                authority_writes=sum(patch.family == "authority" for patch in final_patches),
                certificate_writes=sum(patch.family == "certificate" for patch in final_patches),
                _registry_token=id(self),
                _patches=public_patches,
            )
            token = replace(
                token,
                _integrity_token=_tls_material_preparation_integrity_token(
                    self._tls_preparation_secret,
                    token,
                ),
            )
            trusted_token = replace(token, _patches=final_patches)
            capability = _CryptographicMaterialPreparationCapability(
                token_id=id(token),
                preparation_id=preparation_id,
                integrity_token=token.publication_token,
                trusted_token=trusted_token,
                points=tuple(patch.point for patch in final_patches),
            )
            self._tls_prepared_tokens[preparation_id] = token
            self._tls_prepared_capabilities[id(token)] = capability
            self._tls_prepared_state_xor ^= _tls_material_state_component(
                "tls-prepared-capability-v1",
                capability,
            )
            for point in capability.points:
                self._tls_point_reservations[point] = preparation_id
                self._tls_reservation_state_xor ^= _tls_material_state_component(
                    "tls-point-reservation-v1",
                    (point, preparation_id),
                )
            return token

    def cancel_tls_preparation(self, token: CryptographicMaterialPreparationToken) -> bool:
        """Cancel one unclaimed overlay without publishing canonical material."""

        with self._tls_material_lock:
            capability = self._tls_prepared_capabilities.get(id(token))
            if capability is None:
                return False
            if capability.preparation_id in self._tls_claimed_preparations:
                return False
            try:
                capability = self._active_tls_preparation_locked(token)
            except StateError:
                self._release_tls_preparation_locked(capability)
                raise
            self._release_tls_preparation_locked(capability)
            return True

    def _claim_tls_preparation(self, token: CryptographicMaterialPreparationToken) -> None:
        """Claim and validate one overlay in a short registry-only section."""

        with self._tls_material_lock:
            capability = self._tls_prepared_capabilities.get(id(token))
            if (
                capability is not None
                and capability.preparation_id in self._tls_claimed_preparations
            ):
                raise StateError("TLS material preparation token is already claimed")
            try:
                capability = self._active_tls_preparation_locked(token)
            except StateError:
                if capability is not None:
                    self._release_tls_preparation_locked(capability)
                raise
            self._validate_tls_preparation_locked(capability)
            self._active_tls_preparation_locked(token)
            self._tls_claimed_preparations.add(capability.preparation_id)
            self._tls_claimed_state_xor ^= _tls_material_state_component(
                "tls-claimed-preparation-v1",
                capability.preparation_id,
            )

    def _cancel_claimed_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> None:
        """Release an uncommitted claim after its external composite aborts."""

        with self._tls_material_lock:
            capability = self._tls_prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                self._active_tls_preparation_locked(token)
            except StateError:
                self._release_tls_preparation_locked(capability)
                return
            if capability.preparation_id not in self._tls_claimed_preparations:
                raise StateError("TLS material preparation token is not claimed")
            self._release_tls_preparation_locked(capability)

    @contextmanager
    def prepared_tls_material(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> Iterator[CryptographicMaterialPreparedCommit]:
        """Claim one overlay without retaining the registry lock externally."""

        self._claim_tls_preparation(token)
        transaction = CryptographicMaterialPreparedCommit(self, token)
        try:
            yield transaction
        finally:
            if not transaction.committed:
                self._cancel_claimed_tls_preparation(token)
            transaction._close()

    def _commit_claimed_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
    ) -> CryptographicMaterialPreparationReceipt:
        """Apply already-validated point writes and sign their exact versions."""

        with self._tls_material_lock:
            capability = self._tls_prepared_capabilities.get(id(token))
            if (
                capability is None
                or self._tls_prepared_tokens.get(capability.preparation_id) is not token
            ):
                raise StateError("TLS material preparation token is stale or already consumed")
            if capability.preparation_id not in self._tls_claimed_preparations:
                raise StateError("TLS material preparation token is not claimed")
            committed_points: list[tuple[_TlsMaterialFamily, _TlsMaterialKey, int, str]] = []
            for patch in capability.trusted_token._patches:
                generation = self._publish_tls_material_locked(
                    patch.family,
                    patch.key,
                    patch.value,
                    reservation_id=capability.preparation_id,
                )
                committed_points.append((patch.family, patch.key, generation, patch.value_digest))
            committed_digest = hashlib.sha256(
                repr(tuple(committed_points)).encode("utf-8")
            ).hexdigest()
            trusted_token = capability.trusted_token
            receipt = CryptographicMaterialPreparationReceipt(
                preparation_id=capability.preparation_id,
                publication_token=capability.integrity_token,
                overlay_digest=trusted_token.overlay_digest,
                committed_digest=committed_digest,
                public_key_writes=trusted_token.public_key_writes,
                authority_writes=trusted_token.authority_writes,
                certificate_writes=trusted_token.certificate_writes,
                _registry_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_tls_material_receipt_integrity_token(
                    self._tls_preparation_secret,
                    receipt,
                ),
            )
            self._release_tls_preparation_locked(capability)
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
            cached = self._authorities.get(cache_key)
            if cached is not None:
                return deepcopy(cached)
            point: _TlsMaterialPoint = ("authority", cache_key)
            if point in self._tls_point_reservations:
                raise StateError(f"TLS material point authority:{cache_key!r} is reserved")
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
            cached = self._certificates.get(cache_key)
            if cached is not None:
                return deepcopy(cached)
            point: _TlsMaterialPoint = ("certificate", cache_key)
            if point in self._tls_point_reservations:
                raise StateError(f"TLS material point certificate:{cache_key!r} is reserved")
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
        normalized_size = 3072 if key_size >= 3072 else 2048
        cache_key = (normalized_domain, normalized_selector, normalized_size)
        cached = self._dkim_keys.get(cache_key)
        if cached is not None:
            return cached
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
        self._dkim_keys[cache_key] = plan
        return plan

    def resolve_ocsp_status(
        self,
        certificate: CertificateIdentityPlan,
        profiles: list[dict[str, Any]],
    ) -> tuple[OcspCertificateStatus, str | None]:
        """Return the durable status identity assigned to one certificate."""

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
        cache_key = (certificate.fingerprint, certificate.serial_number, profile_identity)
        cached = self._ocsp_statuses.get(cache_key)
        if cached is not None:
            return cached
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
        self._ocsp_statuses[cache_key] = result
        return result


class CryptographicMaterialPreparedCommit:
    """No-fail TLS material commit capability valid inside one claim context."""

    __slots__ = ("_active", "_committed", "_receipt", "_registry", "_token")

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

    def commit_no_fail(self) -> CryptographicMaterialPreparationReceipt:
        """Publish the validated point writes as the final transaction step."""

        if not self._active:
            raise StateError("TLS material prepared commit is no longer active")
        if self._committed:
            raise StateError("TLS material preparation was already committed")
        self._receipt = self._registry._commit_claimed_tls_preparation(self._token)
        self._committed = True
        return self._receipt

    def commit(self) -> CryptographicMaterialPreparationReceipt:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


class CryptographicMaterialPreparation:
    """Read-through point-COW overlay for one physical TLS transport."""

    __slots__ = ("_cancelled", "_owner", "_patches", "_registry", "_sealed_token")

    def __init__(
        self,
        registry: CryptographicMaterialRegistry,
        *,
        owner: object | None = None,
    ) -> None:
        self._registry = registry
        self._owner = owner
        self._patches: dict[_TlsMaterialPoint, _TlsMaterialPointPatch] = {}
        self._sealed_token: CryptographicMaterialPreparationToken | None = None
        self._cancelled = False

    def _require_open(self) -> None:
        """Reject mutation after seal or cancellation."""

        if self._cancelled:
            raise StateError("TLS material preparation was cancelled")
        if self._sealed_token is not None:
            raise StateError("TLS material preparation was already sealed")

    def _resolve_or_stage(
        self,
        family: _TlsMaterialFamily,
        key: _TlsMaterialKey,
        builder: Callable[[], _TlsMaterialValue],
    ) -> _TlsMaterialValue:
        """Resolve canonical state or stage one deterministic absent-point write."""

        self._require_open()
        point = (family, key)
        staged = self._patches.get(point)
        if staged is not None:
            return staged.value
        value, generation, digest = self._registry._tls_material_snapshot(family, key)
        if value is not None:
            return value
        prepared_value: _TlsMaterialValue = builder()
        current, current_generation, current_digest = self._registry._tls_material_snapshot(
            family,
            key,
        )
        if current is not None:
            if current != prepared_value:
                raise StateError("TLS material point changed to a conflicting canonical value")
            return current
        if current_generation != generation or not hmac.compare_digest(current_digest, digest):
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

        if owner is not self._owner:
            raise StateError("TLS material preparation is owned by another composite")
        if self._cancelled:
            return False
        if self._sealed_token is None:
            self._patches.clear()
            self._cancelled = True
            return True
        try:
            cancelled = self._registry.cancel_tls_preparation(self._sealed_token)
        except StateError:
            self._patches.clear()
            self._cancelled = True
            raise
        if cancelled:
            self._patches.clear()
            self._cancelled = True
        return cancelled


_SHARED_REGISTRY = CryptographicMaterialRegistry()


def shared_cryptographic_material_registry() -> CryptographicMaterialRegistry:
    """Return the process-wide registry used by source-independent DNS helpers."""

    return _SHARED_REGISTRY
