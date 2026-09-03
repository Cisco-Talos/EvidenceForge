"""Incremental semantic checkpoint participant for cryptographic material."""

from __future__ import annotations

from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialRegistry,
    _tls_material_live_point_retained_bytes,
    _tls_material_tombstone_retained_bytes,
    _validate_tls_material_key,
    _validate_tls_material_value_tree,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    CRYPTOGRAPHIC_MATERIAL_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft, SegmentDraft

_SCHEMA_VERSION = "1"
_FAMILIES = frozenset({"public_key", "authority", "certificate"})


def _initial_records(
    registry: CryptographicMaterialRegistry,
) -> list[tuple[str, object, object]]:
    records: list[tuple[str, object, object]] = []
    for point, generation in registry._tls_point_generations.items():
        records.append(("point", point, (generation, True)))
    for point, generation in registry._tls_point_tombstones.items():
        records.append(("point", point, (generation, False)))
    records.extend(("dkim", key, None) for key in registry._dkim_keys)
    return records


def _build_point_value(
    registry: CryptographicMaterialRegistry,
    family: str,
    key: tuple[object, ...],
) -> object:
    try:
        _validate_tls_material_key(key)
        if family == "public_key":
            identity, key_type, key_size = key
            value = registry._build_public_key_spki(
                identity,
                normalized_type=key_type,
                normalized_size=key_size,
            )
        elif family == "authority":
            subject_name, issuer_name, key_type, key_size = key
            spki = registry._build_public_key_spki(
                f"certificate_authority:{subject_name}",
                normalized_type=key_type,
                normalized_size=key_size,
            )
            value = registry._build_authority_material(
                subject_name=subject_name,
                issuer_name=issuer_name,
                normalized_type=key_type,
                normalized_size=key_size,
                spki=spki,
            )
        elif family == "certificate":
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
            value = registry._build_certificate_identity(
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
        else:
            raise ValueError("unsupported cryptographic material family")
        _validate_tls_material_value_tree(value)
        return value
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "cryptographic checkpoint material point is invalid"
        ) from error


def _remove_point(
    registry: CryptographicMaterialRegistry,
    point: tuple[str, tuple[object, ...]],
) -> None:
    family, key = point
    prior_value = registry._tls_material_value_locked(family, key)  # type: ignore[arg-type]
    prior_generation = registry._tls_point_generation_locked(point)  # type: ignore[arg-type]
    registry._tls_canonical_state_xor ^= registry._tls_point_state_component_locked(
        point,  # type: ignore[arg-type]
        prior_value,
        prior_generation,
    )
    if family == "public_key":
        registry._public_keys.pop(key, None)  # type: ignore[arg-type]
    elif family == "authority":
        registry._authorities.pop(key, None)  # type: ignore[arg-type]
    else:
        registry._certificates.pop(key, None)
    registry._tls_point_generations.pop(point, None)  # type: ignore[arg-type]
    registry._tls_point_tombstones.pop(point, None)  # type: ignore[arg-type]
    retained_bytes = registry._tls_point_retained_bytes.pop(point, 0)  # type: ignore[arg-type]
    registry._tls_retained_material_bytes -= retained_bytes


def _apply_point_record(
    registry: CryptographicMaterialRegistry,
    encoded_point: object,
    encoded_state: object,
) -> None:
    point = decode_state_value(encoded_point)
    state = decode_state_value(encoded_state)
    if (
        type(point) is not tuple
        or len(point) != 2
        or point[0] not in _FAMILIES
        or type(point[1]) is not tuple
        or type(state) is not tuple
        or len(state) != 2
        or type(state[0]) is not int
        or state[0] <= 0
        or type(state[1]) is not bool
    ):
        raise CheckpointCorruptionError("cryptographic checkpoint point record is invalid")
    family = point[0]
    key = point[1]
    prior_generation = registry._tls_point_generation_locked(point)  # type: ignore[arg-type]
    if state[0] <= prior_generation:
        raise CheckpointCorruptionError("cryptographic checkpoint point generation regressed")
    _remove_point(registry, point)  # type: ignore[arg-type]
    generation, present = state
    value = _build_point_value(registry, family, key) if present else None
    if present:
        if family == "public_key":
            registry._public_keys[key] = value  # type: ignore[assignment,index]
        elif family == "authority":
            registry._authorities[key] = value  # type: ignore[assignment,index]
        else:
            registry._certificates[key] = value  # type: ignore[assignment]
        registry._tls_point_generations[point] = generation  # type: ignore[index]
    else:
        _validate_tls_material_key(key)
        registry._tls_point_tombstones[point] = generation  # type: ignore[index]
    registry._tls_canonical_state_xor ^= registry._tls_point_state_component_locked(
        point,  # type: ignore[arg-type]
        value,  # type: ignore[arg-type]
        generation,
    )
    if registry._tls_material_capacity is not None:
        retained_bytes = (
            _tls_material_live_point_retained_bytes(point, value)  # type: ignore[arg-type]
            if present
            else _tls_material_tombstone_retained_bytes(point)  # type: ignore[arg-type]
        )
        registry._tls_point_retained_bytes[point] = retained_bytes  # type: ignore[index]
        registry._tls_retained_material_bytes += retained_bytes
        registry._tls_material_generation_high_water = max(
            registry._tls_material_generation_high_water,
            generation,
        )


def _apply_dkim_record(registry: CryptographicMaterialRegistry, encoded_key: object) -> None:
    key = decode_state_value(encoded_key)
    if (
        type(key) is not tuple
        or len(key) != 3
        or any(type(item) is not str for item in key[:2])
        or not all(key[:2])
        or key[2] not in {2048, 3072}
    ):
        raise CheckpointCorruptionError("cryptographic checkpoint DKIM record is invalid")
    if key in registry._dkim_keys:
        raise CheckpointCorruptionError("cryptographic checkpoint DKIM record is duplicated")
    plan = registry.resolve_dkim_key(key[0], key[1], key_size=key[2])
    retained = registry._dkim_keys.get(key)
    if retained != plan:
        raise CheckpointCorruptionError("cryptographic checkpoint DKIM record exceeds capacity")


def _rebuild_capacity_high_water(registry: CryptographicMaterialRegistry) -> None:
    if registry._tls_material_capacity is None:
        return
    registry._tls_material_high_water_points = registry._tls_live_material_points_locked()
    registry._tls_material_high_water_bytes = registry._tls_retained_material_bytes


class CryptographicMaterialParticipant:
    """Persist immutable material identities as append-only delta segments."""

    checkpoint_owner = "cryptographic-material"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = CRYPTOGRAPHIC_MATERIAL_CHECKPOINT_FIELDS

    def __init__(self, registry: CryptographicMaterialRegistry) -> None:
        self.registry = registry
        self._pending_records: list[tuple[str, object, object]] = []
        self._prepared_sequence: int | None = None
        self._prepared_record_count = 0
        self._prepared_seal: ParticipantSeal | None = None
        with registry._tls_material_lock:
            if registry._checkpoint_incremental_recorder is not None:
                raise RuntimeError("cryptographic material already has a checkpoint owner")
            self._pending_records.extend(_initial_records(registry))
            registry._checkpoint_incremental_recorder = self._record_incremental_value

    def _record_incremental_value(self, field_name: str, key: object, value: object) -> None:
        if field_name not in {"point", "dkim"}:
            raise RuntimeError(f"cryptographic material offered unknown delta {field_name!r}")
        self._pending_records.append((field_name, key, value))

    @staticmethod
    def _seal_records(records: list[tuple[str, object, object]]) -> tuple[SegmentDraft, ...]:
        point_records: dict[object, object] = {}
        dkim_records: set[object] = set()
        try:
            for kind, key, value in records:
                if kind == "point":
                    point_records[key] = value
                elif kind == "dkim":
                    dkim_records.add(key)
                else:
                    raise RuntimeError("cryptographic checkpoint delta kind is invalid")
        except TypeError as error:
            raise RuntimeError("cryptographic checkpoint delta key is not hashable") from error
        if not point_records and not dkim_records:
            return ()
        points = [
            [encode_state_value(key), encode_state_value(value)]
            for key, value in point_records.items()
        ]
        points.sort(key=dumps)
        dkim = [encode_state_value(key) for key in dkim_records]
        dkim.sort(key=dumps)
        payload = dumps(
            {
                "dkim": dkim,
                "points": points,
                "schema_version": _SCHEMA_VERSION,
            }
        )
        return (
            SegmentDraft(
                owner=CryptographicMaterialParticipant.checkpoint_owner,
                schema_version=_SCHEMA_VERSION,
                payload=payload,
                record_count=len(points) + len(dkim),
            ),
        )

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Seal only material identities published since the prior recovery point."""

        if self._prepared_sequence is not None:
            if self._prepared_sequence != sequence or self._prepared_seal is None:
                raise RuntimeError("cryptographic participant already prepared another sequence")
            return self._prepared_seal
        assert_complete_owner_inventory(
            self.registry,
            self.checkpoint_state_fields,
            owner_name="CryptographicMaterialRegistry",
        )
        with self.registry._tls_material_lock:
            self.registry._reap_abandoned_tls_preparations_locked()
            assert_transient_owner_state_empty(
                self.registry,
                self.checkpoint_state_fields,
                owner_name="CryptographicMaterialRegistry",
            )
            self._prepared_record_count = len(self._pending_records)
            segments = self._seal_records(self._pending_records[: self._prepared_record_count])
            head = {
                "capacity": self.registry._tls_material_capacity,
                "next_preparation_id": self.registry._next_tls_preparation_id,
                "schema_version": self.checkpoint_schema_version,
                "state_digest": self.registry.state_digest(),
            }
            seal = ParticipantSeal(
                head=HeadDraft(
                    owner=self.checkpoint_owner,
                    schema_version=self.checkpoint_schema_version,
                    payload=dumps(head),
                ),
                segments=segments,
            )
        self._prepared_sequence = sequence
        self._prepared_seal = seal
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the material delta journal after durable publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("cryptographic checkpoint commit does not match its preparation")
        del self._pending_records[: self._prepared_record_count]
        self._prepared_sequence = None
        self._prepared_record_count = 0
        self._prepared_seal = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Retain material mutations after failed publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("cryptographic checkpoint abort does not match its preparation")
        self._prepared_sequence = None
        self._prepared_record_count = 0
        self._prepared_seal = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Rebuild deterministic values from cumulative immutable identity segments."""

        document = loads(head)
        if (
            type(document) is not dict
            or set(document)
            != {"capacity", "next_preparation_id", "schema_version", "state_digest"}
            or document.get("schema_version") != self.checkpoint_schema_version
            or document.get("capacity") != self.registry._tls_material_capacity
            or type(document.get("next_preparation_id")) is not int
            or document["next_preparation_id"] < 0
            or type(document.get("state_digest")) is not str
        ):
            raise CheckpointCorruptionError("cryptographic checkpoint head is invalid")
        with self.registry._tls_material_lock:
            if (
                self.registry._public_keys
                or self.registry._authorities
                or self.registry._certificates
                or self.registry._dkim_keys
            ):
                raise ValueError("cryptographic checkpoint hydration requires a fresh registry")
            self.registry._checkpoint_incremental_recorder = None
            for payload in segments:
                segment = loads(payload)
                if (
                    type(segment) is not dict
                    or set(segment) != {"dkim", "points", "schema_version"}
                    or segment.get("schema_version") != self.checkpoint_schema_version
                    or type(segment.get("points")) is not list
                    or type(segment.get("dkim")) is not list
                ):
                    raise CheckpointCorruptionError("cryptographic checkpoint segment is invalid")
                for row in segment["points"]:
                    if type(row) is not list or len(row) != 2:
                        raise CheckpointCorruptionError(
                            "cryptographic checkpoint point row is invalid"
                        )
                    _apply_point_record(self.registry, row[0], row[1])
                for encoded_key in segment["dkim"]:
                    _apply_dkim_record(self.registry, encoded_key)
            self.registry._next_tls_preparation_id = document["next_preparation_id"]
            _rebuild_capacity_high_water(self.registry)
            if self.registry.state_digest() != document["state_digest"]:
                raise CheckpointCorruptionError("cryptographic checkpoint state digest changed")
            self._pending_records = []
            self._prepared_sequence = None
            self._prepared_record_count = 0
            self._prepared_seal = None
            self.registry._checkpoint_incremental_recorder = self._record_incremental_value


__all__ = ["CryptographicMaterialParticipant"]
