"""Portable numeric checkpoint schema for deterministic RNG state."""

from __future__ import annotations

import random

from evidenceforge.utils.rng import _get_rng, current_generation_seed

from .errors import CheckpointCompatibilityError, CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft

_RNG_SCHEMA_VERSION = "1"
_MT_STATE_WORDS = 625


def encode_random_state(state: tuple[int, tuple[int, ...], float | None]) -> dict[str, object]:
    """Convert CPython's MT state into a validated primitive numeric document."""

    version, words, gaussian = state
    if (
        type(version) is not int
        or version != 3
        or type(words) is not tuple
        or len(words) != _MT_STATE_WORDS
        or any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in words[:-1])
        or type(words[-1]) is not int
        or not 0 <= words[-1] <= 624
        or (gaussian is not None and type(gaussian) is not float)
    ):
        raise ValueError("unsupported Python random state")
    return {
        "algorithm": "MT19937",
        "gaussian": gaussian,
        "index": words[-1],
        "state": list(words[:-1]),
        "version": version,
    }


def decode_random_state(document: object) -> tuple[int, tuple[int, ...], float | None]:
    """Validate and reconstruct one Python ``random.Random`` state tuple."""

    if type(document) is not dict or set(document) != {
        "algorithm",
        "gaussian",
        "index",
        "state",
        "version",
    }:
        raise CheckpointCorruptionError("checkpoint RNG state has an invalid schema")
    words = document["state"]
    index = document["index"]
    gaussian = document["gaussian"]
    version = document["version"]
    if (
        document["algorithm"] != "MT19937"
        or type(version) is not int
        or version != 3
        or type(words) is not list
        or len(words) != _MT_STATE_WORDS - 1
        or any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in words)
        or type(index) is not int
        or not 0 <= index <= 624
        or (gaussian is not None and type(gaussian) is not float)
    ):
        raise CheckpointCorruptionError("checkpoint RNG state is unsupported or corrupt")
    return version, (*words, index), gaussian


class GenerationRngParticipant:
    """Persist the active generation thread's deterministic RNG stream."""

    checkpoint_owner = "generation-rng"
    checkpoint_restore_priority = 60
    checkpoint_schema_version = _RNG_SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("mt19937_state", "bounded-live-head"),
        OwnerStateField("seed_namespace", "deterministically-rebuilt"),
    )

    def __init__(self) -> None:
        self._prepared_sequence: int | None = None
        self._prepared_seal: ParticipantSeal | None = None

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture the current thread stream in its numeric schema."""

        if self._prepared_sequence is not None:
            if self._prepared_sequence != sequence or self._prepared_seal is None:
                raise RuntimeError("generation RNG participant already prepared another sequence")
            return self._prepared_seal
        seal = ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(
                    {
                        "rng": encode_random_state(_get_rng().getstate()),
                        "schema_version": self.checkpoint_schema_version,
                        "seed": current_generation_seed(),
                    }
                ),
            )
        )
        self._prepared_sequence = sequence
        self._prepared_seal = seal
        return seal

    def checkpoint_committed(self, sequence: int) -> None:
        """Release the immutable prepared copy after publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("generation RNG commit does not match its prepared sequence")
        self._prepared_sequence = None
        self._prepared_seal = None

    def checkpoint_aborted(self, sequence: int) -> None:
        """Release the immutable prepared copy after failed publication."""

        if self._prepared_sequence != sequence:
            raise RuntimeError("generation RNG abort does not match its prepared sequence")
        self._prepared_sequence = None
        self._prepared_seal = None

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore the stream only inside its original public-seed namespace."""

        if segments:
            raise CheckpointCorruptionError("generation RNG participant cannot own segments")
        document = loads(head)
        if (
            type(document) is not dict
            or document.get("schema_version") != self.checkpoint_schema_version
            or type(document.get("seed")) is not int
        ):
            raise CheckpointCorruptionError("generation RNG checkpoint head is invalid")
        if document["seed"] != current_generation_seed():
            raise CheckpointCompatibilityError(
                "checkpoint generation seed does not match the active seed namespace"
            )
        state = decode_random_state(document.get("rng"))
        probe = random.Random()
        try:
            probe.setstate(state)
        except (TypeError, ValueError) as error:
            raise CheckpointCorruptionError("checkpoint RNG state cannot be restored") from error
        _get_rng().setstate(state)
        self._prepared_sequence = None
        self._prepared_seal = None
