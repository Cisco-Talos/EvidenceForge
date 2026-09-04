"""Bounded checkpoint head for generation-wide Bash command selection memory."""

from __future__ import annotations

from collections import Counter, deque

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.activity import bash_commands

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _BashCommandMemoryHead(BaseModel):
    """Validated primitive envelope for bounded command-selection history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    recency: list[list[object]] = Field(default_factory=list)
    user_recency: list[list[object]] = Field(default_factory=list)
    global_counts: list[list[object]] = Field(default_factory=list)
    global_low_repeat_counts: list[list[object]] = Field(default_factory=list)


def _capture_recency(
    values: dict[tuple[str, str], deque[str]],
) -> list[list[object]]:
    return [[list(key), list(commands)] for key, commands in sorted(values.items())]


def _capture_user_recency(values: dict[str, deque[str]]) -> list[list[object]]:
    return [[key, list(commands)] for key, commands in sorted(values.items())]


def _capture_counts(values: Counter[str]) -> list[list[object]]:
    return [[key, count] for key, count in sorted(values.items())]


def _decode_commands(value: object, *, limit: int) -> deque[str]:
    if (
        type(value) is not list
        or len(value) > limit
        or any(type(command) is not str for command in value)
    ):
        raise CheckpointCorruptionError("Bash command checkpoint recency row is invalid")
    return deque(value, maxlen=limit)


def _decode_recency(value: object) -> dict[tuple[str, str], deque[str]]:
    if type(value) is not list:
        raise CheckpointCorruptionError("Bash command checkpoint recency table is invalid")
    restored: dict[tuple[str, str], deque[str]] = {}
    for row in value:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not list
            or len(row[0]) != 2
            or any(type(part) is not str for part in row[0])
        ):
            raise CheckpointCorruptionError("Bash command checkpoint recency row is invalid")
        key = (row[0][0], row[0][1])
        if key in restored:
            raise CheckpointCorruptionError("Bash command checkpoint recency key is duplicated")
        restored[key] = _decode_commands(row[1], limit=bash_commands._COMMAND_RECENCY_LIMIT)
    return restored


def _decode_user_recency(value: object) -> dict[str, deque[str]]:
    if type(value) is not list:
        raise CheckpointCorruptionError("Bash command checkpoint user-recency table is invalid")
    restored: dict[str, deque[str]] = {}
    limit = bash_commands._COMMAND_RECENCY_LIMIT * 2
    for row in value:
        if type(row) is not list or len(row) != 2 or type(row[0]) is not str:
            raise CheckpointCorruptionError("Bash command checkpoint user-recency row is invalid")
        key = row[0]
        if key in restored:
            raise CheckpointCorruptionError(
                "Bash command checkpoint user-recency key is duplicated"
            )
        restored[key] = _decode_commands(row[1], limit=limit)
    return restored


def _decode_counts(value: object) -> Counter[str]:
    if type(value) is not list:
        raise CheckpointCorruptionError("Bash command checkpoint count table is invalid")
    restored: Counter[str] = Counter()
    for row in value:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not str
            or type(row[1]) is not int
            or row[1] <= 0
            or row[0] in restored
        ):
            raise CheckpointCorruptionError("Bash command checkpoint count row is invalid")
        restored[row[0]] = row[1]
    return restored


class BashCommandMemoryParticipant:
    """Persist global history that influences deterministic Bash command selection."""

    checkpoint_owner = "bash-command-memory"
    checkpoint_restore_priority = 40
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("_CACHED_COMMANDS", "deterministically-rebuilt"),
        OwnerStateField("_COMMAND_GLOBAL_COUNTS", "bounded-live-head"),
        OwnerStateField("_COMMAND_GLOBAL_LOW_REPEAT_COUNTS", "bounded-live-head"),
        OwnerStateField("_COMMAND_RECENCY", "bounded-live-head"),
        OwnerStateField("_COMMAND_USER_RECENCY", "bounded-live-head"),
        OwnerStateField("_USER_TOOL_AFFINITY", "deterministically-rebuilt"),
    )

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded command-selection memory without retaining a prepared copy."""

        del sequence
        document = _BashCommandMemoryHead(
            schema_version=self.checkpoint_schema_version,
            recency=_capture_recency(bash_commands._COMMAND_RECENCY),
            user_recency=_capture_user_recency(bash_commands._COMMAND_USER_RECENCY),
            global_counts=_capture_counts(bash_commands._COMMAND_GLOBAL_COUNTS),
            global_low_repeat_counts=_capture_counts(
                bash_commands._COMMAND_GLOBAL_LOW_REPEAT_COUNTS
            ),
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded command-memory head owns no publication watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded command-memory head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore command-selection memory after validating every row."""

        if segments:
            raise CheckpointCorruptionError("Bash command checkpoint has unexpected segments")
        try:
            document = _BashCommandMemoryHead.model_validate(loads(head))
            if document.schema_version != self.checkpoint_schema_version:
                raise CheckpointCorruptionError("Bash command checkpoint schema version changed")
            recency = _decode_recency(document.recency)
            user_recency = _decode_user_recency(document.user_recency)
            global_counts = _decode_counts(document.global_counts)
            global_low_repeat_counts = _decode_counts(document.global_low_repeat_counts)
        except CheckpointCorruptionError:
            raise
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("Bash command checkpoint head is invalid") from error

        bash_commands._COMMAND_RECENCY.clear()
        bash_commands._COMMAND_RECENCY.update(recency)
        bash_commands._COMMAND_USER_RECENCY.clear()
        bash_commands._COMMAND_USER_RECENCY.update(user_recency)
        bash_commands._COMMAND_GLOBAL_COUNTS.clear()
        bash_commands._COMMAND_GLOBAL_COUNTS.update(global_counts)
        bash_commands._COMMAND_GLOBAL_LOW_REPEAT_COUNTS.clear()
        bash_commands._COMMAND_GLOBAL_LOW_REPEAT_COUNTS.update(global_low_repeat_counts)


__all__ = ["BashCommandMemoryParticipant"]
