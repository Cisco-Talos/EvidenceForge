# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical normalization for IDS evaluation fingerprints."""

from __future__ import annotations

import ipaddress
import json
import struct
from datetime import UTC, datetime
from typing import Any

from evidenceforge.config.snort_classifications import snort_classification_description

_SHA256_INITIAL_STATE = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_SHA256_ROUND_CONSTANTS = (
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)
_UINT32_MASK = (1 << 32) - 1


def _rotate_right(value: int, amount: int) -> int:
    return ((value >> amount) | (value << (32 - amount))) & _UINT32_MASK


class IdsDigest:
    """SHA-256 with an inert numeric checkpoint state and hashlib-compatible results."""

    digest_size = 32
    block_size = 64
    name = "sha256"

    def __init__(
        self,
        *,
        words: tuple[int, int, int, int, int, int, int, int] = _SHA256_INITIAL_STATE,
        byte_count: int = 0,
        pending: bytes = b"",
    ) -> None:
        if (
            type(words) is not tuple
            or len(words) != 8
            or any(type(word) is not int or not 0 <= word <= _UINT32_MASK for word in words)
            or type(byte_count) is not int
            or byte_count < 0
            or type(pending) is not bytes
            or len(pending) >= self.block_size
            or byte_count < len(pending)
            or (byte_count - len(pending)) % self.block_size
        ):
            raise ValueError("IDS digest checkpoint state is invalid")
        self._words = words
        self._byte_count = byte_count
        self._pending = pending

    def copy(self) -> IdsDigest:
        """Return an independent digest with the same numeric state."""

        return IdsDigest(
            words=self._words,
            byte_count=self._byte_count,
            pending=self._pending,
        )

    def checkpoint_state(self) -> tuple[int, tuple[int, ...], int, bytes]:
        """Return the versioned inert state required to continue this digest."""

        return (1, self._words, self._byte_count, self._pending)

    @classmethod
    def from_checkpoint_state(cls, state: object) -> IdsDigest:
        """Restore a digest from a validated numeric checkpoint state."""

        if type(state) is not tuple or len(state) != 4 or state[0] != 1:
            raise ValueError("IDS digest checkpoint schema is unsupported")
        words = state[1]
        if type(words) is not tuple or len(words) != 8:
            raise ValueError("IDS digest checkpoint state is invalid")
        return cls(words=words, byte_count=state[2], pending=state[3])

    def update(self, payload: bytes | bytearray | memoryview) -> None:
        """Append bytes using the standard SHA-256 compression function."""

        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("IDS digest update requires a bytes-like value")
        incoming = bytes(payload)
        self._byte_count += len(incoming)
        combined = self._pending + incoming
        complete = len(combined) - (len(combined) % self.block_size)
        for offset in range(0, complete, self.block_size):
            self._compress(combined[offset : offset + self.block_size])
        self._pending = combined[complete:]

    def _compress(self, block: bytes) -> None:
        schedule = list(struct.unpack(">16I", block)) + [0] * 48
        for index in range(16, 64):
            prior = schedule[index - 15]
            near = schedule[index - 2]
            sigma_zero = _rotate_right(prior, 7) ^ _rotate_right(prior, 18) ^ (prior >> 3)
            sigma_one = _rotate_right(near, 17) ^ _rotate_right(near, 19) ^ (near >> 10)
            schedule[index] = (
                schedule[index - 16] + sigma_zero + schedule[index - 7] + sigma_one
            ) & _UINT32_MASK

        a, b, c, d, e, f, g, h = self._words
        for constant, value in zip(_SHA256_ROUND_CONSTANTS, schedule, strict=True):
            sigma_one = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
            choose = (e & f) ^ ((~e) & g)
            temporary_one = (h + sigma_one + choose + constant + value) & _UINT32_MASK
            sigma_zero = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary_two = (sigma_zero + majority) & _UINT32_MASK
            h, g, f, e, d, c, b, a = (
                g,
                f,
                e,
                (d + temporary_one) & _UINT32_MASK,
                c,
                b,
                a,
                (temporary_one + temporary_two) & _UINT32_MASK,
            )
        self._words = tuple(
            (current + added) & _UINT32_MASK
            for current, added in zip(self._words, (a, b, c, d, e, f, g, h), strict=True)
        )

    def digest(self) -> bytes:
        """Return the standard SHA-256 digest without changing live state."""

        retained = self.copy()
        bit_count = retained._byte_count * 8
        padding_size = (56 - (retained._byte_count + 1) % 64) % 64
        retained.update(b"\x80" + (b"\x00" * padding_size) + bit_count.to_bytes(8, "big"))
        if retained._pending:  # pragma: no cover - padding arithmetic invariant
            raise RuntimeError("IDS digest padding retained a partial block")
        return struct.pack(">8I", *retained._words)

    def hexdigest(self) -> str:
        """Return the standard lowercase hexadecimal SHA-256 digest."""

        return self.digest().hex()


def normalize_ids_alert(sensor: str, fields: dict[str, Any]) -> dict[str, Any]:
    """Return the stable, source-native IDS fields covered by integrity evaluation."""

    timestamp = fields.get("timestamp") or fields.get("ts")
    if not isinstance(timestamp, datetime):
        timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    timestamp = (
        timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
    )

    return {
        "sensor": sensor,
        "timestamp": timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "gid": int(fields.get("gid", 1)),
        "sid": int(fields["sid"]),
        "rev": int(fields.get("rev", 1)),
        "message": str(fields.get("message") or "").strip(),
        "classification": snort_classification_description(
            str(fields.get("classification") or "").strip()
        ),
        "priority": int(fields.get("priority", 0)),
        "protocol": str(fields.get("protocol") or fields.get("proto") or "").upper(),
        "src_ip": _normalize_ip(fields.get("src_ip") or fields.get("id.orig_h")),
        "src_port": _normalize_port(fields.get("src_port") or fields.get("id.orig_p")),
        "dst_ip": _normalize_ip(fields.get("dst_ip") or fields.get("id.resp_h")),
        "dst_port": _normalize_port(fields.get("dst_port") or fields.get("id.resp_p")),
    }


def update_ids_digest(hasher: Any, sensor: str, fields: dict[str, Any]) -> None:
    """Append one normalized alert to an ordered SHA-256 digest."""

    payload = json.dumps(
        normalize_ids_alert(sensor, fields),
        sort_keys=True,
        separators=(",", ":"),
    )
    hasher.update(payload.encode("utf-8"))
    hasher.update(b"\n")


def new_ids_digest() -> IdsDigest:
    """Return a fresh resumable SHA-256 digest."""

    return IdsDigest()


def _normalize_ip(value: Any) -> str:
    text = str(value or "")
    try:
        return ipaddress.ip_address(text.strip("[]")).compressed
    except ValueError:
        return text


def _normalize_port(value: Any) -> int | None:
    if value in (None, "", "-"):
        return None
    return int(value)
