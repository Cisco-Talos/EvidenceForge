"""Deterministic inert primitive codec for participant heads and segment columns."""

from __future__ import annotations

from struct import Struct

from .errors import CheckpointCorruptionError

PACKED_DOCUMENT_MAGIC = b"EFORGE-INCREMENTAL-PACKED-1\n"

_LENGTH = Struct(">Q")
_FLOAT = Struct(">d")
_MAX_CONTAINER_ITEMS = 100_000_000

_NONE = 0
_FALSE = 1
_TRUE = 2
_INT = 3
_FLOAT_VALUE = 4
_STRING = 5
_BYTES = 6
_LIST = 7
_DICT = 8


def _append_length(target: bytearray, value: int) -> None:
    if value < 0:
        raise ValueError("checkpoint document length cannot be negative")
    target.extend(_LENGTH.pack(value))


def _encode(value: object, target: bytearray) -> None:
    if value is None:
        target.append(_NONE)
    elif value is False:
        target.append(_FALSE)
    elif value is True:
        target.append(_TRUE)
    elif type(value) is int:
        payload = str(value).encode("ascii")
        target.append(_INT)
        _append_length(target, len(payload))
        target.extend(payload)
    elif type(value) is float:
        target.append(_FLOAT_VALUE)
        target.extend(_FLOAT.pack(value))
    elif type(value) is str:
        payload = value.encode("utf-8")
        target.append(_STRING)
        _append_length(target, len(payload))
        target.extend(payload)
    elif type(value) is bytes:
        target.append(_BYTES)
        _append_length(target, len(value))
        target.extend(value)
    elif type(value) is list:
        target.append(_LIST)
        _append_length(target, len(value))
        for item in value:
            _encode(item, target)
    elif type(value) is dict:
        if any(type(key) is not str for key in value):
            raise TypeError("checkpoint document mappings require string keys")
        target.append(_DICT)
        _append_length(target, len(value))
        for key in sorted(value):
            _encode(key, target)
            _encode(value[key], target)
    else:
        raise TypeError(f"unsupported checkpoint document type: {type(value).__name__}")


def dumps(value: object) -> bytes:
    """Encode one inert primitive document deterministically."""

    payload = bytearray(PACKED_DOCUMENT_MAGIC)
    _encode(value, payload)
    return bytes(payload)


class _Reader:
    def __init__(self, payload: bytes) -> None:
        self.payload = memoryview(payload)
        self.position = len(PACKED_DOCUMENT_MAGIC)

    def read(self, size: int) -> memoryview:
        end = self.position + size
        if size < 0 or end > len(self.payload):
            raise CheckpointCorruptionError("packed checkpoint document is truncated")
        value = self.payload[self.position : end]
        self.position = end
        return value

    def length(self) -> int:
        value = _LENGTH.unpack(self.read(_LENGTH.size))[0]
        if value > len(self.payload) or value > _MAX_CONTAINER_ITEMS:
            raise CheckpointCorruptionError("packed checkpoint document length is unreasonable")
        return value

    def decode(self) -> object:
        tag = int(self.read(1)[0])
        if tag == _NONE:
            return None
        if tag == _FALSE:
            return False
        if tag == _TRUE:
            return True
        if tag == _INT:
            try:
                return int(bytes(self.read(self.length())).decode("ascii"))
            except (UnicodeDecodeError, ValueError) as error:
                raise CheckpointCorruptionError("packed checkpoint integer is invalid") from error
        if tag == _FLOAT_VALUE:
            return _FLOAT.unpack(self.read(_FLOAT.size))[0]
        if tag == _STRING:
            try:
                return bytes(self.read(self.length())).decode("utf-8")
            except UnicodeDecodeError as error:
                raise CheckpointCorruptionError("packed checkpoint string is invalid") from error
        if tag == _BYTES:
            return bytes(self.read(self.length()))
        if tag == _LIST:
            return [self.decode() for _ in range(self.length())]
        if tag == _DICT:
            result: dict[str, object] = {}
            for _ in range(self.length()):
                key = self.decode()
                if type(key) is not str or key in result:
                    raise CheckpointCorruptionError(
                        "packed checkpoint mapping has an invalid or duplicate key"
                    )
                result[key] = self.decode()
            return result
        raise CheckpointCorruptionError(f"packed checkpoint document tag is unsupported: {tag}")


def loads(payload: bytes) -> object:
    """Decode one complete inert primitive document."""

    if not payload.startswith(PACKED_DOCUMENT_MAGIC):
        raise CheckpointCorruptionError("packed checkpoint document header is unsupported")
    reader = _Reader(payload)
    value = reader.decode()
    if reader.position != len(reader.payload):
        raise CheckpointCorruptionError("packed checkpoint document has trailing bytes")
    return value
