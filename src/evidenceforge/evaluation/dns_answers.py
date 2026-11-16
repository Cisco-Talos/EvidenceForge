"""Source-native DNS answer semantics shared by evaluation contracts."""

import re

from .parsers import ParsedRecord


def dns_answer_values(record: ParsedRecord, actual: object) -> object:
    """Decode the declared TXT presentation, without changing payload content."""
    if record.source_format != "zeek_dns" or not isinstance(actual, list):
        return actual
    qtype = record.fields.get("qtype_name", record.fields.get("qtype"))
    if str(qtype).upper() not in {"TXT", "16"}:
        return actual
    result: list[object] = []
    for value in actual:
        remaining = value.encode("utf-8") if isinstance(value, str) else b""
        chunks: list[bytes] = []
        while remaining:
            match = re.match(rb"TXT (\d+) ", remaining)
            if match is None:
                break
            size = int(match[1])
            payload = remaining[match.end() : match.end() + size]
            if len(payload) != size:
                break
            chunks.append(payload)
            remaining = remaining[match.end() + size :]
            if remaining.startswith(b" TXT "):
                remaining = remaining[1:]
            elif remaining:
                break
        result.append(b"".join(chunks).decode("utf-8") if chunks and not remaining else value)
    return result
