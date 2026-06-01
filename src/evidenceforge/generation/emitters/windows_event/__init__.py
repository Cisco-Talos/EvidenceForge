"""Shared helpers for Windows Event XML emitters."""

import re

from evidenceforge.generation.emitters.windows_event.time import format_windows_system_time

_INTER_TAG_WHITESPACE_RE = re.compile(r">\s+<")


def compact_windows_event_xml(rendered: str) -> str:
    """Return one physical-line XML event suitable for file-monitor ingestion."""
    compact = _INTER_TAG_WHITESPACE_RE.sub("><", rendered.strip())
    return compact.replace("\r", "&#13;").replace("\n", "&#10;")


__all__ = ["compact_windows_event_xml", "format_windows_system_time"]
