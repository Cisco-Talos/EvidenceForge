"""Shared helpers for Windows Event XML emitters."""

import re

from evidenceforge.generation.emitters.windows_event.time import format_windows_system_time

_INTER_TAG_WHITESPACE_RE = re.compile(r">\s+<")
_DATA_NAME_DOUBLE_QUOTE_RE = re.compile(r'(<Data\s+Name)="([^"]*)"')


def compact_windows_event_xml(rendered: str) -> str:
    """Return one physical-line XML event suitable for file-monitor ingestion."""
    compact = _INTER_TAG_WHITESPACE_RE.sub("><", rendered.strip())
    compact = _DATA_NAME_DOUBLE_QUOTE_RE.sub(r"\1='\2'", compact)
    return compact.replace("\r", "&#13;").replace("\n", "&#10;")


__all__ = ["compact_windows_event_xml", "format_windows_system_time"]
