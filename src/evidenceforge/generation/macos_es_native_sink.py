# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit native export sink for authenticated historical ES publication.

This internal adapter does not register a generator source or select a wire
profile. Only already authenticated frozen records enter the exact journal.
"""

import json
from pathlib import Path

from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter


def _native_sort_key(line: str) -> tuple[str, int, int, str]:
    record = json.loads(line)
    return record["time"], record["global_seq_num"], record["seq_num"], line


def create_es_native_sink(path: Path) -> ExternalSortedLineWriter:
    """Create a fresh bounded sorted journal sink without enabling ES generation."""
    path = path.resolve()
    if path.exists():
        raise FileExistsError("Native ES export requires a fresh output path")
    return ExternalSortedLineWriter(path, sort_key=_native_sort_key)


def validate_es_native_sink(sink: ExternalSortedLineWriter) -> None:
    """Require the exact journal implementation and its native deterministic ordering."""
    if type(sink) is not ExternalSortedLineWriter or sink._sort_key is not _native_sort_key:
        raise ValueError("Native ES publication requires its exact sorted journal sink")
