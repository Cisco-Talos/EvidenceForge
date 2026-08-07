# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded loaders for scenario-relative sidecar assets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import read_text_file_beneath
from evidenceforge.utils.yaml_loader import load_yaml_text

EMAIL_CORPUS_MAX_SOURCE_BYTES = 8 * 1024 * 1024


def load_email_corpus_yaml(scenario_root: Path, reference: str) -> Any:
    """Load one bounded email corpus below the scenario package root."""

    content = read_text_file_beneath(
        scenario_root,
        reference,
        max_bytes=EMAIL_CORPUS_MAX_SOURCE_BYTES,
        label="email corpus",
    )
    return load_yaml_text(content, source=str(Path(scenario_root) / reference))
