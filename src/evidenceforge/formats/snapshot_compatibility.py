# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Decode recognized pre-typed-rule snapshots without changing rendered formats."""

import hashlib
import json
from pathlib import Path
from typing import Any

from evidenceforge.config.provider import packaged_default_document
from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.utils.yaml_loader import load_yaml_text

# Exact legacy validator documents shipped at the immutable 2.1.0 baseline.
_LEGACY_RULE_DIGESTS = {
    "windows_event_security": "3576125ad4f20b5f7c18c7e76ef2fd76b52053b35c16bc8071ac3d0c5f6ec437",
    "zeek_conn": "23c4168a391e0c90fb4d0ba71fcf7c1ea66ffc29e4df503b42917b108ce76996",
}
_LEGACY_THRESHOLDS = "395316c618d24c83792baa5887a23b2e357f705887e4a38c9db9eb82bcb638f2"


def _digest(document: Any) -> str:
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def decode_validation_snapshot(path: Path, document: dict[str, Any]) -> dict[str, Any]:
    """Upgrade only recognized inlined validation metadata, never arbitrary old syntax.

    Render templates, scenario data, and the stored snapshot are untouched.
    Recognized format metadata is promoted to the canonical runtime contract so
    callback-free native renderer identity checks remain intact.
    The runtime's typed rules and exact acceptance policy govern evaluation after upgrade.
    """
    found, _ = packaged_default_document(path)
    if not found:
        return document
    if path.stem in _LEGACY_RULE_DIGESTS and _digest(document) == _LEGACY_RULE_DIGESTS[path.stem]:
        current = load_yaml_text(path.read_text(encoding="utf-8"), source=str(path))
        if current["output"] != document["output"]:
            raise ConfigurationError(
                "Legacy validation snapshot requires a rendering-compatible decoder"
            )
        return current
    if path.name == "thresholds.yaml" and _digest(document) == _LEGACY_THRESHOLDS:
        return load_yaml_text(path.read_text(encoding="utf-8"), source=str(path))
    return document
