# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public configuration compatibility warnings and boundary helpers."""

from __future__ import annotations

import re
import warnings


class EvidenceForgeDeprecationWarning(FutureWarning):
    """A visible warning for supported public input scheduled for future removal."""


def warn_legacy_config(
    legacy_path: str,
    replacement: str,
    *,
    stacklevel: int = 3,
) -> None:
    """Warn once for one legacy input encountered at its owning load boundary.

    Args:
        legacy_path: Actionable dotted path or authored value that needs migration.
        replacement: Exact replacement syntax or field name.
        stacklevel: Warning stack level relative to this helper.
    """

    warnings.warn(
        f"{legacy_path} uses a legacy EvidenceForge configuration shape. "
        f"Replace it with {replacement}. The legacy shape will be removed in a future release.",
        EvidenceForgeDeprecationWarning,
        stacklevel=stacklevel,
    )


def stable_config_id(value: str) -> str:
    """Return a deterministic lowercase identifier for a legacy display name."""

    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")
    return normalized or "legacy-product"
