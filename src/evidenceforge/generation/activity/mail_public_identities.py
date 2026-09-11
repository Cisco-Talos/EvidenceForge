# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deprecated 2.x Python adapters for canonical public identity profiles."""

from evidenceforge.generation.activity.public_identity_profiles import (
    generate_public_mail_ip,
    is_public_mail_ip,
    legacy_mail_projection,
    public_mail_provider_name_for_hostname,
    public_mail_provider_name_for_ip,
    public_mail_ptr_name,
    public_safe_mail_hostname,
    reset_public_identity_profiles_cache,
)


def load_mail_public_identities() -> dict[str, object]:
    """Return canonical mail providers through the deprecated 2.x mapping shape."""

    return legacy_mail_projection()


def reset_mail_public_identities_cache() -> None:
    """Clear the canonical registry loader cache. Intended for compatibility tests."""

    reset_public_identity_profiles_cache()


__all__ = [
    "generate_public_mail_ip",
    "is_public_mail_ip",
    "load_mail_public_identities",
    "public_mail_provider_name_for_hostname",
    "public_mail_provider_name_for_ip",
    "public_mail_ptr_name",
    "public_safe_mail_hostname",
    "reset_mail_public_identities_cache",
]
