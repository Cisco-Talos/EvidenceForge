# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data-driven HTTP request and file-content profiles."""

from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_PROFILE_PATH = get_activity_directory() / "http_file_profiles.yaml"
_CACHED: dict[str, Any] | None = None


def load_http_file_profiles() -> dict[str, Any]:
    """Load HTTP entity profiles, including an optional user overlay."""

    global _CACHED  # noqa: PLW0603
    if _CACHED is None:
        _CACHED = load_with_overlay(
            _PROFILE_PATH,
            "activity/http_file_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED


def request_content_type_for_activity(
    method: str,
    uri: str,
    user_agent: str,
    *,
    local_source_path: str = "",
) -> str:
    """Return a realistic request content type from the owning activity shape."""

    if local_source_path:
        from evidenceforge.generation.activity.http_content import infer_mime_type_from_path

        return infer_mime_type_from_path(local_source_path, "application/octet-stream")
    profiles = load_http_file_profiles().get("request_profiles", {})
    normalized_uri = uri.casefold()
    json_uri_tokens = tuple(str(token).casefold() for token in profiles.get("json_uri_tokens", ()))
    if any(token in normalized_uri for token in json_uri_tokens):
        return str(profiles.get("json_api", "application/json"))
    if method.upper() == "POST" and user_agent:
        return str(profiles.get("browser_form", "application/x-www-form-urlencoded"))
    return str(profiles.get("binary", "application/octet-stream"))
