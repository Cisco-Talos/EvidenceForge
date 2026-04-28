# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for shared HTTP content helpers."""

import random

from evidenceforge.generation.activity.http_content import (
    infer_mime_type_from_path,
    normalize_mime_type_for_path,
    response_size_for_mime,
)


def test_infer_mime_type_strips_query_and_fragment():
    assert infer_mime_type_from_path("/assets/status.gif?cache=1#view") == "image/gif"


def test_known_extension_overrides_supplied_content_type():
    assert normalize_mime_type_for_path("/status.gif", "text/html") == "image/gif"


def test_unknown_extension_keeps_supplied_content_type():
    assert normalize_mime_type_for_path("/download/custom.blob", "application/octet-stream") == (
        "application/octet-stream"
    )


def test_response_size_for_gif_uses_image_range():
    size = response_size_for_mime(random.Random(42), "image/gif")
    assert 500 <= size <= 50_000
