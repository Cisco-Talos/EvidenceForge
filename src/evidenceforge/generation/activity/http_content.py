# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""HTTP content helpers shared by web, proxy, and Zeek HTTP generation."""

import random
from pathlib import PurePosixPath

_EXTENSION_MIME_TYPES: dict[str, str] = {
    ".cab": "application/vnd.ms-cab-compressed",
    ".css": "text/css",
    ".gif": "image/gif",
    ".gz": "application/x-gzip",
    ".ico": "image/x-icon",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "application/javascript",
    ".json": "application/json",
    ".map": "application/json",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".xml": "application/xml",
}

_RESPONSE_SIZE_RANGES: dict[str, tuple[int, int]] = {
    "application/javascript": (10_000, 200_000),
    "application/json": (200, 50_000),
    "application/octet-stream": (1_000, 100_000),
    "application/ocsp-response": (400, 3_000),
    "application/pdf": (20_000, 2_000_000),
    "application/pkix-crl": (2_000, 200_000),
    "application/vnd.ms-cab-compressed": (50_000, 5_000_000),
    "application/x-gzip": (10_000, 5_000_000),
    "font/woff": (20_000, 100_000),
    "font/woff2": (20_000, 100_000),
    "image/gif": (500, 50_000),
    "image/jpeg": (5_000, 500_000),
    "image/png": (2_000, 300_000),
    "image/svg+xml": (500, 20_000),
    "image/webp": (5_000, 400_000),
    "image/x-icon": (500, 5_000),
    "text/css": (2_000, 50_000),
    "text/html": (5_000, 80_000),
    "text/plain": (100, 20_000),
}


def infer_mime_type_from_path(path: str, default: str = "text/html") -> str:
    """Infer a response MIME type from a URI path extension.

    Query strings and fragments are ignored. Unknown extensions keep ``default``.
    """
    clean_path = path.split("?", 1)[0].split("#", 1)[0]
    suffix = PurePosixPath(clean_path).suffix.lower()
    return _EXTENSION_MIME_TYPES.get(suffix, default)


def normalize_mime_type_for_path(path: str, content_type: str | None = None) -> str:
    """Return a path-coherent MIME type, letting known extensions win."""
    return infer_mime_type_from_path(path, content_type or "text/html")


def response_size_for_mime(rng: random.Random, content_type: str) -> int:
    """Generate a realistic response size for a MIME type."""
    lo, hi = _RESPONSE_SIZE_RANGES.get(content_type, (500, 50_000))
    return rng.randint(lo, hi)
