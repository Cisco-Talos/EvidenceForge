# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""HTTP content helpers shared by web, proxy, and Zeek HTTP generation."""

import random
from pathlib import PurePosixPath

from evidenceforge.utils.rng import _stable_seed

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


def is_stable_resource_path(uri: str) -> bool:
    """Return whether repeated 200 responses should keep a stable body size."""
    clean_path = uri.split("?", 1)[0].split("#", 1)[0].lower()
    suffix = PurePosixPath(clean_path).suffix.lower()
    if clean_path in {"/", "/index.html", "/robots.txt", "/sitemap.xml", "/favicon.ico"}:
        return True
    return suffix in {
        ".css",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".js",
        ".map",
        ".png",
        ".svg",
        ".txt",
        ".webp",
        ".woff",
        ".woff2",
        ".xml",
    }


def response_size_for_status(status_code: int, host: str, uri: str) -> int:
    """Return a stable source-native web response body size for an HTTP status."""
    if status_code < 400:
        rng = random.Random(_stable_seed(f"web_response:{status_code}:{host}:{uri}"))
        return response_size_for_mime(rng, normalize_mime_type_for_path(uri, "text/html"))

    ranges = {
        403: (360, 1400),
        404: (420, 1800),
        405: (420, 1600),
        500: (800, 2600),
        502: (600, 1800),
        503: (600, 1800),
        504: (600, 1800),
    }
    lo, hi = ranges.get(status_code, (300, 1600))
    # Real error templates are mostly per-site/status, with small path-specific variance.
    base_rng = random.Random(_stable_seed(f"web_error_template:{host}:{status_code}"))
    path_rng = random.Random(_stable_seed(f"web_error_path:{host}:{status_code}:{uri}"))
    template_size = base_rng.randint(lo, hi)
    return max(128, template_size + path_rng.randint(-80, 80))
