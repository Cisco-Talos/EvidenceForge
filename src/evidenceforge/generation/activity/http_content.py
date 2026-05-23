# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""HTTP content helpers shared by web, proxy, and Zeek HTTP generation."""

import random
from pathlib import PurePosixPath

from evidenceforge.utils.rng import _stable_seed

_EXTENSION_MIME_TYPES: dict[str, str] = {
    ".cab": "application/vnd.ms-cab-compressed",
    ".css": "text/css",
    ".exe": "application/x-msdownload",
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
    "application/x-msdownload": (5_000_000, 150_000_000),
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

_COMPRESSIBLE_MIME_TYPES = {
    "application/javascript",
    "application/json",
    "application/xml",
    "image/svg+xml",
    "text/css",
    "text/html",
    "text/plain",
}

_HEALTH_ENDPOINT_PATHS = {
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/status",
    "/api/health",
    "/api/status",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v2/health",
    "/livez",
}

_HTTP_STATUS_MESSAGES: dict[int, str] = {
    200: "OK",
    204: "No Content",
    206: "Partial Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
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


def response_size_floor_for_mime(content_type: str) -> int:
    """Return the configured minimum body size for a MIME type."""
    lo, _hi = _RESPONSE_SIZE_RANGES.get(content_type, (500, 50_000))
    return lo


def is_download_scale_mime(content_type: str) -> bool:
    """Return whether a MIME type should use download-scale body sizes."""
    return response_size_floor_for_mime(content_type) >= 1_000_000


def coerce_response_size_for_mime(
    rng: random.Random,
    content_type: str,
    preferred_size: int | None,
) -> int:
    """Return a source-native body size, replacing tiny download bodies."""
    preferred = max(0, preferred_size or 0)
    floor = response_size_floor_for_mime(content_type)
    if preferred and (not is_download_scale_mime(content_type) or preferred >= floor):
        return preferred
    return response_size_for_mime(rng, content_type)


def apply_transfer_size_variance(
    body_size: int,
    *,
    status_code: int,
    host: str,
    uri: str,
    content_type: str | None = None,
    variant_key: str | None = None,
) -> int:
    """Return source-visible transfer bytes for a stable response variant.

    Static web resources have stable origin content, but source logs often record
    bytes after client/cache/compression negotiation. Keep the default content
    size stable while allowing callers with a client/session key to model those
    source-visible variants deterministically.
    """
    if (
        not variant_key
        or body_size <= 0
        or status_code != 200
        or not is_stable_resource_path(uri)
        or is_health_endpoint_path(uri)
    ):
        return body_size

    mime_type = content_type or normalize_mime_type_for_path(uri, "text/html")
    rng = random.Random(
        _stable_seed(f"web_transfer_variant:{status_code}:{host}:{uri}:{mime_type}:{variant_key}")
    )
    if mime_type in _COMPRESSIBLE_MIME_TYPES or mime_type.startswith("text/"):
        ratio = rng.uniform(0.36, 0.88)
        jitter = rng.randint(-48, 96)
    elif mime_type.startswith(("image/", "font/")):
        ratio = rng.uniform(0.94, 1.025)
        jitter = rng.randint(-16, 32)
    else:
        ratio = rng.uniform(0.82, 1.03)
        jitter = rng.randint(-32, 64)
    return max(1, int(body_size * ratio) + jitter)


def response_size_for_transfer_variant(
    status_code: int,
    host: str,
    uri: str,
    *,
    content_type: str | None = None,
    variant_key: str | None = None,
) -> int:
    """Return a status-coherent response size with optional client variation."""
    body_size = response_size_for_status(status_code, host, uri)
    return apply_transfer_size_variance(
        body_size,
        status_code=status_code,
        host=host,
        uri=uri,
        content_type=content_type,
        variant_key=variant_key,
    )


def http_status_message(status_code: int) -> str:
    """Return a conventional HTTP reason phrase for a status code."""
    return _HTTP_STATUS_MESSAGES.get(status_code, "OK")


def response_mime_types_for_status(
    status_code: int,
    mime_type: str,
    response_body_len: int,
    *,
    method: str = "GET",
) -> list[str]:
    """Return Zeek-style response MIME metadata only when a body is observable."""
    if not mime_type or response_body_len <= 0:
        return []
    if method.upper() == "HEAD" or status_code in {204, 304}:
        return []
    if status_code in {301, 302} or status_code >= 400:
        return ["text/html"]
    return [mime_type]


def is_health_endpoint_path(uri: str) -> bool:
    """Return whether a URI path is a small operational health endpoint."""
    clean_path = uri.split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
    if not clean_path:
        clean_path = "/"
    return clean_path in _HEALTH_ENDPOINT_PATHS


def response_size_for_health_endpoint(status_code: int, host: str, uri: str) -> int:
    """Return a stable, source-native body size for health/status endpoints."""
    if status_code >= 400:
        return response_size_for_status(status_code, host, uri)
    clean_path = uri.split("?", 1)[0].split("#", 1)[0].lower().rstrip("/")
    rng = random.Random(_stable_seed(f"web_health_response:{status_code}:{host}:{clean_path}"))
    if clean_path.endswith("/status") or clean_path == "/status":
        return rng.randint(18, 180)
    return rng.randint(42, 720)


def is_stable_resource_path(uri: str) -> bool:
    """Return whether repeated 200 responses should keep a stable body size."""
    clean_path = uri.split("?", 1)[0].split("#", 1)[0].lower()
    suffix = PurePosixPath(clean_path).suffix.lower()
    if is_health_endpoint_path(uri):
        return True
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
    if status_code in {204, 304}:
        return 0
    if status_code in {301, 302}:
        rng = random.Random(_stable_seed(f"web_redirect:{status_code}:{host}:{uri}"))
        return rng.randint(120, 480)
    if status_code < 400 and is_health_endpoint_path(uri):
        return response_size_for_health_endpoint(status_code, host, uri)
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
