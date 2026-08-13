# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic, allocation-free HTTP multipart entity serialization."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from urllib.parse import quote, unquote

from evidenceforge.events.contexts import (
    HttpContext,
    HttpEntityPartContext,
    HttpMultipartEntityContext,
    HttpWireSpanContext,
)
from evidenceforge.generation.activity.http_content import infer_mime_type_from_path
from evidenceforge.generation.activity.http_file_profiles import load_http_file_profiles
from evidenceforge.models.http import HttpMultipartEntitySpec, HttpMultipartPartSpec
from evidenceforge.utils.rng import _stable_seed

_BOUNDARY_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


@dataclass(frozen=True, slots=True)
class _SerializedParts:
    body_len: int
    parts: tuple[HttpEntityPartContext, ...]
    spans: tuple[HttpWireSpanContext, ...]


def _client_family(user_agent: str, requested: str | None) -> str:
    """Return the configured multipart boundary family."""

    if requested:
        return requested
    normalized = user_agent.casefold()
    if "curl/" in normalized:
        return "curl"
    if any(token in normalized for token in ("mozilla/", "chrome/", "safari/", "firefox/")):
        return "browser"
    return "generic"


def _stable_boundary(stable_key: str, family: str, path: tuple[int, ...]) -> str:
    """Return a stable source-shaped MIME boundary without allocating payload bytes."""

    config = load_http_file_profiles()["multipart"]
    profiles = config["boundaries"]
    profile = profiles.get(family, profiles["generic"])
    seed = _stable_seed(f"http-multipart-boundary:{stable_key}:{family}:{path}")
    length = int(profile["suffix_length"])
    suffix = "".join(
        _BOUNDARY_ALPHABET[(seed >> ((index % 10) * 6)) % len(_BOUNDARY_ALPHABET)]
        for index in range(length)
    )
    return f"{profile['prefix']}{suffix}"


def encoded_multipart_leaf_size(decoded_size: int, transfer_encoding: str) -> int:
    """Return deterministic wire content bytes for one decoded multipart leaf."""

    if decoded_size <= 0:
        return 0
    if transfer_encoding in {"binary", "7bit", "8bit"}:
        return decoded_size
    if transfer_encoding == "base64":
        encoded_chars = 4 * ((decoded_size + 2) // 3)
        return encoded_chars + 2 * ((encoded_chars - 1) // 76)
    if transfer_encoding == "quoted-printable":
        percent = int(load_http_file_profiles()["multipart"]["quoted_printable_escape_percent"])
        escaped = (decoded_size * percent) // 100
        encoded_chars = decoded_size + 2 * escaped
        return encoded_chars + 3 * ((encoded_chars - 1) // 75)
    raise ValueError(f"unsupported multipart transfer encoding: {transfer_encoding}")


def _decoded_size_for_encoded_size(encoded_size: int, transfer_encoding: str) -> int:
    """Invert the monotonic encoded-size model for an asserted outer body length."""

    if encoded_size < 0:
        raise ValueError("multipart asserted body length is smaller than its envelope")
    if transfer_encoding in {"binary", "7bit", "8bit"}:
        return encoded_size
    low = 0
    high = max(1, encoded_size)
    while encoded_multipart_leaf_size(high, transfer_encoding) < encoded_size:
        high *= 2
    while low <= high:
        middle = (low + high) // 2
        candidate = encoded_multipart_leaf_size(middle, transfer_encoding)
        if candidate == encoded_size:
            return middle
        if candidate < encoded_size:
            low = middle + 1
        else:
            high = middle - 1
    raise ValueError(
        "multipart asserted body length cannot encode the unresolved part exactly with "
        f"{transfer_encoding}"
    )


def _append_span(
    spans: list[HttpWireSpanContext],
    *,
    kind: str,
    offset: int,
    length: int,
    part_path: tuple[int, ...] = (),
) -> None:
    """Append or merge a contiguous envelope span."""

    if length <= 0:
        return
    if (
        kind == "envelope"
        and spans
        and spans[-1].kind == "envelope"
        and spans[-1].offset + spans[-1].length == offset
    ):
        previous = spans[-1]
        spans[-1] = HttpWireSpanContext(
            kind="envelope",
            offset=previous.offset,
            length=previous.length + length,
        )
        return
    spans.append(HttpWireSpanContext(kind=kind, offset=offset, length=length, part_path=part_path))


def _header_lines(
    spec: HttpMultipartPartSpec,
    *,
    parent_media_type: str,
    nested_content_type: str,
) -> tuple[str, ...]:
    """Return source-native ordered headers for one serialized part."""

    values: dict[str, str] = {}
    if parent_media_type == "multipart/form-data":
        disposition = f'Content-Disposition: form-data; name="{spec.name or ""}"'
        if spec.filename:
            disposition += f'; filename="{spec.filename}"'
        if spec.filename_star:
            encoded = spec.filename_star
            if "''" not in encoded:
                encoded = f"UTF-8''{quote(encoded)}"
            disposition += f"; filename*={encoded}"
        values["content_disposition"] = disposition
    elif spec.filename:
        values["content_disposition"] = (
            f'Content-Disposition: attachment; filename="{spec.filename}"'
        )
    elif spec.name:
        values["content_disposition"] = f'Content-Disposition: inline; name="{spec.name}"'

    content_type = nested_content_type or spec.content_type or ""
    if content_type and spec.content_type_name:
        content_type += f'; name="{spec.content_type_name}"'
    if content_type:
        values["content_type"] = f"Content-Type: {content_type}"
    if spec.content_length is not None:
        values["content_length"] = f"Content-Length: {spec.content_length}"
    if spec.transfer_encoding != "binary":
        values["transfer_encoding"] = f"Content-Transfer-Encoding: {spec.transfer_encoding}"

    order = load_http_file_profiles()["multipart"]["header_order"]
    return tuple(values[key] for key in order if key in values)


def _detected_mime_type(spec: HttpMultipartPartSpec) -> str:
    """Return the modeled file-magic result, independently of declared MIME."""

    if spec.detected_mime_type is not None:
        return spec.detected_mime_type
    candidate = spec.local_source_path or spec.filename or ""
    if candidate:
        inferred = infer_mime_type_from_path(candidate, "")
        if inferred:
            return inferred
    declared = spec.content_type or ""
    if declared.startswith("text/") or declared in {
        "application/json",
        "application/xml",
        "application/pdf",
        "application/vnd.rar",
        "application/zip",
        "application/x-dosexec",
        "application/x-msdownload",
    }:
        return declared
    if spec.value is not None and spec.value:
        return "text/plain"
    return ""


def _wire_filename(spec: HttpMultipartPartSpec) -> str:
    """Resolve Zeek's filename, filename*, then Content-Type name fallback order."""

    if spec.filename:
        return spec.filename
    if spec.filename_star:
        encoded = spec.filename_star.split("''", 1)[-1]
        return unquote(encoded)
    return spec.content_type_name or ""


def _serialize_parts(
    specs: list[HttpMultipartPartSpec],
    *,
    media_type: str,
    boundary: str,
    stable_key: str,
    family: str,
    path_prefix: tuple[int, ...],
    source_sizes: Mapping[str, int],
    size_overrides: Mapping[tuple[int, ...], int],
) -> _SerializedParts:
    """Serialize an ordered multipart level and return canonical parts and spans."""

    offset = 0
    parts: list[HttpEntityPartContext] = []
    spans: list[HttpWireSpanContext] = []
    for index, spec in enumerate(specs):
        path = (*path_prefix, index)
        delimiter = f"--{boundary}\r\n".encode()
        _append_span(spans, kind="envelope", offset=offset, length=len(delimiter))
        offset += len(delimiter)

        nested: _SerializedParts | None = None
        nested_content_type = ""
        if spec.parts:
            nested_boundary = _stable_boundary(stable_key, "generic", path)
            nested_content_type = f"{spec.content_type}; boundary={nested_boundary}"
            nested = _serialize_parts(
                spec.parts,
                media_type=spec.content_type or "multipart/mixed",
                boundary=nested_boundary,
                stable_key=stable_key,
                family=family,
                path_prefix=path,
                source_sizes=source_sizes,
                size_overrides=size_overrides,
            )

        headers = _header_lines(
            spec,
            parent_media_type=media_type,
            nested_content_type=nested_content_type,
        )
        header_bytes = ("\r\n".join(headers) + "\r\n\r\n").encode()
        _append_span(spans, kind="envelope", offset=offset, length=len(header_bytes))
        offset += len(header_bytes)

        if nested is not None:
            for nested_span in nested.spans:
                _append_span(
                    spans,
                    kind=nested_span.kind,
                    offset=offset + nested_span.offset,
                    length=nested_span.length,
                    part_path=nested_span.part_path,
                )
            part = HttpEntityPartContext(
                path=path,
                name=spec.name or "",
                declared_content_type=nested_content_type,
                content_identity=f"http-multipart-container:{stable_key}:{path}",
                parts=nested.parts,
            )
            offset += nested.body_len
        else:
            if spec.value is not None:
                decoded_size = len(spec.value.encode())
            elif path in size_overrides:
                decoded_size = size_overrides[path]
            elif spec.body_len is not None:
                decoded_size = spec.body_len
            elif spec.local_source_path and spec.local_source_path in source_sizes:
                decoded_size = int(source_sizes[spec.local_source_path])
            else:
                decoded_size = 0
            encoded_size = encoded_multipart_leaf_size(decoded_size, spec.transfer_encoding)
            if spec.content_length is not None and spec.content_length != decoded_size:
                raise ValueError(
                    "multipart part content_length must equal resolved decoded leaf size"
                )
            _append_span(
                spans,
                kind="leaf",
                offset=offset,
                length=encoded_size,
                part_path=path,
            )
            part = HttpEntityPartContext(
                path=path,
                name=spec.name or "",
                decoded_size=decoded_size,
                encoded_size=encoded_size,
                declared_content_type=spec.content_type or "",
                detected_mime_type=_detected_mime_type(spec),
                transfer_encoding=spec.transfer_encoding,
                local_source_path=spec.local_source_path or "",
                local_source_filename=(spec.local_source_path or "")
                .replace("\\", "/")
                .rsplit("/", 1)[-1],
                wire_filename=_wire_filename(spec),
                content_identity=(
                    f"http-multipart-leaf:{stable_key}:{path}:{decoded_size}:"
                    f"{spec.local_source_path or spec.filename or spec.name or ''}"
                ),
                declared_content_length=spec.content_length,
            )
            offset += encoded_size

        suffix = b"\r\n"
        _append_span(spans, kind="envelope", offset=offset, length=len(suffix))
        offset += len(suffix)
        parts.append(part)

    closing = f"--{boundary}--\r\n".encode()
    _append_span(spans, kind="envelope", offset=offset, length=len(closing))
    offset += len(closing)
    return _SerializedParts(body_len=offset, parts=tuple(parts), spans=tuple(spans))


def _unresolved_paths(
    specs: list[HttpMultipartPartSpec],
    source_sizes: Mapping[str, int],
    prefix: tuple[int, ...] = (),
) -> list[tuple[tuple[int, ...], HttpMultipartPartSpec]]:
    """Return file-backed leaves whose decoded size is not otherwise known."""

    unresolved: list[tuple[tuple[int, ...], HttpMultipartPartSpec]] = []
    for index, spec in enumerate(specs):
        path = (*prefix, index)
        if spec.parts:
            unresolved.extend(_unresolved_paths(spec.parts, source_sizes, path))
        elif (
            spec.value is None
            and spec.body_len is None
            and spec.local_source_path
            and spec.local_source_path not in source_sizes
        ):
            unresolved.append((path, spec))
    return unresolved


def build_http_multipart_context(
    spec: HttpMultipartEntitySpec,
    *,
    stable_key: str,
    user_agent: str = "",
    client_family: str | None = None,
    asserted_body_len: int | None = None,
    source_sizes: Mapping[str, int] | None = None,
) -> HttpMultipartEntityContext:
    """Build one exact multipart entity, solving one unknown file size when possible."""

    source_sizes = source_sizes or {}
    config = load_http_file_profiles()["multipart"]
    family = _client_family(user_agent, client_family)
    boundary = spec.boundary or _stable_boundary(stable_key, family, ())
    unresolved = _unresolved_paths(spec.parts, source_sizes)
    if len(unresolved) > 1:
        paths = ", ".join(str(path) for path, _part in unresolved)
        raise ValueError(f"multipart entity has multiple unresolved local file sizes: {paths}")
    if unresolved and asserted_body_len is None:
        raise ValueError(
            f"multipart local file {unresolved[0][1].local_source_path!r} requires body_len, "
            "staged size, or an exact outer body length"
        )

    def _shape(parts: list[HttpMultipartPartSpec], depth: int = 1) -> tuple[int, int]:
        count = len(parts)
        deepest = depth
        for part in parts:
            if part.parts:
                nested_count, nested_depth = _shape(part.parts, depth + 1)
                count += nested_count
                deepest = max(deepest, nested_depth)
        return count, deepest

    part_count, depth = _shape(spec.parts)
    if part_count > int(config["max_parts"]):
        raise ValueError("multipart entity exceeds configured maximum part count")
    if depth > int(config["max_depth"]):
        raise ValueError("multipart entity exceeds configured maximum nesting depth")

    size_overrides: dict[tuple[int, ...], int] = {}
    serialized = _serialize_parts(
        spec.parts,
        media_type=spec.media_type,
        boundary=boundary,
        stable_key=stable_key,
        family=family,
        path_prefix=(),
        source_sizes=source_sizes,
        size_overrides=size_overrides,
    )
    if unresolved:
        path, part = unresolved[0]
        encoded_size = int(asserted_body_len or 0) - serialized.body_len
        size_overrides[path] = _decoded_size_for_encoded_size(encoded_size, part.transfer_encoding)
        serialized = _serialize_parts(
            spec.parts,
            media_type=spec.media_type,
            boundary=boundary,
            stable_key=stable_key,
            family=family,
            path_prefix=(),
            source_sizes=source_sizes,
            size_overrides=size_overrides,
        )

    if asserted_body_len is not None and asserted_body_len != serialized.body_len:
        raise ValueError(
            f"multipart serialized body length {serialized.body_len} does not match exact "
            f"assertion {asserted_body_len}"
        )
    return HttpMultipartEntityContext(
        media_type=spec.media_type,
        boundary=boundary,
        body_len=serialized.body_len,
        parts=serialized.parts,
        wire_spans=serialized.spans,
    )


def apply_http_multipart_specs(
    http: HttpContext,
    *,
    stable_key: str,
    request_spec: HttpMultipartEntitySpec | None = None,
    response_spec: HttpMultipartEntitySpec | None = None,
    request_body_assertion: int | None = None,
    response_body_assertion: int | None = None,
    client_family: str | None = None,
    source_sizes: Mapping[str, int] | None = None,
) -> HttpContext:
    """Attach authored multipart entities and their exact outer byte counts."""

    if isinstance(request_spec, Mapping):
        request_spec = HttpMultipartEntitySpec.model_validate(request_spec)
    if isinstance(response_spec, Mapping):
        response_spec = HttpMultipartEntitySpec.model_validate(response_spec)

    request_context = None
    response_context = None
    request_body_len = http.request_body_len
    response_body_len = http.response_body_len
    request_content_type = http.request_content_type
    response_mime_types = http.resp_mime_types
    if request_spec is not None:
        request_context = build_http_multipart_context(
            request_spec,
            stable_key=f"{stable_key}:request",
            user_agent=http.user_agent,
            client_family=client_family,
            asserted_body_len=request_body_assertion,
            source_sizes=source_sizes,
        )
        request_body_len = request_context.body_len
        request_content_type = f"{request_context.media_type}; boundary={request_context.boundary}"
    if response_spec is not None:
        from evidenceforge.generation.activity.http_content import http_response_has_entity_body

        response_context = build_http_multipart_context(
            response_spec,
            stable_key=f"{stable_key}:response",
            user_agent=http.user_agent,
            client_family="generic",
            asserted_body_len=response_body_assertion,
            source_sizes=source_sizes,
        )
        if not http_response_has_entity_body(
            http.method,
            http.status_code,
            response_context.body_len,
        ):
            raise ValueError(
                f"HTTP {http.method} status {http.status_code} cannot carry response_multipart"
            )
        response_body_len = response_context.body_len
        response_mime_types = ()
    return replace(
        http,
        request_body_len=request_body_len,
        request_content_type=request_content_type,
        request_entity=None if request_context is not None else http.request_entity,
        request_multipart=request_context,
        response_body_len=response_body_len,
        response_multipart=response_context,
        resp_mime_types=response_mime_types,
    )
