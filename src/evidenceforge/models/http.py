# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public HTTP entity authoring models shared by scenarios and configuration."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_HTTP_ENTITY_BYTES = 10_000_000_000
_MIME_TYPE_RE = re.compile(r"[^/\s]+/[^/\s]+")
_BOUNDARY_RE = re.compile(r"[0-9A-Za-z'()+_,./:=? -]{1,70}")


class HttpMultipartPartSpec(BaseModel):
    """One ordered leaf or nested container in an authored multipart entity."""

    name: str | None = None
    value: str | None = None
    body_len: int | None = Field(default=None, ge=0, le=MAX_HTTP_ENTITY_BYTES)
    local_source_path: str | None = None
    filename: str | None = None
    filename_star: str | None = None
    content_type: str | None = None
    content_type_name: str | None = None
    detected_mime_type: str | None = None
    content_length: int | None = Field(default=None, ge=0, le=MAX_HTTP_ENTITY_BYTES)
    transfer_encoding: Literal["binary", "7bit", "8bit", "base64", "quoted-printable"] = "binary"
    parts: list[HttpMultipartPartSpec] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_shape(self) -> HttpMultipartPartSpec:
        """Reject ambiguous leaf/container definitions and malformed metadata."""

        if self.name is not None and not self.name:
            raise ValueError("multipart part name must not be empty")
        if self.filename is not None and not self.filename:
            raise ValueError("multipart filename must not be empty")
        if self.filename_star is not None and not self.filename_star:
            raise ValueError("multipart filename_star must not be empty")
        if self.content_type_name is not None and not self.content_type_name:
            raise ValueError("multipart content_type_name must not be empty")
        for field_name, mime_type in (
            ("content_type", self.content_type),
            ("detected_mime_type", self.detected_mime_type),
        ):
            if field_name == "detected_mime_type" and mime_type == "":
                continue
            if mime_type is not None and _MIME_TYPE_RE.fullmatch(mime_type) is None:
                raise ValueError(f"{field_name} must be a MIME type such as application/json")

        if self.parts:
            if any(
                value is not None
                for value in (
                    self.value,
                    self.body_len,
                    self.local_source_path,
                    self.filename,
                    self.filename_star,
                    self.content_type_name,
                    self.detected_mime_type,
                    self.content_length,
                )
            ):
                raise ValueError(
                    "nested multipart containers cannot define leaf content, paths, filenames, "
                    "or detected MIME"
                )
            if self.transfer_encoding != "binary":
                raise ValueError("nested multipart containers must use binary transfer encoding")
            if self.content_type not in {"multipart/form-data", "multipart/mixed"}:
                raise ValueError("nested multipart containers require a supported multipart type")
            return self

        if self.value is not None and self.body_len is not None:
            raise ValueError("multipart leaf must not define both value and body_len")
        if self.value is None and self.body_len is None and not self.local_source_path:
            raise ValueError("multipart leaf requires value, body_len, or local_source_path")
        known_size = len(self.value.encode()) if self.value is not None else self.body_len
        if self.content_length is not None and known_size is not None:
            if self.content_length != known_size:
                raise ValueError("multipart part content_length must equal decoded leaf size")
        return self


class HttpMultipartEntitySpec(BaseModel):
    """One complete authored request- or response-side multipart HTTP entity."""

    media_type: Literal["multipart/form-data", "multipart/mixed"] = "multipart/form-data"
    boundary: str | None = None
    parts: list[HttpMultipartPartSpec] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_entity(self) -> HttpMultipartEntitySpec:
        """Validate boundary syntax and form-data disposition requirements."""

        if self.boundary is not None:
            if (
                _BOUNDARY_RE.fullmatch(self.boundary) is None
                or self.boundary.endswith(" ")
                or "\r" in self.boundary
                or "\n" in self.boundary
            ):
                raise ValueError(
                    "multipart boundary must be 1-70 MIME boundary characters and not end in space"
                )
        if self.media_type == "multipart/form-data":
            missing = [index for index, part in enumerate(self.parts) if not part.name]
            if missing:
                raise ValueError(
                    "direct multipart/form-data parts require name; missing at indices "
                    + ", ".join(str(index) for index in missing)
                )
        return self
