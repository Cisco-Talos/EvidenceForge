# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Fixture-free contracts for source-native HTTP multipart file analysis."""

import random
from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    HttpContext,
    HttpEntityPartContext,
    HttpMultipartEntityContext,
    HttpWireSpanContext,
)
from evidenceforge.generation.actions.file_transfer import (
    HttpFileTransferActionBundle,
    HttpFileTransferRequest,
)
from evidenceforge.generation.activity.generator import _attach_http_file_transfers
from evidenceforge.generation.activity.http_multipart import (
    build_http_multipart_context,
    encoded_multipart_leaf_size,
)
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.models.http import HttpMultipartEntitySpec
from evidenceforge.models.scenario import (
    BeaconEventSpec,
    BeaconHttpSequenceEntry,
    ConnectionEventSpec,
    WeightedHttpMethodProfile,
)
from tests.network_factories import network_plan

_NOW = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)


def _captured_shape(body_len: int, sizes: list[int]) -> HttpMultipartEntityContext:
    """Build a literal research-derived analyzer shape without an external fixture."""

    envelope_total = body_len - sum(sizes)
    assert envelope_total >= len(sizes) + 1
    envelope_sizes = [1] * len(sizes) + [envelope_total - len(sizes)]
    offset = 0
    spans: list[HttpWireSpanContext] = []
    parts: list[HttpEntityPartContext] = []
    for index, size in enumerate(sizes):
        spans.append(HttpWireSpanContext(kind="envelope", offset=offset, length=1))
        offset += 1
        spans.append(
            HttpWireSpanContext(kind="leaf", offset=offset, length=size, part_path=(index,))
        )
        parts.append(
            HttpEntityPartContext(
                path=(index,),
                decoded_size=size,
                encoded_size=size,
                content_identity=f"research-shape:{body_len}:{index}:{size}",
            )
        )
        offset += size
    spans.append(HttpWireSpanContext(kind="envelope", offset=offset, length=envelope_sizes[-1]))
    return HttpMultipartEntityContext(
        media_type="multipart/form-data",
        boundary="research-boundary",
        body_len=body_len,
        parts=tuple(parts),
        wire_spans=tuple(spans),
    )


def test_research_shapes_keep_envelope_and_leaf_sizes_separate() -> None:
    one_file = _captured_shape(767, [584])
    anonymous = _captured_shape(350, [4, 5, 5])

    assert one_file.body_len == 767
    assert [part.decoded_size for part in one_file.leaf_parts()] == [584]
    assert anonymous.body_len == 350
    assert [part.decoded_size for part in anonymous.leaf_parts()] == [4, 5, 5]


def test_request_multipart_and_ordinary_response_files_coexist() -> None:
    request = _captured_shape(350, [4, 5, 5])
    event = OccurrenceBuilder(
        timestamp=_NOW,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="198.51.100.10",
            dst_port=80,
            protocol="tcp",
            service="http",
            conn_state="SF",
            duration=1.0,
            orig_bytes=700,
            resp_bytes=800,
        ),
        http=HttpContext(
            method="POST",
            host="upload.example",
            uri="/submit",
            request_body_len=350,
            request_multipart=request,
            response_body_len=465,
            resp_mime_types=("application/json",),
        ),
    )

    _attach_http_file_transfers(event, dst_ip="198.51.100.10", rng=random.Random(7))

    transfers = ([event.file_transfer] if event.file_transfer is not None else []) + list(
        event.file_transfers
    )
    assert [transfer.seen_bytes for transfer in transfers if transfer.is_orig] == [4, 5, 5]
    assert [transfer.seen_bytes for transfer in transfers if not transfer.is_orig] == [465]
    assert len(event.http.orig_fuids) == 3
    assert len(event.http.resp_fuids) == 1


def test_bidirectional_multipart_and_multiple_pe_analyses_coexist() -> None:
    request_spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "request",
            "parts": [
                {
                    "name": "first",
                    "body_len": 10_000,
                    "detected_mime_type": "application/x-dosexec",
                },
                {
                    "name": "second",
                    "body_len": 12_000,
                    "detected_mime_type": "application/x-msdownload",
                },
            ],
        }
    )
    response_spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/mixed",
            "boundary": "response",
            "parts": [{"body_len": 9, "detected_mime_type": "application/json"}],
        }
    )
    request = build_http_multipart_context(request_spec, stable_key="request")
    response = build_http_multipart_context(response_spec, stable_key="response")
    event = OccurrenceBuilder(
        timestamp=_NOW,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="198.51.100.10",
            dst_port=80,
            protocol="tcp",
            service="http",
            conn_state="SF",
            duration=2.0,
            orig_bytes=request.body_len + 500,
            resp_bytes=response.body_len + 500,
        ),
        http=HttpContext(
            method="POST",
            host="upload.example",
            uri="/both",
            request_body_len=request.body_len,
            request_multipart=request,
            response_body_len=response.body_len,
            response_multipart=response,
        ),
    )

    _attach_http_file_transfers(event, dst_ip="198.51.100.10", rng=random.Random(8))

    transfers = ([event.file_transfer] if event.file_transfer is not None else []) + list(
        event.file_transfers
    )
    assert len([transfer for transfer in transfers if transfer.is_orig]) == 2
    assert len([transfer for transfer in transfers if not transfer.is_orig]) == 1
    assert len(event.pe_analyses) == 2
    assert {pe.id for pe in event.pe_analyses} == {
        transfer.fuid for transfer in transfers if transfer.is_orig
    }


def test_sparse_vectors_and_fifteen_entry_limit_keep_all_files() -> None:
    parts = [
        {
            "name": f"field-{index}",
            "body_len": index + 1,
            "filename": "only.bin" if index == 3 else None,
            "detected_mime_type": "application/octet-stream" if index == 7 else "",
        }
        for index in range(20)
    ]
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "many-parts",
            "parts": parts,
        }
    )
    multipart = build_http_multipart_context(spec, stable_key="many")
    event = OccurrenceBuilder(
        timestamp=_NOW,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="198.51.100.10",
            dst_port=80,
            protocol="tcp",
            service="http",
            conn_state="SF",
            duration=1.0,
            orig_bytes=multipart.body_len + 500,
        ),
        http=HttpContext(
            method="POST",
            host="upload.example",
            uri="/submit",
            request_body_len=multipart.body_len,
            request_multipart=multipart,
        ),
    )

    _attach_http_file_transfers(event, dst_ip="198.51.100.10", rng=random.Random(9))

    assert len(event.file_transfers) == 20
    assert len(event.http.orig_fuids) == 15
    assert event.http.orig_filenames == ("only.bin",)
    assert event.http.orig_mime_types == ("application/octet-stream",)


@pytest.mark.parametrize(
    ("encoding", "decoded", "encoded"),
    [
        ("binary", 6, 6),
        ("7bit", 6, 6),
        ("8bit", 6, 6),
        ("base64", 6, 8),
        ("quoted-printable", 100, 127),
    ],
)
def test_transfer_encodings_have_distinct_decoded_and_wire_sizes(
    encoding: str, decoded: int, encoded: int
) -> None:
    assert encoded_multipart_leaf_size(decoded, encoding) == encoded


def test_nested_repeated_parts_preserve_discovery_order() -> None:
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "outer",
            "parts": [
                {"name": "item", "value": "first"},
                {
                    "name": "files",
                    "content_type": "multipart/mixed",
                    "parts": [
                        {"body_len": 3, "filename": "a.bin"},
                        {"body_len": 4, "filename": "b.bin"},
                    ],
                },
                {"name": "item", "value": "last"},
            ],
        }
    )

    multipart = build_http_multipart_context(spec, stable_key="nested")

    assert [part.path for part in multipart.leaf_parts()] == [(0,), (1, 0), (1, 1), (2,)]
    assert [part.wire_filename for part in multipart.leaf_parts()] == [
        "",
        "a.bin",
        "b.bin",
        "",
    ]


def test_filename_star_and_content_type_name_fallback_are_resolved() -> None:
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/mixed",
            "boundary": "names",
            "parts": [
                {"body_len": 1, "filename_star": "UTF-8''caf%C3%A9.txt"},
                {
                    "body_len": 1,
                    "content_type": "application/octet-stream",
                    "content_type_name": "fallback.bin",
                },
            ],
        }
    )

    multipart = build_http_multipart_context(spec, stable_key="names")

    assert [part.wire_filename for part in multipart.leaf_parts()] == [
        "café.txt",
        "fallback.bin",
    ]


def test_outer_length_is_an_exact_assertion() -> None:
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "fixed",
            "parts": [{"name": "value", "value": "abc"}],
        }
    )
    actual = build_http_multipart_context(spec, stable_key="exact")

    with pytest.raises(ValueError, match="does not match exact assertion"):
        build_http_multipart_context(
            spec,
            stable_key="exact",
            asserted_body_len=actual.body_len + 1,
        )


def test_42_mib_rar_leaf_keeps_file_size_below_outer_body_size() -> None:
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "rar-boundary",
            "parts": [
                {
                    "name": "archive",
                    "body_len": 42 * 1024 * 1024,
                    "local_source_path": "/tmp/exfildata.rar",
                    "filename": "exfildata.rar",
                    "content_type": "application/vnd.rar",
                }
            ],
        }
    )
    multipart = build_http_multipart_context(spec, stable_key="rar")
    result = HttpFileTransferActionBundle(
        HttpFileTransferRequest(
            host="some.site",
            uri="/uploads/accept-upload",
            dst_ip="198.51.100.44",
            body_len=multipart.body_len,
            mime_types=(),
            timestamp=_NOW,
            is_orig=True,
            multipart=multipart,
        ),
        random.Random(11),
    ).execute()

    assert multipart.body_len > 44_040_192
    assert result.file_transfer.seen_bytes == 44_040_192
    assert result.file_transfer.total_bytes is None
    assert result.file_transfer.filename == "exfildata.rar"
    assert result.file_transfer.mime_type == "application/vnd.rar"


def test_part_content_length_projects_to_file_total_bytes_only() -> None:
    spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/mixed",
            "boundary": "length",
            "parts": [{"body_len": 3, "content_length": 3}],
        }
    )
    multipart = build_http_multipart_context(spec, stable_key="length")
    result = HttpFileTransferActionBundle(
        HttpFileTransferRequest(
            host="example.test",
            uri="/entity",
            dst_ip="198.51.100.5",
            body_len=multipart.body_len,
            mime_types=(),
            timestamp=_NOW,
            is_orig=False,
            multipart=multipart,
        ),
        random.Random(13),
    ).execute()

    assert result.file_transfer.total_bytes == 3
    assert multipart.body_len > 3


def test_curl_form_parsing_solves_one_unknown_file_from_outer_length() -> None:
    command = "curl -F metadata=case-123 -F archive=@/tmp/exfildata.rar http://some.site/u"
    provisional = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "parts": [
                {"name": "metadata", "value": "case-123"},
                {
                    "name": "archive",
                    "body_len": 44_040_192,
                    "local_source_path": "/tmp/exfildata.rar",
                    "filename": "exfildata.rar",
                },
            ],
        }
    )
    expected = build_http_multipart_context(
        provisional, stable_key="curl-form", client_family="curl"
    )

    parsed = StorylineMixin._http_request_multipart_from_command(
        command,
        expected.body_len,
        stable_key="curl-form",
    )

    assert parsed is not None
    assert [part.decoded_size for part in parsed.leaf_parts()] == [8, 44_040_192]
    assert parsed.leaf_parts()[1].local_source_path == "/tmp/exfildata.rar"
    assert parsed.leaf_parts()[1].wire_filename == "exfildata.rar"


def test_multiple_unresolved_curl_files_are_rejected() -> None:
    with pytest.raises(ValueError, match="multiple unresolved local file sizes"):
        StorylineMixin._http_request_multipart_from_command(
            "curl -F a=@/tmp/a.bin -F b=@/tmp/b.bin http://some.site/u",
            1000,
        )


def test_public_connection_and_beacon_schemas_accept_bidirectional_multipart() -> None:
    multipart = {
        "media_type": "multipart/mixed",
        "parts": [{"body_len": 12, "detected_mime_type": "application/octet-stream"}],
    }

    connection = ConnectionEventSpec(
        dst_ip="198.51.100.4",
        dst_port=80,
        request_multipart=multipart,
        response_multipart=multipart,
    )
    beacon = BeaconEventSpec(
        dst_ip="198.51.100.4",
        dst_port=80,
        interval="1m",
        count=2,
        request_multipart=multipart,
        http_sequence=[BeaconHttpSequenceEntry(response_multipart=multipart)],
    )

    assert connection.request_multipart is not None
    assert connection.response_multipart is not None
    assert beacon.request_multipart is not None
    assert beacon.http_sequence[0].response_multipart is not None


def test_profile_multipart_rejects_competing_body_size_range() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        WeightedHttpMethodProfile(
            request_body_bytes=[100, 200],
            request_multipart={
                "media_type": "multipart/form-data",
                "parts": [{"name": "value", "value": "abc"}],
            },
        )


def test_span_aware_loss_can_land_in_envelope_without_truncating_leaf(monkeypatch) -> None:
    multipart = build_http_multipart_context(
        HttpMultipartEntitySpec.model_validate(
            {
                "media_type": "multipart/form-data",
                "boundary": "loss",
                "parts": [{"name": "value", "body_len": 100}],
            }
        ),
        stable_key="loss",
    )
    result = HttpFileTransferActionBundle(
        HttpFileTransferRequest(
            host="example.test",
            uri="/submit",
            dst_ip="198.51.100.5",
            body_len=multipart.body_len,
            mime_types=(),
            timestamp=_NOW,
            is_orig=True,
            multipart=multipart,
        ),
        random.Random(15),
    ).execute()
    event = OccurrenceBuilder(
        timestamp=_NOW,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="198.51.100.5",
            dst_port=80,
            protocol="tcp",
            service="http",
            conn_state="SF",
            zeek_uid="CLoss",
        ),
        http=HttpContext(
            method="POST",
            request_body_len=multipart.body_len,
            request_multipart=multipart,
        ),
        file_transfers=list(result.file_transfers),
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation._stable_seed", lambda _value: 0
    )

    seen, missing = NetworkObservationPlanner._observed_multipart_leaf(
        event,
        result.file_transfer,
        (multipart.body_len - 1) / multipart.body_len,
    )

    assert (seen, missing) == (100, 0)
