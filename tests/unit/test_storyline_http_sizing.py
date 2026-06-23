# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for authored storyline HTTP response-size decisions."""

import random

from evidenceforge.generation.activity.http_content import response_size_for_status
from evidenceforge.generation.engine.storyline import _storyline_http_response_body_len
from evidenceforge.models.scenario import BeaconEventSpec, ConnectionEventSpec


def test_connection_zip_404_uses_error_page_size_not_asset_size() -> None:
    """Authored HTTP connection errors should not inherit download-scale URI sizing."""
    spec = ConnectionEventSpec(
        dst_ip="192.168.101.14",
        dst_port=80,
        service="http",
        hostname="halcyon-grants.org",
        method="GET",
        uri="/backup.zip",
        status_code=404,
    )

    body_len = _storyline_http_response_body_len(
        spec=spec,
        rng=random.Random(1234),
        method=spec.method or "GET",
        uri=spec.uri or "/",
        host=spec.hostname or spec.dst_ip,
        is_c2_http=False,
        use_connection_path_hints=True,
    )

    assert body_len == response_size_for_status(404, "halcyon-grants.org", "/backup.zip")
    assert 420 <= body_len <= 1800


def test_connection_resp_bytes_controls_http_body_when_body_override_absent() -> None:
    """HTTP authors can pin access-log body bytes with resp_bytes."""
    spec = ConnectionEventSpec(
        dst_ip="192.168.101.14",
        dst_port=80,
        service="http",
        hostname="halcyon-grants.org",
        method="GET",
        uri="/backup.zip",
        status_code=404,
        resp_bytes=548,
    )

    body_len = _storyline_http_response_body_len(
        spec=spec,
        rng=random.Random(1234),
        method=spec.method or "GET",
        uri=spec.uri or "/",
        host=spec.hostname or spec.dst_ip,
        is_c2_http=False,
        use_connection_path_hints=True,
    )

    assert body_len == 548


def test_connection_response_body_len_takes_precedence_over_resp_bytes() -> None:
    """Dedicated HTTP body override should win over connection payload bytes."""
    spec = ConnectionEventSpec(
        dst_ip="192.168.101.14",
        dst_port=80,
        service="http",
        hostname="halcyon-grants.org",
        method="GET",
        uri="/backup.zip",
        status_code=404,
        response_body_len=612,
        resp_bytes=548,
    )

    body_len = _storyline_http_response_body_len(
        spec=spec,
        rng=random.Random(1234),
        method=spec.method or "GET",
        uri=spec.uri or "/",
        host=spec.hostname or spec.dst_ip,
        is_c2_http=False,
        use_connection_path_hints=True,
    )

    assert body_len == 612


def test_beacon_zip_404_uses_error_page_size_not_asset_size() -> None:
    """Authored HTTP beacon errors should use the same status-aware body sizing."""
    spec = BeaconEventSpec(
        dst_ip="192.168.101.14",
        dst_port=80,
        service="http",
        hostname="halcyon-grants.org",
        interval="1m",
        count=1,
        method="GET",
        uri="/backup.zip",
        status_code=404,
    )

    body_len = _storyline_http_response_body_len(
        spec=spec,
        rng=random.Random(1234),
        method=spec.method or "GET",
        uri=spec.uri or "/",
        host=spec.hostname or spec.dst_ip,
        is_c2_http=False,
        use_connection_path_hints=False,
    )

    assert body_len == response_size_for_status(404, "halcyon-grants.org", "/backup.zip")
    assert 420 <= body_len <= 1800
