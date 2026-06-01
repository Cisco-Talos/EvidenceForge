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

"""External parser tests for SOF-ELK Zeek ingestion."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidenceforge.external_parsers.sof_elk_zeek import (
    ZEEK_LOG_SPECS,
    SofElkHarnessError,
    SofElkParserError,
    find_container_runtime,
    run_sof_elk_zeek_parser,
)
from tests.external_parser.sample_data import write_all_type_zeek_sample

pytestmark = pytest.mark.external_parser


def test_sof_elk_parses_every_generated_zeek_type(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    data_dir = _generate_all_type_zeek_sample(tmp_path / "generated")

    result = run_sof_elk_zeek_parser(
        data_dir,
        tmp_path / "harness",
        runtime=runtime,
    )

    assert result.logstash_config_tested
    assert result.manifest.expected_counts == {spec.log_type: 1 for spec in ZEEK_LOG_SPECS}
    for spec in ZEEK_LOG_SPECS:
        assert len(result.events_by_type[spec.log_type]) == 1


def test_sof_elk_reports_corrupted_zeek_json(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    source_dir = tmp_path / "source" / "sensor-a"
    source_dir.mkdir(parents=True)
    (source_dir / "conn.json").write_text(
        '{"ts":"1742036100.000000","uid":"BROKEN",\n',
        encoding="utf-8",
    )

    with pytest.raises(SofElkParserError, match="SOF-ELK parser validation failed"):
        run_sof_elk_zeek_parser(
            tmp_path / "source",
            tmp_path / "work",
            runtime=runtime,
        )


def _runtime_or_skip() -> str:
    try:
        return find_container_runtime()
    except SofElkHarnessError as exc:
        pytest.skip(str(exc))


def _generate_all_type_zeek_sample(output_dir: Path) -> Path:
    return write_all_type_zeek_sample(output_dir, sensor_hostname="core-zeek")
