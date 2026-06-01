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

"""Opt-in Splunk external parser smoke test."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from evidenceforge.external_parsers.splunk import (
    SPLUNK_SOURCE_SPECS,
    CimMode,
    run_splunk_parser,
)
from evidenceforge.output_targets import write_output_target_marker
from tests.external_parser.sample_data import write_splunk_multifamily_dataset

pytestmark = pytest.mark.external_parser


@pytest.mark.skipif(
    os.environ.get("EFORGE_ACCEPT_SPLUNK_LICENSE") != "1",
    reason="set EFORGE_ACCEPT_SPLUNK_LICENSE=1 to run the Splunk container smoke test",
)
def test_splunk_harness_ingests_multifamily_parser_dataset(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    write_output_target_marker(tmp_path, "splunk")
    write_splunk_multifamily_dataset(data_dir)

    result = run_splunk_parser(
        data_dir,
        tmp_path / "work",
        cim_mode=CimMode.OFF,
        accept_splunk_license=True,
        timeout_seconds=600,
        runtime="docker",
    )

    expected_sourcetypes = {spec.sourcetype for spec in SPLUNK_SOURCE_SPECS}
    assert expected_sourcetypes.issubset(result.observed_counts)
    assert result.manifest.expected_counts == {spec.format_name: 1 for spec in SPLUNK_SOURCE_SPECS}
