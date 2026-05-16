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

"""Tests for external parser validation documentation."""

from __future__ import annotations

from pathlib import Path

from evidenceforge.external_parsers.tag_policy import (
    TAG_POLICY_RULES,
    ParserTagDisposition,
)


def test_ignored_parser_tag_policy_is_documented() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    doc = (repo_root / "docs" / "external-parser-validation" / "ignored-parser-tags.md").read_text(
        encoding="utf-8"
    )

    ignored_rules = [
        rule
        for rule in TAG_POLICY_RULES
        if rule.disposition == ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT
    ]

    assert ignored_rules
    for rule in ignored_rules:
        assert f"`{rule.tag}`" in doc
        assert f"`{rule.validator}`" in doc
        assert f"`{rule.log_type}`" in doc
