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

"""Shared parser-tag severity policy for external parser harnesses."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

SOF_ELK_ZEEK_VALIDATOR = "sof-elk-zeek"
SOF_ELK_CISCO_ASA_VALIDATOR = "sof-elk-cisco-asa"
SOF_ELK_WEB_ACCESS_VALIDATOR = "sof-elk-web-access"
SOF_ELK_SYSLOG_VALIDATOR = "sof-elk-syslog"

_DEFAULT_FATAL_TAGS = frozenset(
    {
        "_dateparsefailure",
        "_jsonparsefailure",
        "_grokparsefailure",
        "_rubyexception",
    }
)
_DEFAULT_FATAL_PREFIXES = ("_grokparsefail",)


class ParserTagDisposition(StrEnum):
    """How external parser validation should treat a parser-emitted tag."""

    FATAL = "fatal"
    IGNORED_OPTIONAL_ENRICHMENT = "ignored_optional_enrichment"


@dataclass(frozen=True)
class ParserTagRule:
    """Explicit severity rule for a parser-emitted tag."""

    validator: str
    log_type: str
    tag: str
    disposition: ParserTagDisposition
    source: str
    reason: str


@dataclass(frozen=True)
class ParserTagClassification:
    """Parser tags grouped by validation disposition."""

    fatal: tuple[str, ...]
    ignored_optional_enrichment: tuple[str, ...]


TAG_POLICY_RULES: tuple[ParserTagRule, ...] = (
    ParserTagRule(
        validator=SOF_ELK_ZEEK_VALIDATOR,
        log_type="zeek_dns",
        tag="_grokparsefail_6200-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6200-zeek_dns.conf",
        reason=(
            "Optional dns.answers.ip extraction from dns.answers.data. Non-address DNS "
            "answer types such as NS, PTR, MX, and SOA remain valid parsed records."
        ),
    ),
    ParserTagRule(
        validator=SOF_ELK_CISCO_ASA_VALIDATOR,
        log_type="cisco_asa",
        tag="_grokparsefailure_1100-03",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/1100-preprocess-syslog.conf",
        reason=(
            "Optional archive path-year extraction after a BSD/RFC3164 syslog timestamp. "
            "Cisco ASA parsing can still succeed without a year-bearing directory name."
        ),
    ),
    ParserTagRule(
        validator=SOF_ELK_WEB_ACCESS_VALIDATOR,
        log_type="web_access",
        tag="_grokparsefail_8110-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/8110-postprocess-httpd.conf",
        reason=(
            "Optional page/not-page URL path classification after the HTTP access "
            "record has already been parsed."
        ),
    ),
    ParserTagRule(
        validator=SOF_ELK_SYSLOG_VALIDATOR,
        log_type="syslog",
        tag="_grokparsefailure_1100-03",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/1100-preprocess-syslog.conf",
        reason=(
            "Optional archive path-year extraction after a BSD/RFC3164 syslog timestamp. "
            "Syslog framing and source-specific parsing can still succeed without a "
            "year-bearing directory name."
        ),
    ),
    ParserTagRule(
        validator=SOF_ELK_SYSLOG_VALIDATOR,
        log_type="syslog",
        tag="_grokparsefail_6018-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6018-cisco_asa.conf",
        reason=(
            "SOF-ELK's Cisco ASA filter opportunistically runs on unparsed syslog "
            "records. A miss on ordinary Linux syslog does not mean the syslog "
            "record failed to parse."
        ),
    ),
)
_RULES_BY_KEY = {(rule.validator, rule.log_type, rule.tag): rule for rule in TAG_POLICY_RULES}


def classify_parser_tags(
    *,
    validator: str,
    log_type: str,
    tags: list[Any],
) -> ParserTagClassification:
    """Classify parser tags into validation-fatal and intentionally ignored groups."""
    fatal: list[str] = []
    ignored_optional_enrichment: list[str] = []
    for tag in _unique_tag_strings(tags):
        disposition = parser_tag_disposition(
            validator=validator,
            log_type=log_type,
            tag=tag,
        )
        if disposition == ParserTagDisposition.FATAL:
            fatal.append(tag)
        elif disposition == ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT:
            ignored_optional_enrichment.append(tag)
    return ParserTagClassification(
        fatal=tuple(sorted(fatal)),
        ignored_optional_enrichment=tuple(sorted(ignored_optional_enrichment)),
    )


def parser_tag_disposition(
    *,
    validator: str,
    log_type: str,
    tag: str,
) -> ParserTagDisposition | None:
    """Return the validation disposition for a parser tag, if the tag is actionable."""
    rule = _RULES_BY_KEY.get((validator, log_type, tag))
    if rule:
        return rule.disposition
    if tag in _DEFAULT_FATAL_TAGS or any(
        tag.startswith(prefix) for prefix in _DEFAULT_FATAL_PREFIXES
    ):
        return ParserTagDisposition.FATAL
    return None


def _unique_tag_strings(tags: list[Any]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(tag) for tag in tags))
