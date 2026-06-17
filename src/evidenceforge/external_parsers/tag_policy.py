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

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

SOF_ELK_ZEEK_VALIDATOR = "sof-elk-zeek"
SOF_ELK_CISCO_ASA_VALIDATOR = "sof-elk-cisco-asa"
SOF_ELK_WEB_ACCESS_VALIDATOR = "sof-elk-web-access"
SOF_ELK_SYSLOG_VALIDATOR = "sof-elk-syslog"
SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR = "sof-elk-windows-security-snare"
SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR = "sof-elk-windows-sysmon-snare"

_DEFAULT_FATAL_TAGS = frozenset(
    {
        "_dateparsefailure",
        "_jsonparsefailure",
        "_grokparsefailure",
        "_rubyexception",
    }
)
_DEFAULT_FATAL_PREFIXES = ("_grokparsefail",)
_SIGNED_32BIT_UNIX_MAX = 2_147_483_647
_X509_UTCTIME_MAX_EPOCH = 2_524_607_999
JsonMapping = Mapping[str, Any]
EventPredicate = Callable[[JsonMapping], bool]


class ParserTagDisposition(StrEnum):
    """How external parser validation should treat a parser-emitted tag."""

    FATAL = "fatal"
    IGNORED_OPTIONAL_ENRICHMENT = "ignored_optional_enrichment"
    IGNORED_PARSER_LIMITATION = "ignored_parser_limitation"


@dataclass(frozen=True)
class ParserTagRule:
    """Explicit severity rule for a parser-emitted tag."""

    validator: str
    log_type: str
    tag: str
    disposition: ParserTagDisposition
    source: str
    reason: str
    event_predicate: EventPredicate | None = None


@dataclass(frozen=True)
class ParserTagClassification:
    """Parser tags grouped by validation disposition."""

    fatal: tuple[str, ...]
    ignored_optional_enrichment: tuple[str, ...]
    ignored_parser_limitation: tuple[str, ...]


def _is_parsed_sshd_pam_session_open_close(event: JsonMapping) -> bool:
    tags = event.get("tags", [])
    if not isinstance(tags, list):
        return False
    tag_set = {str(tag) for tag in tags}
    if not {"got_pam", "parse_done"}.issubset(tag_set):
        return False
    if _get_path(event, "log.syslog.appname") != "sshd":
        return False

    pam_event = _get_path(event, "pam.event")
    if (
        _get_path(event, "pam.module") == "pam_unix"
        and _get_path(event, "pam.service") == "sshd"
        and _get_path(event, "pam.sessiontype") == "session"
        and pam_event in {"opened", "closed"}
    ):
        return True

    message = str(event.get("message") or _get_path(event, "event.original") or "")
    return (
        "pam_unix(sshd:session): session opened for user " in message
        or "pam_unix(sshd:session): session closed for user " in message
    )


def _is_parsed_pam_auth_failure(event: JsonMapping) -> bool:
    tags = event.get("tags", [])
    if not isinstance(tags, list):
        return False
    tag_set = {str(tag) for tag in tags}
    if not {"got_pam", "parse_done"}.issubset(tag_set):
        return False
    if _get_path(event, "pam.module") != "pam_unix":
        return False
    if _get_path(event, "pam.sessiontype") != "auth":
        return False
    message = str(event.get("message") or _get_path(event, "event.original") or "")
    return (
        message.startswith("pam_unix(") and ":auth): authentication failure; " in message
    ) or message.startswith("authentication failure; ")


def _is_parsed_snare_windows_event(event: JsonMapping) -> bool:
    tags = event.get("tags", [])
    if not isinstance(tags, list):
        return False
    tag_set = {str(tag) for tag in tags}
    if not {"snare_log", "parse_done"}.issubset(tag_set):
        return False
    return all(
        _get_path(event, path) not in (None, "")
        for path in (
            "winlog.event_id",
            "winlog.provider_name",
            "winlog.channel",
            "winlog.computer_name",
        )
    )


def _is_zeek_dns_non_address_answer_type(event: JsonMapping) -> bool:
    question_type = _get_path(event, "dns.question.type")
    if question_type in (None, ""):
        return False
    return str(question_type).strip().upper() not in {"A", "AAAA"}


def _is_zeek_x509_post_2038_date_limitation(event: JsonMapping) -> bool:
    original = _get_path(event, "event.original")
    if not isinstance(original, str):
        return False
    try:
        raw = json.loads(original)
    except json.JSONDecodeError:
        return False
    if not isinstance(raw, Mapping):
        return False

    epochs: list[int | float] = []
    for path in ("certificate.not_valid_before", "certificate.not_valid_after"):
        epoch = _coerce_epoch(raw.get(path))
        if epoch is None:
            return False
        epochs.append(epoch)
    return any(_SIGNED_32BIT_UNIX_MAX < epoch <= _X509_UTCTIME_MAX_EPOCH for epoch in epochs)


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
        event_predicate=_is_zeek_dns_non_address_answer_type,
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
        tag="_grokparsefail_6018-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6018-cisco_asa.conf",
        reason=(
            "SOF-ELK's Cisco ASA filter opportunistically runs on unparsed syslog "
            "records. A miss on ordinary Linux syslog does not mean the syslog "
            "record failed to parse."
        ),
    ),
    ParserTagRule(
        validator=SOF_ELK_SYSLOG_VALIDATOR,
        log_type="syslog",
        tag="_grokparsefailure_6015-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6015-sshd.conf and 6016-pam.conf",
        reason=(
            "SOF-ELK's SSHD filter runs on all appname=sshd records before the "
            "PAM filter. Parsed pam_unix(sshd:session) open/close records can "
            "therefore retain an SSHD grok miss even though the PAM record parsed."
        ),
        event_predicate=_is_parsed_sshd_pam_session_open_close,
    ),
    ParserTagRule(
        validator=SOF_ELK_SYSLOG_VALIDATOR,
        log_type="syslog",
        tag="_grokparsefail_6016-02",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6016-pam.conf",
        reason=(
            "SOF-ELK parses the pam_unix(...:auth) envelope and marks the event "
            "parse_done, but its second-stage PAM remainder enrichment only covers "
            "session open/close and user lookup errors, not common authentication "
            "failure detail fields."
        ),
        event_predicate=_is_parsed_pam_auth_failure,
    ),
    ParserTagRule(
        validator=SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
        log_type="windows_event_security_snare",
        tag="_grokparsefail_6010-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6010-snare.conf",
        reason=(
            "Second-stage expanded-data enrichment can leave a grok miss even after "
            "the Snare CSV record parsed and required winlog fields were normalized."
        ),
        event_predicate=_is_parsed_snare_windows_event,
    ),
    ParserTagRule(
        validator=SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
        log_type="windows_event_sysmon_snare",
        tag="_grokparsefail_6010-01",
        disposition=ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT,
        source="SOF-ELK configfiles/6010-snare.conf",
        reason=(
            "Second-stage expanded-data enrichment can leave a grok miss even after "
            "the Snare CSV record parsed and required winlog fields were normalized."
        ),
        event_predicate=_is_parsed_snare_windows_event,
    ),
    ParserTagRule(
        validator=SOF_ELK_ZEEK_VALIDATOR,
        log_type="zeek_x509",
        tag="_dateparsefailure",
        disposition=ParserTagDisposition.IGNORED_PARSER_LIMITATION,
        source="SOF-ELK configfiles/6204-zeek_x509.conf",
        reason=(
            "Zeek x509.log records store certificate validity as Unix epoch seconds. "
            "RFC 5280 permits UTCTime validity dates through 2049, but this "
            "SOF-ELK/Logstash date path cannot parse post-2038 epoch values."
        ),
        event_predicate=_is_zeek_x509_post_2038_date_limitation,
    ),
)
_RULES_BY_KEY = {(rule.validator, rule.log_type, rule.tag): rule for rule in TAG_POLICY_RULES}


def classify_parser_tags(
    *,
    validator: str,
    log_type: str,
    tags: list[Any],
    event: JsonMapping | None = None,
) -> ParserTagClassification:
    """Classify parser tags into validation-fatal and intentionally ignored groups."""
    fatal: list[str] = []
    ignored_optional_enrichment: list[str] = []
    ignored_parser_limitation: list[str] = []
    for tag in _unique_tag_strings(tags):
        disposition = parser_tag_disposition(
            validator=validator,
            log_type=log_type,
            tag=tag,
            event=event,
        )
        if disposition == ParserTagDisposition.FATAL:
            fatal.append(tag)
        elif disposition == ParserTagDisposition.IGNORED_OPTIONAL_ENRICHMENT:
            ignored_optional_enrichment.append(tag)
        elif disposition == ParserTagDisposition.IGNORED_PARSER_LIMITATION:
            ignored_parser_limitation.append(tag)
    return ParserTagClassification(
        fatal=tuple(sorted(fatal)),
        ignored_optional_enrichment=tuple(sorted(ignored_optional_enrichment)),
        ignored_parser_limitation=tuple(sorted(ignored_parser_limitation)),
    )


def parser_tag_disposition(
    *,
    validator: str,
    log_type: str,
    tag: str,
    event: JsonMapping | None = None,
) -> ParserTagDisposition | None:
    """Return the validation disposition for a parser tag, if the tag is actionable."""
    rule = _RULES_BY_KEY.get((validator, log_type, tag))
    if rule and (
        rule.event_predicate is None or (event is not None and rule.event_predicate(event))
    ):
        return rule.disposition
    if tag in _DEFAULT_FATAL_TAGS or any(
        tag.startswith(prefix) for prefix in _DEFAULT_FATAL_PREFIXES
    ):
        return ParserTagDisposition.FATAL
    return None


def _get_path(event: JsonMapping, path: str) -> Any:
    value: Any = event
    for part in path.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def _coerce_epoch(value: Any) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _unique_tag_strings(tags: list[Any]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(tag) for tag in tags))
