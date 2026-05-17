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

"""Output target policy and marker helpers.

Scenario YAML names canonical EvidenceForge formats such as ``syslog`` and
``windows_event_security``. The output target controls only the source-native
file shape rendered on disk for those canonical formats.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

OUTPUT_TARGET_FILENAME = "OUTPUT_TARGET.txt"


class OutputTarget(StrEnum):
    """Supported generated-output consumers."""

    DEFAULT = "default"
    SOF_ELK = "sof-elk"


@dataclass(frozen=True)
class TargetFormatPolicy:
    """Rendering policy for one canonical EvidenceForge format."""

    format_name: str
    default_variant: str
    sof_elk_variant: str
    third_party_parser_support: bool = True
    notes: str = ""

    @property
    def target_dependent(self) -> bool:
        """Return whether the on-disk file shape changes by output target."""
        return self.default_variant != self.sof_elk_variant


FORMAT_TARGET_POLICIES: dict[str, TargetFormatPolicy] = {
    "windows_event_security": TargetFormatPolicy(
        "windows_event_security",
        default_variant="xml",
        sof_elk_variant="snare_syslog",
        notes="SOF-ELK consumes Windows Security through Snare-over-syslog.",
    ),
    "windows_event_sysmon": TargetFormatPolicy(
        "windows_event_sysmon",
        default_variant="xml",
        sof_elk_variant="snare_syslog",
        notes="SOF-ELK consumes Sysmon through the same Snare-over-syslog family.",
    ),
    "zeek_conn": TargetFormatPolicy("zeek_conn", "ndjson", "ndjson"),
    "zeek_dns": TargetFormatPolicy("zeek_dns", "ndjson", "ndjson"),
    "zeek_http": TargetFormatPolicy("zeek_http", "ndjson", "ndjson"),
    "zeek_ssl": TargetFormatPolicy("zeek_ssl", "ndjson", "ndjson"),
    "zeek_files": TargetFormatPolicy("zeek_files", "ndjson", "ndjson"),
    "zeek_dhcp": TargetFormatPolicy("zeek_dhcp", "ndjson", "ndjson"),
    "zeek_ntp": TargetFormatPolicy("zeek_ntp", "ndjson", "ndjson"),
    "zeek_weird": TargetFormatPolicy("zeek_weird", "ndjson", "ndjson"),
    "zeek_x509": TargetFormatPolicy("zeek_x509", "ndjson", "ndjson"),
    "zeek_ocsp": TargetFormatPolicy("zeek_ocsp", "ndjson", "ndjson"),
    "zeek_pe": TargetFormatPolicy("zeek_pe", "ndjson", "ndjson"),
    "zeek_packet_filter": TargetFormatPolicy("zeek_packet_filter", "ndjson", "ndjson"),
    "zeek_reporter": TargetFormatPolicy("zeek_reporter", "ndjson", "ndjson"),
    "ecar": TargetFormatPolicy(
        "ecar",
        "json",
        "json",
        third_party_parser_support=False,
        notes="No stable third-party standard parser target.",
    ),
    "syslog": TargetFormatPolicy(
        "syslog",
        default_variant="rfc5424_flat",
        sof_elk_variant="rfc3164_year_partitioned",
    ),
    "bash_history": TargetFormatPolicy(
        "bash_history",
        "bash_history",
        "bash_history",
        third_party_parser_support=False,
        notes="Shell history has no stable third-party parser contract.",
    ),
    "snort_alert": TargetFormatPolicy("snort_alert", "fast_alert", "fast_alert"),
    "cisco_asa": TargetFormatPolicy(
        "cisco_asa",
        default_variant="flat_syslog",
        sof_elk_variant="year_partitioned_syslog",
    ),
    "web_access": TargetFormatPolicy("web_access", "w3c_extended", "w3c_extended"),
    "proxy_access": TargetFormatPolicy("proxy_access", "w3c_extended", "w3c_extended"),
}


def normalize_output_target(value: str | OutputTarget | None) -> OutputTarget:
    """Return a normalized output target or raise ``ValueError``."""
    if value is None:
        return OutputTarget.DEFAULT
    if isinstance(value, OutputTarget):
        return value
    normalized = str(value).strip().lower()
    try:
        return OutputTarget(normalized)
    except ValueError as exc:
        valid = ", ".join(target.value for target in OutputTarget)
        raise ValueError(f"invalid output target {value!r}; expected one of: {valid}") from exc


def write_output_target_marker(root_dir: Path, target: str | OutputTarget | None) -> Path:
    """Write ``OUTPUT_TARGET.txt`` under a scenario/output root directory."""
    normalized = normalize_output_target(target)
    root_dir.mkdir(parents=True, exist_ok=True)
    marker = root_dir / OUTPUT_TARGET_FILENAME
    marker.write_text(f"{normalized.value}\n", encoding="utf-8")
    return marker


def read_output_target_marker(path: Path) -> OutputTarget:
    """Read output target metadata for a generated dataset.

    ``path`` may be either the scenario/output root or its ``data/`` directory.
    Missing markers are treated as legacy/default output.
    """
    path = path.resolve()
    candidates = [path / OUTPUT_TARGET_FILENAME]
    if path.name == "data":
        candidates.append(path.parent / OUTPUT_TARGET_FILENAME)
    else:
        candidates.append(path / "data" / OUTPUT_TARGET_FILENAME)

    for marker in candidates:
        if not marker.exists():
            continue
        value = marker.read_text(encoding="utf-8").strip()
        return normalize_output_target(value or None)
    return OutputTarget.DEFAULT


def is_sof_elk_target(target: str | OutputTarget | None) -> bool:
    """Return whether *target* selects SOF-ELK-compatible render variants."""
    return normalize_output_target(target) == OutputTarget.SOF_ELK


def target_dependent_formats() -> frozenset[str]:
    """Return canonical formats whose generated file shape depends on target."""
    return frozenset(
        name for name, policy in FORMAT_TARGET_POLICIES.items() if policy.target_dependent
    )


def external_parser_unsupported_formats() -> frozenset[str]:
    """Return formats intentionally outside the third-party parser validation lane."""
    return frozenset(
        name
        for name, policy in FORMAT_TARGET_POLICIES.items()
        if not policy.third_party_parser_support
    )
