# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production rendering boundary for validation fixtures."""

from pathlib import Path

from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes


def render_record(tmp_path: Path, case: dict) -> str:
    from datetime import UTC, datetime

    from evidenceforge.formats.loader import load_format

    name = case["format"]
    definition = load_format(name)
    fields = dict(case["fields"])
    for key in ("timestamp", "TimeCreated", "ts"):
        if isinstance(fields.get(key), str):
            fields[key] = datetime.fromisoformat(fields[key].replace("Z", "+00:00"))
    if name == "ecar":
        fields["timestamp"] = fields.pop("timestamp_ms") / 1000
    if name in {"snort_alert", "proxy_access", "web_access", "bash_history"}:
        if isinstance(fields.get("timestamp"), (int, float)):
            fields["timestamp"] = datetime.fromtimestamp(fields["timestamp"], UTC)
    if name == "proxy_access":
        fields.update(method="GET", url="http://example/", protocol="HTTP/1.1", sc_bytes=1)
    if name == "zeek_smb_files":
        for key in ("size", "prev_name", "fuid"):
            fields.setdefault(key, None)
    if case.get("variant") == "process_creation":
        fields.setdefault("TargetUserSid", "S-1-0-0")
    path = tmp_path / (name + definition.output.file_extension)
    emitter = _build_emitter_classes()[name](definition, path, threaded=False)
    try:
        raw = (
            emitter._prepare_event(fields)["rendered"]
            if name == "bash_history"
            else emitter._render_alert(fields)
            if name == "snort_alert"
            else emitter._render_event(fields)
        )
        return raw
    finally:
        emitter.close()
