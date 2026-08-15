# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Cross-platform integration coverage for Linux SMB clients and Samba servers."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.packs import PackRepository
from evidenceforge.evaluation.parsers.syslog import SyslogParser
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.resource_forecast import (
    ForecastRange,
    ResourceForecast,
    ResourceSnapshot,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml, write_yaml
from evidenceforge.validation import ScenarioValidator

SCENARIO_PATH = Path(__file__).parent.parent / "fixtures" / "scenarios" / "smb-linux-matrix.yaml"


def _forecast(output: Path) -> ResourceForecast:
    """Return a non-blocking forecast for integration-only generation."""

    available = 64 * 1024**3
    return ResourceForecast(
        calibration_version=1,
        calibration_label="test",
        memory=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        final_output=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        disk=ForecastRange(lower_bytes=1, expected_bytes=1, upper_bytes=1),
        snapshot=ResourceSnapshot(
            total_memory_bytes=available,
            available_memory_bytes=available,
            free_swap_bytes=available,
            free_disk_bytes=available,
            disk_path=str(output),
        ),
    )


def _json_records(output: Path, filename: str) -> list[dict]:
    records: list[dict] = []
    for path in output.rglob(filename):
        records.extend(
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
        )
    return records


def _syslog_records(output: Path) -> list[dict]:
    records: list[dict] = []
    parser = SyslogParser()
    for path in output.rglob("syslog.log"):
        records.extend(record.fields for record in parser.parse_file(path))
    return records


def _ground_truth_event(output: Path, storyline_id: str) -> dict:
    document = json.loads((output / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    return next(
        event
        for event in document["events"]
        if event.get("kind") == "smb_activity" and event.get("storyline_id") == storyline_id
    )


def _scenario_data(*storyline_ids: str) -> dict:
    data = load_yaml(SCENARIO_PATH)
    if storyline_ids:
        selected = set(storyline_ids)
        data["storyline"] = [event for event in data["storyline"] if event.get("id") in selected]
    return data


def _fixed_cross_server_mapping_data() -> dict:
    """Return one cross-server copy with a distinct fixed credential on each leg."""

    data = _scenario_data("windows-to-linux-copy")
    data["environment"]["service_accounts"] = ["svc_source", "svc_destination"]
    data["environment"]["storage"]["mappings"] = [
        {
            "id": "source-fixed",
            "share": "FS-WIN-01.documents",
            "audience": {"users": ["linux_user"], "systems": ["LNX-CLIENT-01"]},
            "mount": "/mnt/source-fixed",
            "credential_mode": "fixed",
            "principal": "svc_source",
            "lifecycle": "persistent",
        },
        {
            "id": "destination-fixed",
            "share": "SAMBA-01.finance",
            "audience": {"users": ["linux_user"], "systems": ["LNX-CLIENT-01"]},
            "mount": "/mnt/destination-fixed",
            "credential_mode": "fixed",
            "principal": "svc_destination",
            "lifecycle": "persistent",
        },
    ]
    data["environment"]["storage"]["servers"][0]["shares"][0]["access"] = {
        "modify": ["svc_destination"]
    }
    data["environment"]["storage"]["servers"][1]["shares"][0]["access"] = {"read": ["svc_source"]}
    data["storyline"][0]["events"][0]["mapping"] = "SOURCE-FIXED"
    return data


def _generate(data: dict, output: Path) -> None:
    GenerationEngine(
        Scenario(**data),
        output,
        resource_forecast=_forecast(output),
    ).generate()


@pytest.fixture(scope="module")
def linux_matrix_output(tmp_path_factory: pytest.TempPathFactory) -> Path:
    output = tmp_path_factory.mktemp("smb-linux-matrix")
    _generate(_scenario_data(), output)
    return output


def test_cross_platform_smb_matrix_uses_source_native_server_evidence(
    linux_matrix_output: Path,
) -> None:
    """Windows and Linux clients should share wire truth but keep native server evidence."""

    output = linux_matrix_output
    mappings = _json_records(output, "smb_mapping.json")
    smb_files = _json_records(output, "smb_files.json")
    ecar = _json_records(output, "ecar.json")
    syslog = _syslog_records(output)

    samba_mapping = next(record for record in mappings if record.get("service") == "Finance")
    assert samba_mapping["native_file_system"] == "NTFS"
    assert str(samba_mapping["path"]).replace("/", "\\").endswith(r"SAMBA-01\Finance")
    assert any(str(record.get("name", "")).endswith("linux-plan.xlsx") for record in smb_files)

    samba_files = [
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("properties", {}).get("auth_session_ref")
    ]
    assert samba_files
    assert all(
        str(record.get("properties", {}).get("file_path", "")).startswith("/srv/samba/data/")
        for record in samba_files
    )
    assert all(record.get("pid", 0) > 0 and record.get("actorID") for record in samba_files)
    assert all(
        record.get("properties", {}).get("image_path") == "/usr/sbin/smbd" for record in samba_files
    )

    samba_logins = [
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "USER_SESSION"
        and record.get("action") == "LOGIN"
        and record.get("properties", {}).get("session_type") == "smb"
    ]
    assert samba_logins
    assert all("logon_type" not in record.get("properties", {}) for record in samba_logins)

    samba_native = [record for record in syslog if record.get("app_name") in {"smbd", "smbd_audit"}]
    assert samba_native
    assert {record.get("hostname") for record in samba_native} == {"SAMBA-01"}
    assert any(
        record.get("app_name") == "smbd_audit"
        and "linux-plan.xlsx" in str(record.get("message", ""))
        for record in samba_native
    )

    security_paths = [str(path).casefold() for path in output.rglob("windows_event_security.xml")]
    assert any("fs-win-01" in path for path in security_paths)
    assert not any("samba-01" in path for path in security_paths)


def test_linux_smb_flow_precedes_samba_login_and_file_observation(
    linux_matrix_output: Path,
) -> None:
    """The L→L exact transport should be visible before Samba auth and file access."""

    ecar = _json_records(linux_matrix_output, "ecar.json")
    flows = [
        record
        for record in ecar
        if record.get("object") == "FLOW"
        and record.get("properties", {}).get("src_ip") == "10.30.0.10"
        and record.get("properties", {}).get("dst_ip") == "10.30.0.20"
        and int(record.get("properties", {}).get("dst_port", 0)) == 445
    ]
    logins = [
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "USER_SESSION"
        and record.get("action") == "LOGIN"
        and record.get("principal") == "linux_user"
    ]
    files = [
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("properties", {}).get("auth_session_ref")
        and record.get("principal") == "linux_user"
        and str(record.get("properties", {}).get("file_path", "")).endswith("linux-plan.xlsx")
    ]
    logouts = [
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "USER_SESSION"
        and record.get("action") == "LOGOUT"
        and record.get("principal") == "linux_user"
    ]

    assert flows and logins and files and logouts
    file_record = min(files, key=lambda record: record["timestamp_ms"])
    session_id = file_record["properties"]["session_id"]
    login = next(
        record for record in logins if record.get("properties", {}).get("session_id") == session_id
    )
    logout = next(
        record for record in logouts if record.get("properties", {}).get("session_id") == session_id
    )
    source_port = int(login["properties"]["src_port"])
    tuple_flows = [
        record
        for record in flows
        if int(record.get("properties", {}).get("src_port", 0)) == source_port
    ]
    assert {record.get("hostname") for record in tuple_flows} == {
        "LNX-CLIENT-01",
        "SAMBA-01",
    }
    assert max(record["timestamp_ms"] for record in tuple_flows) <= login["timestamp_ms"]
    assert login["timestamp_ms"] <= file_record["timestamp_ms"] <= logout["timestamp_ms"]

    client_flows = [record for record in tuple_flows if record.get("hostname") == "LNX-CLIENT-01"]
    assert client_flows
    attributed_client_flows = [
        record for record in client_flows if record.get("pid", 0) > 0 and record.get("actorID")
    ]
    assert all(
        record.get("properties", {}).get("image_path") == "/usr/bin/smbclient"
        for record in attributed_client_flows
    )
    assert all(
        "smbclient" in record.get("properties", {}).get("command_line", "")
        for record in attributed_client_flows
    )
    assert all(record.get("actorID") != file_record.get("actorID") for record in client_flows)


def test_linux_cifs_mount_uses_actor_owned_posix_client_file_evidence(
    linux_matrix_output: Path,
) -> None:
    """Mounted CIFS I/O should be local application activity, not mount.cifs ownership."""

    client_file = next(
        record
        for record in _json_records(linux_matrix_output, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).startswith(
            "/mnt/windows-documents/"
        )
    )
    properties = client_file["properties"]

    assert client_file.get("pid", 0) > 0
    assert client_file.get("actorID")
    assert properties.get("image_path") == "/usr/bin/head"
    assert "mount.cifs" not in properties.get("command_line", "")
    assert "effective_uid" not in properties
    assert "effective_gid" not in properties

    truth = _ground_truth_event(linux_matrix_output, "linux-to-windows-read")["attributes"]
    transport_uid = truth["transport_uids"][0]
    connection = next(
        record
        for record in _json_records(linux_matrix_output, "conn.json")
        if record.get("uid") == transport_uid
    )
    connection_start_ms = int(float(connection["ts"]) * 1000)
    connection_end_ms = int((float(connection["ts"]) + float(connection.get("duration", 0))) * 1000)
    client_flows = [
        record
        for record in _json_records(linux_matrix_output, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FLOW"
        and record.get("properties", {}).get("dst_ip") == "10.30.0.21"
        and int(record.get("properties", {}).get("dst_port", 0)) == 445
        and int(record.get("properties", {}).get("src_port", 0)) == connection["id.orig_p"]
        and connection_start_ms <= int(record.get("timestamp_ms", 0)) <= connection_end_ms
    ]
    assert client_flows
    assert all("pid" not in record and "actorID" not in record for record in client_flows)


def test_linux_cifs_mount_browse_emits_actor_owned_client_file_read(tmp_path: Path) -> None:
    """A mounted directory enumeration should project only the Linux client file view."""

    data = _scenario_data("linux-to-windows-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-cifs-browse"
    event = storyline["events"][0]
    event["operation"] = "browse"

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, storyline["id"])["attributes"]
    operation = truth["operations"][0]
    assert operation["operation"] == "browse"
    assert operation["outcome"] == "success"

    ecar = _json_records(tmp_path, "ecar.json")
    client_read = next(
        record
        for record in ecar
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).startswith(
            "/mnt/windows-documents/"
        )
    )
    assert client_read.get("pid", 0) > 0
    assert client_read.get("actorID")
    assert client_read["properties"]["image_path"] == "/usr/bin/find"
    assert not [
        record
        for record in ecar
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            r"Briefs\windows-brief.docx"
        )
    ]


def test_linux_cifs_copy_uses_authored_local_destination_in_cp_command(tmp_path: Path) -> None:
    """A mounted download should copy into the authored client path, not a fixed home path."""

    data = _scenario_data("linux-to-windows-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-cifs-copy-download"
    event = storyline["events"][0]
    event["operation"] = "copy"
    event["source"] = event.pop("target")
    event["destination"] = {"type": "client", "path": "/var/tmp/smb-cache/"}

    _generate(data, tmp_path)

    client_create = next(
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "CREATE"
        and record.get("properties", {}).get("file_path") == "/var/tmp/smb-cache/windows-brief.docx"
    )
    properties = client_create["properties"]
    assert properties["image_path"] == "/usr/bin/cp"
    assert properties["command_line"] == (
        'cp -- "/mnt/windows-documents/Briefs/windows-brief.docx" '
        '"/var/tmp/smb-cache/windows-brief.docx"'
    )
    assert "/home/" not in properties["command_line"]
    assert client_create.get("pid", 0) > 0
    assert client_create.get("actorID")


def test_linux_cifs_upload_move_uses_mv_from_authored_source_to_mount(tmp_path: Path) -> None:
    """A mounted upload move should retain mv morphology and both native operands."""

    data = _scenario_data("linux-to-windows-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-cifs-move-upload"
    storyline["events"] = [
        {
            "type": "smb_activity",
            "operation": "move",
            "purpose": "interactive",
            "source": {
                "type": "client",
                "path": "/var/tmp/outgoing/client-report.txt",
            },
            "destination": {
                "type": "share",
                "share": "FS-WIN-01.documents",
                "path": r"Incoming\client-report.txt",
            },
            "outcome": "success",
            "client_access": "cifs_mount",
            "path_style": "mounted",
            "mapping": "linux-windows-docs",
        }
    ]

    _generate(data, tmp_path)

    local_read = next(
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and record.get("properties", {}).get("file_path") == "/var/tmp/outgoing/client-report.txt"
    )
    properties = local_read["properties"]
    assert properties["image_path"] == "/usr/bin/mv"
    assert properties["command_line"] == (
        'mv -- "/var/tmp/outgoing/client-report.txt" '
        '"/mnt/windows-documents/Incoming/client-report.txt"'
    )
    assert "touch" not in properties["command_line"]

    local_delete = next(
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "DELETE"
        and record.get("properties", {}).get("file_path") == "/var/tmp/outgoing/client-report.txt"
    )
    assert local_delete["pid"] == local_read["pid"]
    assert local_delete["actorID"] == local_read["actorID"]
    mounted_flows = [
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FLOW"
        and record.get("properties", {}).get("dst_ip") == "10.30.0.21"
        and int(record.get("properties", {}).get("dst_port", 0)) == 445
    ]
    assert mounted_flows
    authored_flow = min(
        mounted_flows,
        key=lambda record: abs(record["timestamp_ms"] - local_read["timestamp_ms"]),
    )
    # Endpoint FLOW and FILE telemetry use independent source-native latency envelopes.
    assert abs(authored_flow["timestamp_ms"] - local_read["timestamp_ms"]) < 2_000
    assert "pid" not in authored_flow
    assert "actorID" not in authored_flow


def test_linux_cifs_mount_rename_uses_mounted_previous_and_current_paths(tmp_path: Path) -> None:
    """Mounted rename companions should use POSIX paths while server and wire stay native."""

    data = _scenario_data("linux-to-windows-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-cifs-rename"
    event = storyline["events"][0]
    event["operation"] = "move"
    event["source"] = event.pop("target")
    event["destination"] = {
        "type": "share",
        "share": "FS-WIN-01.documents",
        "path": r"Archive\windows-brief-moved.docx",
    }

    _generate(data, tmp_path)

    ecar = _json_records(tmp_path, "ecar.json")
    client_rename = next(
        record
        for record in ecar
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "RENAME"
        and record.get("properties", {}).get("file_path")
        == "/mnt/windows-documents/Archive/windows-brief-moved.docx"
    )
    assert client_rename.get("pid", 0) > 0
    assert client_rename.get("actorID")
    assert client_rename["properties"]["image_path"] == "/usr/bin/mv"
    assert client_rename["properties"]["command_line"] == (
        'mv -- "/mnt/windows-documents/Briefs/windows-brief.docx" '
        '"/mnt/windows-documents/Archive/windows-brief-moved.docx"'
    )
    assert (
        client_rename["properties"]["source_file_path"]
        == "/mnt/windows-documents/Briefs/windows-brief.docx"
    )

    server_rename = next(
        record
        for record in ecar
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and record.get("action") == "RENAME"
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            r"Archive\windows-brief-moved.docx"
        )
    )
    assert server_rename["properties"]["source_file_path"].endswith(r"Briefs\windows-brief.docx")
    zeek_rename = next(
        record
        for record in _json_records(tmp_path, "smb_files.json")
        if record.get("action") == "SMB::FILE_RENAME"
    )
    assert zeek_rename["name"] == r"Archive\windows-brief-moved.docx"
    assert zeek_rename["prev_name"] == r"Briefs\windows-brief.docx"


def test_linux_auto_access_without_mount_falls_back_to_direct_smbclient(
    tmp_path: Path,
) -> None:
    """Installed cifs-utils alone must not invent a mounted presentation."""

    data = _scenario_data("linux-to-windows-read")
    data["environment"]["storage"]["mappings"] = [
        mapping
        for mapping in data["environment"]["storage"]["mappings"]
        if mapping["id"] != "linux-windows-docs"
    ]
    event = data["storyline"][0]["events"][0]
    event.pop("mapping", None)
    event["client_access"] = "auto"
    event["path_style"] = "auto"

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, "linux-to-windows-read")["attributes"]
    connection = next(
        record
        for record in _json_records(tmp_path, "conn.json")
        if record.get("uid") == truth["transport_uids"][0]
    )
    client_flow = next(
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FLOW"
        and int(record.get("properties", {}).get("src_port", 0)) == connection["id.orig_p"]
        and int(record.get("properties", {}).get("dst_port", 0)) == 445
    )

    assert client_flow.get("pid", 0) > 0
    assert client_flow.get("actorID")
    assert client_flow["properties"]["image_path"] == "/usr/bin/smbclient"
    assert "//FS-WIN-01/Documents" in client_flow["properties"]["command_line"]


def test_external_client_to_samba_keeps_network_locality_and_server_only_endpoint(
    linux_matrix_output: Path,
) -> None:
    """An unmodeled SMB client should not acquire fabricated endpoint telemetry."""

    connection = next(
        record
        for record in _json_records(linux_matrix_output, "conn.json")
        if record.get("id.orig_h") == "198.51.100.42"
        and record.get("id.resp_h") == "10.30.0.20"
        and record.get("id.resp_p") == 445
    )
    file_record = next(
        record
        for record in _json_records(linux_matrix_output, "files.json")
        if connection["uid"] in record.get("conn_uids", [])
        and str(record.get("filename", "")).endswith("linux-plan.xlsx")
    )
    ecar = _json_records(linux_matrix_output, "ecar.json")

    assert connection["local_orig"] is False
    assert file_record["local_orig"] is False
    assert file_record["is_orig"] is False
    assert not any(
        record.get("hostname") in {"198.51.100.42", "external-client.example.test"}
        for record in ecar
    )
    assert any(
        record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        for record in ecar
    )


def test_cross_server_copy_keeps_distinct_server_local_paths_and_transport_identities(
    linux_matrix_output: Path,
) -> None:
    """A W-share→Samba copy should render each leg from its owning server."""

    truth = _ground_truth_event(linux_matrix_output, "windows-to-linux-copy")["attributes"]
    assert {operation["share"] for operation in truth["operations"]} == {
        "FS-WIN-01.documents",
        "SAMBA-01.finance",
    }
    assert len(set(truth["transport_uids"])) == 2

    ecar = _json_records(linux_matrix_output, "ecar.json")
    source = next(
        record
        for record in ecar
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            r"Briefs\windows-brief.docx"
        )
    )
    destination = next(
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") in {"CREATE", "WRITE"}
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            "/Archive/windows-brief.docx"
        )
    )

    assert str(source["properties"]["file_path"]).startswith("D:\\")
    assert str(destination["properties"]["file_path"]).startswith("/srv/samba/data/")
    assert source["objectID"] != destination["objectID"]
    assert source.get("actorID") != destination.get("actorID")


def test_cross_server_copy_uses_each_share_fixed_mapping_and_casefolded_id(
    tmp_path: Path,
) -> None:
    """Validation and generation must agree on each transfer leg's fixed credential."""

    data = _fixed_cross_server_mapping_data()
    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]
    assert errors == []

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, "windows-to-linux-copy")["attributes"]
    assert [(operation["share"], operation["outcome"]) for operation in truth["operations"]] == [
        ("FS-WIN-01.documents", "success"),
        ("SAMBA-01.finance", "success"),
    ]
    server_files = [
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("object") == "FILE"
        and record.get("action") in {"READ", "WRITE"}
        and record.get("hostname") in {"FS-WIN-01", "SAMBA-01"}
        and record.get("principal") in {"svc_source", "svc_destination"}
    ]
    assert {(record.get("hostname"), record.get("principal")) for record in server_files} >= {
        ("FS-WIN-01", "svc_source"),
        ("SAMBA-01", "svc_destination"),
    }


def test_samba_to_windows_cross_server_copy_preserves_native_paths_and_direction(
    linux_matrix_output: Path,
) -> None:
    """A Samba→Windows copy should retain distinct objects and transfer directions."""

    truth = _ground_truth_event(linux_matrix_output, "samba-to-windows-copy")["attributes"]
    operations = truth["operations"]
    assert [(item["share"], item["operation"], item["outcome"]) for item in operations] == [
        ("SAMBA-01.finance", "read", "success"),
        ("FS-WIN-01.documents", "create", "success"),
    ]
    assert operations[0]["file_id"] != operations[1]["file_id"]
    assert len(set(truth["transport_uids"])) == 2

    connections = {
        record["uid"]: record
        for record in _json_records(linux_matrix_output, "conn.json")
        if record.get("uid") in set(truth["transport_uids"])
    }
    assert set(connections) == set(truth["transport_uids"])
    assert [connections[uid]["id.orig_h"] for uid in truth["transport_uids"]] == [
        "10.30.0.10",
        "10.30.0.10",
    ]
    assert [connections[uid]["id.resp_h"] for uid in truth["transport_uids"]] == [
        "10.30.0.20",
        "10.30.0.21",
    ]

    assert operations[0]["fuid"] and operations[1]["fuid"]
    assert operations[0]["fuid"] != operations[1]["fuid"]
    file_transfers = _json_records(linux_matrix_output, "files.json")
    source_transfer = next(
        record
        for record in file_transfers
        if truth["transport_uids"][0] in record.get("conn_uids", [])
        and str(record.get("filename", "")).endswith("linux-plan.xlsx")
    )
    destination_transfer = next(
        record
        for record in file_transfers
        if truth["transport_uids"][1] in record.get("conn_uids", [])
        and str(record.get("filename", "")).endswith("linux-plan-copy.xlsx")
    )
    assert source_transfer["is_orig"] is False
    assert destination_transfer["is_orig"] is True
    assert source_transfer["conn_uids"] == [truth["transport_uids"][0]]
    assert destination_transfer["conn_uids"] == [truth["transport_uids"][1]]

    ecar = _json_records(linux_matrix_output, "ecar.json")
    source_read = next(
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and record.get("objectID") == operations[0]["file_id"]
    )
    destination_write = next(
        record
        for record in ecar
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and record.get("action") == "WRITE"
        and record.get("objectID") == operations[1]["file_id"]
    )
    assert source_read["properties"]["file_path"].startswith("/srv/samba/data/")
    assert destination_write["properties"]["file_path"].startswith("D:\\")
    assert source_read["objectID"] != destination_write["objectID"]


def test_successful_cross_server_move_writes_destination_before_source_delete(
    linux_matrix_output: Path,
) -> None:
    """A cross-server move should copy successfully before deleting the source object."""

    truth = _ground_truth_event(linux_matrix_output, "samba-to-windows-move")["attributes"]
    operations = truth["operations"]
    assert [(item["share"], item["operation"], item["outcome"]) for item in operations] == [
        ("SAMBA-01.finance", "read", "success"),
        ("FS-WIN-01.documents", "create", "success"),
        ("SAMBA-01.finance", "delete", "success"),
    ]
    assert operations[0]["file_id"] == operations[2]["file_id"]
    assert operations[0]["file_id"] != operations[1]["file_id"]
    assert len(set(truth["transport_uids"])) == 3

    connections = {
        record["uid"]: record
        for record in _json_records(linux_matrix_output, "conn.json")
        if record.get("uid") in set(truth["transport_uids"])
    }
    assert set(connections) == set(truth["transport_uids"])
    assert [connections[uid]["id.orig_h"] for uid in truth["transport_uids"]] == [
        "10.30.0.10",
        "10.30.0.10",
        "10.30.0.10",
    ]
    assert [connections[uid]["id.resp_h"] for uid in truth["transport_uids"]] == [
        "10.30.0.20",
        "10.30.0.21",
        "10.30.0.20",
    ]

    assert operations[0]["fuid"] and operations[1]["fuid"]
    assert operations[0]["fuid"] != operations[1]["fuid"]
    file_transfers = _json_records(linux_matrix_output, "files.json")
    source_transfer = next(
        record
        for record in file_transfers
        if truth["transport_uids"][0] in record.get("conn_uids", [])
        and str(record.get("filename", "")).endswith("linux-plan.xlsx")
    )
    destination_transfer = next(
        record
        for record in file_transfers
        if truth["transport_uids"][1] in record.get("conn_uids", [])
        and str(record.get("filename", "")).endswith("linux-plan-moved.xlsx")
    )
    assert source_transfer["is_orig"] is False
    assert destination_transfer["is_orig"] is True
    assert source_transfer["conn_uids"] == [truth["transport_uids"][0]]
    assert destination_transfer["conn_uids"] == [truth["transport_uids"][1]]
    assert operations[2]["fuid"] is None

    ecar = _json_records(linux_matrix_output, "ecar.json")
    source_read = next(
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and record.get("objectID") == operations[0]["file_id"]
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            "/Reports/FY26/linux-plan.xlsx"
        )
    )
    destination_write = next(
        record
        for record in ecar
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and record.get("action") == "WRITE"
        and record.get("objectID") == operations[1]["file_id"]
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            r"Archive\linux-plan-moved.xlsx"
        )
    )
    source_delete = next(
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "DELETE"
        and record.get("objectID") == operations[2]["file_id"]
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            "/Reports/FY26/linux-plan.xlsx"
        )
    )
    assert source_read["properties"]["file_path"].startswith("/srv/samba/data/")
    assert destination_write["properties"]["file_path"].startswith("D:\\")
    assert source_delete["objectID"] == source_read["objectID"]
    assert destination_write["objectID"] != source_delete["objectID"]
    assert source_read["timestamp_ms"] < destination_write["timestamp_ms"]
    assert destination_write["timestamp_ms"] < source_delete["timestamp_ms"]


def test_cross_server_move_does_not_delete_source_when_destination_fails(
    tmp_path: Path,
) -> None:
    """A failed destination write must leave the source leg intact."""

    data = _scenario_data("windows-to-linux-copy")
    storyline = data["storyline"][0]
    storyline["id"] = "windows-to-linux-move-denied"
    event = storyline["events"][0]
    event["operation"] = "move"
    event["outcome"] = "access_denied"
    samba_share = data["environment"]["storage"]["servers"][0]["shares"][0]
    samba_share["access"]["modify"] = ["windows_user"]

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, storyline["id"])["attributes"]
    assert [operation["outcome"] for operation in truth["operations"]] == [
        "success",
        "access_denied",
    ]
    assert [operation["operation"] for operation in truth["operations"]] == ["read", "create"]
    assert not [
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "FS-WIN-01"
        and record.get("object") == "FILE"
        and record.get("action") == "DELETE"
    ]


def test_cross_server_denied_leg_uses_its_fixed_mapping_principal(tmp_path: Path) -> None:
    """Parent outcome planning must use the same per-leg credential as each child bundle."""

    data = _fixed_cross_server_mapping_data()
    storyline = data["storyline"][0]
    storyline["id"] = "cross-server-fixed-destination-denied"
    event = storyline["events"][0]
    event["outcome"] = "access_denied"

    samba_server = data["environment"]["storage"]["servers"][0]
    # The actor and explicitly selected source credential can write, but the
    # destination mapping's fixed credential cannot. Parent planning must ignore
    # SOURCE-FIXED for this destination leg and mark only that leg denied.
    samba_server["shares"][0]["access"] = {"modify": ["linux_user", "svc_source"]}

    _generate(data, tmp_path)

    operations = _ground_truth_event(tmp_path, storyline["id"])["attributes"]["operations"]
    assert [operation["operation"] for operation in operations] == ["read", "create"]
    assert [operation["outcome"] for operation in operations] == ["success", "access_denied"]


def test_cross_server_move_can_fail_only_on_source_delete(tmp_path: Path) -> None:
    """Read and destination-create legs must complete before a denied move delete."""

    data = _fixed_cross_server_mapping_data()
    storyline = data["storyline"][0]
    storyline["id"] = "cross-server-fixed-source-delete-denied"
    event = storyline["events"][0]
    event["operation"] = "move"
    event["outcome"] = "access_denied"
    source_share = data["environment"]["storage"]["servers"][1]["shares"][0]
    source_share["access"] = {"read": ["svc_source"]}

    _generate(data, tmp_path)

    operations = _ground_truth_event(tmp_path, storyline["id"])["attributes"]["operations"]
    assert [operation["operation"] for operation in operations] == ["read", "create", "delete"]
    assert [operation["outcome"] for operation in operations] == [
        "success",
        "success",
        "access_denied",
    ]


def test_share_to_client_move_can_fail_only_on_server_delete(tmp_path: Path) -> None:
    """A read-only share move should leave a successful local copy and denied delete."""

    data = _scenario_data("linux-to-linux-read")
    storyline = data["storyline"][0]
    storyline["id"] = "samba-to-linux-move-delete-denied"
    event = storyline["events"][0]
    event["operation"] = "move"
    event["source"] = event.pop("target")
    event["destination"] = {"type": "client", "path": "/var/tmp/smb-cache/"}
    event["outcome"] = "access_denied"
    samba_share = data["environment"]["storage"]["servers"][0]["shares"][0]
    samba_share["access"] = {"read": ["linux_user"]}

    _generate(data, tmp_path)

    operations = _ground_truth_event(tmp_path, storyline["id"])["attributes"]["operations"]
    assert [operation["operation"] for operation in operations] == ["copy", "delete"]
    assert [operation["outcome"] for operation in operations] == ["success", "access_denied"]


def test_client_to_samba_move_is_upload_then_local_delete_not_server_rename(
    tmp_path: Path,
) -> None:
    """Moving a client file onto a share must not rename the new server object."""

    data = _scenario_data("linux-to-linux-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-client-to-samba-move"
    storyline["events"] = [
        {
            "type": "smb_activity",
            "operation": "move",
            "purpose": "collection",
            "source": {
                "type": "client",
                "path": "/home/linux_user/Documents/upload-plan.xlsx",
            },
            "destination": {
                "type": "share",
                "share": "SAMBA-01.finance",
                "path": r"Incoming\upload-plan.xlsx",
            },
            "outcome": "success",
            "client_access": "smbclient",
            "auth_protocol": "ntlmssp",
        }
    ]

    _generate(data, tmp_path)

    server_write = next(
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "WRITE"
        and str(record.get("properties", {}).get("file_path", "")).endswith(
            "/Incoming/upload-plan.xlsx"
        )
    )
    assert "source_file_path" not in server_write["properties"]

    client_actions = {
        record.get("action")
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("properties", {}).get("file_path")
        == "/home/linux_user/Documents/upload-plan.xlsx"
    }
    assert client_actions == {"READ", "DELETE"}

    zeek_writes = [
        record
        for record in _json_records(tmp_path, "smb_files.json")
        if record.get("action") == "SMB::FILE_WRITE"
        and record.get("name") == r"Incoming\upload-plan.xlsx"
    ]
    assert zeek_writes
    assert all(not record.get("prev_name") for record in zeek_writes)
    assert not any(
        "|rename|" in str(record.get("message", "")) for record in _syslog_records(tmp_path)
    )


@pytest.mark.parametrize("operation", ["browse", "create", "update", "move", "delete"])
def test_linux_to_samba_exercises_remaining_vfs_operations(
    operation: str,
    tmp_path: Path,
) -> None:
    """Linux direct access should execute every supported V1 Samba operation."""

    data = _scenario_data("linux-to-linux-read")
    storyline = data["storyline"][0]
    storyline["id"] = f"linux-to-samba-{operation}"
    event = storyline["events"][0]
    event["operation"] = operation
    if operation == "create":
        event["target"] = {
            "type": "share",
            "share": "SAMBA-01.finance",
            "path": "Incoming\\linux-created.txt",
        }
    elif operation == "move":
        event.pop("target", None)
        event["source"] = {
            "type": "share",
            "share": "SAMBA-01.finance",
            "file_ref": "linux-plan",
        }
        event["destination"] = {
            "type": "share",
            "share": "SAMBA-01.finance",
            "path": "Archive\\linux-plan.xlsx",
        }

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, storyline["id"])["attributes"]
    assert [item["operation"] for item in truth["operations"]] == [operation]
    assert {item["outcome"] for item in truth["operations"]} == {"success"}
    assert any(
        record.get("hostname") == "SAMBA-01" and record.get("app_name") == "smbd_audit"
        for record in _syslog_records(tmp_path)
    )
    if operation == "move":
        rename = next(
            record
            for record in _json_records(tmp_path, "ecar.json")
            if record.get("hostname") == "SAMBA-01"
            and record.get("object") == "FILE"
            and record.get("action") == "RENAME"
            and record.get("properties", {}).get("auth_session_ref")
        )
        assert rename["properties"]["file_path"].endswith("/Archive/linux-plan.xlsx")
        assert rename["properties"]["source_file_path"].endswith("/Reports/FY26/linux-plan.xlsx")
        zeek_rename = next(
            record
            for record in _json_records(tmp_path, "smb_files.json")
            if record.get("action") == "SMB::FILE_RENAME"
        )
        assert zeek_rename["prev_name"] == r"Reports\FY26\linux-plan.xlsx"
        assert not zeek_rename["prev_name"].startswith("/")
        assert any(
            "|rename|success|" in str(record.get("message", ""))
            and str(record.get("message", "")).endswith("/Archive/linux-plan.xlsx")
            for record in _syslog_records(tmp_path)
        )


def test_linux_client_copy_uses_posix_local_path_and_distinct_process_identity(
    tmp_path: Path,
) -> None:
    """A Samba download should create a Linux-local file owned by the client process."""

    data = _scenario_data("linux-to-linux-read")
    storyline = data["storyline"][0]
    storyline["id"] = "linux-client-copy"
    event = storyline["events"][0]
    event["operation"] = "copy"
    event["source"] = event.pop("target")
    event["destination"] = {"type": "client", "path": "/var/tmp/smb-cache/"}
    _generate(data, tmp_path)

    ecar = _json_records(tmp_path, "ecar.json")
    server_read = next(
        record
        for record in ecar
        if record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).endswith("linux-plan.xlsx")
    )
    client_create = next(
        record
        for record in ecar
        if record.get("hostname") == "LNX-CLIENT-01"
        and record.get("object") == "FILE"
        and record.get("action") == "CREATE"
        and record.get("properties", {}).get("file_path") == "/var/tmp/smb-cache/linux-plan.xlsx"
    )

    assert client_create.get("pid", 0) > 0
    assert client_create.get("actorID")
    assert client_create.get("actorID") != server_read.get("actorID")
    assert client_create["objectID"] != server_read["objectID"]


def test_generic_linux_tcp_445_connection_remains_transport_only(tmp_path: Path) -> None:
    """A generic connection to Samba must not fabricate semantic share/file activity."""

    data = _scenario_data()
    data["environment"]["systems"][0]["services"] = ["dns-client", "ntp"]
    data["environment"]["storage"]["servers"][0]["shares"] = []
    data["environment"]["storage"]["mappings"] = [
        mapping
        for mapping in data["environment"]["storage"]["mappings"]
        if mapping["share"] != "SAMBA-01.finance"
    ]
    data["storyline"] = [
        {
            "id": "opaque-linux-smb",
            "time": "+10m",
            "actor": "linux_user",
            "system": "LNX-CLIENT-01",
            "activity": "Opaque transport to the Samba listener",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "10.30.0.20",
                    "dst_port": 445,
                    "service": "smb",
                    "orig_bytes": 100000,
                    "resp_bytes": 200000,
                }
            ],
        }
    ]
    _generate(data, tmp_path)

    connections = [
        record
        for record in _json_records(tmp_path, "conn.json")
        if record.get("id.orig_h") == "10.30.0.10"
        and record.get("id.resp_h") == "10.30.0.20"
        and record.get("id.resp_p") == 445
    ]
    assert connections
    transport_uids = {record["uid"] for record in connections}
    assert not [
        record
        for record in _json_records(tmp_path, "smb_mapping.json")
        if record.get("uid") in transport_uids
    ]
    assert not [
        record
        for record in _json_records(tmp_path, "smb_files.json")
        if record.get("uid") in transport_uids
    ]
    assert not [
        record
        for record in _json_records(tmp_path, "files.json")
        if transport_uids.intersection(record.get("conn_uids", []))
    ]
    assert not [
        record
        for record in _json_records(tmp_path, "ecar.json")
        if record.get("hostname") == "SAMBA-01"
        and (
            (
                record.get("object") == "FILE"
                and record.get("properties", {}).get("auth_session_ref")
            )
            or (
                record.get("object") == "USER_SESSION"
                and record.get("properties", {}).get("session_type") == "smb"
                and record.get("properties", {}).get("src_ip") == "10.30.0.10"
            )
        )
    ]
    assert not [
        record
        for record in _syslog_records(tmp_path)
        if record.get("app_name") in {"smbd", "smbd_audit"}
    ]


def test_organization_pack_storage_catalog_composes_with_samba_server(tmp_path: Path) -> None:
    """Organization-pack storage vocabulary should compile unchanged onto Samba."""

    pack_root = PackRepository(tmp_path).create_skeleton(
        "organization",
        "tiny-samba-org",
        "1.0.0",
    )
    write_yaml(
        {
            "storage_catalog": {
                "records": {
                    "description": "One intentionally tiny Samba record vocabulary.",
                    "data": {
                        "directories": ["Records"],
                        "subjects": ["Case"],
                        "files": [
                            {
                                "extension": ".pdf",
                                "mime": "application/pdf",
                                "weight": 1,
                            }
                        ],
                    },
                }
            }
        },
        pack_root / "catalogs/storage_catalog.yaml",
    )
    write_yaml(
        {
            "environment": {
                "description": "Fictional organization using a Samba file server.",
                "timezone": {"default": "UTC"},
                "domain": "tiny-samba.example",
                "users": [
                    {
                        "username": "casey.lee",
                        "full_name": "Casey Lee",
                        "email": "casey.lee@tiny-samba.example",
                        "primary_system": "TINY-LNX-01",
                    }
                ],
                "systems": [
                    {
                        "hostname": "TINY-LNX-01",
                        "ip": "10.89.10.21",
                        "os": "Ubuntu 24.04",
                        "type": "workstation",
                        "assigned_user": "casey.lee",
                        "roles": ["workstation"],
                        "services": ["smb-client", "smbclient"],
                    },
                    {
                        "hostname": "TINY-SAMBA-01",
                        "ip": "10.89.20.20",
                        "os": "Ubuntu Server 24.04",
                        "type": "server",
                        "services": ["smb-server", "samba", "smbd"],
                        "roles": ["file_server"],
                    },
                ],
                "storage": {
                    "servers": [
                        {
                            "system": "TINY-SAMBA-01",
                            "presets": [],
                            "audit": "high",
                            "volumes": [
                                {
                                    "id": "data",
                                    "mount": "/srv/samba/data",
                                    "filesystem": "xfs",
                                }
                            ],
                            "shares": [
                                {
                                    "id": "records",
                                    "name": "Records",
                                    "volume": "data",
                                    "preset": "records",
                                    "access": {"read": ["casey.lee"]},
                                }
                            ],
                        }
                    ]
                },
            }
        },
        pack_root / "model/environment.yaml",
    )
    write_yaml(
        {
            "baseline_activity": {
                "description": "Low-volume Linux background activity.",
                "intensity": "low",
                "variation": "medium",
                "suspicious_noise": "low",
                "traffic_rates": {"smb_interval": 50000},
            }
        },
        pack_root / "model/baseline_activity.yaml",
    )
    scenario_path = tmp_path / "scenario.yaml"
    write_yaml(
        {
            "scenario_version": "2.0",
            "composition": {
                "organization": {
                    "source": "project",
                    "name": "tiny-samba-org",
                    "version": "1.0.0",
                }
            },
            "name": "tiny-samba-organization-regression",
            "description": "Read from a small organization-pack catalog on Samba.",
            "time_window": {"start": "2026-08-17T10:00:00Z", "duration": "20m"},
            "storyline": [
                {
                    "id": "read-record",
                    "time": "+10m",
                    "actor": "casey.lee",
                    "system": "TINY-LNX-01",
                    "activity": "Read one Samba-hosted organization record.",
                    "events": [
                        {
                            "type": "smb_activity",
                            "operation": "read",
                            "target": {"type": "share", "share": "TINY-SAMBA-01.records"},
                            "outcome": "success",
                            "client_access": "smbclient",
                        }
                    ],
                }
            ],
            "output": {
                "logs": [
                    {"format": "zeek"},
                    {"format": "ecar"},
                    {"format": "syslog"},
                ],
                "destination": "./output",
                "compression": False,
            },
        },
        scenario_path,
    )

    compiled = compile_scenario(scenario_path, project_root=tmp_path)
    output = tmp_path / "generated"
    GenerationEngine(
        compiled.scenario,
        output,
        resource_forecast=_forecast(output),
        compiled_scenario=compiled,
        scenario_root=tmp_path,
    ).generate()

    manifest = json.loads((output / "STORAGE_MANIFEST.json").read_text(encoding="utf-8"))
    volume = next(item for item in manifest["volumes"] if item["system"] == "TINY-SAMBA-01")
    share = next(item for item in manifest["shares"] if item["ref"] == "TINY-SAMBA-01.records")
    assert manifest["schema_version"] == 2
    assert volume["platform"] == "linux"
    assert volume["mount"] == "/srv/samba/data"
    assert volume["filesystem"] == "xfs"
    assert share["preset"] == "tiny-samba-org:records"
    assert share["smb_native_filesystem"] == "NTFS"
    assert share["file_count"] == 36
    assert not {"C$", "ADMIN$"}.intersection(item["name"] for item in manifest["shares"])
    assert any(
        record.get("hostname") == "TINY-SAMBA-01"
        and record.get("object") == "FILE"
        and str(record.get("properties", {}).get("file_path", "")).startswith("/srv/samba/data/")
        for record in _json_records(output, "ecar.json")
    )
    assert any(
        record.get("hostname") == "TINY-SAMBA-01" and record.get("app_name") == "smbd_audit"
        for record in _syslog_records(output)
    )


@pytest.mark.parametrize("outcome", ["access_denied", "not_found", "sharing_violation"])
def test_samba_failures_are_audited_without_successful_file_transfer(
    tmp_path: Path,
    outcome: str,
) -> None:
    """Samba failures should retain auth/audit truth without inventing transferred bytes."""

    data = _scenario_data("windows-to-linux-read")
    storyline = copy.deepcopy(data["storyline"][0])
    storyline["id"] = f"samba-{outcome}"
    event = storyline["events"][0]
    event["outcome"] = outcome
    if outcome == "not_found":
        event["target"].pop("file_ref", None)
        event["target"]["path"] = r"Missing\does-not-exist.xlsx"
    if outcome == "access_denied":
        data["environment"]["storage"]["servers"][0]["shares"][0]["access"]["read"] = ["linux_user"]
        data["environment"]["storage"]["servers"][0]["shares"][0]["access"]["modify"] = [
            "linux_user"
        ]
    data["storyline"] = [storyline]

    _generate(data, tmp_path)

    truth = _ground_truth_event(tmp_path, storyline["id"])["attributes"]
    assert truth["operations"]
    assert {operation["outcome"] for operation in truth["operations"]} == {outcome}
    assert all(operation.get("fuid") is None for operation in truth["operations"])
    transfer_fuids = {
        record.get("fuid") for record in _json_records(tmp_path, "files.json") if record.get("fuid")
    }
    assert not any(operation.get("fuid") in transfer_fuids for operation in truth["operations"])

    samba_messages = [
        str(record.get("message", ""))
        for record in _syslog_records(tmp_path)
        if record.get("hostname") == "SAMBA-01" and record.get("app_name") in {"smbd", "smbd_audit"}
    ]
    assert samba_messages
    outcome_tokens = {
        "access_denied": ("access_denied", "ACCESS_DENIED"),
        "not_found": ("not_found", "OBJECT_NAME_NOT_FOUND", "NO_SUCH_FILE"),
        "sharing_violation": ("sharing_violation", "SHARING_VIOLATION"),
    }[outcome]
    assert any(any(token in message for token in outcome_tokens) for message in samba_messages)


def test_encrypted_samba_share_hides_sensor_file_detail_but_keeps_endpoint_evidence(
    tmp_path: Path,
) -> None:
    """SMB encryption should be opaque to Zeek without erasing Samba endpoint truth."""

    data = _scenario_data("linux-to-linux-read")
    data["environment"]["storage"]["servers"][0]["shares"][0]["encryption"] = "required"
    _generate(data, tmp_path)

    mappings = _json_records(tmp_path, "smb_mapping.json")
    assert any(
        record.get("service") == "Finance" and record.get("native_file_system") == "NTFS"
        for record in mappings
    )
    assert not any(
        str(record.get("name", "")).endswith("linux-plan.xlsx")
        for record in _json_records(tmp_path, "smb_files.json")
    )
    assert not any(
        str(record.get("filename", "")).endswith("linux-plan.xlsx")
        for record in _json_records(tmp_path, "files.json")
    )
    assert any(
        record.get("hostname") == "SAMBA-01"
        and record.get("object") == "FILE"
        and record.get("action") == "READ"
        and str(record.get("properties", {}).get("file_path", "")).endswith("linux-plan.xlsx")
        for record in _json_records(tmp_path, "ecar.json")
    )
    assert any(
        record.get("hostname") == "SAMBA-01"
        and record.get("app_name") == "smbd_audit"
        and "linux-plan.xlsx" in str(record.get("message", ""))
        for record in _syslog_records(tmp_path)
    )
