# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Field-level Snare compatibility with both supported upstream revisions."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from evidenceforge.external_parsers.sof_elk import run_sof_elk_parser
from evidenceforge.external_parsers.tag_policy import (
    SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
    SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
)
from evidenceforge.formats.snare import snare_projection
from evidenceforge.generation.emitters.windows_snare import (
    render_windows_security_snare_syslog,
    render_windows_sysmon_snare_syslog,
)

pytestmark = pytest.mark.external_parser
REVISIONS = ["517af9445574cc084cd5f4b80539fc244dab82b0", "d9f9bdd113a606c7b3fa1b2eafaa2d4400a16668"]
CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/snare_full_variants.json").read_text()
)

network = next(c for c in CASES if c["format"].endswith("sysmon") and c["fields"]["EventID"] == 3)
process = next(c for c in CASES if c["format"].endswith("sysmon") and c["fields"]["EventID"] == 1)
CASES += [
    network
    | {
        "stress": True,
        "fields": network["fields"]
        | {
            "SourceIp": "2001:db8::1",
            "DestinationIp": "2001:db8::2",
            "SourceIsIpv6": "true",
            "DestinationIsIpv6": "true",
            "SourcePort": 0,
            "DestinationPort": 0,
        },
    },
    process
    | {
        "stress": True,
        "fields": process["fields"]
        | {
            "Image": r"C:\工具\程序.exe",
            "CommandLine": r'"C:\工具\程序.exe" /c echo "x:y" && echo café' + "\ta\nb || echo done",
        },
    },
]


def nested(event: dict, path: str) -> object:
    value = event
    for key in path.split("."):
        value = value.get(key, {}) if isinstance(value, dict) else None
    return value


@pytest.mark.parametrize("revision", REVISIONS)
def test_all_snare_variants_extract_expected_fields(tmp_path: Path, revision: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    expected = {}
    for index, case in enumerate(CASES, 1):
        fields = dict(case["fields"])
        fields.update(EventRecordID=index, Computer="WIN-01.example.test")
        fields["TimeCreated"] = datetime.fromisoformat(fields["TimeCreated"].replace("Z", "+00:00"))
        for key in ("SubjectUserName", "TargetUserName"):
            if key in fields:
                fields[key] = "subject-user" if key.startswith("Subject") else "target-user"
        for key in ("SourceAddress", "SourceIp", "IpAddress", "ClientAddress"):
            if key in fields and not case.get("stress"):
                fields[key] = "192.0.2.10"
        for key in ("DestAddress", "DestinationIp"):
            if key in fields and not case.get("stress"):
                fields[key] = "198.51.100.20"
        source = case["format"]
        if source.endswith("sysmon"):
            fields["UtcTime"] = "2026-09-15 11:59:59.987"
        renderer = (
            render_windows_security_snare_syslog
            if source.endswith("security")
            else render_windows_sysmon_snare_syslog
        )
        with (data / (source + "_snare.log")).open("a") as stream:
            stream.write(renderer(fields) + "\n")
        expected[index] = (source, fields)
    result = run_sof_elk_parser(
        data,
        tmp_path / "runtime",
        commit=revision,
        timeout_seconds=180,
        validators=(
            SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
            SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
        ),
    )
    records = [r for rows in result.events_by_type.values() for r in rows]
    assert len(records) == len(expected)
    for record in records:
        source, fields = expected[nested(record, "winlog.snare.counter")]
        assert nested(record, "winlog.event_id") == fields["EventID"]
        assert nested(record, "winlog.computer_name") == fields["Computer"]
        aliases = snare_projection(source, fields["EventID"]).aliases
        for label, destination in {
            "Account Name": "winlog.user.name",
            "Security ID": "winlog.user.identifier",
            "Account Domain": "user.domain",
            "SourceIp": "source.ip",
            "SourcePort": "source.port",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
        }.items():
            if label in aliases and fields.get(aliases[label]) not in (None, "", "-"):
                assert str(nested(record, destination)) == str(fields[aliases[label]]), (
                    fields["EventID"],
                    destination,
                    record,
                )
        if "SubjectLogonId" in fields:
            assert not nested(record, "winlog.event_data.LogonId"), record
        projection = snare_projection(source, fields["EventID"])
        owner = next(
            (
                projection.aliases[label]
                for label in ("New Process ID", "Process ID")
                if label in projection.aliases and fields.get(projection.aliases[label]) is not None
            ),
            "ExecutionProcessID",
        )
        value = fields.get(owner)
        if value is not None:
            expected_pid = (
                int(value, 16) if isinstance(value, str) and value.startswith("0x") else str(value)
            )
            assert nested(record, "winlog.process.pid") == expected_pid, (fields["EventID"], record)
        image_owner = projection.aliases.get(
            "New Process Name", projection.aliases.get("Image", "Image")
        )
        if fields.get(image_owner):
            assert nested(record, "process.executable") == fields[image_owner].replace("\\", "/"), (
                record
            )
        if source.endswith("sysmon") and fields.get("ProcessId", 0) > 0:
            assert nested(record, "process.pid") == str(fields["ProcessId"]), record

        if source.endswith("sysmon"):
            assert datetime.fromisoformat(record["@timestamp"].replace("Z", "+00:00")).replace(
                tzinfo=None
            ) == datetime.fromisoformat(fields["UtcTime"])
            for field, destination in {
                "Company": "winlog.event_data.Company",
                "Description": "winlog.event_data.Description",
                "DestinationHostname": "destination.domain",
                "FileVersion": "process.pe.file_version",
                "IntegrityLevel": "winlog.event_data.IntegrityLevel",
                "OriginalFileName": "process.pe.original_file_name",
                "ParentCommandLine": "process.parent.command_line",
                "ParentProcessGuid": "process.parent.entity_id",
                "ParentProcessId": "process.parent.pid",
                "ParentUser": "winlog.event_data.ParentUser",
                "ProcessGuid": "process.entity_id",
                "Product": "winlog.event_data.Product",
                "QueryName": "dns.question.name",
                "Signature": "winlog.event_data.Signature",
                "SignatureStatus": "winlog.event_data.SignatureStatus",
                "SourceHostname": "source.domain",
                "SourceImage": "winlog.event_data.SourceImage",
                "StartAddress": "winlog.event_data.StartAddress",
                "StartFunction": "winlog.event_data.StartFunction",
                "StartModule": "winlog.event_data.StartModule",
                "TargetFilename": "winlog.event_data.TargetFilename",
                "TargetImage": "winlog.event_data.TargetImage",
                "TargetObject": "winlog.event_data.TargetObject",
                "TerminalSessionId": "winlog.event_data.TerminalSessionId",
            }.items():
                if fields.get(field) not in (None, ""):
                    assert nested(record, destination) == str(fields[field]).replace("\\", "/"), (
                        field,
                        record,
                    )
            if fields.get("RuleName"):
                assert nested(record, "rule.name") == [fields["RuleName"]]
            # Both frozen revisions replace backslashes before applying these
            # backslash-dependent patterns. Preserve raw facts without claiming indexing.
            for field, destination in {
                "CurrentDirectory": "process.working_directory",
                "ParentImage": "process.parent.executable",
            }.items():
                if fields.get(field):
                    assert f"{field}: {fields[field]}  " in nested(record, "event.original")
                    assert not nested(record, destination)
            for field, destination in {
                "SourceIp": "source.ip",
                "DestinationIp": "destination.ip",
                "SourcePort": "source.port",
                "DestinationPort": "destination.port",
            }.items():
                if field in fields:
                    value = fields[field]
                    if value == 0:
                        assert not nested(record, destination), record
                    else:
                        assert str(nested(record, destination)) == str(value), record
            if fields.get("CommandLine"):
                assert nested(record, "process.command_line") == fields["CommandLine"].replace(
                    "\\", "/"
                ).replace("\t", " ").replace("\n", " ").replace("||", "|"), record
