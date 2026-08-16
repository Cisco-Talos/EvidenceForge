# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused SMB authoring-boundary validation and runtime tests."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evidenceforge.generation.actions.smb_activity import SmbActivityActionBundle
from evidenceforge.generation.activity.smb_profiles import load_smb_profiles
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.schema import ValidationIssue

_MATRIX_PATH = Path(__file__).parent.parent / "fixtures" / "scenarios" / "smb-linux-matrix.yaml"


def _matrix_data() -> dict:
    return load_yaml(_MATRIX_PATH)


def _validation_errors(data: dict) -> list[ValidationIssue]:
    return [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]


def _timing_bundle(
    *, operation: str = "read", duration: str | None = None
) -> SmbActivityActionBundle:
    bundle = object.__new__(SmbActivityActionBundle)
    bundle.anchor = SimpleNamespace(stable_id="smb-timing-test-session")
    bundle.request = SimpleNamespace(
        spec=SimpleNamespace(
            operation=operation,
            purpose="interactive",
            batch=SimpleNamespace(duration=duration) if duration is not None else None,
            source=None,
            destination=None,
        )
    )
    bundle.executor = SimpleNamespace(
        state_manager=SimpleNamespace(smb_file_size=lambda file: file.size_bytes)
    )
    bundle._operation_time_scale = 1.0
    bundle._session_setup_scale = 1.0
    return bundle


def test_smb_operation_rates_are_deterministic_and_diverse() -> None:
    bundle = _timing_bundle()
    files = tuple(
        CompiledStorageFile(
            file_id=f"timing-file-{index}",
            share="FS-01.finance",
            path=f"Reports\\sample-{index}.dat",
            size_bytes=25_000_000,
            mime_type="application/octet-stream",
        )
        for index in range(32)
    )
    first = [
        bundle._operation_timing(file, index, size_bytes=file.size_bytes)
        for index, file in enumerate(files)
    ]
    second = [
        bundle._operation_timing(file, index, size_bytes=file.size_bytes)
        for index, file in enumerate(files)
    ]
    rates = [
        file.size_bytes / timing.transfer_seconds for file, timing in zip(files, first, strict=True)
    ]
    config = load_smb_profiles().transfer_timing

    assert first == second
    assert len({round(rate, 3) for rate in rates}) == len(rates)
    assert len({round(timing.transfer_seconds, 6) for timing in first}) > 24
    assert all(
        config.throughput_min_bytes_per_second <= rate <= config.throughput_max_bytes_per_second
        for rate in rates
    )
    assert not all(abs(rate - 25_000_000) < 1 for rate in rates)


def test_smb_file_transfer_fuid_is_bound_to_final_content_version() -> None:
    bundle = _timing_bundle(operation="update")
    before = CompiledStorageFile(
        file_id="mutable-file",
        version=1,
        share="FS-01.finance",
        path="Reports\\mutable.xlsx",
        size_bytes=100,
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    after = before.model_copy(update={"version": 2, "size_bytes": 115})

    assert bundle._file_transfer_fuid(after, "write") == bundle._file_transfer_fuid(after, "write")
    assert bundle._file_transfer_fuid(after, "write") != bundle._file_transfer_fuid(before, "write")


def test_authored_smb_duration_scales_operations_inside_transport_budget() -> None:
    bundle = _timing_bundle(duration="250ms")
    files = (
        CompiledStorageFile(
            file_id="large-authored-transfer",
            share="FS-01.finance",
            path="Reports\\large.dat",
            size_bytes=2_000_000_000,
            mime_type="application/octet-stream",
        ),
    )

    duration = bundle._duration(files)
    timing = bundle._operation_timing(files[0], 0, size_bytes=files[0].size_bytes)
    occupied = 0.096 + 0.088 + bundle._session_setup_seconds() + timing.total_seconds

    assert duration == pytest.approx(0.25)
    assert occupied < duration


@pytest.mark.parametrize(
    ("client_access", "path_style", "message"),
    [
        ("smbclient", "mounted", "smbclient access cannot use a mounted"),
        ("cifs_mount", "unc", "cifs_mount access requires an automatic or mounted"),
        ("cifs_mount", "mapped", "cifs_mount access requires an automatic or mounted"),
    ],
)
def test_validator_rejects_incompatible_linux_smb_access_and_path_styles(
    client_access: str,
    path_style: str,
    message: str,
) -> None:
    data = _matrix_data()
    event = data["storyline"][0]["events"][0]
    event["client_access"] = client_access
    event["path_style"] = path_style
    if path_style == "unc":
        event.pop("mapping", None)

    errors = _validation_errors(data)

    assert any(
        issue.field_path.endswith(".path_style") and message in issue.message for issue in errors
    )


@pytest.mark.parametrize(
    ("client_access", "path_style", "mount", "message"),
    [
        ("smbclient", "mounted", "/mnt/windows-documents", "requires one of these path styles"),
        ("cifs_mount", "unc", "/mnt/windows-documents", "requires one of these path styles"),
        ("cifs_mount", "mounted", None, "requires an applicable storage mapping"),
    ],
)
def test_runtime_rejects_incompatible_linux_smb_access_and_path_styles(
    client_access: str,
    path_style: str,
    mount: str | None,
    message: str,
) -> None:
    scenario = Scenario(**_matrix_data())
    bundle = object.__new__(SmbActivityActionBundle)
    bundle.request = SimpleNamespace(
        spec=SimpleNamespace(client_access=client_access, path_style=path_style)
    )
    bundle.mapping = SimpleNamespace(mount=mount) if mount is not None else None

    with pytest.raises(ValueError, match=message):
        bundle._resolve_client_access(scenario.environment.systems[0])


@pytest.mark.parametrize("client_access", ["windows_native", "cifs_mount", "smbclient"])
def test_external_smb_clients_reject_explicit_access_modes(client_access: str) -> None:
    data = _matrix_data()
    data["storyline"][4]["events"][0]["client_access"] = client_access

    with pytest.raises(ValidationError, match="external SMB clients require client_access: auto"):
        Scenario(**data)


@pytest.mark.parametrize("path_style", ["mapped", "mounted"])
def test_external_smb_clients_reject_host_local_path_presentations(path_style: str) -> None:
    data = _matrix_data()
    data["storyline"][4]["events"][0]["path_style"] = path_style

    with pytest.raises(
        ValidationError,
        match="external SMB clients cannot use mapped or mounted path presentation",
    ):
        Scenario(**data)


def test_external_smb_clients_reject_storage_mappings_in_model_and_runtime() -> None:
    data = _matrix_data()
    data["storyline"][4]["events"][0]["mapping"] = "samba-clinical-linux"

    with pytest.raises(ValidationError, match="external SMB clients cannot use storage mappings"):
        Scenario(**data)

    bundle = object.__new__(SmbActivityActionBundle)
    bundle.request = SimpleNamespace(
        spec=SimpleNamespace(client_access="auto", path_style="auto", mapping="external-mapping")
    )
    with pytest.raises(ValueError, match="external SMB clients cannot use storage mappings"):
        bundle._resolve_client_access(None)


@pytest.mark.parametrize(
    ("client_access", "path_style", "message"),
    [
        ("smbclient", "auto", "external SMB clients require client_access: auto"),
        ("auto", "mounted", "external SMB clients require an automatic or UNC"),
    ],
)
def test_runtime_rejects_explicit_external_client_semantics(
    client_access: str,
    path_style: str,
    message: str,
) -> None:
    bundle = object.__new__(SmbActivityActionBundle)
    bundle.request = SimpleNamespace(
        spec=SimpleNamespace(client_access=client_access, path_style=path_style)
    )

    with pytest.raises(ValueError, match=message):
        bundle._resolve_client_access(None)


@pytest.mark.parametrize("path_style", ["auto", "unc"])
def test_runtime_preserves_server_only_external_smb_semantics(path_style: str) -> None:
    bundle = object.__new__(SmbActivityActionBundle)
    bundle.request = SimpleNamespace(
        spec=SimpleNamespace(client_access="auto", path_style=path_style)
    )

    assert bundle._resolve_client_access(None) == "external"


@pytest.mark.parametrize("principal", ["root", "nobody", "Guest"])
def test_validator_rejects_undeclared_non_windows_smb_principals_on_windows(
    principal: str,
) -> None:
    data = _matrix_data()
    event = data["storyline"][0]["events"][0]
    event["smb_principal"] = principal
    event["outcome"] = "access_denied"

    errors = _validation_errors(data)

    assert any(issue.field_path.endswith(".smb_principal") for issue in errors)


@pytest.mark.parametrize("actor", ["root", "nobody"])
def test_validator_rejects_implicit_linux_builtin_credentials_on_windows(actor: str) -> None:
    data = _matrix_data()
    storyline = data["storyline"][0]
    storyline["actor"] = actor
    event = storyline["events"][0]
    event.pop("mapping", None)
    event["client_access"] = "smbclient"
    event["path_style"] = "unc"
    event["outcome"] = "access_denied"
    data["storyline"] = [storyline]

    errors = _validation_errors(data)

    assert any(
        issue.field_path.endswith(".smb_principal")
        and f"Windows SMB principal {actor!r}" in issue.message
        for issue in errors
    )


@pytest.mark.parametrize("principal", ["root", "nobody", "Guest"])
def test_validator_rejects_non_windows_fixed_mapping_principals_on_windows(
    principal: str,
) -> None:
    data = _matrix_data()
    mapping = data["environment"]["storage"]["mappings"][0]
    mapping["credential_mode"] = "fixed"
    mapping["principal"] = principal
    data["storyline"][0]["events"][0]["outcome"] = "access_denied"

    errors = _validation_errors(data)

    assert any(issue.field_path == "environment.storage.mappings.0.principal" for issue in errors)


def test_validator_preserves_windows_builtin_smb_actor_behavior() -> None:
    data = _matrix_data()
    data["storyline"] = [
        {
            "id": "windows-system-to-windows-share",
            "time": "+5m",
            "actor": "SYSTEM",
            "system": "WIN-CLIENT-01",
            "activity": "Windows built-in service reads a Windows share",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {
                        "type": "share",
                        "share": "FS-WIN-01.documents",
                        "file_ref": "windows-brief",
                    },
                    "outcome": "access_denied",
                    "client_access": "windows_native",
                    "path_style": "unc",
                }
            ],
        }
    ]

    assert _validation_errors(data) == []
