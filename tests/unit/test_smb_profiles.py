# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for platform-native SMB client and server profiles."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from evidenceforge.cli.validate_config import validate_config
from evidenceforge.config.schemas import SmbProfilesConfig
from evidenceforge.generation.activity.smb_profiles import (
    advertised_filesystem_default,
    client_auth_options,
    client_process_for_operation,
    get_client_profile,
    get_samba_audit_operation,
    load_smb_profiles,
    local_smbclient_operand,
    render_process,
    reset_smb_profiles_cache,
    samba_audit_enabled,
    select_client_profile,
    select_server_profile,
)


@pytest.fixture(autouse=True)
def _reset_profiles() -> None:
    reset_smb_profiles_cache()
    yield
    reset_smb_profiles_cache()


def test_packaged_profiles_cover_native_client_and_server_modes() -> None:
    config = load_smb_profiles()

    assert config.schema_version == 1
    assert config.advertised_filesystem_defaults.windows == {
        "ntfs": "NTFS",
        "refs": "ReFS",
    }
    assert config.advertised_filesystem_defaults.linux == {
        "ext4": "NTFS",
        "xfs": "NTFS",
    }
    assert config.samba_audit.operations["smb_file_delete"].label == "unlink"
    assert config.samba_audit.failure_audit_profiles == ("standard", "high")
    assert config.client_defaults == {
        "windows": "windows_explorer",
        "linux": "linux_gvfs",
    }
    assert {profile.access_mode for profile in config.client_profiles.values()} == {
        "explorer",
        "desktop",
        "direct",
        "mounted",
    }
    assert config.server_defaults == {
        "windows": "windows_lanmanserver",
        "linux": "linux_samba",
    }

    mounted = get_client_profile("linux_cifs_mount")
    assert mounted.transport_attribution == "kernel"
    assert mounted.process is None
    assert set(mounted.operation_processes) == {
        "browse",
        "read",
        "create",
        "update",
        "copy",
        "move",
        "delete",
    }
    assert all(
        process.image != "/usr/bin/mount.cifs" for process in mounted.operation_processes.values()
    )

    samba = select_server_profile("linux", ["samba"])
    assert samba.listener.image == "/usr/sbin/smbd"
    assert samba.listener.lifecycle == "service"
    assert samba.worker is not None
    assert samba.worker.lifecycle == "transport"


def test_client_selection_prefers_explicit_aliases_and_defaults_generic_smb() -> None:
    assert select_client_profile("linux", ["cifs-utils"]).access_mode == "mounted"
    assert select_client_profile("linux", ["smbclient"]).access_mode == "direct"
    assert select_client_profile("linux", ["gvfsd-smb"]).access_mode == "desktop"
    assert select_client_profile("linux", ["smb-client"]).access_mode == "desktop"
    assert select_client_profile("windows", ["smb"]).access_mode == "explorer"
    assert (
        select_client_profile("linux", ["smb-client"], access_mode="direct").access_mode == "direct"
    )


def test_filesystem_and_samba_audit_accessors_preserve_provider_defaults() -> None:
    assert advertised_filesystem_default("windows", "ntfs") == "NTFS"
    assert advertised_filesystem_default("windows", "refs") == "ReFS"
    assert advertised_filesystem_default("linux", "ext4") == "NTFS"
    assert advertised_filesystem_default("linux", "xfs") == "NTFS"

    operation = get_samba_audit_operation("smb_file_delete")
    assert operation is not None and operation.label == "unlink"
    assert get_samba_audit_operation("connection") is None
    assert not samba_audit_enabled("smb_file_open", "minimal", "success")
    assert not samba_audit_enabled("smb_file_open", "minimal", "access_denied")
    assert samba_audit_enabled("smb_file_open", "standard", "success")
    assert not samba_audit_enabled("smb_file_read", "standard", "success")
    assert samba_audit_enabled("smb_file_read", "standard", "access_denied")
    assert samba_audit_enabled("smb_file_read", "high", "success")


def test_weighted_client_selection_is_scope_deterministic() -> None:
    services = ["smbclient", "cifs-utils"]
    selections = [
        select_client_profile("linux", services, scope_key=f"host-{index}").access_mode
        for index in range(40)
    ]

    assert selections == [
        select_client_profile("linux", services, scope_key=f"host-{index}").access_mode
        for index in range(40)
    ]
    assert set(selections) == {"direct", "mounted"}


def test_process_rendering_uses_only_explicit_values() -> None:
    direct = get_client_profile("linux_smbclient")
    process = client_process_for_operation(direct, "read")
    assert process is not None
    kerberos_options = client_auth_options(direct, "kerberos")

    rendered = render_process(
        process,
        server="files01",
        share="Shared",
        path="Reports/Q3.txt",
        local_path="/home/alice/Downloads/Q3.txt",
        username="alice",
        smb_principal="CORP\\finance-reader",
        auth_options=kerberos_options,
        operation="read",
    )

    assert rendered.image == "/usr/bin/smbclient"
    assert rendered.lifecycle == "operation"
    assert rendered.username == "alice"
    assert "//files01/Shared" in rendered.command_line
    assert 'get "Reports/Q3.txt" "/home/alice/Downloads/Q3.txt"' in rendered.command_line
    assert '-U "CORP\\finance-reader"' in rendered.command_line
    assert "--use-kerberos=required" in rendered.command_line

    opaque_rendered = render_process(
        process,
        server="files01",
        share="Shared",
        path="Reports/Q3.txt",
        local_path="Q3.txt",
        username="alice",
        auth_options=client_auth_options(direct, "auto"),
        operation="read",
    )
    assert '-U "alice"' in opaque_rendered.command_line

    with pytest.raises(ValueError, match="missing SMB process render values"):
        render_process(process, server="files01")
    with pytest.raises(ValueError, match="unsupported SMB process render values"):
        render_process(process, typo="value")


def test_direct_transfer_profiles_choose_coherent_operand_direction() -> None:
    direct = get_client_profile("linux_smbclient")

    download = client_process_for_operation(
        direct,
        "copy",
        transfer_direction="download",
    )
    upload = client_process_for_operation(
        direct,
        "copy",
        transfer_direction="upload",
    )
    rename = client_process_for_operation(
        direct,
        "move",
        transfer_direction="remote",
    )

    assert download is not None and download.operand_mode == "download"
    assert upload is not None and upload.operand_mode == "upload"
    assert rename is not None and rename.operand_mode == "rename"
    assert (
        local_smbclient_operand(
            r"Reports\Q3.txt",
            "//files01/Shared/Reports/Q3.txt",
        )
        == "Q3.txt"
    )


@pytest.mark.parametrize(
    ("operation", "transfer_direction", "expected_image"),
    [
        ("copy", "download", "/usr/bin/cp"),
        ("copy", "upload", "/usr/bin/cp"),
        ("move", "upload", "/usr/bin/mv"),
        ("move", "remote", "/usr/bin/mv"),
    ],
)
def test_mounted_transfer_profiles_preserve_canonical_tool_morphology(
    operation: str,
    transfer_direction: str,
    expected_image: str,
) -> None:
    """Mounted copy/move direction must not collapse into create/touch."""

    mounted = get_client_profile("linux_cifs_mount")
    process = client_process_for_operation(
        mounted,
        operation,
        transfer_direction=transfer_direction,
    )

    assert process is not None
    assert process.image == expected_image
    assert process.operand_mode == "transfer"
    rendered = render_process(
        process,
        source_path="/var/tmp/source.dat",
        destination_path="/mnt/shared/Incoming/destination.dat",
        server="files01",
        share="Shared",
        path=r"Incoming\destination.dat",
        client_path="/mnt/shared/Incoming/destination.dat",
        local_path="/var/tmp/source.dat",
        username="alice",
        operation=operation,
    )
    assert rendered.command_line == (
        f"{expected_image.rsplit('/', 1)[-1]} -- "
        '"/var/tmp/source.dat" "/mnt/shared/Incoming/destination.dat"'
    )


@pytest.mark.parametrize(
    ("auth_protocol", "expected"),
    [
        ("auto", "--use-kerberos=desired"),
        ("kerberos", "--use-kerberos=required"),
        ("ntlmssp", "--use-kerberos=off"),
    ],
)
def test_smbclient_auth_options_are_protocol_specific(
    auth_protocol: str,
    expected: str,
) -> None:
    direct = get_client_profile("linux_smbclient")

    assert client_auth_options(direct, auth_protocol) == expected


def test_runtime_uses_explicit_operation_actors_for_every_mounted_operation() -> None:
    mounted = get_client_profile("linux_cifs_mount")

    assert mounted.transport_attribution == "kernel"
    assert mounted.process is None
    for operation, expected in mounted.operation_processes.items():
        resolved = client_process_for_operation(mounted, operation)

        assert resolved is expected
        assert resolved.lifecycle == "operation"
        assert resolved.image != "/usr/bin/mount.cifs"

    invalid_runtime_profile = mounted.model_copy(
        update={
            "process": load_smb_profiles().server_profiles["linux_samba"].listener,
            "operation_processes": {
                operation: process
                for operation, process in mounted.operation_processes.items()
                if operation != "delete"
            },
        }
    )
    with pytest.raises(ValueError, match="no explicit operation actor for 'delete'"):
        client_process_for_operation(invalid_runtime_profile, "delete")


@pytest.mark.parametrize("transport_attribution", ["kernel", "none"])
def test_schema_requires_process_attribution_for_direct_clients(
    transport_attribution: str,
) -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_smbclient"]["transport_attribution"] = transport_attribution

    with pytest.raises(
        ValidationError,
        match="direct access_mode requires transport_attribution=process",
    ):
        SmbProfilesConfig.model_validate(raw)


def test_schema_rejects_resident_default_process_for_direct_clients() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_smbclient"]["process"] = deepcopy(
        raw["client_profiles"]["linux_gvfs"]["process"]
    )

    with pytest.raises(
        ValidationError,
        match="direct access_mode default process must use lifecycle=operation",
    ):
        SmbProfilesConfig.model_validate(raw)


def test_schema_requires_complete_operation_actors_for_mounted_clients() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_cifs_mount"]["operation_processes"].pop("delete")

    with pytest.raises(
        ValidationError,
        match="mounted access_mode requires operation_processes for every SMB operation",
    ):
        SmbProfilesConfig.model_validate(raw)


def test_schema_rejects_mounted_default_mount_lifecycle_process() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_cifs_mount"]["process"] = {
        "key_template": "cifs_mount:{server}:{share}",
        "image": "/usr/bin/mount.cifs",
        "command_line_template": 'mount.cifs "//{server}/{share}"',
        "username_template": "root",
        "lifecycle": "service",
    }

    with pytest.raises(
        ValidationError,
        match="mounted access_mode cannot declare a default process",
    ):
        SmbProfilesConfig.model_validate(raw)


def test_schema_rejects_remote_principal_as_local_process_owner() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_smbclient"]["operation_processes"]["read"][
        "username_template"
    ] = "{smb_principal}"

    with pytest.raises(ValidationError, match="cannot use the remote SMB principal"):
        SmbProfilesConfig.model_validate(raw)


def test_schema_rejects_unknown_process_template_placeholder() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["client_profiles"]["linux_gvfs"]["process"]["command_line_template"] = (
        "gvfsd-smb-browse smb://{hostname}/{share}"
    )

    with pytest.raises(ValidationError, match="unsupported placeholder 'hostname'"):
        SmbProfilesConfig.model_validate(raw)


def test_schema_rejects_incomplete_audit_map_and_unsafe_filesystem_label() -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["samba_audit"]["operations"].pop("smb_file_close")

    with pytest.raises(ValidationError, match="missing canonical events"):
        SmbProfilesConfig.model_validate(raw)

    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    raw["advertised_filesystem_defaults"]["linux"]["xfs"] = "unsafe/label"
    with pytest.raises(ValidationError, match="nonempty safe labels"):
        SmbProfilesConfig.model_validate(raw)


@pytest.mark.parametrize(
    ("field_path", "expected_message"),
    [
        (
            ("operations", "smb_file_read", "audit_profiles"),
            "Samba operation audit_profiles cannot include minimal; minimal is lifecycle-only",
        ),
        (
            ("failure_audit_profiles",),
            "failure_audit_profiles cannot include minimal; minimal is lifecycle-only",
        ),
    ],
)
def test_schema_rejects_minimal_per_file_samba_audit_profiles(
    field_path: tuple[str, ...],
    expected_message: str,
) -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    target = raw["samba_audit"]
    for key in field_path[:-1]:
        target = target[key]
    target[field_path[-1]] = ["minimal", "high"]

    with pytest.raises(ValidationError, match=expected_message):
        SmbProfilesConfig.model_validate(raw)


@pytest.mark.parametrize(
    "field_path",
    [
        ("operations", "smb_file_open", "audit_profiles"),
        ("failure_audit_profiles",),
    ],
)
def test_schema_rejects_standard_samba_audit_without_high(
    field_path: tuple[str, ...],
) -> None:
    raw = deepcopy(load_smb_profiles().model_dump(mode="python"))
    target = raw["samba_audit"]
    for key in field_path[:-1]:
        target = target[key]
    target[field_path[-1]] = ["standard"]

    with pytest.raises(ValidationError, match="containing standard must also contain high"):
        SmbProfilesConfig.model_validate(raw)


def test_profile_overlay_can_partially_override_one_keyed_profile(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(
        """
schema_version: 1
client_profiles:
  linux_smbclient:
    weight: 125.0
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    profile = get_client_profile("linux_smbclient")

    assert profile.weight == 125.0
    assert profile.operation_processes["read"].image == "/usr/bin/smbclient"


def test_profile_overlay_deep_merges_filesystem_and_audit_defaults(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(
        """
advertised_filesystem_defaults:
  linux:
    xfs: SAMBA
samba_audit:
  operations:
    smb_file_delete:
      label: remove
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    assert advertised_filesystem_default("linux", "xfs") == "SAMBA"
    assert advertised_filesystem_default("linux", "ext4") == "NTFS"
    operation = get_samba_audit_operation("smb_file_delete")
    assert operation is not None
    assert operation.label == "remove"
    assert operation.audit_profiles == ("standard", "high")


def test_validate_config_reports_invalid_nested_smb_profile(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(
        """
client_profiles:
  linux_gvfs:
    process:
      command_line_template: "gvfsd-smb-browse smb://{unsupported}/{share}"
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "smb_profiles.yaml"
        and "unsupported placeholder 'unsupported'" in issue.message
        for issue in result.issues
    )


def test_validate_config_reports_invalid_smb_provider_defaults(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(
        """
advertised_filesystem_defaults:
  linux:
    ext4: "bad|label"
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "smb_profiles.yaml"
        and "nonempty safe labels" in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize(
    ("profile_overlay", "expected_message"),
    [
        (
            """
client_profiles:
  linux_smbclient:
    transport_attribution: kernel
""",
            "direct access_mode requires transport_attribution=process",
        ),
        (
            """
client_profiles:
  linux_cifs_mount:
    process:
      key_template: "cifs_mount:{server}:{share}"
      image: /usr/bin/mount.cifs
      command_line_template: 'mount.cifs "//{server}/{share}"'
      username_template: root
      lifecycle: service
""",
            "mounted access_mode cannot declare a default process",
        ),
        (
            """
client_profiles:
  incomplete_mounted:
    os_category: linux
    access_mode: mounted
    path_style: mounted
    transport_attribution: kernel
    service_aliases: [custom-cifs]
    operation_processes:
      read:
        key_template: "mounted_smb:{server}:{share}:{operation}"
        image: /usr/bin/head
        command_line_template: 'head -c 4096 "{client_path}"'
        username_template: "{username}"
        lifecycle: operation
""",
            "mounted access_mode requires operation_processes for every SMB operation",
        ),
    ],
)
def test_validate_config_rejects_merged_smb_ownership_violations(
    profile_overlay: str,
    expected_message: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(profile_overlay, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "smb_profiles.yaml"
        and expected_message in issue.message
        for issue in result.issues
    )


@pytest.mark.parametrize(
    "audit_overlay",
    [
        """
samba_audit:
  operations:
    smb_file_read:
      audit_profiles: [minimal, high]
""",
        """
samba_audit:
  failure_audit_profiles: [minimal, standard, high]
""",
    ],
)
def test_validate_config_rejects_minimal_samba_vfs_overlay(
    audit_overlay: str,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(audit_overlay, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()

    result = validate_config()

    assert any(
        issue.severity == "ERROR"
        and issue.file == "smb_profiles.yaml"
        and "minimal is lifecycle-only" in issue.message
        for issue in result.issues
    )
