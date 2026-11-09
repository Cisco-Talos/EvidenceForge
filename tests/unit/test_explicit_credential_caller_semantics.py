# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Generated credential-bearing PowerShell inventory uses an actual CIM session."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from evidenceforge.generation.actions.windows_remote_admin import (
    ExplicitCredentialUseActionBundle,
    ExplicitCredentialUseRequest,
)


@pytest.mark.parametrize("executable", ["powershell.exe", "pwsh.exe"])
@pytest.mark.parametrize(
    "principal,target", [("DOMAIN\\admin", "DC-01.example.test"), ("o'brien", "srv'quoted")]
)
def test_generated_cim_caller_scopes_credentials_and_disposes_session(
    executable: str, principal: str, target: str
) -> None:
    request = ExplicitCredentialUseRequest(
        user=SimpleNamespace(username="operator"),
        system=SimpleNamespace(hostname="WS-01"),
        time=datetime(2026, 11, 2, tzinfo=UTC),
        target_username=principal,
        target_server=target,
        process_name=executable,
        process_pid=None,
    )
    bundle = ExplicitCredentialUseActionBundle(SimpleNamespace(), request)
    command = bundle._materialized_caller_command_line()
    session_create = command.split("$session = ", 1)[1].split(";", 1)[0]
    query = command.split("try { ", 1)[1].split(" }", 1)[0]
    assert "New-CimSession" in session_create and "-Credential $cred" in session_create
    assert "Get-CimInstance" in query and "-CimSession $session" in query
    assert "-Credential" not in query and "-ComputerName" not in query
    assert "finally { Remove-CimSession -CimSession $session }" in command
    assert "-UserName '" + principal.replace("'", "''") + "'" in command
    assert "-ComputerName '" + target.replace("'", "''") + "'" in command
    assert "Password" not in command and "SecureString" not in command
