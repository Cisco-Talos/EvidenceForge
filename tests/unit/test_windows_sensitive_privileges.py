# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Special-logon lists describe sensitive privileges, not every token right."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import WindowsSpecialPrivilegesConfig
from evidenceforge.generation.activity.windows_auth_realism import (
    special_privilege_profile,
    special_privileges_config,
)
from evidenceforge.generation.emitters.windows import _special_privilege_fallback


@pytest.mark.parametrize(
    "profile",
    ["service_account", "system_account", "domain_admin", "workstation_admin", "uac_elevated_user"],
)
def test_native_privilege_profiles_are_sensitive_and_empty_is_valid(profile: str) -> None:
    config = WindowsSpecialPrivilegesConfig.model_validate(special_privileges_config())
    privileges = special_privilege_profile(profile)
    assert set(privileges) <= set(config.sensitive_privileges)
    assert len(privileges) == len(set(privileges))
    assert bool(privileges) is (profile != "uac_elevated_user")


@pytest.mark.parametrize(
    "invalid",
    [
        "SeChangeNotifyPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeTimeZonePrivilege",
        "SeShutdownPrivilege",
        "SeUndockPrivilege",
    ],
)
def test_configuration_rejects_nonsensitive_token_rights(invalid: str) -> None:
    data = deepcopy(special_privileges_config())
    data["profiles"]["service_account"]["privileges"].append(invalid)
    with pytest.raises(ValidationError, match="nonsensitive"):
        WindowsSpecialPrivilegesConfig.model_validate(data)


def test_configuration_rejects_duplicate_profile_privilege() -> None:
    data = deepcopy(special_privileges_config())
    data["profiles"]["service_account"]["privileges"] *= 2
    with pytest.raises(ValidationError, match="duplicate"):
        WindowsSpecialPrivilegesConfig.model_validate(data)


@pytest.mark.parametrize(
    "username,profile",
    [
        ("SYSTEM", "system_account"),
        ("HOST$", "system_account"),
        ("NETWORK SERVICE", "service_account"),
        ("LOCAL SERVICE", "service_account"),
        ("admin", "workstation_admin"),
    ],
)
def test_compatibility_fallback_uses_shared_validated_profile(username: str, profile: str) -> None:
    assert _special_privilege_fallback(username).split() == list(special_privilege_profile(profile))


def test_modern_session_impersonation_privilege_is_retained() -> None:
    assert "SeDelegateSessionUserImpersonatePrivilege" in special_privilege_profile(
        "system_account"
    )
    assert "SeDelegateSessionUserImpersonatePrivilege" in special_privilege_profile("domain_admin")
