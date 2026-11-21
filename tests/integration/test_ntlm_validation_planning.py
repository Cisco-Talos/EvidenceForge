# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Account scope, transport phase and manual NTLM compatibility contracts."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.events.contexts import AuthContext
from evidenceforge.generation.actions.auth_session import NtlmValidationRequest
from evidenceforge.generation.activity import windows_auth_realism
from evidenceforge.generation.engine import GenerationEngine
from tests.integration.test_storage_policy_repository import policy_scenario


def test_scope_and_phase_preserve_known_authorities_and_exclude_other_mechanisms(
    scenarios_dir: Path, tmp_path: Path
) -> None:
    engine = GenerationEngine(policy_scenario(scenarios_dir), tmp_path)
    try:
        engine._initialize()
        generator = engine.activity_generator
        target = engine.scenario.environment.systems[0]
        user = engine.scenario.environment.users[0]
        directory = generator.identity_directory
        assert directory is not None
        account = directory.windows_account(user.username, target.hostname)
        assert account is not None
        moment = engine.start_time + timedelta(minutes=5)
        auth = AuthContext(
            username=user.username,
            auth_package="NTLM",
            logon_type=3,
            source_ip="10.0.0.250",
            workstation_name="ORIGINAL-CLIENT",
        )
        drafts = []
        for ordinal in range(50):
            start = moment - timedelta(milliseconds=3)
            event = generator._prepare_successful_ntlm_validation(
                auth=auth,
                system=target,
                time=moment,
                stable_id=f"case-{ordinal}",
                transport_start=start,
            )
            assert event is not None and start < event.timestamp < moment
            assert event.dst_host is not None and event.dst_host.hostname.startswith("DC-")
            assert event.auth is not None and event.auth.source_ip == "ORIGINAL-CLIENT"
            drafts.append(event.timestamp)
        assert len(set(drafts)) > 40
        for altered in (
            replace(auth, auth_package="Kerberos"),
            replace(auth, logon_type=11),
            replace(auth, logon_type=2),
            replace(auth, username="unmodeled-user"),
            replace(auth, username="SYSTEM"),
            replace(auth, source_ip=target.ip),
        ):
            assert (
                generator._prepare_successful_ntlm_validation(
                    auth=altered, system=target, time=moment, stable_id="excluded"
                )
                is None
            )
        directory.windows_accounts[(user.username.casefold(), target.hostname.casefold())] = (
            replace(account, scope="local", host=target.hostname, domain="")
        )
        local = generator._prepare_successful_ntlm_validation(
            auth=auth, system=target, time=moment, stable_id="local-sam"
        )
        assert local is not None and local.dst_host is not None
        assert local.dst_host.hostname == target.hostname
        assert local.dst_host.os == target.os
        assert local.dst_host.ip == target.ip
        failed = generator._build_ntlm_validation_occurrence(
            NtlmValidationRequest(
                username=user.username,
                workstation="ORIGINAL-CLIENT",
                dc_hostname=target.hostname,
                time=moment,
                status="0xc000006a",
            )
        )
        assert failed.auth is not None and failed.auth.failure_status == "0xc000006a"
    finally:
        engine._close_emitters()


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"minimum_ms": True, "maximum_ms": 4.0},
        {"minimum_ms": 9.0, "maximum_ms": 2.0},
        {"minimum_ms": 1.0, "maximum_ms": float("inf")},
    ],
)
def test_present_invalid_validation_timing_is_rejected(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    monkeypatch.setattr(
        windows_auth_realism,
        "load_windows_auth_realism",
        lambda: {"success_ntlm_validation": value},
    )
    with pytest.raises(ValidationError):
        windows_auth_realism.success_ntlm_validation_config()


def test_missing_validation_timing_preserves_frozen_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(windows_auth_realism, "load_windows_auth_realism", lambda: {})
    config = windows_auth_realism.success_ntlm_validation_config()
    assert (config.minimum_ms, config.maximum_ms) == (8.0, 120.0)
