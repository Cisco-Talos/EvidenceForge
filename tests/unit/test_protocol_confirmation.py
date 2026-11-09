# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Confirmed protocol evidence requires its directional exchange, not a port guess."""

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import ProtocolConfirmationConfig
from evidenceforge.generation.activity.network_transport import confirmed_service_for_payload


@pytest.mark.parametrize(
    "orig,resp,expected", [(1500, 0, ""), (0, 95, ""), (1500, 95, "mysql"), (0, 0, "")]
)
def test_fresh_mysql_requires_server_greeting_and_client_response(
    orig: int, resp: int, expected: str
) -> None:
    assert (
        confirmed_service_for_payload(
            "mysql",
            protocol="tcp",
            history="ShADaR",
            orig_bytes=orig,
            resp_bytes=resp,
            missed_bytes=0,
        )
        == expected
    )


@pytest.mark.parametrize(
    "service,history,missed,expected",
    [
        ("mysql", "Dd", 0, "mysql"),
        ("mysql", "ShADaR", 20, "mysql"),
        ("ssh", "ShADaR", 0, "ssh"),
        ("http", "ShADaR", 0, "http"),
    ],
)
def test_midstream_gaps_and_unqualified_protocols_preserve_existing_truth(
    service: str, history: str, missed: int, expected: str
) -> None:
    assert (
        confirmed_service_for_payload(
            service,
            protocol="tcp",
            history=history,
            orig_bytes=900,
            resp_bytes=0,
            missed_bytes=missed,
        )
        == expected
    )


@pytest.mark.parametrize(
    "requirements",
    [{"mysql": []}, {"MySQL": ["orig"]}, {"mysql": ["orig", "orig"]}, {"mysql": ["unknown"]}],
)
def test_confirmation_requirements_reject_ambiguous_config(
    requirements: dict[str, list[str]],
) -> None:
    with pytest.raises(ValidationError):
        ProtocolConfirmationConfig(payload_directions=requirements)


@pytest.mark.parametrize(
    "overlay", [{"payload_direction": {"mysql": ["orig"]}}, {"payload_directions": []}]
)
def test_confirmation_overlay_does_not_hide_invalid_fields(overlay: dict[str, object]) -> None:
    from evidenceforge.generation.activity.network_params import merge_network_params

    merged = merge_network_params(
        {"protocol_confirmation": {"payload_directions": {"mysql": ["orig", "resp"]}}},
        {"protocol_confirmation": overlay},
    )
    with pytest.raises(ValidationError):
        ProtocolConfirmationConfig.model_validate(merged["protocol_confirmation"])
