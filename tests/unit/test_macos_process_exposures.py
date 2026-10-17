# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac process exposure uses explicit Mac overrides or shared local POSIX carriers."""

from types import ModuleType

import pytest

from evidenceforge.config.secret_families import family_names
from evidenceforge.generation import adversarial_payload, spillage


@pytest.mark.parametrize("family", sorted(family_names()))
def test_mac_secret_family_does_not_reuse_linux_tool_installation(family: str) -> None:
    for index in range(16):
        rendered = spillage.render_for_surface(
            "EvidenceForgeFake-example",
            "process_command_line",
            family,
            f"mac-carrier-{index}",
            os_category="macos",
        )
        assert rendered.process_name == "/usr/bin/env"
        assert "EvidenceForgeFake-example" in rendered.command
        assert "/usr/bin/aws" not in rendered.command
        assert "/usr/bin/psql" not in rendered.command


@pytest.mark.parametrize("renderer", [spillage, adversarial_payload])
def test_mac_override_uses_existing_carrier_dictionary(
    renderer: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        renderer,
        "get_family",
        lambda _: {
            "surfaces": ["process_command_line"],
            "carriers": {
                "process_command_line": ["/linux-only {value}"],
                "process_command_line_macos": ["/bin/echo {value}"],
            },
        },
    )
    rendered = renderer.render_for_surface(
        "EvidenceForgeFake-example",
        "process_command_line",
        "custom",
        "same-key",
        os_category="macos",
    )
    assert rendered.process_name == "/bin/echo"
    assert rendered.command == "/bin/echo EvidenceForgeFake-example"


def test_literal_mac_payload_uses_existing_local_posix_carrier() -> None:
    result = adversarial_payload.render_for_surface(
        "EFORGE_TEST_example",
        "process_command_line",
        None,
        "literal",
        os_category="macos",
    )
    assert result.process_name == "/usr/bin/env"
    assert "EFORGE_TEST_example" in result.command


def test_mac_carrier_is_a_value_in_existing_family_schema() -> None:
    from copy import deepcopy

    from evidenceforge.config.payload_families import get_family as payload_family
    from evidenceforge.config.schemas import PayloadFamilyEntry, SecretFamilyEntry
    from evidenceforge.config.secret_families import get_family as secret_family

    for schema, entry in (
        (SecretFamilyEntry, secret_family("aws_iam")),
        (PayloadFamilyEntry, payload_family("structured_log_injection")),
    ):
        values = deepcopy(entry)
        values.setdefault("carriers", {})["process_command_line_macos"] = ["/bin/echo {value}"]
        validated = schema.model_validate(values)
        assert validated.carriers["process_command_line_macos"] == ["/bin/echo {value}"]
