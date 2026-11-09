# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authored HTTP exposures preserve the actor's platform at the network boundary."""

from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.models.scenario import System
from tests.unit.test_macos_foundations import _TIME, _user


@pytest.mark.parametrize("kind", ["spillage", "adversarial_payload"])
@pytest.mark.parametrize(
    ("os_name", "required", "excluded"),
    [
        ("macOS 26", "Macintosh", ("Windows", "X11", "Linux", "iPhone")),
        ("Windows 11", "Windows", ("Macintosh", "Linux")),
        ("Ubuntu 24.04", "Linux", ("Windows", "Macintosh")),
    ],
)
def test_referrer_exposure_uses_actor_browser_pool_at_canonical_connection(
    kind: str, os_name: str, required: str, excluded: tuple[str, ...]
) -> None:
    generator = object.__new__(ActivityGenerator)
    generator._network_visibility = None
    generator._build_host_context = Mock(return_value=Mock(fqdn="web.example.test"))
    generator.generate_connection = Mock(return_value="invented-flow")
    source = System(hostname="ACTOR", ip="192.0.2.10", os=os_name, type="workstation")
    target = System(
        hostname="WEB",
        ip="192.0.2.20",
        os="Ubuntu 24.04",
        type="server",
        roles=["web_server"],
        services=["http"],
    )
    generate = getattr(generator, f"generate_{kind}")
    for index in range(20):
        result = generate(
            user=_user(),
            system=source,
            time=_TIME,
            surface="http_referrer",
            family="jwt" if kind == "spillage" else None,
            value=None if kind == "spillage" else "EFORGE_TEST_referrer",
            seed_key=f"invented-referrer-{index}",
            scheme="http",
            target_system=target,
        )
        connection = generator.generate_connection.call_args.kwargs
        http = connection["http"]
        assert required in http.user_agent
        assert not any(platform in http.user_agent for platform in excluded)
        assert result["rendered_value"] in http.referrer
        assert result["target_system"] == "web.example.test"
        assert connection["src_ip"] == source.ip
        assert connection["dst_ip"] == target.ip
        assert connection["source_system"] is source
        assert connection["proxy_bypass"] is True


def test_default_internal_web_visitor_profile_selects_only_mac_browser_presentations() -> None:
    import random

    from evidenceforge.generation.activity.web_session_profiles import (
        load_web_session_profiles,
        pick_web_user_agent,
    )

    data = load_web_session_profiles()
    profile = data["visitor_classes"]["human_browser"]
    presentations = {
        pick_web_user_agent(random.Random(index), profile, source_os="macos") for index in range(32)
    }
    assert len(presentations) > 1
    assert all("Macintosh" in value for value in presentations)
    assert not any("Windows" in value or "Linux" in value for value in presentations)
