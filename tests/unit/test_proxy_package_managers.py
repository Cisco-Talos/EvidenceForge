# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for distro-aware package-manager proxy activity."""

import random

from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    _linux_foreground_lifetime,
)
from evidenceforge.generation.activity.proxy_user_agents import normalize_proxy_user_agent_for_os
from evidenceforge.models.scenario import System


def _system(hostname: str, os_name: str, system_type: str = "server") -> System:
    return System(
        hostname=hostname,
        ip="10.10.2.30",
        os=os_name,
        type=system_type,
    )


def _generator() -> ActivityGenerator:
    generator = object.__new__(ActivityGenerator)
    generator._ad_domain = "meridianhcs.local"
    generator._proxy_listener_port = 8080
    return generator


def test_normalize_proxy_user_agent_replaces_libdnf_on_ubuntu_package_host() -> None:
    """Ubuntu package repo traffic should use apt-family User-Agents."""
    ubuntu = _system("APP-INT-01", "Ubuntu 22.04")

    user_agent = normalize_proxy_user_agent_for_os(
        random.Random(1),
        ubuntu,
        "libdnf (Fedora Linux 39; server; Linux.x86_64)",
        hostname="security.ubuntu.com",
    )

    assert "apt-http" in user_agent.lower()
    assert "libdnf" not in user_agent.lower()


def test_normalize_proxy_user_agent_replaces_apt_on_centos_package_host() -> None:
    """RPM-family hosts should not keep apt-family User-Agents for repo traffic."""
    centos = _system("DB-PROD-01", "CentOS 8")

    user_agent = normalize_proxy_user_agent_for_os(
        random.Random(2),
        centos,
        "apt-http/2.4.11 (amd64)",
        hostname="download.fedoraproject.org",
    )

    assert "libdnf" in user_agent.lower()
    assert "centos" in user_agent.lower()


def test_explicit_proxy_apt_user_agent_uses_apt_method_helper() -> None:
    """Apt repo sockets are owned by apt's method helper, not repeated apt-get parents."""
    generator = _generator()
    proxy = _system("PROXY-01", "Ubuntu 22.04")
    ubuntu = _system("APP-INT-01", "Ubuntu 22.04")

    hint = generator._explicit_proxy_client_process_hint(
        user_agent="apt-http/2.4.11 (amd64)",
        hostname="security.ubuntu.com",
        dst_port=443,
        proxy_sys=proxy,
        source_system=ubuntu,
    )

    assert hint == ("/usr/lib/apt/methods/https", "/usr/lib/apt/methods/https")


def test_explicit_proxy_rejects_apt_hint_on_rpm_host() -> None:
    """Apt User-Agents should not create apt process owners on RPM-family hosts."""
    generator = _generator()
    proxy = _system("PROXY-01", "Ubuntu 22.04")
    centos = _system("DB-PROD-01", "CentOS 8")

    hint = generator._explicit_proxy_client_process_hint(
        user_agent="apt-http/2.4.11 (amd64)",
        hostname="security.ubuntu.com",
        dst_port=443,
        proxy_sys=proxy,
        source_system=centos,
    )

    assert hint is None


def test_apt_method_helper_has_package_update_lifetime() -> None:
    """Apt method helper ownership should live long enough to cover repo fan-out."""
    assert _linux_foreground_lifetime(
        "/usr/lib/apt/methods/https",
        "/usr/lib/apt/methods/https",
    ) == (20.0, 180.0)
