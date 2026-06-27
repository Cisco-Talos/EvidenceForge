# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for eforge info inventory collection."""

from evidenceforge.cli.info import gather_info


def test_system_roles_include_author_facing_topology_and_activity_roles():
    roles = set(gather_info(field="system_roles")["system_roles"])

    assert {
        "app_server",
        "database",
        "dns_server",
        "domain_controller",
        "file_server",
        "forward_proxy",
        "load_balancer",
        "log_server",
        "mail_server",
        "monitoring",
        "nfs_server",
        "print_server",
        "web_server",
        "workstation",
    } <= roles
    assert "_default" not in roles
