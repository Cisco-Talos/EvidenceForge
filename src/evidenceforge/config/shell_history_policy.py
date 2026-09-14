# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared account eligibility for generated and authored shell-history evidence."""

NONINTERACTIVE_BASH_USERS: set[str] = {"apache", "www-data", "nginx", "httpd", "tomcat"}


def is_noninteractive_bash_user(username: str) -> bool:
    """Return whether the account is excluded from interactive shell history."""
    return username.lower() in NONINTERACTIVE_BASH_USERS
