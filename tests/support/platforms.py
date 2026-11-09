# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Execution requirements for reference-kit operating-system contracts."""

import os

import pytest

requires_posix_reference: pytest.MarkDecorator = pytest.mark.skipif(
    os.name != "posix",
    reason="Reference-kit operations require POSIX paths, ownership, no-follow I/O or Unix syscalls",
)
