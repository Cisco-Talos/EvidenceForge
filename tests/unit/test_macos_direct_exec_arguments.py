# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import pytest

from evidenceforge.generation.activity.direct_exec import catalog_direct_exec_arguments
from evidenceforge.models.exceptions import StateError


@pytest.mark.parametrize(
    "image,command,arguments",
    [
        ("/usr/bin/example", "/usr/bin/example", ("/usr/bin/example",)),
        (
            "/Applications/Example App/Worker",
            '"/Applications/Example App/Worker" --worker',
            ("/Applications/Example App/Worker", "--worker"),
        ),
        (
            "/usr/bin/example",
            "/usr/bin/example 'literal $HOME' ''",
            ("/usr/bin/example", "literal $HOME", ""),
        ),
    ],
)
def test_direct_catalog_arguments_preserve_literal_values(
    image: str, command: str, arguments: tuple[str, ...]
) -> None:
    assert catalog_direct_exec_arguments(image, command) == arguments


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/example $HOME",
        "/usr/bin/example | cat",
        "/usr/bin/example > /tmp/result",
        "OTHER=value /usr/bin/example",
        "/usr/bin/example $(id)",
        "/usr/bin/example '",
        "",
        "/another/executable",
        "/usr/bin/example\0",
        "/usr/bin/example " + "x" * 65536,
    ],
)
def test_direct_catalog_arguments_reject_shell_semantics_or_unbound_images(command: str) -> None:
    with pytest.raises(StateError):
        catalog_direct_exec_arguments("/usr/bin/example", command)
