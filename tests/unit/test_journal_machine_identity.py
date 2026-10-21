# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Journal file effects consume the same host identity as native housekeeping."""

import random

import pytest

from evidenceforge.generation.activity.edr_pools import (
    materialize_edr_template,
    select_ambient_file_churn_effect,
    select_file_side_effect,
)


@pytest.mark.parametrize("machine_id", ["a" * 32, "0123456789abcdef" * 2])
def test_repeated_journald_effects_preserve_canonical_machine_identity(machine_id: str) -> None:
    effects = [
        select_ambient_file_churn_effect(
            "/usr/lib/systemd/systemd-journald",
            "systemd-journald",
            "linux",
            random.Random(seed),
            "root",
            [],
            ["modify"],
            [1],
            machine_id=machine_id,
        )
        for seed in range(40)
    ]
    paths = [effect[1] for effect in effects if effect is not None]
    assert paths
    assert all(f"/journal/{machine_id}/" in path for path in paths)
    assert any(path.startswith("/run/") for path in paths)
    assert any(path.startswith("/var/") for path in paths)


def test_missing_machine_identity_omits_optional_journal_effect() -> None:
    assert (
        select_file_side_effect(
            "/usr/lib/systemd/systemd-journald",
            "systemd-journald",
            "linux",
            random.Random(5),
            user="root",
        )
        is None
    )
    with pytest.raises(ValueError, match="canonical"):
        materialize_edr_template("/run/log/journal/{machine_id}/system.journal", random.Random(2))
    path = materialize_edr_template(r"C:\Temp\{hex}.tmp", random.Random(2))
    assert len(path.rsplit("\\", 1)[1].split(".")[0]) == 8
