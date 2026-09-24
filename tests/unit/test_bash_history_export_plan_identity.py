# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Cross-platform checks for Bash history journal file identities."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import bash_history as bash_history_module
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter, _ExportPlan


def test_export_plan_preserves_native_file_ids_above_sqlite_integer_limit(tmp_path: Path) -> None:
    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
    connection: sqlite3.Connection | None = None
    try:
        batch = ExactPublicationAuthority(capacity=1).issue_batch()
        batch.publish(
            lambda: emitter.emit_event(
                {
                    "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
                    "username": "alice",
                    "hostname": "linux-01",
                    "host_fqdn": "linux-01.example.test",
                    "command": "pwd",
                }
            )
        )
        batch.release_no_fail()
        writer = next(iter(emitter._writers.values()))
        connection = writer._connection
        assert connection is not None

        plan = _ExportPlan(
            max_sequence=1,
            baseline_exists=False,
            baseline_digest="",
            baseline_size=0,
            expected_exists=True,
            expected_digest="",
            expected_size=1,
            temporary_name=".large-native-id.tmp",
            temporary_device=(1 << 64) + 7,
            temporary_inode=(1 << 127) + 9,
            working_bytes=1,
        )
        bash_history_module._insert_export_plan_row(connection, plan)
        connection.commit()

        assert writer._load_export_plan_unlocked() == plan
        assert connection.execute(
            "SELECT typeof(temporary_device), typeof(temporary_inode) FROM export_plan"
        ).fetchone() == ("blob", "blob")

        connection.execute("UPDATE export_plan SET temporary_device = 17, temporary_inode = 23")
        connection.commit()
        assert writer._load_export_plan_unlocked() == replace(
            plan, temporary_device=17, temporary_inode=23
        )
    finally:
        if connection is not None:
            connection.rollback()
            connection.execute("DELETE FROM export_plan")
            connection.commit()
        emitter.close()
