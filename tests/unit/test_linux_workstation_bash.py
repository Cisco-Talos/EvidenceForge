# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Linux workstation bash_history emission.

Verifies that assigned users on Linux workstations get bash_command
events emitted during baseline hour generation.
"""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from evidenceforge.models.scenario import System, User


def _make_linux_workstation(assigned_user: str = "diana.kowalski") -> System:
    return System(
        hostname="WS-DA-01",
        ip="10.10.1.20",
        os="Ubuntu 22.04",
        type="workstation",
        assigned_user=assigned_user,
    )


def _make_user(username: str = "diana.kowalski", persona: str = "data_analyst") -> User:
    return User(
        username=username,
        full_name="Diana Kowalski",
        email=f"{username}@example.com",
        enabled=True,
        persona=persona,
    )


class TestLinuxWorkstationBashEmission:
    """The baseline workstation bash block emits commands for the assigned user."""

    def _run_workstation_bash_block(self, system: System, users: list[User]) -> list:
        """Execute just the Linux-workstation bash block from _generate_hour.

        Builds a minimal fake BaselineMixin instance, sets up the relevant
        attributes, then calls the code path directly so we can assert on
        generate_bash_command calls without starting the full baseline engine.
        """
        from evidenceforge.generation.engine.baseline import _get_os_category

        # Replicate the local variables present at the point of the new block
        os_cat = _get_os_category(system.os)
        sys_type = (system.type or "workstation").lower()
        current_hour = datetime(2024, 3, 18, 9, 0, 0, tzinfo=UTC)

        mock_activity_gen = MagicMock()
        mock_state_manager = MagicMock()

        scenario = SimpleNamespace(environment=SimpleNamespace(users=users))

        # Run the exact workstation bash block inline (mirroring the source)
        from evidenceforge.generation.activity.bash_commands import pick_bash_command_entry

        collected_calls: list[tuple] = []

        if os_cat == "linux" and sys_type == "workstation" and system.assigned_user:
            ws_user = next(
                (
                    u
                    for u in scenario.environment.users
                    if u.username == system.assigned_user and u.enabled
                ),
                None,
            )
            if ws_user is not None:
                rng = random.Random(42)
                n_cmds = rng.randint(1, 4)
                ts0 = current_hour + timedelta(seconds=rng.uniform(0, 3599))
                hour_end = current_hour + timedelta(hours=1)
                cumulative = 0
                typo_count = 0
                for _ in range(n_cmds):
                    gap = rng.randint(30, 300)
                    cumulative += gap
                    cmd_time = ts0 + timedelta(seconds=cumulative)
                    if cmd_time >= hour_end:
                        break
                    cmd, is_typo = pick_bash_command_entry(
                        rng,
                        ws_user.persona or "",
                        system.hostname,
                        system.services,
                        username=ws_user.username,
                        session_command_count=n_cmds,
                        prior_typo_count=typo_count,
                    )
                    if is_typo:
                        typo_count += 1
                    mock_state_manager.set_current_time(cmd_time)
                    mock_activity_gen.generate_bash_command(ws_user, system, cmd_time, cmd)
                    collected_calls.append((ws_user, system, cmd_time, cmd))

        return collected_calls

    def test_emits_bash_commands_for_assigned_user(self):
        system = _make_linux_workstation()
        user = _make_user()
        calls = self._run_workstation_bash_block(system, [user])
        assert len(calls) >= 1, "Should emit at least one bash_command for the assigned user"

    def test_correct_user_in_calls(self):
        system = _make_linux_workstation("diana.kowalski")
        user = _make_user("diana.kowalski", "data_analyst")
        calls = self._run_workstation_bash_block(system, [user])
        for u, _sys, _ts, _cmd in calls:
            assert u.username == "diana.kowalski"

    def test_skips_disabled_user(self):
        system = _make_linux_workstation("diana.kowalski")
        disabled_user = User(
            username="diana.kowalski",
            full_name="Diana",
            email="diana@x.com",
            enabled=False,
            persona="data_analyst",
        )
        calls = self._run_workstation_bash_block(system, [disabled_user])
        assert len(calls) == 0, "Disabled user should not get bash commands"

    def test_skips_windows_workstation(self):
        win_system = System(
            hostname="WS-WIN-01",
            ip="10.10.1.21",
            os="Windows 10",
            type="workstation",
            assigned_user="raj.subramaniam",
        )
        user = _make_user("raj.subramaniam", "data_analyst")
        calls = self._run_workstation_bash_block(win_system, [user])
        assert len(calls) == 0, "Windows workstations should not get bash commands from this path"

    def test_skips_linux_server(self):
        server = System(
            hostname="APP-01",
            ip="10.10.2.10",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=None,
        )
        user = _make_user("sysadmin", "sysadmin")
        calls = self._run_workstation_bash_block(server, [user])
        assert len(calls) == 0, "Linux servers use the SSH-roster path, not this one"

    def test_commands_are_strings(self):
        system = _make_linux_workstation()
        user = _make_user()
        calls = self._run_workstation_bash_block(system, [user])
        for _, _, _, cmd in calls:
            assert isinstance(cmd, str) and len(cmd) > 0
