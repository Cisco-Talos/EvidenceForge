"""Mounted Mac baseline access uses the same exact audience as SMB execution."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.storage_world import CompiledStorageMapping, StorageWorldModel
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import generation_seed_scope


def _world() -> StorageWorldModel:
    return StorageWorldModel(
        volumes=(),
        shares=(),
        mappings=(
            CompiledStorageMapping(
                id="research",
                share="FS.research",
                users={"alice"},
                systems={"CLIENT"},
                mount="/Volumes/Research",
                lifecycle="persistent",
            ),
            CompiledStorageMapping(
                id="drive",
                share="FS.homes",
                users={"alice"},
                systems={"CLIENT"},
                drive="H:",
                lifecycle="persistent",
            ),
            CompiledStorageMapping(
                id="other-user",
                share="FS.homes",
                users={"bob"},
                systems={"CLIENT"},
                mount="/Volumes/Homes",
                lifecycle="persistent",
            ),
            CompiledStorageMapping(
                id="other-host",
                share="FS.department",
                users={"alice"},
                systems={"OTHER"},
                mount="/Volumes/Department",
                lifecycle="persistent",
            ),
        ),
    )


def test_mapping_audience_is_shared_case_insensitive_and_requires_both_actor_and_host() -> None:
    world = _world()
    assert [
        m.id for m in world.applicable_mappings("fs.RESEARCH", username="ALICE", hostname="client")
    ] == ["research"]
    assert [
        m.id for m in world.applicable_mappings("FS.homes", username="alice", hostname="CLIENT")
    ] == ["drive"]
    assert not world.applicable_mappings("FS.research", username="bob", hostname="CLIENT")
    assert not world.applicable_mappings("FS.research", username="alice", hostname="OTHER")


@pytest.mark.parametrize("os_label", ["macOS 27", "Ubuntu 24.04", "Windows 11"])
def test_baseline_mounted_admission_preserves_non_mac_sibling_paths(os_label: str) -> None:
    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    client = System(hostname="CLIENT", ip="192.0.2.10", os=os_label, type="workstation")
    dc = System(hostname="DC", ip="192.0.2.20", os="Windows Server 2022", type="domain_controller")
    server = System(hostname="FS", ip="192.0.2.30", os="Ubuntu 24.04", type="server")
    actor = User(username="alice", full_name="Alice Example", email="alice@example.test")
    world = _world()
    world.shares = tuple(
        SimpleNamespace(ref=ref, system=host, preset=preset, files=(object(),))
        for ref, host, preset in [
            ("DC.sysvol", "DC", "dc_policy"),
            ("FS.research", "FS", "collaboration"),
            ("FS.homes", "FS", "homes"),
            ("FS.department", "FS", "department"),
        ]
    )
    baseline = SimpleNamespace(
        scenario=SimpleNamespace(
            environment=SimpleNamespace(systems=[client, dc, server], users=[actor])
        ),
        world_model=SimpleNamespace(
            hosts={"CLIENT": SimpleNamespace(supports=lambda _capability: True)}
        ),
        state_manager=SimpleNamespace(
            get_active_sessions_on_system_at=Mock(
                return_value=[SimpleNamespace(logon_type=2, username="alice", explorer_pid=None)]
            )
        ),
        activity_generator=SimpleNamespace(_storage_world=world),
        generation_seed=42,
        _generation_epoch=start,
        _infra_ips={"dc": [dc.ip]},
        _uses_linux_smb_prepass=lambda: True,
        _build_smb_targets=lambda *_args: ([dc.ip, server.ip, server.ip, server.ip], [server]),
        _resolve_traffic_rate=lambda _key: (60, 120),
        _scaled_interval_range=lambda _system, _key, low, high: (low, high),
    )
    with generation_seed_scope(42):
        intents = BaselineMixin._plan_baseline_smb_activity(baseline, start)
    assert intents
    shares = {intent.share_ref for intent in intents}
    if os_label.startswith("macOS"):
        assert shares == {"FS.research"}
        assert all(intent.actor == actor for intent in intents)
        world.mappings = ()
        with generation_seed_scope(42):
            assert BaselineMixin._plan_baseline_smb_activity(baseline, start) == ()
    else:
        assert "DC.sysvol" in shares and "FS.homes" in shares
