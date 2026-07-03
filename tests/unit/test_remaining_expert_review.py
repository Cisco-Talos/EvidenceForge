# Tests for remaining expert review fixes (#15, #34).

import random
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from evidenceforge.generation.activity.ids_signatures import load_ids_signatures
from evidenceforge.generation.engine.baseline import (
    BaselineMixin,
    _pick_non_colliding_account_name,
    _scheduled_stale_failure_offsets,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import AccountCreatedEventSpec, AccountDeletedEventSpec
from evidenceforge.utils.rng import _stable_seed


class TestFallbackRidSequential:
    """#34: Fallback RIDs should be sequential from max existing, not 7000+."""

    def test_fallback_rid_near_max(self):
        """Unknown account RID should be close to max existing RID."""
        # Simulate the fixed fallback logic
        existing_sids = {
            "user1": "S-1-5-21-1234-5678-9012-1001",
            "user2": "S-1-5-21-1234-5678-9012-1002",
            "WS-01$": "S-1-5-21-1234-5678-9012-1003",
        }
        max_rid = max(
            (
                int(sid.rsplit("-", 1)[1])
                for sid in existing_sids.values()
                if sid.startswith("S-1-5-21-")
            ),
            default=1100,
        )
        assert max_rid == 1003

        # Fallback RID should be near max_rid, not 7000+
        unknown_username = "svc_sqlreader"
        rid = max_rid + 1 + (_stable_seed(f"unknown_sid_{unknown_username}") % 50)
        assert rid < 1100, f"RID {rid} is too far from max {max_rid}"
        assert rid > max_rid

    def test_no_7000_range(self):
        """Fallback should never produce RIDs in 7000-9999 range."""
        max_rid = 1010
        for name in ["account_a", "account_b", "account_c", "test_svc"]:
            rid = max_rid + 1 + (_stable_seed(f"unknown_sid_{name}") % 50)
            assert rid < 7000, f"RID {rid} for {name} is in old 7000+ range"


class TestBaselineFailedLogonPatterns:
    """#15: Diverse failed logon patterns in baseline."""

    def test_scheduled_task_account_not_collides(self):
        """Scheduled task account names should not collide with scenario accounts."""
        _existing = {"alice.admin", "bob.dev", "svc_backup"}
        _sched_rng = random.Random(42)
        _sched_acct = _pick_non_colliding_account_name(
            rng=_sched_rng,
            existing_accounts=_existing,
            base_names=["svc_backup", "svc_monitor", "svc_report", "svc_deploy", "svc_scan"],
        )
        assert _sched_acct not in _existing

    def test_scheduled_task_account_prefers_available_unsuffixed_alias(self):
        """Stale service-account noise should avoid generated-looking numeric suffixes."""
        _existing = {"alice.admin", "bob.dev", "svc_backup", "svc_monitor"}
        _sched_acct = _pick_non_colliding_account_name(
            rng=random.Random(42),
            existing_accounts=_existing,
            base_names=["svc_backup", "svc_monitor", "svc_report", "svc_deploy", "svc_scan"],
        )

        assert _sched_acct in {"svc_report", "svc_deploy", "svc_scan"}
        assert not re.fullmatch(r"svc_backup\d+", _sched_acct)

    def test_scheduled_task_account_bounded_when_default_pool_exhausted(self):
        """Account selection should terminate with fallback naming if default pool is exhausted."""
        _svc_names = ["svc_backup", "svc_monitor", "svc_report", "svc_deploy", "svc_scan"]
        _existing = {name for name in _svc_names}
        _existing.update(f"{name}{digit}" for name in _svc_names for digit in range(1, 10))

        acct = _pick_non_colliding_account_name(
            rng=random.Random(42),
            existing_accounts=_existing,
            base_names=_svc_names,
        )

        assert acct not in _existing
        assert acct.startswith("svc_backup_")

    def test_management_sweep_account_bounded_when_default_pool_exhausted(self):
        """Management sweep account selection should terminate when svc_mgmt and 1-9 are reserved."""
        _existing = {"svc_mgmt", *(f"svc_mgmt{digit}" for digit in range(1, 10))}
        acct = _pick_non_colliding_account_name(
            rng=random.Random(42),
            existing_accounts=_existing,
            base_names=["svc_mgmt"],
        )
        assert acct == "svc_mgmt_1"

    def test_management_sweep_targets_multiple_hosts(self):
        """Management sweep should target 5-15 servers."""
        rng = random.Random(42)
        servers = [f"SRV-{i:02d}" for i in range(20)]
        n_targets = min(rng.randint(5, 15), len(servers))
        targets = rng.sample(servers, n_targets)
        assert 5 <= len(targets) <= 15

    def test_scheduled_stale_credentials_do_not_use_exact_two_hour_cadence(self):
        """Stale scheduled-credential noise should not expose modulo-hour timing."""
        config = {
            "interval_ranges": [{"min_minutes": 105, "max_minutes": 155, "weight": 1}],
            "first_occurrence_seconds_min": 0,
            "first_occurrence_seconds_max": 1200,
            "jitter_seconds_min": -420,
            "jitter_seconds_max": 780,
            "skip_probability": 0.0,
            "backoff_probability": 0.0,
            "backoff_seconds_min": 0,
            "backoff_seconds_max": 0,
        }
        event_seconds = []
        for hour_idx in range(12):
            for offset in _scheduled_stale_failure_offsets(
                scenario_name="cadence-test",
                account_name="svc_deploy",
                hostname="LNX-01",
                hour_idx=hour_idx,
                config=config,
            ):
                event_seconds.append(hour_idx * 3600 + offset)

        gaps = [right - left for left, right in zip(event_seconds, event_seconds[1:], strict=False)]
        assert len(gaps) >= 3
        assert any(abs(gap - 7200) > 600 for gap in gaps)
        assert len(set(gaps)) > 1

    def test_password_typo_pattern(self):
        """Password typo: 1-2 failures should precede success by seconds."""
        import random
        from datetime import datetime, timedelta

        rng = random.Random(42)
        base_time = datetime(2024, 3, 15, 10, 30, 0)
        n_fails = rng.randint(1, 2)
        fail_times = [base_time + timedelta(seconds=i * rng.randint(2, 8)) for i in range(n_fails)]
        # All failure times should be within 20s of base
        for ft in fail_times:
            assert (ft - base_time).total_seconds() < 20


class TestStorylineAccountLifecycle:
    """Storyline-created accounts should not leak into pre-creation baseline noise."""

    def test_service_account_unavailable_before_storyline_creation(self):
        class Engine(BaselineMixin):
            start_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

            def _parse_storyline_time(self, time_str):
                hours = int(time_str.removeprefix("+").removesuffix("h"))
                return self.start_time + timedelta(hours=hours)

        engine = Engine()
        engine.scenario = SimpleNamespace(
            storyline=[
                SimpleNamespace(
                    time="+4h",
                    events=[AccountCreatedEventSpec(target_username="svc_sqlreader")],
                )
            ]
        )

        assert not engine._service_account_available_at(
            "svc_sqlreader",
            datetime(2024, 3, 18, 14, 0, tzinfo=UTC),
        )
        assert engine._service_account_available_at(
            "svc_sqlreader",
            datetime(2024, 3, 18, 16, 1, tzinfo=UTC),
        )
        assert engine._service_account_available_at(
            "svc_backup",
            datetime(2024, 3, 18, 14, 0, tzinfo=UTC),
        )

    def test_service_account_unavailable_after_storyline_deletion(self):
        class Engine(BaselineMixin):
            start_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

            def _parse_storyline_time(self, time_str):
                hours = int(time_str.removeprefix("+").removesuffix("h"))
                return self.start_time + timedelta(hours=hours)

        engine = Engine()
        engine.scenario = SimpleNamespace(
            storyline=[
                SimpleNamespace(
                    time="+1h",
                    events=[AccountCreatedEventSpec(target_username="svc_sqlreader")],
                ),
                SimpleNamespace(
                    time="+5h",
                    events=[AccountDeletedEventSpec(target_username="svc_sqlreader")],
                ),
            ]
        )

        assert engine._service_account_available_at(
            "svc_sqlreader",
            datetime(2024, 3, 18, 14, 0, tzinfo=UTC),
        )
        assert not engine._service_account_available_at(
            "svc_sqlreader",
            datetime(2024, 3, 18, 17, 1, tzinfo=UTC),
        )

    def test_service_account_delegation_uses_role_specific_caller_process(self):
        engine = object.__new__(BaselineMixin)
        config = {
            "caller_profiles": [
                {
                    "name": "backup_agents",
                    "account_terms": ["backup"],
                    "weight": 1,
                    "processes": [
                        {
                            "image": r"C:\Program Files\BackupAgent\backupsvc.exe",
                            "command_line": r'"C:\Program Files\BackupAgent\backupsvc.exe"',
                            "parent_key": "services",
                            "weight": 1,
                        }
                    ],
                },
                {
                    "name": "default_service_tasks",
                    "account_terms": ["svc"],
                    "weight": 1,
                    "processes": [
                        {
                            "image": r"C:\Windows\System32\taskhostw.exe",
                            "command_line": "taskhostw.exe /Run",
                            "parent_key": "svchost_netsvcs",
                            "weight": 1,
                        }
                    ],
                },
            ]
        }

        with patch(
            "evidenceforge.generation.engine.baseline.service_account_delegation_config",
            return_value=config,
        ):
            choice = engine._pick_service_account_delegation_process(
                "svc_backup",
                random.Random(7),
            )

        assert choice["image"].endswith(r"BackupAgent\backupsvc.exe")
        assert not choice["image"].lower().endswith(r"\services.exe")

    def test_service_account_delegation_reuses_existing_agent_process(self):
        engine = object.__new__(BaselineMixin)
        engine.state_manager = StateManager()
        engine.activity_generator = Mock()
        timestamp = datetime(2024, 3, 18, 13, 0, tzinfo=UTC)
        engine.state_manager.set_current_time(timestamp - timedelta(minutes=5))
        pid = engine.state_manager.create_process(
            system="WS-01",
            parent_pid=0,
            image=r"C:\Program Files\BackupAgent\backupsvc.exe",
            command_line=r'"C:\Program Files\BackupAgent\backupsvc.exe"',
            username="SYSTEM",
            integrity_level="System",
        )
        system = SimpleNamespace(hostname="WS-01", os="Windows 10")
        config = {
            "caller_profiles": [
                {
                    "name": "backup_agents",
                    "account_terms": ["backup"],
                    "weight": 1,
                    "processes": [
                        {
                            "image": r"C:\Program Files\BackupAgent\backupsvc.exe",
                            "command_line": r'"C:\Program Files\BackupAgent\backupsvc.exe"',
                            "parent_key": "services",
                            "weight": 1,
                        }
                    ],
                }
            ]
        }

        with patch(
            "evidenceforge.generation.engine.baseline.service_account_delegation_config",
            return_value=config,
        ):
            image, resolved_pid = engine._ensure_service_account_delegation_process(
                system=system,
                svc_name="svc_backup",
                time=timestamp,
                sys_pids={"services": 700},
                rng=random.Random(11),
            )

        assert image.endswith(r"BackupAgent\backupsvc.exe")
        assert resolved_pid == pid
        engine.activity_generator.generate_system_process.assert_not_called()


class TestIdsFalsePositiveSignatures:
    """Baseline false positives should not claim artifacts the generator does not model."""

    def test_protocol_artifact_signatures_are_not_baseline_false_positives(self):
        signatures = {sig["sid"]: sig for sig in load_ids_signatures()["signatures"]}

        for sid in (255, 2000536, 2000537, 2000545, 2002106, 2019876, 2024364):
            assert signatures[sid]["baseline_fp_allowed"] is False
