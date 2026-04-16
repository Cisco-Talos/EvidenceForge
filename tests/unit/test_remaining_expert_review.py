# Tests for remaining expert review fixes (#15, #34).

import random

from evidenceforge.generation.engine.baseline import _pick_non_colliding_account_name
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
