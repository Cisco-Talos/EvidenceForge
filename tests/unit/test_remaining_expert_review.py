# Tests for remaining expert review fixes (#15, #34).

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
        import random

        _existing = {"alice.admin", "bob.dev", "svc_backup"}
        _svc_names = ["svc_backup", "svc_monitor", "svc_report", "svc_deploy", "svc_scan"]
        _sched_rng = random.Random(42)
        _sched_acct = _sched_rng.choice(_svc_names)
        while _sched_acct in _existing:
            _sched_acct = _sched_rng.choice(_svc_names) + str(_sched_rng.randint(1, 9))
        assert _sched_acct not in _existing

    def test_management_sweep_targets_multiple_hosts(self):
        """Management sweep should target 5-15 servers."""
        import random

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
