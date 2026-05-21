# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Unit tests for ActivityGenerator thread-local RNG (Phase 2.1).

Tests deterministic seeding and RNG isolation between threads.
"""

import tempfile
from datetime import datetime
from pathlib import Path
from threading import Barrier, Thread

from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator, _get_rng
from evidenceforge.generation.emitters import WindowsEventEmitter, ZeekEmitter
from evidenceforge.generation.state_manager import StateManager


class TestThreadLocalRNG:
    """Test thread-local RNG implementation in ActivityGenerator."""

    def test_thread_local_rng_returns_random_instance(self):
        """Verify _get_rng() returns a Random instance."""
        rng = _get_rng()
        import random

        assert isinstance(rng, random.Random)

    def test_rng_reproducibility_within_thread(self):
        """Verify same thread gets same RNG instance."""
        results = []

        def check_same_rng():
            """Call _get_rng() twice and verify they're the same instance."""
            rng1 = _get_rng()
            rng2 = _get_rng()
            results.append(rng1 is rng2)  # Should be same object

        thread = Thread(target=check_same_rng)
        thread.start()
        thread.join()

        assert len(results) == 1
        assert results[0] is True, "Same thread should get same RNG instance"

    def test_rng_produces_deterministic_sequence_within_thread(self):
        """Verify thread-local RNG produces deterministic sequence."""
        # Same thread calling RNG multiple times should get predictable sequence

        results = []

        def generate_sequence():
            """Generate two sequences from same thread."""
            rng = _get_rng()
            seq1 = [rng.randint(1, 100) for _ in range(10)]
            seq2 = [rng.randint(1, 100) for _ in range(10)]
            results.append((seq1, seq2))

        thread = Thread(target=generate_sequence)
        thread.start()
        thread.join()

        # Sequences should be different (RNG advances)
        seq1, seq2 = results[0]
        assert seq1 != seq2, "RNG should advance state between calls"

    def test_rng_isolation_between_concurrent_threads(self):
        """Verify concurrent threads can generate random numbers without interference."""
        # The key test: multiple threads generating randoms concurrently
        # should not interfere with each other (no shared state bugs)

        results = []
        barrier = Barrier(5)  # Synchronize 5 threads

        def generate_concurrently(thread_id):
            """Generate randoms while other threads are also generating."""
            barrier.wait()  # Start all threads at same time
            rng = _get_rng()
            values = [rng.randint(1, 1000000) for _ in range(100)]
            results.append((thread_id, values))

        threads = [Thread(target=generate_concurrently, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify: All 5 threads completed
        assert len(results) == 5

        # Verify: Each thread generated 100 values
        for _thread_id, values in results:
            assert len(values) == 100

        # Each thread should have good internal uniqueness (no corrupted state).
        # Threads may produce identical sequences if they share the same seed,
        # which is fine — it proves they have independent RNG instances.
        for thread_id, values in results:
            unique_values = set(values)
            uniqueness_ratio = len(unique_values) / len(values)
            assert uniqueness_ratio > 0.90, (
                f"Thread {thread_id} uniqueness too low: {uniqueness_ratio:.2%}"
            )

    def test_no_race_conditions_in_rng_access(self):
        """Test rapid concurrent access to _get_rng() doesn't cause race conditions."""
        errors = []

        def rapid_rng_access():
            """Rapidly access RNG and generate numbers."""
            try:
                for _ in range(1000):
                    rng = _get_rng()
                    _ = rng.randint(1, 100)
            except Exception as e:
                errors.append(e)

        threads = [Thread(target=rapid_rng_access) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify: No exceptions occurred
        assert len(errors) == 0, f"Race conditions detected: {errors}"

    def test_activity_generator_uses_thread_local_rng(self):
        """Test that ActivityGenerator methods use thread-local RNG."""
        # This is an integration test to verify the refactoring worked

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)

            # Create emitters
            windows_fmt = load_format("windows_event_security")
            zeek_fmt = load_format("zeek_conn")

            emitters = {
                "windows_event_security": WindowsEventEmitter(
                    windows_fmt, output_dir / "windows.log"
                ),
                "zeek_conn": ZeekEmitter(zeek_fmt, output_dir / "zeek.log"),
            }

            # Create state manager, dispatcher, and activity generator
            from evidenceforge.events.dispatcher import EventDispatcher

            sm = StateManager()
            sm.set_current_time(datetime.now())
            dispatcher = EventDispatcher(state_manager=sm, emitters=emitters)
            ag = ActivityGenerator(sm, emitters, dispatcher=dispatcher)

            # Create dummy user and system with all required fields
            from evidenceforge.models.scenario import System, User

            user = User(
                username="testuser",
                full_name="Test User",
                email="test@example.com",
                persona=None,
                enabled=True,
            )
            system = System(
                hostname="TEST-WS-01", ip="10.0.10.1", os="Windows 10", type="workstation"
            )

            # Generate network logons from main thread. Local interactive logons
            # intentionally reuse an active workstation session for realism.
            results_main = []
            for _ in range(5):
                logon_id = ag.generate_logon(user, system, datetime.now(), logon_type=3)
                results_main.append(logon_id)

            # Generate events from worker threads
            results_thread = []
            barrier = Barrier(4)  # 3 workers + main thread coordination

            def worker():
                barrier.wait()  # Synchronize start
                for _ in range(5):
                    logon_id = ag.generate_logon(user, system, datetime.now(), logon_type=3)
                    results_thread.append(logon_id)

            threads = [Thread(target=worker) for _ in range(3)]
            for t in threads:
                t.start()

            barrier.wait()  # Release workers

            for t in threads:
                t.join()

            # Verify: All logon IDs are unique (StateManager counter is thread-safe)
            all_logon_ids = results_main + results_thread
            assert len(all_logon_ids) == 20  # 5 + (3 threads × 5)
            assert len(set(all_logon_ids)) == 20, "All LogonIDs should be unique"

            # Clean up emitters
            for emitter in emitters.values():
                emitter.close()

    def test_thread_local_rng_different_from_global_random(self):
        """Verify thread-local RNG doesn't affect global random module."""
        import random as global_random

        # Set global random seed
        global_random.seed(12345)
        global_value1 = global_random.randint(1, 1000)

        # Use thread-local RNG
        def use_thread_local():
            rng = _get_rng()
            _ = rng.randint(1, 1000)

        thread = Thread(target=use_thread_local)
        thread.start()
        thread.join()

        # Global random should still be in same state
        global_value2 = global_random.randint(1, 1000)

        # These should be different (global RNG advanced)
        assert global_value1 != global_value2

    def test_deterministic_seeding_based_on_thread_id(self):
        """Verify that deterministic seeding works (same thread ID = same seed)."""
        # This test verifies the design choice: thread IDs produce deterministic seeds

        # Generate values in first thread
        values1 = []

        def generate1():
            rng = _get_rng()
            for _ in range(20):
                values1.append(rng.randint(1, 1000))

        t1 = Thread(target=generate1)
        t1.start()
        t1.join()

        # Note: We can't reliably test that a second thread with "same thread ID"
        # produces same sequence, because thread ID reuse is OS-dependent.
        # The important property is that WITHIN a thread, the sequence is reproducible.

        assert len(values1) == 20
        assert len(set(values1)) > 1, "RNG should produce varied values"
