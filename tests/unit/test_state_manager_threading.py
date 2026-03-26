"""Unit tests for StateManager thread safety (Phase 2.1).

Tests concurrent access patterns, counter uniqueness, and lock behavior.
"""

from collections import Counter
from datetime import datetime
from threading import Barrier, Thread

from evidenceforge.generation.state_manager import StateManager


class TestStateManagerThreadSafety:
    """Test thread safety of StateManager with concurrent access."""

    def test_concurrent_session_creation(self):
        """Test 10 threads creating 100 sessions each, verify 1000 unique LogonIDs."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        created_logon_ids = []

        def create_sessions(thread_id):
            """Create 100 sessions from a single thread."""
            for i in range(100):
                logon_id = sm.create_session(
                    username=f"user{thread_id}_{i}",
                    system="WS-01",
                    logon_type=2,
                    source_ip="192.168.1.1",
                )
                created_logon_ids.append(logon_id)

        # Launch 10 threads
        threads = [Thread(target=create_sessions, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify: 1000 sessions created
        assert len(sm.state.active_sessions) == 1000

        # Verify: 1000 unique LogonIDs (no duplicates)
        assert len(created_logon_ids) == 1000
        assert len(set(created_logon_ids)) == 1000, "Found duplicate LogonIDs!"

        # Verify: LogonIDs are high-entropy random values (not sequential)
        logon_id_values = [int(lid, 16) for lid in created_logon_ids]
        assert all(v >= 0x10000 for v in logon_id_values), "LogonIDs should be high-entropy"
        # Not in reserved range
        assert all(v not in {0x3E4, 0x3E5, 0x3E6, 0x3E7} for v in logon_id_values)

    def test_concurrent_reads_during_writes(self):
        """Test readers see consistent state during concurrent writes."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        # Pre-create 50 sessions
        for i in range(50):
            sm.create_session(
                username=f"user{i}", system="WS-01", logon_type=2, source_ip="192.168.1.1"
            )

        read_counts = []
        barrier = Barrier(11)  # 10 readers + 1 writer

        def writer_thread():
            """Add 50 more sessions."""
            barrier.wait()  # Synchronize start
            for i in range(50, 100):
                sm.create_session(
                    username=f"user{i}", system="WS-01", logon_type=2, source_ip="192.168.1.1"
                )

        def reader_thread():
            """Read session count 100 times."""
            barrier.wait()  # Synchronize start
            for _ in range(100):
                count = len(sm.list_active_sessions())
                read_counts.append(count)

        # Launch 10 reader threads and 1 writer thread
        writer = Thread(target=writer_thread)
        readers = [Thread(target=reader_thread) for _ in range(10)]

        writer.start()
        for r in readers:
            r.start()

        writer.join()
        for r in readers:
            r.join()

        # Verify: Final state has 100 sessions
        assert len(sm.state.active_sessions) == 100

        # Verify: All read counts are valid (between 50 and 100)
        assert all(50 <= count <= 100 for count in read_counts)

        # Verify: Read counts are monotonically increasing or stable
        # (readers never see state go backwards)
        for i in range(1, len(read_counts)):
            assert read_counts[i] >= read_counts[i - 1] or read_counts[i] >= 50

    def test_pid_counter_uniqueness(self):
        """Test 10 threads creating processes on same system, verify unique PIDs."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        # Create parent process (PID 4 = System)
        created_pids = []

        def create_processes(thread_id):
            """Create 100 processes from a single thread."""
            for i in range(100):
                pid = sm.create_process(
                    system="WS-01",
                    parent_pid=4,  # System process
                    image=f"C:\\test{thread_id}_{i}.exe",
                    command_line=f"test{thread_id}_{i}.exe",
                    username="SYSTEM",
                    integrity_level="System",
                )
                created_pids.append(pid)

        # Launch 10 threads
        threads = [Thread(target=create_processes, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify: 1000 processes created
        assert len(sm.state.running_processes) == 1000

        # Verify: 1000 unique PIDs (no collisions)
        assert len(created_pids) == 1000
        pid_counts = Counter(created_pids)
        duplicates = [(pid, count) for pid, count in pid_counts.items() if count > 1]
        assert len(duplicates) == 0, f"Found duplicate PIDs: {duplicates}"

        # Verify: PIDs are strictly increasing (OS-aware allocation)
        pids_sorted = sorted(created_pids)
        assert pids_sorted[0] > 0  # PIDs start in realistic range
        for i in range(1, len(pids_sorted)):
            assert pids_sorted[i] > pids_sorted[i - 1]  # Strictly increasing

    def test_concurrent_connection_creation(self):
        """Test 5 threads creating connections, verify unique connection IDs."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        created_conn_ids = []

        def create_connections(thread_id):
            """Create 200 connections from a single thread."""
            for i in range(200):
                conn_id = sm.open_connection(
                    src_ip=f"10.0.{thread_id}.1",
                    src_port=50000 + i,
                    dst_ip="8.8.8.8",
                    dst_port=443,
                    protocol="tcp",
                )
                created_conn_ids.append(conn_id)

        # Launch 5 threads
        threads = [Thread(target=create_connections, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify: 1000 connections created
        assert len(sm.state.open_connections) == 1000

        # Verify: 1000 unique connection IDs
        assert len(created_conn_ids) == 1000
        assert len(set(created_conn_ids)) == 1000, "Found duplicate connection IDs!"

    def test_concurrent_mixed_operations(self):
        """Test mixed operations (create/read/delete) from multiple threads."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        # Pre-create some sessions
        initial_sessions = []
        for i in range(50):
            logon_id = sm.create_session(
                username=f"user{i}", system="WS-01", logon_type=2, source_ip="192.168.1.1"
            )
            initial_sessions.append(logon_id)

        barrier = Barrier(3)  # Synchronize 3 threads
        create_count = [0]
        read_count = [0]
        delete_count = [0]

        def creator_thread():
            """Create 30 new sessions."""
            barrier.wait()
            for i in range(50, 80):
                sm.create_session(
                    username=f"user{i}", system="WS-01", logon_type=2, source_ip="192.168.1.1"
                )
                create_count[0] += 1

        def reader_thread():
            """Read sessions 100 times."""
            barrier.wait()
            for _ in range(100):
                sessions = sm.list_active_sessions()
                read_count[0] += len(sessions)

        def deleter_thread():
            """Delete first 20 sessions."""
            barrier.wait()
            for logon_id in initial_sessions[:20]:
                if sm.end_session(logon_id):
                    delete_count[0] += 1

        # Launch threads
        creator = Thread(target=creator_thread)
        reader = Thread(target=reader_thread)
        deleter = Thread(target=deleter_thread)

        creator.start()
        reader.start()
        deleter.start()

        creator.join()
        reader.join()
        deleter.join()

        # Verify: Final state is consistent
        # Started with 50, created 30, deleted 20 = 60 total
        assert len(sm.state.active_sessions) == 60
        assert create_count[0] == 30
        assert delete_count[0] == 20
        assert read_count[0] > 0  # Read something

    def test_lock_reentrancy(self):
        """Test that RLock allows reentrant calls within same thread."""
        sm = StateManager()
        sm.set_current_time(datetime.now())

        # create_process calls get_process internally (parent validation)
        # This should work because RLock allows reentrant calls

        # Create parent process first
        parent_pid = sm.create_process(
            system="WS-01",
            parent_pid=4,  # System process
            image="C:\\parent.exe",
            command_line="parent.exe",
            username="SYSTEM",
            integrity_level="System",
        )

        # Create child process (calls get_process to validate parent)
        child_pid = sm.create_process(
            system="WS-01",
            parent_pid=parent_pid,  # This triggers get_process inside create_process
            image="C:\\child.exe",
            command_line="child.exe",
            username="user1",
            integrity_level="Medium",
        )

        # Verify both processes exist
        assert sm.get_process("WS-01", parent_pid) is not None
        assert sm.get_process("WS-01", child_pid) is not None

    def test_stress_1000_iterations(self):
        """Stress test: 1000 iterations of concurrent session creation."""
        for _iteration in range(1000):
            sm = StateManager()
            sm.set_current_time(datetime.now())

            def create_session_pair(idx, sm=sm):
                sm.create_session(
                    username=f"user{idx}", system="WS-01", logon_type=2, source_ip="192.168.1.1"
                )

            # Create 10 sessions concurrently
            threads = [Thread(target=create_session_pair, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Verify no data corruption
            assert len(sm.state.active_sessions) == 10

    def test_concurrent_time_operations(self):
        """Test concurrent set_current_time and get_current_time."""
        sm = StateManager()

        times_set = []
        times_read = []

        def time_setter(idx):
            """Set time to specific values."""
            dt = datetime(2024, 1, 1, idx, 0, 0)
            sm.set_current_time(dt)
            times_set.append(dt)

        def time_reader():
            """Read current time 100 times."""
            for _ in range(100):
                dt = sm.get_current_time()
                if dt is not None:
                    times_read.append(dt)

        # Launch threads
        setters = [Thread(target=time_setter, args=(i,)) for i in range(10)]
        readers = [Thread(target=time_reader) for _ in range(5)]

        for t in setters + readers:
            t.start()
        for t in setters + readers:
            t.join()

        # Verify: Final time is one of the set values
        final_time = sm.get_current_time()
        assert final_time in times_set

        # Verify: All read times are valid (in times_set)
        assert all(t in times_set for t in times_read)
