"""Unit tests for emitter threading (Phase 2.1).

Tests thread safety of emitter file I/O, buffer integrity, and barrier synchronization.
"""

import pytest
from pathlib import Path
from threading import Thread, Barrier
from datetime import datetime
import tempfile
import time

from log_generator.generation.emitters import WindowsEventEmitter, ZeekEmitter
from log_generator.formats import load_format


class TestEmitterThreadSafety:
    """Test thread safety of emitter file I/O."""

    def test_concurrent_buffer_appends(self):
        """Test concurrent _buffer_event() calls don't corrupt buffer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fmt = load_format("windows_event_security")
            emitter = WindowsEventEmitter(
                fmt,
                Path(tmpdir) / "test.xml",
                buffer_size=10000,
                threaded=False  # Test buffer thread-safety directly
            )

            events_per_thread = 1000
            num_threads = 5

            def append_events(thread_id):
                """Append events from a single thread."""
                for i in range(events_per_thread):
                    event = {
                        'EventID': 4624,
                        'TimeCreated': datetime.now(),
                        'Computer': f'TEST-{thread_id}-{i}',
                        'EventRecordID': thread_id * 10000 + i,
                        'Channel': 'Security',
                        'Level': 'Information',
                        'TargetUserName': f'user{thread_id}',
                        'TargetDomainName': 'TESTDOMAIN',
                        'TargetLogonId': f'0x{(thread_id * 1000 + i):x}',
                        'LogonType': 2,
                        'IpAddress': '192.168.1.1',
                        'IpPort': 50000 + i,
                        'SubjectUserName': 'SYSTEM',
                        'SubjectDomainName': 'NT AUTHORITY',
                        'SubjectLogonId': '0x3e7',
                    }
                    rendered = emitter._render_event(event)
                    emitter._buffer_event(rendered)

            # Launch threads
            threads = [Thread(target=append_events, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Verify: 5000 events buffered (no lost events)
            assert emitter.event_count == num_threads * events_per_thread
            # Buffer might have been flushed during execution, so check total count
            # not buffer length

            emitter.close()

    def test_concurrent_flush_calls(self):
        """Test concurrent flush() calls are serialized correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fmt = load_format("zeek_conn")
            emitter = ZeekEmitter(
                fmt,
                Path(tmpdir) / "test.log",
                buffer_size=100,  # Small buffer to trigger flushes
                threaded=False
            )

            events_per_thread = 50
            num_threads = 4
            barrier = Barrier(num_threads)

            def append_and_flush(thread_id):
                """Append events and periodically flush."""
                barrier.wait()  # Synchronize start
                for i in range(events_per_thread):
                    event = {
                        'ts': datetime.now(),
                        'uid': f'C{thread_id}{i:010d}',
                        'id.orig_h': f'10.0.{thread_id}.1',
                        'id.orig_p': 50000 + i,
                        'id.resp_h': '8.8.8.8',
                        'id.resp_p': 443,
                        'proto': 'tcp',
                        'service': '-',
                        'duration': 1.234,
                        'orig_bytes': 1024,
                        'resp_bytes': 2048,
                        'conn_state': 'SF',
                        'local_orig': True,
                        'local_resp': False,
                        'missed_bytes': 0,
                        'history': 'ShADadfF',
                        'orig_pkts': 10,
                        'orig_ip_bytes': 1500,
                        'resp_pkts': 10,
                        'resp_ip_bytes': 2500,
                    }
                    rendered = emitter._render_event(event)
                    emitter._buffer_event(rendered)  # May trigger flush

            # Launch threads
            threads = [Thread(target=append_and_flush, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Final flush
            emitter.close()

            # Verify: All events written to file
            output_file = Path(tmpdir) / "test.log"
            assert output_file.exists()

            with open(output_file) as f:
                lines = [l for l in f if l.strip() and not l.startswith('#')]

            assert len(lines) == num_threads * events_per_thread

    def test_threaded_mode_event_posting(self):
        """Test threaded mode with concurrent event posting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fmt = load_format("zeek_conn")
            emitter = ZeekEmitter(
                fmt,
                Path(tmpdir) / "zeek.log",
                threaded=True  # Enable threaded mode
            )

            events_per_thread = 500
            num_threads = 4
            barrier = Barrier(num_threads)

            def post_events(thread_id):
                """Post events to queue from multiple threads."""
                barrier.wait()  # Synchronize start
                for i in range(events_per_thread):
                    event = {
                        'ts': datetime.now(),
                        'uid': f'C{thread_id}{i:010d}',
                        'id.orig_h': f'10.0.{thread_id}.1',
                        'id.orig_p': 50000 + i,
                        'id.resp_h': '8.8.8.8',
                        'id.resp_p': 443,
                        'proto': 'tcp',
                        'service': '-',
                        'duration': 1.234,
                        'orig_bytes': 1024,
                        'resp_bytes': 2048,
                        'conn_state': 'SF',
                        'local_orig': True,
                        'local_resp': False,
                        'missed_bytes': 0,
                        'history': 'ShADadfF',
                        'orig_pkts': 10,
                        'orig_ip_bytes': 1500,
                        'resp_pkts': 10,
                        'resp_ip_bytes': 2500,
                    }
                    emitter.emit_event(event)

            # Launch threads
            threads = [Thread(target=post_events, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Barrier flush and close
            emitter.barrier_flush()
            emitter.close()

            # Verify: All events written to file
            output_file = Path(tmpdir) / "zeek.log"
            assert output_file.exists()

            with open(output_file) as f:
                lines = [l for l in f if l.strip() and not l.startswith('#')]

            assert len(lines) == num_threads * events_per_thread

    def test_barrier_flush_waits_for_queue_drain(self):
        """Test barrier_flush() waits for all queued events to be processed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fmt = load_format("windows_event_security")
            emitter = WindowsEventEmitter(
                fmt,
                Path(tmpdir) / "windows.xml",
                threaded=True
            )

            # Post many events
            for i in range(1000):
                event = {
                    'EventID': 4688,
                    'TimeCreated': datetime.now(),
                    'Computer': f'TEST-WS-01',
                    'EventRecordID': 10000 + i,
                    'Channel': 'Security',
                    'Level': 'Information',
                    'SubjectUserName': 'user1',
                    'SubjectDomainName': 'TESTDOMAIN',
                    'SubjectLogonId': '0x12345',
                    'NewProcessId': 1000 + i,
                    'NewProcessName': f'C:\\test{i}.exe',
                    'TokenElevationType': '%%1936',
                    'ProcessId': 4,
                    'CommandLine': f'test{i}.exe',
                    'TargetUserName': 'user1',
                    'TargetDomainName': 'TESTDOMAIN',
                    'TargetLogonId': '0x12345',
                    'ParentProcessName': 'C:\\Windows\\System32\\cmd.exe',
                    'MandatoryLabel': 'S-1-16-8192',
                }
                emitter.emit_event(event)

            # Barrier flush - should wait for all events to be processed
            emitter.barrier_flush()

            # Verify: Queue is empty after barrier
            assert emitter._event_queue.qsize() == 0

            # Verify: All events written
            emitter.close()

            output_file = Path(tmpdir) / "windows.xml"
            assert output_file.exists()

    def test_header_written_once_under_concurrency(self):
        """Test header is written exactly once even with concurrent writes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fmt = load_format("zeek_conn")
            emitter = ZeekEmitter(
                fmt,
                Path(tmpdir) / "zeek.log",
                buffer_size=10,  # Small buffer to trigger frequent flushes
                threaded=False
            )

            num_threads = 5
            events_per_thread = 20

            def append_events(thread_id):
                """Append events that will trigger flushes."""
                for i in range(events_per_thread):
                    event = {
                        'ts': datetime.now(),
                        'uid': f'C{thread_id}{i:010d}',
                        'id.orig_h': f'10.0.{thread_id}.1',
                        'id.orig_p': 50000 + i,
                        'id.resp_h': '8.8.8.8',
                        'id.resp_p': 443,
                        'proto': 'tcp',
                        'service': '-',
                        'duration': 1.234,
                        'orig_bytes': 1024,
                        'resp_bytes': 2048,
                        'conn_state': 'SF',
                        'local_orig': True,
                        'local_resp': False,
                        'missed_bytes': 0,
                        'history': 'ShADadfF',
                        'orig_pkts': 10,
                        'orig_ip_bytes': 1500,
                        'resp_pkts': 10,
                        'resp_ip_bytes': 2500,
                    }
                    rendered = emitter._render_event(event)
                    emitter._buffer_event(rendered)  # May trigger flush
                    time.sleep(0.001)  # Small delay to increase concurrency

            # Launch threads
            threads = [Thread(target=append_events, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Close emitter
            emitter.close()

            # Verify: Header written exactly once
            output_file = Path(tmpdir) / "zeek.log"
            assert output_file.exists()

            with open(output_file) as f:
                content = f.read()

            # Count header lines (lines starting with #)
            header_lines = [l for l in content.split('\n') if l.startswith('#')]

            # Should have header fields section (multiple lines)
            # but not duplicated
            assert len(header_lines) > 0
            assert '#separator' in content
            # Verify no duplicate separators
            assert content.count('#separator') == 1
