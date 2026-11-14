"""Real Windows local-pipe framing and kernel endpoint identities."""

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native named-pipe ABI")


def test_cleanup_pipe_preserves_frames_and_identifies_both_processes() -> None:
    from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe
    from evidenceforge.utils.windows_filesystem import current_user_sid

    identity = uuid4().hex
    server = CleanupPipe.server(identity, current_user_sid())
    script = """
import sys
from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe
pipe=CleanupPipe.client(sys.argv[1],int(sys.argv[2]))
pipe.send({'text':'café 汉\\x00end','number':42})
assert pipe.receive()=={'accepted':True}
pipe.close()
"""
    script = "import sys; sys.path[:] = " + repr(sys.path) + "\n" + script
    python = getattr(sys, "_base_executable", sys.executable)
    try:
        with subprocess.Popen([python, "-c", script, identity, str(os.getpid())]) as child:
            try:
                server.accept()
                assert server.peer_pid() == child.pid
                assert server.receive() == {"text": "café 汉\x00end", "number": 42}
                server.send({"accepted": True})
                assert child.wait(timeout=10) == 0
            finally:
                if child.poll() is None:
                    child.kill()
    finally:
        server.close()


def test_review_commands_and_progress_continue_with_a_pending_pipe_read(tmp_path: Path) -> None:
    """Exercise real session traffic, including simultaneous reads and writes."""
    from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe
    from evidenceforge.utils.windows_filesystem import current_user_sid

    identity = uuid4().hex
    server = CleanupPipe.server(identity, current_user_sid())
    script = """
import sys,time
from concurrent.futures import CancelledError
from pathlib import Path
from evidenceforge.studio import windows_uninstall_session as session
from evidenceforge.studio.windows_uninstall import CleanupPlan,CleanupProgress,UserLocations
from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe
from evidenceforge.utils.windows_filesystem import current_user_sid
root=Path(sys.argv[3])
locations=UserLocations(profile=root,local=root/'AppData/Local',documents=root/'Documents',account=current_user_sid())
def inspect(locations,categories,*,check_cancelled,report_target):
    if categories=={'private'}:
        try:
            while True:
                check_cancelled()
                time.sleep(.01)
        except CancelledError:
            (root/'cancelled').touch()
            raise
    return CleanupPlan(locations=locations)
session.build_plan=inspect
def execute(plan,categories,*,report_progress):
    report_progress(CleanupProgress(phase='preparing',completed=1,total=2,path=root))
    (root/'approved').touch()
    report_progress(CleanupProgress(phase='complete',completed=1,total=1))
session.execute=execute
session.serve(CleanupPipe.client(sys.argv[1],int(sys.argv[2])),locations)
"""
    script = "import sys; sys.path[:] = " + repr(sys.path) + "\n" + script
    replies: queue.Queue[dict] = queue.Queue()
    writers: list[threading.Thread] = []

    def read() -> None:
        try:
            while True:
                replies.put(server.receive())
        except OSError:
            pass

    def send(action: str, revision: int, categories: list[str], plan_id: str | None = None) -> None:
        finished = threading.Event()
        errors: list[OSError] = []

        def write() -> None:
            try:
                server.send(
                    dict(action=action, revision=revision, categories=categories, plan_id=plan_id)
                )
            except OSError as error:
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=write, daemon=True)
        writers.append(thread)
        thread.start()
        assert finished.wait(3), "Command blocked behind the pending reply read"
        assert not errors, errors

    python = getattr(sys, "_base_executable", sys.executable)
    reader = threading.Thread(target=read, daemon=True)
    with subprocess.Popen(
        [python, "-c", script, identity, str(os.getpid()), str(tmp_path)]
    ) as child:
        try:
            server.accept()
            assert server.peer_pid() == child.pid
            reader.start()
            assert replies.get(timeout=5)["state"] == "ready"
            # Let the reply reader enter its next ReadFile before writing.
            threading.Event().wait(0.1)
            send("prepare", 1, ["private"])
            assert replies.get(timeout=3)["state"] == "inspecting"
            send("prepare", 2, [])
            while (prepared := replies.get(timeout=3))["state"] != "prepared":
                assert prepared["state"] == "inspecting"
            assert prepared["revision"] == 2 and (tmp_path / "cancelled").exists()
            assert not (tmp_path / "approved").exists()
            send("execute", 2, [], prepared["plan_id"])
            update = replies.get(timeout=3)
            assert update["state"] == "removing"
            assert update["progress"]["completed"] == 1 and update["progress"]["total"] == 2
            assert update["progress"]["path"] == str(tmp_path)
            assert replies.get(timeout=3)["progress"]["phase"] == "complete"
            assert replies.get(timeout=3)["state"] == "applied"
            assert (tmp_path / "approved").exists()
            # Close with the reply reader still pending and the worker waiting
            # for its next command. Cancellation must drain both ends promptly.
            server.close()
            assert child.wait(timeout=5) == 0
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            server.close()
            if reader.ident is not None:
                reader.join(3)
            for writer in writers:
                writer.join(3)
    assert not reader.is_alive() and not any(writer.is_alive() for writer in writers)
