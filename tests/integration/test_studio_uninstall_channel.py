"""Real Windows local-pipe framing and kernel endpoint identities."""

import os
import subprocess
import sys
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
    try:
        with subprocess.Popen([sys.executable, "-c", script, identity, str(os.getpid())]) as child:
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
