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

"""Tests for secure host directory routing in emitters."""

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
from evidenceforge.generation.emitters.path_safety import sanitize_host_directory_name
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter


def test_sanitize_host_directory_name_blocks_traversal() -> None:
    """Traversal and separators are normalized to a safe single directory name."""
    assert sanitize_host_directory_name("../../.ssh") == "______ssh"
    assert sanitize_host_directory_name("host/../../escape") == "host_.._.._escape"


def test_host_multiplex_writer_path_stays_under_base_dir(tmp_path) -> None:
    """HostMultiplexEmitter-derived writers never escape output directory."""
    emitter = SyslogEmitter(load_format("syslog"), tmp_path / "syslog", buffer_size=1)
    writer = emitter._get_writer("../../escape")

    assert writer.output_path.resolve().is_relative_to((tmp_path / "syslog").resolve())


def test_windows_writer_path_stays_under_base_dir(tmp_path) -> None:
    """WindowsEventEmitter host writers never escape output directory."""
    emitter = WindowsEventEmitter(load_format("windows_event_security"), tmp_path / "windows")
    writer = emitter._get_host_writer("../../escape")

    assert writer.output_path.resolve().is_relative_to((tmp_path / "windows").resolve())


def test_bash_history_writer_path_stays_under_base_dir(tmp_path) -> None:
    """BashHistoryEmitter host writers never escape output directory."""
    emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path / "bash_history")
    writer = emitter._get_writer("alice", "../../escape")

    assert writer.output_path.resolve().is_relative_to((tmp_path / "bash_history").resolve())
