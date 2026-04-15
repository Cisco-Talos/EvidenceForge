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

"""Security tests for host-based emitter path routing."""

from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.proxy import ProxyEmitter


def test_emit_to_host_sanitizes_path_traversal(tmp_path):
    """Malicious host routing values cannot escape the configured output directory."""
    emitter = ProxyEmitter(load_format("proxy_access"), tmp_path, buffer_size=1)

    emitter.emit_to_host("test-line", "../../.ssh")
    emitter.close()

    escaped_path = tmp_path.parent / ".ssh" / "proxy_access.log"
    assert not escaped_path.exists()

    sanitized_path = tmp_path / "_.ssh" / "proxy_access.log"
    assert sanitized_path.exists()
