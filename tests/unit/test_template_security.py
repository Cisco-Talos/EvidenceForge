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

"""Security tests for template rendering in emitters."""

from pathlib import Path
from typing import Any

import pytest
from jinja2.exceptions import SecurityError

from evidenceforge.formats.format_def import FormatDefinition, OutputTemplate
from evidenceforge.generation.emitters.base import LogEmitter


class _TestEmitter(LogEmitter):
    """Minimal concrete emitter for template security testing."""

    def emit_event(self, event_data: dict[str, Any]) -> None:
        rendered = self._render_event(event_data)
        self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._template.render(**event_data)


def _build_format(template: str) -> FormatDefinition:
    return FormatDefinition(
        name="test_format",
        version="1.0",
        description="Test format",
        category="host",
        fields=[],
        output=OutputTemplate(format="text", template=template, file_extension=".log"),
    )


def test_log_emitter_sandbox_blocks_unsafe_template_access(tmp_path: Path) -> None:
    """Unsafe template attribute access should be blocked by sandbox."""
    format_def = _build_format("{{ cycler.__init__.__globals__.os.name }}")
    emitter = _TestEmitter(format_def, tmp_path / "out.log", buffer_size=1)

    with pytest.raises(SecurityError):
        emitter.emit_event({})


def test_log_emitter_sandbox_allows_normal_field_rendering(tmp_path: Path) -> None:
    """Safe field interpolation should continue to work."""
    format_def = _build_format("user={{ username }}")
    emitter = _TestEmitter(format_def, tmp_path / "out.log", buffer_size=1)

    emitter.emit_event({"username": "alice"})
    emitter.close()

    assert (tmp_path / "out.log").read_text(encoding="utf-8").strip() == "user=alice"
