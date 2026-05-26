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

"""Log file parsers for the evaluation framework.

Each parser reads generated log output and yields structured ParsedRecord objects.
"""

import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ParsedRecord(BaseModel):
    """A single parsed log record from any format."""

    source_format: str
    raw: str
    fields: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    parse_errors: list[str] = Field(default_factory=list)
    line_number: int | None = None
    source_host: str | None = None


class LogParser(ABC):
    """Base class for format-specific log parsers."""

    format_name: str = ""
    # Optional: set by the evaluation engine before parse_file is called so
    # parsers that need scenario metadata (e.g. time_window year) can read it.
    scenario: Any = None
    output_target: Any = None

    @abstractmethod
    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        """Yield parsed records from a log file."""
        ...

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """Check if this parser can handle the given file/path."""
        ...


# Registry mapping format names to parser classes
_PARSER_CLASSES: dict[str, type[LogParser]] = {}


def register_parser(cls: type[LogParser]) -> type[LogParser]:
    """Decorator to register a parser class."""
    _PARSER_CLASSES[cls.format_name] = cls
    return cls


def get_parser(format_name: str) -> LogParser:
    """Get a parser instance by format name."""
    cls = _PARSER_CLASSES.get(format_name)
    if cls is None:
        raise ValueError(f"No parser registered for format: {format_name}")
    return cls()


def _is_safe_path(path: Path, root: Path) -> bool:
    """Check that path is not a symlink and resolves inside root."""
    if path.is_symlink():
        logger.warning("Skipping symlinked path during log discovery: %s", path)
        return False
    try:
        path.resolve().relative_to(root)
    except ValueError:
        logger.warning("Skipping path outside output directory: %s", path)
        return False
    return True


def _discover_bash_history_files(output_dir: Path, output_root: Path) -> list[Path]:
    """Discover bash history files across supported output layouts."""
    files: dict[Path, None] = {}
    for history_dir in output_dir.rglob("bash_history"):
        if not _is_safe_path(history_dir, output_root) or not history_dir.is_dir():
            continue
        for candidate in history_dir.rglob("*"):
            if not _is_safe_path(candidate, output_root) or not candidate.is_file():
                continue
            if candidate.suffix in (".history", ".bash_history"):
                files[candidate] = None
    return sorted(files, key=lambda path: path.as_posix())


def discover_log_files(output_dir: Path, output_target: Any = None) -> dict[str, list[Path]]:
    """Discover log files in an output directory and map to format parsers.

    Scans both top-level files and per-sensor subdirectories (e.g., zeek-fw01/).
    Rejects symlinks and paths that resolve outside the output directory.

    Returns:
        Dict mapping format_name to list of file paths.
    """
    result: dict[str, list[Path]] = {}
    output_root = output_dir.resolve()
    bash_history_files = _discover_bash_history_files(output_dir, output_root)
    if bash_history_files:
        result["bash_history"] = bash_history_files

    # Collect all candidate files: top-level + one level of subdirectories
    candidates: list[Path] = []
    for child in output_dir.iterdir():
        if not _is_safe_path(child, output_root):
            continue
        if child.is_file():
            candidates.append(child)
        elif child.is_dir():
            if child.name == "bash_history":
                continue
            # Per-host FQDN or per-sensor subdirectory
            for subfile in child.iterdir():
                if not _is_safe_path(subfile, output_root):
                    continue
                if subfile.is_file():
                    candidates.append(subfile)
                elif subfile.is_dir():
                    if subfile.name == "bash_history":
                        continue
                    # Deeper subdirectory (e.g., per-sensor logs)
                    for deepfile in subfile.iterdir():
                        if _is_safe_path(deepfile, output_root) and deepfile.is_file():
                            candidates.append(deepfile)

    for format_name, parser_cls in _PARSER_CLASSES.items():
        if format_name == "bash_history":
            continue  # Already handled above
        parser = parser_cls()
        parser.output_target = output_target
        for candidate in candidates:
            if parser.can_parse(candidate):
                result.setdefault(format_name, []).append(candidate)

    return result


# Import parsers to trigger registration
from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.cisco_asa import CiscoAsaParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.ecar import EcarParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.proxy import ProxyAccessParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.snort import SnortAlertParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.syslog import SyslogParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.web import WebAccessParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.windows import (  # noqa: E402
    SysmonEventParser,  # noqa: F401
    WindowsEventParser,  # noqa: F401
)
from evidenceforge.evaluation.parsers.zeek import ZeekConnParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_dhcp import ZeekDhcpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_dns import ZeekDnsParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_files import ZeekFilesParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_http import ZeekHttpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ntp import ZeekNtpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ocsp import ZeekOcspParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_packet_filter import (  # noqa: E402
    ZeekPacketFilterParser,  # noqa: F401
)
from evidenceforge.evaluation.parsers.zeek_pe import ZeekPeParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_reporter import ZeekReporterParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ssl import ZeekSslParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_weird import ZeekWeirdParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_x509 import ZeekX509Parser  # noqa: E402,F401
