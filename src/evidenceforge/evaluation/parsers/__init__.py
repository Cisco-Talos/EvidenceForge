"""Log file parsers for the evaluation framework.

Each parser reads generated log output and yields structured ParsedRecord objects.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ParsedRecord(BaseModel):
    """A single parsed log record from any format."""

    source_format: str
    raw: str
    fields: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = None
    parse_errors: list[str] = Field(default_factory=list)
    line_number: int | None = None


class LogParser(ABC):
    """Base class for format-specific log parsers."""

    format_name: str = ""

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


def discover_log_files(output_dir: Path) -> dict[str, list[Path]]:
    """Discover log files in an output directory and map to format parsers.

    Scans both top-level files and per-sensor subdirectories (e.g., zeek-fw01/).

    Returns:
        Dict mapping format_name to list of file paths.
    """
    result: dict[str, list[Path]] = {}

    # Collect all candidate files: top-level + one level of subdirectories
    candidates: list[Path] = []
    for child in output_dir.iterdir():
        if child.is_file():
            candidates.append(child)
        elif child.is_dir():
            if child.name == "bash_history":
                # Special case: bash_history has its own discovery
                files = list(child.rglob("*.history")) + list(child.rglob("*.bash_history"))
                if files:
                    result["bash_history"] = files
            else:
                # Per-host FQDN or per-sensor subdirectory
                for subfile in child.iterdir():
                    if subfile.is_file():
                        candidates.append(subfile)
                    elif subfile.is_dir():
                        if subfile.name == "bash_history":
                            # Bash history nested in per-host dir
                            files = list(subfile.rglob("*.bash_history"))
                            if files:
                                result.setdefault("bash_history", []).extend(files)
                        else:
                            # Deeper subdirectory (e.g., per-sensor logs)
                            for deepfile in subfile.iterdir():
                                if deepfile.is_file():
                                    candidates.append(deepfile)

    for format_name, parser_cls in _PARSER_CLASSES.items():
        if format_name == "bash_history":
            continue  # Already handled above
        parser = parser_cls()
        for candidate in candidates:
            if parser.can_parse(candidate):
                result.setdefault(format_name, []).append(candidate)

    return result


# Import parsers to trigger registration
from evidenceforge.evaluation.parsers.windows import WindowsEventParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek import ZeekConnParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_dns import ZeekDnsParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_http import ZeekHttpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ssl import ZeekSslParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_files import ZeekFilesParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_dhcp import ZeekDhcpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ntp import ZeekNtpParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_weird import ZeekWeirdParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_x509 import ZeekX509Parser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_ocsp import ZeekOcspParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_pe import ZeekPeParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_packet_filter import ZeekPacketFilterParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek_reporter import ZeekReporterParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.ecar import EcarParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.syslog import SyslogParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.snort import SnortAlertParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.web import WebAccessParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser  # noqa: E402,F401
