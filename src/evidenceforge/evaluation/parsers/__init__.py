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

    Returns:
        Dict mapping format_name to list of file paths.
    """
    result: dict[str, list[Path]] = {}

    for format_name, parser_cls in _PARSER_CLASSES.items():
        parser = parser_cls()
        # Check for files the parser can handle
        if format_name == "bash_history":
            # Special case: directory structure
            bash_dir = output_dir / "bash_history"
            if bash_dir.is_dir():
                files = list(bash_dir.rglob("*.history"))
                if files:
                    result[format_name] = files
        else:
            # Standard single-file formats
            for child in output_dir.iterdir():
                if child.is_file() and parser.can_parse(child):
                    result.setdefault(format_name, []).append(child)

    return result


# Import parsers to trigger registration
from evidenceforge.evaluation.parsers.windows import WindowsEventParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.zeek import ZeekConnParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.ecar import EcarParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.syslog import SyslogParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.snort import SnortAlertParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.web import WebAccessParser  # noqa: E402,F401
from evidenceforge.evaluation.parsers.bash_history import BashHistoryParser  # noqa: E402,F401
