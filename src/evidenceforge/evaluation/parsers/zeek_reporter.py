"""Parser for Zeek reporter.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekReporterParser(ZeekNdjsonParser):
    format_name = "zeek_reporter"
    _filenames = {"zeek_reporter.json", "reporter.json"}
