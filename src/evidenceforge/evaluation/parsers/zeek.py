"""Parser for Zeek conn.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekConnParser(ZeekNdjsonParser):
    format_name = "zeek_conn"
    _filenames = {"zeek_conn.json", "conn.json"}
