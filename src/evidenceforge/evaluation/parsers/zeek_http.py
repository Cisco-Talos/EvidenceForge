"""Parser for Zeek http.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekHttpParser(ZeekNdjsonParser):
    format_name = "zeek_http"
    _filenames = {"zeek_http.json", "http.json"}
