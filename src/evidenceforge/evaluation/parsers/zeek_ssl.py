"""Parser for Zeek ssl.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekSslParser(ZeekNdjsonParser):
    format_name = "zeek_ssl"
    _filenames = {"zeek_ssl.json", "ssl.json"}
