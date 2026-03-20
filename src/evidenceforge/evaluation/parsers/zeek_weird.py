"""Parser for Zeek weird.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekWeirdParser(ZeekNdjsonParser):
    format_name = "zeek_weird"
    _filenames = {"zeek_weird.json", "weird.json"}
