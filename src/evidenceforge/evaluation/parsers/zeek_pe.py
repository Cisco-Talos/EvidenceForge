"""Parser for Zeek pe.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekPeParser(ZeekNdjsonParser):
    format_name = "zeek_pe"
    _filenames = {"zeek_pe.json", "pe.json"}
