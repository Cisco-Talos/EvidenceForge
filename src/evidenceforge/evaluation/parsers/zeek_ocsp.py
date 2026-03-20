"""Parser for Zeek ocsp.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekOcspParser(ZeekNdjsonParser):
    format_name = "zeek_ocsp"
    _filenames = {"zeek_ocsp.json", "ocsp.json"}
