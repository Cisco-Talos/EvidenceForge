"""Parser for Zeek x509.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekX509Parser(ZeekNdjsonParser):
    format_name = "zeek_x509"
    _filenames = {"zeek_x509.json", "x509.json"}
