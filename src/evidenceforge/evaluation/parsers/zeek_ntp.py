"""Parser for Zeek ntp.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekNtpParser(ZeekNdjsonParser):
    format_name = "zeek_ntp"
    _filenames = {"zeek_ntp.json", "ntp.json"}
