"""Parser for Zeek dns.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekDnsParser(ZeekNdjsonParser):
    format_name = "zeek_dns"
    _filenames = {"zeek_dns.json", "dns.json"}
