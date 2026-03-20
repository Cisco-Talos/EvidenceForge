"""Parser for Zeek dhcp.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekDhcpParser(ZeekNdjsonParser):
    format_name = "zeek_dhcp"
    _filenames = {"zeek_dhcp.json", "dhcp.json"}
