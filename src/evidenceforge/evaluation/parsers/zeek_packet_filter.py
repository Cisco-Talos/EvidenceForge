"""Parser for Zeek packet_filter.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekPacketFilterParser(ZeekNdjsonParser):
    format_name = "zeek_packet_filter"
    _filenames = {"zeek_packet_filter.json", "packet_filter.json"}
