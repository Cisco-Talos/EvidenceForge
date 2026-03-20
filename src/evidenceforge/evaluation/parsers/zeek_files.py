"""Parser for Zeek files.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekFilesParser(ZeekNdjsonParser):
    format_name = "zeek_files"
    _filenames = {"zeek_files.json", "files.json"}
