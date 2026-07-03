# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Parser for Zeek smtp.log (NDJSON) files."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekSmtpParser(ZeekNdjsonParser):
    format_name = "zeek_smtp"
    _filenames = {"zeek_smtp.json", "smtp.json"}
