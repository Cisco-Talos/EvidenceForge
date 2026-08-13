# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Parsers for Zeek smb_mapping.log and smb_files.log NDJSON output."""

from . import register_parser
from .zeek_base_parser import ZeekNdjsonParser


@register_parser
class ZeekSmbMappingParser(ZeekNdjsonParser):
    """Parse canonical Zeek SMB tree-mapping observations."""

    format_name = "zeek_smb_mapping"
    _filenames = {"zeek_smb_mapping.json", "smb_mapping.json"}


@register_parser
class ZeekSmbFilesParser(ZeekNdjsonParser):
    """Parse canonical Zeek SMB file-action observations."""

    format_name = "zeek_smb_files"
    _filenames = {"zeek_smb_files.json", "smb_files.json"}
