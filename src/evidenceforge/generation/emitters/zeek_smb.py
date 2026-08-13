# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Zeek SMB mapping and file-action projections."""

from __future__ import annotations

from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekSmbMappingEmitter(SensorMultiplexEmitter):
    """Render one sparse smb_mapping.log row per tree connection."""

    _log_filename = "smb_mapping.json"
    _flat_filename = "zeek_smb_mapping.json"

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        return (
            event.event_type == "smb_tree_connect"
            and event.smb is not None
            and event.smb.result == "success"
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        net = event.network
        smb = event.smb
        data: dict[str, Any] = {
            "ts": event.timestamp,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "path": f"\\\\{smb.share_ref.split('.', 1)[0]}\\{smb.share_name}",
            "service": smb.share_name,
            "native_file_system": "NTFS",
            "share_type": "DISK",
            **self._sensor_metadata(event, self.format_def.name),
        }
        self.emit_event(data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)


class ZeekSmbFilesEmitter(SensorMultiplexEmitter):
    """Render source-native SMB file actions without requiring a FUID."""

    _log_filename = "smb_files.json"
    _flat_filename = "zeek_smb_files.json"

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        smb = event.smb
        return (
            smb is not None
            and not smb.encrypted
            and smb.result == "success"
            and smb.phase in {"open", "read", "write", "rename", "delete"}
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        net = event.network
        smb = event.smb
        transfer = event.protocol.primary_file_transfer
        server = smb.share_ref.split(".", 1)[0]
        data: dict[str, Any] = {
            "ts": event.timestamp,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "action": f"SMB::FILE_{smb.phase.upper()}",
            "path": f"\\\\{server}\\{smb.share_name}",
            "name": smb.share_path,
            "size": smb.size_bytes if smb.phase in {"read", "write"} else None,
            "prev_name": smb.previous_path or None,
            "fuid": transfer.fuid if transfer is not None else None,
            **self._sensor_metadata(event, self.format_def.name),
        }
        self.emit_event(data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
