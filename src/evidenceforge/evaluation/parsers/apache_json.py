# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Normalize the supported Splunk Apache JSON projection without inventing HTTP facts."""

from datetime import datetime

from . import ParsedRecord
from .json_record import decode_record


def parse_apache_json(
    raw: str, line_number: int, source: str, hostname: str | None
) -> ParsedRecord:
    """Parse one web/proxy JSON record, retaining malformed input for exact acceptance."""
    fields: dict = {}
    errors: list[str] = []
    timestamp = None
    try:
        document = decode_record(raw)
        for key in ("bytes_in", "bytes_out", "dest_port", "response_time_microseconds"):
            if key not in document:
                continue
            value = document[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                errors.append(f"Apache JSON {key} must be a nonnegative integer")
            elif key == "dest_port" and value > 65535:
                errors.append("Apache JSON dest_port exceeds 65535")
        aliases = {
            "client": "client_ip",
            "user": "username",
            "http_method": "method",
            "http_version": "protocol",
            "status": "status_code",
            "http_user_agent": "user_agent",
            "http_referrer": "referrer" if source == "proxy_access" else "referer",
            "bytes_out": "sc_bytes" if source == "proxy_access" else "bytes_sent",
        }
        if source == "proxy_access":
            aliases.update(server="host", bytes_in="cs_bytes")
        for key, value in document.items():
            canonical = aliases.get(key, key)
            if canonical in fields and fields[canonical] != value:
                errors.append(f"Conflicting JSON field: {canonical}")
            fields[canonical] = value
        # Apache's dash means no authenticated user, as in the text projections.
        # Normalize after merging so conflicting aliases still remain parse failures.
        if fields.get("username") == "-":
            fields.pop("username")
        ts = document.get("timestamp")
        if not isinstance(ts, str):
            errors.append("Apache JSON timestamp must be an ISO timestamp string")
        else:
            try:
                timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                errors.append("Invalid Apache JSON timestamp")
        path = document.get("uri_path")
        query = document.get("uri_query", "")
        if not isinstance(path, str) or not isinstance(query, str):
            errors.append("Apache JSON uri_path and uri_query must be strings")
        else:
            target = path + ("?" + query if query else "")
            if source == "proxy_access" and fields.get("method") == "CONNECT":
                host, port = fields.get("host"), document.get("dest_port")
                if (
                    not isinstance(host, str)
                    or isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 0 <= port <= 65535
                ):
                    errors.append(
                        "CONNECT JSON requires a string server and integer destination port"
                    )
                else:
                    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            key = "url" if source == "proxy_access" else "path"
            if key in fields and fields[key] != target:
                errors.append(f"Conflicting JSON field: {key}")
            fields[key] = target
    except (ValueError, TypeError) as exc:
        errors.append(f"Apache JSON parse error: {exc}")
    return ParsedRecord(
        source_format=source,
        raw=raw,
        fields=fields,
        timestamp=timestamp,
        parse_errors=errors,
        line_number=line_number,
        source_host=hostname,
    )
