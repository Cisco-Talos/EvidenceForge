"""Stream relationship verification with disk-backed DNS references and used sets."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections import defaultdict
from contextlib import closing
from datetime import datetime
from pathlib import Path

from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthEventStream,
    read_ground_truth_occurrences,
)


def relationship_violations(root: Path, reference: GroundTruthEventStream) -> dict[str, list[dict]]:
    """Return bounded relationship diagnostics per action without retaining occurrences."""
    result: dict[str, list[dict]] = defaultdict(list)
    with tempfile.TemporaryDirectory(prefix="eforge-eval-relations-") as directory:
        with closing(sqlite3.connect(Path(directory) / "relationships.sqlite")) as db:
            db.executescript(
                "CREATE TABLE dns (id TEXT PRIMARY KEY, facts TEXT); CREATE TABLE used (id TEXT, ip TEXT, UNIQUE(id,ip));"
            )
            for row in read_ground_truth_occurrences(root, reference):
                if row.facts.get("dns"):
                    db.execute(
                        "INSERT INTO dns VALUES (?,?)",
                        (row.occurrence_id, json.dumps(row.facts["dns"])),
                    )
                for link in row.relationships:
                    if link.kind == "dns_answer_use":
                        db.execute(
                            "INSERT OR IGNORE INTO used VALUES (?,?)",
                            (link.facts.get("occurrence_id"), link.facts.get("selected_ip")),
                        )
            for row in read_ground_truth_occurrences(root, reference):
                facts = row.facts
                network, dns, email, smtp = (
                    facts.get(name) or {} for name in ("network", "dns", "email", "smtp")
                )
                problems: set[str] = set()
                kinds = {link.kind for link in row.relationships}
                if dns and "dns_answer_set" not in kinds:
                    problems.add("missing_dns_answer_relationship")
                if email and "recipient_delivery" not in kinds:
                    problems.add("missing_recipient_relationship")
                if (
                    network
                    and not dns
                    and network.get("dst_port") != 53
                    and "connection_attempt" not in kinds
                ):
                    problems.add("missing_connection_relationship")
                for link in row.relationships:
                    data = link.facts
                    if link.kind == "dns_answer_use":
                        if (
                            data.get("selected_ip") != network.get("dst_ip")
                            or data.get("client_ip") != network.get("src_ip")
                            or data.get("selected_ip") not in data.get("answers", [])
                        ):
                            problems.add("invalid_dns_answer_use")
                        prior = db.execute(
                            "SELECT facts FROM dns WHERE id=?", (data.get("occurrence_id"),)
                        ).fetchone()
                        if prior and json.loads(prior[0]).get("answers") != data.get("answers"):
                            problems.add("dns_answer_reference_disagreement")
                        if data.get("time"):
                            delta = (
                                row.time - datetime.fromisoformat(data["time"])
                            ).total_seconds()
                            if (
                                delta < 0
                                or data.get("resolution_mode") == "cache_hit"
                                and delta > max(data.get("ttls", []), default=0)
                            ):
                                problems.add("invalid_dns_cache_provenance")
                    elif link.kind == "dns_answer_set":
                        used = sorted(
                            item[0]
                            for item in db.execute(
                                "SELECT ip FROM used WHERE id=?", (row.occurrence_id,)
                            )
                        )
                        if (
                            data.get("answers") != dns.get("answers")
                            or sorted(data.get("used_answer_ips", [])) != used
                        ):
                            problems.add("dns_available_used_disagreement")
                    elif link.kind == "connection_attempt":
                        if data.get("attempted_ip") != network.get("dst_ip") or data.get(
                            "connection_uid"
                        ) != network.get("zeek_uid"):
                            problems.add("connection_relationship_disagreement")
                    elif link.kind == "recipient_delivery":
                        if (
                            data.get("expanded_recipients") != email.get("expanded_rcptto", [])
                            or data.get("attempted_recipients") != smtp.get("rcptto", [])
                            or data.get("message_outcome") != email.get("outcome")
                            or data.get("policy_action") != email.get("mail_action")
                        ):
                            problems.add("recipient_relationship_disagreement")
                    elif link.kind == "address_translation":
                        nat = facts.get("nat") or {}
                        if (
                            data.get("canonical_transport_id") != network.get("stable_id")
                            or (data.get("translated") or {}).get("src_ip")
                            != nat.get("mapped_src_ip")
                            or (data.get("translated") or {}).get("dst_ip")
                            != nat.get("mapped_dst_ip")
                        ):
                            problems.add("translation_relationship_disagreement")
                    elif link.kind == "proxy_request":
                        proxy = facts.get("proxy") or {}
                        if data.get("requested_origin") != proxy.get("host") or data.get(
                            "decision"
                        ) != proxy.get("cache_result"):
                            problems.add("proxy_relationship_disagreement")
                if problems and len(result[row.intent_id]) < 20:
                    result[row.intent_id].append(
                        {"occurrence_id": row.occurrence_id, "rules": sorted(problems)}
                    )
    return dict(result)
