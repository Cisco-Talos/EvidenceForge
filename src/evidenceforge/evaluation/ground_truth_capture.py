"""Independent deterministic packet-loss and analyzer-visibility verification."""

from __future__ import annotations

import hashlib
import math
import random
from copy import deepcopy

from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    GroundTruthSensorView,
)
from evidenceforge.events.network import tcp_history_packet_minima


def _seed(key: str, seed: int) -> int:
    material = key if seed == 42 else f"seed:{seed}:{key}"
    return int(hashlib.sha256(material.encode()).hexdigest(), 16) % (2**32)


def _direction(value: dict, rule: dict, rng: random.Random, minimum: int) -> tuple[dict, int]:
    payload, packets, wire = (value[key] for key in ("payload_bytes", "packets", "ip_bytes"))
    overhead = wire - payload
    if payload <= 1 or packets <= minimum or overhead < 40 * packets or wire > 1500 * packets:
        return value, 0
    fraction = rng.uniform(rule["min_fraction"], rule["max_fraction"])
    missed = min(payload - 1, rule["max_missed_bytes"], max(1, int(round(payload * fraction))))
    remaining = payload - missed
    lower_packets = max(1, math.ceil(missed / 1460))
    upper_packets = min(packets - minimum, packets - max(minimum, math.ceil(remaining / 1460)))
    if upper_packets < lower_packets:
        return value, 0
    lost = min(upper_packets, max(lower_packets, int(round(packets * fraction))))
    count = packets - lost
    lower = max(40 * lost, wire - missed - 1500 * count)
    upper = min(overhead - 40 * count, 1500 * lost - missed)
    quantum = 4 if overhead % 4 == 0 else 1
    lower, upper = math.ceil(lower / quantum) * quantum, math.floor(upper / quantum) * quantum
    if lower > upper:
        return value, 0
    nonunique = min(upper, max(lower, round(overhead * lost / packets / quantum) * quantum))
    return {
        "payload_bytes": remaining,
        "packets": count,
        "ip_bytes": wire - missed - nonunique,
    }, missed


def capture_errors(
    row: GroundTruthOccurrence, view: GroundTruthSensorView, settings: dict, seed: int
) -> list[str]:
    """Verify a captured sensor receipt from frozen input and configured policy."""
    capture = row.facts.get("capture") or {}
    if not capture or view.profile not in settings.get("profiles", {}):
        return ["unsupported_capture_contract"]
    rule = settings["profiles"][view.profile]["capture_loss"]
    expected = deepcopy(capture["traffic"])
    rng = random.Random(
        _seed(
            f"network-capture-loss:{view.profile}:{view.sensor_identity}:{capture['identity']}",
            seed,
        )
    )
    if (
        capture["protocol"].lower() == "tcp"
        and rule["probability"] > 0
        and rule["max_fraction"] > 0
        and rule["max_missed_bytes"] > 0
        and rng.random() < rule["probability"]
    ):
        has_orig, has_resp = (
            expected["orig"]["payload_bytes"] > 0,
            expected["resp"]["payload_bytes"] > 0,
        )
        if has_orig and has_resp:
            shape = rng.random()
            lose_orig, lose_resp = (
                shape < 0.44 or shape >= 0.88,
                0.44 <= shape < 0.88 or shape >= 0.88,
            )
        else:
            lose_orig, lose_resp = has_orig, has_resp
        minima = tcp_history_packet_minima(capture["history"])
        for index, (direction, lose) in enumerate((("orig", lose_orig), ("resp", lose_resp))):
            if lose:
                expected[direction], missed = _direction(
                    expected[direction], rule, rng, max(1, minima[index])
                )
                expected["missed_" + direction + "_bytes"] += missed
    errors = []
    if expected != view.traffic:
        errors.append("invalid_packet_loss_receipt")
    observed_files = {item["canonical_id"]: item for item in view.files}
    http = row.facts.get("http") or {}
    for transfer in row.facts.get("file_transfers", []):
        direction = "orig" if transfer["is_orig"] else "resp"
        original, observed = capture["traffic"][direction], expected[direction]
        ratio = (
            min(1.0, max(0.0, observed["payload_bytes"] / original["payload_bytes"]))
            if original["payload_bytes"]
            else 1.0
        )
        total, seen, missing = (
            transfer["total_bytes"],
            transfer["seen_bytes"],
            transfer["missing_bytes"],
        )
        if transfer["source"] == "HTTP" and http:
            offset = http.get(
                "request_stream_offset" if transfer["is_orig"] else "response_stream_offset", 0
            ) + (transfer.get("wire_offset") or 0)
            span = transfer.get("wire_length") or seen
            extent = (
                original["payload_bytes"] + capture["traffic"]["missed_" + direction + "_bytes"]
            )
            start, end = min(offset, extent), min(offset + span, extent)
            wire_missing = (
                end * expected["missed_" + direction + "_bytes"] // extent
                - start * expected["missed_" + direction + "_bytes"] // extent
                if extent
                else 0
            )
            decoded = min(seen, wire_missing * seen // span) if span else 0
            seen, missing = seen - decoded, missing + decoded
        elif (
            transfer.get("entity_body_len") is not None
            and transfer.get("wire_offset") is not None
            and transfer.get("wire_length") is not None
        ):
            entity, length, offset = (
                transfer["entity_body_len"],
                transfer["wire_length"],
                transfer["wire_offset"],
            )
            gap = min(entity, entity - int(entity * ratio))
            if entity > 0 and length > 0 and gap > 0:
                position = _seed(
                    f"http-multipart-observation-gap:{row.facts['network'].get('zeek_uid', '')}:{transfer['is_orig']}:{entity}",
                    seed,
                ) % (entity - gap + 1)
                overlap = max(0, min(position + gap, offset + length) - max(position, offset))
                decoded = min(seen, (seen * overlap + length - 1) // length)
                seen, missing = seen - decoded, max(missing, decoded)
        else:
            accounted = total if total is not None else seen + missing
            seen = min(seen, int(seen * ratio))
            missing = max(missing, accounted - seen)
        modeled = {
            "canonical_id": transfer["fuid"],
            "seen_bytes": seen,
            "total_bytes": total,
            "missing_bytes": missing,
            "analyzers_visible": missing == 0 and not transfer.get("timedout", False),
        }
        if observed_files.get(transfer["fuid"]) != modeled:
            errors.append("invalid_file_capture_receipt")
    canonical_resp = capture["traffic"]["resp"]["payload_bytes"]
    ratio = (
        min(1.0, max(0.0, expected["resp"]["payload_bytes"] / canonical_resp))
        if canonical_resp > 0
        else 1.0
    )
    for cert in row.facts.get("x509_chain", []):
        total = cert["file_size"]
        seen = int(total * ratio)
        modeled = {
            "canonical_id": cert["fuid"],
            "seen_bytes": seen,
            "total_bytes": total,
            "missing_bytes": total - seen,
            "analyzers_visible": seen == total,
        }
        if observed_files.get(cert["fuid"]) != modeled:
            errors.append("invalid_certificate_capture_receipt")
    return sorted(set(errors))
