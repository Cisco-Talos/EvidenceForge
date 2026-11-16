"""Independent proof of the emitted stream for policy-filtered IDS candidates."""

from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ids_evaluation import IdsDigest, new_ids_digest, update_ids_digest

from .parsers import RecordCorpus


def verified_filtered_signatures(
    document: GroundTruthDocument, records: RecordCorpus
) -> set[tuple[str, int, int]]:
    """Authenticate complete sensor-local counts and content before delegating checks.

    Candidate occurrence times do not promise an emitted alert when a stateful
    filter is active. The retained independent stream digest includes times,
    endpoints, signature identity and source-native alert facts.
    """
    if document.ids_evaluation is None:
        return set()
    actual: dict[tuple[str, int, int], tuple[int, IdsDigest]] = {}
    for record in records.get("snort_alert", ()):
        if record.parse_errors or record.timestamp is None:
            continue
        sensor = record.source_instance or "__direct__"
        key = (sensor, int(record.fields.get("gid", 1)), int(record.fields["sid"]))
        count, digest = actual.get(key, (0, new_ids_digest()))
        update_ids_digest(digest, sensor, record.fields | {"timestamp": record.timestamp})
        actual[key] = (count + 1, digest)
    verified: set[tuple[str, int, int]] = set()
    for sensor, signatures in document.ids_evaluation.sensors.items():
        for expected in signatures.values():
            if expected.policy_filtered <= 0:
                continue
            key = (sensor, expected.gid, expected.sid)
            count, digest = actual.get(key, (0, new_ids_digest()))
            if count == expected.emitted and digest.hexdigest() == expected.emitted_sha256:
                verified.add(key)
    return verified
