# Loop 37 Assessment Report

## Outcome

Loop 37 generated 85,138 new records from the current code and gave only
neutral copies of those records to four fresh blind reviewers. No previous-loop
finding, score, report, ground truth, evaluation, or implementation context was
available to them.

The half-open endpoint cutoff probe passed: no rendered data record occurs at or
after 18:00, and none of the four reviewers repeated the prior termination-tail
finding. Automated evaluation scored 95.9104, with all source schemas,
canonical invariants, 16,598 field-agreement pairs, 185 IDS assertions, and
12,853 causal-ordering pairs passing. Acceptance still fails only the scenario's
31/62 pivot-linkability gate.

The blind panel was unanimously Synthetic at 76/71/72/68, average 71.75. No
deliberation was required because verdicts agreed, all verdict confidences were
at least 84, and the synthetic-confidence spread was only eight points.

## Fresh Findings

- The Detection reviewer reported a dataset-wide Security 5156 inversion, but
  hard validation rejected it: Microsoft maps `%%14592`/`%%14610` to inbound
  receive/accept and `%%14593`/`%%14611` to outbound connect, matching the
  generated local endpoint perspective.
- Windows file observations pair Defender DetectionHistory and Windows Update
  paths with unrelated processes, and 61/65 Windows SSH clients launch directly
  from Explorer or Firefox.
- Sixty-four incomplete Zeek certificate files still produce complete X.509
  fingerprints/metadata; six incomplete OCSP files likewise produce decoded
  status records. AAAA answers also retain noncanonical padded hextets.
- Two Security 4648 events name caller processes already terminated in Security,
  Sysmon, and eCAR.
- Multiple reviewers also found ambiguous or contradictory proxy tunnel byte
  accounting.

## Next Backlog Family

Apply sensor-local file loss before dependent protocol analyzers. An incomplete
certificate, OCSP response, or PE file must not produce a full decoded analyzer
row or full-file fingerprint at that sensor; complete sensors should retain the
same canonical correlation IDs and metadata.
