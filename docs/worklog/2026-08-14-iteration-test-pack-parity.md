# Iteration-Test Pack Parity Investigation

## Scope

Investigate the apparent data-volume reduction after extracting the canonical
`iteration-test` assessment scenario into
`project:organization:meridian-healthcare-solutions@1.0.0` with the exact
`package:evidenceforge:industry:technology@1.0.0` dependency.

## Decisive Result

The pack migration does not change generated evidence. With current code, seed
42, the default target, the same output formats, and both inputs normalized to
`name: iteration-test`, the expanded inline scenario and pack-backed scenario
each produced:

- 42,964,903 exact data-tree bytes
- 76,191 source records
- 90 data files

`compare_generated_outputs` reported byte-identical output with no missing,
extra, or changed artifacts. The checked-in pack-backed output is also
byte-identical to the fresh pack-backed proof. The sorted per-file SHA-256
manifest digest for all three trees is
`6c29dcc2ab5b3e1dc676737acc5575a7accaced4b5293eb2c4818db3ecd1e4b3`.

A lightweight composition regression now compiles both tracked scenarios and
asserts equal effective environment, baseline, storyline, red herrings, time,
seed, observation profile, output selection, organization origins, and active
persona behavior after normalizing only the intentional wrapper identity and
the unused qualified technology persona.

## Why the Saved Trees Differ

The legacy top-level data tree is not a current-input/current-code golden:

| Dataset | Bytes | Records | Files |
|---|---:|---:|---:|
| Saved top-level data from 2026-08-04 | 51,813,359 | 87,949 | 89 |
| Assessment loop 69 from 2026-08-12 | 44,871,235 | 77,795 | 87 |
| Current normalized inline or pack-backed proof | 42,964,903 | 76,191 | 90 |

The August 4 ground truth has three red herrings, `evt-034`, no `evt-022b`, and
no canonical SMB activity. Later commits added the multipart red herring, ten
typed SMB activities, two SMB red herrings, and `evt-022b`, while removing
`evt-034`. The saved August 4 bundle also predates authoritative resolved and
generation manifests, so it cannot establish identical input, generator, or
runtime options.

The August 4-to-current byte difference is concentrated in Windows Security,
eCAR, and Sysmon (92.18% of the byte delta). Loop 69 is a much closer historical
comparison: current output is 4.25% smaller in bytes and 2.06% smaller in
records after subsequent generator realism and lifecycle changes.

Changing only the scenario name from `iteration-test-expanded-ids` to
`iteration-test` changes deterministic scoped substreams and increased the
current proof by 3.32% in bytes and 4.83% in records. That variance is expected
but runs opposite to the originally reported reduction.

## Compatibility Defect Found During Replay

Replaying the exact pre-multipart scenario on current code initially exposed a
real, pack-independent failure: baseline explicit-credential activity could
select a newer session whose authoritative end preceded the requested event,
then attempt to materialize its caller process after session close. Timestamped
LogonID selection now uses the state manager's time-qualified session lookup,
which excludes authoritative-ended and network-closed sessions while retaining
valid out-of-order history. The focused 4648 regression passes, and the exact
historical replay now completes with 42,740,582 bytes and 75,445 records.

## Comparison Policy

Preserve the August 4 output as historical assessment evidence. Future volume
comparisons should use a generation manifest, resolved scenario, exact generator
version, seed, format set, output target, per-family record counts, and file
digests. `du` alone is useful as a symptom, not as an equivalence contract.
