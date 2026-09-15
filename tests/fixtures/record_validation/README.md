# Record validation witnesses

`rule_cases.json` contains explicit passing/failing field dictionaries for every bundled rule.
They isolate the rule under test; they are not complete log records.

`formats.json` contains positive schema-level records for every format without variants, including
representative generated fields and minimal standalone source-health records. `windows_variants.json`
contains minimal schema-level witnesses for every Security/Sysmon variant. Tests also remove each
required field and verify variant selection. These fixtures test contracts, not dataset realism.

Native parser fixtures remain under `tests/fixtures/eval/good`. DNS parser mutation tests serialize
complete records before parsing; malformed NDJSON/XML tests exercise native input boundaries.
No test in `test_record_contracts.py` requires local `sample_data`.

The native mutation suite covers all 66 format/variant witnesses. JSON and XML required-field
mutations exercise missing values, illegal empties, wrong types, and nonnullable JSON nulls. All
JSON fields also exercise null/empty/dash/object values, declared numeric boundaries, nonfinite
numbers, and typed list members. Rule witnesses pass through native parsing and shared scoring;
required-field/type failures can make the corresponding rule not applicable without losing the
scalar failure. A mixed malformed-native CLI test exercises all pillars and counted acceptance.

Inapplicable combinations are deliberate: XML has text rather than object/null values, unconstrained
strings and lists may be empty, and an empty Bash username cannot be represented by the nonempty
filename from which the parser derives it. Fixed-position text sources use native malformed
headers/timestamps and rule-specific wire examples. Existing positive fixtures preserve optional
fields, observation gaps, source-native conversions, and unusual evidence.

`legacy/` contains the exact two format documents and threshold document from immutable baseline
`787fd733`. Routine decoder tests use these committed fixtures; the historical slow checkpoint gate
also accepts `EFORGE_VALIDATION_BASELINE_PYTHON` pointing to that baseline's isolated interpreter.
No essential decoder test requires a local historical checkout or sample directory.

`targets/` holds compact Splunk web/proxy JSON examples and a SOF-ELK Snare projection witness from
the iteration scenario. The Splunk fixtures exercise aliases, malformed types/shapes, and conflicts
through the complete CLI. The historical Snare witness retains ambiguous identity labels and omitted
XML metadata; tests require explicit unavailable-check findings rather than invented values.

`snare_full_variants.json` adds synthetic optional-field witnesses for all 43 variants and all 826
declared field slots. These are test values, not new generator defaults. Internal tests compare
canonical fields after rendering/parsing; external tests verify downstream extraction against both
frozen parser revisions. `targets/snare_v1/` contains compact generated projection-version-1 rows.
