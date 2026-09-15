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
