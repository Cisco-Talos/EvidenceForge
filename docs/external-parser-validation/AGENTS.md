# External Parser Validation Agent Notes

This directory documents the developer-facing third-party parser validation
pipeline. It is separate from `eforge eval` and separate from blind realism
assessment skills.

Start here:

1. Read `README.md` for the purpose and quickstart.
2. Read `coverage-matrix.md` before adding or changing parser coverage.
3. Read `ignored-parser-tags.md` before touching tag policy.
4. Read `sof-elk-harness.md` before changing SOF-ELK® Compose runtime, staging,
   or config handling.
5. Read `splunk-harness.md` before changing Splunk Compose runtime, generated
   app config, CIM activation, or search/report validation.

Primary full-dataset command:

```bash
uv run python scripts/external_parser.py <data-dir> --work-dir <work-dir>
```

The script supports SOF-ELK and Splunk backends. The generated dataset must have
an explicit `OUTPUT_TARGET.txt` marker set to `sof-elk` or `splunk`; missing,
invalid, or `default` markers should fail before discovery or staging.

Contributor smoke command:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

Implementation lives under `src/evidenceforge/external_parsers/`. The script
entrypoint is `scripts/external_parser.py`. Keep this developer-facing; do not
add it to the user-facing `eforge` CLI.

For SOF-ELK checks, use data generated with `eforge generate --target sof-elk`.
For Splunk checks, use data generated with `eforge generate --target splunk`.

Ignored parser tags must be explicit, scoped, tested, and documented. Never add
a blanket `_grokparsefail*` ignore.
