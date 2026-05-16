# External Parser Validation Agent Notes

This directory documents the developer-facing third-party parser validation
pipeline. It is separate from `eforge eval` and separate from blind realism
assessment skills.

Start here:

1. Read `README.md` for the purpose and quickstart.
2. Read `coverage-matrix.md` before adding or changing parser coverage.
3. Read `ignored-parser-tags.md` before touching tag policy.
4. Read `sof-elk-harness.md` before changing Compose runtime, staging, or
   SOF-ELK config handling.

Primary full-dataset command:

```bash
uv run python scripts/external_parser.py <data-dir> --work-dir <work-dir>
```

Contributor smoke command:

```bash
uv run pytest --include-external-parsers -m external_parser --no-cov
```

Implementation lives under `src/evidenceforge/external_parsers/`. The script
entrypoint is `scripts/external_parser.py`. Keep this developer-facing; do not
add it to the user-facing `eforge` CLI.

Ignored parser tags must be explicit, scoped, tested, and documented. Never add
a blanket `_grokparsefail*` ignore.
