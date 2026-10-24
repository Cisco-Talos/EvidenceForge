# Human-only offline v11 shape review

Run this privately in standalone Terminal after closing Codex and other agents.
Agents may prepare code and test invented inputs only. They must never run a
review on your capture, browse old private directories, or ask for raw records,
digests, paths, screenshots or exception text.

This tool reads existing evidence only. It starts no collector, runs no native
command or binary, uses no network, compiles nothing and changes no permissions.
Do not run another capture for this step. No sudo is needed.
It imports the existing checkout's field models; keep that checkout and Python
environment unchanged while running and interpreting the diagnostic.

## Select your existing run privately

Use your existing Python environment and the new code-only review kit:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B private_review.py review --private-run
```

At `Private run directory (input hidden):`, enter the **absolute path to the
existing private-run subdirectory**, then Return. Input is hidden; do not paste
the path into chat or put it in the command line. Select the run whose version-3
report had every behavioral check PASS and V11_UNQUALIFIED. In the capture kit,
the run directory is named `private-run-...` and contains `probe-events.jsonl`
and `SHAREABLE-REPORT.json`. Choose it yourself; agents must not locate it.

The script rejects noninteractive input. Both the review kit and the input run
must stay outside every Git tree. The run directory and its two files must be
private to your current account (normally 0700/0600). The checker rejects
nonregular files, leaf symlinks and multiply linked files. Do not weaken these
checks, automatically chmod files, or copy evidence into the repository to make
the review work. Keep any error private except for the fixed report.

The reader opens only:

- `SHAREABLE-REPORT.json`, requiring the successful version-3/v11 fixed report.
- `probe-events.jsonl`, with strict JSON and bounded record/byte limits.

It does not open private provenance, controls, the compiled probe or unrelated
files. It does not enumerate the directory or select a run automatically.
Selecting the prior report is a consistency check, not cryptographic proof
that the records remained unchanged since collection. It does not repeat the
live behavioral experiment or claim independent custody of the evidence.

## Review the fixed report before sharing

The checker prints only fixed keys and enumerated classifications. It creates
no report file and changes no capture contents. Privately review its JSON, then
share only that text. Do not add tee, shell tracing, transcripts, screenshots or
archives. The hidden input prompt is operational text, not part of the JSON.

Every output retains:

```json
{
  "mode": "OFFLINE_ONLY",
  "purpose": "SHAPE_DIAGNOSTIC_ONLY",
  "reference_review": "REQUIRED",
  "gate_status": "NOT_EVALUATED",
  "message_shapes": "INCONCLUSIVE"
}
```

`review_complete: PASS` means the diagnostic completed. A zero exit code means
it produced that diagnostic without an input/source error. **Neither means v11
has been qualified.** Candidate encoding failures are useful diagnostics, not
instructions to collect again.

### Known structure checks

- `capture_summary` checks the fixed version-3 successful-run report. A different
  kit, unsuccessful capture report or unexpected report fields yields SOURCE.
- `wire_profile` describes original headers. No record is retagged or coerced.
  A disagreement with the selected v11 report yields SOURCE.
- `retained_families` requires fork, exec and exit families to be present.
- `envelope_fields/values` check the known envelope fields with an explicit
  message-11 discriminant. This is not a complete v11 codec.
- `process_fields` requires every existing process field and permits the
  documented candidate `cdhash_full` key. Its presence/null handling is reported
  separately, without assuming v11 requires it. Unexpected keys fail this check.
- `process_values` checks **only the existing process fields** against the
  legacy field models, including explicit nonnull code-validation category.
  Unknown keys are never silently accepted as a complete message. New full-hash
  values are excluded from this diagnostic view; originals remain unchanged.
- `fork_payload`, `exec_fields/values` and `exit_payload` inspect known event
  wrappers and fields. Exec's process target uses the same legacy-only view.
  Missing nullable fields, unknown nested fields and invalid existing values
  cannot become a full-layout pass.
- `audit_token_form` and `process_start_form` classify only explicit known
  representations. A val-wrapper or timeval can be classified while failing
  the existing process-value model; the tool does not normalize these layouts.

FAIL is aggregate: at least one observed instance failed. INCONCLUSIVE means
the check had no applicable evidence. No instance counts, record positions,
unknown field names, native values or error snippets are exported.

### Full-hash diagnostics

`full_hash` aggregates the source process, fork child and exec target snapshots:

- `presence`: PRESENT_ALL, ABSENT_ALL or MIXED distinguishes absent keys from
  present values. `representation` separately distinguishes NULL, STRING,
  BYTE_ARRAY, SIZE_DATA_OBJECT, OTHER_OBJECT and unrecognized/mixed forms.
- `object_keys` checks whether any observed objects have exactly size/data.
  `declared_size_type` checks a strict nonnegative bounded integer size. These
  are candidate-shape probes, not assertions about Apple's actual JSON format.
- `hex_decoding`, `base64_decoding` and `array_decoding` independently test
  **nonnull present values**. Sized objects test their data member. Null and
  absent values never masquerade as empty byte buffers. Several candidates can
  pass for the same text; the checker does not choose an encoding automatically.
- Each encoding's `extent` exports only EMPTY, BYTES_20, BYTES_32, BYTES_48,
  BYTES_64, OTHER or MIXED. It exports no arbitrary length. These buckets do not
  identify a hash algorithm, declare a native limit or qualify the representation.
- `*_declared_size` compares decoded extent with explicit size only when all
  nonnull candidate values are sized objects with valid sizes.
- `*_legacy_prefix` compares the first twenty decoded bytes with the existing
  40-hex cdhash only when all candidate values permit that comparison. It does
  not assume that this relationship must hold, recover a full digest from a
  truncated one, or validate a hash algorithm. Unknown or too-short values stay
  inconclusive.

All unknown fields and all digest/native values remain private. A full v11
codec, correct canonical metadata ownership, private human reference review,
and parser/source/filtering/manifest/checkpoint acceptance still follow these
diagnostics. macOS 27 evidence does not establish macOS 26 fidelity. Gatekeeper
is a separate experiment and is not inspected by this tool.
