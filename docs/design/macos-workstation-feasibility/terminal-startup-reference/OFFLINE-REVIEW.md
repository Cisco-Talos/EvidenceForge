# Existing terminal capture: private offline detail review

This reviewer uses the **completed original version-2 terminal kit**. It starts no collector,
app, marker, command or live query and writes nothing. It does not open installed system apps,
shell history or unrelated logs. No new Terminal collection is needed.

The purpose is to classify the remaining entitlement value types, login arguments and extra
descriptors, credential changes around fork/exec, and responsibility relationships. The output
contains fixed role/word/type labels only: no entitlement keys or values, paths, usernames,
PIDs, audit-session IDs, native pipe IDs, environment strings, signatures or hashes.
`FD_0` through `FD_15` are fixed descriptor slots, not exported process identities. Unknown
descriptor kinds use fixed `TYPE_…` labels; unknown argument strings become `OTHER`.

The reader verifies the original code/codec hashes, private marker/guard metadata, setup and
run provenance, successful collection controls and the retained marker-to-app chain before
classification. The report is diagnostic and does not automatically enable generation.
Private file permissions and bounded record/line/depth limits remain enforced.

Only run it privately with agents closed, unless you explicitly authorize an agent to run
this exact fixed-output reader against the original kit. Never share the original directory,
native records, provenance, terminal contents or screenshots.

From the newly prepared **reviewer** directory, run as your normal user:

```sh
/Users/dabianco/projects/SURGe/EvidenceForge/.venv/bin/python -I -B ./private_terminal_review.py review-existing --private-run
```

At `Original terminal kit (hidden):`, enter the **original outer capture-kit directory**
containing `SETUP.json` and `ACTIVE-RUN`. Do not select the new reviewer directory or the inner
`run-…` directory. The prompt does not echo the path. No sudo, setup or app launch is needed.

Review and share only the final fixed JSON. A successful review has error `NONE`, step
`COMPLETE`, provenance `PASS`, original collection controls `PASS` and retained chain `PASS`.
Comparison failures within individual phases describe observed differences; they are not
automatically capture failures. Keep all existing files unchanged, including after an error.
