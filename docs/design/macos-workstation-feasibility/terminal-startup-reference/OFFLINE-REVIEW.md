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

The reader verifies the original code hashes, private marker/guard metadata, setup and
run provenance, successful collection controls and the retained marker-to-app chain before
classification. The report is diagnostic and does not automatically enable generation.
Private file permissions and bounded record/line/depth limits remain enforced.

Review version 2 accepts the current codec or the exact revision-359 Boolean-only predecessor
used by the completed version-2 Terminal capture. `codec_lineage` reports `CURRENT` or
`QUALIFIED_BOOLEAN_PREDECESSOR`; any other fingerprint is `UNQUALIFIED` and fails provenance.
This preserves review of the original capture after the qualified string-array decoder update
without accepting arbitrary old codecs or changing the capture. It does not authorize another
private review; the standing permission rule still applies.

Version 2 also adds two bounded comparisons needed by the startup producer: whether login's
FDs 4 and 5 share a pipe identity (`SAME`/`DIFFERENT`), and whether Terminal/login's native
entitlements exactly match the independently verified Apple-shipped templates (`PASS`/`FAIL`).
It exports neither pipe IDs nor entitlement keys/values and opens no installed binary. Missing
or malformed inputs remain `NOT_OBSERVED`/`INCONCLUSIVE`; iTerm2 has no inferred vendor template.

Review version 3 adds equivalent pipe-identity grouping for every pipe FD in fixed slots 0-15,
so a different iTerm2 descriptor layout does not need another comparison just to identify
shared pipes. Groups contain only labels such as `FD_3` and `FD_7`, never native identities.
Duplicate/malformed slots fail; pipe slots outside that vocabulary remain inconclusive.
The capture protocol and private-file scope are unchanged. A fresh paired kit can bundle this
reader beside the capture helper; see `ITERM2-RUN.md` for the one-session collection/review flow.

Review version 4 adds closed comparisons for the two iTerm2 helper stages discovered in the
successful paired capture. It compares native signing ID/team, app-bundle versus exact user
support-copy placement, and entitlement equality against independently verified vendor signing
templates. It recognizes the public ShellLauncher path/name and `--launch_shell` switch; a
server's second argument can be classified as a canonical absolute path without exporting it.
Candidates remain separate from proven signing, placement and template matches. OTHER roles
are not silently renamed or admitted by these comparisons.

The same report classifies each responsible-token word as matching the process, zero, both
or other. This resolves the nonexact pre-exec responsibility token without disclosing any ID.
The exact revision-360/361 string-array codec fingerprint is now a second accepted predecessor,
reported as `QUALIFIED_STRING_ARRAY_PREDECESSOR`; arbitrary codec fingerprints still fail.
Code/provenance/marker/guard, collection, scope and private-file checks are unchanged. The reader
runs no commands, opens no installed app or preference, writes nothing and starts no collection.
Preparing version 4 does not authorize it to read an existing private capture.

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
