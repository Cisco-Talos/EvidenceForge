# SSH ULF: ordinary log shape passes; authentication callsite pending

The user supplied a fixed version-1 report with **38 retained records**, PASS for
collector readiness/cleanup and execution binding, and no ring eviction. The
implemented `logEvent` schema check failed. Message families, sender classes and
other classifications remained at their defaults because that analyzer returns
at the first validation failure. Those zero counts do not establish absent SSH
authentication or session messages.

The capture selector authenticates process/image/time ownership but does not
restrict `eventType`. The analyzer validates every selected row as a `logEvent`.
Consequently a non-log entry can prevent classification of genuine log entries;
a genuine log entry outside the current schema can do the same. The fixed report
alone did not identify which happened. Neither the wire contract nor generation
was relaxed on that hypothesis.

## Authorized offline result

The approved fixed-output review authenticated provenance, original controls and
all retained execution bindings. It found **17 valid ordinary log records and 21
activity-creation entries**, with **zero invalid ordinary logs**. The activity
entries caused the earlier analyzer failure. All 17 ordinary logs already fit
the existing production decoder; the decoder needs no relaxation.

One ordinary record matches successful keyboard-interactive/PAM authentication.
Grouped fixed comparisons identify its writer as root-owned `sshd-session`, its
sender as the same main image/UUID, its level as Info, empty subsystem/category,
and zero activity/parent activity. Trace, program counter, uptime and thread are
nonzero. Its format/callsite does **not** fit the current static main-image
generation profile. The other 16 ordinary messages remain `other_controlled`;
they do not qualify guessed PAM-open/close or disconnect templates.

The version-2 capture summary now counts ordinary, other, invalid and classified
records separately. Activity-only retention stays INCONCLUSIVE for ordinary-log
shape. Invalid ordinary logs keep overall shape FAIL while valid-subset message
counts remain available. Existing capture/support/provenance files are untouched.

The prepared version-3 offline reviewer adds one grouped classification of the
remaining callsite differences: public namespace/level/PC-style/flag meanings,
dynamic/static format, known public format strings and coarse range/alignment/
code-to-PC comparisons. It returns no native text, numbers, offsets, addresses or
unknown names. Apple's public
[tracepoint layout](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/libkern/firehose/tracepoint_private.h)
and [discriminants](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/libkern/firehose/firehose_types_private.h)
define these comparisons. Apple's published
[OpenSSH logger](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/log.c)
uses a syslog path with a bounded string format; this is a source clue, not proof
of the private binary's layout. No SSH ULF generation profile is enabled until
the actual remaining comparisons establish a compatible rendering path.

## One offline review of the existing capture

`scripts/macos_ssh_unified_review.py prepare` creates code and expected fingerprints
only, outside Git. It opens no original capture. A separately authorized
`review-existing --private-run --source-kit KIT` does the following locally:

- Authenticates code/marker/guard hashes, original controls, immutable opt-in and
  client nonce; re-proves the saved ES connection tree and closed server execution
  windows without executing captured code or querying installed applications.
- Reads the bounded saved ULF file, checks its count and re-binds **every** row to
  those windows. It reads no broader native stream, system log or unrelated kit.
- Separates non-log kinds from log entries. It reports all failing log fields in
  one pass, using only allowlisted field names, error categories and coarse type,
  string, integer-sentinel and object-key comparisons. Unknown keys and every
  observed value, validator message/context, identity, path and native text remain
  private. Only recognized public object-key names can be reported.
- Classifies only fully valid log entries using the already-intended fixed
  role/sender/format/message-family comparisons. `shape_scope: LOG_EVENT_ROWS_ONLY`
  and the separate valid/invalid/other counts prevent a valid subset from passing
  off the entire capture as schema-valid.

This review starts no collectors, commands, apps or probes, makes no live queries,
and writes nothing. The existing used kit remains untouched. Permission is needed
before this read under the user's standing local-log rule. **No new collection is
needed for the reported shape failure.** The gate remains NOT_EVALUATED, and SSH
ULF generation remains unqualified pending the callsite result and implementation.
