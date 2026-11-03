# SSH ULF: records captured; wire-shape diagnosis pending

The user supplied a fixed version-1 report with **38 retained records**, PASS for
collector readiness/cleanup and execution binding, and no ring eviction. The
implemented `logEvent` schema check failed. Message families, sender classes and
other classifications remained at their defaults because that analyzer returns
at the first validation failure. Those zero counts do not establish absent SSH
authentication or session messages. No private records were read by the agent.

The capture selector authenticates process/image/time ownership but does not
restrict `eventType`. The analyzer validates every selected row as a `logEvent`.
Consequently a non-log entry can prevent classification of genuine log entries;
a genuine log entry outside the current schema can do the same. The fixed report
alone does not identify which happened. Neither the wire contract nor generation
is relaxed on that hypothesis.

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
ULF generation remains unqualified pending actual results and implementation.
