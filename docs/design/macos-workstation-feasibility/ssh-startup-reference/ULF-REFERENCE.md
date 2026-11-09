# SSH ULF: qualified envelope and bounded accepted-authentication methods

The user supplied a fixed version-1 report with **38 retained records**, PASS for
collector readiness/cleanup and execution binding, and no ring eviction. The
implemented `logEvent` schema check failed. Message families, sender classes and
other classifications remained at their defaults because that analyzer returns
at the first validation failure. Those zero counts do not establish absent SSH
authentication or session messages.

The capture selector authenticates process/image/time ownership but does not
restrict `eventType`. The original analyzer validated every selected row as a `logEvent`.
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
nonzero. Its format/callsite did **not** fit the previous static main-image
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
of the private binary's layout. The completed authorized comparison and supported
generation boundary are described below.

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
needed for the reported shape failure.** Review output remains NOT_EVALUATED until
an implementation and its tests establish the supported boundary below.

## Authorized version-3 result and implemented boundary

The user approved the grouped comparison and it completed with error NONE; all
provenance, original controls and execution bindings pass. The accepted PAM row
uses the log namespace, matching Info level, MAIN_IMAGE PC style and only the
PRIVATE_DATA flag. The format is the public OpenSSH `%.500s`, static offset and
PC ranges pass, and the PC is arm64-aligned. Source is absent and a backtrace is
present. Dynamic format is absent. No offsets, addresses, frame contents or other
native values were exported. The previous static-profile mismatch is explained
by its excluded private-data flag, rather than a need for a dynamic-format codec.

Generation now supports that bounded PAM success family through the canonical
receiver's successful-authentication/audit-adoption occurrence. Both PTY modes
share the same producer; password intent selects this reviewed PAM profile. A
public-key session does not acquire an invented PAM-success message. The exact
receiver, session user and transport peer are checked against State before
publication. ULF and eCAR share one retained source journal and can recover a
committed write with a lost return without duplicate authentication.

The production profile supplies explicit synthetic build offsets and a modeled
main-image backtrace; it does not claim the private executable's call-stack
contents or frame count. This models the reference's visible/unredacted Info
collection, not every collector's privacy or persistence configuration. Other
16 messages, PAM open/close, disconnect and launchd lifecycle
ULF remain unqualified. No new native collection or unrelated log read occurred.

## Public-source extension and ordinary daemon verbosity

Apple's published [authentication implementation](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/auth.c)
uses one accepted-authentication function for PAM and plain public keys, at Info,
with key type/fingerprint supplied by the authentication owner. Its
[logging implementation](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/log.c)
uses the same `%.500s` syslog callsite. The
[privilege-separation sequence](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/sshd-session.c)
keeps this successful-authentication logging before the post-auth child privilege drop.
This supports the explicit inference that plain public-key success can reuse the
qualified envelope. Its text remains source-derived, not separately captured on
the private system. Generation records `public_source_same_logger` as its semantic
basis, preserves the canonical authentication method, and requires a complete plain
RSA/ED25519/ECDSA type and canonical SHA256 fingerprint. Unknown keys and certificates
remain unsupported; no fallback key is invented. Historical PAM-only profiles remain
readable without acquiring a new message family.

The same public source distinguishes daemon verbosity from collector selection.
The [session implementation](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/session.c)
marks session-start and close messages VERBOSE. Enabling Info in `log stream` does
not enable messages already filtered by the daemon. The
[PAM implementation](https://github.com/apple-oss-distributions/OpenSSH/blob/main/openssh/auth-pam.c)
does not establish a generic successful PAM-open Info message from session creation
alone. On 2026-11-03 the user chose to retain ordinary daemon verbosity and leave
verbose session messages gated. No system setting is changed and no new capture is
requested for those messages. The other sixteen existing native messages remain
unclassified; none was read again or promoted by this source review.
