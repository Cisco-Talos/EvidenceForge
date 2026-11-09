# Native installed-file allocation chronology

Classification: sibling_defect / family_level. Owner: canonical modeled installed
filesystem, before ES/eCAR rendering. Both Macs expose lexically ordered inode
inventories because provisioning sorts full paths before assigning inode counters.

Invariant: each host/volume assigns stable, unique object identity in its existing
modeled file-birth/installation chronology. Full path is only a deterministic
tie-breaker for equal births; unrelated input ordering does not affect allocation.
All consumers retain one metadata object, size/times/permissions/deployment binding
and reserved directory ranges. No random emitter inode rewrite or shuffled output.

Verify chronological allocation, shuffled input equivalence, per-volume isolation,
stat/cdhash/path consistency and native recovery. Dense modeled allocation remains
a declared limitation, not a full APFS allocator. Browser singleton lifecycle and
Linux session numbering are higher architectural follow-ups; this bounded repeated
metadata repair is feasible without inventing native launches or changing author intent.

## Hard-validity priority: protocol confirmation prerequisites

Loop66's network specialist finds13no-gap MySQL exchanges with a visible TCP open,
positive client payload and zero server payload, yet service=mysql. Coordinator
qualification against tagged Zeekv8.0.5 confirms that server greeting establishes
protocol version and the versioned client response triggers analyzer confirmation.

Owner: canonical network protocol finalization, after payload/state planning and
before sensor projection. Application intent/port guesses do not establish a
confirmed protocol. For a fully observed TCP open with no canonical gap, require
the configured directional payload prerequisites before publishing a confirmed
service. Keep malformed/unconfirmed bytes/history/tuple intact; do not invent a
server greeting or patch only conn output. Preserve midstream/gapped observations
as qualified unknowns and leave unconfigured protocol semantics unchanged.

Use validated YAML prerequisites (MySQL requires both directions). Cover client-only
reset, server-banner-only scan sibling, valid exchange, gaps/midstream and unrelated
protocol controls. This P0 validity repair outranks the inode texture family; both
are bounded owning-layer changes. Primary references:
https://github.com/zeek/zeek/blob/v8.0.5/src/analyzer/protocol/mysql/mysql-protocol.pac
https://github.com/zeek/zeek/blob/v8.0.5/src/analyzer/protocol/mysql/mysql-analyzer.pac
