# Loop 7 family contract

## Family A: runtime executable content identity

- **Owner:** `ProcessPreflightPlanner` and `RuntimeContentIdentityManager`, which create the canonical local artifact version for an executable whose deployment catalog has no exact binary identity.
- **Entry:** a process start with an unresolved image and no matching executable file effect; current root publication omits size and the content identity defaults it to zero.
- **Invariant:** modeled executable images have a positive, deterministic canonical content size before publication; their identity/hash triplet is computed once and reused by every renderer. Explicitly authored or observed file sizes remain authoritative.
- **Consumers / sibling risks:** Sysmon, eCAR/EDR, SMB and file-transfer projections that resolve the same artifact version; Windows, Linux, and macOS executable fallback paths.
- **Scope:** source-owned fallback metadata only; no emitter hash rewrite and no scenario-specific executable patch.

## Family B: failed SSH transport/authentication chronology

- **Owner:** the failed-logon/SSH action expansion and shared source timing planner.
- **Entry:** remote failed SSH authentication on Linux, including baseline and typed-storyline calls to `generate_failed_logon`.
- **Invariant:** the matching inbound transport observation is visible before failed-authentication evidence in endpoint sources, while Zeek/syslog transport and responder ordering retain their canonical tuple and lifecycle.
- **Consumers / sibling risks:** eCAR FLOW/LOGIN, Zeek `conn.log`, sshd syslog, endpoint process attribution, all modeled Linux targets.
- **Scope:** correct the transport/auth temporal contract at canonical planning/generation, not by sorting eCAR output or shifting one report row.
