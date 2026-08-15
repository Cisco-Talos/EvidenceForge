# EvidenceForge v2 Assessment Loops 21–30

## Loop 21 — Linux session and process identity

### Family contract (before implementation)

- **Accepted finding:** in the Loop 20 frozen corpus, one Linux process rendered different
  `session_id` values at create and terminate, and one completed local Linux session's `logon_id`
  was reused by a later distinct session. Both lifecycle endpoints were inside the strict review
  window, so boundary censoring cannot explain either contradiction.
- **Owning layer:** `StateManager` owns canonical session identity and session registration;
  `ActivityGenerator` owns local Linux logind allocation before it publishes login/process
  occurrences. Emitters must only project the immutable canonical values.
- **Entry path:** generic local Linux `generate_logon()` / `LogonActionBundle`, including
  pre-window bootstraps that later acquire visible shell/process lifecycles.
- **Sibling inventory:** workstation GDM sessions, server/console `/bin/login` sessions,
  pre-window local sessions, baseline sudo-created local sessions, and SSH sessions. SSH keeps its
  bundle-owned post-auth logind allocation; Windows terminal session IDs and service/network token
  identities remain unchanged.
- **Invariant:** a session receives one nonzero logind `session_id` before any local Linux login or
  member process occurrence can be published; that ID cannot be replaced afterward. A
  `RunningProcess` retains its owning session identity across create/terminate. An ended LogonID
  cannot be registered as a new lifecycle; callers must allocate a fresh canonical identity.
- **Boundary semantics:** unmatched pre-window creates or post-window terminations remain valid and
  are excluded from completeness assertions. The invariant applies when both lifecycle endpoints
  are observable in the half-open review window.
- **Rendered hard probe:** within `[start,end)`, group Linux eCAR `PROCESS/CREATE` and
  `PROCESS/TERMINATE` by host, PID, and process start/object identity; require equal LogonID and
  session ID for complete pairs. Group `USER_SESSION/LOGIN` through logout by host and session
  object; require one LogonID per object and reject a LogonID assigned to two non-overlapping,
  complete session objects. Report boundary-only unmatched rows separately. Split local/GDM,
  console, and SSH counts so sibling regressions cannot hide in an aggregate pass.

### Implementation handoff

- Local Linux generic-logon and carried-in sudo paths now create session state with a zero
  unpublished placeholder, allocate the host-local logind ID immediately, and only then publish
  login or member-process evidence. `_emit_linux_local_logon_syslog()` projects that existing
  identity rather than reallocating it.
- `StateManager.update_session_metadata()` permits bundle finalization from zero and idempotent
  repetition, but rejects replacement of a nonzero session ID. This preserves SSH's bundle-owned
  post-auth assignment while making published session identity immutable.
- `StateManager.register_session()` resolves active aliases idempotently and rejects resurrection
  of an ended LogonID. Pre-window sudo bootstraps now use the canonical LUID allocator instead of a
  repeatable host/user/TTY/day hash, so a reused TTY receives a fresh LogonID and object lifecycle.
- Focused verification: 2 state invariant tests passed; 2 sudo bootstrap/reuse tests passed; 7
  local/GDM/console plus SSH lifecycle tests passed.
- Broad relevant verification: 744 passed, 1 skipped across state, activity, baseline canonical,
  world-model, eCAR object-graph, and logoff suites. A 221-test Linux/session/SSH selection also
  passed. Ruff check and format check passed for all five modified Python files.
- Configuration validation was not required because no configuration catalog or schema changed.

### Hard-probe follow-up

The first regenerated probe cleared session-ID mutation and ended-LogonID reuse, but found 23 of
736 complete Linux process pairs whose CREATE used the root `sshd: user [priv]` token
(`0x3e7`, no terminal session ID) while TERMINATE used the attached user's SSH LogonID and logind
session ID. All 23 were tuple-scoped receiver sshd children across APP-INT-01, DB-PROD-01,
MAIL-CLIN-01, MAIL-EDGE-01, and sibling Linux receivers.

Root cause: `RunningProcess.logon_id` was serving both as the immutable process token identity and
as mutable session-membership metadata. `assign_process_to_session()` correctly attached the root
sshd responder so session teardown could find it, but termination rebuilt authentication fields
from that membership value.

The canonical process state now preserves `token_logon_id` plus the exact published auth session
ID/logon type separately from mutable teardown membership. The central create-recording path freezes
that tuple once and rejects replacement; termination projects it while still using membership for
session close timing and process discovery. This also preserves Windows winlogon's SYSTEM token plus
terminal-session metadata exactly across CREATE/TERMINATE.

Follow-up verification: the central membership/token invariant, SSH receiver lifecycle, Windows
interactive winlogon, and RDP sibling tests pass. The broad relevant suite passes with 746 passed
and 1 skipped.
