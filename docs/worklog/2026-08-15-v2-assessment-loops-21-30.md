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

### Loop 21 outcome

- Commits `7842607c` and `c9cba448`; final full suite 6,022 passed with 22 skips. Evaluation scored
  96.4475/100 over 74,261 records. The accepted rendered probe passed 736/736 complete Linux
  process pairs and 27/27 complete session pairs with zero identity/session mutations, zero ended
  LogonID reuse, and exact SSH syslog lifecycle joins.
- The first candidate corpus was rejected before blind review after its hard probe exposed 23 root
  sshd token/session mutations. The owning state split was fixed, the full suite and generation
  were repeated, and a completely fresh panel reviewed only the corrected corpus.
- Frozen corpus SHA-256 remained
  `54c8a1016104f92f1ca3666a24015e4a1bc23c98e18f7920157cea9b018f36e5` before and after review.
  Standalone scores were 68/36/32/86 (mean 55.5); verdict disagreement and a 54-point spread
  triggered deliberation, which revised the mean to 75.25 and consensus to Synthetic.
- The repaired Linux session/process identity contradictions did not recur. Next priorities are
  native MRU/PIDL encoding, Linux command construction, network timing/throughput quantization,
  and the detached PSEXESVC file lifecycle.

## Loop 22 — Windows MRU and PIDL registry artifacts

### Family contract (before implementation)

- **Accepted findings:** Loop 21 exposed extension-specific `RecentDocs` and `OpenSavePidlMRU`
  values whose filenames disagree with their registry subkeys in seven of nine inspected examples,
  plus `OpenSavePidlMRU` and `LastVisitedPidlMRU` data that are decorated UTF-16 paths rather than
  credible serialized Windows shell item-ID lists. These are repeated visible source-native
  contradictions across five workstations, not boundary-censoring or completeness findings.
- **Owning layer and classification:** the shared Windows registry-artifact encoder/serializer owns
  native registry value bytes and extension-subkey binding. This is a `family_level` source-native
  serialization fix: canonical file/path truth remains upstream, while the encoder must express it
  in the native binary family consumed by registry forensic tools.
- **Entry paths:** baseline shell/Office activity that creates `RecentDocs`, `OpenSavePidlMRU`,
  `LastVisitedPidlMRU`, and `UserAssist` registry artifacts; any storyline or direct registry path
  that delegates to the same artifact helpers; and multi-user/multi-host baseline generation.
- **Consumers:** eCAR registry projection, rendered registry value-data bytes, native-aware forensic
  decoders, blind-review probes, and focused generator/emitter tests.
- **Invariant:** an extension-specific MRU subkey is derived from and agrees with the actual bound
  filename extension. PIDL-family values contain a structurally valid, terminating shell
  item-ID-list whose decoded leaf/path identity agrees with the canonical artifact, rather than a
  magic prefix plus plain UTF-16 text. Family-specific framing remains distinct: UserAssist ROT13
  and execution metadata, RecentDocs value shape, OpenSave PIDLs, and LastVisited PIDLs must not be
  collapsed into one encoding.
- **Sibling risks:** preserve UserAssist, non-extension RecentDocs ordering/MRUListEx, and
  LastVisited application/path semantics. This loop does not claim full fidelity for every possible
  Windows Shell Item class; it targets a native-decodable filesystem PIDL subset with strict size,
  terminator, and extension-binding checks across multiple hosts and sibling families.

### Implementation handoff

- The group-scoped registry materializer now chooses one configured artifact filename and derives
  extension-specific `OpenSavePidlMRU`/`RecentDocs` contents from that same identity. The filename
  pool moved to `edr_pools.yaml`; the loader rejects malformed overlays and `validate-config`
  rejects paths, extensionless identities, and case-insensitive duplicates.
- The shared PIDL serializer now emits a terminating sequence of native SHITEMID frames: the My
  Computer namespace root, a drive-volume item, and separate directory/file items. OpenSave values
  begin directly with the item-ID list; LastVisited values retain their distinct UTF-16 application
  prefix and bind that executable to the selected file type. The old one-item decorated UTF-16 full
  path is no longer emitted.
- **Materializer hard probe:** 12/12 extension-specific artifacts across three synthetic host
  contexts decoded successfully and matched their `.docx`/`.pdf` subkeys. OpenSave and LastVisited
  samples both passed generic SHITEMID length/termination decoding, native root/volume/file class
  checks, and leaf recovery; zero OpenSave values contained the former UTF-16 full-path signature.
  UserAssist FILETIME/ROT13, AccentPalette, wildcard OpenSave, and RecentDocs sibling checks remain
  green.
- Verification: 164 focused EDR/config tests passed; 377 passed and 1 skipped across EDR pools,
  baseline canonical generation, Sysmon, and eCAR source projection; 4 activity-level registry and
  UserAssist tests passed. `eforge validate-config` passed 93 files with zero issues. Ruff check,
  Ruff format check, and `git diff --check` passed.
