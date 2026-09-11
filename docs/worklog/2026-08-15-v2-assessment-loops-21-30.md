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

### Loop 22 outcome

- Commit `e432bd27`; full suite 6,025 passed with 22 skips. Evaluation scored 96.8280/100 over
  71,618 records. The rendered probe passed all native PIDL, extension-key, LastVisited,
  UserAssist, and RecentDocs checks with zero legacy decorated-path signatures.
- Frozen corpus SHA-256 remained
  `3f18346483a37eed2eb6ed6f5e7efa1f4962f519cb00dd5f6097030b200eb1f8` before and after review.
  Standalone scores were 67/66/62/97 (mean 73.0); the 35-point spread triggered deliberation.
- The Host review's WFP direction claim was independently disproven: all 6,008 rows use the native
  mapping correctly. Corrected deliberation gives that false positive zero weight and revises the
  panel to 76/80/72/78 (mean 76.5). The MRU/PIDL findings did not recur.
- Next accepted priorities are family-specific duration/throughput floors, detached PSEXESVC
  delivery timing, bounded eCAR process-observation latency, and SMB endpoint actor projection.

## Loop 23 — SMB transfer timing and mutable file identity

### Family contract (before implementation)

- **Accepted finding:** the Loop 22 frozen corpus exposed successful SMB sessions with materially
  different byte volumes closing at the same 2.5-second floor and tightly repeated mapping/file
  offsets. Source inspection also found that every SMB `FileTransferContext` used the fixed
  `size / 25,000,000` duration, while an `update` constructed its WRITE transfer context and FUID
  from the old size/content version before mutating canonical SMB file state.
- **Owning layer and classification:** `SmbActivityActionBundle` owns SMB operation timing within
  its canonical transport budget and must construct file-transfer identity from the final
  operation state. This is a `family_level` canonical bundle fix; Zeek, eCAR, Windows, and Samba
  renderers remain source-native projections and must not invent replacement timing or identity.
- **Entry paths:** Windows Explorer reads/creates/updates, Linux `smbclient` and CIFS-mounted
  operations, batch activity, and the read/write legs of client/share and cross-share copy/move.
- **Invariant:** each successful read/write samples deterministic session-scoped lognormal wire
  throughput plus bounded setup and operation jitter from a dedicated stable RNG. Its transfer
  duration and action/close timestamps stay inside the owning connection interval. An update
  mutates state before deriving WRITE size, content version, and FUID, so rendered bytes and
  ground truth identify the same post-update version exactly.
- **Sibling and observation semantics:** preserve Windows and Linux process/auth ownership,
  copy/move leg ordering, file handle closure, transport byte accounting, and coherent source-level
  observation loss. Missing rendered siblings remain a shared observation decision rather than a
  second timing sample. Authored batch duration remains the connection budget and cannot be
  overrun by sampled operation timing.
- **Verification contract:** focused tests cover exact Windows update size/version/FUID identity,
  deterministic rate diversity without a fixed 25 MB/s signature, Linux projection siblings,
  helper bounds/config validation, and child-within-parent ordering for every retained source view.

### Implementation handoff

- `SmbActivityActionBundle` now plans each operation with a dedicated stable RNG scoped by the
  canonical SMB action, operation index, and file identity. Wire rates use the validated
  lognormal profile in `smb_profiles.yaml`; tree setup, per-operation setup/jitter, close delay,
  purpose dwell, and transport tail are also data-driven. The former 2.5-second connection floor
  and fixed 25 MB/s file duration are gone.
- Operation cursors advance by the exact planned open-to-close span, with the transport budget
  reserving worst-case auth/tree setup. Explicitly authored short batch durations deterministically
  scale their session/operation spans so children remain inside the parent connection rather than
  silently extending it.
- SMB `update` now mutates canonical state before constructing its WRITE context. Transport byte
  accounting, Zeek SMB size, Zeek `files` size, ground truth, and the version-derived canonical
  FUID therefore all use the same post-update bytes/content version. Client-to-share move uploads
  retain payload-bearing timing; cross-share copy/move and Linux/Windows siblings remain on their
  existing canonical paths.
- Verification: 71 focused timing/config/update tests passed. The broader SMB/storage/source-
  timing/network-observation suite passed 228 tests. `eforge validate-config` passed 93 files with
  zero issues; Ruff check/format and `git diff --check` passed.

### Loop 23 outcome

- Commit `f4b549ec`; full suite 6,029 passed with 22 skips. Evaluation scored 96.8268/100 over
  71,618 records. The rendered probe passed all 8 transfers and 10 mappings, with 8/8 distinct
  rounded rates, a 2.222 max/min rate ratio, exact post-update FUID/size agreement, and no 2.5s
  duration floor.
- Frozen corpus SHA-256 remained
  `0ab041b1ef720f8449259e71d3c0d3cb1c4cb31243d1bea36c841d3c6fae0256` before and after review.
  Standalone scores were 68/32/46/89 (mean 58.75); required deliberation revised the mean to 70.0.
- The SMB finding did not recur. The next P0 is overlapping non-backgrounded foreground commands
  under one Linux shell; PSEXESVC delivery timing, inventory-shaped scan expansion, endpoint actor
  omission, and role-insensitive baseline palettes remain follow-ups.

## Loop 24 — Linux interactive foreground-job serialization

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 23 Host review found repeated visible
  `hard_contradiction` evidence where one Linux interactive shell launched unrelated foreground
  commands before earlier children terminated. This is a `new_family` process-lifecycle defect,
  including both nearly simultaneous polkit/admin commands and long-lived developer commands such
  as `git`, `cargo`, and `kubectl` followed by later siblings.
- **Owning layer:** the Linux shell-command action/process scheduling layer owns foreground-job
  admission and canonical process lifetime. `ActivityGenerator` owns the shared shell reservation
  and completion state used by bash-history, baseline catalog, storyline, SSH, local console/GDM,
  and loose user-CLI companion paths. eCAR and other endpoint emitters only project that truth.
- **Invariant:** for one concrete interactive shell PID, unrelated non-backgrounded foreground
  child intervals must never overlap. True stages of the same explicit pipeline may overlap;
  commands explicitly backgrounded with shell syntax, terminal-multiplexer launches, detached GUI
  clients, and service/daemon helpers do not reserve the foreground slot. A bounded or hung/long
  foreground child blocks later unrelated children through its canonical/source-visible completion
  or owning session boundary.
- **Entry paths:** direct `LinuxShellCommandActionBundle` process inference; application-catalog and
  legacy baseline process activity; typed storyline process events; SSH source clients; SSH/local
  console/GDM session shells; polkit/user-CLI companions; explicit pipelines and compound commands.
  Raw system/service processes whose parent is not an interactive shell are intentionally outside
  the foreground-job contract.
- **Consumers:** canonical `RunningProcess` state and process create/terminate occurrences, eCAR
  process lifecycle, bash history, Linux session teardown, process-owned network attribution, and
  the rendered no-overlap hard probe.
- **Layer rationale:** only shared shell scheduling can prevent sibling callers from creating the
  contradiction. Changing eCAR timestamps would conceal incorrect canonical lifecycles, while
  patching the two observed commands or one baseline caller would leave the other entry paths open.
- **Sibling risks and verification:** preserve legitimate same-pipeline concurrency and explicit
  background/detached work; cover SSH and local/GDM ownership, loose polkit-style CLI creation,
  long/hung foreground siblings, and session-bound behavior. The rendered probe must group eCAR
  process intervals by host and shell PID, reject overlapping unrelated foreground children wholly
  visible in-window, and separately report pipeline/background/detached exemptions.

### Implementation handoff

- `ActivityGenerator` now enforces foreground admission after canonical Linux parent repair, so
  every bounded process whose real parent is an interactive `bash`/`sh`/`zsh` observes the shared
  shell reservation even when its caller omitted explicit scheduling. Canonical `RunningProcess`
  state retains the pipeline concurrency-group identity through termination.
- Process finalizers, process-owned transport holds, unbounded foreground session boundaries, and
  source-visible termination observations all advance the same shell release watermark. Repeated
  caller bookkeeping remains idempotent. Same-group pipeline stages may overlap; explicit `&`,
  `nohup`, detached `tmux`/`screen`/`setsid`, terminal-follow commands, and detached GUI terminals
  and editors do not occupy the foreground slot.
- Linux sudo generation now reserves the concrete session shell before creating `sudo` and shifts
  its elevated child, PAM runtime, TTY reservation, and returned timing delta together. Loose
  polkit CLI companions use the same public reservation and are omitted when no pre-authorization
  slot remains, rather than being rendered after their authorization evidence.
- Focused shell/process tests passed 481/481. Broader state, sudo, bash-history, baseline,
  storyline, SSH/world-model, eCAR, and process-family validation passed 1,057 tests with one
  skip across the two broad runs. Ruff check, Ruff format check, and `git diff --check` passed.
- **Rendered hard-probe design:** inside the strict review window, index eCAR `PROCESS/CREATE` and
  `PROCESS/TERMINATE` by `(host, objectID)`, then group complete child intervals by parent shell
  `(host, ppid)` after proving that parent is `bash`/`sh`/`zsh`. Classify explicit background,
  detached/multiplexer, and same-command pipeline cohorts separately. Fail when two complete,
  unrelated foreground intervals overlap; report host, shell PID, both commands, interval bounds,
  overlap duration, and exemption counts. Add targeted assertions that the former DB sudo burst
  and workstation `git`/`cargo`/`kubectl` sequence contain zero unexplained overlaps, while at
  least one real pipeline remains concurrently visible.
- **Rendered-probe correction:** the first corrected corpus still failed with 16 contradictions
  (10 complete overlaps and 6 visible creates that appeared unbounded before a successor),
  concentrated in the workstation GDM shell with three SSH-shell cases. Two missed contracts were
  responsible. Transport-anchored Linux client processes used `source_visible_by` to bypass normal
  admission and parent repair then returned them to the busy primary shell. They now select an
  available same-session shell and materialize a sibling terminal/SSH-channel shell when the
  transport deadline cannot fit the primary shell's reservation; the valid explicit sibling shell
  parent is preserved through canonical parent sanitation. Separately, process termination events
  now retain the create's `concurrency_group_id`, so source observation missingness cannot show a
  grouped foreground create while independently dropping its bounded termination. Regression tests
  cover a long-held GDM command followed by an anchored SSH client on a sibling shell and coherent
  create/terminate observation grouping.
- **Second rendered-probe correction:** the next corpus reduced the family to five GDM-shell
  contradictions, all loose developer commands (`npm`, `docker`, and `git`) followed by another
  baseline/polkit command. Canonical process creation previously reserved only admission; bounded
  completion was registered later by selected callers. That left a re-entrant gap while command
  network effects were materialized and left a few loose entry paths without any finalizer.
  Every bounded foreground child now claims a deterministic provisional lifetime and finalizer
  immediately after state allocation, before dispatch or command/network side effects. Explicit
  caller termination and process-owned transport holds may extend that claim, while deduplication
  keeps one termination. A direct GDM regression creates `docker images` followed 75 ms later by
  `git diff --stat`, proves the second start moves after the provisional end, and proves finalization
  renders the first termination before the successor.
- **Full-suite SMB correction:** the provisional reservation exposed a transport-anchored sibling
  shell whose startup-readiness floor could consume the entire SMB deadline. Mounted CIFS copy and
  move then fell back to the session's `systemd --user` process instead of materializing `cp`/`mv`.
  Sibling shells now start early enough to satisfy the canonical readiness ceiling. The shared
  process-hold contract also extends any already-registered foreground finalizer through dependent
  action-bundle effects; the SMB bundle holds its user-space actor through the transport/operation
  close even when CIFS transport attribution remains kernel-owned. This preserves `cp`/`mv` FILE
  provenance while keeping the owning shell reserved until the extended termination. The exact
  copy/upload-move/rename regressions passed, as did all 30 Linux SMB integration tests, 53 process
  lifetime tests, and 197 related SMB/eCAR tests.

### Loop 24 outcome

- Final verification passed the complete suite: 6,038 passed and 22 skipped; repository-wide Ruff
  check and format check passed. The final correction is commit `eef7523a`.
- The regenerated corpus passed the strict rendered foreground probe: 335 non-exempt commands,
  145 exact shell groups, 333 visible parent-create checks, 190 successor checks, and zero
  violations. Pipelines, detached GUI work, and follow-mode commands remained explicit exemptions.
- Automated evaluation scored 96.7054 over 73,361 records. The frozen review-data digest is
  `b3fd699a5aa0b61fb9821158d74831a6f2c5bf9b2429c8fca473bcf33231e4de`.
- The fresh panel was unanimous Synthetic with standalone scores 68/72/72/74 (average 71.5), so no
  deliberation was required. The repaired shell-overlap family did not recur. The next highest
  priority is the cross-source PSEXESVC file lifecycle inversion, followed by the inventory-shaped
  `/24` scan, proxy DNS millisecond quantization, bounded eCAR delay, and scheduled-task ownership.

### Loop 25 outcome

- Commit `c507f995` binds the remote service payload, install, process, child, and termination to one
  canonical lifecycle, makes kernel System/PID 4 the remote drop writer, and prevents generic
  process creation from inventing duplicate PSEXESVC/HealthMonitorSvc file effects.
- The complete suite passed with 6,041 tests and 22 skips; Ruff check and format check passed. The
  strict rendered probe found one full PSEXESVC transaction, zero ordering or identity violations,
  one correct preexisting-binary exemption, and no boundary/observation exemptions.
- Automated evaluation remained 96.7054 over 73,361 records. Frozen review-data digest:
  `470234b68e2f662a0fc37189ab778a446d1b37c7ff5204688af036b3b8669527`.
- The fresh standalone scores were 68/66/57/86 (average 69.25). Deliberation reconciled them to a
  Synthetic consensus at 78.0. The corrected PsExec lifecycle became explicit realism
  counterevidence. Loop 26 will address the highest-ranked remaining signature: near-universal
  exact 35 ms Linux pipeline-stage spacing.

### Loop 26 outcome

- Commit `31d9f272` replaces both hardcoded pipeline offsets with one scoped, data-driven timing
  plan and makes operator parsing semantic: only a true unquoted single `|` shares concurrent
  pipeline identity; control operators are admitted as separate foreground cohorts.
- The full suite passed with 6,052 tests and 22 skips; Ruff check and format check passed. The
  rendered probe passed 38 adjacent pairs across eight hosts with 30 distinct gaps, 2.63% exact-35
  share, 7.89% modal share, complete pipeline overlap, and zero partial cohorts.
- Automated evaluation scored 96.2755 over 72,386 records. Frozen review-data digest:
  `8b0a71f9d4b21774ee647c846dd8c4f8c25164d24fe7b23c5638e736115a9f46`.
- The fresh panel was unanimously Synthetic at 68/68/64/73 (average 68.25), with no deliberation.
  The fixed spacing did not recur. Loop 27 will address the repeated direct-SCM PowerShell
  maintenance family, which three reviewers independently prioritized.

### Loop 27 outcome

- Commit `6e6e03f0` replaces account × host × hour trials with stable compatible owners and cadence,
  validates all symbolic parents, and materializes demand-scoped native scheduler ancestry without
  perturbing unrelated process allocation.
- The full suite passed with 6,059 tests and 22 skips after repairing the singleton exact-pack
  sibling regression; Ruff and config validation passed. The rendered probe found three complete
  scheduled PowerShell lifecycles, zero direct SCM parent edges, host-distinct task GUIDs, sparse
  placement, multi-hour jittered recurrence, and correct resident-agent ownership.
- Automated evaluation scored 97.6467 over 79,449 records. Frozen review-data digest:
  `2b76fe8d18af216d293d28bc2831fd54558e04db901ce37cd7755a09ca38c24e`.
- Standalone scores were 64/42/52/72 (average 57.5); deliberation reconciled to Synthetic at 65.75.
  The fixed scheduler family did not recur. Loop 28 will address the P0 SearchIndexer service-token
  and singleton-lifecycle contradiction.

### Loop 28 outcome

- Commit `387d3e62` classifies canonical System32 SearchIndexer as a protected boot-seeded singleton
  with SYSTEM/0x3e7 identity while retaining SearchProtocolHost/SearchFilterHost worker families.
- The full suite and Ruff passed. The strict probe found one stable SearchIndexer on each of nine
  Windows hosts, zero overlaps/restarts/identity violations, and 54 helper creates aligned across
  eCAR, Sysmon, and Security.
- Automated evaluation scored 97.3877 over 78,902 records. Frozen review-data digest:
  `46becc15b64ed72dac8eb7b93367fbdaf3b574829e73455ef36387017c216163`.
- Standalone scores were 69/48/66/67 (average 62.5); deliberation converged on Synthetic at 68.25.
  SearchIndexer did not recur. Loop 29 will repair the P0 Kerberos pre-authentication contract;
  Loop 30 is expected to take the failed-SSH privilege-process lifecycle gap.

### Loop 29 outcome

- Commit `af3edef1` adds validated Windows account-control flags and enforces status/policy-aware
  Kerberos pre-authentication. Commit `c8cb60cb` closes the generation-exposed sibling gap where
  foreground serialization could move sudo work beyond an SSH session close.
- The full suite, documentation-contract tests, Ruff, and generation passed. The strict probe parsed
  524 Kerberos records with zero illegal success type-0 records and all five `0x18` failures at
  pre-auth type 2.
- Automated evaluation scored 97.4828 over 77,522 records. Frozen review-data digest:
  `76f24ab8c2f471b0893de7214b8e1b503ab772127439cf9d2ae2d5da3c371910`.
- Standalone scores were 72/38/48/67 (average 56.25); deliberation revised to likely synthetic at
  63.0. Kerberos did not recur. Loop 30 will validate and repair the ranked P0 remote-WMI chronology;
  the failed-SSH lifecycle remains queued for the extended Loop 31–40 run.

### Loop 30 outcome

- The proposed remote-WMI P0 was rejected after exact identity joins proved the later MMC/GPMC
  DCOM session unrelated to the earlier DC-local WmiPrvSE account chain. No chronology was changed.
- Commit `065c608b` instead repairs the next validated family: `/24` scans expand to all 254 usable
  targets, `-sn` emits ICMP discovery, unmodeled targets remain silent, large ranges are stratified,
  and workload/process-lifetime contracts cover the full fan-out.
- The full suite, Ruff, generation, and strict probe passed. Both Zeek sensors saw all 254 discovery
  targets and 99.76% of 1,270 connect probes after observation loss, with zero unassigned responses.
- Automated evaluation scored 97.2016 over 86,077 records. Frozen digest:
  `fdff216b4a76486de3b38022d8f3be19bc5804b5f7f82e0103777a363e59b729`.
- Standalone scores were 52/48/43/78 (average 55.25); deliberation revised to 69.5. The original ten
  requested loops are complete. The user extended the run through Loop 40; Loop 31 starts with the
  scanner FLOW-before-process source-timing inversion.

## Loop 25 — Windows remote-service payload lifecycle

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 24 Detection and Host reviews independently
  found one complete in-window PsExec transaction on `DC-01` whose Security 4697 service install,
  Security/Sysmon/eCAR `PSEXESVC.exe` execution, child command, and termination all precede the only
  retained Sysmon/eCAR `FILE/CREATE` for `C:\Windows\PSEXESVC.exe` by almost 59 minutes. This is a
  repeated cross-source `hard_contradiction` and a `sibling_defect`: the bundle already constructs a
  pre-install payload event, but the payload, service, service process, and closure do not share one
  canonical action lifecycle for coherent source observation.
- **Owning layer:** `WindowsServiceInstallActionBundle` owns the remote-service payload prerequisite
  and service-install occurrence. The storyline remote-service adapter must propagate that same
  lifecycle identity into an explicitly authored or lazily materialized service process and its
  termination. Security, Sysmon, and eCAR remain projections of the shared lifecycle and must not
  repair the inversion independently.
- **Invariant:** for a modeled non-preexisting Windows service binary, the canonical payload create
  is the lifecycle start and precedes service installation and every service-process start. All
  phases share one stable action group, so a source's observation decision cannot retain the
  service/process lifecycle while independently dropping its modeled payload prerequisite. A later
  unrelated create/overwrite may exist only as a separate action and must not become the apparent
  prerequisite for the earlier execution.
- **Entry paths:** direct `ActivityGenerator.generate_service_installed`; typed storyline and red-
  herring `service_installed`; causal `sc.exe create` expansion; same-cluster explicit
  `PSEXESVC.exe`/`HealthMonitorSvc.exe` process events; and later service-backed command materialized
  through `_ensure_storyline_service_process_for_beacon` or
  `_storyline_service_context_for_process`.
- **Consumers:** canonical lifecycle/occurrence identity, source-observation grouping and source
  timing, Security 4697/4688/4689, Sysmon 1/5/11, eCAR SERVICE/PROCESS/FILE, process state, and
  storyline service-parent selection.
- **Sibling risks:** preserve preexisting System32/Program Files service binaries without fabricated
  drops; preserve HealthMonitorSvc and generic `sc.exe create` behavior; keep SMB/RPC control
  evidence and service start-type/account semantics; do not merge distinct later service installs
  on the same host; and keep process/termination identity stable when a service owns follow-on
  commands.
- **Verification and rendered hard probe:** focused tests must prove the payload and service share
  one lifecycle, same-cluster and later materialized service processes reuse it, and observation
  missingness is coherent for the payload/service/process family while a preexisting service path
  remains drop-free. The strict `[12:00,18:00)` rendered probe will normalize service image paths,
  join Security 4697, Security/Sysmon/eCAR process starts and stops, and Sysmon/eCAR file creates by
  host/path/action group, then fail any transaction whose visible nonpreexisting service image is
  installed or executed before its retained payload create; it will report every unmatched or
  inverted phase and separately count pre-window/censored and preexisting-binary exemptions.

### Implementation handoff

- `WindowsServiceInstallActionBundle` now marks a nonpreexisting service payload create as the
  lifecycle start and the service install as its dependent, using one stable group. A preexisting
  System32, SysWOW64, or Program Files image instead starts at the service-install occurrence and
  still produces no fabricated file drop. The target-side ADMIN$ payload write is attributed to
  kernel `System` PID 4 rather than `services.exe`; the service manager owns installation and launch,
  not the preceding remote file write.
- The activity adapter accepts an explicit lifecycle owner. Storyline and red-herring service
  installs derive that owner from the stable cluster/host/service identity, retain it in installed-
  service state, and pass it to same-cluster service processes, lazily materialized service
  processes, follow-on command children, and their state-owned terminations. This covers direct,
  causal, explicit, and delayed service-backed entry paths without changing emitters.
- The action lifecycle is now the observation-coherence key for Security, Sysmon, and eCAR. Within
  each source family, payload/service/process phases therefore share drop and delay sampling rather
  than allowing the prerequisite file event to disappear independently while the service execution
  remains visible.
- The central process-execution bundle excludes `PSEXESVC.exe` and `HealthMonitorSvc.exe` from
  generic `ensure_file_event` synthesis on every caller path. Their payload creation is owned only
  by the remote-service bundle, preventing a later detached process call from emitting a second,
  apparently post-execution drop.
- Verification: 7 exact payload/exclusion/preexisting/same-cluster/follow-on tests passed. The
  broader service, process, observation, lifecycle, Sysmon, Windows, and eCAR regression set passed
  364 tests. Repository-targeted Ruff check, Ruff format check, and `git diff --check` passed.

## Loop 26 — Linux pipeline-stage timing texture

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 25 Host review measured 41 of 42 qualifying
  Linux pipeline-stage pairs at exactly 35 ms, across eight hosts and unrelated commands; panel
  deliberation accepted this as its strongest dataset-wide synthetic fingerprint. This is a
  `sibling_defect` in the Linux shell-process family: Loop 24 made true pipeline peers concurrently
  admissible, but their canonical start offsets still use one fixed constant.
- **Owning abstraction and layer:** the Linux shell-command action family's pipeline timing planner
  owns the ordered start schedule for every stage in one shell-owned action. `ActivityGenerator`
  adapts both action-bundle bash-history telemetry and the legacy/application-catalog path into that
  shared plan. Source observation and eCAR render already-correct canonical stage timestamps and
  must not add renderer-local jitter to conceal a bad action schedule.
- **Invariant:** stage zero retains the admitted shell-action anchor. Each later stage starts after
  its predecessor by a deterministic, scoped, positive, sub-millisecond-capable sample from a
  bounded non-uniform distribution whose scale responds to host load. All stages retain the same
  pipeline concurrency group and parent shell, so valid pipeline overlap remains possible while
  stage order, process lifetime ordering, session/network deadlines, and source visibility remain
  causal.
- **Entry paths:** `LinuxShellCommandActionBundle` through
  `_maybe_emit_bash_process_telemetry`; baseline, storyline, world-planned, and noise callers of
  `generate_bash_command`; and Linux application/catalog process generation through
  `_linux_catalog_processes_from_shell_command`. Typed storyline process events that disable
  inferred process telemetry and single-process commands remain unchanged.
- **Consumers:** canonical `RunningProcess` start/lifecycle state, foreground reservations and
  finalizers, eCAR process create/terminate projection, process-owned network/file effects, bash
  history correlation, strict rendered pipeline probes, and focused activity/action-bundle tests.
- **Sibling risks and verification:** preserve deterministic regeneration, positive ordered gaps,
  same-group concurrency, parent-shell identity, bounded command/session deadlines, and single-stage
  anchors. Cover both direct shell-action and catalog adapters, prove repeatability and host/load
  sensitivity, and use a strict-window rendered probe that groups Linux eCAR children by host,
  shell PID, and concurrency group; it must report gap histograms/concentration and fail any return
  of a fleet-wide exact-millisecond mode rather than checking only the original 35 ms value.

### Implementation handoff

- `plan_linux_pipeline_stage_times` now owns the canonical stage schedule for one shell action.
  Stage zero keeps the admitted action anchor; later stages use deterministic scoped triangular
  samples at microsecond resolution from the data-driven 6–115 ms timing window. The distribution
  mode moves with the host's active-process count, while positive cumulative gaps preserve stage
  ordering and shared pipeline concurrency.
- Both inferred-process adapters now consume the same complete plan before creating any stage:
  `LinuxShellCommandActionBundle` bash-history telemetry and the legacy/application-catalog
  baseline path. Parent PID, logon/session ownership, concurrency group, foreground finalization,
  process effects, observation grouping, and renderer behavior are unchanged.
- Focused verification passed 3 planner/direct/catalog tests. The broader shell, process-lifetime,
  bash-noise, Linux-workstation, and world-model suite passed 546 tests; timing-profile and config-
  validator tests passed 101. `eforge validate-config` passed 93 files with zero issues, and
  repository-wide Ruff check/format plus `git diff --check` passed.
- **Rendered hard probe:** within `[2024-03-18T12:00:00Z, 2024-03-18T18:00:00Z)`, parse Linux eCAR
  process creates, identify direct children of a concrete `bash`/`sh`/`zsh`, and group stages by
  host, shell PID, and the shared concurrency/action cohort. For ordered stage pairs, report exact
  microsecond and rounded-millisecond gaps, host/command coverage, modal count/share, distinct gap
  count, bounds, and inversions. Fail on any non-positive gap, parent/group mismatch, or dominant
  fleet-wide exact-millisecond mode; separately confirm at least one concurrently alive pipeline so
  the fix has not serialized valid stages.

### Operator-aware sibling correction

- Independent review found that the existing shell-stage scanner split `||`, `&&`, and `;` through
  the same API used for true `|` pipelines, while `_contains_unquoted_shell_pipe` accepted either
  character of `||`. The corrected parser must retain source-native multi-command inference but
  expose the unquoted operator between stages. Only contiguous stages joined by a single unquoted
  `|` may share a pipeline concurrency cohort and the pipeline-stage timing plan; control/sequential
  operators start a separately admitted foreground cohort. Quoted and escaped pipes remain literal
  argv content and never create a second stage.
- The scanner now returns each stage with its exact preceding unquoted operator. Process inference
  preserves the prior flat compatibility view, while both generation adapters consume cohorts that
  join only single-`|` neighbors. `||`, `&&`, `;`, and `|&` start new cohorts with distinct
  concurrency IDs; quoted and escaped pipes remain within one argv. Direct shell actions admit the
  next cohort only after the prior cohort's actual bounded termination, and the catalog adapter
  reserves through each prior executable's maximum bounded lifetime before admitting its successor.
- Focused parser/planner/generation coverage passed 14 cases, including a mixed
  `pipeline && command` lifecycle whose control-stage create follows both pipeline terminations.
  The broader shell, process-lifetime, bash-noise, Linux-workstation, and world-model suite passed
  554 tests. Repository-wide Ruff check/format and `git diff --check` passed.

## Loop 27 — Scheduler-owned Windows maintenance automation

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 26 Threat Hunter, Detection Engineer, and
  Host/EDR reviews independently found 22–23 direct `services.exe` to `powershell.exe` process
  creations across eight Windows hosts. Three generic script identities recur densely across a DC,
  mail server, and workstations. This is a `family_level` baseline execution-mechanism and
  distribution-state defect, not an emitter formatting issue.
- **Owning abstraction and layer:** service-account delegation baseline planning owns which stable
  host runs a recurring automation job, its durable cadence, and its configured caller mechanism.
  The seeded Windows scheduler process tree owns the concrete scheduler parent identity. Canonical
  process generation owns parent/token/lifetime correlation; Security, Sysmon, and eCAR only render
  that shared truth.
- **Invariant:** recurring maintenance for one service account is assigned deterministically to a
  small stable set of eligible Windows owner hosts for the scenario, then fires on a stable,
  non-hourly interval with scoped jitter. Scheduler-configured PowerShell must be parented by the
  seeded Task Scheduler execution chain, while resident service/management-agent processes remain
  SCM-owned. An unknown configured parent symbol is an authoring error and must fail before any
  child process is fabricated under `services.exe`.
- **Entry paths:** all `service_account_delegation` caller profiles (backup, monitoring,
  deployment, reporting, and generic service tasks); one-shot PowerShell and OpsAgent jobs;
  resident management/backup agents; Windows scheduled/background process catalog entries that use
  the same symbolic seeded-parent namespace; and package/project configuration overlays.
- **Consumers:** canonical `RunningProcess` parent and token state, 4648 delegation evidence,
  Security 4688, Sysmon Event 1, eCAR process lifecycle, source-local observation grouping,
  process termination, config validation, and strict rendered process-tree/cadence probes.
- **Sibling risks and verification:** preserve role filtering, compatibility-group deployment
  selection, reuse of genuinely resident agents, fresh bounded one-shot lifecycles, target-server
  selection, and deterministic regeneration. Focused tests must prove stable owner placement,
  multi-hour cadence, scheduler parentage, and fail-fast unknown symbols. The rendered probe will
  group PowerShell maintenance by normalized command, host, parent image, and occurrence time;
  it must reject direct SCM parentage, fleet-wide placement, or an hourly Cartesian recurrence.

### Implementation handoff

- `service_account_delegation` now assigns each durable account to one or two deterministic Windows
  owner hosts, then schedules it on a scoped 150–330 minute interval with per-occurrence jitter.
  Event-local RNG owns caller and remote-target selection, so traversal order no longer turns the
  family into independent account-by-host-by-hour trials.
- The seeded Windows process tree now includes the Schedule service host and its `taskeng.exe`
  execution engine. Existing PowerShell profiles that already declared `parent_key: taskeng`
  therefore retain their intended scheduler ancestry instead of silently falling back to SCM.
  Resident backup, monitoring, deployment, and agent binaries remain under their configured
  service parents.
- Configured Windows parent symbols now resolve through one fail-fast boundary for scheduled tasks,
  recurring system services, and service-account delegation. `validate-config` rejects unknown
  parent symbols across both process catalogs, preventing project overlays from reintroducing a
  hidden `services.exe` fallback.
- Focused and broad relevant verification passed 325 tests with one skip across service-account
  lifecycle, Windows boot/process trees, baseline canonical generation, process stability, and
  configuration validation. `eforge validate-config` passed all 93 files. Repository-wide Ruff
  check/format and `git diff --check` passed.

### Independent-review sibling correction

- Account matching now treats the generic `account_terms: [svc]` profile strictly as fallback;
  account-specific backup, monitoring, deployment, and reporting profiles cannot be diluted by the
  generic pool. One deployment/account-stable caller choice is cached before owner placement, and
  the caller's `system_types` constrain the eligible stable owner-host set. Repeated occurrences
  therefore keep one execution mechanism rather than resampling parent grammar each time.
- Scheduler seeding now gives each host a deterministic distinct Task Scheduler GUID. Both
  `taskeng.exe` and the seeded `taskhostw.exe` are children of the dedicated Schedule service host,
  not direct SCM children or children of an unrelated generic netsvcs instance. Focused regression
  coverage proves specific-profile precedence, caller stability across regeneration, role-eligible
  placement, scheduler sibling ancestry, and cross-host GUID diversity.
- Full-suite reconciliation found that unconditionally adding scheduler processes perturbed the
  ordinary Windows process-allocation stream and caused a pre-existing exact-pack singleton
  regression to lose one of two cadence-bound application flows. The Schedule identity now aliases
  the modeled shared netsvcs service host, while `taskeng.exe` is seeded only when service-account
  automation or a configured taskeng-owned task requires it. This preserves scheduler ancestry and
  host-scoped task identity without changing unrelated scenarios' process allocation; the exact
  singleton pack regression again retains one process and both scheduled flows.

## Loop 28 — Windows Search service identity and singleton lifecycle

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 27 Host/EDR review found four visibly
  overlapping `SearchIndexer.exe /Embedding` roots on one workstation, all parented by
  `services.exe` but carrying an interactive user's medium-integrity token. Deliberation retained
  this as the panel's highest-confidence `P0` `hard_contradiction`. This is a `family_level`
  Windows service-role identity and lifecycle defect, not an emitter issue.
- **Owning abstraction and layer:** the boot-seeded Windows process/service plan owns the one
  durable WSearch indexer root and its SCM ancestry. Canonical process admission owns reuse of that
  seeded host singleton and service-token identity across regular user-noise, system-service,
  scheduled/background, and direct process entry paths. Security, Sysmon, and eCAR only project
  the shared canonical process.
- **Invariant:** each modeled Windows host has at most one active canonical
  `C:\\Windows\\System32\\SearchIndexer.exe` service root. Requests for that exact service image
  reuse the boot-seeded `search_indexer` PID, remain parented by the seeded `services.exe`, and
  preserve the `SYSTEM` token (`0x3e7`) and System integrity. Interactive-session identity remains
  available to Search UI/worker families, but must never be assigned to the indexer service root.
- **Entry paths:** legacy Windows `process_system` baseline selection; independent configured
  `system_services`; `generate_process()` callers using either a user or built-in account;
  `generate_system_process()` callers; spawn-rule parent repair; seeded SearchProtocolHost and
  SearchFilterHost siblings; and stale-process cleanup.
- **Consumers:** canonical `RunningProcess` identity and lifetime, Security 4688/4689, Sysmon
  Events 1/5, eCAR PROCESS CREATE/TERMINATE and dependent ownership, Search helper parentage, and
  strict rendered singleton/token probes.
- **Sibling risks and verification:** do not collapse `SearchProtocolHost.exe`,
  `SearchFilterHost.exe`, `SearchHost.exe`, or shell/UI processes into the service singleton; do
  not broaden basename-only reuse to an alternate path; and do not terminate the boot-seeded
  indexer when a transient caller requests cleanup. Focused tests must exercise both regular and
  system process APIs, repeated/out-of-order requests, exact-path rejection, canonical parent and
  token state, zero duplicate create/terminate events, and unchanged Search helper ancestry.

### Implementation handoff

- The canonical Windows singleton registries now classify the System32 Search indexer as both the
  seeded `search_indexer` role and a host-scoped service singleton. The interactive-user process
  classification no longer includes `SearchIndexer.exe`; exact canonical-path fallback creation is
  forced to `SYSTEM`/`0x3e7`/System integrity. Alternate-path basename collisions do not alias the
  WSearch singleton.
- Boot seeding publishes the indexer's immutable SYSTEM token LogonID into `RunningProcess` state.
  Both `generate_process()` and `generate_system_process()` therefore reuse one SCM-owned PID, even
  when the request arrives from user baseline noise or supplies an unrelated parent. The protected
  seeded-PID boundary makes transient cleanup idempotent instead of emitting a false termination.
  SearchProtocolHost/SearchFilterHost ancestry remains a separate child family.
- Focused Windows process/service/pool verification passed 168 tests. Broader baseline canonical,
  process lifetime/termination, eCAR projection, and Windows record-ID verification passed 296
  tests with one skip. Ruff check/format and `git diff --check` passed.
- **Rendered hard-probe design:** within strict `[12:00,18:00)`, parse Sysmon Event 1/5 and eCAR
  PROCESS CREATE/TERMINATE for the exact System32 `SearchIndexer.exe` image. Join by host plus
  ProcessGuid/object ID, construct visible live intervals, and fail on overlapping roots, any
  non-SYSTEM principal, LogonID other than `0x3e7`, non-System integrity, or a parent other than
  `services.exe`. Separately inventory SearchProtocolHost/SearchFilterHost rows to prove they remain
  distinct children rather than being incorrectly reused as the indexer. Report zero in-window
  indexer creates as a valid pre-window singleton, not a completeness defect.

## Loop 29 — Kerberos pre-authentication status and account policy

### Family contract (before implementation)

- **Accepted finding and classification:** the Loop 28 Detection review found a visible Security
  4771 with `Status=0x18` (`KDC_ERR_PREAUTH_FAILED`) but `PreAuthType=0`, plus six successful 4768
  TGT requests with `PreAuthType=0` for ordinary machine accounts. Deliberation retained this as
  the clearest `P0` `hard_contradiction` and a repeated
  `environment_or_collection_plausibility` defect. This is a `family_level` canonical Kerberos
  authentication/account-state defect, not a Windows XML emitter defect.
- **Owning abstraction and layer:** the shared Kerberos realism selector owns status-compatible
  pre-authentication fields, while the canonical identity directory owns explicit Windows account
  control state. The TGT and pre-auth-failure action bundles must combine those truths before
  constructing `KerberosContext`; renderers only project the resulting event.
- **Invariant:** a failed 4771 with `Status=0x18` identifies a supplied failed mechanism and may not
  use `PreAuthType=0`; under the supported password-failure family it uses encrypted timestamp
  type 2. A successful 4768 may use `PreAuthType=0` only when its resolved domain account explicitly
  owns the `DONT_REQUIRE_PREAUTH` account-control flag. Missing identity state, ordinary users,
  machine accounts, and service accounts require pre-authentication by default.
- **Entry paths:** direct and cached-gated `generate_kerberos_tgt()` calls; member-host logon causal
  expansion; visible newly-created account exchanges; baseline machine-account cycles; automatic
  Kerberos/88 connection audit companions; active-user and stale-account 4771 generation; and
  failed-logon validation paths that add DC-side 4771 evidence.
- **Consumers:** canonical `KerberosContext`, Security 4768/4771 projection, TGT cache state,
  Kerberos connection/audit correlation, detections for bad-password failures and AS-REP-roastable
  principals, configuration validation, and rendered dataset probes.
- **Sibling risks and verification:** preserve PKINIT type 15 plus certificate fields, ticket and
  encryption distributions, source-port/transport reuse, DC timing, and non-`0x18` failure
  profiles. Record-level tests must prove status/type compatibility and positive/negative explicit
  account-policy gating for users and machine accounts. The strict rendered probe will parse every
  4768/4771 in `[12:00,18:00)`, reject `4771 Status=0x18 + PreAuthType=0`, and reject successful
  4768 type 0 unless the reviewed account is present in an independently exported explicit
  `DONT_REQUIRE_PREAUTH` allowlist; it will report user and machine-account populations separately.

### Implementation handoff

- Scenario identity state now supports a validated `windows_account_control` map for modeled user,
  machine, and service principals. `IdentityDirectory` attaches those flags to the resolved frozen
  Windows account, normalizes SAM/UPN principal forms for lookup, and rejects flags for unknown
  accounts. The default is an empty flag set for every account, including all ordinary machine
  accounts in the iteration scenario.
- The shared 4768 picker excludes type-0 profiles unless the canonical identity directory confirms
  `DONT_REQUIRE_PREAUTH`; PKINIT and encrypted-timestamp profiles retain their prior weighting and
  certificate semantics. The 4771 picker now receives the actual status and filters type 0 for
  `0x18`, falling back safely to encrypted timestamp type 2 even if an overlay supplies only an
  incompatible no-preauth profile.
- Record and dataset-level tests cover `0x18` failures, ordinary and explicitly exempt users,
  ordinary and explicitly exempt machine accounts, UPN normalization, and unknown-account policy
  rejection. Broad Kerberos, identity, causal, baseline, source-projection, and config verification
  passed 947 tests with one skip; `eforge validate-config` passed all 93 files. Repository-wide
  Ruff check/format and `git diff --check` passed.

### Generation-gate sibling correction

- The first authoritative regeneration exposed a pre-existing Linux admission gap rather than a
  Kerberos RNG-stream change: ambient sudo selected a still-live SSH session, then shared
  foreground-shell serialization shifted the sudo process beyond that session's transport close.
  The source-timing closure-tail invariant correctly rejected the resulting dependent.
- Sudo admission now requires the owning interactive/SSH session to remain active through the
  planned command close with source-observation margin, and rechecks that boundary after shell
  serialization. If a busy shell pushes an ambient invocation past its owning session, the bundle
  emits no process or PAM evidence instead of attaching activity to an ended session; the strict
  closure-tail bound is unchanged. The focused busy-shell/SSH-close regression passes, and the
  broader process, sudo, source-timing, dispatcher, eCAR, activity, and baseline suite passes 855
  tests with one skip. Repository-wide Ruff check/format and `git diff --check` pass.

## Loop 30 — Remote-WMI chronology finding validation

### Finding disposition (before implementation)

- **Classification:** `false_positive_or_unproven`; no implementation was made. The Loop 29
  Threat Hunter report treated WS-AJOHNSON-01 MMC PID 7008 and its later DCOM traffic as the
  apparent initiator of DC-01's earlier account-creation command. A strict action-identity join
  disproves that ownership assumption.
- DC-01's `16:15:28Z` command is PROCESS object
  `1daa6cd0-05b8-4e03-bdea-2969676805a8`, parented by the durable target-local WmiPrvSE object
  `4453d681-312b-4457-bfc1-92dd8d519cde` as NETWORK SERVICE. The dependent `net.exe` process and
  subsequent account effects remain within that target-local process chain.
- WS-AJOHNSON-01's `16:15:52Z` MMC is PROCESS object
  `e262703a-95e9-4580-b302-92681e2d4de0`, command line
  `mmc.exe gpmc.msc`, user `aisha.johnson`. Its port-135 FLOW at `16:15:56Z` carries that MMC
  object as `actorID`; it shares no process, session, source port, lifecycle, or action identity
  with the DC command. The same workstation emits independent `dsa.msc`, `gpmc.msc`,
  `dnsmgmt.msc`, and `dhcpmgmt.msc` MMC/DCOM transactions throughout the window, confirming that
  this row belongs to the recurring administrative-console baseline family rather than the
  account-creation chain.
- The lack of a rendered source-side owner for the target-local WmiPrvSE command may be evaluated
  separately as a coverage or authoring-contract question, but unrelated later MMC activity is
  not evidence of impossible chronology. Moving either action to satisfy that false join would
  corrupt two valid independent lifecycles and risk regressions in ordinary RPC/authentication,
  target process ordering, and the already-correct PsExec sibling.
- **Rendered-probe design:** for every alleged remote-administration inversion, require a durable
  join before comparing time: source process UUID, exact transport tuple/source port, target
  network logon identity, and shared lifecycle/action group where available. Report temporally
  nearby but unjoined MMC/DCOM activity as an independent candidate, never as the initiator. This
  sample fails the ownership join and therefore contributes zero chronology violations.

## Loop 30 — CIDR-scoped nmap discovery and probe planning

### Family contract (before implementation)

- **Accepted finding and classification:** after rejecting the unjoined WMI chronology claim, the
  next validated Loop 29 finding is a `new_family` scanner `distribution_texture` and
  `contract_gap`: `nmap -sn 10.10.2.0/24` emits no discovery evidence, while the following
  five-port connect scan expands to exactly the six modeled hosts and no silent address-space
  targets.
- **Owning abstraction and layer:** `NmapCommandProbeActionBundle` and its canonical address-space
  planner own interpretation of explicit IP/CIDR targets, scan mode, bounded target sampling, and
  which targets are modeled responders versus unallocated/silent probes. The canonical network
  connection bundle continues to own tuple allocation, sensor visibility, packet accounting,
  endpoint process attribution, and source-native projection.
- **Invariant:** an explicit CIDR must never collapse to only the scenario host inventory. Small
  CIDRs at or below the configured usable-host threshold expand to every usable address (`/24`
  means 254 targets), while larger CIDRs use a deterministic stratified cap that preserves broad
  address-space coverage without materializing the range. TCP probes against unmodeled addresses
  are silent S0 attempts; `-sn`/legacy `-sP` emits process-owned ICMP discovery attempts, with
  modeled targets answering and unmodeled targets remaining silent. Explicit single-IP commands
  remain exact and no target may equal the scanner source.
- **Entry paths:** process-command effects from storyline and baseline Linux nmap processes;
  explicit IPv4/IPv6 literals; CIDR arguments with or without modeled members; TCP connect/default
  port probes; and ping-only discovery commands. Typed `port_scan`, scheduled scanner overlap, web
  scans, and external perimeter noise remain sibling bundles outside this command-specific plan.
- **Consumers:** canonical network connections and process holds; Zeek/eCAR/firewall visibility;
  packet/byte accounting; source timing; rendered scan-shape probes; and the deterministic
  assessment corpus.
- **Sibling risks and verification:** cap large-CIDR targets and authored ports so broad ranges
  cannot explode output, while the workload estimator accounts for deliberate full expansion of
  bounded small CIDRs. Preserve every authored port within the configured cap, target
  service/open-port inference for modeled hosts, stable RNG scoping, concurrent rather than serial
  probe timing, application-side-effect suppression, and process lifetime through the latest
  canonical transport close. Focused tests must prove `/24` plans contain exactly 254 usable
  targets and 1,270 attempts for five ports, `-sn` emits 254 ICMP attempts with mixed
  response/silence, explicit IPs do not gain invented neighbors, huge CIDRs stay stratified and
  bounded, and canonical output retains the nmap PID with coherent ICMP/TCP accounting.

### Implementation handoff

- `NmapCommandProbePlanner` now parses the process command once into a canonical discovery/port
  mode and deterministic address-space plan. CIDRs with at most 256 usable hosts expand fully, so
  the assessment `/24` yields all 254 usable addresses. Larger IPv4/IPv6 ranges use deterministic
  arithmetic stratification without materializing their host iterators; explicit IP literals stay
  exact.
- The bounds moved to validated `network_params.yaml` configuration: full expansion through 256
  usable hosts, an overall 256-target ceiling, stratified large-range caps of 20 TCP or 24
  discovery targets with 12 unmodeled slots, and 12 authored ports. Project overlays may adjust
  individual fields while inheriting the remaining defaults, and `eforge validate-config`
  rejects inverted timing or impossible target bounds.
- Connect scans still route every target/port pair through the canonical network-connection
  action. Modeled hosts retain inventory-aware `SF`/`REJ`/`S0` behavior; unmodeled addresses are
  request-only `S0` probes with zero responder bytes. `-sn` and legacy `-sP` now emit bounded
  process-owned ICMP attempts: modeled addresses have echo replies, while unmodeled addresses have
  one request and no response. Probe starts are densely distributed inside configurable concurrent
  windows (6-12 seconds for TCP and 2-5 seconds for discovery), rather than serially extending the
  scan by one delay per attempt. Network visibility, tuple identity, endpoint PID, observation,
  and packet accounting remain owned downstream by the network bundle.
- The workload estimator recognizes nmap process commands and charges their planned probe
  cardinality before generation; the assessment `/24` five-port command therefore contributes
  exactly 1,270 explicit occurrences. The network transaction boundary refreshes process holds
  after final duration/timing reconciliation, keeping the initiating process alive through the
  maximum canonical source-visible close without comparing unrelated sensor clock domains.
- Focused verification passed all six nmap tests, including exact 254-target `/24` TCP and
  discovery expansion, exact 1,270 five-port attempts, canonical ICMP packet accounting,
  explicit-IP exactness, deterministic stratified broad-CIDR bounds, concurrent timing, lifecycle
  bracketing, and action-bundle delegation/identity. Workload and configuration tests passed 13
  additional checks. The broader activity, network visibility, dispatcher, Zeek/eCAR projection,
  process-lifecycle, source-timing, workload, and configuration suite passed 1,098 tests. Config
  validation passed all 93 files; repository-wide Ruff check/format and `git diff --check` passed.
- **Rendered hard-probe design:** within `[12:00,18:00)`, identify the `nmap -sn` and subsequent
  connect-scan PIDs on WEB-EXT-01, then join Zeek/eCAR connections by source host and initiating
  PID. Require discovery to contain only ICMP, at least one modeled reply and at least one silent
  unmodeled request, with coherent 1/1 versus 1/0 packet accounting, and require exactly 254
  discovery attempts for the `/24`. Require the TCP phase to retain every authored port across
  all 254 usable targets and render exactly 1,270 connections, with every unmodeled attempt `S0`
  and zero response bytes. Both phases must remain inside their configured concurrent windows,
  bracket their latest canonical transport close with the nmap process lifetime, and have zero
  HTTP/TLS/file side effects.
