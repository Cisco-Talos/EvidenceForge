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
