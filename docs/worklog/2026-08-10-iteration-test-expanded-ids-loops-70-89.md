# iteration-test-expanded-ids assessment loops 70-89

## Scope

Twenty fresh end-to-end assessment loops on `iteration-test-expanded-ids`, continuing from loop 69.
Each loop regenerates the corpus, runs the deterministic evaluator, commissions four blind expert
reviews, verifies the preceding fix, and selects at most one family-level implementation target.
The scenario remains unchanged.

## Loop 70

- Generated 73,964 records. Automated score: 91.1453; all hard gates passed, but the dynamic
  guardrail triggered because Timing fell to 64.0714.
- The fresh loop-69 endpoint-FLOW probe failed: among 4,709 unique opposite-endpoint tuple pairs,
  846 (17.97%) remained exact-millisecond matches and 91 pairs were separated by more than one
  hour. The maximum separation was 2,066,864,775 ms; 91 inbound FLOW rows landed before the
  six-hour collection window.
- Root cause: the very-short-interval separation path treated a long-lived process start as the
  available observation interval's lower bound. It then sampled across the daemon's multi-week
  lifetime instead of the canonical transport interval.

### Family contract: endpoint FLOW interval containment

- **Owning abstraction:** `SourceTimingPlanner`, specifically paired eCAR endpoint observation
  timing inside the canonical network-connection interval.
- **Invariant:** every source-local endpoint FLOW observation remains between the finalized
  canonical transport start and close, regardless of how old its attributed process is; paired
  endpoints may differ within that interval.
- **Entry paths:** direct canonical connections, nested explicit-proxy child transports, SSH/RDP,
  baseline and storyline connections, and causal network prerequisites.
- **Consumers:** eCAR FLOW rendering, endpoint/network lifecycle probes, authentication timing,
  the automated timing evaluator, and blind host/network correlation reviews.
- **Layer rationale:** this is shared source-observation truth. Emitters only render finalized
  timestamps, while process lifetime is an identity constraint rather than permission to predate
  the transport.
- **Sibling risk:** the fix covers old source and destination daemon identities across nested and
  direct paths. Independent host-clock texture for extremely short sub-millisecond transports may
  still collapse after millisecond serialization and remains separately measurable.

### Implementation

- Made the canonical transport start the unconditional lower bound for paired endpoint timing,
  then intersected it with any later process-visibility bound.
- Extended the nested proxy timing regression with 30-day-old source and destination processes,
  proving both endpoint observations remain inside the 200 ms transport interval and differ.
- Focused source-timing suite: 42 passed; focused Ruff checks pass.

## Loop 71

- Generated 76,278 records. Automated score: 97.5882; all hard gates passed and Timing returned
  to 96.3637.
- The loop-70 containment probe passed: zero unique endpoint pairs were separated by more than one
  hour, with a 3,572 ms maximum. Same-millisecond endpoint serialization remains common (1,850 of
  5,866 unique pairs), concentrated in short DNS and proxy-child transports.
- Initial blind synthetic-confidence scores: 47/46/24/89 (mean 51.5). Verdict disagreement and a
  65-point spread triggered deliberation; final scores were 53/52/39/78 (mean 55.5).
- The host reviewer found 33/37 complete SSH sessions whose PAM close PID differed from the visible
  session-opening `sshd` PID. Deliberation conservatively classified this as unproven from reports
  alone and preferred one-shot process lifetime planning.
- Direct state/code verification established the generator defect: the baseline logoff planner
  preempted action-bundle deferred closure, terminated the canonical receiver `sshd`, cleared
  `session.transport_pid`, then allocated a fresh transient PID for the generic PAM close. The SSH
  action bundle never got to execute its owned close.

### Family contract: single-owner SSH close lifecycle

- **Owning abstraction:** SSH action bundle plus canonical active-session ownership state.
- **Invariant:** when an SSH bundle declares that it emits the session close, no baseline or
  compatibility cleanup path may preempt it; PAM open/close, receiver process termination, eCAR
  logout, and logind removal retain the bundle's session/PID identity.
- **Entry paths:** baseline WorldPlanner SSH sessions, storyline SSH, SCP-to-Linux receiver
  sessions, and compatibility Linux remote logons.
- **Consumers:** syslog PAM/sshd/logind, eCAR PROCESS and USER_SESSION, session state, baseline
  logoff planning, and lifecycle probes.
- **Layer rationale:** close ownership is action/session state, not a renderer concern. The generic
  baseline planner may still close compatibility sessions for which no action owns a close.
- **Sibling risk:** source-native OpenSSH monitor/child role detail is still simplified; this fix
  addresses the proven generator-created fresh close PID, not all possible process-role texture.

### Implementation

- Added `closure_owned_by_bundle` to canonical active-session state and set it when the SSH request
  owns close emission.
- Made baseline planning and execution skip bundle-owned closures while retaining generic cleanup
  for compatibility SSH sessions without an action owner.
- Added owner/preemption and non-owner sibling tests. Focused lifecycle/state/world suite: 153
  passed; focused Ruff checks pass.

## Loop 72

- The first two generation attempts exposed sibling gaps in the loop-71 change and were not
  counted as completed loops. Deferred future closures were initially discarded at intermediate
  cutoffs, and explicit storyline logoffs were initially preempted by action closure. The shared
  contract now retains future pending closures, finalizes due bundle closures before later user or
  storyline activity, leaves explicit intent as the owner of authoritative logoffs, and snapshots
  the receiver PID before generic teardown.
- Successful generation produced 83,293 records. Automated score: 97.8154; all hard gates passed.
- The loop-71 SSH probe passed: 44/44 fully visible PAM sessions closed under their opening
  `sshd` PID, with zero mismatches. Four close-only bounded-window records were excluded.
- Initial blind scores: 58/47/67/86 (mean 64.5). Verdict disagreement and a 39-point spread
  triggered deliberation; final scores were 70/64/72/86 (mean 73.0), unanimously Synthetic.
- Selected target: canonical lifecycle completion for one-shot `cmd.exe /c` wrappers. The panel
  verified a 54-minute parent-after-child gap on FILE-SRV-01 and 49-70 second sibling gaps on the
  DC, consistently projected across Security, Sysmon, and eCAR.

### Family contract: one-shot Windows wrapper completion

- **Owning abstraction:** canonical process termination lifecycle in `ActivityGenerator`.
- **Invariant:** after the final visible foreground child invoked by a noninteractive `cmd.exe /c`
  wrapper terminates, the wrapper terminates within a short bounded cleanup interval; session
  teardown must not become its default lifetime.
- **Entry paths:** service/network-logon admin utilities, storyline remote administration,
  baseline one-shot shells, scheduled tasks, and direct process generation.
- **Consumers:** StateManager running-process state, Security 4689, Sysmon Event 5, eCAR PROCESS
  termination, process-lifetime probes, and session cleanup.
- **Layer rationale:** the parent/child completion relationship is canonical lifecycle truth shared
  by all endpoint sources, not an emitter timestamp correction.
- **Sibling risk:** multi-command pipelines whose shell payload cannot yet be matched to one final
  child remain outside the exact-signature completion path.

### Implementation

- After a child termination, detect a live one-shot Windows shell whose payload invokes that child.
  If no sibling child remains, terminate the wrapper 80-999 ms later through the same canonical
  action bundle.
- Added a `cmd.exe /c net view` regression proving child-before-parent order, sub-second cleanup,
  and removal from running state. Focused wrapper/SSH suites: 154 passed; Ruff passes.

## Loop 73

- Generated 83,302 records. Automated score: 97.8655; all hard gates passed.
- The loop-72 wrapper probe passed: seven complete `cmd.exe /c` wrapper lifecycles all closed
  within 0.918 seconds of their final child, with no gap over two seconds.
- Initial blind scores: 53/48/58/73 (mean 58.0). Verdict disagreement triggered deliberation;
  final scores were 61/57/64/76 (mean 64.5).
- Selected target: a source-visible SSH teardown inversion. APP-INT-01 eCAR terminated `sshd` PID
  1096899 1.029 seconds before syslog attributed the PAM close to that PID. Five of 47 matched
  teardowns also placed eCAR logout after owner-`sshd` termination.

### Family contract: source-visible SSH teardown causality

- **Owning abstraction:** SSH action-bundle lifecycle timing before source observation/rendering.
- **Invariant:** the receiver `sshd` remains source-visibly alive through its PAM close; its eCAR
  termination may follow, but can never render before, the same PID's source-native close record.
- **Entry paths:** baseline WorldPlanner SSH, storyline SSH, SCP receiver sessions, and public SSH
  adapter sessions whose close is bundle-owned.
- **Consumers:** syslog PAM close, eCAR PROCESS/TERMINATE and USER_SESSION/LOGOUT, session state,
  and host-forensics lifecycle pivots.
- **Layer rationale:** this is action lifecycle truth plus cross-source delay budgeting, not an
  emitter-local timestamp rewrite.
- **Sibling risk:** compatibility and explicit-authoritative generic logoff paths use their own
  close planner; loop 74's corpus probe must check all complete SSH sessions, not only bundle paths.

### Implementation

- Extended receiver `sshd` lifetime to a deterministic 3.2-5.2 second tail after the canonical PAM
  close, covering the configured syslog source-native and collection delay relative to eCAR.
- Tightened the bundle regression to require the receiver termination 3.2-5.2 seconds after close.
  Focused SSH/logoff suites: 113 passed.

## Loop 74

- The first pre-review corpus caught the unchanged authoritative-storyline SSH sibling. The
  generic logoff path now defers its transport `sshd` termination until after its planned PAM
  close, and authoritative cleanup permits exactly that deferred process. The corpus was
  regenerated before review.
- Final generation produced 83,302 records. Automated score: 97.8655; all hard gates passed.
- The loop-73 probe passed on the final corpus: 47 complete PAM/termination PID pairs, zero
  inversions, and a 3.883-7.404 second post-PAM termination range.
- Initial blind scores: 62/27/66/68 (mean 55.75). Verdict disagreement and a 41-point spread
  triggered deliberation; final scores were 66/45/69/72 (mean 63.0).
- Selected target: 141 nearly identical root/PID-1 `smbclient` share-listing processes spread
  across six unrelated Linux server roles.

### Family contract: role-owned Linux SMB connection attribution

- **Owning abstraction:** canonical high-confidence connection owner selection plus data-driven
  network activity profiles.
- **Invariant:** Linux server SMB flows receive a role-compatible deployed service identity when
  one is configured; unsupported roles stay unattributed rather than receiving invented generic
  root `smbclient` processes.
- **Entry paths:** baseline lateral movement, scanner overlap, storyline connections, and any
  canonical server-originated TCP/445 flow without an explicit process owner.
- **Consumers:** eCAR PROCESS/FLOW, process state and lifetime planning, cross-host pivots, and
  blind host/threat workload analysis.
- **Layer rationale:** process ownership is canonical endpoint truth. The process vocabulary is
  enumerable configuration, not emitter-specific rendering.
- **Sibling risk:** the baseline connection planner may still send SMB from implausible roles;
  unattributed FLOWs avoid false process claims but do not by themselves correct traffic policy.

### Implementation

- Added overlayable role profiles for application document sync, database backup, mail attachment
  archive, and web content publication.
- Replaced the universal Linux `smbclient` owner with the matching configured service or no owner.
  Focused SMB connection-owner tests pass.

## Loop 75

- Generated 76,969 records. Automated score: 98.0816; all hard gates passed.
- The loop-74 probe passed: zero generic `smbclient` owners across 131 reviewed Linux server SMB
  FLOWs, six reusable role-owned actors, four service families, and 18 deliberately unattributed
  proxy-role flows.
- Initial blind scores: 64/39/68/67 (mean 59.5). Verdict disagreement triggered deliberation;
  final scores were 69/57/72/72 (mean 67.5), unanimously Synthetic.
- Selected target: all 715 non-resumed TLS 1.3 rows correctly omitted passive certificate/x509
  artifacts but retained `X` (certificate) in `ssl_history`, contradicting the same canonical
  visibility model. Zeek's official SSL history reference confirms `X` denotes a certificate.

### Family contract: passive TLS 1.3 handshake visibility

- **Owning abstraction:** canonical TLS version/resumption/history sampler.
- **Invariant:** a passive TLS 1.3 observation may expose ClientHello and ServerHello plus encrypted
  outer records, but must not claim parsed post-ServerHello handshake messages whose artifacts are
  intentionally unavailable; TLS 1.2 full handshakes continue to expose certificates and x509.
- **Entry paths:** direct TLS, explicit-proxy origin TLS, inbound public TLS, SMTP STARTTLS, and
  resumed/non-resumed shared TLS context generation.
- **Consumers:** Zeek `ssl.json`, files/x509 fan-out, resumption probes, automated field agreement,
  and blind network-forensics review.
- **Layer rationale:** version, passive visibility, history, and certificate fan-out are shared
  canonical protocol truth; the Zeek emitter only serializes them.
- **Sibling risk:** decrypted TLS 1.3 observation is not modeled and remains outside this passive
  collection contract.

### Implementation

- Replaced TLS 1.3 histories containing `O/X/Y/F/T` with `CSD`, `CSDD`, and `CSDDD` passive
  patterns; resumed TLS 1.3 uses `CSD`.
- Added assertions that TLS 1.3 history contains no certificate marker while TLS 1.2/resumption
  contracts remain covered. Focused TLS/Zeek suite: 76 passed; Ruff passes.

## Loop 76

- Generated 76,969 records. Automated score: 98.0816; all hard gates passed.
- The loop-75 probe passed: 1,104 TLS 1.3 rows contained zero hidden post-ServerHello markers, and
  the TLS 1.2 certificate-bearing control remained present.
- Initial blind scores: 88/17/28/64 (mean 49.25). Verdict disagreement and a 71-point spread
  triggered deliberation; final scores were 91/69/63/76 (mean 74.75), unanimously Synthetic.
- Selected target: target-bearing Linux SMB service processes were reused across unrelated peers,
  making endpoint FLOW destinations contradict the repository named in the process command line.

### Family contract: destination-bound service process ownership

- **Owning abstraction:** canonical high-confidence connection-owner identity and matching.
- **Invariant:** when a process command line declares a literal SMB peer, that process may own only
  flows to that peer; a different peer requires a distinct process identity unless an explicit
  alias, referral, proxy, NAT, or failover relationship is modeled.
- **Entry paths:** baseline lateral movement, scanners, storyline connections, and every canonical
  Linux TCP/445 connection receiving role-owned service attribution.
- **Consumers:** eCAR PROCESS/FLOW, process state/lifetimes, threat-hunting pivots, and future
  process-to-network semantic evaluation.
- **Layer rationale:** the peer and process identity are shared endpoint truth, not emitter detail.
- **Sibling risk:** other custom executables with literal HTTP, database, or remote-shell targets
  may require the same executable-independent semantic classification.

### Implementation

- Scoped configured Linux SMB service keys to the resolved destination and made literal `smb://`
  commands require exact-command matching for every executable.
- Added a regression proving two repository peers cannot reuse one target-bearing backup process.
  Focused owner tests: 3 passed; Ruff passes.

## Loop 77

- Fresh generation first failed because a root SCP process was scheduled after its SSH session
  transport close. Linux bash availability was keyed by host/user instead of the owning session;
  session-scoping fixed the generation blocker.
- Regeneration produced 80,431 records. Automated score: 97.8039; all hard gates passed.
- The loop-76 probe passed: 84 target-bearing SMB FLOWs, 17 owning processes, and zero identities
  spanning multiple destination IPs.
- Initial blind scores: 52/79/27/46 (mean 51.0). Deliberation final: 72/82/58/57 (mean 67.25).
- Selected target: 876 DMZ-to-inside ASA builds were labeled `outbound` because the emitter treated
  only a literal `outside` source as inbound.

### Family contract: ASA interface-security direction

- **Owning abstraction:** source-native ASA network projection and sensor topology.
- **Invariant:** lower-to-higher interface initiation is `inbound`; higher-to-lower is `outbound`;
  every protocol family uses the same classification.
- **Entry paths:** canonical TCP, UDP, and ICMP permits with or without source/destination NAT.
- **Consumers:** ASA 302013/302015/302020 build semantics, ICMP address orientation, detection
  rules, and blind network/detection review.
- **Layer rationale:** direction is a source-native ASA interpretation of canonical topology.
- **Sibling risk:** custom nameifs require explicit security levels; same-level hairpin traffic
  retains compatibility behavior.

### Implementation

- Added optional sensor `interface_security_levels`, conventional 0/50/100 defaults, and one ASA
  classifier shared by TCP, UDP, and ICMP.
- Focused ASA/shell/SMB suite: 21 passed; Ruff passes.

## Loop 78

- Fresh generation produced 80,431 records. Automated score: 97.8039; all hard gates passed.
- The loop-77 probe passed across every unequal-security ASA interface pair.
- Initial blind scores: 74/17/57/46 (mean 48.5). Deliberation final: 76/42/64/66 (mean 62.0).
- Selected target: six of nine Type 10 sessions rendered eCAR child processes 530-1,304 ms
  before the eCAR USER_SESSION LOGIN carrying the same LogonID.

### Family contract: source-visible interactive session readiness

- **Owning abstraction:** canonical session state plus admitted source-native lifecycle timing.
- **Invariant:** an eCAR process carrying an interactive session LogonID must render strictly after
  that session's admitted eCAR LOGIN row.
- **Entry paths:** local interactive, RDP, cached interactive, preallocated RDP, and direct Type 10
  compatibility generation.
- **Consumers:** eCAR USER_SESSION and PROCESS, process-source timing, session teardown, and
  host/threat-hunting pivots.
- **Layer rationale:** this is shared source-visible session ownership, not an emitter rewrite.
- **Sibling risk:** other session-owned dependent event families must consume the same readiness
  floor when they can render immediately after login.

### Implementation

- Exposed admitted source-native session-start times from `SourceTimingPlanner` and published the
  eCAR login as the session readiness floor before Windows shell materialization.
- Stopped the RDP bundle from overwriting that finalized floor with canonical logon time.
- Focused RDP/source-timing regressions and Ruff pass.

## Loop 79

- The first fresh corpus failed the prior-family probe because dispatcher identity planning
  replaced the generator's process-source floor. That corpus was rejected before blind review.
- Moved the invariant into the dispatcher-owned source planner; regenerated 80,431 records with
  all nine Type 10 sessions placing their earliest eCAR child 67-677 ms after LOGIN.
- Automated score: 97.8039; all hard gates passed.
- Initial blind scores: 34/70/74/74 (mean 63.0). Deliberation final: 63/75/82/79
  (mean 74.75), unanimously Synthetic.
- Selected target: an unmodeled public SMTP peer was copied into a serial-linked OCSP request to
  an untranslated `.local`/RFC1918 responder and assigned a Firefox User-Agent.

### Family contract: certificate-validator ownership and collection boundary

- **Owning abstraction:** canonical OCSP action bundle derived from the owning TLS client.
- **Invariant:** only a modeled TLS client can originate enterprise-visible OCSP traffic; an
  external peer's validation occurs outside the enterprise collection boundary.
- **Entry paths:** inbound SMTP STARTTLS, public web TLS, direct internal/external TLS, and proxy
  origin TLS certificate fan-out.
- **Consumers:** DNS, HTTP, Zeek conn/files/OCSP, ASA, proxy, certificate-serial pivots, and blind
  network-forensics review.
- **Layer rationale:** validator identity and route are canonical action ownership, not an emitter
  rendering choice.
- **Sibling risk:** modeled internal clients must retain OCSP evidence and source-native User-Agent
  selection; server-side OCSP stapling is a distinct future action rather than client validation.

### Implementation

- The OCSP action bundle now suppresses child generation when the TLS originator is not a modeled
  system, preventing external validation from being imported onto public peer addresses.
- Modeled clients preserve the complete standards-valid OCSP transaction contract.
- Focused cryptographic/OCSP suite: 10 passed; Ruff passes.

## Loop 80

- Fresh generation produced 77,806 records. Automated score: 97.9996; all hard gates passed.
- The loop-79 probe passed: 49 OCSP transactions, all from modeled internal clients; zero
  public/unmodeled validator origins.
- Initial blind scores: 74/70/44/72 (mean 65.0). Deliberation final: 80/82/66/81
  (mean 77.25), unanimously Synthetic.
- Selected target: all 321 built-in Type 5 logons used random LUIDs instead of the Windows
  well-known SYSTEM/LOCAL SERVICE/NETWORK SERVICE authentication IDs.

### Family contract: Windows built-in service-token identity

- **Owning abstraction:** canonical service-logon action and authentication identity.
- **Invariant:** SYSTEM, LOCAL SERVICE, and NETWORK SERVICE use `0x3e7`, `0x3e5`, and `0x3e4`
  across every Type 5/session/process consumer; named service accounts use allocated sessions.
- **Entry paths:** baseline service logons, storyline service actions, system-process ownership,
  log-clear attribution, and direct service-logon adapters.
- **Consumers:** Security 4624/4672/4688/4689, Sysmon, eCAR USER_SESSION/PROCESS, and pivots.
- **Layer rationale:** the LUID is canonical authentication identity, not emitter formatting.
- **Sibling risk:** well-known LUIDs repeat on every host, so durable identity must remain host
  scoped and must not collide in globally keyed mutable session state.

### Implementation

- Built-in service logons now reuse their well-known authentication IDs and stable host/token
  identity plans without allocating fake mutable sessions.
- Named service accounts retain allocated Type 5 session identities.
- Focused service-logon suite: 4 passed; Ruff passes.

## Loop 81

- Fresh generation produced 78,023 records. Automated score: 97.8964; all hard gates passed.
- The loop-80 probe passed: all 330 built-in Type 5 logons used the correct well-known LUID.
- Initial blind scores: 56/28/76/84 (mean 61.0). Deliberation final: 64/45/78/86
  (mean 68.25), panel 3-0-1 Synthetic.
- Selected target: repeated cross-application Office MRUs, arbitrary Internet Settings writes,
  and static policy values assigned to actors that do not own those effects.

### Family contract: actor-native registry/file effect ownership

- **Owning abstraction:** canonical data-driven process-effect selection.
- **Invariant:** an ambient registry/file artifact is eligible only when the executable family owns
  that application state or a concrete maintenance/configuration transaction explains it.
- **Entry paths:** baseline process side effects, system-process churn, Office applications,
  storyline process generation, and ambient EDR file/registry projections.
- **Consumers:** Sysmon Event 13/11, eCAR REGISTRY/FILE, process pivots, and host forensics.
- **Layer rationale:** artifact ownership is canonical action truth shared by all endpoint sources.
- **Sibling risk:** explicit `reg.exe`/PowerShell storyline mutations remain action-authored and
  must not be blocked by ambient-noise eligibility rules.

### Implementation

- Registry eligibility now matches combined key/value artifacts, enabling value-specific ownership.
- Added executable-specific Office Word/Excel/PowerPoint, Internet Settings, and static machine
  policy ownership rules in overlayable YAML.
- Focused registry/effect suite: 10 passed; Ruff passes.

## Loop 82

- Two fresh corpora were rejected before review: the first exposed baseline registry-writer
  selection bypassing process-effect eligibility, and the second exposed value-specific/HKU target
  matching gaps. The final corpus passed the family probe with 215 Event 13 records and zero
  ownership violations.
- Generation also caught a bounded `git` process extending beyond its SSH transport close. The
  foreground lifetime owner now caps commands against transport and authoritative session bounds;
  focused lifecycle tests pass.
- Final fresh generation produced 77,088 records. Automated score: 97.8769; all hard gates passed.
- Blind scores: 29/18/24/24 (mean 23.75), unanimously Real; deliberation was not triggered.
- Selected target: repeated fleet-wide maintenance command vocabulary observed independently by
  Threat Hunter and Host/EDR.

### Family contract: role-bound maintenance command cohorts

- **Owning abstraction:** data-driven service-account delegation process catalog.
- **Invariant:** managed service maintenance offers multiple role-compatible command families;
  workstation-only and server-only commands never cross roles.
- **Entry paths:** scheduled stale/service credential delegation and baseline 4648 caller process.
- **Consumers:** Security/Sysmon, eCAR PROCESS, process trees, and host/threat blind review.
- **Layer rationale:** command vocabulary and role eligibility are catalog truth, not rendering.
- **Sibling risk:** standardized Linux cron cadence remains a separate schedule-observation family.

### Implementation

- Added endpoint-inventory, certificate-health, and OpsAgent alternatives to the generic service
  maintenance cohort with workstation/server role constraints.
- Regression proves at least four eligible command shapes per role and prevents cross-role use.
- Focused suite: 3 passed; config validation and Ruff pass.

## Loop 83

- Fresh generation produced 82,524 records. Automated score: 97.6344; all hard gates passed.
- The maintenance cohort probe passed with four command families and zero cross-role violations.
- Initial blind scores: 34/24/74/24 (mean 39.0), panel 3 Real / 1 Synthetic. Deliberation revised
  scores to 55/58/70/43 (mean 56.5), panel 3 Synthetic / 1 Real.
- A version-aware probe rejected the deliberation's TLS target: all 799 clean chainless sessions
  were TLS 1.3, whose certificate flight is encrypted; TLS 1.2 chain omissions all had capture loss.
- Selected validated target: 739/752 lossy flows carried symmetric `Gg`, with zero responder-only
  loss.

### Family contract: directional sensor capture loss

- **Owning abstraction:** network source-observation planner.
- **Invariant:** origin-only, responder-only, and paired loss all occur; paired loss is a minority.
- **Entry paths:** every TCP connection under a lossy sensor profile.
- **Consumers:** Zeek history/missed bytes, protocol/file completeness, IDS, and network review.
- **Layer rationale:** loss is sensor-local observation truth, not canonical or emitter truth.
- **Sibling risk:** file-terminal timing and scanner behavior remain separate families.

### Implementation

- Loss profiles now select origin-only and responder-only at 44% each and paired at 12%.
- Focused capture-loss suite: 5 passed; Ruff passes.

## Loop 84

- Fresh generation produced 82,569 records. Automated score: 97.6358; all hard gates passed.
- Directional-loss probe: 363 origin-only, 302 responder-only, 87 paired (11.6%).
- Initial blind scores: 34/23/83/22 (mean 40.5), panel 3 Real / 1 Synthetic. Deliberation final:
  56/57/79/44 (mean 59.0), panel 3 Synthetic / 1 Real.
- Selected target: 241/242 SMB files collapsed to ten stems while 238/242 full paths were unique.

### Family contract: durable SMB working sets

- **Owning abstraction:** data-driven SMB transfer working-set model.
- **Invariant:** most observations recur on concrete cohort-scoped files; a minority provides a
  broad lexical long tail.
- **Entry paths:** baseline successful SMB transfer metadata.
- **Consumers:** Zeek files, MIME/hash/name pivots, and network review.
- **Layer rationale:** durable file identity and vocabulary are behavior/config truth.
- **Sibling risk:** eCAR-only SMB file operations and file-close timing are separate families.

### Implementation

- Moved five filename pools and fifty basenames into validated YAML.
- Added a 68% six-file stable working set per server/user/MIME cohort plus 32% novel tail.
- Focused recurrence/overlay tests pass; config validation and Ruff pass.

## Loop 85

- Rejected one corpus because lexical breadth improved but recurrence remained weak.
- Final probe: 51 normalized stems, 41 revisited paths, 91/215 observations on revisited paths.
- Automated score: 97.4423 across 79,614 records; all hard gates passed.
- Initial blind scores: 31/18/87/20 (mean 39.0), panel 3 Real / 1 Synthetic. Deliberation final:
  57/60/82/43 (mean 60.5), panel 3 Synthetic / 1 Real.
- Exact sibling defect: all repeated read-only SMB paths changed size on every observation.

### Family contract: stable SMB file metadata identity

- **Owning abstraction:** canonical SMB file metadata identity.
- **Invariant:** repeated read-only paths retain MIME, size, and content hashes.
- **Entry paths:** SMB file analysis on successful canonical connections.
- **Consumers:** Zeek files/hashes/accounting and repeated-access pivots.
- **Layer rationale:** file metadata belongs to file identity, not transport occurrence/FUID.
- **Sibling risk:** future explicit SMB writes need a mutation owner.

### Implementation

- Added validated per-MIME size ranges; size is stable by path/MIME and hashes use the same file
  identity rather than flow bytes/FUID.
- Focused stable-metadata/working-set suite: 3 passed; config validation and Ruff pass.

## Loop 86

- Fresh generation produced 79,614 records. Automated score: 97.4423; all hard gates passed.
- The stable-SMB-metadata probe passed: 41 repeated paths and zero MIME/size/hash violations.
- Initial blind scores: 31/17/79/20 (mean 36.75), panel 3 Real / 1 Synthetic. Deliberation final:
  54/56/74/40 (mean 56.0), panel 3 Synthetic / 1 Real.
- Selected target: every DHCP client reused one fixed lease-scoped renewal interval; per-client
  multi-cycle interval ranges were only 0.749-2.460 seconds.

### Family contract: evolving DHCP client timer state

- **Owning abstraction:** DHCP lease scheduler and client timer state.
- **Invariant:** every ACK recomputes the next T1-adjacent interval while retaining deterministic
  per-client implementation character.
- **Entry paths:** warm-up acquisitions, baseline renewals, and authored lease events.
- **Consumers:** lease state, Zeek DHCP/conn, dhclient syslog, registry effects, and timing probes.
- **Layer rationale:** renewal scheduling is lease/client state, not emitter timestamp polish.
- **Sibling risk:** rebinding and server failover remain topology-dependent behaviors.

### Implementation

- Added a client-scoped deterministic timer RNG and stable granularity, with per-cycle scheduler
  drift, quantization, and low-rate deferral/retry delay.
- Hourly scheduling carries each newly advertised interval across boundaries; authored renewals use
  the same state path. Focused DHCP suite: 15 passed; Ruff and format checks pass.

## Loop 87

- Fresh generation produced 78,132 records. Automated score: 98.0793; all hard gates passed.
- DHCP probe passed: minimum per-client multi-cycle range 24.1 seconds, median 94.6 seconds, and no
  client below ten seconds. The network reviewer explicitly credited the new T1-centered texture.
- Initial blind scores: 34/17/75/19 (mean 36.25), panel 3 Real / 1 Synthetic. Deliberation final:
  39/36/63/31 (mean 42.25), retaining the 3 Real / 1 Synthetic split.
- Selected target: 62/311 duration-bearing file rows ended at one approximately 1 ms transport-close
  margin across unrelated HTTP and SMB transfers.

### Family contract: file-observation completion and transport teardown

- **Owning abstraction:** source-native file-observation timing.
- **Invariant:** file analysis remains inside transport with a transfer-specific, protocol-shaped
  completion margin rather than a shared epsilon.
- **Entry paths:** HTTP, SMB, SMTP, proxy legs, and canonical file-transfer contexts.
- **Consumers:** Zeek files/conn lifecycle pivots and timing diagnostics.
- **Layer rationale:** the relationship is source-observation timing, not content identity/rendering.
- **Sibling risk:** very short transports constrain available separation proportionally.

### Implementation

- Added deterministic UID/FUID/protocol/size/duration close margins to `SourceTimingPlanner` and made
  the Zeek file interval constraint consume them instead of a global 1 ms epsilon.
- Focused source-timing/Zeek-file suite: 71 passed.

## Loop 88

- Fresh generation produced 78,132 records. Automated score: 98.0793; all hard gates passed.
- File timing probe passed: zero near-1 ms margins, 305/308 millisecond-distinct gaps, and zero
  interval violations.
- Initial blind scores: 34/17/85/19 (mean 38.75), panel 3 Real / 1 Synthetic. Deliberation final:
  56/58/80/42 (mean 59.0), panel 3 Synthetic / 1 Real.
- Selected target: 220/221 SMB objects were below 32 KiB, none occupied the middle, and one authored
  object stood alone at 315 MB.

### Family contract: baseline SMB object-size population

- **Owning abstraction:** SMB file-object population plus canonical transport accounting.
- **Invariant:** MIME families occupy weighted small/medium/large bands and the carrying transport
  accounts for the observed object plus overhead.
- **Entry paths:** successful baseline SMB read/write metadata and repeated working-set observations.
- **Consumers:** network ledger, Zeek conn/files, hashes, and size-distribution pivots.
- **Layer rationale:** size is stable file identity; matching wire volume is canonical transport truth.
- **Sibling risk:** explicit file mutations still require a separate owner.

### Implementation

- Added validated weighted bands for six MIME families with stable path-derived selection.
- Reconciled directional payload, packet, and IP-byte accounting before canonical network freeze.
- Focused SMB/file suite: 14 passed; config validation zero issues; Ruff/format checks pass.

## Loop 89

- Final fresh generation produced 75,026 records. Automated score: 97.1418; all hard gates passed.
- SMB-size probe passed: 205/219 objects in the 32 KiB-100 MiB middle, 1.98 MiB median, 174 unique
  sizes, and zero wire-accounting violations.
- Initial blind scores: 38/17/66/23 (mean 36.0), panel 3 Real / 1 Synthetic. Deliberation final:
  42/34/58/41 (mean 43.75), retaining the 3 Real / 1 Synthetic split.
- Selected target: 219 SMB observations normalized to only 50 semantic stems with six singletons;
  year/opaque suffix novelty did not survive normalization.

### Family contract: SMB lexical working-set generation

- **Owning abstraction:** data-driven SMB lexical working-set generation.
- **Invariant:** recurring concrete files coexist with a semantic long tail that survives removal of
  years, extensions, and opaque suffixes.
- **Entry paths:** baseline SMB filenames across MIME families and cohort working sets.
- **Consumers:** Zeek files, stable file identities/hashes/sizes, and distribution pivots.
- **Layer rationale:** document vocabulary is behavior/config truth, not emitter rendering.
- **Sibling risk:** department-specific terminology is a later refinement.

### Implementation

- Added validated subject, document-kind, and qualifier pools with 82% compositional selection for
  both stable working sets and the novel tail.
- Zeek-file suite: 29 passed, including 45+ normalized stems from 60 samples; config validation and
  focused Ruff/format checks pass.

## Final validation

- All 20 loop score artifacts (70-89) validate against `eforge-assess-scores/v1`.
- Full default suite: 5,365 passed, 41 skipped in 306.17 seconds.
- `eforge validate-config`: 0 errors, 0 warnings, 0 info items across 88 files.
- Full Ruff lint and format checks pass across 465 files.
- Regenerated the rolling 20-loop assessment dashboard through loop 89.
