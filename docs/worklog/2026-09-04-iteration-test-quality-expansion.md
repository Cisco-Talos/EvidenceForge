# Iteration-Test Quality Expansion

## Scope

Expand the six-hour iteration benchmark around data-quality coverage: a second domain
controller, a Linux Samba server, a centralized log/monitoring server, database SPAN
visibility, cross-platform SMB activity, correlated remote administration, multipart
archive exfiltration, and a late benign SSH investigation. Preserve the historical
Meridian 1.0.0 pack and all prior blind-assessment reports.

## Authored changes

- Created project-local organization pack
  `project:davidjbianco:organization:meridian-healthcare-solutions@1.1.0` by copying
  the packaged 1.0.0 release.
- Added `DC-02`, `FILE-LNX-01`, and `LOG-MON-01`, Linux SMB clients and mappings,
  the XFS-backed `ClinicalResearch` Samba share, and `zeek-db`.
- Added the planned malicious and benign storyline beats while retaining the six-hour
  window, seed, warmup, observation profile, and output formats.
- Updated the attack-free environment briefing and scenario pack reference.

## Engine findings and fixes

1. Linux SMB source-only eCAR projection failed generation because endpoint source
   timing incorrectly required a target-local transport-close deadline. The source
   timing planner now accepts its preferred timestamp when that target-local deadline
   does not exist. A focused regression test covers the source-only projection.
2. Explicit DC-01 to DC-02 remote service installation originally selected the user's
   primary workstation for SMB/RPC. `service_installed` now accepts an optional
   `source_ip`, resolves it through the world model, and passes the resulting system to
   the Windows remote-service action bundle. The bundle remains the canonical owner of
   the SMB/RPC transport. A focused test verifies that an authored source overrides the
   user's primary system.

## Validation and generation

- Pack validation: valid. Meridian 1.1.0 digest:
  `3cbe51326bbb8bab04b6936c5e2d853d76eafb2bf73ddf5a24994db2e29ebec4`.
- Locked technology dependency unchanged:
  `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.
- Scenario validation: 0 errors, 0 warnings, 24 informational pivot suggestions.
- Resolved composition: 21 systems, 49 storyline events, 10 red herrings, six sensors.
- Generation succeeded through hour 6 and atomically replaced the prior output.
- Generated corpus: 111,598 records across 22 parsed source families.

## Automated evaluation

- Overall: 95.8753 (96 rounded).
- Parseability: 99.9202.
- Plausibility: 97.0032.
- Causality: 92.2298.
- Timing: 92.9550.
- The requested overall threshold is met and no pillar is at or below 90.
- The evaluator's independent hard gate remains failed for temporal integrity
  (81.6327, threshold 85). Its reported misses are mainly pre-existing event-presence,
  pivot, and timing behavior; retain this as follow-up engine-quality work rather than
  expanding the current scenario-data effort.

## Focused evidence verification

- DC-01 to DC-02 now has Zeek SMB and DCE/RPC flows immediately before the target
  network logon and `DirectoryCacheSvc` creation/process evidence. Cleanup commands
  use the same target session context.
- `zeek-db` observes application-to-database MySQL traffic.
- Samba server syslog/eCAR and Zeek SMB records preserve Linux paths, XFS share
  identity, principals, authentication protocols, outcomes, and cross-platform client
  paths for mounted and direct clients.
- The staged ZIP read is owned by the generated `curl.exe` PID; proxy and ground-truth
  metadata agree on URI, multipart filename/MIME, decoded size 18,782,613 bytes, and
  the 2,048-byte response body (proxy wire bytes include protocol overhead).
- Priya's SSH transport/authentication precedes `journalctl`; no explicit authored
  logoff exists, and the action-owned lifecycle closes at the collection boundary.

## Assessment

A new standalone blind assessment was saved as `v2-loop-31`; prior loops and reports
remain unchanged. All four reviewers returned Synthetic verdicts with synthetic-confidence
scores of 95, 88, 96, and 86 (average 91.25). Deliberation was not needed because the verdicts
were unanimous and the score spread was only 10 points.

Final acceptance is blocked by new P0/P1 contradictions in the expanded families: inconsistent
Type 9 local-file principal ownership, Samba transfer effects attached to a directory-creation
process, impossible bidirectional/zero-payload UDP syslog accounting, and destination-as-source
Windows network-logon fields on the new DC. The full prioritized list is in
`scenarios/iteration-test/blind-test/v2-loop-31/REPORT.md`; lower-severity findings remain for
later engine-quality loops.

## Assessment loop 32 — endpoint effect ownership

### Family contract

- **Owning abstraction:** canonical process/session state and the HTTP-upload and SMB action
  bundles that attach endpoint file/network effects to a process.
- **Invariant:** a local file effect uses the owning process's local token principal even when
  the same process has outbound NewCredentials, and every SMB effect with PID/process identity
  is owned by a process whose executable/command can perform that SMB operation.
- **Entry paths:** storyline connection multipart staging, baseline and storyline HTTP uploads,
  Windows-native SMB, mounted-CIFS SMB, direct `smbclient`, causal file effects, and raw
  storyline process references.
- **Consumers:** eCAR process/file/flow records, Windows Security/Sysmon process companions,
  Samba audit, Zeek SMB/files/conn, ground truth, and endpoint ownership probes.
- **Layer rationale:** process state owns the local token and action bundles own effect-causing
  process selection. Renderer-only rewriting would leave sibling sources and future callers
  contradictory.
- **Sibling risks:** the fix must cover non-sample upload and SMB operations, avoid changing the
  remote SMB credential/effective identity, and preserve explicit capable process ownership.
  Broader actor-native Windows registry/file side effects remain outside this loop.

### Result

- Focused generated-data probe passed: local archive effects retain Aisha's local token,
  outbound upload credentials remain Marcus, the Windows SMB client uses Explorer rather than
  the unrelated `New-Item` PID, and Samba retains Marcus as the remote principal.
- Automated evaluation was 95.8246 across 111,587 records; temporal integrity remained below
  its hard gate.
- The blind panel returned four Synthetic verdicts with scores 99, 97, 94, and 98 (average
  97.0). The next dominant blocker is a repeated Sysmon native timestamp contradiction.

## Assessment loop 33 — atomic Sysmon process timing

### Family contract

- **Owning abstraction:** `SourceTimingPlanner`'s host-shared Sysmon process lifecycle pair.
- **Invariant:** Event 1 and Event 5 payload `UtcTime` and provider-envelope `TimeCreated` are
  projections of the same exact occurrence; an instance-local retained envelope may not be
  combined with a separately resolved native timestamp.
- **Entry paths:** baseline process starts/stops, storyline processes, RDP/SSH client processes,
  services, causal process companions, and collection-boundary finalization.
- **Consumers:** Sysmon Event 1/5, Security 4688/4689 ordering, eCAR process correlation,
  ProcessGuid identity, and dependent Sysmon Event 3/7/11/22 ordering.
- **Layer rationale:** the planner owns both timestamps as one canonical source-native pair.
  Repairing XML after rendering would leave ProcessGuid and sibling timing contracts stale.
- **Sibling risks:** preserve parent-before-child and create-before-dependent ordering, provider
  latency, deterministic rendering, exact-publication replay, and termination containment.

### Result

- The generated hard probe reduced Sysmon payload/envelope differences over one second from 132
  to zero across 4,682 rows.
- Automated evaluation remained 95.8248 across 111,587 records.
- The blind panel returned four Synthetic verdicts with scores 98, 96, 95, and 94 (average
  95.75). All endpoint reviewers converged on eCAR process dependents preceding exact creation.

## Assessment loop 34 — process starts before session dependents

### Family contract

- **Owning abstraction:** source-timing process lifecycle and session dependency frontiers.
- **Invariant:** a process creation follows its visible session login but precedes every module,
  flow, file, registry, child-process, and termination event carrying its exact process identity.
- **Entry paths:** baseline applications, SSH/RDP clients and receivers, storyline processes,
  service processes, causal effects, PID reuse, and terminal lifecycle publication.
- **Consumers:** eCAR PROCESS/dependent records, Sysmon ProcessGuid lifecycles, Security 4688/4689,
  parent-child identity, and source-timing validation.
- **Layer rationale:** process creation is a prerequisite, so session frontier logic must not
  reorder it as if it were an ordinary dependent. Renderer sorting cannot repair identity state.
- **Sibling risks:** retain login-before-process, termination-after-dependent, session closure,
  parent-before-child, immutable PID-generation identity, and bounded cache behavior.

### Result

- The generated hard probe reduced eCAR exact-identity dependents preceding creation from 855
  across 101 identities to zero across 31,615 records.
- The same source-timing repair reduced live Sysmon PID-generation overlaps from 55 to zero.
- Automated evaluation remained 95.8248 across 111,587 records.
- The blind panel returned four Synthetic verdicts with scores 93, 84, 95, and 88 (average
  90.0). All endpoint reviewers independently confirmed the repaired process/PID ordering.

## Assessment loop 35 — Windows service execution identity

### Family contract

- **Owning abstraction:** authored Windows service definition plus canonical process/session
  ownership for the SCM-launched service executable.
- **Invariant:** a service process inherits the configured built-in service account, logon ID,
  integrity, and `services.exe` parent; the remote installer remains the subject of installation
  but never becomes the service process token.
- **Entry paths:** service installation before process start, process intent before a later
  same-cluster service definition, remote administration, arbitrary service executable names,
  and LocalSystem/LocalService/NetworkService aliases.
- **Consumers:** Security 4688/4689 and 4697, Sysmon Event 1/5 and module records, eCAR process and
  dependent records, service lifecycle reconciliation, and ground truth.
- **Layer rationale:** storyline intent binds an authored service definition to canonical process
  identity. Rewriting only one emitter would preserve contradictory actor/session state elsewhere.
- **Sibling risks:** preserve the remote installer on 4697, explicit network-logon continuity,
  service payload ownership, lifecycle grouping, child-command inheritance, and non-built-in
  domain service accounts.

### Result

- The generated hard probe confirmed `DirectoryCacheSvc` keeps Marcus Chen as the 4697 installer
  while Security, Sysmon, and eCAR render the running process as LocalSystem with logon ID `0x3e7`,
  System integrity, and `services.exe` parentage.
- Automated evaluation was 95.8280 across 111,587 records; temporal integrity remained below its
  hard gate.
- The blind panel returned four Synthetic verdicts with scores 92, 90, 94, and 68 (average 86.0).
  No reviewer repeated the repaired service-process identity finding.

## Assessment loop 36 — immutable Windows logon-session identity

### Family contract

- **Owning abstraction:** canonical Windows authentication/session state, with local token identity
  distinct from outbound NewCredentials identity.
- **Invariant:** one Windows LUID is permanently bound to one local SID/account for its lifetime.
  Type 9 credentials may change only outbound authentication fields; a process attributed locally
  to another principal requires a distinct session and LUID.
- **Entry paths:** `runas /netonly`, explicit credentials, stolen-session storyline actions,
  Windows-native SMB, archive staging, HTTP upload, interactive bootstrap, and process inheritance.
- **Consumers:** Security 4624/4688/4689, Sysmon Event 1/5, eCAR process/file/flow rows, outbound SMB
  and proxy authentication, session lifecycle validation, and ground truth.
- **Layer rationale:** the contradiction is shared by three endpoint sources, so the session/token
  owner must be corrected in canonical state rather than rewritten independently by emitters.
- **Sibling risks:** preserve Marcus as the outbound SMB/proxy principal where authored; retain
  Aisha as the local `runas /netonly` token; allocate and close any distinct stolen-user session;
  avoid changing service-account, RDP, SSH, or network-logon semantics.

### Result

- The generated probe found zero cross-principal uses of the Type 9 LUID. Aisha owns every attached
  process and local profile path; Marcus remains the outbound credential principal.
- Automated evaluation was 95.8281 across 111,625 records; temporal integrity remained below its
  hard gate.
- The blind panel returned four Synthetic verdicts with scores 88, 68, 84, and 64 (average 76.0).
  No reviewer repeated the repaired LUID-ownership contradiction.

## Assessment loop 37 — one-way UDP syslog accounting

### Family contract

- **Owning abstraction:** canonical role-profile connection intent and protocol-aware transport
  accounting for one-way datagram services.
- **Invariant:** a successful UDP/514 syslog delivery carries application payload only from sender
  to collector. The collector contributes no responder application bytes or packets; any ICMP error
  is a separate failed-network occurrence, never a bulk response on the syslog flow.
- **Entry paths:** log-server inbound role profiles, direct role-profile connections, multi-sensor
  observations, perimeter-denied attempts, and future explicit UDP syslog actions.
- **Consumers:** Zeek conn rows on every observing sensor, eCAR FLOW, firewall projections, packet
  and IP-byte accounting, protocol classifiers, and blind network review.
- **Layer rationale:** reverse traffic is invented by generic baseline profile sizing before fan-out,
  so the fix belongs at canonical connection intent rather than in Zeek or another renderer.
- **Sibling risks:** preserve realistic nonzero sender bytes/packets, UDP header accounting, sensor
  agreement, denied/S0 zero-payload behavior, TCP/514 semantics, and bidirectional UDP protocols such
  as DNS, DHCP, and NTP.

### Result

- The generated hard probe found 263 UDP/514 observations across all three sensors with zero
  responder payload bytes, packets, or IP bytes; 232 retained nonzero sender payload.
- A generation-time RDP assertion exposed insufficient SSH-client teardown headroom. The SSH
  transport clamp now reserves the full deterministic source-process termination tail before an
  authoritative source-session end.
- Automated evaluation increased to 96.4760 across 115,117 records and passed every hard gate; all
  four pillars exceed 93.
- The blind panel returned four Synthetic verdicts with scores 68, 84, 94, and 91 (average 84.25).
  No reviewer repeated the repaired UDP/syslog contradiction.

## Assessment loop 38 — exact multipart upload ownership

### Family contract

- **Owning abstraction:** explicit-proxy transaction action bundle plus canonical process identity
  selected for an authored HTTP upload.
- **Invariant:** one exact process owns the multipart command, local archive read, client-to-proxy
  tuple, eCAR FLOW, Sysmon Event 3, proxy request, and process termination. A neighboring probe
  process may not inherit the upload tuple merely because it shares executable, user, host, or URL.
- **Entry paths:** authored multipart uploads, benign support uploads, explicit proxy CONNECT reuse,
  curl/browser process discovery, existing process reuse, and source PID inference.
- **Consumers:** eCAR PROCESS/FILE/FLOW, Sysmon Event 1/3/5/11, proxy access records, Zeek conn/http,
  multipart and artifact metadata, ground truth, and upload hard probes.
- **Layer rationale:** the proxy action bundle owns the logical request and must carry the authored
  process identity into the canonical client leg. Renderer-side PID replacement would leave the
  source process, endpoint effects, and lifecycle state contradictory.
- **Sibling risks:** keep benign and malicious multipart uploads distinct, preserve tunnel reuse and
  source-port identity, avoid duplicating process creation, retain local token versus outbound
  credential semantics, and keep every process alive through its owned network/file dependents.

### Result

- The proxy transaction now treats a validated caller-owned PID as authoritative for its nested
  client transport, so CONNECT semantics cannot replace the multipart upload process with a nearby
  generic curl process. Anonymous multipart activity may still materialize a suitable owner.
- The generated probe found PID `7140` and process object `c6e27dd8-a08d-4357-8d08-003808c23911`
  consistently across the upload command, ZIP read, eCAR flow, Sysmon Event 3, proxy source port
  `57936`, and later termination.
- The routine suite passed 8,204 tests with 5 skipped and 2,003 deselected; repository-wide Ruff
  checks passed across 753 files.
- Automated evaluation scored 95.8011 across 110,715 records. The four pillars remained above 91,
  but pivot linkability and temporal integrity missed their hard thresholds, so acceptance failed.
- The blind panel returned four Synthetic verdicts with scores 94, 66, 94, and 86 (average 85.0).
  No reviewer repeated the upload-ownership contradiction; multiple reviewers explicitly praised
  the repaired exfiltration correlation.

## Assessment loop 39 — process-visible ordering for dependent endpoint effects

### Family contract

- **Owning abstraction:** canonical process lifecycle and source-timing planner for process-dependent
  endpoint effects.
- **Invariant:** when a process creation is visible in a source, every dependent event carrying that
  exact process identity must render after the source-local create. No DNS, network, module, file,
  registry, access, or remote-thread event may precede Event 1/PROCESS CREATE for the same identity.
- **Entry paths:** RDP client startup and DNS prerequisites, ordinary process-to-network expansion,
  explicit proxy and SSH clients, storyline processes, baseline applications, and observation delay.
- **Consumers:** Sysmon Event 1/3/7/8/10/11/12-14/22, eCAR PROCESS and dependent objects, RDP and
  network action bundles, process source bounds, and lifecycle validators.
- **Layer rationale:** the inversion is created by independent source-time planning for a shared
  canonical process and its dependent event. The source planner/lifecycle owner must enforce one
  atomic frontier rather than patching Sysmon DNS output.
- **Sibling risks:** preserve DNS-before-transport semantics, cross-source jitter, session readiness,
  RDP transport-before-auth ordering, collection-boundary behavior, and valid pre-window processes
  whose creation is intentionally absent.

### Result

- Sysmon dependent timing now keys DNS events to their exact query process and shares the Event 1
  source frontier for every process-visible dependent family.
- The generated hard probe checked 578 Event 3/7/8/10/11/12-14/22 records with visible matching
  Event 1 identities and found zero inversions. The reported `mstsc.exe` PID `5380` Event 1 rendered
  at `13:15:14.241643Z`; its first DNS event followed at `13:15:14.244244Z`.
- The routine suite passed 8,205 tests with 5 skipped and 2,003 deselected; repository-wide Ruff
  checks passed across 753 files.
- Automated evaluation remained 95.8011 across 110,715 records. All pillars exceeded 91, but pivot
  linkability and temporal integrity remained below their hard thresholds.
- The blind panel returned four Synthetic verdicts with scores 82, 64, 72, and 72 (average 72.5,
  spread 18). Neither endpoint reviewer repeated the fixed process-ordering contradiction.

## Assessment loop 40 — receiver file availability before SMB upload

### Family contract

- **Owning abstraction:** ordered storyline action execution and canonical file-transfer lifecycle.
- **Invariant:** an SMB client may read a local source file only after that exact path has been
  created on the client host. When SCP supplies the file, receiver creation must precede every
  SMB process read, network transfer, and server-side write derived from it.
- **Entry paths:** storyline SCP commands, receiver file materialization, direct `smbclient` writes,
  mounted CIFS writes, HTTP multipart reads, and archive/staging chains.
- **Consumers:** source-host eCAR file events, SMB client processes, Zeek SMB/file records, Samba or
  Windows server audit, causal ordering, and ground-truth chronology.
- **Layer rationale:** availability is shared canonical state owned by the transfer/storyline
  lifecycle. Moving one rendered file row would leave the SMB transport and server mutation able to
  consume a file that does not yet exist.
- **Sibling risks:** preserve authored event order where feasible, do not duplicate SCP receiver
  creation, keep process ownership and authentication identity distinct, and retain deterministic
  explicit offsets for independent storyline events.

### Result

- SCP receiver publication now records the exact host/path availability frontier, and storyline SMB
  uploads of that local path wait until the canonical receiver file exists.
- The generated chain rendered the APP-INT-01 receiver create at `17:21:34.302Z`, SMB client read at
  `17:21:36.765Z`, and FILE-LNX-01 server write at `17:21:36.853Z`.
- The routine suite passed 8,206 tests with 5 skipped and 2,003 deselected; repository-wide Ruff
  checks passed across 753 files.
- Automated evaluation rose to 95.8512 across 110,715 records. Pivot linkability reached 80.0 and
  passed, leaving temporal integrity as the only failed hard gate.
- The blind panel returned four Synthetic verdicts with scores 72, 91, 72, and 74 (average 77.25,
  spread 19). No reviewer repeated the premature-read contradiction, and reviewers described Samba
  timing and lifecycle correlation as especially strong.

## Assessment loop 41 — protocol-independent Zeek file hash rendering

### Family contract

- **Owning abstraction:** Zeek Files-framework source renderer.
- **Invariant:** one Zeek sensor renders MD5, SHA-1, and SHA-256 using the same lowercase hexadecimal
  convention regardless of whether file analysis originated from SMB, HTTP, SMTP, or TLS.
- **Entry paths:** SMB reads/writes, HTTP request and response bodies, SMTP attachments, TLS
  certificate analysis, capture-loss projections, and repeated file observations.
- **Consumers:** Zeek `files.log` JSON, FUID/content pivots, SMB durability checks, TLS fingerprint
  agreement, deterministic evaluator field agreement, and blind network review.
- **Layer rationale:** canonical content identity deliberately remains source-neutral; hexadecimal
  presentation belongs to the source-native Zeek renderer and must not leak the capitalization used
  by endpoint-oriented identity objects.
- **Sibling risks:** preserve digest values and lengths, TLS SHA-1-to-x509 fingerprint agreement,
  repeated-file stability, sparse/absent hashes, and all non-Zeek consumers of canonical digests.

### Result

- The Zeek Files renderer now normalizes every present MD5, SHA-1, and SHA-256 digest to lowercase
  without changing canonical source-neutral content identities.
- The generated hard probe inspected 1,941 Zeek files rows and 3,507 digest values across `zeek-db`,
  `zeek-core`, and `zeek-dmz`. All 480 SMB and 3,027 non-SMB values were lowercase.
- The routine suite passed 8,206 tests with 5 skipped and 2,003 deselected; repository-wide Ruff
  checks passed across 753 files. The exact legacy slow SMB test remains independently red because
  it assumes every observed row has hashes and every client read belongs to `robocopy.exe`; this
  loop did not weaken that unrelated assertion.
- Automated evaluation remained 95.8512 across 110,715 records. Temporal integrity at 83.67 is the
  sole failed hard gate.
- The blind panel returned four Synthetic verdicts with scores 99, 99, 99, and 97 (average 98.5,
  spread 2). No reviewer repeated the hash-capitalization defect; the network reviewer explicitly
  praised SMB hashes and complete Zeek joins.

## Ten-loop assessment summary — loops 32–41

The requested ten-loop run repaired ten bounded evidence-family contracts and produced one fresh,
standalone four-reviewer panel per loop. Exact reports and per-loop scores are archived under
`scenarios/iteration-test/blind-test/v2-loop-32` through `v2-loop-41`; the final directory also
contains a 20-loop dashboard spanning loops 22–41.

The strongest final capabilities are deterministic parseability, network/endpoint tuple agreement,
IDS pivots, SMB auditing, attack-chain reconstruction, multipart exfiltration ownership, Windows
service identity, and endpoint process ordering. Acceptance is not complete: temporal integrity
remains below its hard threshold. Blind review also leaves systemic realism work in Sysmon session
GUIDs, remote-execution attribution, proxy tunnel lifetimes, ASA ID chronology, one-shot Linux
process duration, SSH observation coherence, collection-boundary handling, public DNS/PTR identity,
TTL state, and SMB/SMTP reuse. These are follow-on engine-quality families, not scenario edits.

## Assessment loop 42 — proxy tunnel lifetime ownership

### Finding classification

- Proxy setup rows ending before visible inspected children: `new_family`, confirmed across 114
  tunnels by the loop-41 network reviewer.
- Near-universal zero Sysmon `LogonGuid`: `false_positive_or_unproven`; native Microsoft examples
  legitimately use the null GUID for local Negotiate, NTLM, and several RDP paths, and the current
  generator already produces stable nonzero GUIDs for Kerberos-backed sessions.

### Family contract

- **Owning abstraction:** proxy emitter's bounded pending-tunnel summary, which owns the
  source-native CONNECT lifetime after all visible child requests have been folded.
- **Invariant:** `tunnel_duration_ms` must span both the canonical client transport and every
  proxy-visible child transaction assigned to the CONNECT channel.
- **Entry paths:** explicit HTTPS proxy transactions, reused CONNECT channels, raw compatibility
  proxy events, incremental checkpoint finalization, and final emitter closure.
- **Consumers:** combined proxy logs, Splunk proxy JSON, tunnel/child correlation probes, evaluator
  proxy parsing, and blind network review.
- **Layer rationale:** the canonical transport duration and visible child frontier are both known
  only when the proxy source finalizes its summary; rendering either input alone can understate the
  source-native channel lifetime.
- **Sibling risks:** preserve exact child byte aggregation, inactivity-timeout channel splitting,
  setup timing, denied/cache terminal actions, output-target parity, and collection-boundary rules.

### Result

- Proxy setup lifetime now spans both the canonical transport and the last visible child request.
- The hard probe parsed 548 setup rows and 792 children; zero children ended after their owning
  tunnel, eliminating the loop-41 contradiction.
- The routine suite passed 8,206 tests with 5 skipped and 2,003 deselected; repository-wide Ruff
  lint and format checks passed across 753 files.
- Automated evaluation remained 95.8512 across 110,715 records. Temporal integrity at 83.67 remains
  the only failed hard gate.
- Standalone blind scores were 44, 88, 64, and 89 (average 71.25; spread 45). Verdict disagreement
  triggered deliberation; after cross-specialty evidence was shared, all four positions were
  Synthetic with an average revised synthetic confidence of 84.25.
- No reviewer repeated the proxy-lifetime defect. The next highest proven root contract is durable
  Sysmon process identity across create, terminate, PID 4, and dependent-event projections.

## Assessment loop 43 — durable Sysmon process identity

### Family contract

- **Owning abstraction:** the host-shared Sysmon process-create timing anchor in
  `SourceTimingPlanner`.
- **Invariant:** one host/PID/start lifecycle renders one immutable `ProcessGuid` across Event 1,
  Event 5, DNS, network, file, registry, module, process-access, and remote-thread projections.
- **Entry paths:** direct process create/terminate, long-running baseline services, PID 4 dependent
  activity, parent-before-child timing repair, dropped Event 1 collection, checkpointed batches, and
  compatibility rendering.
- **Consumers:** Sysmon lifecycle joins, eCAR-to-Sysmon process correlation, parent GUIDs, evaluator
  causality checks, detection process graphs, and blind endpoint review.
- **Layer rationale:** `ProcessGuid` encodes the visible Event 1 anchor. A parent-order repair changed
  that anchor only in an instance-local cache, allowing later events to recover the unrepaired
  host-shared value. The repaired anchor must be published by the timing owner, not rewritten by an
  emitter.
- **Sibling risks:** preserve native versus provider-envelope timestamps, PID reuse isolation,
  cross-source Security 4688 ordering, parent identity, collection-dropped creates, cache retention,
  checkpoint recovery, and deterministic replay.

### Result

- Parent-order repairs now update the host-shared Sysmon create anchor, and dependent renderers
  prefer the durable canonical actor over a thinner same-PID process carrier.
- The definitive hard probe joined 759 visible create/terminate lifecycles with zero ProcessGuid
  mismatches. All seven hosts with PID 4 evidence retained one GUID.
- Focused Sysmon tests passed twice while closing the discovered PID 4 sibling. The final routine
  suite passed 8,208 tests with 5 skipped and 2,003 deselected; repository-wide Ruff lint and format
  checks passed across 753 files.
- Automated evaluation remained 95.8512 across 110,715 records, with temporal integrity as the only
  failed hard gate.
- Blind scores were 84, 84, 76, and 78 (average 80.5; spread 8), all Synthetic. No deliberation was
  required, and no reviewer repeated the immutable ProcessGuid contradiction.
- Two reviewers independently retained ASA connection-ID chronology as a dataset-wide defect; it
  is the next highest-leverage repeated source-native family.

## Assessment loop 44 — ASA connection-ID chronology

### Family contract

- **Owning abstraction:** the ASA source finalizer over the appliance's timestamp-sorted build and
  teardown stream.
- **Invariant:** each appliance allocates one unique, monotonically increasing connection ID when a
  built record enters final source chronology, and every teardown retains that exact ID.
- **Entry paths:** baseline and storyline permits, TCP and UDP, NAT and identity-NAT paths, retries,
  external sorted runs, incremental checkpoints, output-target year partitioning, and final close.
- **Consumers:** ASA 302013/302014 and 302015/302016 joins, firewall hunting pivots, SIEM sequence
  analytics, deterministic parsers, and blind network/detection review.
- **Layer rationale:** canonical connection identity is generation-order truth, while an ASA counter
  is source-local runtime order. The latter cannot be finalized until the appliance's rows are
  globally sorted, so the source finalizer owns allocation and pair-preserving projection.
- **Sibling risks:** retain build/teardown pairing across year-split files, deterministic retry,
  atomic replacement, multiple appliance lanes, NAT companion ordering, explicit deny records,
  checkpoint-restored runs, and byte-identical repeated close.

### Result

- Canonical ASA permits now receive appliance-local IDs only after the definitive source stream is
  timestamp sorted. Raw caller-supplied records remain byte-faithful, and teardown rows retain their
  build ID through atomic finalization.
- The hard probe inspected 6,751 generated build/teardown lifecycles: build IDs were unique and
  strictly consecutive, with zero orphaned build or teardown references.
- Focused ASA, output-target, and constructor-bypass compatibility tests passed. The final routine
  suite passed 8,208 tests with 5 skipped and 2,003 deselected; repository-wide Ruff lint and format
  checks passed across 753 files.
- Automated evaluation remained 95.8512 across 110,715 records, with temporal integrity as the only
  failed hard gate.
- Blind scores were 72, 84, 67, and 78 (average 75.25; spread 17), all Synthetic. No deliberation
  was required, and no reviewer repeated the backward ASA connection-ID defect.
- Two reviewers independently prioritized operation-detached one-shot command lifetimes and
  millisecond-scale retirement sweeps; this is the next family for loop 45.

## Assessment loop 45 — operation-owned SMB client lifetime

### Finding classification

- Direct `smbclient -c` processes surviving completed SMB transports by tens of minutes or hours:
  `new_family`, independently confirmed by threat-hunting and host-forensics review.
- Millisecond-scale retirement sweeps: `same_family_sibling`; these are the delayed consequence of
  leaving bounded operation processes in live State until a later stale/session drain.
- Other bounded utilities (`git log`, `head`, and `cmd.exe /c`) with delayed exits:
  `same_family_sibling`, retained for the hard probe and follow-on expansion if the SMB owner fix
  does not remove their common lifecycle cause.

### Family contract

- **Owning abstraction:** the canonical SMB action bundle and its resolved client-process plan.
- **Invariant:** a process profile marked as operation-lived remains active through its SMB
  transport and file effects, then terminates independently within bounded jitter after transport
  close; session-lived clients such as Explorer and mounted-kernel transport remain unaffected.
- **Entry paths:** direct Linux `smbclient`, Windows-native access, mounted CIFS operations,
  downloads, uploads, remote copies, multi-file channel reuse, denied operations, storyline and
  baseline actions, and explicit preferred process ownership.
- **Consumers:** client eCAR process lifecycle, endpoint FLOW actor joins, SMB source file effects,
  Zeek transport close, session teardown, stale-process cleanup, shell serialization, and blind
  host/threat review.
- **Layer rationale:** executable lifetime is an action-bundle fact because only the SMB owner knows
  both the profile's lifecycle class and the definitive transport/file completion frontier. A
  generic hourly drain sees the process but not the completed operation it should follow.
- **Sibling risks:** preserve source-process visibility through every dependent effect, do not
  terminate persistent Explorer or mounted transport owners, keep client and server processes
  distinct, respect authoritative session deadlines and collection bounds, and retain exact retry
  behavior for persistent SMB publication.

### Result

- Operation-lived SMB clients now close after definitive publication, bounded foreground
  finalizers run before their hourly watermark, and eCAR process termination remains governed by
  the process's own dependent frontier rather than unrelated later session activity.
- The hard probe joined 26 direct `smbclient -c` lifecycles with zero missing or duplicate endpoint
  events, zero lifetimes over 60 seconds, and a 43.018-second maximum.
- Focused source-timing and process-lifecycle tests passed. The final routine suite passed 8,211
  tests with 5 skipped and 2,003 deselected; repository-wide Ruff lint and format checks passed
  across 753 files.
- Automated evaluation improved to 96.2822 across 123,124 records, and every hard acceptance gate
  passed.
- Initial blind scores were 43, 78, 72, and 84 (average 69.25; spread 41), with one Inconclusive
  and three Synthetic verdicts. Deliberation revised all four to Synthetic with an average score
  of 87.25. No reviewer repeated the SMB lifetime defect.
- The next highest-impact independent contradiction is positive duration on unanswered one-packet
  ICMP scan flows; this becomes the loop-46 family.
