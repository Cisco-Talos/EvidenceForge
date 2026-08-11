# iteration-test-expanded-ids assessment loops 60-69

## Scope

Ten fresh end-to-end assessment loops on `iteration-test-expanded-ids`, continuing from loop 59.
Each loop regenerates the corpus, runs the deterministic evaluator, commissions four blind expert
reviews, verifies the preceding fix, and selects at most one family-level implementation target.
The scenario remains unchanged.

## Loop 60

- Baseline commit: `dcb89ca6`.
- Generated 78,920 records. Automated score: 97.7347; all hard acceptance criteria passed,
  including 45/45 expected-visible events and 67/67 pivot edges.
- Loop-59 email ownership fix passed: all 12 Outlook-private artifacts were Outlook-owned, with
  zero Chrome/Edge mismatches.
- Initial blind synthetic-confidence scores: 76/56/57/73 (mean 65.5). Verdict disagreement
  triggered deliberation; final scores were 72/66/66/75 (mean 69.75, displayed 69.8).
- The panel rejected the threat-hunter's empty-1102 claim: native event 1102 correctly stores the
  clearing subject in populated `LogFileCleared` `UserData`, not `EventData`.
- Selected target: generic Linux server proxy-client ownership. DB and web servers received
  fabricated root-owned `wget` processes, parented directly by PID 1, for role-profile HTTPS
  traffic whose intent did not identify a process owner.

### Family contract: unknown Linux server role-traffic process ownership

- The role-profile layer may describe a network transaction without claiming a process owner.
- If a Linux server's external HTTP(S) role-profile entry has no canonical PID, explicit proxy
  routing must preserve that unknown ownership; it must not materialize `wget`, `curl`, or another
  client solely from a sampled User-Agent.
- A valid caller-supplied process remains authoritative and may own the proxy socket.
- Explicit proxy transport, access, DNS, origin-egress, timing, and pivot contracts remain intact
  when endpoint process identity is absent.
- Workstation/user browsing and package-manager traffic with a concrete canonical owner remain
  unchanged.

### Implementation

- Threaded `suppress_source_pid_inference` through the explicit proxy transaction contract.
- Applied it only to Linux external HTTP(S) role traffic when the profile has no canonical PID.
- Added a proxy-bundle regression proving the process-synthesis hook is not called under that
  contract.

## Loop 61

- Generated 77,926 records. Automated score: 97.8796; all hard acceptance criteria passed,
  including 46/46 expected-visible events and 69/69 pivot edges.
- The loop-60 ownership probe passed with zero `wget` creates, zero `curl` creates, and zero
  PID-1-parented `wget`/`curl` processes.
- Initial blind synthetic-confidence scores: 40/72/84/66 (mean 65.5). Verdict disagreement and a
  44-point spread triggered deliberation; final scores were 72/82/87/76 (mean 79.25).
- The panel again rejected the alleged empty Event 1102 defect after confirming populated native
  `UserData/LogFileCleared` subject fields.
- Selected target: IDS response-trigger semantics. ZIP/PE and certificate alerts were rendered in
  request direction, and the file rules were attached to unrelated transactions without eligible
  response artifacts.

### Family contract: IDS trigger evidence and packet side

- A response-content signature renders the responder-to-originator packet tuple; request-content,
  DNS-query, and User-Agent rules retain originator-to-responder direction.
- File-content alerts require a response-side network file artifact with an allowed MIME family and
  sufficient response payload.
- A baseline path that cannot construct the claimed file or certificate evidence must not emit the
  corresponding false-positive alert.

### Implementation

- Added validated file MIME requirements to canonical IDS signature predicates and enforced them
  against response-side `FileTransferContext` artifacts.
- Added response-side predicates for ZIP, PE, and certificate signature families and disabled them
  in the baseline false-positive path that cannot construct their required artifacts.
- Made the Snort renderer derive packet direction from the canonical predicate payload side.
- Added regression coverage for MIME/direction gating and responder-to-originator rendering.

## Loop 62

- Generated 83,205 records. Automated score: 98.1015; all hard acceptance criteria passed,
  including 46/46 expected-visible events and 69/69 pivot edges.
- The loop-61 response-content probe passed: targeted ZIP, PE, and certificate alerts were absent
  without their required response evidence.
- Initial blind synthetic-confidence scores: 55/34/54/62 (mean 51.25). Verdict disagreement
  triggered deliberation; final scores were 66/50/65/70 (mean 62.75).
- Selected target: Linux role/identity/access-method ownership. Headless-server local sessions were
  sampled from unrelated syslog volume and populated with generic human identities.

### Family contract: Linux human session ownership

- Local human session volume is budgeted per host and time window, not sampled independently from
  generic syslog rows.
- Rare headless-server console access is an explicit root `login`; routine human administration is
  remote and must use the canonical SSH session bundle.
- Linux workstation graphical sessions belong to the modeled assigned user and use a display
  manager PAM service.
- Canonical sessions own their PAM opener so the renderer does not infer an access method.

### Implementation

- Added a sparse per-host-hour ambient local-session budget, capped at one session.
- Replaced generic server `admin`/`ubuntu` and `su` noise with rare root console logins; assigned
  workstation users now receive `gdm-password` sessions.
- Routed after-hours Linux server administration through `WorldPlanner` with `session_kind="ssh"`.
- Added canonical PAM-open evidence for durable local Linux sessions and regression coverage for
  budgeting and PAM ownership.

## Loop 63

- Generated 78,561 records. Automated score: 97.8955; all hard acceptance criteria passed.
- The loop-62 Linux session probe passed: ambient generic server console identities and `su`
  sessions were eliminated, while workstation sessions used assigned users and `gdm-password`.
- Initial blind synthetic-confidence scores: 73/74/34/95 (mean 69.0). Verdict disagreement and a
  61-point spread triggered deliberation; final scores were 90/88/76/96 (mean 87.5).
- Selected target: canonical Windows registry-artifact state, value structure, and actor ownership.

### Family contract: Windows registry artifact realism

- Persistent registry objects retain stable identities per host rather than receiving a fresh GUID
  on every observation.
- Binary values use source-native structure and length rather than arbitrary random blobs.
- Shell settings belong to shell-native processes; Defender scan processes do not author exclusion
  policy changes.
- Ambient generation skips mutations that require an explicit administrative action.

### Implementation

- Made UpdateOrchestrator Schedule Scan task IDs stable per host and allowed registry state tracking
  to suppress unchanged rewrites.
- Replaced random-size UserAssist values with structured 72-byte Windows 7+ payloads.
- Expanded data-driven registry ownership rules for Search, Themes, ContentDeliveryManager,
  InputPersonalization, TaskCache, and Defender exclusions.
- Removed ambient Defender exclusion mutations and added ownership/structure/stability regressions.

## Loop 64

- Generated 82,502 records. Automated score: 98.1514; all hard gates passed.
- The loop-63 registry probe passed across native UserAssist structure, stable TaskCache identity,
  and actor/effect ownership.
- Blind scores: 64/86/86/69 (mean 76.25), unanimously Synthetic; no deliberation required.
- Selected target: HTTP request timing. 351/2,385 HTTP analyzer records exactly matched TCP start.

### Family contract and implementation: transport before HTTP request

- A first HTTP request on TCP occurs after transport establishment and within transport close.
- The canonical planner owns this phase relationship; emitters only project it.
- Reused keep-alive requests keep their existing canonical request time and do not invent another
  transport phase.
- Added regression coverage for delayed first requests and ordered persistent transactions.

## Loop 65

- Generated 82,502 records. Automated score: 98.1514; all hard gates passed.
- The HTTP timing probe passed: 2,385/2,385 matched requests followed TCP start.
- Blind scores: 64/76/72/84 (mean 74.0), unanimously Synthetic.
- Selected target: Windows third-party updater deployment monoculture, independently identified by
  detection and host reviewers.

### Family contract and implementation: host software inventory

- Third-party services and their scheduled tasks derive from one stable per-host inventory.
- A host does not run updater tasks for products absent from its service inventory.
- Different hosts may select different product families deterministically.
- Added data-driven compatibility metadata, host-scoped selection, and a variation/coherence test.

## Loop 66

- Generated 81,372 records. Automated score: 97.4456; all hard gates passed.
- The host-scoped updater probe passed with a coherent 3/2/1 Google/Adobe/Dropbox distribution.
- Initial scores: 52/36/66/46 (mean 50.0); deliberated final scores: 58/47/68/52 (mean 56.25).
- Selected target: exact integer-millisecond protocol-child timing across HTTP, SMTP, and DHCP.

### Family contract and implementation: packet-child timing texture

- Packet-derived protocol child records receive deterministic sub-millisecond capture texture.
- Texture remains bounded by declared causal floors and transport intervals.
- One shared source-timing method owns the behavior across HTTP, SMTP, and DHCP emitters.
- Focused protocol and source-timing tests pass.

## Loop 67

- Generated 81,372 records. Automated score: 97.4956; all hard gates passed.
- The loop-66 timing probe passed: HTTP, SMTP, and DHCP had zero exact integer-millisecond child
  offsets and broad fractional-millisecond distributions.
- Initial scores: 64/55/65/76 (mean 65.0); verdict disagreement triggered deliberation. Final
  scores: 68/64/68/78 (mean 69.5), unanimously Synthetic.
- Selected target: executable-aware lifecycle ownership for bounded foreground commands.

### Family contract and implementation: bounded foreground process ownership

- Version/status queries, VCS operations, build commands, and noninteractive SMB clients receive
  executable- and invocation-aware lifetimes.
- `smbclient -c` is a unique process per invocation/transport and cannot be reused hours later as
  though it were a resident service.
- Interactive `smbclient` and explicitly long-running commands retain unbounded semantics.
- Focused lifecycle and activity tests pass (394 tests).

## Loop 68

- Generated 80,818 records. Automated score: 97.7116; all hard gates passed.
- The loop-67 lifecycle probe passed: 167/168 bounded creates terminated visibly, the unmatched
  create was at the slice boundary, and maximum matched lifetime was 72.637 seconds.
- Blind scores: 96/94/82/96 (mean 92.0), unanimously Synthetic; no deliberation required.
- Selected target: clock-like Linux PID allocation across all host roles.

### Family contract and implementation: bursty host-local PID consumption

- PID allocation remains deterministic, host scoped, chronological, and compatible with
  out-of-order generation.
- Hidden process consumption uses broad shuffled hourly load regimes and minute-level bursts rather
  than a nearly constant PID-per-second slope.
- Ordinary PID limits, namespace sharing, and bounded collision behavior remain intact.
- Focused state-manager tests pass (104 tests); six-hour hidden-churn probes reduced representative
  host linear-fit R-squared values to 0.9351-0.9864 before visible allocation texture.

## Loop 69

- Generated 76,278 records. Automated score: 97.5882; all hard gates passed.
- The loop-68 PID probe passed: Linux eCAR process-create PID fits were approximately
  0.9515-0.9869 instead of 0.994-0.999.
- Initial scores: 42/95/95/91 (mean 80.75). Verdict disagreement and a 53-point spread triggered
  deliberation; final scores were 86/96/97/94 (mean 93.25), unanimously Synthetic.
- Selected target: independent source-local observation timing for paired endpoint eCAR FLOW rows.

### Family contract and implementation: endpoint FLOW observation clocks

- Source-host and destination-host eCAR FLOW rows derive independent deterministic observation
  times rather than inheriting an identical nested-bundle timestamp.
- Paired observations remain inside the canonical connection interval and transport-before-auth
  lifecycle constraints.
- Nested proxy child transports now retain paired-endpoint timing texture; very short intervals use
  separated direction-aware positions when at least two milliseconds are available.
- Focused source-timing/proxy tests pass (139 tests). This final-loop fix has no subsequent corpus
  probe in the requested set.

## Validation and handoff

- Full suite before the final cleanup: 5,333 passed, 41 skipped, 9 failed across three root causes.
- Fixed the loop-62 source-less SSH fallback recursion, loop-65 config-schema metadata omission,
  and SSH process-close margin; all nine failed tests pass on targeted rerun.
- Final endpoint FLOW timing tests pass. Run the next assessment loop to probe the loop-69 fix on a
  fresh corpus before treating its population-level effect as verified.
