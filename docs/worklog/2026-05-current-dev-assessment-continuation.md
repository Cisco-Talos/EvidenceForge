# Current-Dev Assessment Continuation

## Status

Active handoff memory for the current-dev realism assessment continuation that
was previously tracked directly in `TODO.md`.

The central roadmap now points here instead of carrying loop-by-loop status
updates. Continue appending concise handoff notes here if another assessment loop
or follow-up batch is needed.

## Current Handoff

- The previous TODO history recorded current-dev assessment loops through a long
  branch-era sequence, including the 143+ loop series and later follow-up batches.
- The latest recorded generator-owned targets included bash-history/process
  timing alignment, web/proxy path-template diversity, richer TLS/X.509 SAN
  distributions, and continued reduction of overly tidy scenario-authored names
  when scenario edits are in scope.
- Scenario-authored name legibility was repeatedly identified as a broad tell,
  but was deferred unless scenario edits were explicitly authorized.
- Preserve per-loop artifacts under the scenario or assessment output directory
  chosen for that loop; do not use `TODO.md` for loop transcripts.

## 2026-05-27 Loop Batch Notes

- Loop 200 fixed eCAR endpoint file texture and installed-software registry
  identity stability (`ed4ab68a`, `88db6b22`). Automated eval passed at
  96.66140704016262 over 78539 records; the hard probe saw 419 eCAR FILE events
  across all 15 hosts and zero duplicate installed-software DisplayName/GUID
  groups.
- Loop 200 blind review remained synthetic-leaning: initial synthetic-confidence
  average 59.0, deliberated average 64.75. The strongest confirmed next targets
  are proxy file-transfer object identity/timing and Linux eCAR process-to-flow
  attribution.
- Loop 201 fixed explicit-proxy HTTP file-transfer identity/timing by sharing
  origin-form content identity across proxy legs, pairing client/origin
  `files.log` metadata, and delaying client-facing file observation until after
  proxy-origin fetch observation. Automated eval passed at 95.83681405251764
  over 78513 records; the hard probe saw zero hash/size mismatches and both
  Dell updater client observations started/finished after origin observation.
  Blind synthetic-confidence scores were 72/68/67/76, average 70.75. Next
  target: AD account-management lifecycle ordering, with UDP/123/NTP contracts
  and built-in service-account profile paths queued behind it.
- Loop 202 fixed AD account-management lifecycle ordering by recording
  account-create effect times and delaying later same-host storyline commands
  and group-membership effects until after the prior AD audit effect is visible.
  Automated eval passed at 95.83680366637293 over 78514 records; the hard probe
  confirmed `net user`/4720 now precede `net group`/4728 for `svc_mhsync` in
  DC Security, Sysmon, and eCAR. Blind synthetic-confidence scores were
  68/76/72/74, average 72.50. Next target: canonical endpoint process/file
  ownership, especially service/kernel principals on user profile paths and
  Sysmon terminal-session inheritance.
- Loop 203 fixed service-principal endpoint profile artifacts and Sysmon
  terminal-session drift (`649fa9a6`). Automated eval passed at
  97.1909324170483 over 76333 records; the hard probe found zero service
  profile-path hits in eCAR/Sysmon, zero eCAR PID 4 interactive-profile
  contradictions, and zero Sysmon terminal-session drift cases. Blind scores
  were 68/55/44/72, average 59.75; deliberation final scores were
  72/66/50/76, average 66.00. Next target: eCAR process lifecycle ownership,
  especially module/process activity after native Security/Sysmon termination.
- Loop 204 fixed eCAR process lifecycle containment (`8f2881c2`, `2e9462a4`,
  `af62abd0`) by suppressing stale module loads after ended sessions, dropping
  or de-attributing stale eCAR process references after termination, and
  bounding parent/child termination repair so long-lived children do not drag
  parents hours forward. Automated eval passed at 96.7350560010721 over 78665
  records; the hard probe found zero eCAR modules, stale FLOW identities, or
  process terminates after matching Sysmon termination beyond the configured
  threshold. Blind scores were 47/64/35/52, average 49.50; deliberation final
  scores were 52/67/38/56, average 53.25. Next target: eCAR FILE
  source-native artifacts, especially Linux `/proc/<pid>/status` CREATE/WRITE
  rows and Windows Prefetch suffix morphology.
- Loop 205 fixed eCAR FILE source-native artifact pools (`2e86c4aa`) by moving
  Windows Prefetch templates to `{hex}` suffixes, removing generic Linux paths
  that could be paired with invalid churn actions, and adding `validate-config`
  guards for overlays. Automated eval passed at 96.83137893723699 over 76420
  records; the reviewer-finding probe confirmed zero decimal/non-hex Prefetch
  hits, zero Linux `/proc/<pid>/status` non-read hits, zero apache private-temp
  leaks, and zero service-principal `/etc/passwd` hits. Blind scores were
  42/38/64/63, average 51.75; deliberation final scores were 58/56/72/69,
  average 63.75. Next target: DNS source-native semantics, especially
  short-name/FQDN qtype behavior and resolver TTL modeling.
- Loop 206 fixed known internal DNS short-name semantics (`c95bd588`) by
  canonicalizing scenario host short names to internal FQDNs before resolver
  normalization and automatic lookup fan-out, and by rejecting MX owner context
  for single-label hostnames. Automated eval passed at 96.36440050584102 over
  78826 records; DNS probes confirmed zero internal short-name NOERROR rows,
  zero short-name MX rows, zero non-authoritative known internal FQDN rows, and
  zero public MX answers on internal names, with 7 remaining external RRset TTL
  increase cases inside 600 seconds. Blind scores were 28/36/68/66, average
  49.50; deliberation final scores were 58/61/72/70, average 65.25. The new
  highest-leverage target is TCP source-port lifecycle ownership: hard probes
  confirmed one same-sensor overlapping SMB 5-tuple in Zeek core and 32
  unmatched/stale eCAR FLOW examples after checking 9353 TCP flow rows.
- Loop 207 fixed SMB logon/transport ownership (`b7a9c0fa`) by binding
  companion Type 3 file-server logons to the just-emitted SMB transport source
  port and suppressing duplicate network evidence for that same session.
  Automated eval passed at 96.97058244405527 over 78480 records; hard probes
  confirmed zero same-sensor overlapping identical TCP tuple pairs and no
  recurrence of the loop-206 bad tuples. Valid blind scores were 48/30/34/33,
  average 36.25; deliberation final scores were 44/29/32/34, average 34.75.
  One initial detection review was discarded because the reviewer accidentally
  overwrote the frozen DC Security XML; the file was restored, data made
  read-only, and detection review rerun. The next target is texture rather than
  correctness: diversify Linux bash-history command pools by persona/role/host
  purpose and reduce exact-hour update/proxy/package traffic alignment.
- Loop 208 fixed exact Linux shell diagnostic repetition (`ca6ebca6`) by
  replacing broad exact diagnostic commands in the bash YAML pools, adding
  low-repeat command-family caps, and routing legacy activity-key shell commands
  through the shared command-memory selector. Automated eval passed at
  96.90138712062229 over 75650 records; rendered probes confirmed exact
  reviewer-cited command hits dropped from 30 in loop 207 to 1 in loop 208 and
  recent DNS/TCP tuple regression probes stayed clean. Blind scores were
  46/53/47/58, average 51.00. No deliberation was triggered because all
  reviewers agreed on Synthetic and score spread was small. The next
  highest-leverage target is Linux session semantics: reduce repeated named-user
  SSH fan-out across production Linux systems and eliminate unsupported generic
  eCAR `remote` successful sessions unless source-native SSH/PAM companion
  evidence exists.
- Loop 209 fixed Linux remote-session noise (`67bec768`) by keeping generic
  baseline Linux logon activity local/service, reducing organic SSH fan-out, and
  thinning ambient SSH noise while preserving SSH-bundle-owned remote sessions.
  Automated eval passed at 97.42953794362485 over 75679 records; rendered
  probes confirmed successful generic Linux `remote` eCAR sessions dropped from
  4 to 0 and successful SSH sessions dropped from 221 to 83. Blind scores were
  47/51/50/45, average 48.25. No deliberation was triggered because all
  reviewers agreed on Synthetic and score spread was small. The next
  highest-leverage target is multi-sensor Zeek timing texture: add per-sensor
  clock offset/drift, broader capture jitter, occasional missing companions, and
  packet-accounting variance.
- Loop 210 fixed multi-sensor Zeek timing texture (`f2b1c34b`) by widening
  flow-local sensor path-delay jitter inside configured timing bounds so
  duplicated core/DMZ observations no longer imply one fixed positive tap order.
  Automated eval passed at 97.42953794362485 over 75679 records; rendered probes
  showed paired core/DMZ conn offsets move from 1 negative / 2271 positive rows
  in loop 209 to 805 negative / 1467 positive rows in loop 210, with rounded
  offset buckets increasing from 25 to 91. Blind scores were 47/51/42/46,
  average 46.50. No deliberation was triggered because all reviewers agreed on
  Synthetic and score spread was small. The next highest-leverage target is
  Windows explicit-credential 4648 source/target semantics, with shell workflow
  texture close behind.
- Loop 211 fixed Windows explicit-credential 4648 source semantics (`c2c6a344`)
  by omitting synthetic local-host network endpoints from source-side 4648
  records while preserving authored modeled remote origins. Automated eval
  passed at 96.29214042141777 over 73942 records; the rendered probe showed
  loop 210 had 31/31 remote 4648 rows using the reporting host IP as
  `NetworkAddress`, while loop 211 had zero local-host-IP 4648 network
  addresses and only the authored attacker origin remained nonblank. Blind
  scores were 56/31/42/42, average 42.75. Deliberation was triggered by verdict
  disagreement and ended Inconclusive with final scores 50/38/42/44, average
  43.50. The next highest-leverage target is Windows remote-execution lifecycle
  texture, especially long-lived PsExec parentage and audit-log-clear 1102
  subject rendering.
- Loop 212 fixed Windows PsExec remote-execution lifecycle texture (`0ad5983c`,
  `b725f912`) by bounding `PSEXESVC.exe` lifetime, expiring stale PsExec service
  context, and emitting explicit wrapper termination. Automated eval passed at
  96.39589873896136 over 74657 records; the rendered probe showed loop 211 had
  8 PSEXESVC-parented child processes, 7 late children after two minutes, no
  termination, and 6 monitored later commands parented by PsExec, while loop
  212 had one immediate PsExec child, one termination, zero late children, and
  zero monitored later commands parented by PsExec. Blind scores were
  78/86/91/86, average 85.25. No deliberation was triggered because all
  reviewers agreed on Synthetic. The next highest-leverage target is endpoint
  source-native consistency, especially Windows Security channel `EventRecordID`
  monotonicity after log clear and eCAR FLOW/session/process lifecycle timing and
  identity pairing.
- Loop 213 fixed Windows Security channel `EventRecordID` monotonicity
  (`9ce3ad27`) by removing the renderer reset on Event ID 1102 while preserving
  the 1102 event. Automated eval passed at 96.39589873896136 over 74657 records;
  the rendered probe showed loop 212 had one non-increasing/decreasing Security
  record-ID transition on DC-01, from Event ID 4688 record `11619147` to Event
  ID 1102 record `2`, while loop 213 had zero non-increasing record IDs across
  7044 Security rows and still had one 1102 row. Blind scores were
  86/88/86/88, average 87.00. No deliberation was triggered because all
  reviewers agreed on Synthetic. The next highest-leverage target is
  source-observation realism for endpoint/network/proxy correlations: reduce
  same-second eCAR FLOW/Zeek/proxy completeness with realistic jitter, dropout,
  caching, and source-specific visibility gaps while preserving huntable pivots.
- Loop 214 fixed eCAR FLOW source-observation timing texture (`9895f149`) by
  widening the data-driven `source.ecar_flow` latency profile from 40-300ms to
  180-1800ms while preserving connection-interval clamps and remote-session FLOW
  ordering tests. Automated eval passed at 96.39580305774429 over 74653 records;
  the hard probe matched 13565 eCAR FLOW rows to Zeek tuples in both loop 213 and
  loop 214, with same-second matches dropping from 66.31% to 43.84%, within-one-
  second matches dropping from 99.42% to 70.61%, and p90 delta moving from
  0.573s to 1.649s. Blind scores were 68/64/67/74, average 68.25. No
  deliberation was triggered because all reviewers agreed on Synthetic and score
  spread was 10 points. The next highest-leverage targets are eCAR Linux
  local-session durability and file/process ownership, TLSv1.2 resumed-handshake
  consistency across `resumed`/`ssl_history`/certificate FUIDs, and Windows
  source-native texture for Defender paths and Sysmon `ProcessGuid` shape.

- Loop 215 fixed eCAR Linux local-session durability and generic Linux FILE
  ownership (`e8ea4deb`) by reusing active same-user local Linux sessions and
  removing Apache access-log paths from generic eCAR file churn. Automated eval
  passed at 96.58483954300257 over 69503 records; the hard probe showed
  `WS-LNGUYEN-01/lina.nguyen` successful local logins dropped from 12 to 1,
  max duplicate local-login groups dropped from 12 to 2, and generic
  `/var/log/apache2/access.log` FILE rows dropped from 24 to 0. Blind scores
  were 63/66/32/43, average 51.00; deliberation final scores were
  66/68/45/56, average 58.75. The next highest-leverage target is Linux shell
  pipeline process overlap: probe confirmed 10 of 10 visible two-stage pipeline
  commands had non-overlapping eCAR process lifetimes, with WEB-EXT LDAP stale
  endpoint/Zeek tuple ownership queued behind it.

- Loop 216 fixed eCAR Linux shell pipeline process concurrency (`fd786afc`) by
  grouping near-simultaneous same-shell foreground creates during eCAR timing
  normalization while preserving serialization for separate foreground
  commands. Automated eval passed at 96.58483954300257 over 69503 records; the
  hard probe showed visible two-stage pipeline non-overlap dropped from 10/10 in
  loop 215 to 0/10 in loop 216. Blind scores were 38/32/36/43, average 37.25.
  No deliberation was triggered because reviewers clustered in
  mostly-realistic, mixed, or inconclusive territory with an 11-point score
  spread. The next highest-leverage target is remote-session and receiver-side
  file-transfer ordering, especially RDP login-before-endpoint-flow and SCP
  receiver file-before-SSH/session evidence.

- Loop 217 fixed remote-session and receiver-side file-transfer ordering
  (`70351fe7`, `057db70b`) by clamping SSH/RDP target logins after matching
  inbound eCAR FLOW evidence, recording SSH session readiness for SCP receiver
  file timing, and making recent explicit SSH source-port reservations
  idempotent. Automated eval passed at 96.29905741773004 over 70577 records; the
  hard probe confirmed zero SCP file-before-readiness violations, shared
  source-port `57349` across Zeek/eCAR/syslog for the DB-to-APP SCP transfer,
  and zero RDP target-login-before-flow inversions, with one target-side RDP
  FLOW collection-gap note. Blind initial scores were 56/48/34/64, average
  50.50; deliberation was triggered by verdict disagreement and produced final
  scores 58/50/38/62, average 52.00. The highest-leverage next target is
  host-source texture: DC remote-admin command parentage through concrete
  execution owners and high-frequency Linux journald runtime-size filler.

- Loop 218 was a fresh post-merge `dev` assessment with no code changes in the
  loop. Automated eval passed at 96.29905741773004 over 70577 records. Blind
  initial scores were 43/43/68/64, average 54.50; deliberation was triggered by
  verdict disagreement and produced final scores 48/58/72/66, average 61.00.
  The dominant new finding is a DB-to-DC LDAP lifecycle contradiction: four
  DB-PROD-01 eCAR `ldapsearch` FLOW rows at 17:50-17:51 reused exact LDAP source
  ports that Zeek and DC endpoint telemetry already observed at 15:25-16:31.
  Secondary targets are RDP target Security 4624 evidence preceding target eCAR
  inbound FLOW for matching tuples, over-sampled Windows maintenance process
  texture, and the previously noted DC remote-admin command parentage.

- Loop 219 fixed stale endpoint FLOW process attribution by keeping eCAR FLOW
  rows bounded to canonical connection timing and dropping PID/actor attribution
  when the visible process create is too late to claim the flow. It also added a
  same-day exact 5-tuple reuse guard in the source-port allocator. Automated eval
  passed at 96.29905741773004 over 70577 records; the hard probe showed 5
  DB-PROD-01 to DC-01 LDAP eCAR FLOW rows, 5 matching Zeek rows, and zero late
  attributed exact-tuple matches over 60 seconds apart. Blind initial scores were
  62/44/28/68, average 50.50; deliberation produced final scores 64/52/36/70,
  average 55.50. The next highest-leverage target is Linux host/auth texture:
  per-host UID ownership collisions, overproduced `unattended-upgr` chatter, and
  excess direct `pam_unix(login:session)` local/root/admin sessions on servers.

- Loop 220 fixed the Linux host/auth texture family by assigning named Linux
  users non-default UID ranges, repairing same-host PAM UID collisions at syslog
  finalization, capping `unattended-upgr` filler to 8 rows per host/window, and
  reducing server local-console login noise. Automated eval passed at
  96.88614699870703 over 69207 records; the probe showed zero same-host PAM UID
  collisions, max 8 `unattended-upgr` rows per host, and sharply reduced server
  local login rows. Blind initial scores were 28/34/30/66, average 39.50;
  deliberation produced final scores 46/48/42/66, average 50.50. The next
  highest-leverage target is an APP-INT SSH lifecycle contradiction: a root SSH
  shell/session tied to `10.10.3.10:47995 -> 10.10.2.30:22` continued producing
  eCAR child process/logout evidence hours after the matching Zeek TCP/22 flow
  closed.

- Loop 221 fixed the Linux SSH storyline lifecycle family by preventing reuse of
  recorded SSH sessions after transport close, rejecting closed SSH shells for
  later process parents, extending SSH transports when future authored logoffs
  need the session to remain open, and preserving in-window storyline logoffs
  while clamping genuinely late logoffs to transport close. Automated eval
  passed at 96.44916777020666 over 76731 records; the probe showed the APP-INT
  root SSH FLOW, LOGIN, cleanup process, and LOGOUT all share a transport that
  remains open through the cleanup/logoff window. Blind initial scores were
  57/42/34/67, average 50.00; deliberation produced final scores 68/60/47/72,
  average 61.75. The next highest-leverage target is Windows outbound SMB
  network-logon ownership: client workstations emit local Type 3/self-IP logons
  and eCAR USER_SESSION rows for outbound SMB while the file server also records
  the correct remote Type 3 logon.

- Loop 222 fixed human Windows Type 3 network-logon source ownership by making
  ambient/direct successful Type 3 logons choose a real remote source when the
  environment inventory supports it, or downgrade to local interactive semantics
  instead of fabricating a human self-IP/port-0 network session. It also removed
  the successful Type 3 `NtLmSsp`/`Negotiate`/`LmPackageName=-` auth tuple in
  favor of NTLM V2. Automated eval passed at 96.9222107992763 over 72722
  records; hard probes found zero human/admin successful Type 3 self-IP
  `IpPort=0` rows and zero human eCAR Type 3 `USER_SESSION LOGIN` rows with
  `src_ip:"-"`. Blind scores were 48/36/49/46, average 44.75; no deliberation
  was triggered because all reviewers returned Inconclusive. Next targets are
  TLS/X.509 CA-chain validity bounds, endpoint collection timing texture, and
  broader scenario/noise messiness.

- Loop 223 fixed TLS/X.509 chain-validity contradictions by correcting public
  CA authority profiles so configured intermediates no longer outlive their
  roots, moving Cloudflare ECC issuance under the configured Cloudflare ECC
  root, adding config validation for child-CA windows versus parent issuer
  windows, and clamping generated leaf/intermediate validity to configured
  issuer validity. Focused cert/config tests, Ruff checks, and
  `uv run eforge validate-config` passed. Automated eval stayed at
  96.9222107992763 over 72722 records; the hard probe found 718 rendered
  X.509 rows and zero parent-window violations. Blind scores were 42/39/43/45,
  average 42.25, all Inconclusive; network forensics explicitly called TLS
  varied and credible. Next targets are source-native network byte/accounting
  texture, especially NTP payload sizing, DHCP byte-size invariance, and one
  HTTP response-body total exceeding Zeek connection payload accounting.

- Loop 224 fixed source-native network byte/accounting texture by clamping
  NTP payload accounting to realistic UDP/123 message sizes, varying DHCP
  request/response payload buckets by host and message type, and making Zeek
  connection accounting honor flow-level HTTP body totals for reused HTTP UIDs.
  Focused NTP/DHCP/HTTP body-floor tests and Ruff checks passed. Automated eval
  stayed at 96.9222107992763 over 72722 records; hard probes found NTP payloads
  bounded to 144/124 bytes, 28 distinct DHCP byte-size buckets across 28 rows,
  and zero HTTP body-budget violations. Initial blind scores were 66/35/62/42,
  average 51.25; deliberation was triggered by mixed verdicts and a 31-point
  spread, producing final scores 68/48/64/52, average 58.00. The strongest next
  target is HTTP binary-transfer realism: successful `.msi`/`.zip` proxy/Zeek
  downloads rendered as `200 application/octet-stream` with only 23-38 KB
  bodies and no coherent Zeek file-transfer evidence.

- Loop 225 fixed HTTP binary-transfer realism by teaching shared HTTP content
  helpers to infer installer/archive/package MIME types from `.msi`, `.msp`,
  `.zip`, `.deb`, and `.rpm` paths and size them at download scale. Focused
  HTTP helper and explicit-proxy file-transfer tests plus Ruff checks passed.
  Automated eval passed at 96.77569096689754 over 72405 records; hard probes
  found 6 MSI/ZIP-style HTTP rows, zero tiny successful binary-body violations,
  zero missing `resp_fuids` references, 2 proxy binary rows, and zero tiny proxy
  binary rows. Initial blind scores were 38/61/42/68, average 52.25;
  deliberation was triggered by mixed verdicts and a 30-point spread, producing
  final scores 46/64/48/70, average 57.00. The next highest-leverage target is
  Linux interactive session ownership/timing: `WS-LNGUYEN-01` developer
  workflows are anchored to cron/local session semantics with near-zero
  shell-to-command think time and short editor lifetimes. Public PTR realism is
  next behind it.

- Loop 226 fixed Linux interactive session ownership/timing by preventing
  syslog logind PAM backfill from labeling human local sessions as cron,
  adding shell-readiness gaps before first foreground children, and treating
  Linux `code`/`codium` launches as long-lived GUI editors rather than
  short-lived foreground commands. Focused syslog/activity/world-model tests,
  scenario validation, Ruff checks, and rendered probes passed. Automated eval
  passed at 96.47672953376664 over 72989 records; hard probes found zero human
  `cron:session` PAM opens, a minimum human shell-to-child gap of 11806 ms
  across 82 pairs, and zero short `code` terminations. Initial blind scores
  were 66/55/42/67, average 57.50; deliberation produced final scores
  70/62/48/72, average 63.00. The next highest-leverage target is the sibling
  Linux SSH endpoint ownership defect: outbound TCP/22 client flows on Linux
  hosts are attributed to long-running `sshd` listener PIDs instead of
  `/usr/bin/ssh`, `/usr/bin/scp`, or the invoking shell.

- Loop 227 fixed the sibling Linux SSH endpoint ownership defect by
  materializing source-side `/usr/bin/ssh` or `/usr/bin/scp` processes for SSH
  bundle transports and suppressing generic Linux outbound TCP/22 attribution to
  local `sshd` listener PIDs when no explicit client process is known. Focused
  SSH/world-model/activity tests, scenario validation, Ruff checks, and rendered
  probes passed; the hard probe found 101 outbound TCP/22 flows, zero `sshd`
  owner hits, and 34 explicit ssh/scp client-owned rows. Automated eval passed
  at 96.74526439145288 over 76230 records. Initial blind scores were
  62/61/43/62, average 57.00; deliberation final scores were 63/64/45/66,
  average 59.50. The next highest-leverage targets are Windows source-native
  metadata and coverage texture: Security/Sysmon `EventRecordID` gap bands,
  outbound-only 5156 direction coverage, and Sysmon/Security process timing
  bias.

- Loop 228 fixed Windows Security/Sysmon `EventRecordID` texture by replacing
  bounded renderer gap buckets with a shared per-host/per-channel sequence model
  that includes elapsed-time hidden activity, mid-range gaps, and occasional
  large filtered-channel jumps. Focused record-ID/emitter tests, Ruff checks,
  scenario validation, generation, and rendered probes passed; the rendered
  probe found Security now has 1946 gaps in the 9-40 range, 280 gaps over 200,
  and max gap 17933, while Sysmon has 925 gaps in the 9-40 range, 155 gaps over
  200, and max gap 7407. Automated eval passed at 96.74526439145288 over 76230
  records. Initial blind scores were 64/42/38/43, average 46.75; deliberation
  final scores were 58/44/40/46, average 47.00. No reviewer repeated the prior
  EventRecordID finding. The next highest-leverage target is a concrete
  web/endpoint contract gap: add source-native web-access precursor evidence
  around service-user reverse-shell process creation, with eCAR/Sysmon timing
  texture next behind it.

- Loop 229 first hard-probed the loop-228 web/endpoint precursor claim and
  found it was a false positive: `WEB-EXT-01` has a same-second
  `POST /ehr/admin/upload.php` web-access row for the service-user reverse-shell
  process creation. The loop then fixed the verified eCAR/Sysmon process-create
  timing texture by widening `source.ecar_after_sysmon_process_create_gap` in
  the data-driven timing profile. Focused timing/config tests, Ruff checks,
  config validation, scenario validation, generation, and rendered probes
  passed; the hard probe moved exact Sysmon/eCAR process-create deltas from a
  loop-228 median of 0.28s and max 1.45s to a loop-229 median of 1.81s, p90
  3.25s, and 136 matches over 3s while preserving ordering. Automated eval
  passed at 96.83950751584356 over 75311 records. Initial blind scores were
  46/67/74/64, average 62.75; deliberation final scores were 62/70/76/68,
  average 69.00. The timing fix was not criticized; reviewers instead converged
  on a new highest-leverage hard contradiction: proxy-origin TLS byte/packet
  accounting diverges from ASA teardown bytes for same tuples, with Linux
  journald filler, public IP role reuse, repeated Windows maintenance/RDP
  density, and polished intrusion-path texture queued behind it.

- Loop 230 fixed proxy-origin TLS byte/packet accounting by sizing canonical
  TLS transport bytes from HTTP flow-level request/response body budgets and
  updating connection state after TCP SF normalization. Focused activity tests,
  Ruff checks, scenario validation, generation, and rendered probes passed; the
  hard probe moved large Zeek-greater-than-ASA mismatches from 75 to 0 and bad
  payload-per-packet rows from 34 to 0 across matched teardowns. Automated eval
  passed at 95.35415427133147 over 80189 records. Initial blind scores were
  64/38/34/55, average 47.75; deliberation final scores were 67/44/38/60,
  average 52.25. The previous hard proxy/TLS accounting contradiction was not
  repeated. The next highest-leverage targets are behavioral texture: large
  upload endpoint staging evidence, dense regular-user RDP/DC sessions, generic
  Linux/eCAR temp paths, exact-hour proxy bursts with inconsistent User-Agent
  families, and overly clean network collection.

- Loop 231 fixed dense baseline RDP session texture by capping domain-controller
  RDP noise to one considered session per hour, sorting candidate sessions
  chronologically, selecting the source workstation up front, and applying a
  same source/user/target cooldown keyed to the actual materialized session
  start. Focused RDP tests, Ruff checks, scenario validation, generation, and
  rendered probes passed; the hard probe moved `mstsc.exe` creates from 38 to
  14, DC-01 targets from 27 to 7, and the maximum two-minute
  same-source/user/target cluster from 5 to 1. Automated eval passed at
  96.6902301042063 over 74252 records. Initial blind scores were 47/38/31/34,
  average 37.50; deliberation final scores were 44/40/34/36, average 38.50.
  The prior RDP/DC tell was inverted into positive host evidence. The next
  highest-leverage targets are Security 1102 native EventData, operational
  roughness around the `svc_mhsync` attack path, host-specific sysstat/cron and
  top-of-hour scheduling texture, and eCAR FLOW actor semantics.

- Loop 232 fixed the verified Linux sysstat CRON cadence tell by honoring
  configured `slot_jitter_seconds` for cron schedules while keeping
  unconfigured cron schedules minute-aligned. Focused scheduler tests, Ruff,
  config validation, scenario validation, generation, and rendered probes
  passed; the probe moved sysstat rows at second `00` from 66/66 in loop 231 to
  2/66 in loop 232, with zero exact half-hour boundary rows. Automated eval
  passed at 96.52362201870753 over 75598 records. Blind scores were
  61/57/58/49, average 56.25, with no deliberation because all reviewers agreed
  on Synthetic and the score spread was 12. The next highest-leverage targets
  are broad SSH/admin access and scenario roughness, Windows remote-exec/service
  staging semantics, public web-client persona stability plus DNS TTL texture,
  and endpoint software inventory/registry churn. A full non-slow pytest run
  still had unrelated broader failures in existing storyline/session, TLS-chain,
  nmap, baseline failure-rate, and foreground-process timing tests.

- Loop 233 fixed generic external web-client persona instability by reserving
  scanner/authored external source IPs away from ordinary baseline web clients
  and making external visitor profile selection sticky per source IP. Focused
  web-access tests, Ruff, config validation, scenario validation, generation,
  and rendered probes passed; the probe moved generic mixed external web-client
  IPs from 8 in loop 232 to 0 in loop 233, with the only remaining mixed source
  being authored storyline IP `185.70.41.45`. Automated eval passed at
  97.17049896473532 over 74239 records. Blind scores were 58/64/32/63, average
  54.25. Network review improved to Mostly realistic with no hard network
  contradictions; the next highest-leverage target is Linux eCAR attaching
  privileged apt/dpkg file writes to non-root daemon principals, followed by
  Windows utility runtimes, Linux eCAR pid/tid texture, SSH eCAR session tuple
  symmetry, repeated LDAP discovery commands, and polished attack-storyline
  semantics.

- Loop 234 fixed Linux eCAR privileged package-state ownership by removing
  package-manager state paths from generic Linux FILE churn and filtering
  root-owned apt/dpkg/dnf paths away from non-root principals in the
  process-aware side-effect helper. Focused EDR/config tests, Ruff, config
  validation, scenario validation, generation, and rendered probes passed; the
  probe moved non-root privileged package FILE events from 17 in loop 233 to 0
  in loop 234. Automated eval passed at 97.09115240170016 over 74508 records.
  Initial blind scores were 31/29/44/37, average 35.25; deliberation final
  scores were 38/36/47/39, average 40.0. Detection and Host/EDR both flipped to
  Real and the previous apt/dpkg contradiction was not repeated. The next
  highest-leverage target is public-domain HTTP/proxy protocol policy plus
  host-role constraints for workstation-style proxy/update traffic on server
  roles, followed by SSH command-to-flow timing, eCAR principal/timing texture,
  bash-history monotonicity, scanner cadence, and Windows utility lifetimes.

- Loop 235 fixed public-domain HTTP/proxy protocol policy and host-role
  constraints for workstation-style proxy/update traffic by adding
  source-system-type filtering to proxy URI, DNS, TLS, world-model, and
  baseline destination selection, marking workstation update/sync domains as
  workstation-only, and applying HTTPS-first plaintext redirect policy before
  explicit proxy routing. Focused proxy/domain/config tests, Ruff checks,
  config validation, scenario validation, generation, and rendered probes
  passed; the hard probe moved HTTPS-first plaintext HTTP `200` responses from
  53 in loop 234 to 0 in loop 235 and DC-originated consumer/update proxy rows
  from 22 to 0. Automated eval passed at 95.46721057150579 over 86450 records.
  Initial blind scores were 56/38/63/32, average 47.25; deliberation final
  scores were 60/45/65/42, average 53.0. The targeted public-HTTP/DC-role
  defects were not repeated. The next highest-leverage target is binding
  OCSP/certificate revocation status to proxy/TLS inspection outcomes so
  revoked certificate evidence cannot coexist with repeated clean
  SSL-inspected HTTP `200` responses unless policy-exception telemetry explains
  the outcome; proxy endpoint identity semantics are the next sibling target.

- Loop 236 fixed the OCSP/proxy revocation contradiction by allowing successful
  HTTP-backed TLS activity to suppress revoked OCSP statuses and by suppressing
  mainstream Adobe telemetry revocation false positives in TLS realism config.
  Focused OCSP tests, Ruff checks, config validation, scenario validation,
  generation, and rendered probes passed; the hard probe moved revoked
  `assets.adobedtm.com` leaf evidence and clean SSL-inspected `200` responses
  for revoked hosts from present in loop 235 to zero in loop 236. Automated eval
  passed at 95.46721057150579 over 86450 records. Blind scores were
  56/47/69/68, average 60.0, with no deliberation because all reviewers agreed
  on Synthetic and the score spread was 22. The targeted OCSP/proxy defect was
  not repeated. The next highest-leverage target is the hard endpoint/network
  causality contradiction where eCAR `FLOW` rows and process attribution can
  appear after the matching Zeek tuple has already started or closed; Windows
  Security/Sysmon `EventRecordID` hidden-volume pairing realism is the next
  close target.

- Loop 237 fixed the hard eCAR/Zeek endpoint-network causality contradiction by
  keeping eCAR `FLOW/CONNECT` rows at network-observation time and dropping
  unsafe process identity when visible process timing would require shifting the
  flow after the matching Zeek tuple close. It also prefers stable SSH/RDP
  listener PIDs for inbound transport ownership instead of late per-session
  child PIDs. Focused eCAR/source-timing tests, Ruff checks, scenario
  validation, generation, hard probes, and automated eval passed. The hard probe
  moved identified process-create-after-Zeek-close cases from 6 in loop 236 to
  0 in loop 237, while process-create-after-Zeek-start cases dropped from 41 to
  4 and remained inside open intervals. Automated eval passed at
  95.46721057150579 over 86450 records. Initial blind scores were 52/34/24/44,
  average 38.5; deliberation final scores were 48/34/30/44, average 39.0.
  Network flipped to Real before deliberation and explicitly found no impossible
  endpoint/network ordering. The next highest-leverage target is Linux
  bash-history/session alignment: commands for `lina.nguyen` continue after all
  visible SSH sessions close on `DB-PROD-01` and `WEB-EXT-01`; Windows inbound
  endpoint network telemetry is the next broad source-shape target.

- Loop 238 fixed Linux bash-history/session alignment by fitting bash-history
  timestamps into concrete visible Linux sessions, suppressing commands that
  cannot be owned by an active/recent session, updating Linux SSH client session
  activity, and extending Linux SSH baseline sessions through the hour they
  serve. Focused activity/world-model tests, Ruff checks, scenario validation,
  generation, hard probes, automated eval, and the full `uv run pytest --no-cov`
  suite passed. The hard probe found 202 checked bash commands with zero outside
  syslog/eCAR session intervals. Automated eval passed at 95.808647580328 over
  83833 records. Initial blind scores were 62/66/46/64, average 59.5;
  deliberation final average was 62.5. Host/EDR explicitly called Linux SSH
  ordering a strength. A sidecar read-only scenario-authoredness review found
  recurring Threat Hunter feedback clusters around textbook linear kill chain,
  compressed six-hour window, analyst-readable artifacts, low operator friction,
  and bounded background entropy; scenario edits are deferred per user request.

- Loop 239 fixed Windows process lifecycle and Security/Sysmon process-create
  source timing by coupling Security 4688 to the matching Sysmon Event 1 through
  source timing constraints and replacing hour-centered Windows stale-process
  cleanup with application-class bounded/heavy-tailed lifetimes. Focused tests,
  Ruff checks, scenario validation, generation, hard probes, automated eval, and
  the full `uv run pytest --no-cov` suite passed with 3916 passed and 18 skipped.
  The hard probe moved Security-before-Sysmon process-create inversions from
  226 in loop 238 to 0 and over-1000ms process-create gaps from 459 to 0.
  Automated eval passed at 96.33355975624633 over 84473 records. Blind scores
  were 58/35/56/42, average 47.75, with no deliberation because all reviewers
  returned Inconclusive. The next highest-leverage target is public external IP
  role separation across scanner pools, benign destinations, NTP/STUN, and
  suspicious direct-IP activity; Windows endpoint inbound/egress collection
  asymmetry and eCAR session-before-flow timing are close follow-ups.

- Loop 240 fixed public external IP role separation by routing baseline outbound
  IDS false-positive destinations through a deterministic outbound-destination
  pool that excludes external scanner IPs, explicit external storyline sources,
  and public NTP IPs. Focused baseline/network tests, Ruff checks, scenario
  validation, generation, automated eval, and the full `uv run pytest --no-cov`
  suite passed with 3917 passed and 18 skipped. The hard probe moved
  scanner/destination collisions from 7 in loop 239 to 0. Automated eval passed
  at 95.94966202503336 over 82736 records. Blind scores were 68/72/32/74,
  average 61.5. Network Forensics scored Realistic and explicitly praised role
  consistency and proxy pivots; Threat Hunter and Detection Engineering again
  centered scenario-authoredness (textbook kill chain, signposted C2/exfil,
  clean domain-compromise sequence). Host/EDR found the next engine target:
  Linux eCAR source-native semantics, especially `pid == tid`, row-level
  principal visibility toggling for the same daemon/PID, and a remaining
  bash-history/session ownership gap.

- Loop 241 fixed Linux eCAR source-native semantics by varying Linux TIDs
  instead of mirroring PID for almost every event, making FLOW principal
  visibility stable for the same host/process/direction, preserving rebased
  PID/TID morphology, and suppressing unowned Linux server SSH-client or
  bash-history evidence in full scenario generation. Focused eCAR/activity
  tests, Ruff checks, scenario validation, generation, automated eval, and the
  full `uv run pytest --no-cov` suite passed with 3923 passed and 18 skipped.
  The hard probe moved Linux `pid == tid` rows from 100.0% in loop 240 to 6.5%,
  FLOW principal toggle groups from 27 to 0, all bash-history outside visible
  eCAR sessions from 25 to 17, and SSH/SCP bash-history outside visible eCAR
  sessions from 6 to 4. Automated eval passed at 95.37754385363799 over 78485
  records. Blind scores were 34/32/30/38, average 33.5, with all four reviewers
  scoring Realistic. Next highest-leverage target is perimeter scan service/role
  consistency, especially successful public DNS/PostgreSQL-style probes against
  WEB-EXT without matching service/protocol/host evidence. IDS/application
  detection richness and endpoint software inventory lifecycle are strong
  follow-ups. Scenario-authoredness findings remain deferred per user request.

- Loop 242 fixed perimeter scan service/role consistency by making baseline
  inbound IDS false-positive companions and authored external port-scan
  expansion honor public service exposure and firewall deny policy. Unpermitted
  or unexposed public TCP ports now render as denied, reset, or no-response
  traffic instead of successful handshakes with invented services. Focused
  baseline/storyline tests, Ruff checks, scenario validation, generation,
  automated eval, hard probes, and the full `uv run pytest --no-cov` suite
  passed with 3927 passed and 18 skipped. The hard probe moved successful
  external inbound handshakes to unpermitted public `WEB-EXT` ports from 7 in
  loop 241 to 0, TCP/53 successful probe rows without parsed DNS companions
  from 2 to 0, and ASA successful teardowns for those unpermitted ports from 7
  to 0. Automated eval passed at 96.17723878448457 over 79418 records. Blind
  scores were 31/34/34/55, average 38.5. The targeted public-service exposure
  issue did not recur; Network Forensics instead called out proxy
  User-Agent/domain binding and narrow ASA/Snort texture. The next
  highest-leverage target is eCAR FILE/REGISTRY/FLOW source-native provenance
  and source-observation asymmetry across Security/Sysmon/eCAR. Scenario
  staging/polish findings remain deferred per user request.

- Loop 243 fixed eCAR FILE/REGISTRY/FLOW source-native provenance by copying
  known process image and command line from canonical `ProcessContext` onto
  dependent eCAR rows when process identity is timing-safe, while preserving
  stale-flow identity scrubbing. Focused eCAR tests, Ruff checks, scenario
  validation, generation, automated eval, hard probes, and the full
  `uv run pytest --no-cov` suite passed with 3929 passed and 18 skipped. The
  hard probe moved PID-bearing eCAR image-path coverage for FILE, REGISTRY, and
  FLOW from 0% in loop 242 to 100% in loop 243; command-line coverage reached
  98.03% for FILE, 100% for REGISTRY, and 92.15% for FLOW. Automated eval
  passed at 96.78792550789055 over 79418 records. Blind scores were
  68/72/31/47, average 54.5 under the stricter full briefing. The targeted
  provenance gap improved, but Threat Hunter and Detection Engineering surfaced
  a sharper source-native ownership defect: proxy HTTP flows with apt/curl/wget/
  python/browser User-Agents are attributed to incompatible processes such as
  `/bin/bash`, `git status`, Webex, or Slack. That process-to-proxy ownership
  family is the next highest-leverage target. Linux journald filler volume is
  the next host texture target. Scenario-authoredness remains deferred per user
  request.

- Loop 244 fixed explicit-proxy endpoint process ownership by making the proxy
  transaction / network action path replace or scrub incompatible source-side
  process identity for browser, package-manager, curl/wget, python, Java, Go,
  and PowerShell User-Agent families, and by scoping CONNECT tunnel reuse by
  User-Agent. Focused explicit-proxy tests, Ruff checks, scenario validation,
  generation, automated eval, hard probes, and the full `uv run pytest --no-cov`
  suite passed with 3938 passed and 18 skipped. The corrected hard probe
  matched only source-side `OUTBOUND` eCAR FLOW rows to Zeek HTTP proxy tuples
  and found 0 incompatible process owners across 2120 matched outbound proxy
  rows; 1913 rows carried compatible process identity and 207 safely omitted
  process identity. Automated eval passed at 96.89339473777208 over 78405
  records. Blind scores were 37/34/38/62, average 42.75. The targeted
  proxy-process defect did not recur; Threat Hunter and Detection Engineering
  both moved to Inconclusive. The next highest-leverage engine target is Sysmon
  `ProcessGuid` morphology, with DNS TTL/rtt texture and eCAR logout context as
  close follow-ups. Scenario-authoredness remains deferred per user request.

- Loop 245 fixed Sysmon `ProcessGuid` morphology in the Sysmon emitter while
  preserving stable process correlation across Event 1/3/5/7/8/10/11/13/22.
  Focused Sysmon ProcessGuid tests, broader Sysmon/Snare tests, Ruff checks,
  scenario validation, generation, automated eval, hard probes, and the full
  `uv run pytest --no-cov` suite passed with 3938 passed and 18 skipped. The
  hard probe moved UUID-like/random-tail Sysmon process GUID references from
  5313 in loop 244 to 0 in loop 245, with 5313 native-shape references and all
  792 Event 1 timestamp-word matches preserved. Automated eval passed at
  96.89339473777208 over 78405 records. Blind scores were 54/76/36/38, average
  51.0. The targeted Sysmon GUID morphology issue did not recur; Host/EDR moved
  from Synthetic at 62 to Inconclusive at 38. The next highest-leverage engine
  target is cross-source process lifecycle ordering, where Detection Engineering
  found a DC-01 `python.exe` Security 4689 termination before later same-guid
  Sysmon Event 3 telemetry, and Threat Hunter found related eCAR remote-thread
  evidence trailing attacker process termination. Scenario-authoredness remains
  deferred per user request.

- Loop 246 fixed cross-source Windows process lifecycle ordering by extending
  the Windows Security lifecycle fixup so Security 4689 process terminations
  render after later same-process WFP 5156 dependents in both buffered and
  spooled paths. Focused Windows lifecycle tests, broader Windows/timing tests,
  config validation, Ruff checks, scenario validation, generation, automated
  eval, hard probes, and the full `uv run pytest --no-cov` suite passed with
  3940 passed and 18 skipped. The hard probe moved Security 4689 before later
  same-process WFP 5156 from 1 in loop 245 to 0 in loop 246, and Security 4689
  before later same-process Sysmon dependent from 1 to 0. Automated eval passed
  at 96.89339473777208 over 78405 records. Blind scores were 66/64/48/76,
  average 63.5. The targeted lifecycle contradiction was fixed, but reviewers
  surfaced deeper remaining source-native issues: Windows remote-admin commands
  directly parented by `services.exe`, Linux SSH/session foreground child
  lifecycle ordering, eCAR remote-session `src_port` asymmetry, and endpoint
  FLOW exact-millisecond pair timing. Scenario-authoredness remains deferred per
  user request.

- Loop 247 fixed Windows remote-admin process parentage by adding a concrete
  short-lived SYSTEM `cmd.exe /c ...` owner for later service-context admin
  utilities while preserving live `PSEXESVC.exe` ownership for immediate
  PsExec follow-on commands and preserving the guard that old PsExec services do
  not own unrelated later commands. Focused parentage tests, broader
  remote-admin/service tests, config validation, Ruff checks, scenario
  validation, generation, automated eval, hard probes, and the full
  `uv run pytest --no-cov` suite passed with 3941 passed and 18 skipped. The
  hard probe moved DC-01 Security 4688 direct-`services.exe` parentage for
  `net.exe`, `sc.exe`, `schtasks.exe`, and `wevtutil.exe` from 6/6 in loop 246
  to 0/6 in loop 247, with all six now parented by concrete shell owners.
  Automated eval passed at 96.84452779117338 over 78635 records. Blind scores
  were 42/36/36/34, average 37.0, all Inconclusive; no deliberation triggered.
  Remaining highest-leverage targets are now mostly Linux bash/syslog texture,
  eCAR SSH `USER_SESSION LOGIN` `src_port` symmetry, Zeek NTP service/log
  fan-out, and scenario/storyline polish. The 10-loop batch is complete, and
  scenario updates are still deferred until explicitly authorized.

- Loops 248-257 continued the current-dev blind realism loop on
  `scenarios/iteration-test`. The batch fixed eCAR SSH login/logout source-port
  symmetry, public DNS PTR/MX/NS/SOA realism, SSH receiver-side lifecycle,
  forward-proxy daemon identity, DNS answer/packet accounting, Windows Security
  5156 inbound directionality, firewall deny path ownership, paired endpoint
  eCAR FLOW millisecond texture, and Windows Security unavailable endpoint port
  rendering. Loop 256 moved exact same-ms cross-host eCAR FLOW pairs from 1804 to
  125 and scored 38/38/34/36, average 36.5. Loop 257 moved Windows
  address-dash/port-zero pairs from 322 to 0 and scored 32/63/34/46, average
  43.75; Detection's high score came from public DNS answer ownership rather
  than recurrence of the fixed Windows port issue. Highest-leverage remaining
  targets are recognizable public DNS answer ownership, generic Linux eCAR
  `/tmp/.cache-*` daemon file side effects, bash-history command-pool diversity,
  and source-side SCP flow attribution.

- Loops 258-267 continued the current-dev bounded assessment loop on
  `scenarios/iteration-test` without subagents. The batch fixed public DNS
  NS/MX/SOA answer ownership, Linux daemon eCAR file side-effect pools,
  source-side SSH/SCP command texture and file attribution, public AAAA profile
  ownership, upload source-prep/file-read evidence, Linux operator shell
  friction, NTP service/analyzer fan-out with public NTP pool selection, Nikto
  web-scan method diversity, and external port-scan event-presence matching for
  reset/allowed probe evidence. Loop 267 passed at 97.11049764410731 over
  81803 records with Event Presence at 35/35 and Storyline Trace Coverage at
  49/49. Focused tests, config validation, scenario validation, deterministic
  generation, eval, Ruff checks, and the full `uv run pytest --no-cov` suite
  passed with 3983 passed and 18 skipped. The next highest-leverage assessment
  target is now remaining indicator accuracy and pivot linkability: inspect the
  59 indicator misses and 10 non-pivotable consecutive storyline pairs before
  deciding whether to fix canonical evidence or scenario-authoredness.
  A follow-up standalone blind panel was then run against a data-only copy of
  the current loop-267 output. Reviewer synthetic-confidence scores were Threat
  Hunter 42, Detection Engineer 28, Network Forensics 31, and Host/EDR
  Forensics 34, for an average of 33.75. Three reviewers assessed the data as
  Real and one as Inconclusive. Residual reviewer-backed targets are stable
  byte lengths for repeated hashed/static web assets, explicit/observable
  collection texture for small ASA-to-Zeek visibility misses, and tighter Linux
  eCAR SSH/SCP receiver process lifecycle pairing.

## Recent Completed Work Previously Kept in TODO

- Codex fix-family PR disposition and rework completed: rejected PRs were closed
  with rationale, acceptable PRs were merged, and accept-with-changes PRs were
  reworked.
- Full slow-suite regression cleanup completed after the recent fix-family work.
  The successful recorded run was `uv run pytest --no-cov --include-slow` with
  `3771 passed, 2 skipped`.
- Earlier assessment work completed many source-native realism fixes across
  Kerberos/DC evidence, X.509/DNS/TLS, eCAR/session/FLOW ownership, Linux
  syslog/bash texture, proxy/browser semantics, Zeek HTTP reuse, and Windows
  process/session timing.

## How to Continue

1. Start from the current `dev` state and read `TODO.md` for durable priorities.
2. Select the next assessment target from the latest verified blind-review or
   hard-probe findings.
3. Fix the owning layer, not an emitter symptom, unless the defect is truly
   source-local rendering.
4. Verify with focused tests, `uv run eforge validate-config`, Ruff checks, and
   normal `uv run pytest --no-cov` unless the loop specifically requires slow
   coverage.
5. Record only the concise loop outcome, next target, and validation result here.

## References

- `TODO.md` keeps the durable backlog.
- `CHANGELOG.md` keeps release history.
- Loop artifacts should remain in their scenario or temporary assessment output
  directories and be referenced here when needed.
