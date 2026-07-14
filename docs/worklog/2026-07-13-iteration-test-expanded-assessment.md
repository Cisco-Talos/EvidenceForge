# Iteration-Test-Expanded Assessment Continuation

## Scope

The initial request covered ten iterative realism fix loops against
`scenarios/iteration-test-expanded/scenario.yaml`, preserving prior artifacts and
writing new results under `scenarios/iteration-test-expanded/blind-test/loop-N/`.
Each loop selects concrete blind-review evidence, fixes the highest owning layer,
verifies a sibling path, regenerates, evaluates, and runs a standalone blind panel.

After stopping at loop 62, the user requested ten additional loops. The active continuation is
loops 63-72 against the same expanded scenario.

## Loop 62 Family Contract

- **Selected family:** Zeek TLS resumption, handshake-history, and certificate fan-out
  coherence.
- **Finding classification:** `sibling_defect` in the existing canonical TLS/X.509 family.
- **Owning abstraction:** the shared TLS handshake-history sampler and canonical TLS context
  construction in `ActivityGenerator`.
- **Invariant:** `SslContext.resumed` must agree with the Zeek `ssl_history` handshake messages.
  Abbreviated TLS 1.2 and PSK-style TLS 1.3 histories must not contain certificate or full key
  exchange messages, while non-resumed handshakes must not use abbreviated-session histories.
  Resumed sessions must continue to omit fresh certificate/file/x509 fan-out.
- **Entry paths:** ordinary TLS connections, explicit-proxy origin TLS, inbound TLS, SMTP
  STARTTLS, and any caller that uses `_choose_ssl_history()` or `_attach_ssl_context()`.
- **Consumers:** Zeek `ssl.json`, `files.json`, and `x509.json`; automated correlation checks;
  network-forensics review; TLS hard probes.
- **Layer rationale:** the contradiction is created when canonical `SslContext` fields are
  sampled, before Zeek rendering. The emitter correctly serializes the supplied values and the
  certificate builder correctly omits chains for resumed sessions, so an emitter patch would
  preserve the inconsistent source truth.
- **Sibling risks:** this fix covers both TLS 1.2 and TLS 1.3 plus SMTP STARTTLS. It does not
  attempt to model every Zeek handshake-history permutation, TLS renegotiation, decrypted TLS
  1.3 certificate visibility, or packet-loss-driven partial histories.

## Loop 62 Outcome

- **Commit:** `72f9b86e fix: align TLS history with session resumption`
- **Verification:** focused TLS/Zeek/SMTP tests passed; full default suite passed with 4,888 tests
  and 19 skips; Ruff lint/format and configuration/scenario validation passed.
- **Generation:** 96,398 records from `iteration-test-expanded`.
- **Automated evaluation:** 95.90804086572041, PASS across all hard gates.
- **Targeted hard probe:** 1,888 established SSL rows, 0 resumption/history/certificate contract
  violations. The loop 61 defect did not recur in blind review.
- **Blind panel:** Threat Hunter 63, Detection Engineer 84, Network Forensics 88, Host/EDR 89;
  average 81.0. All verdicts were Synthetic, so deliberation was not triggered; score spread was
  26 points.
- **Highest new root contracts:** universal sudo authorization/PAM inversion; DMZ DNS RTT versus
  connection-duration divergence; unstable per-host IRQ identity; impossible rsyslog socket
  reacquisition; Security EventRecordID continuity after channel clear; broad symmetric
  Security/Sysmon occurrence jitter; and cross-sensor accounting jitter without modeled loss.
- **Artifacts:** `scenarios/iteration-test-expanded/blind-test/loop-62/REPORT.md` and
  `scores.json` contain the complete synthesis and owning-layer recommendations.

## Stop Point

The user requested that the run stop at the end of loop 62. Loops 63-71 were not started. The
highest-leverage next effort, if resumed, is a family-level lifecycle/state correction selected
from the P0 contracts in the loop 62 report; do not patch those defects as isolated emitter text.

## Loop 63 Family Contract

- **Selected family:** Linux sudo authorization/PAM session lifecycle ordering.
- **Finding classification:** `new_family` within Linux/syslog session semantics.
- **Owning abstraction:** a Linux sudo session action bundle that owns the multi-event lifecycle,
  with the syslog finalizer acting only as a source-local ordering guard after observation timing.
- **Invariant:** every allowed sudo invocation must render one same-PID sequence ordered as the
  sudoers command authorization record, PAM session open, and PAM session close. Denied commands
  must not create PAM session rows. A close must never precede either the authorization or open.
- **Entry paths:** baseline extra-syslog sudo command generation, role-conditioned sudo command
  configuration, default and SOF-ELK® syslog finalization, and future callers of the public sudo
  action request. Raw syslog escape hatches remain outside the modeled lifecycle.
- **Consumers:** canonical syslog events, RFC5424/RFC3164 rendering, strict syslog parsers,
  detection/host review, and rendered-output lifecycle probes.
- **Layer rationale:** authorization, session open, runtime, and close are distinct phases of one
  sudo action. Their causal relationship belongs above rendering; the emitter may clamp
  source-local jitter but must not invent the lifecycle. Patching only timestamps in rendered
  text would leave canonical event order wrong and future consumers exposed.
- **Sibling risks:** the shared action bundle covers every generated allowed baseline sudo command
  and both syslog output targets. It does not infer lifecycle around explicit raw syslog samples,
  model PAM authentication failures, or yet correlate sudo with shell/eCAR process execution.
- **Sibling-path closure:** the rendered-data probe found that generic ambient logind sessions
  could still select `sudo`, producing PAM rows without a command authorization. Generic logind
  noise now selects only `login` or `su`; all modeled sudo session rows therefore enter through
  the action bundle that owns command authorization and closure.
- **Observation contract:** all three bundle phases share one canonical `AuthContext` lifecycle
  identity, so source-observation missingness and delay are sampled once for the complete sudo
  session instead of independently orphaning authorization, open, or close rows.

## Loop 63 Outcome

- **Commits:** `016c1984 fix: model ordered Linux sudo lifecycles`, `281d5fe5 fix: close
  ambient sudo lifecycle bypass`, and `14b094e1 fix: group sudo lifecycle observations`.
- **Verification:** focused action/baseline/emitter/observation tests passed; final full suite passed
  with 4,892 tests and 19 skips; Ruff lint/format passed.
- **Generation and eval:** 90,405 records from `iteration-test-expanded`; automated score
  96.00265028575151, PASS across all hard gates.
- **Hard probe:** 134 allowed invocations across nine hosts, two denied invocations, and zero
  orphan, missing, misordered, or unexpected sudo lifecycle phases.
- **Blind panel:** Threat Hunter 72, Detection Engineer 67, Network Forensics 68, Host/EDR 72;
  average 69.75 (`likely synthetic`), 11.25 points lower than loop 62. All verdicts were Synthetic;
  deliberation did not trigger because verdict confidence was 75-79 and score spread was 5.
- **Target result:** no reviewer repeated the authorization-after-PAM contradiction. Two reviewers
  independently found the remaining distribution sibling: six servers converged on 18-19 unique
  commands, which is deferred to role/operator-conditioned activity-count and reuse state.
- **Highest new root contracts:** SSH and RDP endpoint FLOW-after-auth inversions, one complete
  post-window new transaction, a live-session `LogonGuid` mutation, PsExec file-writer ownership,
  record-ID continuity after Security clear, stable sensor clocks, resolver-upstream transport,
  and missing Sysmon Event 7 `User` fields.

## Loop 64 Family Contract

- **Selected family:** remote-interactive endpoint transport observation before successful SSH/RDP
  authentication.
- **Finding classification:** `existing_family_regression` in the shared remote-session timing and
  observation contract.
- **Owning abstraction:** SSH and RDP action bundles compute auth readiness from the canonical
  transport interval plus the active observation policy's worst-case relative eCAR delay; the
  source-timing planner remains the owner of per-source latency, and eCAR remains a renderer.
- **Invariant:** for a successful remote session, same-tuple source/target eCAR `FLOW/CONNECT`
  observations must remain inside the canonical connection interval and precede successful target
  auth/session evidence. For SSH this means before Accepted/PAM open and eCAR `USER_SESSION/LOGIN`;
  for RDP it means before Security 4624 Type 10 and eCAR `USER_SESSION/LOGIN`. When process-create
  visibility conflicts with the bound, process identity is omitted instead of delaying transport.
- **Entry paths:** typed storyline SSH/RDP, baseline remote administration, SCP receiver sessions,
  Linux `logon_type=10` compatibility delegation, Windows RDP planner calls, and future callers of
  both public action bundles.
- **Consumers:** eCAR FLOW and USER_SESSION records, Linux SSH syslog, Windows Security 4624,
  Sysmon network rows, Zeek transport, rendered cross-source hard probes, and blind host review.
- **Layer rationale:** the inversion is created by combining bundle-level auth gaps with active
  source-observation delay ranges; the current bundles budget only intrinsic eCAR source latency.
  The observation policy owns those delay ranges, so exposing a typed relative-delay bound to the
  bundles prevents every sibling path without rewriting timestamps in eCAR or auth emitters.
- **Sibling risks:** cover both `enterprise_standard` and larger `messy_collection` delay profiles,
  complete/no-delay profiles, target and source endpoint views, and short connection intervals.
  Do not force eCAR FLOW before the Linux `Connection from` line when native collection latency can
  explain that order; the hard boundary is successful auth/session establishment.

## Loop 64 Outcome

- **Commits:** `4d441adc fix: preserve remote transport before authentication` and `f6c00225
  fix: route type 10 logons through RDP bundles`.
- **Root-cause closure:** SSH/RDP bundles now budget the active observation profile's relative
  eCAR/auth delay and the relevant endpoint clock relationship. Inbound eCAR FLOW clock scope is
  the receiving endpoint rather than always the source host. Generic Windows Type 10 logons now
  delegate to the RDP bundle instead of emitting auth first and transport later, while explicit
  storyline source identity and source-port truth are preserved.
- **Verification:** focused dispatcher/source-timing/SSH/RDP/storyline tests passed; final full
  suite passed with 4,897 tests and 19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.91799130579982, PASS across all hard gates.
- **Hard probe:** 104 successful SSH authentications, 103 observed matching target eCAR FLOW rows,
  one modeled cross-source collection gap, and zero FLOW-after-Accepted/PAM inversions. All 26 RDP
  Type 10 sessions had both endpoint FLOW views present and before Security authentication, with
  minimum source/target leads of 707 ms and 1,400 ms.
- **Blind panel:** initial Threat Hunter 69, Detection Engineer 88, Network Forensics 87, Host/EDR
  27; average 67.75 (`likely synthetic`), 2.0 points lower than loop 63. Verdict disagreement
  triggered deliberation. Two initial missing-format findings were invalid because the nested
  source files were present; deliberation removed them and revised all verdicts to Synthetic with
  a final average of 84.5. Deliberation scores remain outside trend calculations.
- **Target result:** no reviewer repeated the SSH/RDP authentication-before-endpoint-transport
  contradiction. The network reviewer found the broader sibling contract: 8,944 of 15,744 matched
  successful eCAR FLOW observations landed after every matching Zeek connection interval.
- **Highest new root contracts:** network-wide endpoint FLOW interval alignment; Event 4769
  service-account/SPN namespace ownership; collection-window admission before fan-out; DMZ DNS
  RTT/parent-duration identity; TCP state/history derivation; stable sensor clocks; TGS
  `LogonGuid`; and NTP stratum/reference-ID semantics.

## Loop 65 Family Contract

- **Selected family:** network-wide endpoint FLOW occurrence time inside the canonical connection
  interval.
- **Finding classification:** `existing_family_sibling` in the canonical network-connection and
  source-timing contract.
- **Owning abstraction:** the network-connection action bundle owns the canonical/source-visible
  interval, while `SourceTimingPlanner` owns source latency and endpoint clock texture. eCAR remains
  a source-native renderer of the already-bounded occurrence.
- **Invariant:** every observed eCAR `FLOW/CONNECT` row for a successful exact-tuple connection must
  have an occurrence timestamp within that connection's canonical source-visible open/close
  interval. Observation delay and host-clock texture must not move the occurrence past close. If a
  very short connection cannot also satisfy visible process-create ordering, omit PID/principal/
  actor identity instead of delaying the FLOW.
- **Entry paths:** ordinary TCP/UDP connections, automatic DNS and Kerberos prerequisites, proxy
  transactions, DHCP/NTP, scanner probes, browsing/mail/file transfer, baseline/service traffic,
  and higher-level SSH/RDP/admin bundles that request the canonical connection contract.
- **Consumers:** source and target eCAR FLOW rows, canonical connection state, process/session
  lifecycle guards, remote-auth bundles, cross-source probes, and network/host blind review.
- **Layer rationale:** the defect is created when per-source observation delay, intrinsic eCAR
  latency, and endpoint clock adjustment shift a connection occurrence without respecting its
  already-owned close time. Patching eCAR JSON after rendering would hide the contradiction from
  one consumer while leaving canonical/source-timing truth and future endpoint sources exposed.
- **Sibling risks:** cover both endpoint directions, Windows/Linux hosts, very short UDP/DNS/
  Kerberos intervals, TCP connections with longer lifetimes, multiple sensor views, all observation
  profiles, and process-attributed versus unattributed FLOW rows. Do not change Zeek duration or
  inflate short connections merely to accommodate endpoint reporting latency.

## Loop 65 Outcome

- **Commits:** `6bfe4dfa fix: bound endpoint flows to canonical intervals` and `1650965c fix:
  preserve canonical TLS connection duration`.
- **Root-cause closure:** `NetworkContext` and connection state now share one finalized immutable
  source-visible interval after protocol/payload/process timing settles. eCAR timing consumes that
  interval and omits impossible actor identity rather than moving short FLOW rows after close.
  Zeek TLS duration texture can no longer shorten the canonical interval.
- **Verification:** focused canonical interval/eCAR/Zeek tests passed; final full suite passed with
  4,900 tests and 19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.91799130579982, PASS across all hard gates.
- **Hard probe:** 15,744 exact-tuple eCAR FLOW rows matched successful rendered Zeek intervals and
  zero landed after the nearest transport close, down from 8,944 in loop 64.
- **Blind panel:** Threat Hunter 74, Detection Engineer 76, Network Forensics 72, Host/EDR 84;
  average 76.5 (`likely synthetic`). All verdicts were Synthetic; average verdict confidence 82.5
  and score spread 12, so deliberation did not trigger.
- **Target result:** no reviewer repeated the FLOW-after-close defect. Reviewers explicitly praised
  endpoint transport interval alignment and found no impossible packet/state/UID/TLS/file
  contradiction.
- **Highest next root contracts:** Security channel `EventRecordID` epoch reset after Event 1102;
  post-window new-activity admission; Windows 4648/Sysmon 7/8 native XML fields; machine-account
  eCAR lifecycle grouping; persistent sensor clocks; proxy DNS-to-origin readiness; stable
  `LogonGuid`; and behavior-specific Type 3 duration tails.
- **False-positive exclusion:** two reports incorrectly said declared ASA/Snort/proxy/web/syslog
  artifacts were absent; those nested files exist and automated eval parsed them. The claim was
  excluded from synthesis without altering standalone scores.

## Loop 66 Family Contract

- **Selected family:** source-native Windows Security channel record identity after audit-log clear.
- **Finding classification:** `existing_family_regression` in the Windows record-ID lifecycle.
- **Owning abstraction:** `WindowsRecordIdSequence` owns per-host, per-channel native record
  identity during final chronological rendering; the Security emitter identifies clear boundaries
  but must not retain one global monotonic epoch through Event 1102.
- **Invariant:** Event 1102 starts a new Security-channel epoch. Its native `EventRecordID` and all
  subsequent Security records must use a reset low sequence for that host/channel. Other Windows
  channels and hosts retain their independent sequences. A collector-global durable cursor, if
  needed, must not replace the native XML field.
- **Entry paths:** explicit typed `log_cleared` storyline events, causal `wevtutil cl Security`
  expansion, direct canonical log-clear calls, default Windows XML rendering, Snare rendering from
  the same event data, and multi-host buffered/sorted output.
- **Consumers:** Windows Security XML/Snare records, evaluator record ordering, SIEM correlation,
  native-event parsers, channel-clear hard probes, and blind detection/host/hunting review.
- **Layer rationale:** chronological finalization assigns every `EventRecordID` only after buffered
  events are sorted. The sequence model already owns source-native gaps and channel identity, so
  the epoch transition belongs there rather than in the action bundle or XML template.
- **Sibling risks:** cover clear-as-first-record, multiple clears, events at identical timestamps,
  host isolation, Security versus Sysmon channel isolation, and the clear event's own position in
  the new epoch. Preserve organic filtered-channel gaps within each epoch and do not reset eCAR,
  process, session, or collector-owned identifiers.

## Loop 66 Outcome

- **Commit:** `a6bc3172 fix: reset Security record IDs after log clear`.
- **Verification:** focused record-sequence/emitter tests passed; final full suite passed with
  4,903 tests and 19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.91799130579982, PASS across all hard gates.
- **Hard probe:** one visible Security clear, record ID 29,051,410 immediately before the clear,
  ID 1 on Event 1102, and ID 28 on the next visible Security event. Other channels remained
  independent.
- **Blind panel:** standalone Threat Hunter 69, Detection Engineer 76, Network Forensics 42, and
  Host/EDR 34; average 55.25 (`mixed / inconclusive`). Verdict disagreement and the 44-point spread
  triggered deliberation; its separate final average was 68.25 (`likely synthetic`).
- **Target result:** no report repeated the record-ID contradiction. Host/EDR and deliberation
  explicitly cited the reset as convincing native state change.
- **Highest next root contracts:** Event 4769 service-account/SPN ownership; Event 4688 target-
  subject semantics; process-owned Windows file/registry effects; DMZ DNS completion within parent
  intervals; output-window admission; OS-native Event 4698 versions; and role-conditioned Linux
  activity rates.

## Loop 67 Family Contract

- **Selected family:** Windows Event 4769 account identity versus requested Kerberos SPN.
- **Finding classification:** `new_family` in canonical Kerberos identity ownership and native
  Windows rendering.
- **Owning abstraction:** `KerberosContext` owns both the full requested SPN and the resolved
  ticketed service-account identity; the Kerberos DC action bundle derives them together and the
  Windows emitter only renders the native account field.
- **Invariant:** `KerberosContext.service_name` preserves the protocol SPN used for ticket intent
  and correlation. `service_account_name` and `service_sid` identify the same AD account. Event
  4769 `ServiceName` renders that account name, never a slash-delimited SPN, while service-ticket
  generation and stable action identity continue to use the requested SPN.
- **Entry paths:** DC ticket expansion for Windows logons, baseline machine Kerberos, direct KDC
  connections, cached-TGT service tickets, storyline-driven service use, and TGT renewals/default
  compatibility contexts.
- **Consumers:** Security 4769 XML/Snare, Kerberos source timing and cache state, ServiceSid
  correlation, detection analytics, canonical contexts, and rendered hard probes.
- **Layer rationale:** the generator currently derives the service SID from the account encoded by
  the SPN but stores only the SPN string, forcing the Windows emitter to put protocol identity in
  an account field. Splitting truth once at the Kerberos owner preserves both consumers and avoids
  an emitter-only hostname rewrite.
- **Sibling risks:** cover `krbtgt/REALM`, host/CIFS/LDAP/DNS/HTTP machine-hosted SPNs, slashless
  account requests, explicit managed/user service accounts, and contexts created outside the
  primary bundle. Preserve deterministic ticket timing, cache identity, and ServiceSid values.

## Loop 67 Outcome

- **Commit:** `27ccb505 fix: separate Kerberos SPN and service identity`.
- **Verification:** focused Kerberos context/bundle/emitter tests passed; final full suite passed
  with 4,904 tests and 19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.91799130579982, PASS across all hard gates.
- **Hard probe:** all 1,212 Event 4769 rows use account-style `ServiceName`, with zero slash-
  delimited names and zero empty `ServiceSid` values.
- **Blind panel:** standalone Threat Hunter 34, Detection Engineer 58, Network Forensics 28, and
  Host/EDR 78; average 49.5 (`mixed / inconclusive`). Verdict disagreement and the 50-point spread
  triggered deliberation; its separate final average was 54.0.
- **Adjudication:** the host report's two PsExec hard contradictions were false associations with a
  later Diego SMB tuple. The earlier Aisha transport and target session correctly precede file and
  service evidence. The missing source PsExec client remains an isolated contract gap.
- **Target result:** no report repeated the Event 4769 SPN/account defect.
- **Highest next root contracts:** eCAR FLOW PID/TID coherence; process-aware Sysmon DNS ownership;
  stateful/native MRU registry evidence; ProcessAccess stack diversity; shared DNS RTT/connection
  duration; remote-admin source callers; and coherent endpoint clock processes.

## Loop 68 Family Contract

- **Selected family:** eCAR FLOW process-attribution coherence when process identity is unavailable.
- **Finding classification:** `existing_family_sibling` in source-local FLOW identity removal.
- **Owning abstraction:** the eCAR FLOW identity group owns PID, TID, actor ID, principal, and process
  provenance as one source-native attribution unit. Finalization may remove that unit when process
  visibility/lifetime conflicts with the transport occurrence.
- **Invariant:** a FLOW TID may appear only with a positive owning PID. Whenever eCAR drops process
  attribution because the process is absent, late, terminated, or not source-visible, it must remove
  PID, TID, actor ID, principal, image, command line, and parent provenance together. Transport tuple,
  direction, outcome, and FLOW object identity remain intact.
- **Entry paths:** outbound and inbound canonical connections, short SSH/RDP transports, pre-window
  processes, post-termination flows, observation-dropped process creates, and close-time normalization.
- **Consumers:** eCAR FLOW JSON, endpoint actor/process joins, lifecycle finalizers, detection rules,
  strict schema checks, and rendered hard probes.
- **Layer rationale:** the canonical transport remains valid when endpoint process attribution cannot
  be safely exposed. The defect is created by eCAR's source-local identity scrubber removing PID and
  actor fields but leaving the process-owned TID behind, so the fix belongs in that shared scrubber,
  not in connection generation or post-render JSON text.
- **Sibling risks:** preserve TID when a visible positive PID remains; remove it across all four
  identity-scrub call sites; do not drop `objectID` or network properties; cover Windows/Linux,
  source/destination directions, stale lifetimes, late process visibility, and missing creates.

## Loop 68 Outcome

- **Commit:** `286cf8bb fix: drop orphan eCAR flow thread identity`.
- **Verification:** focused eCAR identity tests passed; final full suite passed with 4,904 tests and
  19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.91799130579982, PASS across all hard gates.
- **Hard probe:** all 17,370 FLOW rows were inspected; 1,849 retained positive PID/TID pairs and
  zero retained positive TID without positive PID.
- **Blind panel:** Threat Hunter 73, Detection Engineer 84, Network Forensics 72, and Host/EDR 86;
  standalone average 78.75 (`likely synthetic`). All verdicts were Synthetic, average verdict
  confidence was 89.0, and score spread was 14, so deliberation did not trigger.
- **Target result:** no reviewer repeated the orphan-TID defect; Host/EDR explicitly verified zero
  FLOW rows with TID but no PID.
- **Highest next root contracts:** Event 4688 creator versus target-token semantics; single-owner
  SSH/SCP receiver lifecycles; process-aware Sysmon DNS; Event 4648 native field names; registry
  state/value typing; and NTP analyzer/payload agreement.

## Loop 69 Family Contract

- **Selected family:** Windows Security Event 4688 creator identity versus optional target-token
  identity.
- **Finding classification:** `new_family` in canonical process security-context ownership and
  source-native Windows rendering.
- **Owning abstraction:** `ProcessContext` owns an optional target security context separately from
  the creator/subject `AuthContext`; the Windows emitter renders those already-resolved identities.
- **Invariant:** ordinary same-token process creation renders the native null Target Subject block
  (`S-1-0-0`, `-`, `-`, `0x0`). Only a process action that explicitly models a different target
  token may populate target SID, name, domain, and logon ID, and those fields must describe one
  coherent security context rather than copy Creator Subject mechanically.
- **Entry paths:** ordinary user processes, SYSTEM/service processes, scheduled tasks, remote
  service execution, WMI, runas/explicit credentials, RDP/SSH compatibility paths, and future
  alternate-token process actions.
- **Consumers:** Security 4688 XML/Snare, creator/target token detections, process-context joins,
  downstream parsers, rendered hard probes, and blind endpoint/detection review.
- **Layer rationale:** the emitter currently has no canonical target-token truth, so it substitutes
  the creator in every Target field. Adding optional truth to the process context makes ordinary
  and alternate-token semantics explicit and prevents each process entry path or renderer from
  inventing identity independently.
- **Sibling risks:** cover SYSTEM and ordinary-user same-token creation, explicit different-token
  creation, partial/invalid target contexts, Security/Snare fan-out, and process create/terminate
  joins. Do not change Subject identity, process ownership, LogonID, Sysmon identity, or eCAR actor
  attribution while correcting only the optional Event 4688 Target Subject block.

## Loop 69 Outcome

- **Commit:** `42373185 fix: model process target security context`.
- **Verification:** focused ordinary/SYSTEM/explicit-target tests passed; final full suite passed
  with 4,907 tests and 19 skips; repository-wide Ruff lint/format passed.
- **Generation and eval:** 91,524 records from `iteration-test-expanded`; automated score
  95.86827539670891, PASS across all hard gates.
- **Hard probe:** all 927 Event 4688 rows used the native null Target Subject block and zero copied
  Creator Subject; no explicit alternate-token process exists in this scenario.
- **Blind panel:** Threat Hunter 72, Detection Engineer 86, Network Forensics 68, and Host/EDR 76;
  standalone average 75.5 (`likely synthetic`). All verdicts were Synthetic, average verdict
  confidence was 85.5, and score spread was 18, so deliberation did not trigger.
- **Target result:** no reviewer repeated the prior Event 4688 target-subject defect.
- **Highest next root contracts:** sensor-shared DNS response/parent duration; process-aware Sysmon
  DNS; Type 5 workstation semantics; stateful/native MRU values; ProcessAccess stack families;
  rare Zeek state/history combinations; and collection-window admission.

## Loop 70 Family Contract

- **Selected family:** sensor-local DNS RTT bounded by the same-UID Zeek connection lifetime.
- **Finding classification:** `existing_family_regression` in multi-sensor source-observation
  timing.
- **Owning abstraction:** the Zeek sensor-observation layer owns one response/end anchor for each
  sensor's DNS connection and analyzer views; the canonical network/DNS bundle continues to own the
  unobserved base duration and RTT.
- **Invariant:** on every sensor, a DNS row's response interval must fit inside its same-UID parent
  connection. Sensor clock/path texture may shift the shared start and response anchors, but it may
  not independently extend DNS RTT beyond connection duration. Packet accounting remains exact.
- **Entry paths:** automatic prerequisite DNS, explicit storyline queries, resolver companions, AD
  SRV discovery, proxy-origin DNS, UDP and TCP DNS, multi-sensor NAT views, and direct emitter tests.
- **Consumers:** Zeek conn/dns rows, source-timing planners, fan-out evaluators, network detections,
  rendered hard probes, and blind network/detection/hunting review.
- **Layer rationale:** canonical generation already guarantees `duration >= rtt`; the contradiction
  appears only on the second sensor because conn duration and DNS RTT receive independent
  source-observation extensions. One sensor-local response delta shared by both views preserves
  canonical truth without flattening legitimate sensor clocks or patching output files.
- **Sibling risks:** cover equal and unequal canonical duration/RTT, short sub-millisecond queries,
  UDP/TCP, two or more sensors, rounding to Zeek microseconds, NAT-derived UIDs, and absent RTT.
  Preserve independent sensor UID/clock identity and exact DNS packet accounting.
