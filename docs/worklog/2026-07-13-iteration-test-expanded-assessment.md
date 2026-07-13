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
