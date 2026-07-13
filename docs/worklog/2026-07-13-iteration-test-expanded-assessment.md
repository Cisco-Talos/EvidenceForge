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
