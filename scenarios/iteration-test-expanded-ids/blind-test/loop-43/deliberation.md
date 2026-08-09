# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 78 | 44 | Synthetic | 91 | 88 |
| Detection Engineer | Synthetic | 94 | 87 | Synthetic | 97 | 93 |
| Network Forensics | Synthetic | 76 | 67 | Synthetic | 92 | 89 |
| Host/EDR Forensics | Synthetic | 93 | 87 | Synthetic | 97 | 94 |

## Key Agreements

- All four experts agreed that the corpus has strong source-format fidelity, useful cross-source joins, convincing source-native timing, and a technically coherent attack sequence. In particular, the web-to-process chain, Windows process correlation, SSH lifecycle ordering, TCP state handling, TLS/certificate behavior, and log-clear sequence were regarded as credible.
- The panel agreed that coherent attack causality does not resolve provenance. The threat hunter's lack of a visible causal impossibility remains an important quality finding, but the other experts' repeated source-semantic contradictions can coexist with an otherwise huntable, well-correlated storyline.
- The panel agreed that bounded-window conditions must not be treated as defects by themselves. Unmatched events at the window edges, absent initial DHCP acquisition, and selective source loss were therefore excluded from the decisive evidence.
- After cross-examination, all experts agreed that the authentication, Windows service-lifecycle, and cross-sensor HTTP findings are independent defect families. Their repetition and their propagation across configured sources make a coincidental collection explanation implausible.
- Most experts also observed overly compact reusable populations: dense SSH administration, repeated Linux message pools, a small persistent scanner population, and narrow command or packet-fingerprint vocabularies. The panel treated these as corroboration, not as substitutes for the hard contradictions.

## Key Disagreements

- The initial disagreement concerned whether excellent operational coherence outweighed authenticity defects. The threat hunter initially returned Inconclusive because the attack can be pivoted end to end and no visible lifecycle ordering failure appeared in that review. The detection and host findings changed that balance: impossible built-in service-token identities and concurrent singleton services are properties of normal source semantics, not merely gaps in the attack narrative. The threat hunter therefore revised to Synthetic.
- The network expert initially assigned less weight to the overall synthetic assessment because most network telemetry is unusually realistic. Cross-examination strengthened the network position: the host and detection defects are independent of the dual-sensor HTTP mismatch, so even a disputed explanation for one family would leave two other repeated systemic contradictions.
- The precise severity of distributional evidence remains debated. Near-periodic DHCP renewals can follow legitimate T1 timers, a quiet perimeter can produce mostly `S0` probes, shared Linux daemon messages can reflect standardized builds, and high SSH volume can reflect an unusually active operations team. The panel retained these observations as supporting texture and did not let them drive the final verdict.
- The unexplained privileged pivot from `WS-EBROOKS-01` remains a plausibility concern rather than a contradiction. A pre-window compromise or unobserved credential transition could explain it, so the panel did not rank it among the decisive findings.

## Most Convincing Evidence

1. Multiple Windows hosts contain overlapping, still-active instances of singleton services such as `Schedule`, `LanmanServer`, and `EventLog`. The older PIDs continue producing eCAR activity after replacement instances start, while Sysmon, Security, and eCAR all lack the required termination transition. This directly defeats a logging-gap or bounded-window explanation.
2. All 296 Type 5 logons for `SYSTEM`, `LOCAL SERVICE`, and `NETWORK SERVICE` use newly allocated high-valued Logon IDs instead of the built-in authentication LUIDs, and those invented identities propagate into 4672, 4634, process, and eCAR records. The breadth and cross-source consistency identify a systemic identity-model defect.
3. Fifteen matched HTTP transactions have different response body lengths at the core and DMZ sensors despite identical connection byte and packet counters, identical histories, and `missed_bytes: 0`. Sensor-specific capture loss cannot explain parser disagreement over the same complete TCP stream.
4. Machine accounts generate 484 successful TGT requests in six hours, including near-simultaneous requests for the same client/account with rapidly changing ticket options and AES/RC4 choices. Normal ticket caching and stable client capability preferences do not fit this repeated pattern.
5. All 915 `WEB-EXT-01` kernel UFW records imply a boot epoch with independently varying residuals constrained to an exact 0–250 ms band. A stable boot clock plus naturally shaped collection delay would not normally create that hard-capped relationship.

## Most Debated Points

- The panel debated whether highly accurate schemas, strong lifecycle ordering, realistic sensor drift, and complete attack pivots should lower synthetic confidence. The conclusion was that these are genuine realism strengths but cannot neutralize repeated violations of source semantics.
- The dual-sensor HTTP mismatch received a strength challenge based on possible independent parsing or capture effects. That alternative was rejected for the cited cases because both sensors report matching complete stream counters and no missed bytes; transactions with actual missing bytes were not counted.
- The Windows singleton-service finding received a missing-termination challenge. Later telemetry from the older PIDs disproves an unobserved replacement termination for the demonstrated cases, making this stronger than an ordinary collection-gap claim.
- Scanner diversity, DHCP regularity, SSH density, shared command pools, and high-frequency Linux daemon messages remained boundary indicators. Each has a plausible operational explanation in isolation, but their joint compactness reinforces the harder evidence.
- The workstation-to-root pivot was considered underexplained but not impossible. Because the visible slice may omit the ownership transition, it was retained as a realism-improvement target rather than provenance proof.

## Improvement Recommendations (Consensus)

- Enforce canonical per-host Windows service ownership. Reuse a running singleton service process; when a restart is intended, emit the stop and correlated Sysmon 5, Security 4689, and eCAR termination before creating the replacement instance.
- Assign the well-known built-in LUIDs consistently to `SYSTEM`, `LOCAL SERVICE`, and `NETWORK SERVICE`, and propagate those canonical identities through logon, privilege, process, logoff, and eCAR records rather than allocating a new session for routine service activity.
- Add a Kerberos cache model keyed by host, principal, logon session, realm, encryption policy, and lifetime. Generate a new TGT only for a cache miss, renewal, expiry, purge, credential change, or genuinely separate authentication context, and keep encryption preferences stable per client/account.
- Compute HTTP semantic body lengths once per canonical transaction and preserve them across sensors. Apply sensor-local parsing differences only when the associated stream observation records compatible loss, gaps, or incompleteness.
- Derive kernel uptime and wall-clock timestamps from one stable boot epoch. Model collection delay with an empirically shaped distribution rather than independently sampling a hard-bounded 0–250 ms residual.
- Broaden background populations with more transient scanners, overlapping service interests, varied campaign lifetimes and packet fingerprints, stronger user-to-server SSH specialization, and more role-specific Linux daemon/message pools.
- Tie DHCP renewals to explicit lease T1/T2 behavior with realistic scheduler and observation variance, rather than a nearly fixed per-host interval with uniformly sub-second jitter.
- Preserve the existing strengths: source-native envelopes, process and session joins, web-process lineage, SSH ordering, sensor-local UIDs and clock drift, TCP history diversity, TLS/certificate-loss semantics, and log-clear behavior.
