# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Synthetic | 78 | 67 | Synthetic | 82 | 72 |
| Detection Engineer | Real | 87 | 18 | Real | 63 | 40 |
| Network Forensics | Real | 78 | 27 | Real | 65 | 39 |
| Host/EDR Forensics | Synthetic | 74 | 64 | Synthetic | 82 | 74 |

## Round 1 — Initial Positions

The **Threat Hunter** assessed the collection as synthetic, led by three repeated
environment-level patterns: almost invariant per-client DHCP renewal gaps over many cycles,
unusually dense SSH administration drawn from a narrow set of exact client commands, and no
visible UDP/123 traffic despite endpoint evidence of active Linux time synchronization. The
expert simultaneously regarded the archive-to-SMB-to-browser-to-proxy exfiltration chain and the
Windows audit-clear sequence as highly convincing source-native evidence.

The **Detection Engineer** assessed it as real. The strongest evidence was exact contract
behavior: Windows provider/channel/version and payload shapes, the Event 1102 record-counter
reset, 834/834 Sysmon process creates matching Security 4688 records, coherent logon lifecycles,
valid Zeek protocol fan-out, and independently rendered Zeek/ASA timing and byte semantics. The
only synthetic reservations were all-established Zeek SSL rows and one DNS row per UID, both
treated as weak and plausibly source-native.

The **Network Forensics Analyst** also assessed it as real. This expert found broad connection
state, duration, loss, DNS, TLS, proxy, firewall, and IDS texture, plus independent observations
between the two Zeek sensors and close-but-not-cloned Zeek/ASA and Zeek/Snort correlations. The
main reservation was the same DHCP cadence independently identified by the threat hunter:
client-specific renewal intervals repeat for 10–12 cycles with only about one second of jitter.

The **Host/EDR Forensics Analyst** assessed it as synthetic. This expert agreed that Windows
process/session ownership and Linux SSH lifecycle ordering were excellent, but found a more
discriminating SSH identity problem: the same client/user presents a stable but different public
key fingerprint to each destination, systematically across three administrators, while visible
client commands do not select identities. Thirteen of 20 active client/user/target groups also
alternate between password and public-key authentication, and the overall SSH session volume is
unusually high.

## Round 2 — Cross-Examination

### Source-native correctness versus authenticity

The Detection Engineer's evidence decisively establishes that the collection is parser-ready,
well correlated, and largely faithful to native source contracts. It does not, by itself,
distinguish production telemetry from a generator capable of maintaining those contracts. No
expert reported an impossible PID lifecycle, reversed session, broken Zeek UID tuple, malformed
Windows event, or cloned cross-sensor timestamp. The panel therefore treats source-native
correctness as strong evidence of quality and plausibility, but not as dispositive evidence of a
real origin.

The Host/EDR finding carries greater authenticity weight than generic regularity because it
concerns durable credential identity. Per-host SSH keys are operationally possible, including
through client configuration not exposed in a simple `ssh.exe user@host` command. That alternative
explanation weakens the finding from a hard contradiction. Its systematic form nevertheless makes
it difficult to dismiss: every multi-server administrator exhibits destination-specific key
identity while many stable tuples repeatedly switch authentication method without a reported
failure or policy transition. This looks less like missing telemetry than state sampled at the
session or destination level.

### Corroborated DHCP texture

The DHCP concern was independently measured by the Threat Hunter and Network Analyst. Stable T1
behavior explains a client having its own characteristic interval, but it does not fully explain
10–12 consecutive renewals constrained to a roughly two-second range with no delayed, missed,
sleep/wake, or rebinding episode. Because this pattern spans several clients and much of the
six-hour window, the bounded-window caveat is weaker here than it is for a single periodic
observation. It remains a distribution tell rather than a protocol contradiction.

### SSH volume and command repetition

High SSH volume is compatible with an administration-heavy shift, and shared diagnostic commands
are normal among operators. Dual-sensor visibility can also inflate network counts. The endpoint
counts, however, independently show 70 SSH client creates on two Windows workstations and the host
review found 93 matched target lifecycles. Volume and a compact command vocabulary are not decisive
alone, but they amplify the credential-state findings by making the questionable sampling pattern
recur often.

### NTP absence and bounded collection

The zero-UDP/123 observation is notable in a network view that captures DHCP, DNS, Kerberos, LDAP,
SMB, and protocol companions. It is not a hard contradiction. Time-sync file activity does not
prove that an NTP poll occurred inside this exact six-hour window or crossed the observed sensors;
an internal hierarchy, long polling interval, or collection boundary could explain the absence.
The panel retains this as a secondary environment/visibility concern only.

### TLS and DNS weak signals

The all-established SSL population is adequately explained by Zeek's analyzer threshold: failed
443 connections can remain in `conn.log` without producing an SSL row. Likewise, one DNS
transaction per UID can result from per-query UDP sockets. These are useful opportunities for more
production texture, but they do not materially determine the verdict.

## Round 3 — Revised Positions

### Threat Hunter

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 82  
**Final Synthetic-Confidence Score:** 72

The Host/EDR analyst's destination-specific public-key evidence strengthens the initial assessment
because it supplies a durable-state concern independent of the hunter's DHCP and volume findings.
Confidence rises modestly. The NTP gap is down-weighted after the bounded-sensor challenge.

### Detection Engineer

**Final Assessment:** Real  
**Final Verdict Confidence:** 63  
**Final Synthetic-Confidence Score:** 40

The engineer retains a Real verdict because the sampled source contracts, lifecycle accounting,
and independent-sensor semantics are exceptionally strong and contain no reported impossible
ordering. Confidence falls substantially, and synthetic confidence rises, because the SSH key
ownership pattern is more probative than the engineer's original low-weight TLS/DNS observations
and was outside that report's strongest checks. The evidence is strong enough to make the verdict
close, but the plausible per-host-configuration explanation prevents a flip.

### Network Forensics Analyst

**Final Assessment:** Real  
**Final Verdict Confidence:** 65  
**Final Synthetic-Confidence Score:** 39

The analyst retains a narrow Real verdict for the network evidence: state distributions, sensor
differences, capture loss, protocol timing, firewall lifecycles, and proxy outcomes are broad and
source-native. Confidence declines because the independently corroborated DHCP cadence is joined
by a credible host-state issue. The analyst does not treat the NTP absence or all-established SSL
rows as contradictions given the bounded collection and analyzer-selection explanations.

### Host/EDR Forensics Analyst

**Final Assessment:** Synthetic  
**Final Verdict Confidence:** 82  
**Final Synthetic-Confidence Score:** 74

The analyst retains and strengthens the Synthetic verdict. The Threat Hunter's independent SSH
volume measurements and repeated-command observations support the conclusion that the
destination-specific key and method-switching patterns are family-level behavior rather than an
isolated configuration oddity. The strong Windows and SSH lifecycle contracts continue to cap
confidence below a near-certain verdict.

## Round 4 — Consensus

**Consensus Assessment:** Synthetic  
**Consensus Verdict Confidence:** 68  
**Consensus Synthetic-Confidence Score:** 59

The panel does not reach unanimity: the final role vote remains split 2–2. The facilitated
consensus nevertheless leans Synthetic because the most origin-discriminating observation is not
a formatting imperfection but a repeated ownership/state pattern: client key identity tracks the
destination while authentication method changes repeatedly inside stable tuples. The independently
corroborated DHCP timing adds a second, unrelated family-level sampling signal. These outweigh the
Real side only narrowly because the collection's source-native structures, lifecycles,
cross-source correlations, failure states, and independent observation delays are unusually
convincing and no expert reported a hard causal contradiction.

The 49-point initial synthetic-confidence spread arose mainly from weighting different evidence,
not from conflicting measurements. Detection and network specialists weighted exact contracts
and sensor semantics most heavily; host and hunting specialists weighted persistent behavioral
state and repeated distributions. After cross-examination, the spread narrows from 49 points to 35
points, while preserving the legitimate distinction between technical correctness and origin.

## Key Agreements

- Windows Security, Sysmon, and eCAR process/session lifecycles are source-native and internally
  coherent in the reported checks.
- Zeek protocol fan-out, connection accounting, and ASA/IDS/proxy relationships are strong, with
  believable independent-observer timing rather than exact cloning.
- DHCP renewal timing is the clearest network-side synthetic-looking distribution, independently
  observed by two experts.
- The collection is operationally huntable and its suspicious multi-source chains contain no
  reported causal reversal.
- All-established SSL rows, compact destination pools, and repeated generic commands are weak
  signals when considered alone.

## Key Disagreements

- The Real-voting experts regard contract fidelity and the lack of hard contradictions as stronger
  evidence of production origin; the Synthetic-voting experts regard those properties as
  compatible with a high-quality deterministic generator.
- The panel disagrees on whether systematic per-destination SSH keys could reasonably result from
  unseen per-host client configuration. All agree that the simultaneous authentication-method
  switching makes that explanation less persuasive.
- The NTP family gap remains unresolved because the six-hour window and sensor boundary permit
  benign explanations not testable from the reports.

## Most Convincing Evidence

1. **Synthetic:** The same user/client identity presents a different stable public-key fingerprint
   to each destination across three administrators, while visible commands do not select keys.
2. **Synthetic:** Thirteen of 20 stable SSH client/user/target groups alternate between password
   and public-key authentication without a reported causal fallback.
3. **Real:** Exact Windows/Sysmon/eCAR PID, command, lifecycle, and observation-delay contracts hold
   across hundreds of matched events, including realistic source coverage gaps.
4. **Real:** Zeek, ASA, IDS, proxy, and dual-sensor observations reconcile in tuple, timing, state,
   and accounting while retaining source-specific differences.
5. **Synthetic:** Multiple DHCP clients repeat host-specific renewal gaps for 10–12 cycles with
   only about one second of jitter and no missed or delayed renewal.

## Most Debated Points

- Whether source-native perfection is evidence of real collection or merely evidence of a mature
  generator.
- Whether unseen SSH client configuration can explain systematic destination-specific keys.
- How much a six-hour bounded sample should discount missing NTP and lifecycle endpoints.
- Whether high SSH volume is an authentic operations shift or a mechanism that overexposes a
  sampled behavior model.

## Improvement Recommendations (Consensus)

1. **Own SSH credentials at the client/user layer.** Reuse a user's selected public-key
   fingerprint across destinations by default. Permit per-host keys only through explicit,
   persistent client configuration, and propagate that selected identity consistently into every
   receiving sshd record.
2. **Make SSH authentication policy stateful.** Keep the method sticky for a
   client/user/target-policy relationship. A change from key to password should follow visible key
   rejection, agent unavailability, credential migration, or explicit client options rather than
   an independent session draw.
3. **Model administration as task-centered routines.** Reduce broad independent SSH sampling;
   create task-related bursts, longer quiet periods, long-tailed target preferences, and
   user-specific multi-command workflows while preserving the existing high-quality lifecycle
   ordering.
4. **Add stateful DHCP timing texture.** Preserve lease and T1 semantics while adding
   client/server scheduling drift, sleep/wake effects, delayed or missed renewals, occasional
   rebinds, and lease changes. Avoid confining a client's full-window renewals to a roughly
   two-second gap range.
5. **Make time-sync visibility explicit.** Where network sensors should observe it, add plausible
   NTP exchanges tied to the environment's time hierarchy. Otherwise make the internal source,
   polling interval, or collection exclusion apparent so endpoint time-sync state does not imply a
   missing network family.
6. **Add low-volume protocol edge texture.** Where source-native, include occasional DNS socket
   reuse and parseable incomplete TLS handshakes linked to compatible connection states. These are
   polish items and should not compromise the strong existing UID, tuple, and lifecycle contracts.

