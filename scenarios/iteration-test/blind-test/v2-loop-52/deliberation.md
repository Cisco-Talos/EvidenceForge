# Deliberation Summary

The panel began split 3-1: the Threat Hunter judged the corpus real, while the Detection
Engineer, Network Forensics Analyst, and Host/EDR Forensics Analyst judged it synthetic. The
split was not about whether the corpus is polished. All four experts found strong source-native
formatting, role-aware background activity, coherent identifiers, and unusually good lifecycle
and cross-source correlation. It was about whether several concrete contradictions and repeated
cross-host distributions outweigh those strengths.

After cross-examination, the Threat Hunter revised to Synthetic. The decisive change was exposure
to evidence outside the hunter's initial emphasis: repeated Snort alerts whose named HTTP
User-Agent conflicts with the only Zeek HTTP transaction on the same tuple; successful
machine-account TGT requests recurring every few minutes; a 0.635 ms lock/unlock lifecycle; and
identical bounded metadata pools across independent hosts. The other three experts retained their
Synthetic verdicts and increased confidence because the strongest findings are independent across
network, authentication, and endpoint source families. The final verdict is unanimous Synthetic,
while disagreement remains over the evidentiary weight of fixed timing offsets, selective
collection gaps, Linux PID slopes, universal NTLM on one file server, and compact scanner pools.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 74 | 32 | Synthetic | 84 | 79 |
| Detection Engineer | Synthetic | 88 | 78 | Synthetic | 94 | 91 |
| Network Forensics | Synthetic | 89 | 84 | Synthetic | 94 | 92 |
| Host/EDR Forensics | Synthetic | 95 | 93 | Synthetic | 97 | 96 |

**Round 1 — initial positions and strongest evidence.**

- **Threat Hunter:** Initially assessed the data as Real because the six-hour collection has
  credible scale and role-sensitive source mix; varied Zeek states and noisy baseline behavior;
  and a technically coherent intrusion path from SMB/PsExec through persistence, database
  collection, SCP/SMB relay, and cleanup. The hunter's strongest synthetic concerns were narrower:
  no source-side PsExec process despite an outbound SMB flow, an unattributed APP-INT staging-file
  read, a close-only in-window SSH syslog lifecycle, and repeated long shell-command templates.
- **Detection Engineer:** Assessed the data as Synthetic, led by 788 machine-account 4768 events
  and repeated successful TGT acquisition every few minutes, plus the 0.635 ms WS-AJOHNSON lock
  and unlock with no nearby Type 7 companion. Secondary evidence included similar Linux PID-growth
  rates, exact one-millisecond registry-write batches, and universal NTLM for FILE-SRV network
  logons. The expert nevertheless rated schemas, identifier morphology, process correlation,
  Security-log clearing, SMB handle lifecycles, and Zeek typing as highly credible.
- **Network Forensics:** Assessed the data as Synthetic because all five Snort `curl User-Agent`
  alerts conflict with the matching Zeek HTTP User-Agent, one APT alert maps to a Go client, and
  two Python-urllib alerts occur on TLS-only origin flows without visible decryption context.
  Nearly fixed cross-sensor offsets and narrow IDS latency bands reinforced that verdict. The
  expert uniquely emphasized that sensor-local UIDs, loss-aware byte differences, DNS/TLS/X.509
  semantics, proxy tunnel identity, and firewall/NAT lifecycles are unusually production-like.
- **Host/EDR Forensics:** Assessed the data as Synthetic with the highest confidence. The strongest
  findings were the impossible lock/unlock pair; a local `runas.exe` Event 4648 carrying another
  endpoint's IP; the same incorrect TiWorker ancestry on six systems; Security 4688 always lagging
  Sysmon Event 1 within a bounded one-way envelope; all ten Windows hosts using the exact same 38
  WFP ThreadIDs; and Linux daemon families landing on exact repeated per-host counts. The expert
  also found excellent ProcessGUID, hash, parent/child, termination, and Security-log-reset
  integrity.

**Round 3 — revised positions.** The Threat Hunter changed verdict because the network payload
contradictions and authentication/endpoint distributions are concrete log-visible defects that
cannot be dismissed as an intrusion being cleanly narrated or as correlation being unusually
complete. The hunter retained the lowest final synthetic-confidence score because the operational
background, attack lifecycle, mixed connection outcomes, and cleanup consequences remain strong.
The Detection Engineer increased confidence after the network analyst's payload-contract findings
and the host analyst's cross-host metadata evidence independently supported the existing Kerberos
and lock-lifecycle findings. The Network Analyst increased confidence after the endpoint and
Kerberos evidence showed the problem was not confined to IDS rendering. The Host Analyst changed
no verdict but increased confidence because the network contradictions provide a separate
source-family failure mode. None of the experts withdrew their positive findings about schema,
identity, lifecycle, role, proxy, TLS, or firewall realism.

## Key Agreements

- The dataset's ordinary source-native shape is strong. Windows and Sysmon schemas, Zeek typing,
  eCAR identifiers, proxy tunnel references, TLS certificate relationships, and ASA connection
  lifecycles are credible in isolation.
- Cross-source completeness and correlation are strengths, not synthetic indicators by
  themselves. The panel found no broad pattern of child-before-parent processes,
  terminate-before-create lifecycles, protocol records before their Zeek connections, or firewall
  teardowns before builds.
- The 0.635 ms WS-AJOHNSON Event 4800-to-4801 interval is physically implausible. The raw Security
  log places the same user, logon ID `0x263743b`, and session 2 at
  `17:48:17.3933800Z` and `17:48:17.3940149Z`, with no nearby Type 7 event.
- The Snort HTTP-content contract is broken. The five `curl` alerts map to one
  `Go-http-client/1.1` and four `Wget/1.21.3` Zeek transactions; the cited APT alert maps to
  `Go-http-client/1.1`; and the two Python-urllib alerts map to TLS sessions with no Zeek HTTP row
  or other visible decryption context.
- Machine-account Kerberos activity is implausibly repetitive. Direct verification confirmed 121
  successful 4768s for `MAIL-FIN-01$` (median 147.1 seconds), 116 for `FILE-SRV-01$` (168.7
  seconds), 87 for `WS-PPATEL-01$` (140.3 seconds), and 93 for `WS-AJOHNSON-01$` (194.8 seconds)
  during the six-hour window.
- Repeated cross-host cardinalities are persuasive synthetic texture. Every Windows host uses all
  and only the same 38 Event 5156 ThreadIDs, from 52 through 200 in increments of four. Six hosts
  render TiWorker as a SYSTEM child of a NETWORK SERVICE `svchost.exe -k netsvcs`. Ten Linux
  systems have exactly four `systemd-resolved` and five `anacron` records, and nine have exactly
  eight `dbus-daemon` records.
- The final assessment must not rely on the attack being linear, compact, richly correlated, or
  easy to narrate. The consensus rests on source-visible contradictions and repeated distribution
  texture instead.

## Key Disagreements

**Round 2 — cross-examination.** The panel did not give equal weight to every cited clue.

- **Fixed timing offsets:** The Host Analyst considered the one-way 35-650 ms Security-after-Sysmon
  envelope across 926 process pairs a strong shared-profile fingerprint. The Detection Engineer
  regarded that range as plausible provider-pipeline behavior. Similarly, the Network Analyst's
  roughly 114 ms core/DMZ offset could reflect stable clock skew. The panel retained both as
  supporting evidence only; neither is needed for the final verdict without drift, clock, or
  capture-path evidence.
- **Collection gaps versus generation gaps:** The Threat Hunter highlighted the missing source
  PsExec client process, APP-INT's unattributed file read, and an SSH close without connection/auth
  syslog. Other experts agreed these weaken huntability but noted that endpoint collection loss,
  selective provider coverage, and process attribution gaps occur in production. These remain
  contract-gap recommendations, not hard contradictions.
- **Linux PID slopes:** The Detection Engineer saw similar long-window PID advancement across
  unlike hosts as evidence of a shared process-rate model. The Host Analyst's exact daemon quotas
  provide related support, but the panel judged slopes alone less reliable because unobserved
  processes, uptime, PID namespaces, and collection selection complicate inference.
- **FILE-SRV universal NTLM:** Hostname-based domain SMB normally favors Kerberos, but SPN,
  delegation, policy, or environment problems can yield NTLM. The panel kept this as an
  environment oddity, not proof.
- **Scanner and HTTP pool concentration:** The Network Analyst found 97.2% of inbound DMZ S0
  traffic concentrated in eight sources and substantial exact HTTP-shape repetition. The Threat
  Hunter viewed campaign reuse, updaters, sanitization, and bounded collection as credible
  alternatives. These remain weak-to-moderate texture findings.
- **How much the realism strengths offset defects:** The Threat Hunter continued to give more
  weight than the other experts to role-aware volumes, mixed Zeek outcomes, coherent attack
  pivots, proxy semantics, and cleanup consequences. The other experts agreed those are genuine
  strengths but held that independent hard failures across IDS, Kerberos, and endpoint telemetry
  dominate authenticity classification.

## Most Convincing Evidence

1. **Snort-to-Zeek payload contradictions.** Five of five named curl detections conflict with the
   only parsed HTTP User-Agent on their tuples; the APT mismatch and TLS-only urllib detections
   extend the defect beyond one signature. Repeated rule labels appear detached from observable
   triggering content.
2. **Machine-account TGT reacquisition every few minutes.** Dozens to more than a hundred
   successful 4768s per machine in six hours conflict with ordinary LSA ticket reuse. Its breadth
   across both DCs and multiple host roles makes this stronger than an isolated Kerberos anomaly.
3. **The 0.635 ms lock/unlock lifecycle.** This is a direct physical impossibility for a human
   unlock and is strengthened by the missing nearby Type 7 event and by coherent multi-minute
   lock/unlock examples elsewhere in the same corpus.
4. **Identical WFP ThreadID support across ten hosts.** Every host, despite materially different
   Event 5156 volumes, exhausts exactly the same 38-value set and emits no value outside it. A
   shared finite allocation pool is a more credible explanation than independent kernel activity.
5. **Repeated invalid TiWorker ancestry plus exact Linux subsystem quotas.** The same
   `svchost.exe -k netsvcs`/NETWORK SERVICE parent substitution recurs on six Windows systems,
   while unlike Linux hosts repeatedly stop at identical daemon-family counts. Together they show
   family-level templating across operating systems.

The strongest evidence on the Real side is the absence of broad causal inversions and the quality
of source-native relationships: process identity and termination, Zeek UID/protocol linkage,
loss-aware multi-vantage bytes, TLS/SNI/certificate consistency, proxy tunnel reuse, ASA
build/teardown pairing, role-sensitive source volumes, and a coherent attack-and-cleanup chain.
These strengths explain why the final score is not 100 and should be preserved during fixes.

## Most Debated Points

- Whether narrow cross-sensor and inter-provider timestamp envelopes reflect deterministic delay
  profiles or stable production clocks and logging pipelines.
- Whether the absent source PsExec process and close-only SSH evidence are coherent collection
  loss or incomplete lifecycle construction.
- Whether similar Linux PID slopes are meaningful after accounting for unobserved churn and
  collection selection.
- Whether FILE-SRV's universal NTLM profile signals a missing Kerberos state model or a plausible
  SPN/policy failure.
- Whether concentrated scanner sources and repeated HTTP shapes are overly curated or credible
  campaign/updater behavior in a bounded window.
- Whether the Threat Hunter's strong operational narrative and cross-source pivots should offset
  defects in lower-level source contracts. The panel concluded that good narrative coherence
  cannot neutralize payload mismatches or physically impossible lifecycle timing, but it remains
  a material realism strength.

## Improvement Recommendations (Consensus)

1. **Bind IDS alerts to the exact observable trigger.** For the perimeter tuples using source
   ports 41512, 52164, 44261, 51613, and 47332, a curl rule must not coexist with Zeek's sole Go or
   Wget User-Agent. Derive alert identity from the same HTTP header rendered to Zeek/proxy logs and
   enforce negative contracts among curl, Wget, APT, Go, and urllib signatures.
2. **Respect encryption visibility.** Do not emit Python-urllib content detections on the
   `10.10.3.20:48048 -> 52.84.215.166:443` and
   `10.10.3.20:42257 -> 104.16.197.212:443` origin TLS flows unless a log-visible decryption point
   owns those observations. If inspection occurs at the proxy, attach the alert to the decrypted
   client-side transaction; otherwise use TLS-visible indicators.
3. **Maintain Kerberos ticket cache state.** Reuse machine-account TGTs and service tickets across
   ordinary activity. Emit fresh 4768s only for boot/first use, expiry or renewal, credential
   changes, cache purge, or failure/recovery conditions. Validate per-account issuance rates over
   multi-hour windows.
4. **Repair Windows session and ownership invariants.** Generate lock/unlock from a session state
   machine with human-scale locked duration and a Type 7 companion when that audit family is
   visible. Resolve the WS-MCHEN Event 4648 source address from the local `runas.exe` owner so PID
   `0x20d0` cannot be paired with unrelated address `10.10.1.99`.
5. **Replace shared host metadata pools with host lifecycle state.** Allocate Event 5156 ThreadIDs
   per host/boot/CPU context and allow realistic churn outside a universal 52-200 set. Correct the
   servicing process family so TrustedInstaller owns TiWorker across Server 2022, Windows 10, and
   Windows 11 paths. Revisit Security/Sysmon delay distributions without forcing a single order.
6. **Drive Linux background activity from subsystem state, not quotas.** Vary
   `systemd-resolved`, `anacron`, and `dbus-daemon` counts and vocabulary by role, uptime, faults,
   and recovery episodes. Let PID consumption follow modeled and role-specific unobserved process
   churn. Reduce exact reuse of long parameterized shell commands across unrelated users and
   hosts.
7. **Preserve attribution and observation coherence through action lifecycles.** Keep the source
   PsExec process when process telemetry is otherwise present, attribute APP-INT's read of
   `/tmp/.cache/rpt_0318.sql.gz` to the forwarding process/session, and apply SSH collection drops
   coherently to connection/auth/open/close groups rather than leaving a lone close for PID
   1937270.
8. **Protect the existing realism strengths as regression invariants.** Retain sensor-local Zeek
   UIDs, loss-aware multi-vantage accounting, DNS answer/TTL consistency, TLS/SNI/certificate
   contracts, proxy tunnel identity, varied connection states, ASA lifecycle pairing, process
   identity integrity, role-sensitive source volumes, and concrete cleanup consequences.
