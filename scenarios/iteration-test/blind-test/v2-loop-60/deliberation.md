# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive — synthetic-leaning | 80/100 | 56/100 | Synthetic | 85/100 | 68/100 |
| Detection Engineer | Synthetic | 95/100 | 86/100 | Synthetic | 96/100 | 88/100 |
| Network Forensics | Real | 74/100 | 34/100 | Inconclusive — synthetic-leaning | 78/100 | 53/100 |
| Host/EDR Forensics | Synthetic | 80/100 | 68/100 | Synthetic | 86/100 | 77/100 |

## Key Agreements

- The panel’s final majority assessment is **Synthetic**, with three synthetic verdicts and one inconclusive, synthetic-leaning verdict. The disagreement concerns strength, not the existence of suspicious artifacts.
- No expert found a P0 hard contradiction such as impossible visible ordering, create-after-terminate behavior, malformed identifiers, or authentication preceding transport.
- Schema fidelity, temporal ordering, cross-source correlation, protocol semantics, and attack-path usability are unusually strong. The Windows log-clear and PsExec sequences, scan response texture, DNS cache aging, TLS behavior, sensor clock differences, and transfer-byte agreement were repeatedly judged convincing.
- Completeness itself is not evidence of synthesis. The panel distinguished technically coherent correlation from concrete fingerprints such as finite global value pools, implausible process structures, asymmetric lifecycle loss, and repeated distribution texture.
- The Detection Engineer’s Windows thread-ID finding materially changed the discussion. A common image or shared configuration might explain some cross-host similarity, but it does not readily explain every host exhausting the same 38-value Event 5156 pool, separate event-family-specific pools, and the sharp 4625 boundary across heterogeneous systems.
- The panel agreed that collection loss remains a viable explanation for isolated missing artifacts. It becomes less persuasive where loss repeatedly preserves one lifecycle half, or selectively removes attribution from highly relevant activity while retaining it for nearly all comparable traffic.

## Key Disagreements

- **Windows fingerprints versus network realism:** The Detection Engineer regarded the global thread-ID pools as decisive evidence of generation. The Network Analyst emphasized organic-looking clock drift, packet differences, connection-state distributions, DNS TTL aging, and TLS visibility. The panel concluded these positions are compatible: sophisticated network evidence does not invalidate independent endpoint-generation fingerprints.
- **Firewall-policy discontinuity:** The Network Analyst found repeated denies changing to bulk acceptance during the scan and then reverting. A temporary ACL, dynamic pinhole, or uncollected policy change could explain it, so the panel did not elevate this to a hard contradiction. It remains a significant contract gap because the supplied traffic evidence provides no transition context.
- **Browser subprocess absence:** The Host Analyst treated monolithic, long-lived browser processes as a major defect. Process filtering could hide browser children, but the corpus’s approximately 99% Security/Sysmon/eCAR process matching and repeated independent Firefox URL launches make generic collection loss an incomplete explanation.
- **SSH lifecycle gaps:** The Threat Hunter found seven fully in-window sessions with activity and close evidence but no PAM open. Syslog loss or filtering remains possible without collector-health telemetry; however, the repeated open-versus-close asymmetry makes simple window censoring untenable.
- **Background uniformity:** Shared Linux images and package defaults could explain common `irqbalance`, `snapd`, CRON, and anacron behavior. The Host Analyst maintained that identical commands, cadences, and narrow message pools across role-diverse hosts exceed what shared provisioning alone would normally produce.
- **Overall authenticity threshold:** The Network Analyst did not consider the network evidence independently sufficient for a synthetic verdict and therefore revised only to inconclusive. The other experts judged the endpoint and metadata fingerprints sufficiently broad to outweigh the production-like network layer.

## Most Convincing Evidence

1. **Identical Windows execution-thread populations across ten hosts:** All 11,605 Event 5156 records use the same 38 multiples of four from 52 through 200, with every host exhausting the set. Separate fixed pools govern several authentication families, while almost every 4625 failure falls outside them. The panel judged this the strongest synthetic indicator because ordinary thread alignment does not explain the exhaustive cross-host and event-family partitioning.

2. **Implausible browser ownership and lifecycle modeling:** Across 44 browser creates on eight hosts, only two roots have visible children, while most completed browser processes last over an hour. Four separate Firefox URL-bearing processes on one workstation remain alive concurrently without normal multiprocess children or reuse behavior.

3. **Repeated, fully in-window SSH lifecycle omissions:** Seven of 37 sessions independently established as starting and ending in-window preserve PAM close evidence while lacking the corresponding open. Genuine loss remains possible, but the repeated asymmetric lifecycle pattern is stronger than an ordinary bounded-window gap.

4. **Production-like network mechanics:** Connection states, packet accounting, DNS cache aging, independent sensor UIDs, clock drift, TLS/certificate behavior, and firewall lifecycle accounting all show convincing source-native behavior. This is the strongest evidence against a confident corpus-wide synthetic verdict and the main reason the panel did not converge near 100 synthetic confidence.

5. **Dataset-wide distribution fingerprints outside Windows metadata:** Virtually every AAAA query follows its paired A query within a narrow interval; Linux hosts reuse a small fleet-wide daemon vocabulary and identical scheduled commands; and 93.2% of public-host firewall blocks come from five invariant scanner profiles. Each has a possible operational explanation, but together they reinforce a shared generative-texture hypothesis.

## Most Debated Points

- **Could collection or export normalization explain the Windows thread pools?** A collector transformation could theoretically normalize metadata, but no report found evidence of such a transformation. It would also need to explain the exhaustive per-host pools and event-family boundaries. The Detection Engineer retained the strongest verdict, increasing synthetic confidence from 86 to 88.
- **Can excellent network realism coexist with synthetic endpoint evidence?** Yes. The network findings establish that substantial portions of the corpus are believable; they do not directly refute the endpoint metadata and process-model findings. This moved the Network Analyst from Real at 34 synthetic confidence to Inconclusive — synthetic-leaning at 53.
- **Are absent browser children merely filtering?** Filtering remains possible, so this is not a hard contradiction. The repeated long-lived independent roots, especially Firefox launches that should normally hand off to an existing instance, persuaded the Threat Hunter to revise from inconclusive to Synthetic.
- **Is the firewall transition evidence of generation or an unseen control-plane event?** The panel could not resolve this from traffic logs alone. The finding remains actionable because synthetic data should either obey the standing policy or make the temporary exception observable somewhere appropriate.
- **How much weight should be placed on several moderate indicators?** No single SSH, DNS, Linux-noise, scanner, attribution, or timing finding proves synthesis. The Host Analyst increased synthetic confidence because these patterns recur across independent source families and align with the stronger Windows metadata fingerprint.

## Improvement Recommendations (Consensus)

1. **Generate Windows execution metadata from persistent, host-specific process and thread state.** Replace finite global ThreadID pools with per-host lifecycles influenced by OS build, service process, event provider, concurrency, and load. Ensure related event families share the correct provider process without imposing visibly separate success/failure pools.

2. **Rebuild browser activity as an action lifecycle.** Model a persistent browser root with realistic renderer, GPU, network, utility, and crash-handling children. Subsequent URL invocations should usually hand off to the existing instance and terminate quickly unless an independent profile or explicit new-instance option is present.

3. **Make SSH observation decisions lifecycle-coherent.** Group accepted authentication, PAM open, session creation, shell activity, PAM close, and transport closure under coherent source-local observation decisions. Preserve deliberate pivot process ownership when available; if attribution loss is modeled, distribute it across comparable benign and suspicious sessions.

4. **Make firewall policy authoritative across all network evidence.** Have scan outcomes follow the active ACL. If temporary access is intended, represent the rule installation or dynamic authorization, its effective interval, and restoration so ASA, Zeek, endpoint, and IDS observations agree with one policy state.

5. **Diversify recurring activity using host- and role-specific populations.** Vary Linux daemon availability, package history, maintenance commands, message vocabulary, and cadence. Add long-tailed Internet scanner sources and diversify resolver behavior with AAAA-first, simultaneous, single-family, cached, and legitimately missing companion queries.

6. **Add host-specific source-native identity and semantics.** Assign stable NT device-volume mappings per installation, render deployment-appropriate SYSVOL/NETLOGON paths, and remove Sysmon Event 8 from read-only LSASS access unless an actual injection lifecycle with a plausible remote entry point is modeled.

7. **Preserve the corpus’s strongest realism features.** Retain sparse subnet responses, bursty timing, lifecycle ordering, independent sensor identifiers and clock offsets, DNS TTL decrementing, TLS visibility behavior, source-native schemas, and cross-source byte and tuple agreement.

