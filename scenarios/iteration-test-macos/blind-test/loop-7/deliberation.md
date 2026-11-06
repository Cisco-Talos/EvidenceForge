# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 63 | 64 | Synthetic (initial position carried forward; no revised assessment supplied) | 63 | 64 |
| Detection Engineer | Synthetic | 78 | 62 | Synthetic (initial position carried forward; no revised assessment supplied) | 78 | 62 |
| Network Forensics | Inconclusive | 67 | 37 | Inconclusive (initial position carried forward; no revised assessment supplied) | 67 | 37 |
| Host/EDR Forensics | Synthetic | 76 | 63 | Synthetic (initial position carried forward; no revised assessment supplied) | 76 | 63 |

The four reports contain independent initial assessments only. No expert supplied a revised position after cross-examination; the final columns therefore repeat the reported initial scores and do not represent invented revisions.

## Key Agreements

- All four experts found meaningful source-native and cross-source consistency. Examples include Windows process/authentication records, macOS SSH client-to-server tuple and timing matches, Zeek application-to-connection UID joins, and proxy/firewall/endpoint pivots. The panel treated this corroboration as evidence of coherent records, not as proof by itself that the data is real.
- The main concerns are bounded anomalies rather than broad format failure. The reports identify no general parser-breaking or source-schema defect in their reviewed samples.
- The Mac records deserve attention, but the observed issues differ in strength: eCAR timestamp collapse affects event ordering; repeated shell-command texture and document utility pairings are behavioral concerns; repeated Unified Log trace IDs are explicitly weak because uniqueness semantics are unknown.
- Missing records require care. Shell-history omissions may reflect incomplete history, an eCAR batching delay may reflect collection, and a network TLS record cannot establish the client's certificate-validation outcome.

## Key Disagreements

- Three experts assessed the bundle as synthetic, while Network Forensics remained inconclusive. The network analyst found varied connection states, plausible protocol mix, and strong tuple/byte/timing pivots across Zeek, proxy, firewall, IDS, web, and endpoint FLOW records. Their sole material synthetic concern was an expired R3 intermediate in a completed `www.reddit.com` TLS session; the analyst could not determine whether the client accepted or rejected it. This supports caution but does not directly refute the endpoint and host-side concerns.
- Threat Hunter's leading concern is a host-level contract gap: two successful root SSH sessions are visible in APP-INT-01 eCAR, but matching sshd acceptance/session-open evidence is absent from that host's syslog, with only a close for the second session. Other users do have syslog SSH/PAM lifecycles. The other experts did not discuss this specific gap, so the reports provide no cross-examination that resolves whether it is collection loss or generation inconsistency.
- Detection Engineer and Host/EDR Forensics both emphasize macOS, but weight different signals. Detection Engineer centers on four native fork/exec transitions compressed into one eCAR millisecond, with repeated trace ID and command vocabulary as weaker signals. Host/EDR Forensics emphasizes recurring inventory routines, repeated `cat`/`tee` operations on office-document paths, and history gaps. These observations can coexist; a shared operator workflow or incomplete history could explain some behavioral patterns, but would not by itself restore the lost ordering in eCAR.
- Host/EDR Forensics gives the Mac activity a low behavioral realism score (5), while Detection Engineer considers the endpoint shapes and SSH lifecycles plausible and scores behavioral realism at 7. This is a difference in weight assigned to unusual but possible user activity, not a disagreement about the observed records.
- No expert changed or confirmed a position in a follow-up report. The deliberation therefore preserves disagreement rather than claiming a consensus vote.

## Most Convincing Evidence

1. **APP-INT-01 SSH/syslog lifecycle gap — synthetic-leaning, strongest host-specific contract concern.** eCAR shows successful root SSH sessions with source tuples and session activity, while the destination syslog lacks corresponding acceptance/session-open records; other SSH users have those records. A collection gap remains possible, but the repeated visible sessions make this more specific than a general absence claim.
2. **Mac native-to-eCAR timestamp collapse — synthetic-leaning, strongest ordering defect.** Four distinct MAC-MROSS-01 Endpoint Security transitions spanning about 59 ms map to one eCAR timestamp roughly 1.1 seconds later. Batching could explain the delay, but the shared timestamp removes order needed by time-based detections.
3. **Expired R3 intermediate in an established TLS session — suspicious but inconclusive.** The `www.reddit.com` connection is otherwise a completed, correlated session, while the intermediate expired before observation. Zeek and endpoint FLOW evidence do not show the client's validation decision.
4. **Repeated Mac command and document-operation patterns — synthetic-leaning, moderate and interpretive.** Both Mac reports note recurring inventory-command vocabulary; Host/EDR also cites repeated `cat` reads and `tee` writes involving binary office documents and corresponding history omissions. Shared workflow, raw-byte use, or incomplete shell history remain possible explanations.
5. **Independent tuple and lifecycle corroboration — real-leaning.** Examples include aligned Windows process records, two cross-host Mac SSH sessions with matching tuple and auth timing, consistent Zeek UID joins, and proxy tunnel byte counts matching Zeek. These show substantial internal coherence, though they do not negate isolated defects.

## Most Debated Points

- Whether the APP-INT-01 SSH omissions reflect a real collection blind spot or a broken cross-source lifecycle. The session is visible in eCAR during the covered interval, and similar syslog lifecycles exist for other users, but the reports cannot establish collection policy for this host/session.
- Whether the eCAR timestamp collapse is a source-normalization defect with practical detection impact or acceptable batching. The native event ordering is distinct; the normalized timestamp is not.
- How much the Mac command texture should affect authenticity. Repeated probes and binary-document utility operations are possible, but their recurrence across two endpoints and the partial history coverage make the pattern more notable to Host/EDR than to Detection Engineering.
- Whether the expired certificate chain reflects synthetic certificate material, permissive/local trust, or an unusual server configuration. The completed TLS and TCP sessions establish transport completion, not successful certificate validation.
- Whether the coherent pivots outweigh localized anomalies. The Network Forensics inconclusive verdict reflects strong network consistency and limited proof from its one anomaly; the other synthetic verdicts rely on host/endpoint inconsistencies that network records cannot adjudicate.

## Improvement Recommendations (Consensus)

- Preserve native event ordering in eCAR for macOS fork/exec transitions. Store source event time separately from ingest time, or retain enough timestamp precision that distinct transitions do not collapse to one millisecond.
- Make APP-INT-01 SSH collection behavior internally consistent: emit the matching sshd acceptance and PAM session-open records for eCAR-visible successful logins, or represent a documented, observable collection gap that explains the missing records.
- Use a certificate chain valid at the observation time for successful TLS sessions, or include client-side evidence that explains rejection or a permissive trust path when an expired intermediate is presented.
- Broaden Mac routine activity and vary command timing across users and hosts. For document interactions, choose commands appropriate to the file format or include visible pipeline/redirect context that explains raw `cat`/`tee` use.
- Keep shell-history coverage aligned with the modeled collection behavior. If history is intentionally incomplete, make exclusions or gaps consistent rather than selectively omitting several visible executions while retaining nearby commands.
