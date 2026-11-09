# Loop 22: same-data model comparison

The user requested another assessment after correcting the selected model. This round uses four fresh, context-isolated reviewers inheriting the current gpt-6.1-sol session. They received the existing briefing and only their persona, a neutral data directory, and no prior reports, scores, scenario, or generator context. Generator and scenario were held unchanged: all 117 fresh data files match loop 21 and reviewer input byte for byte. Hashes are in comparison-provenance.json. No code changes or commits were made in this loop.

## Score comparison

All values below are standalone synthetic-confidence scores, where lower means more production-like.

| Reviewer | Loop 21 | Loop 22 | Difference | Previous 20 mean |
|---|---:|---:|---:|---:|
| Threat Hunter | 32 | 44 | +12 | 60.45 |
| Detection Engineer | 28 | 32 | +4 | 53.65 |
| Network Forensics | 88 | 88 | 0 | 52.00 |
| Host/EDR | 50 | 71 | +21 | 65.15 |
| Mean | 49.50 | 58.75 | +9.25 | 57.8125 |

The current mean is 0.9375 above the previous 20-loop mean, with unchanged deterministic evaluation at 96.349501 over 132,196 records. Historical loops 2–21 used evolving data; the adjacent loop21/22 pair alone controls input. The new panel demonstrates more precise evidence in several areas, but one run cannot establish comparative model accuracy or separate model effects from reviewer variation. Previous model identity is user-reported and unverified. No baseline scores were retrospectively changed.

## Individual Expert Summaries

**Threat Hunter — Inconclusive, verdict confidence 75, synthetic-confidence 44.** Credential ownership, Windows archive upload, Linux SCP and Mac SSH pivots were coherent, and its broad lifecycle checks found no visible actor-after-exit defect. Its main concern was 37 proxy-originating HTTP records with an exact 1 ms offset, plus weaker Mac command and office-file helper texture.

**Detection Engineer — Inconclusive, confidence 78, synthetic-confidence 32.** Windows XML, process/session identity, and elementary network accounting passed extensive checks. The only scored concern was an additive ProcessName field in all 38 Security 4658 version-0 records, conservatively treated as a native-template/enrichment issue; a suspected task XML defect was disproved.

**Network Forensics — Synthetic, confidence 98, synthetic-confidence 88.** It found full non-resumed TLS 1.2 ECDHE_RSA exchanges with RSA-2048 leaves and only 280 responder bytes beyond their certificate chain. A 256-byte signature alone leaves insufficient space for mandatory messages. It also found 152 of 2,516 successful DMZ HTTPS flows clustered in 1.200070–1.201719 seconds, while documenting credible DNS, proxy, UID, certificate-identity and protocol-state behavior.

**Host/EDR — Synthetic, confidence 87, synthetic-confidence 71.** It found repeated fractional command anchors, duplicated Chrome helper offsets, six exactly two-second inventory lifetimes, and 232 executable stat timestamps with fractions below 1,000 ns. Windows GUID and eCAR actor ordering remained coherent; same-shell foreground SSH overlap was explicitly qualified because job control could explain it.

## Deliberation Findings

Two Synthetic and two Inconclusive verdicts triggered deliberation. The facilitator modeled revised scores of 78 / 74 / 88 / 80 (mean 80.0), reflecting shared awareness of the TLS budget contradiction and Mac timing/metadata findings. These are modeled reactions to shared reports, not new independent reviewer turns or measured consensus; the standalone trend retains 58.75. The full deliberation report preserves that distinction.

## Prioritized Improvements

Reviewers assigned no original P0–P4 labels; priorities below were added during synthesis. Evidence verification and source ownership are documented in root-cause-probe.md and root-cause-probes.json.

| Priority | Issue and category | Reviewer | Scope / leverage | Owner, risk, and next action |
|---|---|---|---|---|
| P0 | TLS responder byte budget: hard_contradiction | Network | Repeated; high | Shared canonical TLS/network accounting. Replace certificate-size-plus-280 with protocol/key-aware full-handshake and application byte budgets; moderate risk, verify TLS 1.2/1.3, resumption, key sizes, SMTP STARTTLS, proxy and multiple sensors. |
| P1 | TLS duration floor: distribution_texture | Network | 152 DMZ observations; high | Same shared TLS accounting owner imposes 1.05 + 0.075 seconds per certificate. Model certificate observation and actual transport/application timing together rather than inflating every short connection; moderate risk. |
| P1 | Mac executable stat fractions: distribution_texture | Host | Both Macs, 232 timestamps; high | Installed-file provisioning subtracts integer-second ages then adds only 0–999 ns. Separate package/build preservation from host installation/access/change timing and keep file identity stable; moderate risk. |
| P1 | Mac process timing templates: distribution_texture | Host | Multiple batches, two Chrome starts, six inventory jobs; medium/high | Authoring intent and shared process lifecycle planners own launch phases and durations. Trace explicit timing versus generated scaffolds before introducing independent realistic phase timing; moderate risk. |
| P2 | Exact proxy HTTP timing floor: distribution_texture | Threat | 37 rows, 16 user agents; medium | Canonical network/application request planner applies 1 ms minimum to application-only requests lacking explicit request time. Preserve upstream request intent through proxy planning; moderate risk. |
| P3 | Security 4658 extra ProcessName: schema_or_format | Detection | 38/38 rows; low | Source-native Windows template owns the field set. Verify against native schema and separate any intentional enrichment; low risk. |
| P3 | Foreground SSH overlap: contract_gap, unproven | Host | One local shell; low/medium | Shell/session planner or explicit scenario commands own foreground/job-control behavior. Verify whether suspension, backgrounding or distinct shell intent is actually required before changing lifecycle scheduling; moderate risk. |

## Previous finding correction

The previous panel's alleged sixth port is a false positive: all 254 rows are ICMP echo type 8/code 0, not TCP port 0. Official Zeek semantics and a direct parent probe confirm this. The new Network reviewer independently recognized ICMP type/code semantics without being told the previous diagnosis. A correction banner was added to loop21's synthesized report; original reports and scores remain preserved. Neither the broad scan nor complete correlation is a defect by itself.

## Priority Rationale and Quantitative Comparison

The verified TLS impossibility outranks distribution concerns. Both TLS byte and duration issues trace to `_ensure_tls_conn_covers_certificate_bytes` in the canonical generation owner; the fixed 280-byte and 1.2-second minima explain why elementary file-fits-connection and timing checks pass while protocol lower bounds fail. The deterministic evaluator remains PASS at 96.349501 and does not enforce the full handshake lower bound or flag these narrow timing/metadata distributions. The next repair should target that shared TLS owner first, followed by canonical Mac installed-file metadata and generated process timing. This round deliberately records those repairs as next work to keep its model comparison on identical data.
