## Prioritized reported issues

Categories and priorities below are synthesis judgments. Reviewers did not assign
P0–P4 labels. Coordinator-only residual probes are explicitly distinguished from
new independent panel findings; no reviewer score was recomputed from those probes.

| Priority | Issue | Category | Original reviewer rating | Score impact | Evidence and next action |
|---|---|---|---|---|---|
| P0 | ASA direction/reset projection | contract_gap | Network 43: not labeled | High | All 4,528 outbound TCP builds use initiating-endpoint-first layout;60 unambiguous DMZ/external resets invert the native I/O side labels. Repair the ASA native projection from canonical endpoint/security-side facts, covering both directions, NAT and UDP; retain the correct underlying transport tuple. |
| P0 | Zeek stream extent versus capture bytes | hard_contradiction | Network 41: not labeled; coordinator recheck 43 | High | Fresh probes reproduce 570 completed sensor pairs whose stream-total deficits equal relative capture gaps. Separate sequence-derived stream extent from captured packet/payload and application/file ledgers at the observation owner. |
| P1 | Browser fragments in HTTP targets | hard_contradiction | Detection 42: not labeled; coordinator recheck 43 | High locally | Thirteen quoted proxy requests contain literal client-side URL fragments. Normalize the canonical request target before generating proxy/HTTP evidence, retaining full navigation URLs only in an appropriate client source. |
| P1 | Small-command and pipeline runtimes | distribution_texture | Host 43 / Detection 43: not labeled | Medium–high | All 46 selected short head/tail pipeline stages last 0.468–4.980 s, with none below 0.4 s; an 88-second Mac id and 12–14-second document cat operations are weaker related leads. Model command/EOF/producer completion through the shared execution lifecycle, qualifying blocking alternatives rather than declaring individual slow commands impossible. |
| P2 | Mac process-version allocation blocks | distribution_texture | Detection 43: not labeled | Medium, qualified | New process versions return from 69–71 to 47–58 and 84–85 to 72–83 in later native records. Establish the qualified native allocation/sanitization contract before changing the canonical identity allocator; no collision or same-identity lifecycle contradiction was demonstrated. |
| P2 | SMB vocabulary and target-role binding | environment_or_collection_plausibility | Host 43 / Threat 43: not labeled | Medium, qualified | Twenty-nine NETLOGON/SYSVOL invocations reuse recombined policy vocabulary, while web/integration content also targets DC shares. Check stable share trees and service-role selection; custom deployment and organization-specific automation remain plausible explanations. |
| P4 | Shared cron and Mac command vocabulary | weak_signal | Threat 43: not labeled | Low | Ten Linux hosts each show twelve half-hour sysstat jobs, and one user repeats tools across two Macs. Shared schedules and user habits explain these patterns well, so retain them unless independent evidence establishes a role or platform mismatch. |

### Owning layers, risk and classification

- ASA: source-native firewall projection, with security-side context supplied by
  topology/firewall policy. New family surfaced in this panel, not a Mac-timing
  regression. Medium risk; cover TCP/UDP, inbound/outbound, mapped endpoints and
  reset sender. Coordinator reproduces 4,528 outbound TCP rows, including 4,501 cross-
  interface and 27 same-interface cases. The latter are not independently qualified
  by the cross-interface ordering check. All 7 outbound UDP rows are cross-interface.
  Reset inversion is independently reproduced on 41 RSTO and 19 RSTR unique pairs.
- Stream/capture: shared source-observation and application-child accounting;
  carried known family, high architectural risk. Preserve physical packet/header
  partition guarantees while separating the different source meanings.
- HTTP targets: canonical browser/HTTP request construction; carried known family,
  medium risk. Preserve encoded `%23`, queries and the distinct CONNECT authority
  form; avoid emitter-only stripping.
- Command runtime: execution/action lifecycle and command semantics; sibling family,
  medium risk. A selected short-stage distribution is evidence, not a proof that
  each process must finish before a fixed latency. Mac id may involve directory
  lookup or scheduling; mounted document reads can include storage/terminal delay.
- Mac identity: native identity/timeline allocation; recurring qualified lead,
  high risk until native monotonicity/sanitization semantics are established.
- SMB roles/vocabulary: world capabilities and storage catalogs/operation intent;
  sibling distribution lead, medium risk. Avoid inventing GUI evidence to replace
  legitimate explicit shell access.
- Cron/vocabulary: false_positive_or_unproven as a repair target, low leverage.
  Do not add arbitrary randomness to a justified half-hour scheduler.

### Priority rationale and verification

ASA is the strongest newly independent specialist finding and offers a bounded
native-source repair. Its mapped endpoints and reset senders already exist in
canonical evidence; the defect is their ASA projection, so an emitter/projection
fix can be the correct owning-layer repair. Stream/capture accounting remains an
important architectural contract, with higher implementation risk. Request-target
normalization is a narrower high-value fix. Runtime texture follows these concrete
source-native errors; the identity and storage leads retain explicit uncertainty.

[Cisco's ASA message definitions](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html)
identify Reset-I/O by inside/outside side, independently of Zeek originator/responder.
[Cisco's NAT example](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/15243-19.html)
shows the outbound foreign-first/local-second message representation. Both were
checked against the reviewer examples and saved ASA probe.
[Zeek's Conn::Info definitions](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html)
and [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1)
support the two carried contract findings. Exact probe scopes and examples are in
`asa-source-semantics-probe.json`, `residual-contract-probes.json` and
`source-semantics.md`. No source repair was made in this assessment.
