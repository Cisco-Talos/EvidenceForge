# Loop 43 Assessment Report

Loop 43 generated 79,750 new records after correcting proxy CONNECT byte
scopes. Automated evaluation remained 96.1147 and failed only pivot linkability.
For 611 matched successful CONNECT rows, zero Zeek connections equaled the
tunnel-only ledger; 510 matched the additive control-plus-tunnel total exactly,
with remaining differences explained by sensor observations. No terminal denial
retained tunnel fields. The Network reviewer explicitly identified the new
proxy scoping as realistic and did not repeat the prior contradiction.

The initial blind panel was Inconclusive/Synthetic/Synthetic/Synthetic at
44/87/67/87, average 71.25. Verdict disagreement and a 43-point spread triggered
deliberation; all four converged on Synthetic at 88/93/89/94, average 91.0.

## Individual Expert Summaries

The Threat Hunter was initially Inconclusive (78% verdict confidence,
synthetic-confidence 44). Attack pivots, volumes, and ordering were convincing;
its main concerns were dense repeated SSH administration, paired rotating
health checks, and one privileged workstation-to-server ownership gap.

The Detection Engineer assessed Synthetic (94%, 87). All 296 Type 5 logons for
built-in service principals used dynamic LUIDs instead of `0x3e7`, `0x3e5`, or
`0x3e4`, and machine accounts generated 515 TGT requests with minute-scale churn
and rapidly varying encryption/options.

The Network analyst assessed Synthetic (76%, 67). It found 15 repeated cases in
which two sensors reported different HTTP response body lengths despite
identical complete TCP streams, plus a thin nine-source scanner population and
near-fixed DHCP renewal intervals. It considered proxy byte scoping realistic.

The Host/EDR analyst assessed Synthetic (93%, 87). Multiple hosts created
overlapping live `svchost -s` instances for singleton services such as Schedule,
LanmanServer, BITS, and EventLog; later activity proved predecessor PIDs still
active. It also found a capped kernel uptime residual and narrow UFW populations.

## Deliberation Findings

The panel converged unanimously on confidently Synthetic. Cross-specialty
findings were independent and source-semantic: built-in-token identity,
singleton service lifecycle, and gap-free cross-sensor HTTP values could not be
explained by strong schemas, completeness, or bounded-window state. Operational
realism remained a strength but did not negate these repeated contradictions.

## Prioritized Improvements

- **P0 — Enforce one active process per named singleton Windows service.** Host
  showed live overlapping instances across several hosts and three endpoint
  sources. Reuse the active canonical `svchost -s <service>` PID, or explicitly
  terminate/restart it before replacement. Owning layer: system-process planner
  and process state; high leverage, low-to-medium risk.
- **P0 — Reuse well-known built-in service LUIDs.** Detection found every
  SYSTEM/Local Service/Network Service Type 5 logon using a dynamic value.
  Propagate `0x3e7`/`0x3e5`/`0x3e4` through Security, eCAR, privileges, process,
  and closure evidence. Owning layer: service-logon/session bundle; medium risk.
- **P0 — Preserve one canonical HTTP body length across complete sensors.**
  Sensor-local loss may alter parser results only when observation state records
  gaps. Owning layer: network observation plan and HTTP projection; medium risk.
- **P1 — Add host/principal Kerberos ticket caches.** Machine TGT issuance should
  occur on cache miss, expiry, renewal, purge, or new context with stable
  capability preferences. Owning layer: authentication state; medium-high risk.
- **P1 — Expand scanner and operational long tails.** Increase transient scan
  sources and specialize SSH/health checks by stable workload and role. Owning
  layer: baseline profiles/config; low-to-medium risk.

## Priority Rationale

The singleton service family is selected for Loop 44 because it is a repeated
hard lifecycle contradiction, spans multiple hosts and sources, and has a
bounded low-risk root fix: canonical named-service process reuse. Built-in LUID
and cross-sensor HTTP defects are equally source-semantic but affect broader
authentication or observation contracts.

## Comparison with Quantitative Eval

Automated evaluation passed parseability, source agreement, and causal ordering
because it does not yet encode named-service singleton constraints, well-known
service LUID semantics, or sensor-equality requirements for gap-free HTTP bodies.
Its only gate failure remained pivot linkability. The blind panel therefore
continues to expose high-value semantic constraints missed by aggregate scoring.
