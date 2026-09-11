# Iteration Test Blind Assessment — Loop 59

## Outcome

Both loop-59 family contracts pass direct rendered probes. All 522 successful tunnels matched on
the DMZ sensor by SNI and exact proxy tunnel byte counts preserve CONNECT request before proxy-origin
TCP open and TLS detection; the minimum gaps are 8.074 ms and 31.597 ms. Across Windows telemetry,
all 969 exact Security 4688/Sysmon Event 1 process joins agree on integrity, no High user process has
the wrong elevation token, and all 30 matched Type 10 `userinit.exe`/`explorer.exe` rows share the
nonzero session `LogonGuid`. Automated evaluation passed at 96.2817 across 122,916 records.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 82 verdict confidence, 44 synthetic-confidence. Exact process,
network, lifecycle, and storyline pivots were strongly production-like. Systematic RDP client FLOW
attribution loss, incompatible curl versions on near-simultaneous same-binary executions, and sparse
Windows process churn prevented a Real verdict, but the hunter found no hard contradiction alone.

**Detection Engineer:** Synthetic, 78 verdict confidence, 72 synthetic-confidence. Three tightly
joined KDC-local exchanges place 4769 before 4768 by 7.949–30.950 ms, while 119 of 204 nearby
machine-account sequences place 4624 before the nearest 4769. Zero Kerberos `LogonGuid` values, two
orphan HTTP FUIDs, and a narrow registry-write delay reinforced the verdict. Exact Windows process
triples and source schema fidelity remained strong.

**Network Forensics:** Synthetic, 84 verdict confidence, 72 synthetic-confidence. All 3,885 UDP DNS
rows have positive delay after their same-sensor connection start; 3,863 one-query/one-response
`Dd` flows therefore separate the DNS query from its only possible origin packet and close after the
modeled response. Sub-millisecond external SMTP application timing, a balanced PAT-port pool, short
browser tunnels, and three orphan FUIDs added support. Proxy causality, TLS/certificate identity,
firewall lifecycle, packet accounting, and sensor clocks were otherwise highly convincing.

**Host/EDR Forensics:** Synthetic, 84 verdict confidence, 72 synthetic-confidence. A DB-PROD-01 root
history sequence starts before its matching SSH transport, authentication, shell, and child-process
evidence, then interleaves commands with a foreground dump process. Fleet-wide reuse of exact Linux
IRQ/device inventories, narrow RDP auth latency, and mixed eCAR file-ID shapes added texture. Windows
process identity, ancestry, terminalization, RDP bootstrap GUIDs, and source-native schemas were
strong.

## Deliberation Findings

Verdict disagreement required deliberation. The facilitator accepted the one-packet DNS proof as a
dataset-wide hard contradiction and retained the Kerberos and DB shell findings as independent,
high-specificity defects with narrower alternative explanations. Final synthetic-confidence scores
were 70, 78, 82, and 80 (mean 77.5), unanimously Synthetic. This is a 9.25-point improvement from
loop 58's deliberated mean.

## Prioritized Improvements

### P0 — Restore packet-derived Zeek DNS timing

The canonical UDP DNS query packet must own both `conn.ts` and `dns.ts`; for a single-query,
single-response `Dd` transaction, the response packet must likewise own both `dns.ts + rtt` and the
transport close. Apply sensor clock/route projection once to the transaction, not independently to
protocol siblings. Cover all sensor views and retransmission paths.

### P0 — Unify SSH session, shell, command, history, and process timing

One action timeline must own transport, authentication, shell readiness, command starts, process
lifecycles, and history. External foreground commands must occur after shell creation, receive child
process evidence when collected, and serialize unless explicitly backgrounded.

### P0 — Enforce Kerberos AS/TGS/logon source-local order

Build TGT, TGS, and dependent logon evidence through one canonical authentication dependency graph,
then project source delay without allowing 4769 before its required 4768 or 4624 before its required
4769. Exercise machine, user, service, and DC-to-DC siblings.

### P1 — Correct SMTP readiness and connection-population models

Place SMTP records after handshake/banner/application readiness, including WAN latency. Replace the
balanced PAT pool with stateful allocation and broaden browser tunnel persistence and request reuse.

### P1 — Derive Linux hardware messages from per-host inventory

Assign stable devices, IRQs, CPUs, and accelerators by host class and role; render kernel and
`irqbalance` evidence only from that inventory rather than a fleet-wide vocabulary.

### P1 — Complete the RDP transport/auth/process contract

Retain actor/PID attribution on source flows when process visibility permits and condition auth
latency on path, host, DC, authentication package, and reconnect state while preserving ordering.

### P2 — Make object references and application identity coherent

Share observation decisions between protocol FUID references and file rows. Standardize eCAR file
identity and derive HTTP/proxy User-Agent versions from canonical executable identity unless an
explicit override is modeled.

## Priority Rationale

DNS is first because it is a same-sensor packet contradiction across nearly every UDP transaction.
SSH and Kerberos follow because they break causal reconstruction in independent host and auth
families. SMTP, PAT, browser persistence, inventory, and RDP are broad fingerprints but have more
environmental alternatives. Sparse FUID, file-ID, and application-version defects remain important
cross-source cleanup after the causal owners are repaired.

## Comparison with Quantitative Eval

The deterministic evaluator remained at 96.2817 with the same pillar shape as loop 58: 99.9992
parseability, 96.8186 plausibility, 93.9479 causality, and 92.9514 timing. It confirmed broad schema,
field-agreement, causal-order, and rate requirements, while flagging one eCAR rename action, two HTTP
file-reference gaps, OCSP identity mismatches, two missing storyline events, and weaker pivot/timing
targets. It did not detect either repaired loop-59 family or the new DNS packet identity, KDC-local
ordering, SSH/history chronology, SMTP readiness, PAT allocation, and inventory findings. Rendered
contract probes and blind review therefore remain necessary complements to aggregate scoring.
