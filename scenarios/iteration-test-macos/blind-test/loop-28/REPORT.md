# Loop 28 assessment

The machine schedule owner now excludes user-scoped Tracker units on both servers and workstations. The config loader/validator accepts explicit execution scope; explicit scenario processes remain eligible. Eleven focused tests passed, configuration validation found zero errors, and Ruff passed. Rendered automatic Tracker starts are zero. Actual updatedb starts are zero in this short window; focused tests verify system-maintenance eligibility remains intact.

Standalone scores are 29/27/74/43 (mean 43.25); facilitator-modeled deliberation is 45/43/68/50 (mean 51.5). Network identified retransmitted SMTP responses whose wire counters allow no repeated payload; this verified accounting family is targeted in loop 30. Shell texture observations require checking authored timing before any product change. Quantitative eval remains a passing guardrail at 96.3065 and does not test these expert timing/accounting relationships.

## Family contract

# Linux task execution scope

Family-level owner: task catalog/schema plus shared deployment and baseline eligibility boundaries. Tracker is a user-session service, not a root machine timer. Declare execution_scope explicitly; machine task generation/inventory must reject user-scoped descriptors on both servers and workstations, while genuine system maintenance remains eligible. Explicit scenario process intents remain supported separately. This does not invent a user-session lifecycle; automatic user-unit scheduling is intentionally unsupported until a user-session owner exists. Consumers: machine task inventory, root process/syslog timer evidence. Test both entry paths and a real system task sibling; config validation rejects unknown scope. Low/moderate risk. Primary reference: Debian bookworm tracker-miner-fs file list places the unit under /usr/lib/systemd/user/.


## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 84; synthetic-confidence score 29. The supplied records support practical hunting across Windows, Linux, macOS, network sensors, proxy and firewall sources. Representative SSH, file-staging and Windows credential-access pivots are technically coherent; I found no demonstrated impossible ordering or source-native contradiction in the checks described below. Shell-history texture merits scrutiny, but plausible collection settings prevent treating it as decisive evidence of synthesis.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 27. The inspected records are mostly production-like and suitable for ordinary SIEM parsing and correlation. I found no defensible hard contradiction in the bounded checks: source-native event shapes, observed process lifecycles, and representative network/protocol relationships are coherent. These results support realism, but do not distinguish genuine collection from carefully constructed synthetic telemetry with sufficient confidence to assert provenance.

**Network Forensics:** Synthetic; verdict confidence 88; synthetic-confidence score 74. The network data is largely coherent, with realistic protocol diversity, explicit proxy behavior, and consistent protocol-to-connection references. Two Zeek TCP records nevertheless contain a concrete accounting contradiction: responder payload retransmission is recorded while the responder IP-byte total leaves no room for any retransmitted payload. A broader population of unusually small retransmission budgets supports concern about how packet statistics were constructed, although those additional records are not individually impossible.

**Host Forensics:** Inconclusive; verdict confidence 72; synthetic-confidence score 43. The endpoint evidence is substantially coherent across Windows, Linux, and macOS. Repeated macOS command/startup timing has a modest scripted texture, but the bounded checks did not establish a hard contradiction, so the available endpoint evidence does not support a confident synthetic verdict.


## Deliberation

See deliberation.md for modeled reconciliation; initial standalone scores are preserved.

## Prioritized improvements

P1: shared retransmission wire payload budget (Network, repeated, high leverage, canonical network owner, medium risk). P1: automatic Windows management target capability selection (Threat, repeated, medium leverage, world model/baseline owner, low risk). P2: opaque CONNECT stream accounting across legs (Network, repeated, medium leverage, proxy bundle owner, architectural risk). Narrative-only impressions and unverified schema claims are excluded.
