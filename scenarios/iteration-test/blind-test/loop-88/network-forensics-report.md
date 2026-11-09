# Network Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 67

## Executive Summary

Zeek schemas, states, counters, DNS, proxy and cross-sensor observations are coherent. The reviewer found concentrated DB flows and sustained external scans against one DMZ host conspicuous in combination, while recognizing that the patterns are technically plausible.

## Evidence For Synthetic

- **[distribution_texture]** `zeek-db/conn.json` has 291 of 478 connections from `10.10.3.10` to `10.10.4.10:3306`; states vary, but the concentration is notable.
- **[distribution_texture]** DMZ records show thousands of probes to `10.10.3.10`. For example, `185.220.88.13` has 232 probes across service ports; `185.220.163.140` has 200 across database ports, with source-specific port portfolios.
- **[weak_signal]** Core DNS has hundreds of repeated DC hostname queries. Such lookups can be normal.
- Different sensor totals (core 12,891; DMZ 10,334; DB 478) are partly role-explained, but DB concentration is narrow.

## Evidence For Real

- TCP states and counters include completed, incomplete, rejected and reset flows; failed handshakes commonly show a single origin packet and no response.
- Core and DMZ see the same workstation-to-proxy flow with matching tuple/counters and about 114 ms timestamp offset.
- DNS outcomes/types/RTTs vary. HTTP includes auth/access/gateway failures. TLS has established sessions and a failure.
- Core spans DNS, Kerberos, proxy, LDAP, SMB, SMTP, DHCP, SSH and RDP; DMZ and DB have distinct mixes.

## Detailed Analysis

The capture spans roughly 13:00–19:00 UTC. Core has 12,891 rows, DMZ 10,334, and DB 478. DMZ inbound probes to one target are mostly `S0` with no response, compatible with blocked or unanswered probes. Database traffic concentrates on a single source/destination MySQL pair but includes varied states. The core/DMZ proxy visibility split and TLS observations are plausible. Repeated DC DNS queries and suffix-search NXDOMAINs are not impossible. No clear hard contradiction or Zeek schema defect was identified.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None identified |
| contract_gap | None identified |
| distribution_texture | Concentrated DB pair and sustained single-host DMZ probes |
| schema_or_format | None identified |
| environment_or_collection_plausibility | Focused scans are plausible but unusually concentrated |
| weak_signal | Repeated DC lookups |

## Realism Score by Category

- **Field format accuracy: 9/10** — Zeek names, states, and counters are coherent.
- **Temporal patterns: 7/10** — Timestamps and cross-sensor offsets are plausible; scan activity is concentrated.
- **Cross-source correlation: 9/10** — Shared proxy flow agrees across sensors.
- **Behavioral realism: 6/10** — Background mix is varied, while DB flows and scans are concentrated.
- **Environmental consistency: 7/10** — Internal paths fit roles; external probing focuses on one DMZ host.

## Recommendations

- Check whether the DB source-pair concentration reflects the expected application workload.
- Compare DMZ scans against perimeter exposure and scanner/collection context.
- Retain the plausible cross-tap timing/counter alignment.
