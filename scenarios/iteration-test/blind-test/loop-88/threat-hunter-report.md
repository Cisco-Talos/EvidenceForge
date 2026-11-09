# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 69

## Executive Summary

The six-hour slice has coherent host and network roles, but the reviewer judged the fleet-wide aligned window and concentrated security sequences as likely exercise data. No hard contradiction was identified, and the report cautions that bounded collection, complete pivots, and nearby SYSTEM activity do not identify an operator.

## Evidence For Synthetic

- **[distribution_texture]** Many source files cover approximately 13:00–19:00 UTC on Nov 2. `zeek-core/conn.json` spans 13:00:01–18:59:31, and Windows/eCAR files have similar bounds. A common export window is a plausible alternative.
- **[environment_or_collection_plausibility]** DC-01 records PSEXESVC service installation around 16:59:41, `svc_dirsync` creation at 17:14:34, Domain Admins addition at 17:14:43 and deletion at 18:50:01; DC-02 has a DirectoryCacheSvc install around 17:25:34. These are high-impact but technically plausible events.
- **[weak_signal]** WS-AJOHNSON-01 has network logon failures from LT-MRIVERA-02 around 15:59 UTC. One timestamp was described as a later 15:06 event, but XML shows 15:06 is earlier.
- **[environment_or_collection_plausibility]** Mac Unified Log coverage is three and two rows, respectively, compared with 132 and 183 Endpoint Security events; scope is unknown.

## Evidence For Real

- Proxy and Zeek HTTP logs agree on client, proxy, host, method and timestamp for sampled CONNECT requests.
- Network roles are coherent: clients use DCs for DNS/Kerberos and the proxy for web; the DB sensor sees MySQL to `10.10.4.10:3306`.
- Connection outcomes include completed flows, scans, resets, and rejects.
- The database dump and SSH path provide useful pivots, though flow records alone do not establish file contents or authorization.

## Detailed Analysis

The six-hour slice includes mixed Windows, Linux, macOS, proxy, Zeek, ASA and IDS sources. The reviewer highlights concentrated DC-01/DC-02 security sequences and the workstation login-failure cluster as suspicious leads. However, the report explicitly does not attribute SYSTEM account changes to Aisha or another nearby actor. DB-PROD-01 history and Zeek show SSH around 18:15–18:16 toward APP-INT-01, but network flow does not disclose authenticated user or content. Collection bounds and sparse Mac Unified Log do not establish a contradiction.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None identified |
| contract_gap | SYSTEM account changes lack a visible human initiator; attribution gap only |
| distribution_texture | Aligned six-hour source bounds |
| schema_or_format | None identified |
| environment_or_collection_plausibility | Sparse Mac Unified Log; scope unknown |
| weak_signal | Concentrated security sequences and login failures |

## Realism Score by Category

- **Field format accuracy: 8/10** — Formats are recognizable and detailed.
- **Temporal patterns: 6/10** — Within-source sequences are coherent; common time bounds were judged unusually tidy.
- **Cross-source correlation: 8/10** — Proxy/Zeek and DB/SSH pivots align.
- **Behavioral realism: 6/10** — High-impact account/service activity is concentrated, though plausible.
- **Environmental consistency: 7/10** — Host and sensor roles align; Mac coverage is uncertain.

## Recommendations

- Triage DC-01 service/account actions and the WS-AJOHNSON-01 failures without inferring operator identity from proximity.
- Validate the database dump against authorization and share ownership.
- Check whether the common six-hour boundary and Mac collection density reflect configured export scope.
