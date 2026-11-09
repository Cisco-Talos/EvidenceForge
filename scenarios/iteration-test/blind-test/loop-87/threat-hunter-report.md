# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 78  
**Synthetic-Confidence Score:** 34

## Executive Summary

The six-hour slice contains coherent cross-source evidence for an external support archive upload and a database export relayed to a file share. Linux sysstat cadence is a weak texture signal, but no decisive synthetic artifact was identified.

## Evidence For Synthetic

- **[distribution_texture]** APP-INT-01 eCAR records sysstat starts at 13:05:01, 13:15:01 and 13:25:01 UTC, consistent with scheduled collection; regularity alone is weak.
- The two transfer chains are easy to pivot across sources, but cross-source consistency alone is not a synthetic indicator.

## Evidence For Real

- Lina Nguyen's history, eCAR, DNS, HTTP, proxy and Zeek records align on an archive upload and HTTP 200 response.
- DB-PROD-01 history/eCAR and SSH network records align on a database dump, compression and transfer to APP-INT-01. Subsequent SMB and FILE-LNX-01 records align on a write to the ClinicalResearch share.
- Host and sensor volumes differ by role across Windows, Linux, macOS, Zeek, Snort, proxy and ASA sources.

## Detailed Analysis

The visible window is approximately 13:00–19:00 UTC. The support archive contains two EHR connector logs and is posted to an external support domain; the proxy and Zeek records show a successful response, but do not establish authorization. A root session on DB-PROD-01 exports EHR tables, compresses and copies the data over SSH to APP-INT-01, then the same named archive appears in SMB/file-share evidence. This is sensitive activity, but approval/business purpose is outside the available records. Routine monitoring and network alerts provide background; alerts do not prove compromise.

## Synthetic Indicator Summary

| Category | Finding |
|---|---|
| hard_contradiction | None found |
| contract_gap | None decisive |
| distribution_texture | Weak regular sysstat schedule, compatible with cron |
| schema_or_format | No concrete issue identified |
| environment_or_collection_plausibility | Rich source pivots do not alone establish synthetic origin |
| weak_signal | Two sensitive but coherent transfer chains |

## Realism Score by Category

- **Field format accuracy: 8/10** — Reviewed Zeek, proxy, eCAR, history and syslog fields are usable and source-appropriate.
- **Temporal patterns: 8/10** — Process, file, DNS, HTTP, SSH and SMB sequences align plausibly.
- **Cross-source correlation: 9/10** — Transfer chains retain matching filenames, hosts, identities and network paths.
- **Behavioral realism: 7/10** — Actions are plausible, but authorization and business purpose are unknown.
- **Environmental consistency: 8/10** — Host roles, source volumes and pivotable identities are coherent.

## Recommendations

- Validate ticket MHS-48217 and the external support destination.
- Confirm the database export's business owner and approved path to the ClinicalResearch share.
