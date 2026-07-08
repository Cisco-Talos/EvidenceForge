# Loop 61 Combined Fix-Forward Blind Assessment

## Purpose

Loop 61 re-applies the previously reverted loop 60-a, 60-b, and 60-c fixes
together on top of accepted loop 60, then runs a fresh standalone blind panel on
`iteration-test-expanded`.

No deliberation was run. This artifact uses the arithmetic average of the four
standalone blind reviewer synthetic-confidence scores.

## Fixes Under Test

| Prior attempt | Commit | Target |
|---|---|---|
| 60-a | `00d8dd8a fix: add ASA hidden connection-id volume` | Add hidden-volume texture to ASA connection IDs. |
| 60-b | `564c4848 fix: align proxy origin with scenario DNS identity` | Keep `mail-fin.meridianhcs.com` proxy-origin traffic aligned to the scenario-owned internal IP. |
| 60-c | `c883a30d fix: vary Postfix mail syslog lifecycles` | Fix Postfix lifecycle ordering, invalid reject text, and formulaic `delays=` tuples. |

Accepted loop 60's collection-profile fix (`8ccc066b`) remains in place.

## Score Summary

| Reviewer | Assessment | Verdict Confidence | Synthetic-Confidence Score |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 68 | 36 |
| Detection Engineer | Inconclusive | 68 | 32 |
| Network Forensics | Synthetic | 66 | 64 |
| Host/EDR | Inconclusive | 66 | 36 |
| Average | - | - | 42.0 |

Accepted loop 60 averaged 37.25. Under the monotonic experiment rule, this
combined re-apply run would not be accepted because `42.0` is not lower than
`37.25`.

Automated eval passed at 95.90804086572041 over 96,398 records. Automated eval
remains a guardrail only and was not used as the blind-review score.

## Hard Probe Summary

`hard_probe_combined_60abc60d.json` confirms the re-applied fixes are present in
the generated output:

- ASA Built IDs: 194 distinct adjacent gap sizes, 0 nonpositive gaps, max gap
  231.
- `mail-fin.meridianhcs.com`: 25/25 Zeek SSL destinations on `10.10.2.27`, 0
  public SSL mismatches, ASA matches on `10.10.2.27`.
- Postfix syslog: 32 complete ordered lifecycles, 0 ordering violations, 45
  distinct delay-ratio shapes.
- Review-tree collection profile: 0 `mail_artifacts`, 0 `email_artifacts`, 0
  `eml` formats, and no `.eml` files inside the reviewer-visible tree.

## Individual Expert Summaries

Threat Hunter assessed the dataset as Inconclusive with synthetic-confidence 36.
They found a mostly coherent enterprise slice, with concrete concerns around one
APP-INT publickey SSH line omitting key type/fingerprint, one DB-PROD root SSH
session lacking visible close/logout companions, and repeated DB healthcheck-like
`wget` texture.

Detection Engineer assessed the dataset as Inconclusive with synthetic-confidence
32. They found strong source-native Windows, Zeek, Linux, proxy, ASA, and eCAR
coherence, and scored only weak collection/export cleanliness and sparse NTP
texture.

Network Forensics assessed the dataset as Synthetic with synthetic-confidence
64. Their primary finding was a repeated Zeek TLS contract issue: TLSv1.2 rows
marked `resumed:true` with full-handshake-style `ssl_history` and no
certificate/file/x509 artifacts.

Host/EDR assessed the dataset as Inconclusive with synthetic-confidence 36. They
found RDP, SSH/SCP, DC log clearing, Windows lifecycle, and eCAR evidence mostly
production-like, with weak concerns around endpoint collection tidiness, repeated
Linux admin command texture, endpoint-family tail asymmetry, and placeholder
metadata for internal tools.

## Reported Issues

| Priority | Issue | Category | Reviewer | Score Impact |
|---|---|---|---|---|
| P0 | Zeek TLSv1.2 resumed/full-handshake contract | `schema_or_format` | Network Forensics | High |
| P1 | DB-PROD root SSH session lacks visible endpoint close/logout companions | `contract_gap` | Threat Hunter | Medium |
| P1 | APP-INT root scp `Accepted publickey` line omits key type/fingerprint while same-host peers include them | `schema_or_format` | Threat Hunter | Medium |
| P2 | Repeated Linux admin/healthcheck command texture | `distribution_texture` | Threat Hunter, Host/EDR | Low-medium |
| P2 | Same-UID HTTP keep-alive transactions can advance roughly 1 ms after large responses | `distribution_texture` | Network Forensics | Low-medium |
| P3 | Sparse NTP / low-level infrastructure texture | `distribution_texture` | Detection Engineer | Low |
| P3 | Endpoint/eCAR collection tidiness and tail asymmetry | `weak_signal` / `environment_or_collection_plausibility` | Host/EDR | Low |

## Interpretation

This run supports the post-experiment concern that the monotonic average can
reject real local improvements. The three re-applied fixes appear to hold
together technically and did not reappear as dominant blind-review defects, but
the fresh panel surfaced different issues and the average worsened versus loop
60 because Network Forensics found a high-impact TLS contract problem.

If continuing from this branch, the next highest-leverage target is the Zeek TLS
resumption/certificate contract, followed by SSH lifecycle/format consistency.
