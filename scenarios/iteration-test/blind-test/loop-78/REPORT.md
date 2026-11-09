# Loop 78 — DNS/IDS background families

No generator changes. The canonical seed42 dataset was copied from loop77 after confirming the
113 source files were byte-identical; the same authoritative evaluation therefore applies:
**96.3400 PASS**, 135,966 records (parseability 100.00, plausibility 96.82, causality 95.90,
timing 90.79). Scenario validation passed with the established 28 warning/information notices.

## Family probe

The two Snort sensors report 157 alerts total. The most common messages are DNS `.top` (34), `.bit`
(17), `.cloud` (15), rapid HTTP/HTTPS scans (14), `.tk` (12), STUN (11), and `.to` (10), followed
by several ICMP and policy signatures. The network reviewer independently tied the main scan spike
to endpoint-observed Nmap commands and found Snort/Zeek DNS tuple agreement, proxy byte accounting,
and ASA/Zeek NAT/RDP-attempt agreement. This supports the alerts as observations of visible
activity; the bounded signature palette remains a weak distribution signal, not a contract defect.

## Independent reviews

- **Threat Hunter — Inconclusive, confidence 62, synthetic-confidence 46.** Found a coherent APP-INT
  root SSH → DB export/compress/SCP → SMB share movement chain. Two-second failed-login bursts and
  normalized coverage are weak texture signals; no decisive contradiction.
- **Detection Engineer — Inconclusive, confidence 76, synthetic-confidence 31.** Found no hard
  contradiction in sampled fields, IDs, timestamps, joins, or process order; strong correlations
  could reflect either real collection or deterministic generation.
- **Network Forensics — Inconclusive, confidence 78, synthetic-confidence 22.** Found strong
  tuple, timing and byte-accounting joins; scan volume matched visible Nmap invocations. No
  unexplained network anomaly.
- **Host/EDR Forensics — Inconclusive, confidence 66, synthetic-confidence 18.** Found coherent
  Windows, Linux and macOS endpoint lifecycles; repetitive shell enumeration was weak and not
  diagnostic.

Standalone synthetic-confidence mean is **29.25** (mostly realistic), with all four reviewers
choosing Inconclusive. No deliberation was triggered. The four reviews identify no hard
contradiction or definite contract gap.

## Prioritized findings

| Priority | Finding | Category | Original reviewer rating | Leverage | Disposition |
|---|---|---|---|---|---|
| P3 | Recurring compact DNS/IDS signature and TLD palette | `distribution_texture` | not labeled | Low–medium; cross-sensor but tuple-supported | No change. Track as weak signal; the alerts map to visible DNS/network activity. |
| P4 | Two-second failed-login retry bursts | `distribution_texture` | not labeled | Low; no reviewer established impossible authentication state | Defer absent a repeated behavioral contract violation. |
| P4 | Sparse macOS Unified Log and normalized coverage | `environment_or_collection_plausibility` | not labeled | Low without collection policy | Treat as collection-scope uncertainty, not a data defect. |

Next candidate: loop79 compares the half-hour `debian-sa1` pattern found in loop77 to the package's
cron/timer schedule and the shared baseline scheduler. Artifacts: `ids-dns-family-probe.json`,
`family-contract.md`, four reports, and `scores.json`.
