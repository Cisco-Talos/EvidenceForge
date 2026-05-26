# Loop 138 Blind Realism Assessment

## Individual Expert Summaries

**Threat Hunter:** Synthetic, confidence 86. The attack chain remained coherent and huntable, but the reviewer found hard Zeek TCP accounting contradictions on the large exfiltration path: multi-hundred-megabyte SMB/proxy/TLS transfers carried only 4-9 packets on the ACK side. That source-native packet physics issue became the highest-impact finding.

**Detection Engineer:** Synthetic, confidence 82. The dataset would mostly parse and correlate cleanly in a SIEM, but the reviewer found 26 Kerberos cases where a visible 4769 TGS event precedes the matching 4768 TGT event on the same principal, IP, and source port by milliseconds. They also noted one-sided WFP 5156 direction coverage and sparse PE metadata for common signed applications.

**Network Forensics Analyst:** Synthetic, confidence 74. The prior OCSP timing contradiction was not repeated, and Zeek TLS/files/x509 joins were considered strong. The main network finding shifted to DNS recursive-cache semantics: repeated TXT/DMARC answers from resolver `10.10.2.10` changed inside the earlier TTL window for names such as `github.com`, `_dmarc.meridianhcs.com`, and `atlassian.net`.

**Host/EDR Forensics Analyst:** Synthetic, confidence 70. Windows Security/Sysmon/eCAR correlation was described as unusually strong, with plausible process trees and logon lifecycles. Remaining endpoint tells were selective Sysmon Event 1 omissions for processes that had Security/eCAR create evidence plus Sysmon file/terminate evidence, and repeated Linux bash-history command-pool artifacts.

## Prioritized Improvements

**P0 — Large TCP transfer ACK-side packet counters are physically implausible**  
Reviewer rating(s): not labeled (Threat Hunter). Scope: repeated across the main large exfiltration path. Score leverage: high. Owning layer: network connection packet accounting / transfer-size modeling. Fix risk: medium. Scale ACK-side packet counts from payload volume, MSS/MTU, delayed ACK assumptions, duration, and direction so large uploads/downloads cannot retain single-digit reverse packet counts.

**P0 — Kerberos 4769 precedes matching 4768 on the same socket**  
Reviewer rating(s): not labeled (Detection Engineer). Scope: repeated, 26 reported cases. Score leverage: high. Owning layer: Windows Security auth event timing/order. Fix risk: medium. Ensure visible AS/TGT 4768 rows precede same-socket TGS 4769 rows, or omit the visible 4768 when modeling cached/pre-window TGT usage.

**P1 — DNS resolver TXT/DMARC answers change inside TTL windows**  
Reviewer rating(s): not labeled (Network Forensics). Scope: repeated for same resolver/name/type. Score leverage: high. Owning layer: DNS answer selection/cache state. Fix risk: medium. Cache positive resolver/name/qtype answers through TTL expiry unless the generator explicitly models resolver restart, split-horizon change, or cache-bypass behavior.

**P1 — Missing Sysmon Event 1 for otherwise visible process lifecycles**  
Reviewer rating(s): not labeled (Host/EDR). Scope: small number of Windows process records, but high-signal because adjacent Sysmon Event 11/5 rows exist. Score leverage: medium. Owning layer: endpoint process lifecycle visibility/routing. Fix risk: medium. If Security 4688 and eCAR PROCESS CREATE are visible and Sysmon later renders file or termination evidence for the same ProcessGuid, render a source-consistent Sysmon Event 1 unless an explicit Sysmon filtering profile explains the gap.

**P2 — WFP 5156 direction coverage is unnaturally one-sided**  
Reviewer rating(s): not labeled (Detection Engineer). Scope: dataset-wide 5156 distribution. Score leverage: medium. Owning layer: Windows Filtering Platform rendering/visibility profile. Fix risk: medium. Add inbound/listener-side 5156 examples for servers receiving SMB, Kerberos/LDAP, RDP, and HTTP where host Security logs are available.

**P2 — Linux bash-history and command-pool artifacts remain templated**  
Reviewer rating(s): not labeled (Threat Hunter, Host/EDR). Scope: repeated across Linux hosts/users. Score leverage: medium. Owning layer: persona/role activity config and shell-history timing. Fix risk: low-medium. Make command vocabularies more role/host-specific, allow rapid-fire bursts, reduce evenly distributed typo artifacts, and avoid desktop diagnostics on server-named hosts unless the host profile supports them.

## Priority Rationale

The OCSP fix removed the specific hard contradiction from Loop 137: hard probes found zero OCSP rows outside linked HTTP/file/connection lifetimes, and Network no longer flagged OCSP ordering. The next priorities are source-native contradictions with clear evidence and high score leverage. TCP packet physics and Kerberos same-socket ordering outrank broader polish because both are hard realism breaks experts can reproduce directly from rendered logs.

## Comparison With Quantitative Eval

Automated eval scored 95.3467 across 81,434 records with acceptance passing. Pillars were Parseability 100.0, Plausibility 93.9944, Causality 93.3542, and Timing 92.5478. The eval did not catch the large-transfer ACK packet contradiction, DNS cache semantics, WFP direction monotony, or selective Sysmon Event 1 omission; it did continue to surface timing/causality residuals. The blind panel remains more sensitive to source-native protocol physics and collection-profile plausibility than the current deterministic checks.

## Loop 138 Scores

| Loop | Automated Eval | Records | Threat Hunter synthetic-confidence score | Detection synthetic-confidence score | Network synthetic-confidence score | Host/EDR synthetic-confidence score | Avg Blind synthetic-confidence score |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 138 | 95.3467 | 81,434 | 86 | 82 | 74 | 70 | 78.00 |

Lower blind synthetic-confidence is better.
