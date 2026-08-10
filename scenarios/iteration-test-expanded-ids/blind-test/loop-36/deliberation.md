# Deliberation Summary

## Evidence Boundary

This deliberation uses only the four loop-36 blind reports: Threat Hunter, Detection
Engineer, Network Forensics, and Host/EDR Forensics. It does not add findings from the
generated data, scenario, ground truth, evaluation, source code, git history, or prior loops.
The facilitator is reconciling the reviewers' cited evidence, not acting as a fifth reviewer.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---:|---:|---:|---:|---:|---:|
| Threat Hunter | Real | 67 | 32 | Inconclusive | 76 | 55 |
| Detection Engineer | Inconclusive | 84 | 49 | Synthetic | 87 | 63 |
| Network Forensics | Synthetic | 78 | 67 | Synthetic | 85 | 72 |
| Host/EDR Forensics | Synthetic | 91 | 78 | Synthetic | 90 | 77 |

Initial panel-average synthetic-confidence was **56.5**. Revised panel-average
synthetic-confidence is **66.8**, corresponding to **likely synthetic**. The final panel
verdict is **Synthetic by a 3-1 majority**, with the remaining reviewer Inconclusive; this is
not unanimous.

## Round 1 — Initial Positions

### Threat Hunter

The Threat Hunter initially assessed the collection as **Real** (67 verdict confidence,
32 synthetic-confidence). The strongest production-like evidence was the coherent archive,
SMB transfer, browser read, proxy upload, database staging, SCP transfer, and cleanup chain;
the reviewer also cited substantial background volume and role-specific behavior. The main
synthetic concern was the FILE-SRV-01 WMI-like execution: a type-3 logon and target-side
`WmiPrvSE.exe` child activity were visible, but the only cited contemporaneous flow from
`10.10.1.35` to `10.10.2.20` was TCP/445, with no TCP/135 or dynamic RPC/DCOM transport.

### Detection Engineer

The Detection Engineer initially assessed the collection as **Inconclusive** (84 verdict
confidence, 49 synthetic-confidence). Strong source-native formatting, 921 of 923 Security
4688 events matching Sysmon Event 1, coherent eCAR actor relationships, and resolvable Zeek
UID/tuple relationships weighed toward real. The main contrary evidence was a selective
post-18:00 lifecycle tail across eCAR PROCESS/TERMINATE, Security 4689, and Sysmon Event 5,
plus incorrect-looking LogonType 7 Subject ownership, nonzero tunnel accounting on 32 of 37
denied proxy transactions, and dataset-wide zero LogonGuid values on 1,119 Security 4769
events.

### Network Forensics

The Network Forensics analyst initially assessed the collection as **Synthetic** (78 verdict
confidence, 67 synthetic-confidence). The decisive evidence was the public-client population:
180 EHR TLS client IPs occupied 180 distinct /16s and /24s across 123 /8s; completed,
bidirectional TLS sessions originated from numerous cited U.S. DoD-owned /8 ranges; and 67
cleartext HTTP client IPs collapsed to eight exact User-Agent strings. Zero port-123 records
across 11,776 Zeek connections and categorical DHCP lease behavior added environmental and
distribution pressure. In the other direction, Zeek states and histories, TLS/certificate
semantics, DNS, proxy fan-out, ASA byte accounting, and UID/tuple correlations were judged
highly credible.

### Host/EDR Forensics

The Host/EDR analyst initially assessed the collection as **Synthetic** (91 verdict
confidence, 78 synthetic-confidence). The decisive evidence was the same termination-only
tail identified by Detection, with exact Security, Sysmon, and eCAR companions extending as
late as 18:49:43 and similar spillover on multiple hosts. The other major indicator was cloned
Linux background texture: identical IRQ/device/CPU combinations and a broad hybrid hardware
inventory recurred across unrelated workstations and servers, accompanied by repeated
administrative-account and command pools. Windows process correlation, log clearing,
intrusion audit companions, SSH ordering, logon variety, and host-role differentiation were
otherwise considered strong.

## Round 2 — Cross-Examination

### Agreements

- All four reports describe source-native structure and cross-source correlation as strong.
  Security/Sysmon/eCAR process identity, Zeek UID/tuple fan-out, TLS/certificate references,
  and the suspicious transfer chain are repeatedly cited as coherent.
- No reviewer reports a visible create/terminate, logon/logoff, or transport/protocol ordering
  inversion inside the ordinary six-hour activity interval. The disputed boundary issue is a
  collection-scope contract problem, not a process termination-before-creation problem.
- The environment contains credible role differentiation and substantial background volume.
  The disagreement is whether dataset-wide population and observation textures outweigh that
  realism.
- The strongest synthetic indicators are not narrative-design impressions. They are concrete
  timestamp-boundary behavior, address/User-Agent distributions, source-native field or
  terminal-action semantics, missing transport, and repeated host-profile values.

### Calibrated Disagreements

1. **Post-window termination tail.** Detection and Host independently cite the same exact
   cross-source MAIL-FIN-01 termination around 18:49:42-18:49:43, plus additional late events
   on DC-01, FILE-SRV-01, WS-MCHEN-01, WS-DRAMIREZ-01, and MAIL-FIN-01. Network reports its
   visible Zeek interval ending at 17:59:53, which is consistent with the claim that the tail
   is selective to endpoint lifecycle closure rather than ordinary continued collection.
   Threat Hunter's production-like lifecycle evidence does not refute those timestamps. The
   Host label `hard_contradiction` is slightly overstated: the cited terminations remain
   causally valid and could be explained by an explicitly documented teardown tail. Without
   such a documented exception in any report, however, the selective source-family spillover
   is strong, repeated `contract_gap` evidence and deserves high weight.

2. **Public-client provenance versus sanitized production.** Threat Hunter's initial
   alternative was sanitized production telemetry. That could explain broad address
   substitution in principle, so the IP distribution is not an impossible packet-level
   value. Network's evidence nevertheless remains stronger than a generic sanitization
   hypothesis: every one of 180 clients occupying a distinct /16 and /24, the spread over
   123 /8s, multiple completed sessions from cited DoD-owned space, and ASA bidirectional
   byte/FIN evidence collectively rule out spoofed SYN noise and look pool-generated. This
   is strong `distribution_texture` and `environment_or_collection_plausibility` evidence,
   though not a hard contradiction.

3. **Proxy realism versus denied-tunnel accounting.** Network's positive proxy examples cover
   coherent client/proxy/origin fan-out and a gateway-error transaction; they do not directly
   answer Detection's narrower result that 32 of 37 `proxy_action=deny` records carry nonzero
   tunnel counters while five do not. Both claims can be true. The general proxy model is
   strong, while denied CONNECT terminal semantics remain an internally inconsistent repeated
   contract gap.

4. **Role differentiation versus cloned Linux texture.** Threat Hunter and Host both observe
   meaningful role-specific software and user behavior. That does not refute Host's exact
   repetition of IRQ 32/`nvme0q1`, IRQ 64/`mlx5_comp0`, IRQ 122/`nvme0q2`, IRQ 137/`ens192`,
   and a hybrid VMware/Mellanox/virtio/AHCI/NVMe inventory across dissimilar hosts. Threat
   Hunter's separate observation of identical `debian-sa1 1 1` pairs near 1,800-second
   boundaries reinforces the broader conclusion: high-level roles vary, but parts of the
   Linux baseline profile are visibly shared or pooled.

5. **Broad network coherence versus missing WMI transport.** Network's general statement that
   flows and source companions correlate well does not examine the precise FILE-SRV-01 event
   cited by Threat Hunter. The specific absence of TCP/135 and dynamic RPC/DCOM alongside a
   target-side `WmiPrvSE.exe` chain is therefore unrebutted. Sensor or collection omission is
   an alternative explanation, so this remains a localized contract gap rather than an
   impossible event.

6. **Convincing lock/unlock lifecycle versus LogonType 7 field ownership.** Host finds the
   4800/4801 and LogonType 7 lifecycle plausible. Detection's field-level check is more
   specific: all six LogonType 7 events reportedly use the unlocked user and identical logon
   IDs as both Subject and Target. The lifecycle can be correct while Subject ownership is
   source-natively wrong. The panel therefore retains this as a medium, scoped schema issue.

7. **Absent NTP and zero TGS LogonGuid.** Network's zero-port-123 count is meaningful given the
   otherwise broad infrastructure capture, but a collection policy can omit NTP, so it is an
   environmental plausibility gap rather than proof by itself. Detection similarly treats all
   1,119 zero 4769 LogonGuid values as a weak fidelity signal, not a decisive contradiction.

## Round 3 — Revised Positions

### Threat Hunter — revised to Inconclusive, 76 confidence, 55 synthetic-confidence

The strong attack-lifecycle and background-volume evidence still prevents a Synthetic verdict
with high confidence. The position moves materially upward because two endpoint-focused
reviews independently identify a repeated, exact termination-only boundary tail, while the
network specialist supplies quantified public-IP and User-Agent population evidence that the
Threat Hunter did not address. The WMI transport gap and Linux schedule texture remain
supporting rather than decisive evidence.

### Detection Engineer — revised to Synthetic, 87 confidence, 63 synthetic-confidence

The Detection Engineer's own boundary and proxy-contract findings are reinforced by Host's
independent timestamp/identity examples. Network's quantified public-client distributions add
a separate dataset-wide family of evidence, reducing the chance that the endpoint tail is an
isolated export peculiarity. The excellent schema parsing and event correlation continue to
cap the score well below confidently synthetic.

### Network Forensics — remains Synthetic, 85 confidence, 72 synthetic-confidence

The public-IP and User-Agent findings remain the strongest network-specific basis for the
verdict. Detection and Host add an independent endpoint observation-boundary defect, and the
Threat Hunter adds an unrebutted WMI transport gap. Confidence rises, but the score remains
tempered because the reports consistently describe excellent protocol mechanics and because
sanitization or collection-policy alternatives could explain part of the address and NTP
evidence.

### Host/EDR Forensics — remains Synthetic, 90 confidence, 77 synthetic-confidence

The termination-only tail and cloned Linux host profiles remain decisive. The finding is
recalibrated from a hard causality contradiction to a strong collection-contract gap because
the terminations correctly follow their creates and an explicitly documented teardown tail
could make them legitimate. Network's independent public-client evidence offsets that
calibration, leaving the verdict and score nearly unchanged while slightly reducing verdict
confidence.

## Round 4 — Consensus Summary

### Key Agreements

- The collection is technically sophisticated and often source-native at the individual-record
  level.
- Cross-source identity, tuple, byte, certificate, process, session, and file-transfer
  relationships are among its strongest realism features and should be preserved.
- The principal synthetic pressure comes from dataset-wide boundaries and population/profile
  distributions, not from the core suspicious storyline being too orderly or too complete.
- The selective endpoint teardown tail is the best corroborated improvement target because it
  was independently documented by two specialists across three source families and multiple
  hosts.

### Key Disagreements

- The Threat Hunter still considers the production/sanitization explanation plausible enough
  for an Inconclusive verdict, while the other three reviewers judge the combination of
  boundary leakage and generated-looking populations sufficient for Synthetic.
- The panel does not agree that any single cited issue is an impossible security event. Host's
  initial `hard_contradiction` label is moderated to a contract gap; Network's public-address
  evidence is strong distributional evidence but can be challenged by sanitization; missing
  NTP can be challenged by collection policy.
- The panel agrees that proxy behavior is generally strong but distinguishes that broad
  success from the narrower denied-CONNECT counter inconsistency.

### Most Convincing Evidence

1. **Termination-only boundary spillover (synthetic):** exact correlated Security 4689,
   Sysmon Event 5, and eCAR PROCESS/TERMINATE records extend up to roughly 49 minutes after
   ordinary activity and network collection end, across multiple hosts.
2. **Public-client address population (synthetic):** 180 clients in 180 distinct /16s and
   /24s across 123 /8s, including multiple completed bidirectional TLS sessions from cited
   DoD-owned ranges.
3. **Cross-source protocol and process fidelity (real):** matching process identities,
   coherent Zeek UID/tuple and certificate fan-out, ASA/Zeek byte agreement, and credible
   SMB/proxy/SCP transfer pivots strongly resemble production-quality telemetry.
4. **External User-Agent compression (synthetic):** 67 public HTTP client IPs reduce to eight
   exact User-Agent strings, with six Windows browser strings accounting for 66 of 73 requests.
5. **Cloned Linux host texture (synthetic):** identical device/IRQ/CPU combinations and broad
   hybrid device inventories recur across unrelated roles, reinforced by repeated sysstat and
   administrative pools.

### Most Debated Points

- Whether the public-address spread represents generated traffic or sanitized real traffic.
- Whether post-18:00 closures are an undocumented permissible teardown tail or an observation
  boundary leak. The selective source-family shape favors the latter, but causality itself is
  intact.
- Whether absent NTP reflects unrealistic environment modeling or a defensible sensor/filtering
  gap.
- Whether excellent cross-source completeness should lower synthetic confidence. The panel
  treats it as positive realism evidence, not as a synthetic tell by itself.

## Improvement Recommendations (Consensus Ranking)

| Rank | Improvement target | Cited scope | Expected score leverage | Panel rationale |
|---:|---|---|---|---|
| 1 | Enforce the declared collection cutoff coherently for process lifecycle observations across Security 4689, Sysmon Event 5, and eCAR PROCESS/TERMINATE; processes alive at cutoff should remain open unless a teardown tail is explicitly documented. | Detection + Host; repeated across multiple Windows hosts and three endpoint sources | High | It is the only major issue independently reproduced by two reviewers with exact cross-source timestamps, and it drove Host's verdict plus Detection's highest-impact finding. |
| 2 | Replace broad random public-IP selection with weighted ASN/provider/prefix populations, realistic prefix reuse and clustering, institutionally plausible address weighting, and client personas coupled to a much larger coherent User-Agent population. | Network; dataset-wide public TLS/HTTP population | High | It is Network's decisive evidence and combines two mutually reinforcing, quantified distribution fingerprints. |
| 3 | Generate Linux hardware/IRQ and scheduled/admin background profiles per host or infrastructure cohort, preserving role-specific inventory, phase, account, and command variation. | Host + Threat Hunter; broad Linux fleet | High | Two reviewers independently identify shared Linux baseline texture; the exact hardware repetition is stronger than schedule regularity alone. |
| 4 | Add RPC endpoint-mapper and negotiated dynamic DCOM transport when remote WMI execution produces target-side `WmiPrvSE.exe` children, tied to the same source, target, session, and execution window. | Threat Hunter; one high-value FILE-SRV-01 chain | Medium-high | The evidence is specific and unrebutted, but currently localized to one cited execution chain. |
| 5 | Define one terminal contract for denied CONNECT transactions and suppress established-tunnel counters for denied requests. | Detection; 32 of 37 denied proxy records | Medium-high | The problem repeats and is internally inconsistent, though the broader proxy model is otherwise convincing. |
| 6 | Add role-appropriate NTP observations or make the collection profile's NTP omission explicit and coherent. | Network; zero port-123 records across 11,776 Zeek connections | Medium | The absence is conspicuous in a broad collection, but filtering remains a plausible alternative explanation. |
| 7 | Model Security 4624 LogonType 7 Subject fields from trusted logon/system context while retaining the unlocked user and session in Target fields. | Detection; all six LogonType 7 events | Medium | This is a concrete source-native schema issue, but its record count and score reach are limited. |
| 8 | Derive DHCP lease behavior from shared scopes, reservations, or client classes and add occasional acquisition/rebind texture where appropriate. | Network; 69 transactions across eight clients | Medium-low | The pattern looks categorical but remains operationally possible and was reported by one specialist. |
| 9 | Populate Security 4769 LogonGuid where correlated Kerberos/logon activity has a usable native GUID. | Detection; all 1,119 TGS events | Low | The scope is broad, but the reporting specialist explicitly classifies it as a weak signal rather than decisive authenticity evidence. |
| 10 | Diversify lower-confidence pool textures, including endpoint module-observation policy by host and public HTTP response-state pools by URI. | Threat Hunter + Network; multiple endpoint/web records | Low | Both reviewers identify these as weak signals with plausible deployment, authentication, or routing explanations. |

## Selected Single Best Next Target

**Enforce the collection cutoff coherently across endpoint process lifecycle sources.** The
next iteration should ensure that Security 4689, Sysmon Event 5, and eCAR PROCESS/TERMINATE
share one observation-window decision, leaving still-running processes open at 18:00 unless
the collection explicitly declares and applies a consistent teardown-tail policy. This target
has the best expected score leverage because it is repeated, cross-source, multi-host,
independently corroborated by Detection and Host, and was the decisive evidence for the
highest synthetic-confidence reviewer.
