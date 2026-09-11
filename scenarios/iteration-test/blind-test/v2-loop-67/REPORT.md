# Iteration Test Blind Assessment — Loop 67

## Outcome

Loop 67 bound Windows inbox executable identities and VERSIONINFO to each host's exact build.
The automated evaluation scored 96.2339 PASS across 125,914 records. The blind panel produced
synthetic-confidence scores of 72, 76, 65, and 90 (mean 75.75), unanimously Synthetic. No
deliberation was required: average verdict confidence was 82.75 and the score spread was 25.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 78 verdict confidence, 72 synthetic-confidence. Endpoint lifecycle
and cross-source correlation were strong. Stable scanner identities nevertheless drew TCP windows
near-uniformly from three values, fixed public routes had broad all-unique response sizes, and all
83 ECDSA certificates omitted curve metadata while carrying an empty RSA exponent.

**Detection Engineer:** Synthetic, 86 verdict confidence, 76 synthetic-confidence. Schema,
identifier, process, file, TLS, and network linkage were convincing. The decisive defect was a
systemic KDC/WFP inversion: matching Event 5156 permits followed Kerberos processing for
1,173/1,192 DC-01 and 1,154/1,161 DC-02 transactions. Implausible CreateRemoteThread and LSASS
module pairings reinforced the verdict.

**Network Forensics:** Synthetic, 74 verdict confidence, 65 synthetic-confidence. Firewall/NAT,
proxy accounting, TLS, DNS cache behavior, and multi-sensor lifecycles were unusually strong. DNS
retries added packet/history markers without payload bytes, both Snort sources used nearly
identical bounded alert-delay envelopes, and the certificate population was over-specialized.

**Host/EDR Forensics:** Synthetic, 93 verdict confidence, 90 synthetic-confidence. Process trees,
sessions, audit clearing, and eCAR/Sysmon/Security joins were strong. All eight invalid-user SSH
sequences retained one microsecond suffix across multi-message spans, while heterogeneous Linux
hosts cloned the same ten-entry IRQ/device catalog. A few Windows 11 hosts still selected older
gpupdate/gpresult metadata.

## Fix Verification

- Complete five-field PE metadata gaps in Sysmon Event 1 fell from 691/938 rows across 51 images
  in loop 66 to 104/938 rows across 29 mostly third-party/versioned images in loop 67.
- Explorer now resolves four host-build versions: 10.0.17763.1, 10.0.19041.1, 10.0.20348.1,
  and 10.0.22621.1. Each version has exactly one stable SHA-256 identity and no digest overlaps
  another build.
- High-volume native descriptors now carry data-driven VERSIONINFO into deployment compilation,
  including capability-owned service/task paths and materialized WinSxS paths.
- Behavior revision 31 records the family change with surface digest
  `7be368c84bf4e383e2cb7d1e6b27bfb027b8fbcfcff9433428097ba185c5df44`.
- The routine gate passed with 8,398 tests and 5 skips; repository-wide Ruff check and format check
  passed across 769 files.
- The repaired fixed Explorer 19041 identity did not recur as a prioritized blind finding. The
  host reviewer found narrower incomplete catalog coverage for gpupdate/gpresult.

## Prioritized Improvements

### P0 — Publish packet admission before Kerberos processing

Tie each KDC request to its canonical network/WFP occurrence and make Event 5156 observation the
lower bound for Event 4768, 4769, or 4771 processing on that DC. Preserve this causal order through
source timing and collection-delay projection rather than rewriting Security rows afterward.

### P1 — Give Linux hosts distinct hardware identities

Own IRQ/device inventory per host or justified hardware template. Do not mix SATA, NVMe, VirtIO,
Mellanox, and two NIC catalogs into one fleet-wide pool or reuse exact IRQ numbers across unrelated
machines.

### P2 — Remove event-family timestamp fingerprints

Timestamp each failed/invalid SSH phase independently at native precision, and model IDS sensor
clock offset as stable, autocorrelated drift from the triggering packet rather than an independent
bounded delay per alert.

### P3 — Repair source-native packet and certificate contracts

Account for retransmitted UDP DNS payload bytes whenever history and packet counts record a retry.
Emit key-algorithm-specific X.509 parameters and broaden certificate reuse, wildcard, SAN, and
issuer-policy ecology.

### P4 — Stabilize modeled content and TCP-stack identity

Bind TCP window/options/TTL to a modeled origin and make fixed web-route response sizes
content-backed with explainable variants. Complete remaining Windows native binary catalog
coverage and constrain Sysmon Event 8/Event 7 process-module combinations by real semantics.

## Priority Rationale

The KDC/WFP ordering is first because it is a near-universal hard causal inversion on both domain
controllers and is independently measurable by exact tuples. The cloned Linux hardware catalog
and timestamp fingerprints are broad generator signatures. Packet/certificate contracts and
content/TCP distributions are material but do not invert causality. Nmap command semantics remains
an important queued family even though this panel credited the scan mechanics overall.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.2339: 99.9992 parseability, 96.8682 plausibility, 94.2708
causality, and 92.2471 timing. It confirmed broad schema conformance and cross-source consistency,
but did not detect the KDC/WFP ordering, cloned IRQ identities, suffix-locked SSH timestamps,
bounded IDS delay families, DNS retry payload accounting, certificate ecology, TCP-stack mixing,
or route-conditioned web-size distributions. Its one strict schema failure remains eCAR
`FILE/RENAME`.
