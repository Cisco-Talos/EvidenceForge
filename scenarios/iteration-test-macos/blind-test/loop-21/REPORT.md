# Iterative assessment loop 21

> **Loop 22 verification correction:** The purported sixth port is ICMP type 8/code 0, not TCP port 0. All 254 rows have `proto=icmp`. The scan-family diagnosis below is historical and its port-0 premise is withdrawn; see [loop 22 verification](../loop-22/root-cause-probe.md). Original reviewer scores remain preserved.

## Targeted root-cause fix

The owning layer was the eCAR causal evaluator. Its ordering check compared timestamps serialized at millisecond precision and treated an equal-time inbound FLOW and LOGIN as proof that FLOW preceded LOGIN. The generated DC-02 rows tie at `timestamp_ms=1793629313776`; the matching Windows 5156 is earlier than 4624. The evaluator now treats equal eCAR timestamps as indeterminate/acceptable and still fails a visibly later FLOW. The focused temporal suite passed 29 tests, including the equality case and the retained +25 ms inversion case. No generation behavior change was kept.

Fresh generation produced 132,196 records and passed evaluation at 96.349501. All 117 files in the blind-copy data tree are byte-identical to generated output. The former SMB causal-order failure is gone.

## Individual expert summaries

- **Threat Hunter:** Inconclusive / mixed, broadly production-like (confidence 82; synthetic-confidence 32). SSH/process lifecycles and ordinary signed application activity were coherent. A root-owned shell created and deleted a LaunchDaemon plist; activation was not established.
- **Detection Engineer:** Plausible, with no hard contradiction in the reviewed records (84; 28). Two macOS SSH sessions align across eCAR, Unified Log, and Endpoint Security; sampled formats and correlations were credible.
- **Network Forensics:** Synthetic (95; 88). One Zeek source produced 1,521 attempts to 254 addresses in about 27 seconds, with nearly the same six-port set and a port-0 cohort. Ordinary network traffic, proxy/TLS layering, and DNS/connection UID linkage were realistic.
- **Host/EDR Forensics:** Inconclusive / mostly coherent host telemetry (86; 50). It noted a few-second Endpoint Security/eCAR SSH projection difference and four local failed logins with 6/6/12-second gaps; neither was proven impossible.

Initial blind synthetic-confidence scores were 32 / 28 / 88 / 50 (mean 49.5). Verdict spread and a 60-point score range triggered deliberation. Revised scores were 46 / 48 / 88 / 55 (mean 59.25); the panel agreed the scan matrix is the strongest dataset-level concern while retaining uncertainty about its exact cause.

## Prioritized findings

1. **P1 — Scan-family volume and port selection (`distribution_texture`; Network Forensics, discussed by all after review):** The explicit scenario nmap command requests TCP 22, 80, 443, 445, and 3306 against `10.10.2.0/24`. The Zeek matrix has a sixth cohort on port 0 and nearly exhaustive, balanced host coverage in 27 seconds. The breadth may represent an authored scan, but port 0 is not in the command and the rendered matrix's source/selection owner needs tracing. This is the strongest concrete follow-up for a scanner-family root-cause investigation; do not generalize the scenario command into a generator patch without confirming the owning path.
2. **P2 — macOS SSH source projection (`contract_gap`, possible source delay; Host/EDR):** On MAC-MROSS-01, eCAR login precedes eCAR child-process rows by 1–15 ms, while Endpoint Security records the process chain earlier. The source-delay explanation remains plausible; preserve occurrence ordering or represent observation delay explicitly if the canonical contract requires it.
3. **P3 — LaunchDaemon plist lifecycle (`weak_signal`; Threat Hunter):** A root-owned process creates and later deletes the plist, but no reviewed record shows registration, activation, or execution. Treat activation as unknown; this is a hunt lead rather than a confirmed lifecycle defect.
4. **P4 — Local authentication retry texture (`distribution_texture`, weak; Host/EDR):** Four failed local attempts are spaced about 6, 6, and 12 seconds apart. This is possible behavior but looks regular; adjust only if the shared auth-attempt timing owner confirms a fixed cadence.

## Assessment and next focus

Automated evaluation passed at 96.349501 (parseability 100.0, plausibility 96.840832, causality 95.326968, timing 91.537755). The eCAR equality correction raised causality slightly without changing generated records. The panel's leading concern is the network scan matrix, especially the port-0 rows absent from the authored nmap port list. A follow-up should trace scanner action intent through canonical connection construction and Zeek rendering, then verify port selection and target sampling across sibling scanner paths. The LaunchDaemon activation and SSH timing observations remain lower-confidence findings.

Full loop artifacts are in this directory; generated data is in `data/`.
