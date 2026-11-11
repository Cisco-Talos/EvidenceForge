# Deliberation Summary

## Facilitation scope and measurement integrity

This is a bounded synthesis of four completed independent reports, not a fifth authenticity review or a live panel discussion. No reviewer supplied a revised verdict or score. The original measurements below remain unchanged; the synthesis and prioritized targets are facilitator conclusions from their cited evidence, not an invented consensus or re-vote. Only the four reports and the exact cited reverse-shell records in the sibling data directory were inspected.

## Panel composition and original positions

| Expert | Initial verdict | Initial verdict confidence | Initial synthetic-confidence | Final recorded verdict | Final recorded verdict confidence | Final recorded synthetic-confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Synthetic | 91 | 76 | Synthetic — unchanged | 91 | 76 |
| Detection Engineer | Synthetic | 78 | 57 | Synthetic — unchanged | 78 | 57 |
| Network Forensics | Real | 68 | 24 | Real — unchanged | 68 | 24 |
| Host/EDR Forensics | Inconclusive | 82 | 34 | Inconclusive — unchanged | 82 | 34 |

“Final recorded” preserves the independent submission; it does not imply the reviewer participated in this synthesis.

The Threat Hunter's principal evidence is one raw Bash reverse-shell connection carrying successful TLS/certificate observations. Credible SSH/SCP and archive-upload chains limit the demonstrated defect's scope. The Detection Engineer emphasizes a shared Linux PID increment signature across ten hosts, while reporting strong native schemas and exact identity joins. The Network analyst emphasizes protocol joins, proxy byte accounting and compatible TLS certificate fields, with a weak reservation about universal single-SYN S0 shapes. The Host analyst finds coherent Windows identities and Linux/macOS session lifecycles, with mild concerns about binary-document `cat` access and repetitive diagnostic commands.

## Agreements supported by the reports

- The inspected Windows identities and process lifecycles are coherent. The Host analyst's 912 matched Sysmon/Security creation pairs agree on parent PID and command; the Detection Engineer's broader GUID-reference checks found no demonstrated lifecycle or PID contradiction.
- The Detection Engineer and Network analyst independently report 14,171 protocol companion records joining to sensor-local connection UIDs and tuples. These are overlapping checks of the same records, not independent collections to be added together.
- Examined SSH sessions preserve transport-before-authentication and source-specific timing; the reports give different exact-session examples. The Host and Detection reports also recognize native macOS fork/exec identity transitions.
- A normal cron schedule, complete joins, a readable incident progression, sparse source volumes, and collection-window lifecycle boundaries are not established defects. None warrants additional synthetic weight here.

## Cross-examination and disagreements

### Protocol joins versus protocol capability

The Network analyst's “no demonstrated impossible network relationship” and compatible TLS/certificate findings do not refute the Threat Hunter's exact process-to-protocol contradiction. Network-internal joins can be correct while the endpoint mechanism attached to that connection cannot produce the asserted protocol. The reports tested different semantic layers.

The facilitator rechecked `WEB-EXT-01.meridianhcs.local/ecar.json` records 875–880, `zeek-dmz/conn.json:1955`, `ssl.json:830` and `files.json:355`. The parent command contains the encoded Bash `/dev/tcp/45.33.32.30/8443` payload; child Bash PID 2702806 owns endpoint tuple `10.10.3.10:56738 → 45.33.32.30:8443`. The matching Zeek UID `CgR5Lvle5WdWRKjoSq` asserts established TLS 1.2, a negotiated cipher, and a certificate FUID that resolves to an SSL certificate file. This is more than an `ssl` service guess based on port 8443.

A raw Bash TCP socket does not perform that TLS handshake. An unobserved TLS transformation is an alternative hypothesis, but the inspected process chain supplies no such mechanism or distinguishable transformed leg. The strongest supported conclusion is one verified contradiction between the visible mechanism and the attached protocol observations. It does not establish that every TLS record is wrong, and it does not justify revising the Network analyst's original score without their participation.

### Cron regularity versus PID allocation texture

The Host analyst correctly treats ten-minute sysstat scheduling as ordinary. The Detection Engineer challenges a different property: 65/350 consecutive PID increments are exactly +940, 349/350 are at least +940, and +940 is the mode on every one of ten hosts. These observations are compatible; normal periodicity does not explain away a shared numeric allocation signature. The latter is a quantified distribution cue, not an impossible identity relationship. Common configurations and similar workload behavior remain alternatives. It ranks below the protocol contradiction.

### One-SYN failures and macOS behavior

The Network analyst's 3,992 TCP S0 rows are sensor observations, not distinct attempts. Scanner dominance and overlapping vantage points substantially weaken their apparent sample size. Nineteen process-attributed non-nmap matches warrant a bounded check of cancellation, retry and observation behavior, not a blanket instruction to add retransmissions.

The Host analyst's seven binary-document `cat` executions and diagnostic-heavy histories are behavioral texture. A real script can read binary bytes, and the two histories share a user. These are weaker than the repeated PID distribution and far weaker than the exact protocol contradiction. No denied-execution, launchd-unload or audit-token contradiction was demonstrated by those observations.

## Ranked evidence and justified next targets

1. **Highest priority: process mechanism versus TLS capability.** Ensure a raw `/dev/tcp` connection carries plain TCP evidence, or represent a real TLS-capable process/intermediary and its correctly owned legs. Validate protocol eligibility together with process ownership, rather than merely checking UID/tuple/certificate consistency. This target follows one exact verified contradiction; preserve the demonstrated good SSH, SCP, proxy and identity relationships.
2. **Second: Linux PID consumption texture.** Investigate the ten-host +940 floor/mode with independently varying host workload and process/thread churn. Preserve legitimate cron cadence. This is the strongest reported distribution cue, with no demonstrated impossible PID ownership.
3. **Lower priority: unsuccessful non-scanner TCP behavior.** Examine the 19 attributed application failures under explicit cancellation and collection assumptions. Introduce different timeout/retransmission behavior only when those mechanisms justify it.
4. **Lower priority: macOS file-access mechanisms.** Check whether office-document reads should belong to an application or an actual automation chain; retain `cat` when that mechanism explains the read. Expand diagnostic vocabulary only when user activity supports it.

These are evidence-ranked facilitator recommendations, not recommendations approved through a new panel vote. No generic noise, missing-source additions, artificial retries, narrative disruption or out-of-window lifecycle repairs are justified.

## Original result

The original synthetic-confidence mean is **47.75/100**: `(76 + 57 + 24 + 34) / 4`. Verdicts remain two Synthetic, one Real and one Inconclusive. The mean summarizes disagreement and is not a calibrated probability or a new consensus verdict. The strongest justified next target is the exact Bash/TLS protocol mismatch, followed by the cross-host PID allocation signature; S0 and macOS texture remain secondary hypotheses.
