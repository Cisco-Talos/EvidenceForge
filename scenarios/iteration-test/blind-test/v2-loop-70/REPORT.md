# Iteration Test Blind Assessment — Loop 70

## Outcome

Loop 70 moved SMB authentication and tree-connect phase gaps onto the shared packet-stage timing
runtime, eliminating the exact integer-millisecond mapping lattice. The automated evaluation scored
97.0499 PASS across 124,333 records. Initial blind synthetic-confidence scores were 66, 34, 36,
and 64 (mean 50.0). Verdict disagreement and a 32-point spread triggered deliberation; revised
scores were 68, 48, 50, and 62 (mean 57.0), yielding an Inconclusive, synthetic-leaning panel.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 78 verdict confidence, 66 synthetic-confidence. Strong lifecycle,
noise, and pivot realism were offset by one exact Zeek/proxy Referer disagreement, repeated archive
inspection before visible creation, and formulaic future-year SMB paths.

**Detection Engineer:** Real, 72 verdict confidence, 34 synthetic-confidence. Windows, Zeek, and
cross-source contracts were mostly production-like. The main reservations were a one-to-three-frame
ceiling across 713 Sysmon Event 10 call traces, 19 selectively missing process hashes, and dense
repeated Linux daemon vocabulary.

**Network Forensics:** Real, 78 verdict confidence, 36 synthetic-confidence. The repaired SMB
millisecond lattice was absent, while transport states, capture loss, DNS/TLS, clock drift, and
cutoff lifecycles looked real. Six cleartext proxy transactions mutated the client authority into
an unrelated IP-literal outbound Host value.

**Host/EDR Forensics:** Synthetic, 80 verdict confidence, 64 synthetic-confidence. Process/session
and SSH/SCP lifecycles were strong. Exact D-Bus counts, competing endpoint access agents, overlapping
UI instances, business middleware on a domain controller, and fleet-wide daemon chatter drove the
synthetic verdict.

## Deliberation Findings

Verification preserved the exact eight-record D-Bus quota but rejected an overstated resolver-count
claim. Detection and Network moved from Real to Inconclusive after considering the repeated proxy
authority mutations and isolated Referer disagreement; Threat and Host retained Synthetic. Final
scores were Threat 68, Detection 48, Network 50, and Host 62 (mean 57.0).

## Fix Verification

- All 119 rendered core Zeek SMB mappings retained parent connections and valid setup ordering.
- Zero mapping timestamps were integer-millisecond offsets from their parent connection starts;
  the corpus contained 108 distinct microsecond residues.
- Rendered tree-connect gaps ranged from 68.184 to 159.981 milliseconds.
- Behavior revision 34 records surface digest
  `9958d695d3e7470381cd44a9e91869dee545bb45b8eed53c59bcdaddd5f4ca9d`.
- The routine gate passed 8,403 tests with 5 skips and 2,009 deselections; repository-wide Ruff
  check and format check passed across 769 files.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The loop-69 SMB timestamp lattice did not recur in any initial expert report.

## Prioritized Improvements

### P0 — Preserve canonical HTTP authority and headers across proxy legs

Carry one source-of-truth authority and header set through client request, proxy log, outbound Host,
DNS, destination selection, and TLS SNI. Permit only explicit modeled transformations. Repair both
the six outbound Host mutations and the isolated Zeek/proxy Referer disagreement.

### P1 — Replace fixed host-category quotas with workload-driven activity

Let D-Bus, resolver, irqbalance, snapd, and anacron counts and timing vary by host role, installed
services, demand, and elapsed state rather than fixed per-host budgets.

### P1 — Enforce file-workflow dependencies

Order archive inspection and transfer after successful archive creation, or emit visible failure or
pre-existing-file evidence when an earlier command is intentional.

### P2 — Broaden endpoint metadata and deployment state

Condition Sysmon call-trace depth/modules and hash loss on source mechanics. Select one primary
endpoint-access stack unless a migration cohort is explicit, protect singleton UI lifecycles, and
require an exception for business middleware on domain controllers.

### P3 — Diversify stable environment naming

Tie SYSVOL/NETLOGON paths and rare-TLD prefixes to stable organizational/software entities, reducing
formulaic future-year and suffix pools.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.0499: 99.9992 parseability, 96.8587 plausibility, 97.1246
causality, and 92.7714 timing. It did not detect the proxy authority/header mismatches, fixed D-Bus
counts, shallow Sysmon call traces, backward archive dependencies, deployment oddities, or naming
texture identified by the panel.
