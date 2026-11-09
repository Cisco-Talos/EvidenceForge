# Loop 74 — Browser User-Agent identity

## Selected family and fix

Loop73's Network reviewer noted older Windows browser User-Agent majors. The confirmed defect was
a browser identity contract gap: the generated internal workstation proxy catalog offered Chrome
119/121 and Firefox 120, while modeled workstation executables are Chrome 120, Edge 120 and Firefox
121. Scenario-authored headers are separate and retain their precedence.

The family owner is the data-driven workstation UA catalog, with generated-default provenance
carried through `BrowserSessionRequest` and `HttpContext` so the shared `NetworkTransactionPlanner`
can bind a generated request to a known browser process. The catalog now includes only the modeled
Windows browser versions. The process-binding change remains a second safeguard for baseline and
other generated request paths. This is a family-level change; Zeek, proxy and endpoint outputs
continue to consume the same canonical request/process relationship.

The clean seed42 output has 360 exact Sysmon Event3-to-Zeek HTTP tuple matches. Among them, 179
requests have a supported Windows browser family and process FileVersion; all 179 majors match, with
zero mismatches. The 11-host logind probe also shows 57 visible New-session records, no duplicate
IDs, and zero chronological inversions. Earlier finalization failures during loop74 exposed an
exhausted out-of-order ID interval; the bounded uniqueness fallback now preserves generation when
that interval has no free integer. In this output the fallback did not create visible inversions.

## Validation and evaluation

- `eforge validate-config`: 101 files checked, zero issues.
- Focused browser ownership/session/logind tests: 53 passed; Windows UA pool contract tests: 4
  passed.
- `ruff check .`, `ruff format --check .`, `git diff --check`, and generation behavior manifest
  validation passed; manifest is revision 495.
- The fixed-seed generation completed; human and JSON evaluations passed. Score: 96.3400/100,
  135,966 records. Pillars: parseability 100, plausibility 96.82, causality 95.90, timing 90.79.
  The score is above the assessment guardrail; no automated-eval optimization was pursued.
- The full routine pytest suite was not run. No commit was requested.

## Blind panel

| Reviewer | Assessment | Verdict confidence | Synthetic confidence |
|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 68 | 34 |
| Detection Engineer | Inconclusive | 67 | 48 |
| Network Forensics | Inconclusive | 62 | 43 |
| Host/EDR Forensics | Inconclusive | 58 | 47 |
| **Mean** | **Inconclusive** | **63.75** | **43.00** |

Spread is 14 points. All four verdicts are Inconclusive, so deliberation was not triggered. The mean
synthetic-confidence score rose 1.25 points from loop73; the loop72→73 reviewer variance remains a
larger recent movement than this fix effect. The panel identified no hard contradiction.

## Prioritized findings

- **P2 — [distribution_texture], Network Forensics, one scanner burst:** `10.10.3.10` produced
  roughly 246–254 unanswered SYN attempts per port across ports 22, 80, 3306 and 445 in about six
  seconds, with similar counts in two Zeek views. A fast scan is plausible, so this is not an
  impossibility. Next loop should identify the owning scanner/action path and test its cross-port
  scheduling before deciding whether any family change is warranted.
- **P3 — [distribution_texture], Detection Engineer, Linux forwarding queues:** WEB-EXT-01 and
  FILE-LNX-01 show queue-backlog/checkpoint counters in the thousands compared with hundreds of
  visible local syslog lines. A remote or pre-window backlog is possible; inspect whether the
  repeated values and host distribution have a credible source/collection explanation.
- **P4 — [weak_signal], Detection Engineer, Linux maintenance motif recurrence:** several
  operational-noise themes recur across Linux hosts. Individually they are plausible; retain as a
  low-confidence texture observation unless a broader distribution probe supports it.
- **Deferred / unproven — macOS Unified Log volume:** Host/EDR notes a small sample, but collection
  scope is unknown and sparsity alone is not evidence of fabrication.

Full reviewer reports, evaluation artifacts, family contract, and probes are in this loop folder.
