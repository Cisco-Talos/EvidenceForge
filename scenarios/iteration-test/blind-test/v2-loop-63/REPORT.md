# Iteration Test Blind Assessment — Loop 63

## Outcome

Loop 63 preserved canonical SSH/logind close identities when observation omitted the visible
opener. The automated evaluation scored 97.2286 PASS across 129,460 records. The current-model
blind panel produced initial synthetic-confidence scores of 29, 71, 66, and 92 (mean 64.50),
with one Real and three Synthetic verdicts. Required deliberation revised the scores to 64, 82,
78, and 93 (mean 79.25), with a unanimous final Synthetic verdict.

## Individual Expert Summaries

**Threat Hunter:** Real, 74 verdict confidence, 29 initial synthetic-confidence; revised to
Synthetic, 78 and 64. The repaired SSH cross-source identifiers agreed, and attack, role, network,
and lifecycle evidence was unusually production-like. Four in-window SSH processes nevertheless
had close-only syslog lifecycles, suggesting incoherent observation grouping.

**Detection Engineer:** Synthetic, 84 verdict confidence, 71 initial synthetic-confidence;
revised to 90 and 82. A WS-MCHEN-01 Event 4648 used another workstation's stable IP address,
successful runas/PSEXESVC wrappers omitted executable children, and Zeek file analyzer metadata
contradicted the populated hashes and PE records.

**Network Forensics:** Synthetic, 74 verdict confidence, 66 initial synthetic-confidence;
revised to 84 and 78. The reviewer independently confirmed the Zeek analyzer contradictions and
found implausible multi-megabyte SYSVOL artifacts and templated SMB naming, while judging TCP,
DNS, TLS, proxy, certificate, and multi-sensor behavior exceptionally coherent.

**Host/EDR Forensics:** Synthetic, 95 verdict confidence, 92 initial synthetic-confidence;
revised to 96 and 93. Identical third-party releases received divergent full hash sets across
users and hosts, while build-specific Windows binaries collapsed to identical hashes. Doubled
Exchange path separators and weak service, TiWorker, snapd, and irqbalance texture were secondary.

## Fix Verification

- All five rendered SSH lifecycle joins with visible eCAR sshd termination and syslog logind
  removal use the same canonical numeric session identity; zero mismatches remain.
- APP-INT-01 session 378754, DB-PROD-01 session 278296, WEB-EXT-01 session 351238, and
  LOG-MON-01 session 39130 retain the IDs used by their canonical continuations.
- The former cross-source ID-substitution fingerprint did not recur in any expert report.
- The threat review exposed a narrower sibling: source-local syslog observation can retain only
  the terminal close after an in-window SSH opener.

## Prioritized Improvements

### P0 — Repair canonical binary content identity

Key installed third-party artifacts by product release, architecture, build, and artifact rather
than user, host, or installation path. Key OS binaries by modeled OS build. Generate hashes and
PE metadata atomically and validate both equality and inequality contracts across the fleet.

### P0 — Enforce Event 4648 host ownership

Derive local process and address fields from one canonical source host and reject addresses owned
by another modeled endpoint unless the field explicitly represents a remote origin.

### P0 — Derive Zeek analyzer declarations from completed analysis

Populated MD5, SHA1, and SHA256 fields must imply their analyzer names, and every emitted PE row
must imply `PE` in its parent files row across SMB, HTTP, SMTP, TLS, and future file paths.

### P1 — Apply SSH observation loss to lifecycle groups

Bind auth, PAM/logind open, shell, and terminal close visibility to a coherent source-local loss
decision. Model deliberate partial loss as an outage interval rather than repeated close-only
survival.

### P1 — Complete command-wrapper and service lifecycles

Materialize executable children for successful runas and cmd wrappers, normalize local Exchange
paths without damaging UNC paths, bound service recycle overlap, and parent TiWorker through a
modeled TrustedInstaller process.

### P1 — Condition Linux and SMB texture on environment identity

Bind package and hardware messages to durable host inventories. Separate SMB client/server process
semantics and condition file names and sizes on extension, share purpose, and operational role.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.2286: 99.9992 parseability, 96.4484 plausibility, 97.2176
causality, and 94.0615 timing. It confirmed source conformance and canonical ordering but did not
detect release/hash identity contradictions, the Event 4648 ownership leak, Zeek analyzer
bookkeeping, source-local SSH observation grouping, or environment-conditioned content texture.
