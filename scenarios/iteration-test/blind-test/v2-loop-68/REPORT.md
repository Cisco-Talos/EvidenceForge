# Iteration Test Blind Assessment — Loop 68

## Outcome

Loop 68 bound successful port-88 KDC audit events to their exact canonical transport and made
target-side Windows 5156 packet admission the source-local lower bound for 4768, 4769, and 4771.
The automated evaluation scored 96.3826 PASS across 122,597 records. Initial blind
synthetic-confidence scores were 68, 43, 29, and 92 (mean 58.0). Verdict disagreement and the
63-point spread triggered deliberation; revised scores were 82, 78, 58, and 93 (mean 77.75).

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 80 verdict confidence, 68 synthetic-confidence. Cross-source
coverage and source-native formats were strong. The decisive concern was an `nmap -sT` invocation
without `-Pn` that scanned almost every port on all 254 addresses after a separate discovery found
only nine live hosts; collapsed reverse-shell children and one-connection-per-file SMB texture
added support.

**Detection Engineer:** Inconclusive, 82 verdict confidence, 43 synthetic-confidence. Windows,
Sysmon, eCAR, Zeek, and lifecycle schema behavior was highly credible, and the repaired KDC/WFP
inversion did not recur. A same-session 4800-to-4801 interval of 406 microseconds was a hard
one-off contradiction, while repeated blank PE version-resource fields on GoogleUpdater and
MpCmdRun remained a medium-strength enrichment fingerprint.

**Network Forensics:** Real, 73 verdict confidence, 29 synthetic-confidence. Sensor-local UIDs,
state histories, durations, DNS, TLS/X.509, proxy legs, clock offsets, and packet accounting were
judged production-like. Two dangling HTTP FUIDs, six file/connection missing-byte mismatches, and
a 623 MB SMB transfer without file companions were concrete gaps but retained plausible
collection, encryption, or analyzer-policy explanations.

**Host/EDR Forensics:** Synthetic, 96 verdict confidence, 92 synthetic-confidence. The strongest
finding was systematic: 71 sudo records across 14 continuing parent shells and 11 hosts rotated
among multiple controlling terminals without a new shell or session identity. Eight in-window
sshd processes had close-only source lifecycles, and high-rate fleet-wide irqbalance/snapd chatter
reinforced the host-side fingerprint.

## Deliberation Findings

The facilitator preserved the broad Windows and network realism but found the shell/TTY identity
contradiction unrebutted and the command-to-network Nmap mismatch material. Revised positions were
Threat 82, Detection 78, Network 58, and Host 93 (mean 77.75): three Synthetic verdicts and one
Inconclusive. The network analyst's credible collection alternatives prevented a stronger
corpus-wide consensus.

## Fix Verification

- Exact target-side WFP/KDC tuple probes found 1,302 of 1,302 matched DC-01 audit rows and 1,386 of
  1,386 matched DC-02 rows after Event 5156, with zero inversions on either controller.
- Baseline outbound, inbound, service-client, DC-cycle, member-logon, machine-account, and visible
  failed-preauthentication paths now delegate KDC evidence to the committed transport contract.
- A rejected KDC transport cannot publish a source-local 4771 or leave audit reservations behind.
- Behavior revision 32 now records surface digest
  `921a464f493e07f915d0be797cf97bd48becb090e2503481f30aac8c9cdbf5bb`.
- The routine gate passed 8,401 tests with 5 skips and 2,009 deselections; repository-wide Ruff
  check and format check passed across 769 files.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The loop-67 KDC/WFP inversion did not recur in any initial expert report.

## Prioritized Improvements

### P0 — Make controlling terminal immutable session state

Bind each interactive shell process identity to one controlling TTY for its lifetime. Allocate a
new `pts/*` only through a separately evidenced login/session and shell creation, and reject any
child command whose terminal disagrees with its continuing parent shell.

### P1 — Derive scan traffic from each visible Nmap invocation

For `nmap -sT` without `-Pn`, generate that invocation's own discovery phase and restrict service
probes to hosts it classifies as up. If an external configuration or wrapper forces `-Pn`, retain
visible evidence of that override so the full-address footprint is explainable.

### P1 — Preserve SSH source lifecycles coherently

Apply one source-local observation decision to connection, authentication, PAM open, logind,
shell, PAM close, and termination evidence for each in-window sshd process. Do not repeatedly
retain only a close for a process whose start is visible in the same source window.

### P2 — Repair user-state and shell-pipeline causality

Enforce a human-plausible minimum lock dwell between 4800 and 4801 for one session. Materialize
external pipeline commands and the inner shell, and attribute `/dev/tcp` flow ownership to the
process that actually opens the socket.

### P3 — Complete source-native metadata and file-session contracts

Populate stable VERSIONINFO for known installed binaries or tie enrichment loss to an explicit
collector condition. Reuse SMB connections and tree mappings across adjacent operations, and
ensure every emitted HTTP FUID resolves or carries a coherent observation-drop explanation.

### P4 — Broaden host-local distribution texture

Vary irqbalance, snapd, scheduling, hardware, and diagnostic message families by host role and
installation rather than deploying one high-rate fleet-wide vocabulary.

## Priority Rationale

TTY identity is first because it is a fleet-wide hard process/session contradiction with no
credible collection explanation. Nmap semantics and close-only SSH are next because visible
command and process evidence make them directly testable. Lock timing, pipeline lineage, metadata,
SMB/FUID contracts, and host chatter are narrower or admit stronger operational alternatives.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.3826: 99.9992 parseability, 96.8608 plausibility, 94.3789
causality, and 92.8647 timing. It reflected the repaired transport ordering through higher
causality and timing than the provisional loop-68 run, but did not detect terminal identity
changes, Nmap command semantics, close-only SSH groups, the 406-microsecond lock, dangling FUIDs,
blank PE resources, or SMB sessionization. Expert review also credited sensor clock drift,
Windows lifecycle semantics, and TLS/X.509 coherence that the aggregate score does not expose.
