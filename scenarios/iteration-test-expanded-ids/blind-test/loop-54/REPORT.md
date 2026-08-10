# Loop 54 Assessment Report

## Outcome

Loop 54 generated 84,155 records and scored 95.95. Fresh initial synthetic-confidence scores
were 56 (Threat Hunter), 64 (Detection), 65 (Network), and 55 (Host/EDR), averaging 60.0. The
Inconclusive/Synthetic split triggered deliberation. The reconciled panel unanimously assessed
the corpus Synthetic at 63/76/69/68, averaging 69.0.

## Fresh Expert Findings

- Host found that 112/129 Sysmon Event 11 records used one five-digit `C:\Windows\Temp` grammar
  across all nine Windows hosts and implausibly broad process owners.
- Detection found 37 visibly closed SSH sessions without same-PID eCAR termination and a
  one-sided 0.403–6.757 second Bash-history-to-process timing band.
- Threat Hunter found 106 successful human SSH logins with five-to-seven concurrent sessions,
  plus finite `tail` and `du` processes without termination.
- Network found subsecond-invariant per-host DHCP renewal intervals despite common lease lengths,
  while packet, UID, certificate, firewall, and multi-sensor contracts remained strong.

## Prioritized Improvements

1. **P0 — Process-native Windows files (`contract_gap`).** Ambient file creation must not assign
   one system-temp grammar to arbitrary core processes.
2. **P1 — SSH/finite process lifecycle (`contract_gap`).** Closed sessions and one-shot commands
   require coherent process termination.
3. **P1 — Source timestamp semantics (`distribution_texture`).** Shared execution anchors must
   not become universal one-direction observation bands.
4. **P2 — Stateful recurring behavior (`distribution_texture`).** SSH concurrency and DHCP
   renewals should evolve from role/session/protocol state.

## Implemented Fix

The generic ambient Windows file pool no longer contains the unowned
`C:\Windows\Temp\{rand}.tmp` template. Installer/update and shell side-effect profiles retain
their own process-native temp conventions, while arbitrary system processes no longer receive
generic numeric temp-file creation. The EDR pool suite passes (65 tests).

## Quantitative Comparison

Parseability was 100.0, plausibility 96.53, causality 90.66, and timing 95.75. The Loop 53
ownership probe found zero `rsyncd`-owned outbound SMB flows; 107 used `smbclient`, 72 used
`gvfsd-smb-browse`, and six were explicit `nmap` probes.
