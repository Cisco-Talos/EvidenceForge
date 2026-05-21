# Loop 137 Blind Realism Report

## Individual Expert Summaries

Threat Hunter judged the data synthetic with 74 confidence. They did not re-flag the Loop 137 endpoint-fidelity fixes, and instead focused on repeated Linux command vocabulary, quoted shell arguments rendered in eCAR, unstable dynamic web response sizes, clean adversary storyline phases, and patterned DNS-tunnel TXT payloads.

Detection Engineer judged the data synthetic with 66 confidence. They found Windows, Zeek, ASA, proxy, and eCAR records mostly SIEM-usable, with no hard Windows/Sysmon schema blocker. Their remaining concerns were high-volume Linux baseline telemetry: repeated `systemd-journald` disk-usage messages, excessive `systemd-logind` session churn, and repeated Linux noise motifs across hosts.

Network Forensics judged the data synthetic with 76 confidence. They found many realistic Zeek/proxy/TLS correlations, but reported a source-native hard contradiction: OCSP rows occur seconds after their referenced HTTP response file and parent TCP connection have ended. They also noted no SRV DNS in an AD-heavy environment and all-TCP Kerberos.

Host/EDR Forensics judged the data synthetic with 77 confidence. They found Windows endpoint and attack-chain evidence strong, but identified systemic Linux same-parent PID regressions in eCAR: later child processes under the same visible shell parent repeatedly receive lower PIDs across multiple Linux hosts.

## Fixed And Verified

- Loop 137 fixed the Host/Detection endpoint-fidelity cluster from Loop 136.
- Hard probe results found zero numbered UserAssist placeholders, zero short UserAssist details, zero polkit action/process mismatches, zero invalid polkit authentication-agent paths, zero missing metadata on sampled common Microsoft binaries, and zero low-entropy Sysmon ProcessGuid tails.
- Focused and related tests passed (`231 passed`), config validation passed, Ruff checks passed, and the full normal test suite passed with `3388 passed, 15 skipped`.

## Quantitative Eval

- Overall automated eval: `96.14669526004657`
- Records: `81,434`
- Parseability: `100.0`
- Plausibility: `97.19436829026284`
- Causality: `93.35420005424965`
- Timing: `92.54776586959221`

## Prioritized Improvements

### P0 — Zeek OCSP After Parent HTTP/TCP Lifetime

Reviewer original rating: not labeled. Score impact: high. Observed by Network.

OCSP records share file IDs and connection UIDs with HTTP/files/conn records but render several seconds after the parent TCP connection has ended. This is an impossible visible source-native ordering for the same identifier chain. Owning layer is Zeek OCSP/file timing; fix risk is moderate and should be validated with a hard probe across `ocsp.json`, `files.json`, `http.json`, and `conn.json`.

### P1 — Linux Same-Parent PID Regression

Reviewer original rating: not labeled. Score impact: high. Observed by Host/EDR.

eCAR Linux process rows show later children under the same visible shell parent receiving lower PIDs on several hosts. Real Linux PID allocation can wrap, but repeated backward movement under the same live parent in a six-hour window is implausible. Owning layer is Linux process PID allocation/state; fix risk is moderate because it touches process identity and correlations.

### P1 — Linux Journald/Logind Baseline Overproduction

Reviewer original rating: not labeled. Score impact: high. Observed by Detection.

`systemd-journald` disk-usage messages and `systemd-logind` session starts are emitted at high volume and with repeated motifs across unrelated Linux hosts. Owning layer is Linux syslog baseline scheduling/config. Fix risk is moderate; reduce journald disk lines to trigger-based events and tie logind sessions to concrete SSH/PAM/sudo/cron/GUI activity.

### P2 — Linux Command Pool And eCAR Argv Realism

Reviewer original rating: not labeled. Score impact: medium-high. Observed by Threat Hunter and Host/EDR.

Linux process telemetry and bash histories reuse exact command strings across unrelated hosts, and eCAR process command lines preserve shell quoting such as `tail -50 '~/.xsession-errors'`. Owning layer is command pool selection and process command rendering. Fix risk is moderate; argv should strip shell-only quotes while bash history can preserve shell syntax.

### P2 — AD DNS Discovery Distribution

Reviewer original rating: not labeled. Score impact: medium. Observed by Network.

An AD-heavy environment shows direct A lookups for `DC-01` but no SRV queries for `_ldap._tcp`, `_kerberos._tcp`, or `_msdcs`, despite heavy Kerberos/LDAP connections. Owning layer is DNS/Kerberos causal expansion. Fix risk is moderate and may pair naturally with future Kerberos UDP/TCP transport mix work.

### P3 — Dynamic Web Response Size Stability

Reviewer original rating: not labeled. Score impact: medium. Observed by Threat Hunter.

Static assets are stable, but identical dynamic paths without query strings vary widely in byte counts. Owning layer is web access content-size modeling. Fix risk is low to moderate if modeled as path/session-class stable with bounded dynamic variance.

## Priority Rationale

The Loop 137 endpoint-fidelity fixes held under blind review. Loop 138 should target the OCSP hard ordering contradiction first because it is a concrete source-native impossibility. Linux PID regression is the next strongest root-cause candidate, followed by Linux syslog baseline overproduction and command-pool polish.

## Comparison With Quantitative Eval

The automated eval remained high at `96.1467`, but blind average synthetic-confidence increased from `71.0` to `73.25` because the panel surfaced deeper concrete issues after the prior Host/Detection tells were removed. Eval did not detect OCSP-after-connection-end, Linux PID monotonicity under a live shell parent, journald/logind overproduction, or shell quoting in eCAR process arguments. Blind reviewers did not emphasize the automated eval's causality/pivot-linkability penalties.
