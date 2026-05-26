# Loop 142 Blind Realism Assessment

## Individual Expert Summaries

**Threat Hunter:** Synthetic at 66 confidence. The reviewer praised source-native Windows escalation, SMB/proxy/TLS exfil correlation, and realistic background entropy, but still read the scenario as too “training complete”: compact full-kill-chain execution, repeated bash history commands across hosts, readable DNS tunnel grammar, and tidy breadcrumbs such as `svc_mhsync`, `DeviceSyncSvc`, and `cache_7f3a.zip`.

**Detection Engineer:** Synthetic at 72 confidence. Windows Security, Sysmon, Zeek, ASA, Snort, proxy, and syslog schemas were judged strong, but Linux eCAR SSH session lifecycle was a hard source-correlation issue: eCAR LOGINs matched syslog opens, while 23/23 sampled eCAR LOGOUTs lacked matching `pam_unix(sshd:session): session closed` rows and at least one APP-INT session changed apparent eCAR object ID between login and logout.

**Network Forensics Analyst:** Synthetic at 64 confidence. Zeek source-native references, core/DMZ sensor observation, SMB-to-proxy-to-TLS exfil, DNS messiness, and TLS/X509 chains were convincing with no hard network ordering contradictions found. Remaining network realism issues were authored-looking DNS-tunnel TXT payloads, repeated HTTP body sizes on API paths, pool-like User-Agent/application strings, and proxy DNS caching that looked too convenient around low-TTL C2 hostnames.

**Host/EDR Forensics Analyst:** Synthetic at 72 confidence. Windows process trees, DC log clearing, Linux syslog texture, and bash history entropy were strong, with no visible logoff-before-logon or terminate-before-create contradictions found. The main endpoint tells were command-agnostic eCAR process/network behavior (`docker ps` emitted proxy flow and a multi-hour runtime), sudo denied-command records missing `PWD=`, and repeated service-account denied-command pools across hosts.

## Prioritized Improvements

| Priority | Issue | Reviewer original rating(s) | Score impact | Description |
| --- | --- | --- | --- | --- |
| P0 | Linux eCAR SSH LOGOUT/session identity mismatch | not labeled | High | Detection found eCAR SSH LOGIN rows align with syslog opens, but eCAR LOGOUT rows do not align with visible PAM/syslog closes and can use different session object IDs. This is a concrete cross-source lifecycle contradiction and should be fixed at the canonical SSH/session state layer so eCAR and syslog render the same session close. |
| P1 | Command-agnostic eCAR network/lifetime behavior | not labeled | High | Host/EDR found `/usr/bin/docker` with `docker ps` emitted a proxy flow and lived for hours. Network effects and foreground lifetimes should be command-aware: local-only commands should not inherit generic proxy/network behavior or long-lived process state. |
| P1 | Sudo denial formatting and template repetition | not labeled | High | Host/EDR found 137 denied sudo records on WEB-EXT/PROXY that all omit the usual `PWD=` field and cycle a tiny pool of service users and commands. Fix the syslog template/source-native fields first, then diversify service-account and denial-command pools by host role. |
| P1 | Readable DNS tunnel TXT payloads | not labeled | Medium | Threat and Network both called out TXT answers like `xid:...:path-c24:n1` as too explanatory. Replace semantic labels with opaque encoded chunks and vary TXT answer size/structure while preserving deterministic exfil accounting. |
| P2 | Compact “training-complete” attack flow | not labeled | Medium | Threat Hunter found the full chain too polished within a short window. Longer dwell, partial dead ends, alternate branches, and less meaningful artifact names would reduce the authored feel, though this is partly scenario-level rather than engine-level. |
| P2 | Repeated HTTP response/User-Agent pools | not labeled | Medium | Network found repeated response sizes for dynamic-looking API paths and pool-like User-Agent/application strings. Add per-endpoint dynamic body variance, occasional response metadata inconsistencies, and broader long-tail UA/app inventory binding. |
| P3 | Small DB exfil size for EHR narrative | not labeled | Low | Threat Hunter noted the `mysqldump`/SCP path transfers only about 90 KB, small for implied production patient/claims data. Scale DB dump size or adjust narrative/ground truth language where this specific scenario is reused. |

## Priority Rationale

Loop 142 deliberately fixed hard source-native issues from Loop 141 before regeneration: literal `{username}` module path leaks, Zeek DNS RTT/connection-window contradictions, and LDAP base-DN/template leaks. The new highest-priority target is Detection’s eCAR/syslog SSH logout mismatch because it is the only current reviewer finding framed as a concrete cross-source lifecycle contradiction. Host/EDR’s eCAR command semantics and sudo-denial formatting follow because they are source-native and high-volume, while DNS tunnel grammar, compact story polish, and UA/HTTP pool repetition are broader realism-polish work.

## Comparison With Quantitative Eval

Automated eval passed at `96.6809/100` across `79,847` parsed records. Acceptance criteria all passed; hard probes found zero `{username}`/`{user}` placeholder leaks, zero `{ldap_base_dn}` leaks, zero `dc=corp,dc=local` LDAP base-DN leaks, and zero same-UID Zeek DNS RTT rows outside the rendered connection lifetime. Eval still flags known storyline pivot-linkability limitations and one expected-visible external scan with no traces, but it did not catch the blind-panel’s Linux eCAR SSH logout/syslog close mismatch, command-aware eCAR network/lifetime issue, sudo denied-message field shape, or authored-looking DNS/HTTP payload grammar.

## Score Summary

| Loop | Automated eval | Records | Threat Hunter synthetic-confidence | Detection synthetic-confidence | Network synthetic-confidence | Host/EDR synthetic-confidence | Avg synthetic-confidence |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 133 | 96.1304 | 75,833 | 72 | 72 | 68 | 72 | 71.00 |
| 134 | 95.7270 | 80,629 | 70 | 78 | 72 | 74 | 73.50 |
| 135 | 96.1770 | 80,629 | 72 | 64 | 88 | 62 | 71.50 |
| 136 | 96.2770 | 80,629 | 66 | 72 | 68 | 78 | 71.00 |
| 137 | 96.1467 | 81,434 | 74 | 66 | 76 | 77 | 73.25 |
| 138 | 95.3467 | 81,434 | 86 | 82 | 74 | 70 | 78.00 |
| 139 | 96.6267 | 77,465 | 72 | 72 | 72 | 72 | 72.00 |
| 140 | 96.0962 | 81,999 | 78 | 36 | 70 | 66 | 62.50 |
| 141 | 96.1313 | 79,737 | 74 | 74 | 78 | 76 | 75.50 |
| 142 | 96.6809 | 79,847 | 66 | 72 | 64 | 72 | 68.50 |
