# Loop 141 Blind Realism Assessment

## Individual Expert Summaries

**Threat Hunter:** Assessed Synthetic with confidence 74. The hunter found the attack story coherent and highly pivotable, with strong Windows/Zeek/proxy evidence, but called out exact Linux admin command reuse across unrelated users/hosts and a too-neat intrusion sequence with stable C2 and exfil behavior.

**Detection Engineer:** Assessed Synthetic with confidence 74. The detection review found SIEM-friendly Windows, Zeek, proxy, ASA, syslog, and eCAR data, but identified a hard source-native placeholder leak: `C:\Users\{username}\...zVideoApp.dll` appears in both Sysmon Event 7 and eCAR file telemetry for a real user path.

**Network Forensics:** Assessed Synthetic with confidence 78. The network review praised the Zeek/proxy/TLS/DNS macro texture, but found a systematic same-UID DNS timing contradiction: many one-query/one-response DNS records have `dns.ts` shifted after `conn.ts` while `conn.duration == dns.rtt`, making the response fall outside the connection window.

**Host/EDR Forensics:** Assessed Synthetic with confidence 76. The endpoint review considered Windows evidence particularly strong, but found Linux/eCAR command provenance defects: repeated `ldapsearch` commands use `dc=corp,dc=local` in a `meridianhcs.local` estate and short LDAP lookups remain alive for hours.

## Quantitative Eval

- Overall score: `96.13125761629647/100`
- Records: `79,737`
- Acceptance: PASS
- Pillars: Parseability `100.0`, Plausibility `97.2392`, Causality `94.0244`, Timing `91.9406`
- Notable eval gaps: automated eval did not catch literal `{username}` placeholders, Zeek DNS transaction-window semantics, LDAP base-DN vocabulary leaks, or cross-user command-pool repetition.

## Hard Probe Results

Loop 141 hard probes after the fixes found:

- `0` bad bare-shell history-clear process rows
- `0` quoted-tilde process command lines
- `0` `*.corp.local` internal app URL command lines
- `0` exact `kubectl get nodes -o wide` commands
- `0` server-side desktop command process rows

The Loop 140 shell/process, internal app-domain, and server desktop-command issues are verified fixed.

## Prioritized Improvements

| Priority | Issue | Reviewer Original Rating(s) | Score Impact | Description |
| --- | --- | --- | --- | --- |
| P0 | Literal `{username}` placeholder in module-load paths | not labeled | High | Detection found a concrete source-native leak in Sysmon Event 7 and eCAR file telemetry for Zoom. This is an immediate authenticity failure because a real endpoint would render `evelyn.brooks`, not a template token. |
| P0 | Zeek DNS transaction timing contradiction | not labeled | High | Network found hundreds of same-UID DNS rows where `dns.ts`, `dns.rtt`, and `conn.duration` cannot all describe the same one-query/one-response UDP exchange. This belongs in Zeek DNS/conn analyzer timing, not reviewer prompt handling. |
| P1 | LDAP base-DN leak and long-lived quick LDAP processes | not labeled | High | Host/EDR found `ldapsearch -b "dc=corp,dc=local"` in a `meridianhcs.local` estate and simple queries lasting hours. Fix command parameterization and source-native process lifetime modeling for short CLI queries. |
| P1 | Repeated Linux command pools across users/roles | not labeled | Medium | Threat Hunter and Host/EDR both found exact command strings repeated across unrelated users and Linux hosts. Loop 141 reduced some server-role bleed, but broader per-user/per-host command individuality still needs work. |
| P2 | Weak Sysmon metadata for known Program Files binaries | not labeled | Medium | Detection counted many Event ID 1 rows for signed third-party software with `Company`, `Product`, `Description`, and `OriginalFileName` as `-`. Extend data-driven PE metadata for common service/update binaries. |
| P2 | C2/exfil chain too clean | not labeled | Medium | Threat Hunter found C2 check-ins and the single upload plausible but exercise-shaped. Add failed attempts, header/user-agent variation, alternate endpoints, local staging residue, and benign interleaving. |

## Priority Rationale

The next loop should target hard source-native contradictions before subjective behavioral polish. The literal `{username}` path leak is the fastest high-confidence fix; Zeek DNS timing is also high leverage but likely touches shared analyzer timing. LDAP base-DN/lifetime and command-pool repetition are next because they recur in host and threat-hunting reviews.

## Comparison With Loop 140

Loop 141 fixed the Loop 140 Linux shell-process and domain drift probes, but blind confidence worsened from `62.5` to `75.5`. This appears to be deeper concrete issue surfacing rather than a regression in the latest fixes: reviewers no longer centered on shell builtins or `corp.local` app URLs, and instead found new source-native leaks and timing contradictions.

