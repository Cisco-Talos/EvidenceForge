# Loop 140 Blind Assessment Report

## Individual Expert Summaries

Threat Hunter assessed the data as synthetic with 78 synthetic-confidence. The attack chain and cross-source pivots were coherent, but Linux eCAR process records looked like shell-history strings were converted directly into process telemetry. The clearest examples were `history -c && cat /dev/null > ~/.bash_history` rendered as a `/bin/bash` process create and quoted-tilde command lines such as `find '~/Downloads'`.

Detection Engineer assessed the data as real with confidence 64, which converts to synthetic-confidence 36 for the rolling score table. They found no hard field contradiction or impossible visible ordering and praised Windows/Sysmon/eCAR/Zeek/TLS consistency. Their residual synthetic evidence was mostly mild: start-time-sorted Zeek conn files, a bounded-window lock/unlock edge, and repeated Linux diagnostic families.

Network Forensics assessed the data as synthetic with 70 synthetic-confidence. The prior Snort TLS-failure contradiction disappeared; the new network concerns were PTR/A mirror regularity, templated malicious DNS labels/TXT answers, evenly distributed public resolvers, and a clean staged exfiltration chain.

Host/EDR Forensics assessed the data as synthetic with 66 synthetic-confidence. They found endpoint schema, process lifecycle, Linux SSH ordering, and cross-source correlations unusually strong. Their synthetic call came from repeated Linux/admin command vocabulary, `corp.local`/generic-host naming drift, and a compact DC compromise narrative.

## Prioritized Improvements

| Priority | Issue | Reviewer rating(s) | Score impact | Description |
| --- | --- | --- | --- | --- |
| P0 | Linux eCAR shell/process semantics | Threat P0 | High | eCAR renders shell builtins, redirection, pipes, and quoted `~` paths as process creates. Fix the Linux process generation/rendering owner so eCAR PROCESS/CREATE rows represent executable argv or explicitly rendered shell invocations, not raw bash-history strings. |
| P1 | Repeated Linux command templates | Threat P1, Host P1, Detection P4 | High | Exact diagnostic/admin commands recur across users and host roles, including desktop-oriented checks on server systems. Add role/persona-aware command families and vary flags, targets, paths, aliases, correction patterns, and user habits. |
| P1 | PTR/A lookup mirror regularity | Network P1 | Medium | DMZ PTR records all have same-origin A lookups for the same name/IP within about one second, often PTR-before-A. Add cache/miss behavior and unmatched PTRs so reverse lookups are not mechanically paired with forward lookups. |
| P2 | Environment naming drift in Linux/admin artifacts | Host P2 | Medium | Linux command artifacts reference `corp.local`, `db-srv-01`, and `app-srv-02` while the modeled domain/host inventory uses `meridianhcs.local`, `DB-PROD-01`, and `APP-INT-01`. Harmonize these pools or model legacy aliases with corroborating evidence. |
| P2 | Malicious DNS label/TXT grammar | Network P2 | Medium | C2/TXT labels and answers still look generated, e.g. fixed token styles under `westbridge-services.net` and `.tk`/`.top` labels. Broaden grammar and statefulness before tuning lower-impact network polish. |
| P3 | Exfiltration and attack narrative neatness | Threat P3, Network P2, Host P2 | Low | The exfil chain is coherent but compact and low-friction. Add selected operator hesitation, retries, benign concurrent admin noise, and larger-transfer timing variation after the source-native process/DNS issues. |

## Comparison With Quantitative Eval

Automated eval passed at `96.0962/100` across `81,999` records. The Loop 140 hard probe found `0` TLS-handshake-failure alerts and `0` Rapid POP3 alerts across `39` Snort alerts, confirming the unsupported baseline IDS false positives are suppressed.

The blind score improved substantially because Detection judged the dataset real, but the panel exposed a new high-leverage endpoint source-native issue. Loop 141 should target Linux eCAR command semantics and repeated command pools first because that was the only P0 and was echoed by Host and Detection as behavioral/template evidence.
