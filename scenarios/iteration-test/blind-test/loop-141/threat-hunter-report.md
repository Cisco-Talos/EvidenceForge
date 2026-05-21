# Threat Hunter — Authenticity Assessment
## Verdict
**Assessment:** Synthetic
**Confidence:** 74

## Executive Summary
This is a high-quality dataset with strong source-native formatting and a coherent enterprise attack storyline, but several behavioral patterns feel generated rather than organically collected. The strongest synthetic indicators are repeated Linux command templates across users/hosts and a tightly staged, curriculum-like intrusion chain with unusually clean beacon/exfil behavior.

## Evidence For Synthetic
- `data/*/bash_history/*`: the same exact administrative commands repeat across unrelated users and hosts, e.g. `systemctl status sshd --no-pager`, `systemctl --user status 2>/dev/null | head -30`, `journalctl --since '10 min ago' --no-pager -n 20`, and `resolvectl query company.okta.com` appear 6-7 times across multiple bash histories. This looks like a shared command pool rather than independent analyst/admin behavior.
- `data/DC-01.meridianhcs.local/windows_event_security.xml:83020` through `:126060`: the attack chain is very complete and neatly staged: `PSEXESVC` install, service execution, domain account creation, Domain Admins addition, C2 PowerShell, `wevtutil cl Security`, then account deletion.
- `data/PROXY-01.meridianhcs.local/proxy_access.log:808`, `:834`, `:869`, `:906`, `:933`, `:976`, `:1002`, `:1060`, `:1097`, `:1137`: repeated DC check-ins to `api.westbridge-services.net/api/v2/checkin` have a clean cadence and stable endpoint/UA behavior.
- `data/PROXY-01.meridianhcs.local/proxy_access.log:991`: a single large upload to `/upload/telemetry/7f3a2b19` from `10.10.1.35` is plausible, but it lands very cleanly in the middle of the storyline without much surrounding operator mess.
- `data/WEB-EXT-01.meridianhcs.local/web_access.log:13` and `data/snort-perimeter/snort_alert.log:3`: the external Nikto-style scan is realistic in isolation, but the bounded 20-minute burst plus clean downstream alerting feels training-scenario shaped.

## Evidence For Real
- Windows Security and Sysmon formatting is mostly source-native: event IDs, provider metadata, `ProcessGuid`, `LogonId`, Kerberos fields, and process ancestry all look internally coherent.
- `data/DC-01.meridianhcs.local/windows_event_security.xml:126060`: the Security log clear is modeled plausibly, including the `1102` event and EventRecordID reset behavior.
- Zeek, proxy, ASA, Snort, web, and Windows records align without obvious impossible visible ordering. The PowerShell download, proxy request, DNS/SSL evidence, and network flow are feasible pivots.
- The dataset contains useful real-world messiness: proxy `407` auth failures, `502/504` errors, HTTP `206/304` responses, syslog service noise, failed auth events, storage/journald/polkit noise, and ordinary browser/update traffic.
- Certificate, DNS, and connection fields in Zeek have plausible shapes and do not show obvious malformed source-native values.

## Detailed Analysis
The apparent window is March 18, 2024, roughly 12:00-18:00 UTC for the core enterprise/network telemetry, with some Linux shell and session artifacts extending later. Sources include Windows Security/Sysmon/eCAR, Linux syslog/eCAR/bash history, Zeek core/DMZ, Cisco ASA, Snort, proxy, and web access logs.

The kill chain is coherent. An external source scans `WEB-EXT-01`, internal activity later pivots to domain infrastructure, `PSEXESVC` appears on `DC-01`, `svc_mhsync` is created and added to Domain Admins, proxy traffic shows C2/check-ins to `api.westbridge-services.net`, a large upload occurs from `10.10.1.35`, and DC cleanup follows via PowerShell and `wevtutil cl Security`. As a threat hunt dataset, it has excellent pivotability.

The issue is not field accuracy; it is behavioral entropy. The Linux bash histories reuse exact command strings too often across hosts and people, which is a classic synthetic fingerprint. The attack also has a clean “exercise narrative” quality: strong signals are present in the right places, in the right order, with limited failed tooling, dead ends, local staging residue, or competing operational noise.

I did not find a hard causality contradiction such as a visible dependent event preceding its visible initiator for the same identifier. I also would not treat the high cross-source correlation as suspicious by itself; the concern is that the surrounding human and adversary behavior is too templated for production telemetry.

## Realism Score by Category
- **Field format accuracy:** 8/10 — Windows, Zeek, ASA, proxy, web, and syslog records are largely source-native and internally consistent.
- **Temporal patterns:** 6/10 — plausible jitter exists, but C2 and scan activity are cleaner and more bounded than typical production evidence.
- **Cross-source correlation:** 8/10 — pivots line up well without obvious impossible ordering or source-native contradictions.
- **Behavioral realism:** 6/10 — the kill chain is plausible, but command reuse and attack neatness feel generated.
- **Environmental consistency:** 7/10 — topology, host roles, and log source coverage are coherent, with believable enterprise background noise.

## Recommendations
- Increase per-user and per-host command individuality in bash histories; reduce exact command reuse across unrelated users.
- Add more adversary messiness: failed attempts, retries, staging files, alternate commands, cleanup gaps, and benign activity interleaved around the intrusion.
- Vary C2 endpoints, headers, user agents, session behavior, and beacon timing more aggressively.
- Keep the strong field fidelity and cross-source consistency, but surround high-signal events with more partial visibility and organic operational noise.

