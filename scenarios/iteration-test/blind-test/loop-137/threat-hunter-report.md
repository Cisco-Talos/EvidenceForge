# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 74

## Executive Summary

This dataset is high-quality and the intrusion storyline is coherent across host, network, proxy, firewall, and web logs. I judge it synthetic primarily because the background behavior and some source details show templated generation patterns: repeated Linux command vocabulary across unrelated users/hosts, odd shell argument rendering, and web response-size behavior that looks randomized rather than organic.

## Evidence For Synthetic

- Linux process telemetry repeats a small command pool heavily: eCAR shows `head` 71 times, `tail -20` 14 times, `wc -l` 11 times, and repeated exact commands such as `tail -50 '~/.xsession-errors'` across DB-PROD-01, WEB-EXT-01, and APP-INT-01.
- Some eCAR Linux command lines preserve shell quoting in a way argv-based process telemetry normally would not. Example: APP-INT-01 eCAR at `2024-03-18T12:00:08.326Z` records `tail -50 '~/.xsession-errors'`, while bash history records the more shell-native `tail -50 ~/.xsession-errors 2>/dev/null`.
- WEB-EXT-01 web logs have suspicious response-size behavior: static assets are stable, but identical dynamic paths without query strings vary widely. Examples: `/login` returns `47437`, `42657`, `12624`, `13211`, `76026`, etc.; `/about`, `/blog`, and `/products` show similar one-off size variation.
- The adversary storyline is slightly too narratively clean: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, `api.westbridge-services.net`, log clearing, and account deletion all appear in clear phases with very little operator error, tooling failure, or unrelated ambiguity.
- DNS tunnel-style TXT traffic from `10.10.2.30` to `*.ns1.westbridge-services.net` rotates through many patterned answer formats (`s=N;d=...`, `xid:...:path...`, `m=...;c=...`) in a way that feels generator-authored, although this is also plausible malware behavior.

## Evidence For Real

- The attack chain is internally coherent. DC-01 shows `aisha.johnson` network logon from `10.10.1.35` at `15:59:57Z`, PSEXESVC service install at `15:59:59Z`, and `cmd.exe /c whoami && hostname` from `C:\Windows\PSEXESVC.exe` at `16:00:03Z`.
- Privilege and persistence events align cleanly: `net user svc_mhsync MhsSvc!2024 /add /domain` at `16:15:16Z`, Security 4720 account creation at `16:15:18Z`, Domain Admins add at `16:15:21Z`, `DeviceSyncSvc` service creation at `16:20:04Z`, and scheduled task creation at `16:20:07Z`.
- Exfiltration is cross-source plausible: FILE-SRV-01 creates `C:\ProgramData\Microsoft\cache_7f3a.zip`; Zeek records SMB transfer of `313934166` bytes from `10.10.2.20` to `10.10.1.35`; proxy logs then show a `314782740` byte POST from `10.10.1.35` to `/upload/telemetry/7f3a2b19`.
- Network artifacts look source-native: Zeek conn/http/ssl/x509, Cisco ASA NAT/build/teardown, proxy CONNECT/ssl-inspect, and Windows 5156/Sysmon 3 all tell consistent views of the same flows.
- Background noise is credible: Windows Update/Dell/Snapcraft/npm traffic, web crawler and Nikto-style probes, UFW blocks, journald/snapd/cron messages, DHCP renewals, and ordinary Kerberos 4768/4769 activity are present.

## Detailed Analysis

The main intrusion path starts on WS-AJOHNSON-01 and lands on DC-01. Aisha's workstation runs domain discovery at `15:20:18Z` (`net user /domain`, `net group "Domain Admins" /domain`), then DC-01 logs PSEXESVC installation from `10.10.1.35` at `15:59:59Z`. From there the operator validates execution, creates `svc_mhsync`, adds it to Domain Admins, installs `DeviceSyncSvc`, and creates an hourly scheduled task.

The C2 path is also coherent. DC-01 Sysmon records `DeviceSyncSvc.exe` making connections to PROXY-01 on `10.10.3.20:8080`; proxy logs show repeated `api.westbridge-services.net` check-ins beginning `16:30:24Z`; Zeek-DMZ records DNS A/AAAA lookups and TLS sessions to `45.33.32.30` with matching SNI.

Collection/exfiltration is one of the strongest realism points. FILE-SRV-01 logs `Compress-Archive` at `17:00:34Z` to create `cache_7f3a.zip`; Zeek sees the SMB download at `17:23:07Z`; WS-AJOHNSON-01 logs Chrome connecting to the proxy at `17:24:35Z`; the proxy logs the large POST one second later. That is a feasible pivot chain.

The main realism weakness is the non-attack baseline. Linux command activity looks like sampled command templates replayed across personas and hosts. Web application response sizes also look statistically synthetic: repeated static assets behave correctly, but dynamic pages vary in ways that do not track obvious query strings, sessions, or user-agent differences.

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Zeek, ASA, proxy, and syslog fields are mostly source-native with only minor oddities.
- **Temporal patterns:** 7 — Attack timing and C2 jitter are plausible; some baseline activity feels scheduled/generated.
- **Cross-source correlation:** 9 — Host, proxy, Zeek, firewall, and web artifacts line up well without obvious impossible ordering.
- **Behavioral realism:** 7 — The kill chain is believable, but admin/background command diversity is too templated.
- **Environmental consistency:** 7 — The enterprise layout is coherent, but web and Linux baseline artifacts reduce authenticity.

## Recommendations

If this were synthetic, I would improve it by expanding per-user command vocabularies, preserving Linux argv more realistically, making web response sizes stable unless a modeled dynamic factor changes them, and adding more operator imperfections: failed commands, mistyped paths, alternate tool attempts, partial cleanup, and unrelated admin activity around the intrusion. More host-specific quirks and small clock/collection irregularities would also make the environment feel less authored.
