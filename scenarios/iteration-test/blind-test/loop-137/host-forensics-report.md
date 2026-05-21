# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 77

## Executive Summary

The Windows endpoint and attack-chain evidence is unusually coherent and often source-native, but the Linux/eCAR process model has repeated PID allocation artifacts that are hard to reconcile with real host telemetry. The strongest synthetic signal is systemic: later child processes under the same shell parent repeatedly receive lower PIDs within the same visible session.

## Evidence For Synthetic

- APP-INT-01 eCAR line 22: at `2024-03-18T12:12:17.235Z`, `ppid=836042` creates `wc -l` with `pid=838419`; 190 ms later, same `ppid=836042` creates `grep ESTABLISHED` with lower `pid=838393`.
- PROXY-01 eCAR line 231: at `12:21:26.706Z`, `kubectl get pods -n kube-system` has `pid=655163`; 18 ms later, same parent `ppid=653461` creates `kubectl get pods -n default` with lower `pid=655137`.
- WS-LNGUYEN-01 eCAR line 45: same shell `ppid=33562` creates `cargo build --release` with `pid=781025`, then later `git diff --stat` with `pid=780960`, then `cat /etc/os-release` with `pid=780774`.
- DB-PROD-01 eCAR line 465: same root shell `ppid=699072` creates `gzip` with `pid=699114`; nearly five minutes later, `scp` is created with lower `pid=699086`.
- This is not isolated. I observed same-parent PID decreases across multiple Linux hosts: APP-INT-01, DB-PROD-01, PROXY-01, WEB-EXT-01, WS-LNGUYEN-01, and WS-OHADDAD-01. Real Linux PID allocation can wrap or reuse, but repeated backward movement under the same live shell across a short six-hour window is a strong generator artifact.
- Bash histories show command-pool repetition across unrelated users and hosts, for example repeated `systemctl status systemd-resolved --no-pager`, `apt-cache policy google-chrome-stable 2>/dev/null`, `ip route get 8.8.8.8`, and `journalctl -u sshd --since '1 hour ago'`. This is plausible in isolation, but the breadth and exact string reuse looks templated.

## Evidence For Real

- DC attack chain is well formed: `DC-01/windows_event_sysmon.xml` shows `services.exe` writing `C:\Windows\PSEXESVC.exe` at `2024-03-18T15:59:59.1256176Z`, then `PSEXESVC.exe` launching under `services.exe` at `16:00:01.7215206Z`.
- Account-management evidence is source-native: `DC-01/windows_event_security.xml` has Event `4720` for `TargetUserName=svc_mhsync` at `16:15:18.8006976Z`, Event `4728` adding it to `Domain Admins` at `16:15:21.0464573Z`, then Event `4726` deleting it at `17:50:18.8736983Z`.
- Audit clearing is realistic: Sysmon records `wevtutil cl Security` at `17:42:02.7425612Z`, and Security Event `1102` follows at `17:42:15.5173613Z` with the Security log record counter reset.
- The DB exfil chain is coherent. DB-PROD-01 eCAR line 461 shows root SSH login from `10.10.2.30`, `mysqldump`, gzip file creation, and `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`.
- APP-INT-01 eCAR line 849 records the matching inbound SSH flow from `10.10.4.10:33725` and file creation `/tmp/.cache/rpt_0318.sql.gz`. Zeek-core also records the same SSH transfer at `2024-03-18T17:20:15.881640Z`.

## Detailed Analysis

Windows endpoint evidence is the strongest part of the dataset. Process creation, service install, account creation, privilege escalation, PowerShell execution, log clearing, and cleanup line up in a way I would expect from a real incident export. The Security/Sysmon/eCAR timings are not perfectly identical, which helps; they look like separate telemetry pipelines observing the same actions.

The Linux endpoint evidence is where authenticity breaks. The same-shell PID regressions are not just gaps or missing pre-window parents. They are visible, same-parent process creation events occurring in chronological order with decreasing PIDs. That points to PIDs being sampled or derived independently instead of allocated from a host-level process counter.

The bash histories are mixed. Typos such as `hostnaem`, `systtemctl`, and `lastt` are plausible user behavior, and I did not see obvious process creates for those failed commands. But many histories read like sampled operational command pools, with exact repeated diagnostics across hosts and users rather than strongly individualized work patterns.

The cross-source correlation is high quality. I do not treat that as synthetic by itself, per the briefing. In fact, the DB-to-APP scp flow and the DC PSEXESVC sequence are both good realism anchors. The final verdict is driven by concrete endpoint process-lifecycle artifacts, not by the completeness of correlation.

## Realism Score by Category

- **Field format accuracy:** 84 — Windows XML, Security IDs, Sysmon fields, and Zeek records are mostly credible; eCAR Linux PID semantics are the major flaw.
- **Temporal patterns:** 72 — Attack sequences and log clearing are plausible, but Linux process ordering exposes synthetic allocation.
- **Cross-source correlation:** 90 — DB/APP/Zeek and DC Security/Sysmon/eCAR correlations are internally strong.
- **Behavioral realism:** 63 — The attack behavior is credible; repeated shell command pools across users/hosts feel generated.
- **Environmental consistency:** 70 — Host roles and user activity mostly fit, but Linux endpoint process behavior is not host-realistic.

## Recommendations

Fix Linux PID generation at the host namespace level: allocate monotonically from a persistent per-host counter and only reuse after realistic wrap/reboot conditions. Model shell pipelines and same-parent child creation as real forks from one shell, preserving plausible PID order. Reduce exact command-string reuse by making bash histories more persona-, role-, distro-, and host-specific.
