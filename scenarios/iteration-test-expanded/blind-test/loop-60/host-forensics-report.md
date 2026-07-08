# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 72

## Executive Summary

The dataset is highly realistic in cross-source correlation, especially SSH and RDP session evidence across syslog, eCAR, Windows Security, Sysmon, and Zeek. However, multiple shell pipeline process lifecycles are impossible or extremely unlikely at the endpoint level: upstream `cat` processes remain alive long after downstream `head`, `grep`, or `cut` consumers have exited, which points to synthetic process-duration modeling.

## Evidence For Synthetic

- **hard_contradiction:** `DB-PROD-01` bash history records `cat /proc/cpuinfo | grep 'model name' | head -1` at `/private/tmp/research-data-he-t1iawF/dataset/DB-PROD-01.meridianhcs.local/bash_history/marcus.chen.bash_history:12`. eCAR lines 601-606 split that pipeline into `grep`, `cat`, and `head`; `head` terminates at `2024-03-18T17:24:22.853Z`, `grep` at `17:24:23.850Z`, but upstream `cat /proc/cpuinfo` does not terminate until `17:24:42.604Z`.
- **hard_contradiction:** `DB-PROD-01` bash history records `cat /proc/version | cut -d' ' -f1-3` at line 16. eCAR lines 609-612 show `cut` terminating at `2024-03-18T17:25:25.018Z`, while upstream `cat /proc/version` remains until `17:25:47.587Z`, 22.569 seconds after its consumer exited.
- **hard_contradiction:** `PROXY-01` bash history records `cat /etc/passwd | head` at `/private/tmp/research-data-he-t1iawF/dataset/PROXY-01.meridianhcs.local/bash_history/marcus.chen.bash_history:10`. eCAR lines 805-807 show `head` terminating at `2024-03-18T13:31:33.788Z`; line 820 shows upstream `cat /etc/passwd` terminating only at `13:31:51.131Z`.
- **distribution_texture / weak_signal:** Several standalone short utilities have implausibly long eCAR lifetimes, consistent with duration texture being assigned independently of command semantics: `PROXY-01` `whoami` runs from `13:20:53.744Z` to `13:21:13.753Z` in eCAR lines 715/719, and `APP-INT-01` `cat /etc/hosts` runs from `12:45:17.853Z` to `12:45:38.726Z` in eCAR lines 71/72.

## Evidence For Real

- SSH correlation is strong: `PROXY-01` syslog lines 30-32 show `10.10.1.35:50379 -> 10.10.3.20:22` accepted for `aisha.johnson`; eCAR lines 242-244 show the matching `sshd` process, flow, and login; Zeek `conn.json:471` has the same tuple, `service:"ssh"`, and `conn_state:"SF"`.
- RDP correlation is also convincing: `WS-SMARTINEZ-01` eCAR line 407 creates `mstsc.exe /v:WS-PPATEL-01`, line 409 records `10.10.1.36:65523 -> 10.10.1.32:3389`; `WS-PPATEL-01` eCAR lines 366-367 record the inbound flow and Type 10 login with `logon_id:"0xd9ebadc"`, and Zeek `conn.json:3021` records the same RDP tuple.
- Windows account and session fields are internally consistent in inspected samples: domain SIDs are stable per user, logon IDs recur across related process/session activity, and Sysmon ProcessGUID/image mappings did not show reuse contradictions in the visible records.

## Detailed Analysis

The strongest endpoint defect is in shell pipeline lifecycle modeling. The DB and proxy examples are not merely "long commands"; they are pipelines where an upstream producer remains alive after downstream consumers have exited. For finite files like `/proc/version` and `/etc/passwd`, and for `head -1` early termination, the upstream `cat` should receive EOF or SIGPIPE and exit at roughly the same time as the downstream command.

The defect repeats across hosts and commands. On `DB-PROD-01`, the pipeline components share the same principal `marcus.chen`, same `session_id:"278970"`, same bash actor ID, and creation times within milliseconds, tying them to the bash history pipeline rather than unrelated commands. On `PROXY-01`, `head` and `cat /etc/passwd` likewise share the same session and bash actor.

Host and EDR correlation otherwise looks mature. SSH session records include syslog connection/auth/session open/session close, eCAR process/session lifecycle, and Zeek connection state with consistent ports and users. RDP includes source-side `mstsc.exe`, source and target eCAR flow records, target Type 10 login, and Zeek RDP traffic.

I did not treat suspicious activity, compact narrative, sanitized host/domain values, or missing Sysmon event types as synthetic indicators. The score is driven by concrete process-lifecycle contradictions visible in eCAR plus bash history.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---|---|
| hard_contradiction | bash_history + eCAR | DB-PROD-01 pipelines | High: impossible producer/consumer process ordering |
| hard_contradiction | bash_history + eCAR | PROXY-01 pipeline | High: upstream `cat` outlives `head` by 17.343s |
| distribution_texture / weak_signal | eCAR | Short utility lifetimes | Medium: command-aware duration modeling appears weak |

## Realism Score by Category

- **Field format accuracy:** 86 - Windows, syslog, eCAR, and Zeek fields are mostly source-native and internally coherent.
- **Temporal patterns:** 58 - Broad session timing is plausible, but pipeline process lifecycles are materially wrong.
- **Cross-source correlation:** 90 - SSH and RDP tuples, users, ports, and sessions align well across sources.
- **Behavioral realism:** 72 - User/admin activity is plausible; command duration semantics weaken realism.
- **Environmental consistency:** 84 - Host roles, IPs, users, and authentication paths are largely consistent.

## Recommendations

- Model shell pipelines as coupled process groups: when `head`, `cut`, or `grep` exits and closes the pipe, upstream producers should terminate immediately or near-immediately.
- Use command-aware lifetimes for common short utilities such as `whoami`, `cat`, `df`, `ls`, and simple `/proc` reads.
- If endpoint timestamps represent collector delay rather than process stop time, preserve true process end time separately so eCAR lifecycle ordering remains plausible.
