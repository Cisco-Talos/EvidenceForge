# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 76

## Executive Summary

The host evidence has strong field-level and cross-source construction, but two repeated lifecycle defects are difficult to reconcile with the otherwise rich endpoint collection: closed SSH sessions usually leave their per-session `sshd` process alive in eCAR, and Windows `taskhostw.exe` instances accumulate almost without termination. These are family-specific, dataset-wide defects rather than mere boundary truncation, so I assess the data as likely synthetic.

## Evidence For Synthetic

- `[contract_gap]` Across the Linux eCAR files, `/usr/sbin/sshd` has 52 `PROCESS/CREATE` records but only 7 `PROCESS/TERMINATE` records; 45 created responder processes have no termination. This is not confined to sessions open at the end of the six-hour window. On `MAIL-EDGE-01`, PID 3788016 is created at 2024-03-18 14:44:51.523Z, syslog records `pam_unix(sshd:session): session closed` at 15:00:44.041149Z, and eCAR records the matching `USER_SESSION/LOGOUT` at 15:00:44.041Z, but no eCAR termination exists for process object `de48ae51-1ff8-423b-a8f4-56f73f27d919`. The same defect affects PIDs 3790956 and 3791674 after their visible session closes.
- `[contract_gap]` Windows eCAR contains 84 `taskhostw.exe` creations but only one termination. `DC-01` alone creates 31 SYSTEM-owned instances from PID 2352 between 12:28 and 17:52, all with `taskhostw.exe` or `taskhostw.exe /Run`, and none terminates. `FILE-SRV-01` similarly creates 14 from PID 3368 with no termination. In a feed that records 1,398 other process terminations, this family-specific accumulation would leave dozens of concurrent short-task hosts and is not plausibly explained by a global termination-collection gap.
- `[distribution_texture]` The Windows maintenance palette is repeated at conspicuous fleet scale in only six hours: 84 `taskhostw.exe`, 47 bare `wsqmcons.exe`, 30 `GoogleUpdater.exe -Embedding`, and repeated identical `WmiPrvSE.exe` and `dllhost.exe` command lines across workstations and server roles. Individual instances are valid, but the combination of high recurrence, limited command-line vocabulary, and role-insensitive placement looks assembled rather than organically installed and scheduled.
- `[environment_or_collection_plausibility]` The eCAR collection behavior is selectively complete by executable family. Shell helpers such as `sh` and `debian-sa1` each have 88 creates and 88 terminations, while `sshd` has 52 creates and 7 terminations; Windows `wsqmcons.exe` has 47/47 but `taskhostw.exe` has 84/1. A real collection profile could miss events, but these sharply executable-specific ratios align with missing lifecycle ownership more than ordinary packet loss or endpoint-agent dropout.
- `[weak_signal]` Every one of the 1,495 Linux eCAR process records carrying both fields sets `tid == pid`. That is legal for a main thread and therefore not a contradiction, but the absence of any non-main-thread process observation across this volume gives the Linux endpoint view unusually uniform texture.

## Evidence For Real

- The Windows process trees are generally credible. For example, `WS-SMARTINEZ-01` PID 7296 is Outlook launched by user-owned `explorer.exe` PID 7108 with a realistic `/recycle` command line; its eCAR process object then owns Office-specific module loads, IMAP/SMTP flows, and Outlook cache-file creation under Sophia Martinez's profile.
- For actor relationships that can be bounded by visible eCAR process creation and termination, I found no dependent event before its actor's creation and no dependent event after its actor's termination. That is a strong positive for internal lifecycle ordering.
- Linux syslog has source-native SSH sequences with connection, key method and fingerprint, PAM open, systemd-logind session creation, and PAM close evidence. Values remain consistent across user, source address, source port, PID, and session identifiers.
- The environment has credible role differentiation: Windows Security/Sysmon on Windows systems, syslog on Linux systems, mail-daemon records on mail hosts, proxy activity on the proxy, and server/client process and path conventions appropriate to each OS.
- Windows and eCAR records use plausible paths, principals, PIDs, parent PIDs, logon IDs, session IDs, and Office/module vocabulary. The observed defect is not broad schema breakage.

## Detailed Analysis

The visible interval is approximately 12:00–18:00 UTC on 2024-03-18 and covers 18 endpoint directories. Endpoint volume is substantial: Windows hosts carry Security, Sysmon, and eCAR; Linux hosts carry syslog and eCAR. eCAR includes processes, flows, files, registry activity, modules, and user sessions, allowing lifecycle checks rather than judgments based on isolated strings.

### SSH endpoint lifecycle

`MAIL-EDGE-01` provides a particularly clear example. Syslog PID 3788016 records the connection from `10.10.1.35:59978`, accepted RSA public-key authentication for `aisha.johnson`, PAM session open, and PAM session close. eCAR creates `/usr/sbin/sshd` PID 3788016 at 14:44:51.523Z, logs in the corresponding user at 14:44:55.097Z, and logs out the same session object at 15:00:44.041Z. Yet no termination exists for the responder's process object. The same host repeats this for Marcus Chen's PIDs 3790956 and 3791674, whose syslog sessions close at 16:06:19.985971Z and 16:00:45.125785Z respectively.

The fleet counts reinforce that these are not isolated losses: `MAIL-EDGE-01` has 7 responder creates and zero terminations; `DB-PROD-01` 9/2; `WEB-EXT-01` 11/1; `PROXY-01` 7/1; `MAIL-CLIN-01` 5/1; and `APP-INT-01` 12/2. Some late creates can legitimately extend beyond the capture, but many have explicit in-window close records.

### Windows process lifecycle and baseline texture

The strongest Windows tell is `taskhostw.exe`. On `DC-01`, all 31 instances are SYSTEM-owned children of the same `svchost.exe` PID 2352 and all remain live in eCAR. They are created throughout the full window, so this cannot be explained as a single cutoff at 18:00. `FILE-SRV-01` repeats the pattern with 14 unterminated children of PID 3368. Fleet-wide, 83 of 84 created task hosts lack a termination.

This differs from expected persistent services: `taskhostw.exe` is a task host, and repeated `/Run` launches should not all accumulate indefinitely. It also differs sharply from nearby short-lived telemetry that closes cleanly: `wsqmcons.exe` is 47 creates/47 terminates, `sh` and `debian-sa1` are each 88/88, and `conhost.exe` is 62/62. That selectivity makes the task-host pattern a lifecycle-model defect rather than a general capture-policy assumption.

### Correlation quality

The positive side is materially strong. The Outlook PID 7296 chain on `WS-SMARTINEZ-01` has a coherent explorer parent, user and logon context, expected modules such as `OLMAPI32.DLL` and `mso.dll`, and subsequent network/file actions attached to the same eCAR object. Across all eCAR data, I found zero known-actor dependents occurring before their visible process create or after their visible process terminate. SSH syslog and eCAR also agree on principals, PIDs, tuples, and close times even where the process termination is absent.

Thus, the verdict is not based on malformed fields or mere completeness. The dataset is realistic in individual records, while repeated lifecycle ownership gaps and a narrow fleet-wide maintenance palette provide the differentiating evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---:|---|
| `contract_gap` | Linux eCAR + syslog SSH | 45 of 52 created responder `sshd` processes lack termination; explicit closed-session examples on multiple hosts | A visible session close should retire its per-session responder process; family-wide absence is a strong lifecycle defect. |
| `contract_gap` | Windows eCAR process lifecycle | 83 of 84 `taskhostw.exe` creates lack termination; 31 on the DC and 14 on the file server | Implies implausible accumulation of short-task host processes despite rich termination telemetry for other executables. |
| `distribution_texture` | Windows process baseline | Repeated small command palette across workstations and server roles during six hours | Valid individual records become generator-like in fleet-wide frequency and limited variety. |
| `weak_signal` | Linux eCAR process fields | 1,495 of 1,495 process records have `tid == pid` | Legal individually, but uniformly lacks thread-level texture. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows, Linux, and eCAR fields are generally well formed and source-appropriate.
- **Temporal patterns:** 6 — local ordering is good, but repeated open-ended process lifecycles materially reduce realism.
- **Cross-source correlation:** 7 — process, session, and source-native identifiers align well; the missing SSH termination is the main break.
- **Behavioral realism:** 6 — user applications and admin sessions are plausible, but task-host accumulation and repeated maintenance vocabulary are conspicuous.
- **Environmental consistency:** 7 — OS and server roles are mostly coherent, though the maintenance palette is too broadly repeated across roles.

## Recommendations

- If this were synthetic, make the SSH session owner emit or coherently drop the receiver `sshd` termination whenever PAM/eCAR session close is observed; validate this across every successful in-window SSH session, not only file-transfer cases.
- Give `taskhostw.exe` launches bounded, task-appropriate lifetimes and terminate each process after its modeled work. Add a fleet-level concurrency check so repeated tasks cannot leave dozens of live task hosts on a server.
- Diversify Windows maintenance activity by host role, installed-software cohort, and schedule history. Reduce repeated bare `wsqmcons.exe` and identical updater/task-host command lines where the host role or software inventory does not support them.
- If Linux eCAR intends to represent actual thread telemetry, populate a plausible `tid` distribution for thread-attributed records; otherwise omit `tid` where only process identity is known.
