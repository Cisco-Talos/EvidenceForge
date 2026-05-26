# Host/EDR Forensics Analyst - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 66

## Executive Summary

This dataset is unusually strong from an endpoint-forensics perspective: Windows Security/Sysmon/eCAR correlations are source-native, Linux SSH/session ordering is plausible, and I found no hard process-lifecycle or visible causality contradictions. I judge it synthetic mainly because the human/admin behavior has template-pool fingerprints: repeated exact command vocabularies, internal naming drift, and a very clean attack storyline.

## Evidence For Synthetic

- Linux/eCAR command activity repeats exact command strings across hosts and users, including `kubectl get nodes -o wide`, `kubectl logs web-frontend-8c9a1 --tail=100`, and repeated `curl -X GET https://wiki.corp.local/display/ENG/Architecture -H 'Accept: application/json'`.
- Endpoint command artifacts reference `corp.local`, `db-srv-01`, and `app-srv-02`, while the surrounding AD/host evidence consistently uses `meridianhcs.local`, `DB-PROD-01`, and `APP-INT-01`. Sanitization could explain this, but internally it feels like mixed vocabulary sources.
- The DC attack chain is highly coherent and narratively compact: `PSEXESVC.exe` service execution, `net user svc_mhsync ... /add /domain`, Domain Admins membership, scheduled task creation, `wevtutil` clearing, and cleanup all occur with little incidental mess.
- Bash histories contain plausible typo/noise commands, but the mistakes feel deliberately sprinkled rather than organically tied to individual user habits.
- eCAR records are very normalized: tidy object/action taxonomy, consistent millisecond timing, UUID-style object IDs, and clean process/flow relationships. This is not a contradiction, but it reinforces the curated feel when combined with repeated command pools.

## Evidence For Real

- Sysmon Event 22 DNS behavior is accurate: for example, `WS-MCHEN-01` shows DNS attributed to `C:\Windows\System32\svchost.exe` as `NT AUTHORITY\LOCAL SERVICE`, matching Windows DNS Client behavior.
- Windows process trees are plausible. `WS-MCHEN-01` shows `explorer.exe` launching `mstsc.exe /v:FILE-SRV-01`, with matching Security, Sysmon, and eCAR records around `2024-03-18T12:00:16Z`.
- Linux SSH evidence has realistic ordering: connection, accepted public key, PAM session open, then `systemd-logind` new session. I did not find visible close-before-open contradictions.
- DC account-management evidence is internally consistent: `net.exe` process creation is followed by Security 4720 account creation, 4728 group membership change, and later 4726 deletion.
- The security log clear sequence is realistic: Security 1102 occurs around `2024-03-18T17:41:49Z` and subsequent EventRecordID values reset.

## Detailed Analysis

Endpoint source formatting is one of the dataset's strongest areas. Windows Security XML fields look source-native, including failed logons with `SubjectUserName` as `-`, `SubjectLogonId` as `0x0`, appropriate `winlogon.exe` or `lsass.exe` process names, and IPv4-mapped remote addresses such as `::ffff:10.10.3.20`.

Process lifecycle behavior also holds up well. I checked for visible Sysmon/eCAR cases where child processes or dependent network/module/registry actions occurred before their process creation, or after visible process termination, and did not find hard contradictions. Parent-child relationships such as `explorer.exe` to `mstsc.exe`, `services.exe` to `PSEXESVC.exe`, and `PSEXESVC.exe` to `net.exe` are believable.

The DC compromise sequence is forensically convincing at the field level. Around `2024-03-18T16:14Z`, Security 4688 records show `net user svc_mhsync MhsSvc!2024 /add /domain` and `net group "Domain Admins" svc_mhsync /add /domain`, followed by 4720 and 4728 account-management events. The same storyline later includes scheduled task creation and security-log clearing, which is coherent.

Linux host evidence is also fairly strong. `DB-PROD-01` shows SSH connection and session lifecycle messages in believable order, and the root bash history lines for `mysqldump`, `gzip`, and `scp` correlate with eCAR process and flow telemetry. The outbound SCP to `10.10.2.30:22` also has matching Zeek connection evidence.

The main weakness is behavioral realism. The repeated exact administrative commands across users and hosts feel less like an organic environment and more like sampled activity templates. In particular, the recurring `kubectl`, `curl` to internal wiki/Jira/Grafana-style URLs, and `ldapsearch` command forms appear across systems with limited user-specific variation.

## Realism Score by Category

- **Field format accuracy:** 8 - Windows Security, Sysmon, syslog, Zeek, and eCAR fields are mostly source-native and internally plausible.
- **Temporal patterns:** 8 - Session and process ordering is realistic, with no hard visible lifecycle contradictions found.
- **Cross-source correlation:** 9 - Security/Sysmon/eCAR/Zeek correlations are strong and concrete.
- **Behavioral realism:** 6 - Human/admin command activity has repeated template-like vocabulary and limited individuality.
- **Environmental consistency:** 7 - Host/domain evidence is mostly coherent, but `corp.local`/generic hostnames drift from the main environment naming.

## Recommendations

- **P1:** Reduce repeated exact command strings across Linux hosts and users; vary flags, targets, working directories, typos, and user-specific habits.
- **P2:** Harmonize internal naming artifacts or add corroborating evidence for aliases like `corp.local`, `db-srv-01`, and `app-srv-02`.
- **P2:** Add more incidental operator behavior around the DC compromise, such as failed attempts, discovery commands, pauses, or benign concurrent admin noise.
- **P3:** Make bash-history mistakes less evenly distributed and more tied to individual typing patterns.
- **P4:** Add a little more source-local messiness in eCAR while preserving the strong canonical correlations.
