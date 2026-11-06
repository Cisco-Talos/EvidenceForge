# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 38

## Executive Summary

The logs describe a broad mixed Windows, Linux, and macOS environment over roughly six hours on 2026-11-02, with endpoint, network, web, and firewall evidence. Several high-risk actions are visible, including an Apache-child reverse shell and Windows service/task persistence, and their principal endpoint/network pivots align well. I found no decisive source-native contradiction; the main synthetic tell is a small timestamp-batching artifact in one macOS shell history, so the data is mostly realistic but its origin is not identifiable with confidence from these records alone.

## Evidence For Synthetic

- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/zsh_history/maya.ross.zsh_history` records three separate commands (`find ... '*.pdf'`, `ps aux`, and `pwd`) at the identical second `1793644147` (2026-11-02 18:29:07 UTC). Second-resolution shell history can collide, but three distinct commands sharing one second is a weak indication of batched or rounded event times.
- [weak_signal] Maya Ross's two Mac histories repeat a similar inventory sequence (`sw_vers`, `uname`, `pwd`, document listing/size, process and disk checks) across both machines. This is plausible user behavior and not independently diagnostic, but contributes some repeated texture when considered alongside the timestamp collision.

## Evidence For Real

- `WEB-EXT-01.meridianhcs.local/ecar.json:833,835` shows a `www-data` Bash process launched by `/usr/sbin/apache2` at 2026-11-02 14:19:56 UTC, followed by an outbound TCP flow from `10.10.3.10:53317` to `45.33.32.30:8443` at 14:20:00. The encoded command decodes to a Bash TCP reverse shell. This is also consistent with the web request at `WEB-EXT-01.meridianhcs.local/web_access.log:460` (14:19:57 UTC, `POST /ehr/admin/upload.php`, HTTP 200) and the firewall connection build/teardown at `fw-perimeter/cisco_asa.log:3310,3312` (14:20:00–14:20:13, same tuple, 2,929 bytes). `zeek-dmz/conn.json:1493` independently records the same tuple, an established `SF` connection lasting 12.88 seconds with traffic in both directions. These source-native pivots agree on the observed activity.
- `DC-01.meridianhcs.local/ecar.json:3806,3810,3820,3826` records `sc.exe create DeviceSyncSvc` and an hourly SYSTEM scheduled task at 17:19:38–17:19:41 UTC. The service image starts under `services.exe` at 17:29:17 (`ecar.json:3970`). The Windows event exports contain corresponding `DeviceSyncSvc` process, service, and task evidence (`windows_event_sysmon.xml:119692,119782`; `windows_event_security.xml:192213,192397,192479`). The chronology is operationally plausible and the process lineage is coherent.
- `DC-02.meridianhcs.local/ecar.json:3308–3316` records `DirectoryCacheSvc` installation and execution at 17:25:33–17:25:40 UTC. Later, at 18:51:35–18:51:38, `marcus.chen` stops and deletes it (`ecar.json:4654,4660,4672,4680`), with matching command evidence in `windows_event_sysmon.xml:143274–143420` and `windows_event_security.xml:238761–238890`. The service lifecycle is visible across separate records rather than being inferred from a single command.
- The environment has substantial routine activity and varied sources: Windows Security/Sysmon and eCAR, Linux syslog and histories, macOS Unified Log/Endpoint Security, Zeek at core/DB/DMZ vantage points, proxy/web logs, Snort, and ASA. Web and perimeter records include ordinary browsing/service traffic, routine blocked probes, and unrelated traffic around the high-signal events; the dataset does not consist solely of attack events.
- macOS evidence distinguishes endpoint process/session observations from shell history and Unified Log output. For example, the Endpoint Security export on `MAC-MROSS-02` identifies version 11 records with audit tokens, PID versions, executable identity, and `exec`/`exit` observations. I did not treat these notifications as authorization decisions or infer effects from a prompt.

## Detailed Analysis

### Scope and collection window

The visible data includes Windows domain controllers and workstations, Linux servers and workstations, two Mac hosts, and perimeter/core/DMZ/DB network sources. eCAR spans approximately 2026-11-02 13:00–19:00 UTC on many hosts. The main server and workstation event streams contain extensive routine activity as well as a few notable events. Source coverage is broad, but I have not treated completeness by itself as a synthetic indicator.

### Web server foothold and network pivot

At 14:19:57 UTC, the web access log records an external POST to `/ehr/admin/upload.php` returning 200. Three seconds earlier, the web host's eCAR records a Bash command whose parent is Apache; four seconds later it observes a TCP connection to `45.33.32.30:8443`. The firewall and Zeek records corroborate the internal source, ephemeral source port, destination, port, and successful bidirectional exchange. Zeek reports `SF`, 620 originator bytes and 1,840 responder bytes, with 4/5 packets. This is a technically coherent compromise signal and a workable cross-source pivot. The firewall and Zeek confirmation are positive realism evidence, not a synthetic tell.

### Windows persistence and cleanup

On `DC-01`, SYSTEM-context WMI provider children invoke service creation and scheduled-task creation for `DeviceSyncSvc`/`DeviceSync`; the image subsequently runs as a `services.exe` child. On `DC-02`, `DirectoryCacheSvc` is created and launched, then later stopped and deleted by commands attributed to `marcus.chen` through `WmiPrvSE.exe`. Sysmon and Security exports carry the corresponding process and service records. Those observations establish suspicious persistence and removal activity, but I do not treat a coherent, narratable attack sequence as synthetic evidence in itself.

### Mac activity and timing

The two Mac histories show repeated local inventory commands and SSH pivots to other visible hosts. Their timestamps fall within the wider collection window. One `MAC-MROSS-02` history line gives the same Unix-second timestamp to three separate commands at 18:29:07 UTC. This is possible with second-resolution shell history but is a weak timing-texture concern. I saw no demonstrated impossible process, session, or endpoint-security relationship in the sampled Mac records.

### Overall huntability

The high-risk activity is discoverable through several independent pivots: HTTP request → Apache child → endpoint flow → Zeek and firewall; and service/task creation → service execution → later removal. Routine endpoint and network traffic supplies background context. This supports realistic pivot feasibility. The timestamps are often precise and correlated across sources, but the briefing explicitly treats complete matching as neutral unless a concrete contradiction exists, and I found none in these pivots.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS zsh history | One host, one second | Three distinct commands share the timestamp 2026-11-02 18:29:07 UTC; weak evidence of rounded or batched timestamps. |
| `weak_signal` | macOS zsh histories | Two hosts, same user | Similar inventory command patterns repeat across hosts; plausible routine behavior, so this has little weight. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled eCAR, Zeek, ASA, Windows and macOS records use plausible source-specific fields and values.
- **Temporal patterns:** 7 — The principal web-shell and Windows service lifecycles progress coherently; one shell-history timestamp collision is a minor blemish.
- **Cross-source correlation:** 9 — The web foothold's process, connection tuple, firewall, and Zeek evidence align; Windows service activity is also present across endpoint and event exports.
- **Behavioral realism:** 7 — Both ordinary administrative activity and suspicious actions appear; histories have some repeated inventory behavior but remain plausible.
- **Environmental consistency:** 8 — The visible host roles and network segments support the observed web, domain-controller, Linux, Mac, and perimeter evidence.

## Recommendations

- If this were synthetic, retain sub-second or naturally varying command timestamps in shell-history exports where the source supports them; avoid assigning one identical second to several sequential commands unless it reflects the actual history timestamp resolution.
- If this were synthetic, vary routine inventory commands across user sessions and hosts where justified by the modeled users, while preserving the observed SSH and service workflows.
