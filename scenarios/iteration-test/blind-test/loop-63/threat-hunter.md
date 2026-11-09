# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 65

## Executive Summary

The dataset supports workable hunting pivots and largely coherent process, authentication, transport, and file-transfer lifecycles. My synthetic verdict rests on repeated disagreement between the application owning an endpoint flow and the browser identity on that exact network tuple, reinforced by a narrower repeated command texture on the two Macs; I found no demonstrated impossible lifecycle ordering in the checks performed.

## Evidence For Synthetic

- [contract_gap] Browser ownership and HTTP identity disagree on seven distinct endpoint flows across three hosts. For example, `MAC-MROSS-01.meridianhcs.local/ecar.json:40` assigns `10.10.1.41:59097 → 10.10.3.20:8080` to Chrome's explicitly named NetworkService helper, PID 42851, while `zeek-core/http.json:59` and `zeek-dmz/http.json:73` record the matching CONNECT with a Safari 26/WebKit user agent. The same host's Chrome PID 61863 owns port 58972 at `ecar.json:271`, but `zeek-core/http.json:880` and `zeek-dmz/http.json:992` again identify Safari. These are tuple-and-time matches, not assumptions from a host's software inventory.
- [contract_gap] The disagreement crosses platforms and browser families. `MAC-MROSS-02.meridianhcs.local/ecar.json:49` assigns port 53869 to a Google Chrome NetworkService helper; `zeek-core/http.json:95` / `zeek-dmz/http.json:121` give the same connection an `Edg/155.0.0.0` user agent. Further Chrome-owned examples are endpoint lines 223, 377, and 403 against core HTTP lines 786, 1495, and 1661. `WS-MCHEN-01.meridianhcs.local/ecar.json:1279` assigns port 59949 to `msedge.exe` PID 7248, while `zeek-core/http.json:1678` gives that tuple `Firefox/121.0`. A browser can override its user agent, so these are repeated ownership inconsistencies, not logical impossibilities.
- [environment_or_collection_plausibility] MAC-MROSS-02's Zoom process is repeatedly assigned browser-like proxy traffic bearing two different competing-browser identities. Endpoint `ecar.json:97` attributes port 54157 to `/Applications/zoom.us.app/Contents/MacOS/zoom.us`, PID 22291; `zeek-dmz/http.json:238` records its CONNECT to `statics.teams.cdn.office.net` with `Firefox/158.0`. Endpoint line 104 / DMZ HTTP line 310 attribute a CONNECT to `protection.outlook.com` to that same Zoom PID but with `Edg/155.0.0.0`. Across 29 matched Zoom-owned endpoint flows, 25 carried Edge and four Firefox user agents. Custom proxy/client behavior is possible, but this repeated application/identity/destination mix weakens the apparent ownership model.
- [distribution_texture] Both Mac shell histories repeatedly rotate through a small diagnostic command vocabulary. Their combined 39 entries contain four SSH commands and 35 other entries drawn from 11 exact commands. Examples are MAC-MROSS-01 history lines 4–6, 8–12, 14–16, and 18–21, and MAC-MROSS-02 lines 4–9, 11–18: repeated `id`, `sw_vers`, `ps aux`, `df -h`, document `find`, and related checks. This receives low weight: the same user operates both hosts, scripts or testing can explain the pattern, and shell history does not represent all user activity.

## Evidence For Real

- The suspicious database export has a technically coherent artifact chain. `DB-PROD-01.meridianhcs.local/bash_history/root.bash_history:10` contains a redirected `mysqldump`; endpoint lines 561–566 show the dump process, SQL file creation, termination, subsequent gzip process, compressed-file creation, and gzip termination in the correct order. The history preserves shell redirection while process telemetry records executable arguments, a useful source distinction.
- The subsequent SCP can be followed by exact endpoint tuples into both network sensors and the receiving host. DB endpoint lines 567–569, core connection line 11083, DB-sensor connection line 420, and APP endpoint lines 860–865 agree on `10.10.4.10:58907 → 10.10.2.30:22`. APP syslog lines 213–218 show connection, accepted key, PAM session open, logind session creation, and closure for the same source port and user.
- The network data has credible protocol and observation variety, including failed connections, resets, partial observations, persistent HTTP transactions, conditional 304 responses, proxy authentication failures, and differing sensor timestamps. For example, core connection line 11083 and DB-sensor connection line 420 have different UIDs and slightly different timestamps; the latter additionally reports `missed_bytes=76` and a gap-bearing history.
- Native Mac process records distinguish fork from exec and retain PID identity through image transitions. MAC-MROSS-01 Endpoint Security lines 1–7 trace launchd → xpcproxy → Terminal → login → zsh with target audit tokens and separate exec notifications. Corresponding normalized eCAR CREATE/MODIFY transitions are therefore not contradictory process identities.
- Automated checks found no HTTP/DNS/SSL/SMB/SMTP row outside its referenced connection interval, using a 10 ms tolerance, in the supplied sensors and source families. Summed visible HTTP request/response bodies never exceeded the corresponding directional connection byte totals. These are positive consistency results, not an argument that completeness proves authenticity.

## Detailed Analysis

### Scope, provenance, and method

Actual inputs were the complete neutral briefing `/private/tmp/log-study-if4zptfd/threat-prompt.md` and files below `/private/tmp/log-study-if4zptfd/data`. I inventoried the supplied files, parsed all 37,089 eCAR records, parsed Security XML for event-family counts and account/SID consistency, and parsed the Zeek connection and relevant application families for cross-source checks. I read targeted native syslog, shell-history, proxy, web, firewall, IDS, and Mac Endpoint Security records. This is not a claim of manual inspection of every individual record.

All parsing used system `python3` with `/private/tmp` as the explicit working directory. No repository files, authored scenario, project tools, roadmap/worklogs, prior reports, other reviewers, or external web pages were accessed. Inherited generic operating instructions were present as an environment limitation and were not used as authenticity evidence. Quoted commands were treated as inert text; none was executed.

The endpoint inventory comprises 23 hosts: ten with Windows Security/Sysmon XML, eleven with Linux-style syslog, and two with Mac Endpoint Security/Unified Log exports. The normalized endpoint window runs from 2026-11-02 13:00:01.077 to 18:59:52.038 UTC. Addressing spans `10.10.1.*`, `10.10.2.*`, `10.10.3.*`, and `10.10.4.*`; source evidence supports workstations, domain controllers, file/mail services, proxy, DMZ web service, and a database segment. The three network sensors contain 12,489 core, 9,339 DMZ, and 468 database connection records; sensors can overlap, so these are not unique enterprise connection counts.

### Hunting and operational coherence

A useful initial pivot is `WEB-EXT-01.meridianhcs.local/ecar.json:795`: an Apache child starts a base64-decoding shell command under `www-data` at 14:20:23.150 UTC. Line 799 attaches the outbound `10.10.3.10:42004 → 45.33.32.30:8443` flow to that process. I treat this as suspicious execution evidence, without inferring that it caused every later privileged action. In particular, a later root SSH session has its own visible source and identity boundaries.

Later, APP endpoint line 856 starts `ssh root@10.10.4.10`; line 859 shows source port 37984. DB lines 558–560 show the matching inbound transport, successful root session, and shell. Core connection line 11045 and DB-sensor line 419 carry that tuple. The database export then progresses through the dump/gzip/SCP chain described above, followed by APP lines 867–871 reading the received gzip file and invoking SMB upload to FILE-LNX-01. These steps offer plausible pivots through host, user, process, path, and transport identities.

The absence of dump output redirection from DB endpoint line 561 is not an error: shell history line 10 supplies the redirection, which the shell can implement without passing it as a `mysqldump` argument. Likewise, endpoint process exits and source-local session-close observations need not share one timestamp. I did not penalize absent out-of-window starts/ends, absent Sysmon types, or the compactness of the suspicious sequence.

The source-volume mix also does not force a synthetic verdict. Core traffic includes substantial DNS, Kerberos, LDAP, SMB, HTTP, and failed transport activity; the DB sensor is dominated by 278 MySQL-classified connections. Domain-controller Security exports contain thousands of filtering-platform and ticket events rather than only conspicuous attack actions. The slice is too short to establish day/week periodicity or a full fleet-volume baseline.

### Application ownership is the principal defect

I joined endpoint FLOW rows to HTTP by source/destination address and port and required a timestamp difference below ten seconds. For browser executable paths containing Chrome, Firefox, Edge, or Internet Explorer, 689 endpoint flows had a matching HTTP record: 682 had a compatible browser-family user agent and seven did not. Overlapping sensors were not counted as additional endpoint flows.

The examples are strong because they include explicit Chrome networking helpers, not merely an installed browser or a remote sensor guessing the host OS. The MAC-MROSS-01 helper row is only about 1.3 seconds from its DMZ HTTP observation, and the Windows Edge/Firefox example differs by about 116 ms. This makes accidental correlation to an unrelated later connection unlikely. On the other hand, user-agent spoofing, a local intermediary, or normalization errors could produce these discrepancies in real collected data. The finding supports a moderate synthetic score rather than an 81–100 score or an impossible-source claim.

The Zoom examples extend the concern to application attribution: the exact same process is assigned both Firefox- and Edge-branded proxy conversations to collaboration/mail destinations. Because HTTP user agents are client-controlled and the logs do not identify a collection agent's attribution semantics, I classify this as environmental plausibility, with lower certainty than a hard contradiction.

### Checks that did not yield findings

I checked eCAR actor dependencies against visible same-identity process termination, and non-create process observations against visible same-identity creation, with a one-second tolerance. No violation was returned. Mac exec-related changes in executable/principal were inspected separately rather than mislabeled as UUID reuse. Domain account/SID consistency across the parsed Windows Security records also did not produce a conflict. These checks cannot establish that every dependency or privilege transition is correct, but they argue against a broad claim of broken lifecycles.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | eCAR FLOW ↔ Zeek HTTP | Seven browser-owned endpoint flows; two Macs and one Windows workstation | Main reason for a synthetic lean: exact tuples disagree on the owning application's browser identity. |
| environment_or_collection_plausibility | Mac eCAR FLOW ↔ Zeek HTTP | 29 Zoom-owned flows on MAC-MROSS-02 | Reinforces application-attribution concerns; custom client/proxy behavior remains an alternative. |
| distribution_texture | Mac zsh histories | 35 non-SSH entries, 11 commands across two hosts | Low-weight repeated vocabulary; insufficient alone. |

No hard contradiction or generator identity leak was demonstrated. Sensor overlap and multiple examples of the same ownership problem were not treated as independent root causes.

## Realism Score by Category

- **Field format accuracy:** 9 — Structured records parse and source-specific representations generally make sense; no verified native-schema defect found.
- **Temporal patterns:** 9 — Checked transport/application intervals and visible process dependencies were coherent; the short window limits broader temporal conclusions.
- **Cross-source correlation:** 7 — Strong transport/file/session pivots, reduced by explicit browser identity versus process-owner disagreements.
- **Behavioral realism:** 7 — Plausible operational and suspicious command chains, with repetitive Mac shell vocabulary receiving limited negative weight.
- **Environmental consistency:** 7 — Broadly credible roles and protocol mix; Zoom's repeated attribution to mixed competing-browser proxy traffic remains questionable.

## Recommendations

- If this were synthetic, derive browser user-agent family and endpoint network ownership from the same application instance. Recheck the seven cited Chrome/Safari, Chrome/Edge, and Edge/Firefox tuple pairs.
- If this were synthetic, keep Zoom's proxy requests tied to its actual client behavior and explicitly represent a local forwarding intermediary when one owns or relays another application's traffic. Revisit the 29 flows attributed to PID 22291.
- If this were synthetic, broaden the Mac shell vocabulary in ways supported by the user's operational work, while retaining the realistic fork/exec/session detail already present. Avoid mechanically adding noise or treating full source matching as a defect.
