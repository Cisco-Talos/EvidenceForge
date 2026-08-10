# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 78

## Executive Summary

The telemetry is structurally excellent and most lifecycle/correlation checks behave like production data, but two repeated endpoint-to-network ownership defects are difficult to reconcile with real process behavior. In particular, unique `wget` processes advertise one command-line destination while their only visible proxy transaction targets unrelated domains, and a single Postfix `smtpd` identity is repeatedly credited with Python HTTP proxy traffic and unrelated connection attempts over nearly the whole window.

## Evidence For Synthetic

- `[contract_gap]` Thirteen separately created `/usr/bin/wget` processes on `DB-PROD-01` all have the command line `wget -q -e use_proxy=yes -O - https://internal-service/`, but each process's sole visible FLOW uses a unique source port to `10.10.3.20:8080`, where Zeek records a CONNECT for a different host. Reproducible examples are `DB-PROD-01.../ecar.json` lines 134-136 (`pid=130000`, source port `57911`) versus `zeek-dmz/http.json` line 184 (`host=packages.microsoft.com`); eCAR lines 188-190 (`pid=133503`, port `52312`) versus HTTP line 327 (`changelogs.ubuntu.com`); and eCAR lines 195-198 (`pid=133818`, port `42085`) versus HTTP line 339 (`api.snapcraft.io`). The same defect repeats at eCAR FLOW lines 345, 353, 364, 448, 459, 603, 606, 609, 630, and 661, targeting such unrelated names as `pypi.org`, `images.formstack.io`, and `js.docusync.app`. A redirect could explain one instance only if the initiating request were visible; it does not plausibly explain 13/13 fresh, one-flow process instances with this same command line and a different only-visible CONNECT host.
- `[contract_gap]` `MAIL-CLIN-01.../ecar.json` attributes 21 outbound proxy connections to one long-lived identity, `actorID=cb399949-ad06-482b-b1b8-8c4cc46d85b6`, `pid=3004901`, `/usr/lib/postfix/sbin/smtpd`, command `smtpd -n smtp -t inet -u`. Exact tuple evidence for the first is eCAR line 1 (`10.10.2.26:58228 -> 10.10.3.20:8080`), `zeek-core/http.json` line 6, and `zeek-dmz/http.json` line 6: the request is `CONNECT px.ads.linkedin.com:443` with `user_agent=python-requests/2.31.0`. The same actor produces 21 Python-requests proxy transactions over the window, including `registry.npmjs.org`, `static.parastorage.com`, `data.pagerduty.net`, `pypi.org`, and `www.amplitude.com`. Native Postfix `smtpd` does not embed Python Requests; an external content-filter/helper would have its own process identity.
- `[environment_or_collection_plausibility]` The same Postfix identity is also used as a generic network actor well outside SMTP-server behavior. For example, `MAIL-CLIN-01.../ecar.json` lines 15-28 assign that `smtpd` PID failed outbound probes to workstation/server ports 443, 8443, 8080, and 80, while later records repeatedly assign it LDAP connections to `10.10.2.10:389`. Reusing one pre-window daemon identity is not itself a defect, but using that exact source identity as the owner of unrelated proxy browsing, scanning-like failures, LDAP, and inbound SMTP throughout the window is a concrete process-ownership inconsistency.
- `[distribution_texture]` The two ownership problems are repeated families rather than isolated bad rows: all 13 inspected DB `wget` actors reproduce the same command-line/CONNECT-host mismatch, and all 21 MAIL-CLIN proxy rows with process attribution reuse the same inappropriate `smtpd` actor and Python UA. That consistency looks like role-based actor selection and command-pool reuse rather than organic endpoint telemetry.

## Evidence For Real

- Windows event envelopes and source-native metadata are strong. Across the nine Windows hosts, Security event versions/tasks/keywords match the observed IDs (for example 4624 v2/task 12544, 4688 v2/task 13312, 5156 v1/task 12810), while Sysmon uses the expected per-event versions and tasks (Event 1 v5, Event 5 v3, Event 8 v2, Event 22 v5). Event 1102 correctly uses the Eventlog provider and `UserData/LogFileCleared`; its `EventRecordID` resets to 1 and the following record starts at 2.
- Process lifecycle evidence is coherent. For all visible Sysmon Event 1/Event 5 pairs, ProcessGuid, PID, and Image agree and no same-GUID termination precedes creation. Security 4688/4689 records matched nearby Sysmon create/terminate records without image mismatch, and Sysmon `UtcTime` agreed with outer `SystemTime` within the expected millisecond rounding.
- Zeek JSON parses cleanly and has source-native field shapes. No protocol row examined fell outside its corresponding conn interval, and DNS, HTTP, SMTP, and SSL rows all had a conn UID at their own sensor. This completeness was treated as neutral, not as evidence of synthesis.
- Dual-sensor observations have plausible independent texture: the same `10.10.2.26:58228 -> 10.10.3.20:8080` transaction has UID `CjVsKZSeiSDMg6kVW03` at core and `Cmheyl9IWveVFx12Ldb` at DMZ, with approximately 45 ms sensor-clock separation rather than copied timestamps or UIDs.
- ASA lifecycle accounting is convincing: 4,877 built TCP/UDP connections, 4,875 teardowns, no teardown without a visible build, no protocol mismatch, and no duration discrepancy beyond two seconds. The two still-open connections are naturally explainable at the window boundary.
- Linux SSH evidence is ordered correctly for visible identities. Where connection, accepted-authentication, PAM open, and PAM close were all present for one `sshd` PID, their order was causal; close-only records at the beginning were not penalized because their initiators can predate the slice.
- The dataset has meaningful source-family and behavioral variation: Windows build cohorts carry internally consistent file versions/hashes, DMZ scanning is much heavier than core traffic, workstations and servers have different source mixes, and normal failures/resets/denials are present.

## Detailed Analysis

### Windows Security and Sysmon schema checks

I parsed every Windows XML record rather than relying on text search. Representative aggregate counts included 7,915 Security records on `DC-01` (601 x 4624, 536 x 4768, 1,267 x 4769, 4,498 x 5156), 757 Security records on `WS-AJOHNSON-01`, and 547/573 corresponding Sysmon records on those two hosts. Field sets were stable and source-appropriate: 4624 included the v2 outbound/linked/elevated fields; 4688 used hexadecimal process IDs and v2 target/parent/mandatory-label fields; 5156 used device-style Application paths and numeric protocol values; Sysmon Event 1 supplied the expected process, hash, parent, session, and integrity fields.

I also checked source-native values. SIDs and GUIDs were well formed, ProcessGuids were unique per visible creation, hash strings had valid SHA1/MD5/SHA256/IMPHASH shapes, and one image path never changed hash on the same host during the six-hour slice. Windows system-file versions formed coherent build cohorts (17763, 19041, 20348, and 22621) rather than changing arbitrarily per record.

The rare high-signal records were especially convincing. The Security-log clear at `2024-03-18T17:42:18.8498896Z` is provider-correct and follows visible `wevtutil.exe` activity; the record ID reset is carried through subsequent records. I found no impossible same-identity ordering in the visible slice.

### Endpoint/network ownership

This is where authenticity failed. On DB-PROD, the first mismatch is fully joinable without relying on completeness: eCAR process creation line 134 occurs at `1710767755921`, FLOW line 135 at `1710767756332` carries actorID `1c33b6a2-3c00-411a-a558-24f8d567bfee` and source port 57911, and termination line 136 occurs at `1710767772523`. The DMZ HTTP row on that exact tuple records `CONNECT packages.microsoft.com`, not `internal-service`. Each of the other twelve cases uses a new PID/object ID, has only one actor-owned FLOW, and terminates shortly afterward. This is not the normal long-lived-browser situation where a launch URL remains in the process command line while the browser contacts many dependency domains.

On MAIL-CLIN, the opposite ownership error occurs: one pre-window Postfix `smtpd` actor is used for many unrelated families. Exact source-port joins show Python Requests CONNECT traffic, while nearby records attribute failed port probes and LDAP traffic to the same PID. This would cause a SIEM rule or graph analytics engine to assert that Postfix itself browsed ad/CDN/developer sites and performed generic network probing. The source process and network facts therefore disagree even though the tuples correlate perfectly.

### Zeek, proxy, firewall, and IDS

Both Zeek trees are valid newline-delimited JSON. Core contained 6,408 conn, 2,250 DNS, 1,039 HTTP, 110 SSL, and 67 SMTP rows; DMZ contained 5,467 conn, 774 DNS, 1,232 HTTP, and 1,583 SSL rows. Conn states, histories, packet/byte accounting, and optional-field variation were plausible. S0 connections had no response packets/bytes, successful protocol records remained inside connection intervals, and sensor-specific UIDs were not incorrectly expected to match across observation points.

The proxy access rows agree with Zeek method, host, status, UA, and byte-scope semantics on sampled tuples. That agreement strengthens, rather than excuses, the ownership findings: the HTTP fact is consistent across network sources; only the endpoint actor/command context is wrong. ASA records were likewise internally paired and temporally consistent. IDS alerts used plausible Snort fast-alert structure and did not supply an independent schema defect.

### Linux telemetry and temporal behavior

RFC5424 syslog rows parsed cleanly, were time ordered, and used plausible facilities/severities for SSH, PAM, cron, system services, mail, and kernel firewall events. SSH child-PID sequences had valid visible ordering. Bash history used epoch markers and contained role-aware commands, with concurrent-shell-style irregularity rather than rigidly sorted narratives. These sources materially lowered the synthetic-confidence score from the top rubric band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---|---|
| `contract_gap` | eCAR + Zeek HTTP/proxy | 13 fresh DB-PROD wget processes | The command says `https://internal-service/`, but the only visible request for each exact actor/tuple CONNECTs to one of 13 unrelated hosts. |
| `contract_gap` | eCAR + Zeek HTTP/proxy | 21 MAIL-CLIN proxy transactions | One Postfix `smtpd` PID is the endpoint owner of Python-requests HTTP traffic on exact source-port joins. |
| `environment_or_collection_plausibility` | eCAR network activity | Dataset-wide lifetime of the MAIL-CLIN Postfix actor | The same daemon identity also owns unrelated port probes, LDAP, inbound SMTP, and browsing-like proxy traffic. |
| `distribution_texture` | Endpoint process attribution | Two repeated behavior families | The defects repeat uniformly (13/13 wget actors and 21/21 attributed MAIL-CLIN proxy rows), consistent with deterministic actor/command reuse. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows, Sysmon, Zeek, ASA, RFC5424, proxy, and IDS records are parseable and largely source-native.
- **Temporal patterns:** 9/10 — Visible lifecycles and protocol intervals are causal; boundary-only missing initiators were not penalized.
- **Cross-source correlation:** 7/10 — Tuples and protocol facts correlate very well, but endpoint process ownership and command context conflict with those exact transactions.
- **Behavioral realism:** 6/10 — Most user/server activity is credible, but the Postfix and one-flow wget behavior families are not.
- **Environmental consistency:** 7/10 — Roles, build cohorts, collection profiles, and traffic placement are coherent aside from repeated service/process-role misattribution.

## Recommendations

- If this were synthetic, derive proxy transaction actor identity from the actual client process that owns the source socket. Never select a generic long-lived role process such as Postfix `smtpd` merely because it is available on the host.
- Bind short-lived command-line tools to their requested host. For each `wget` process, the command URL, proxy CONNECT host, DNS prerequisite, and subsequent TLS hostname should reflect the same request chain; if modeling a redirect, emit the initiating request and redirect response before the new-host connection.
- Add a validation contract that joins endpoint FLOW to Zeek HTTP by source/destination tuple and checks process-family invariants: Python Requests should have a Python-capable actor, Wget requests should agree with the per-process command URL or a visible redirect chain, and Postfix daemons should be limited to mail/auth/directory behavior unless an explicit helper or compromise is modeled.
- Add distribution tests that flag one process UUID accumulating semantically unrelated network families over an implausibly long window, especially listener daemons that become the owner of arbitrary failed probes and web destinations.
