# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 43

## Executive Summary

The collection is operationally convincing: remote credential boundaries, SSH transport/authentication, file staging and inspected proxy uploads generally support feasible investigative pivots. A small, unusually regular sequence of shell-driven document accesses on one Mac raises a concrete workload-texture concern, but I did not establish an impossible lifecycle or cross-source contradiction in the checks performed. This looks mostly realistic, with insufficient evidence to confidently distinguish production telemetry from a careful simulation.

## Evidence For Synthetic

- [distribution_texture] On `MAC-MROSS-01.meridianhcs.local/ecar.json`, six shell-driven accesses to different mounted-share documents occur at lines 108, 149, 178, 277, 328 and 344: 14:17:19.344, 14:43:41.191, 15:10:35.095, 15:37:59.214, 16:03:32.245 and 16:30:19.058 UTC. Consecutive intervals are 1,581.847, 1,613.904, 1,644.119, 1,533.031 and 1,606.813 seconds: mean 1,595.943, population standard deviation 37.198 seconds, coefficient of variation 2.3%. The paths and operations change, yet the cadence remains close to one access every 26.6 minutes. This resembles a jittered workload schedule more than ordinary document handling. A real scheduled script remains a plausible explanation; six observations are a limited sample.
- [weak_signal] The same sequence uses `/bin/cat` for an XLSX and two PDFs, and `/usr/bin/tee` for a PPTX and XLSX. Examples are line 149 (`/Volumes/Users/Documents/contacts.xlsx`), line 178 (`.../action-items-review.pdf`) and line 328 (`.../team-roadmap.xlsx`). `MAC-MROSS-02.../ecar.json` also has `/bin/cat .../status-update-review.pdf` at line 452 and `/bin/cat .../schedule.xlsx` at line 608. These commands can validly read or write binary files, so their existence is not an impossibility. Their repeated use for office documents, together with the first host's cadence, makes the file-workload texture less natural. I treat this as part of the same concern, not independent evidence that doubles its weight.

## Evidence For Real

- The `runas /netonly` sequence distinguishes the local process principal from outbound credentials correctly. `WS-AJOHNSON-01.../windows_event_security.xml`, EventRecordIDs 131011–131013, records explicit use of `marcus.chen`, a Type 9 logon locally owned by `aisha.johnson`, `TargetOutboundUserName=marcus.chen`, and the new command shell under LogonId `0x27c9452`. On `FILE-SRV-01`, EventRecordIDs 273610–273629 attribute the ensuing Finance share accesses to `marcus.chen` from `::ffff:10.10.1.35:54138`. This is a substantive identity-boundary detail, not merely a matching timestamp.
- SSH transport, auth and shell ordering is sensible for the database pivot. `zeek-db/conn.json:380` opens `10.10.2.30:46416 -> 10.10.4.10:22` at 18:14:57.412857, followed by `DB-PROD-01.../syslog.log:162–164` connection notice at 18:15:01.323891, accepted password at 18:15:11.273178 and PAM session open at 18:15:11.345223. The shell and commands follow in endpoint telemetry.
- Explicit proxy behavior is modeled as two network legs rather than a fictitious direct workstation connection. `zeek-core/http.json:2066` shows the workstation CONNECT; `PROXY-01.../proxy_access.log:3387–3388` distinguishes tunnel setup from the inspected POST with the same tunnel identifier; `zeek-dmz/conn.json:8487` carries the proxy's external upload leg.
- Background network data includes heterogeneous outcomes and observation artifacts. Among 6,773 TCP rows in `zeek-core/conn.json`, there are 4,968 SF, 1,440 S0, 166 RSTO, 98 RSTR, 36 OTH and smaller other-state populations. For example, line 82 includes `missed_bytes=49` and history `ShADadfFGg`. I do not see an all-success or entirely identical connection texture.

## Detailed Analysis

### Orientation and collection scope

The records cover approximately 13:00–19:00 UTC on 2 November 2026. There are endpoint records for 24 named hosts, including Windows workstations and domain controllers, Linux application/database/mail/proxy systems, and two Macs. The visible internal addressing includes workstation, server, DMZ and database ranges under `10.10.1.*` through `10.10.4.*`; this is a topology inference from names and observed paths, not a claim about subnet masks.

The collection contains 35,813 normalized eCAR rows, 18,978 Windows Security events across ten hosts, Linux syslog and shell histories, Mac Endpoint Security and Unified Log exports, Zeek protocol families, perimeter firewall, IDS, proxy and web access data. Zeek has 12,279 core, 9,287 DMZ and 464 database connection rows. Those sensor counts include overlapping observations and should not be summed as unique physical connections. XML line counts likewise are not event counts.

### Hunt and pivot feasibility

On the public web server, `WEB-EXT-01.../ecar.json:811` records Apache spawning a base64-decoding bash command as `www-data` at 14:20:06.215. Its decoded payload is an interactive bash TCP redirection to `45.33.32.30:8443`. `zeek-dmz/conn.json:1743` shows `10.10.3.10:54918` reaching that destination at 14:20:09.625084. The process ends at 14:20:21.163 (`ecar.json:814`), after the short visible transport interval. This supports suspicious command execution and outbound transport. It does not establish that this particular short connection remained an interactive command channel for later hours.

The later Windows collection workflow is investigable without conflating principals. The workstation command shell under the new Type 9 session creates staging directories and launches the copy commands (`WS-AJOHNSON-01.../ecar.json:1032–1110`). Five Finance files appear in `zeek-core/smb_files.json:158–167`, with read sizes from 284,672 to 4,928,307 bytes; three research files appear at lines 169–174. The remote server Security subject is the outbound credential principal, while the local command owner remains Aisha. This distinction materially strengthens the operational realism.

The upload then uses `curl.exe --proxy http://10.10.3.20:8080 -F ...` (`WS-AJOHNSON-01.../ecar.json:1199`). Proxy lines 3387–3388 record `client_src_port=62702`, the CONNECT authority, the HTTPS POST URL and approximately 18.8 MB outbound. The exterior Zeek connection originates from the proxy, `10.10.3.20:50391`, rather than the workstation. Differing byte counts between CONNECT control traffic, inspected HTTP and encrypted external traffic are expected at these layers; I did not treat them as a mismatch.

### Linux dump and transfer lifecycle

`DB-PROD-01.../ecar.json:493–507` shows remote root login, shell creation, `mysqldump`, output creation, gzip, compressed output creation and scp in that order. The scp process starts at 18:15:57.555 and its outbound FLOW is at 18:16:01.199. The receiving application's syslog records the matching source tuple `10.10.4.10:53008`, accepted public key and PAM session opening at `APP-INT-01.../syslog.log:219–221`.

The receiver creates `/tmp/.cache/rpt_0318.sql.gz` at `APP-INT-01.../ecar.json:761`, after authentication. Its subsequent `smbclient` process reads that staged object at lines 774–776, and `zeek-core/smb_files.json:187–188` records a 10,464-byte write into `ClinicalResearch/Integration/DB-Staging`. These are usable investigative pivots. The small compressed dump size alone does not establish fabrication; the logs do not disclose database cardinality.

### Baseline ambiguity and visible lifecycle checks

The Linux support upload is a useful competing explanation for a large outbound transfer: `WS-LNGUYEN-01.../ecar.json:313,317` shows a tar of two named connector logs followed by a multipart support attachment request with ticket `MHS-48217`. `zeek-core/http.json:1264` records the matching URI, `curl/7.81.0`, gzip filename, JSON/gzip parts and a 1,573,258-byte request. It resembles an operational support workflow; no external allowlist was supplied to prove it benign.

I checked visible normalized process creations against their recorded actor creation/termination and separately checked native Sysmon ProcessGuid create/terminate ordering, including parent GUID references. I found no same-identity before-create or after-termination defect in those checks. I also compared endpoint FLOW times to SSH/RDP login times and checked associated visible transport closes against endpoint process termination; those checks did not produce a material inversion. These results do not certify every source or every lifecycle, but they constrain the authenticity verdict.

The Mac concern is specifically the cadence and choice of file operations cited above. I did not interpret a network observation as native Mac telemetry, assume a missing ES event was an authorization denial, or require additional Unified Log categories. The second Mac's five analogous file-access intervals are much more variable, which limits the scope of the regularity finding to the first host.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Mac normalized process telemetry | Six mounted-document commands on MAC-MROSS-01, 14:17–16:30 UTC | Five intervals cluster around 26.6 minutes with 2.3% CV despite changing paths and operations; moderate concern, plausible automation alternative. |
| weak_signal | Mac normalized process telemetry | Both Macs' visible mounted-share file commands | Repeated cat/tee handling of PDF/Office files makes the cadence concern more suggestive; no demonstrated command impossibility and no separate large penalty. |

No hard contradiction, demonstrated schema failure or verified cross-source contract gap was established in this review. Missing out-of-window initiators/closures, selected Sysmon coverage, sanitized domains, and completeness of matching evidence did not increase the score.

## Realism Score by Category

- **Field format accuracy:** 9 — Inspected source fields and identifiers are usable; nested task XML parses, and no demonstrated native schema defect was found.
- **Temporal patterns:** 8 — Transport/auth/process relationships hold in tested paths; one small Mac file-workload sequence has unusually regular spacing.
- **Cross-source correlation:** 9 — Proxy legs, remote credential identity and SSH/file staging support technically coherent pivots.
- **Behavioral realism:** 7 — Commands and credential boundaries largely make sense; repeated shell-driven binary-document accesses weaken baseline texture.
- **Environmental consistency:** 9 — Roles and observed network paths generally agree; source absence alone is neutral.

## Recommendations

- If this were synthetic, make the mounted-share document workload on MAC-MROSS-01 reflect either explicit scheduled automation or clustered human work. The current changing file paths and operations combined with five near-equal intervals create ambiguity that could be avoided with a better behavioral model.
- If these are intended to represent interactive office-document use, model the actual application access path where collected rather than repeatedly representing PDF/XLSX/PPTX activity through cat and tee. Retain such shell operations when the intended behavior is a real script, binary inspection or command-driven transfer; those commands are technically valid.
- Preserve the existing separation between local and outbound identities, source-side and proxy-side transport, and SSH authentication/session phases. These details are already strong and should survive changes to baseline texture.
