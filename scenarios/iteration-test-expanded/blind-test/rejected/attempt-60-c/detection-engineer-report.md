# Detection Engineer - Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 58
**Synthetic-Confidence Score:** 47

## Executive Summary

The dataset is largely SIEM-usable and source-native: Windows XML, Sysmon, Zeek, ASA, proxy, syslog, and web records mostly parse cleanly and correlate well. I lean synthetic because the collection profile contradicts visible network/perimeter timestamps at the boundary, and a few field-value/packaging patterns look generated rather than collected.

## Evidence For Synthetic

- `environment_or_collection_plausibility`: `COLLECTION_PROFILE.json` sets the primary window end to `2024-03-18T18:00:00Z`, but Zeek network-sensor records start after that: `zeek-core/conn.json` has 4 rows from `18:00:16.077696Z` to `18:00:22.516323Z`; `zeek-dmz/conn.json` has 4 rows from `18:00:16.071732Z` to `18:00:25.285928Z`.
- `environment_or_collection_plausibility`: `fw-perimeter/cisco_asa.log` has 5 post-window initiation/build records, not just teardown tails, including new outbound builds at `18:00:16`, `18:00:22`, and `18:00:25`.
- `environment_or_collection_plausibility`: `COLLECTION_PROFILE.json` advertises `mail_artifacts` formats `email_artifacts` and `eml`, but the dataset contains no `.eml`, email artifact, artifact, or manifest files.
- `weak_signal`: Sysmon Event ID 7 metadata is narrow and templated: 298 ImageLoad events use only 21 unique metadata tuples, with repeated generic descriptions such as `MpClient.dll system library`, `vmStatsProvider.dll module`, and `pcdrsysinfosoftware.p5x module`.

## Evidence For Real

- Windows Security/Sysmon XML is well-formed and source-native: expected Event IDs and field sets appear for 4624, 4625, 4688, 4689, 4768, 4769, 5156, and Sysmon 1/3/7/10/11/13/22.
- Zeek companion integrity is strong: DNS, HTTP, SSL, and SMTP rows reference existing parent UIDs with matching tuples; file `conn_uids` and SSL/X.509 certificate references resolve.
- Endpoint lifecycle checks did not show visible impossible ordering: visible eCAR process terminations and user logouts occur after matching visible creates/logins.
- Linux/syslog texture is realistic, with sudo sessions, cron, unattended-upgrades, UFW blocks, sshd accepted-key sessions, systemd-logind, rsyslog queue messages, and normal service noise.
- Web, proxy, ASA, and Snort logs include plausible mixed status codes, scans, NAT build/teardown records, proxy `CONNECT` and inspected HTTPS flows, and browser/system/tool user agents.

## Detailed Analysis

**Schema and parsing:** The Windows XML files parse cleanly and have monotonic EventRecordIDs within each host file. Security 5156 uses expected WFP fields, 4688/4689 process fields are coherent, and 1102 correctly uses `UserData/LogFileCleared`. Sysmon field sets also match expected structures for process, network, image load, registry, DNS, file, and process-access telemetry.

**Collection-window consistency:** The strongest synthetic indicator is boundary handling. The profile says network sensors are clipped to the `12:00:00Z` to `18:00:00Z` primary window and that connection rows use observed connection start time. Despite that, `zeek-dmz/ssl.json` has `api.westbridge-services.net` at `18:00:25.560340Z`, and both core/dmz Zeek `conn.json` include new post-window starts. ASA has matching post-window "Built" records, which are initiations rather than permitted teardown tails.

**Cross-source correlation:** Correlation is mostly excellent. Zeek parent/companion UID checks found no missing DNS/HTTP/SSL/SMTP parent connections and no missing file or X.509 references. Proxy-to-origin HTTP and TLS chains line up with Zeek tuples, and endpoint/network observations around SSH and proxy traffic generally preserve source/destination semantics.

**Behavioral realism:** The dataset has believable enterprise texture: DHCP renewals with stable host/MAC identity, varied web/proxy traffic, external scanning, endpoint process/module noise, Kerberos/LDAP/SMB flows, and Linux administrative sessions. Some areas feel curated, especially Sysmon ImageLoad metadata repetition, but not enough to be a hard contradiction.

## Synthetic Indicator Summary

| Category | Source Family | Scope | Impact |
|---|---|---:|---|
| environment_or_collection_plausibility | Zeek network sensors | 8 post-window conn rows plus companions | Medium |
| environment_or_collection_plausibility | ASA perimeter | 5 post-window build/initiation rows | Medium |
| environment_or_collection_plausibility | Collection profile/mail | Missing advertised artifact formats | Low |
| weak_signal | Sysmon ImageLoad | Repeated generic metadata | Low |

## Realism Score by Category

- **Field format accuracy:** 84 - Core schemas and parsability are strong; only weak metadata templating stands out.
- **Temporal patterns:** 68 - Internal ordering is good, but boundary clipping contradicts the profile.
- **Cross-source correlation:** 89 - UID, tuple, file, certificate, and endpoint/network correlations are consistently maintained.
- **Behavioral realism:** 82 - User, service, web, proxy, firewall, and Linux activity have credible operational texture.
- **Environmental consistency:** 66 - Host/IP roles are coherent, but profile/source-family and window mismatches reduce confidence.

## Recommendations

- Enforce the stated sensor window: remove or reclassify new Zeek/ASA initiation rows after `2024-03-18T18:00:00Z`, or change the profile to explicitly allow post-window starts.
- If `mail_artifacts` are advertised, include the corresponding `.eml`/manifest artifacts; otherwise remove that family from `COLLECTION_PROFILE.json`.
- Diversify Sysmon ImageLoad PE metadata so descriptions/products look collected from real file resources rather than generated from filenames.
- Keep the current UID, tuple, X.509, file, and endpoint lifecycle correlation model; it is one of the dataset's strongest realism anchors.
