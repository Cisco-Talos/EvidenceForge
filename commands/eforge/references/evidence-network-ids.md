---
description: "Zeek, Snort/Suricata IDS, and Cisco ASA evidence reference"
---

# Network, IDS, And Firewall Evidence

## Contents

- [Zeek](#zeek)
- [Snort/Suricata IDS](#snortsuricata-ids)
- [Cisco ASA](#cisco-asa)

Read this reference for sensor visibility, Zeek paths and joins, IDS attachment/filter semantics,
or Cisco ASA evidence. For HTTP bodies, SMTP artifacts, web servers, and proxies, also read
`/eforge:references:evidence-web-email`.

## Zeek

Files are NDJSON at `<sensor-name>/<logtype>.json`. Evidence is emitted only for configured sensors
that can observe the connection according to segment, direction, topology, and source-observation
policy. Protocol rows for one connection share its sensor-local Zeek UID.

| Zeek log | File | Contract |
| --- | --- | --- |
| conn.log | `conn.json` | TCP, UDP, and ICMP tuple, duration, bytes, packets, state, and history. |
| dns.log | `dns.json` | A, AAAA, PTR, SRV, TXT, MX, NS, and SOA; cache/resolver/TTL semantics and conn fan-out share one DNS bundle. |
| http.log | `http.json` | Plaintext or proxy-inspected HTTP; method, URI, status, user agent, body lengths, depth, and file vectors. |
| ssl.log | `ssl.json` | TLS version, cipher, SNI, and certificate-chain FUIDs. |
| files.log | `files.json` | Visible HTTP, SMTP, SMB, and OCSP analysis with directional hosts, conn UID, optional name/MIME, counts, and hashes. SMB reads are responder-to-originator and writes originator-to-responder. |
| smb_mapping.log | `smb_mapping.json` | One sparse visible mapping for a successful share tree. `native_file_system` is the wire-advertised value, not necessarily the backing filesystem. |
| smb_files.log | `smb_files.json` | Sparse successful OPEN/READ/WRITE/RENAME/DELETE; FUID only when matching file analysis exists. |
| dhcp.log | `dhcp.json` | Lease identity, MAC/IP/server/domain metadata; acquisition/renewal agrees with conn and Linux dhclient evidence. |
| ntp.log | `ntp.json` | Response-bearing UDP/123 only; stable association values and server-owned response properties. |
| x509.log | `x509.json` | Leaf/intermediate identity, subject/issuer, validity, key and CA constraints. |
| ocsp.log | `ocsp.json` | Response IDs join the matching files.log FUID. |
| weird.log | `weird.json` | Explicit WeirdContext only; automatic weird generation is currently disabled. |
| pe.log | `pe.json` | Portable Executable metadata over visible network file analysis. |
| packet_filter.log | `packet_filter.json` | Packet-filter status changes. |
| reporter.log | `reporter.json` | Zeek operational messages. |

Ordinary TLS (`service: ssl`) is opaque and does not produce `http.log`. HTTP is not limited to
port 80: cleartext or explicitly proxy-inspected HTTP may use other ports. Encrypted SMB operations
are opaque to `smb_files.log` and `files.log`, while eligible endpoint evidence remains independent.
Samba may advertise NTFS while backed by ext4/XFS. SMB conn, mapping, file rows, and files analysis
reuse the canonical tuple/UID; each visible content version/direction receives a sensor-local FUID.
Native Zeek Kerberos and NTLM logs are not currently emitted. `missed_bytes` models probabilistic
capture loss rather than a real PCAP counter. Exact SMB fields follow the version-sensitive
[Zeek SMB contract](https://docs.zeek.org/en/lts/logs/smb.html).

## Snort/Suricata IDS

`<ids-sensor-name>/snort_alert.log` uses Snort fast-alert text. Baseline false positives and
storyline true positives are projected from canonical network/DNS/HTTP context through each IDS
sensor's visibility, clock, and NAT/PAT view.

Typed `connection`, `beacon`, `ssh_session`, `rdp_session`, `dhcp_lease`, `port_scan`, `dns_query`,
`dga_queries`, `dns_tunnel`, and `web_scan` events may attach multiple configured SIDs with
`ids_alerts`. An attachment asserts a match; EvidenceForge does not execute the Snort predicate,
decrypt traffic, apply IPS actions, or implement arbitrary `rate_filter`/CIDR suppression. A tuple
without explicit or built-in IDS context does not alert.

Inspect the effective curated signature catalog with `eforge info ids_signatures` before authoring
an attachment. Its rows identify the valid SID and the signature's protocol, preferred port,
direction, and message; use `--json` directly only when the structured compatibility fields are
needed.

Attachments follow only transports owned by their authored event:

- SSH/RDP: the session transport only.
- DHCP: the explicitly authored transaction, not automatic renewals.
- Scans/web scans: each authored probe or request.
- DNS families: authored queries, not DNS-tunnel cover traffic.
- Email transport attachments are deferred.

Candidates are deterministically ordered through a disk-backed spool before each sensor's
`detection_filter` and `event_filter` state is applied. Authored web-scan SIDs take precedence over
automatic duplicate `(gid, sid)` rows. Policy suppression is different from collection dropping or
output-window clipping and advances filter state only where appropriate.

`GROUND_TRUTH.json`/`.md` records each attached SID, effective policy, and candidate/emitted/
policy-filtered sensor totals. `OBSERVATION_MANIFEST.json` reports policy suppression as filtered
evidence separately from missingness and clipping. Ground-truth schema v2 `ids_evaluation` is the
acceptance contract: per sensor and `(gid, sid)` it includes candidate, emitted, policy-filtered,
visible/delayed, and authorized-origin totals plus a SHA-256 digest over normalized alerts in file
order. The normalized digest covers sensor, UTC time, signature, protocol, tuple, and visible
NAT/PAT projection.

Web scans can generate scanner-user-agent and path-content alerts for visible non-TLS traffic plus
connection-rate alerts for TLS or non-TLS transport. Alert identity uses `[gid:sid:rev]`; the
curated SID pool is not a complete ruleset simulation.

## Cisco ASA

Paths are `<firewall>/cisco_asa.log` for default/Splunk and
`<firewall>/<year>/cisco_asa.log` for SOF-ELK®. Records are ASA message payloads in RFC3164/BSD
syslog. A matching `environment.network.sensors` firewall entry with `cisco_asa` in `log_formats`
is required.

| Message IDs | Meaning |
| --- | --- |
| 302013 / 302014 | TCP built / teardown with duration, bytes, and reason. |
| 302015 / 302016 | UDP built / teardown. |
| 302020 / 302021 | ICMP built / teardown. |
| 106023 | Access-group deny. |
| 305011 / 305012 | NAT translation built / teardown. |
| 733100 | Automatic rate-based threat-detection scan alert. |

NAT rows accompany permitted boundary-crossing connections, and inside/outside Zeek sensors see
their appropriate pre-/post-NAT address. Baseline deny noise follows the firewall's `deny_ratio`;
high-rate scans can trigger 733100. Denied traffic is visible only on the firewall source side.
The message model omits some device details such as IDFW user, internal port numbers, and rx-ring
metadata.
