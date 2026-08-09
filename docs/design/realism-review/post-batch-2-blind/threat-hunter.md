# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 99
**Synthetic-Confidence Score:** 98

## Executive Summary

The dataset is highly sophisticated and gets many difficult correlations right, especially Zeek protocol fan-out, TLS/X.509 behavior, endpoint process lifecycles, and firewall state. However, multiple source-native contradictions—most decisively impossible Windows `EventRecordID` jumps in millisecond intervals and backward allocation of new Linux `sshd` PIDs—are generator fingerprints that outweigh the otherwise strong realism.

## Evidence For Synthetic

- `hard_contradiction` — Windows event-record allocation is impossible at the visible host scale. In `WS-NKAPOOR-01.../windows_event_security.xml`, two Event 4689 records at `2024-05-14T15:01:26.0897934Z` and `15:01:26.0987921Z` jump from `EventRecordID 940529` to `953735`: 13,206 channel records in 8.999 ms. The same defect recurs across independent hosts and channels:

  - `DC-BO-01.../windows_event_security.xml`: Event 4769 at `15:40:04.1887025Z`, record `15670315`, followed 1.0003 ms later by Event 4624, record `15671215`—a 900-record jump.
  - `FILE-BO-01.../windows_event_security.xml`: record `2730479` at `16:36:37.5515775Z` to `2746189` at `16:36:37.5705778Z`—15,710 records in 19 ms.
  - `WS-MPATEL-01.../windows_event_security.xml`: record `874123` to `890523` in 89 ms—16,400 records.
  - `WS-OREED-01.../windows_event_sysmon.xml`: record `470405` to `471143` in 4.151 ms.
  - `WS-MPATEL-01.../windows_event_sysmon.xml`: record `592119` to `592642` in 2.077 ms.

  Filtered exports explain ordinary gaps, but they cannot explain repeated hundreds-to-tens-of-thousands of same-channel records being assigned within milliseconds on small branch endpoints. The surrounding logs average orders of magnitude less activity.

- `hard_contradiction` — Linux PID allocation runs backward for newly accepted SSH connections without a plausible wrap. `PROXY-BO-01.../syslog.log` records source-native `sshd` connection children as PID `234531` at `12:31:48`, then lower PID `233681` at `12:42:54`; PID `235199` at `13:03:46`, then lower PID `234985` at `13:41:17`; and PID `236338` at `15:33:27`, then lower PID `236110` at `15:48:29`. These are new connection children from the same host-level daemon, not delayed close messages. Multiple allocator wraps would require hundreds of thousands or millions of forks between these modest-volume sessions and are incompatible with the visible workload.

- `hard_contradiction` — Zeek state/history disagreement in `ZEEK-BO-CORE/conn.json`. UID `CK1AnxAfXo2jJQtCB6` at epoch `1715705418.890453` is labeled `conn_state:"S1"`—established and not terminated—while `history:"ShR"`, zero application bytes, and packet counts `2/1` show SYN, SYN-ACK, then an originator RST. The state must represent an aborted/reset handshake, not an unterminated established connection.

- `contract_gap` — resolver cache state is not maintained for internal reverse DNS. In `ZEEK-BO-CORE/dns.json`, `10.44.10.25` queries `20.20.44.10.in-addr.arpa` through recursive resolver `10.44.20.10` at `14:34:35.383039Z` and again 16.140 seconds later. Both non-authoritative (`AA:false`) replies return the same answer and full `86400` TTL, rather than a decremented cached TTL. Across the file, 25 of 28 same-client/same-name repeats occurring inside the prior TTL show this full-TTL reset pattern, predominantly for the internal file-server PTR record.

- `distribution_texture` — Linux operational logs expose repeated randomized template pools rather than durable daemon state. `WEB-BO-01.../syslog.log` has 16 messages in which the same long-lived `rsyslogd` PID `16869` “Acquired” `/run/systemd/journal/syslog` under changing FDs; two occur at `12:18:35` and `12:19:05` with no intervening reload or restart. The host also records 34 reload/reloaded messages in six hours. `PROXY-BO-01` shows nine acquisitions and nine reload messages under PID `38115`. This is far beyond normal configuration behavior and appears sampled from a shared message vocabulary.

- `environment_or_collection_plausibility` — the same Linux noise pool assigns both servers an implausibly broad, nearly identical hardware vocabulary. `irqbalance` on each host references VMware-style `ens160`, Mellanox `mlx5_comp0`, virtio input, `nvme0q1`, and AHCI; on WEB the counts are respectively 22, 25, 28, 13, and 22. A specially built mixed-hardware host is possible, but the same pool appearing independently on WEB and PROXY reinforces the template explanation.

## Evidence For Real

- All 1,007 DNS, 1,030 SSL, and 47 DHCP Zeek UIDs have matching `conn.json` rows. Every unique HTTP UID also has a connection, all `files.json` connection UIDs resolve, and all protocol/file timestamps fall inside their connection intervals.

- TLS analyzer behavior is unusually accurate. All 286 TLS 1.2 non-resumed sessions with certificate visibility have leaf certificate artifacts; all 424 TLS 1.3 non-resumed sessions correctly lack plaintext certificate artifacts; and all 320 resumed sessions omit certificates. TLS 1.2 cipher authentication types agree with RSA/ECDSA leaf key types.

- The 537 X.509 observations reduce to 103 stable certificate identities. Repeated certificates retain serials and hashes, all are valid at observation time, and every visible leaf SAN matches the associated SNI.

- Zeek connection accounting is coherent across all 6,115 rows: no TCP or UDP row violates minimum IP/transport header accounting, and state/history patterns are generally correct apart from the single reset case above. Scan traffic has realistic `S0/S`, `REJ/Sr`, reset, partial-close, and packet-loss texture.

- Endpoint process identities are stable. Across all eCAR files there are no actor references after a visible termination, no termination preceding the matching creation, no duplicate process object creation/termination IDs, and no overlapping reuse of a created PID. Sysmon hashes are stable for all 84 image/version identities and all 20 module/version identities across hosts.

- Windows authentication placement is role-consistent: the DC carries 4768/4769/4776 activity, the file server has dense Type 3 SMB logons, service hosts generate Type 5 sessions, and visible RDP sessions use Type 10. No same-logon-ID logout precedes its visible login.

- ASA state is internally tidy: 2,469 TCP builds match 2,469 teardowns, and 707 dynamic translations match 707 translation teardowns. Long SSH teardowns after the main six-hour network window are compatible with a slice-of-time export.

- The environment contains credible unevenness: 1,140 Zeek TCP `S0` attempts, 904 WEB kernel/UFW messages, 124 ASA denies, only 38 IDS alerts, failed SSH users, NTLM and Kerberos mixtures, DHCP renewals, and incomplete pre/post-window endpoint lifecycles.

## Detailed Analysis

The principal collection window is approximately `2024-05-14 12:00–18:00 UTC`, with 6,115 Zeek connections, 6,700 ASA messages, 1,007 DNS records, 1,030 SSL records, 700 HTTP records, two Linux servers, five workstations, a file server, and a DC. Endpoint-only lifecycle records extend later—DC to `18:36` and FILE to `19:57`—which is compatible with recording terminations for state opened inside the main slice.

Operationally, the topology is coherent: workstations in `10.44.10.0/24`, infrastructure in `10.44.20.0/24`, web in `10.44.30.0/24`, explicit proxy traffic through `10.44.20.30:8080`, the DC at `10.44.20.10`, and file services at `10.44.20.20`. Proxy client CONNECTs, proxy-origin DNS/TLS, ASA NAT, inbound web scans, SMB/Kerberos, SSH, and RDP generally preserve source/destination semantics.

The strongest authenticity-positive feature is protocol-aware correlation. DNS RTTs fit connection durations; X.509/file artifacts occur during TLS intervals; TLS 1.3 certificate invisibility is modeled correctly; resumed sessions do not invent certificate chains; DHCP transaction UIDs share exact client/server/lease truth with connection rows; and transport byte counts have viable packet overhead. This is substantially better than shallow synthetic data.

The Windows endpoint model is also strong at the semantic layer. Event 4624/4634 IDs remain ordered, 4672 placement is plausible, process hashes are stable across machines, Sysmon process GUIDs and parent identities are coherent, and ECAR actors remain within their visible process lifetimes. Those strengths make the record-number defects more decisive: they are not random parser damage but an otherwise coordinated model assigning channel sequence numbers at impossible rates.

The Linux SSH evidence exposes a separate identity-allocation error. Close records for pre-window sessions are acceptable, but the backward PIDs cited above are attached to new `Connection from` records. A new `sshd` child receives its PID at accept/fork time; it cannot repeatedly receive an older number unless the system wraps its PID space multiple times. The observed connection and process volume does not support such wraps.

DNS cache behavior supplies a third independent subsystem-level tell. Authoritative internal SRV replies legitimately return their configured `600` TTL repeatedly with `AA:true`. The problematic PTR replies are explicitly non-authoritative and recursive, yet repeatedly reset to `86400`, including 16-second repetitions from the same client. This contrast shows that response fields are being rendered per event without retaining recursive-cache TTL state.

Finally, the one `S1/ShR` row is a compact source-native contradiction: the packet history says the originator reset after SYN/SYN-ACK, while `S1` says the connection remains established. Real Zeek derives both fields from one TCP analyzer state machine and would not independently sample them.

## Synthetic Indicator Summary

| Category | Source family | Scope | Impact |
|---|---|---:|---|
| `hard_contradiction` | Windows Security/Sysmon XML | DC, FILE, NKAPOOR, MPATEL, OREED examples | Impossible per-channel record allocation rates; strong generator identity leak |
| `hard_contradiction` | Linux SSH syslog | PROXY, repeated | New `sshd` child PIDs run backward without plausible allocator wrap |
| `hard_contradiction` | Zeek connection | One UID | TCP reset history contradicts `S1` state |
| `contract_gap` | Zeek DNS | 25 within-TTL repeats | Recursive cache TTL state is not preserved |
| `distribution_texture` | Linux rsyslog | Both Linux hosts | Frequent socket reacquisition/reloads under long-lived PIDs |
| `environment_or_collection_plausibility` | Linux irqbalance | Both Linux hosts | Shared mixed-hardware vocabulary suggests a common random pool |

## Realism Score by Category

- **Field format accuracy:** 7/10 — Most Zeek, Windows, ASA, and syslog records are source-shaped correctly, but the TCP state/history contradiction and Windows record-number behavior are material defects.
- **Temporal patterns:** 3/10 — Normal traffic timing and lifecycle jitter are good, but millisecond-scale record-ID leaps and backward new-process PIDs are decisive failures.
- **Cross-source correlation:** 9/10 — UIDs, tuples, authentication, process identities, TLS artifacts, and lifecycle timing are unusually coherent; resolver cache state is the main exception.
- **Behavioral realism:** 7/10 — Scans, failures, user/service traffic, SSH/RDP, SMB, and long-tail outcomes are credible, while the Linux daemon-noise texture is overactive and templated.
- **Environmental consistency:** 6/10 — Host roles and subnet placement are strong, but the duplicated mixed-device pool and implausible daemon churn weaken the environment.

## Recommendations

- Allocate Windows `EventRecordID` values with one stateful counter per host/channel. Hidden-event gaps must be proportional to elapsed time and realistic channel throughput; never insert hundreds or thousands of records between events only milliseconds apart.
- Allocate Linux PIDs at event execution time from one host/namespace lifecycle. New `sshd` children and process-create records should advance through the active PID space, with reuse only after a recorded termination and a plausible allocator wrap.
- Derive Zeek `conn_state`, `history`, packet counts, and termination cause from one TCP state machine. The `ShR` example should resolve to an appropriate reset/aborted-handshake state.
- Maintain resolver-cache entries per DNS resolver. For non-authoritative replies, decrement TTL on repeated cache hits and refresh it only on a modeled upstream lookup; alternatively mark a genuinely authoritative internal reverse zone with consistent `AA` semantics.
- Make Linux daemon noise stateful. Tie socket acquisition to an actual startup/reload lifecycle, bound reload frequency, and retain configured queue/action names rather than independently sampling each message.
- Give each Linux host a durable hardware inventory and restrict `irqbalance`, interface, and storage vocabulary to devices present on that host.
