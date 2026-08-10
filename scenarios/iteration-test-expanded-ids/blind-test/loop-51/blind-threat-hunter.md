# Threat Hunter — Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict Confidence:** 88/100
- **Synthetic-Confidence Score:** 76/100 — likely synthetic

## Executive Summary

The dataset is substantially more realistic than a simple generated exercise: it contains six
hours of dense, varied enterprise activity, credible lifecycle coverage, two distinct Zeek sensor
perspectives, and a broad mix of endpoint, authentication, proxy, mail, web, firewall, IDS, DHCP,
DNS, TLS, and file evidence.

The strongest authenticity defect is mechanical cross-host timing. In eCAR telemetry, 1,004
timestamp groups contain 2,013 FLOW rows where different hosts report the same connection at the
exact millisecond. Repeated module-load bursts are likewise serialized into unusually tidy
millisecond sequences. Linux workload construction also shows a small number of reusable templates
assigned across hosts in ways that are operationally questionable. These artifacts outweigh the
dataset's otherwise strong realism.

## Evidence For Synthetic

- **Cross-host timestamp cloning:** 1,004 eCAR FLOW timestamp groups contain 2,013 rows with exact
  millisecond equality across different hosts. Examples include:
  - `1710763273961`: identical `10.10.1.32 → 10.10.3.20:8080` rows on `WS-PPATEL-01` and
    `PROXY-01`.
  - `1710763284068`: identical `10.10.3.20 → 10.10.2.10:53` rows on `PROXY-01` and `DC-01`.
  - `1710776424495`: identical client-to-proxy FLOW rows on `WS-EBROOKS-01` and `PROXY-01`.
  This looks like one canonical occurrence copied to two endpoint records without independent
  collection latency.
- **Mechanically serialized module fan-out:** `DC-01`, PID 5492, has six MODULE/LOAD records in
  3 ms; `WS-AJOHNSON-01`, PID 6140, has seven in 6 ms. The SSH process on `WS-MCHEN-01`, PID 9656,
  has successive module rows at `1710776475411`, `...5412`, `...5413`, `...5414`, `...5415`,
  `...5416`, and `...5418`. The recurring one-record-per-millisecond pattern is more consistent
  with deterministic rendering than native event arrival.
- **Reusable Linux workload templates:** 55 `proxy_healthcheck.py` process creations occur only on
  `APP-INT-01` and `MAIL-CLIN-01`; all have PPID 1 and differ mainly by one of 39 target domains.
  Thirty-seven `/usr/bin/wget` creations occur only on `DB-PROD-01` and `WEB-EXT-01`, again all
  with PPID 1.
- **Questionable host-role behavior:** `DB-PROD-01` alone runs 17 root-owned, proxy-aware `wget`
  commands against a broad assortment including PyPI, Snapcraft, Ubuntu archives, FullStory,
  Mixpanel, and Statuspage. This is an implausibly generic application model for a production
  database server.
- **Template-shaped web browsing:** Successful visits frequently expand into a recurring page
  bundle—root document, CSS, vendor JavaScript, application JavaScript, logo, favicon, and hero
  image—with randomized hashes and sizes. Individual sessions are plausible, but the repeated
  bundle grammar is visible.
- **Highly explicit threat artifacts:** The activity includes
  `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, PSEXESVC creation,
  `mysqldump`, `scp`, history shredding, service persistence, and Security-log clearing. These are
  valid threat-hunting artifacts, but their source-native presentation is unusually clean.

## Evidence For Real

- Volume is credible for the six-hour window: 11,663 Zeek connections, 15,948 eCAR FLOW records,
  and substantial Windows Security/Sysmon coverage rather than a thin storyline-only dataset.
- Family mix is broad: eCAR includes 1,783 process creations, 1,485 process terminations, 2,561
  module loads, 1,253 logins, 900 logouts, 560 process opens, 358 registry changes, and multiple
  file and service families.
- Lifecycle behavior is comparatively strong. Of 1,783 in-window process creations, 1,401 have a
  matching termination; matched lifetimes have a median of about 30.4 seconds. The remainder can
  include persistent processes and right-window truncation.
- Traffic timing and volume are nonuniform. Users, servers, scanners, SMTP systems, browsers,
  proxy traffic, authentication, and background services show different rates and burst shapes.
- The two Zeek sensors do not simply duplicate records: no duplicate UIDs or exact
  timestamp-plus-five-tuple records were found between core and DMZ connection logs.
- Protocol fan-out is convincing: DNS, HTTP, TLS, X.509, OCSP, SMTP, DHCP, files, PE metadata,
  proxy, firewall, and endpoint observations coexist with varied packet counts, durations,
  connection states, and outcomes.
- Pre-window session closures appear in Linux syslog and are consistent with legitimate boundary
  effects.

## Detailed Analysis

**Temporal realism:** Workload-level timing is strong, with irregular activity across the six-hour
window and credible periodic jobs. Rendered-source timing is weaker because exact milliseconds are
reused between separate host records and module-load bursts repeatedly form serialized sequences.

**Lifecycle realism:** Process and SSH-session open/close pairs are common, multiple concurrent SSH
sessions are represented, and network records have varied durations and terminal states. The
unmatched process tail is not independently suspicious because persistent processes and window
boundaries explain much of it.

**Cross-source pivots:** Endpoint flows, proxy transactions, DNS, Zeek, Windows authentication, SSH,
firewall, and application records align coherently. However, correlation is occasionally
implemented with identical timestamps where independent sensors would normally introduce small,
source-specific differences.

**Volume and family mix:** The dataset contains enough routine authentication, web traffic, mail
flow, scanning, endpoint maintenance, registry activity, process access, and background service
noise to support genuine hunting pivots. The suspicious chain is embedded in rather than isolated
from this background.

**Source semantics:** Windows and Zeek records generally resemble their native families, but eCAR
fan-out exposes deterministic ordering. Linux service activity relies visibly on root/systemd-launched
command templates, particularly the database-server `wget` behavior. Public web traffic also shows
recurring session-construction patterns.

## Synthetic Indicator Summary

| Indicator | Category | Strength |
|---|---|---:|
| 1,004 exact cross-host eCAR FLOW timestamp groups | Cross-source timing | Very strong |
| Repeated one-millisecond module-load serialization | Endpoint timing | Strong |
| Root/PPID-1 health-check command templates | Workload ecology | Moderate |
| Production database making templated third-party `wget` checks | Host-role semantics | Moderate |
| Repeated browser asset-bundle grammar | Application behavior | Moderate |
| Broad volumes and nonuniform activity | Evidence for real | Strong |
| Good process/session lifecycle coverage | Evidence for real | Strong |
| Independent core/DMZ Zeek identities | Evidence for real | Strong |

## Realism Categories

1. **Temporal and burst realism:** 7/10
2. **Process, session, and connection lifecycle realism:** 8/10
3. **Cross-source correlation realism:** 8/10
4. **Background volume and event-family mix:** 8/10
5. **Source-native semantic fidelity:** 6/10

## Recommendations

1. Apply independent, source-specific observation delay to host-local FLOW records; avoid exact
   timestamp reuse across separate hosts.
2. Preserve natural timestamp precision for module loads instead of emitting deterministic
   one-millisecond sequences.
3. Replace generic root/systemd `wget` and health-check templates with role-specific daemons,
   timers, parent chains, destinations, and failure behavior.
4. Remove broad third-party health checks from database servers unless supported by a concrete
   installed service.
5. Expand web-session grammars with cache hits, partial loads, aborted requests, API calls,
   redirects, idle reuse, and browser-specific concurrency patterns.
6. Keep the current lifecycle, family diversity, sensor partitioning, and nonuniform volume model;
   these are the dataset's strongest realism features.
