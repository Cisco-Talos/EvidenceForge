# Detection Engineer — Blind Authenticity Assessment

## Verdict

- **Assessment:** Synthetic
- **Verdict confidence:** 87/100
- **Synthetic-confidence score:** 85/100

## Executive summary

The reviewer found no decisive hard contradiction. The synthetic verdict came from population
texture: a compact scanner population with pool-like TCP fingerprints, excessive catalog-shaped
Linux daemon messages, a public web population without 4xx/5xx outcomes, and exercise-like remote
administration demand. Format accuracy, cross-source joins, and endpoint lifecycle ordering were
strong.

## Evidence supporting synthetic

- Of 973 WEB UFW blocks, 968 came from eight addresses. Each high-volume source kept one packet
  length and TTL, but all sources rotated through the same three TCP windows (`1024`, `14600`, and
  `65535`), indicating independently sampled fields rather than coherent stack profiles.
- In six hours the WEB host emitted 158 `systemd-resolved`, 135 `irqbalance`, 133 `rsyslogd`, and
  104 `snapd` messages from compact phrase catalogs.
- All 538 web-access responses were 200, 206, 301, 302, or 304. Even sensitive and nonexistent
  scan targets such as `/.env`, `/.git/HEAD`, `/backup.sql`, and `/phpMyAdmin/` produced no 4xx or
  5xx texture.
- Nina Kapoor launched 27 SSH clients in six hours; the command population was varied but looked
  curated rather than session-persistent.

## Evidence supporting real

- The Nikto activity joined correctly across IDS, ASA, Zeek HTTP, and web access, including NAT,
  source port, URI, and User-Agent.
- Every DNS, HTTP, and TLS UID existed in `conn.json`; all 750 file rows referenced valid parent
  UIDs. TLS versions, ciphers, resumption, and certificate chains were coherent.
- No eCAR process termination preceded create, no dependent preceded its known actor, and no
  session logout preceded login.
- All source files parsed and native field morphology was generally strong.

## Scores

| Category | Score |
|---|---:|
| Field and format authenticity | 91 |
| Temporal authenticity | 86 |
| Cross-source correlation | 97 |
| Behavioral authenticity | 70 |
| Environmental authenticity | 66 |

## Disposition

These are accepted Batch 4 distribution/world findings already covered by the approved roadmap.
They do not reopen the bounded lifecycle/module gate.
