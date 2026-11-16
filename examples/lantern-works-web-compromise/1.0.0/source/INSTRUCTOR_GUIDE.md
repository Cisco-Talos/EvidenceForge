# Lantern Works Software - Web Server Compromise: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Identify successful server-side execution among noisy probes and scanner alerts.

## Learning questions

1. Which scan activity precedes the compromise, and which requests fail?
2. What accepted upload and later request indicate the vulnerability was actually exercised?
3. Which server-side process chain corroborates execution under the web service account?
4. What secondary helper appears, and what outbound behavior follows?
5. Which scanner activity is authorized, and why is an IDS alert alone insufficient to establish compromise?

## Intended interpretation

The external client at 198.51.100.77 enumerates the portal using gobuster. A 403 upload is followed by a 201 multipart upload of status.php and a request to /uploads/status.php?cmd=id. The PHP worker creates /bin/sh and id under www-data. It subsequently retrieves /tmp/cache-maint, changes its mode and starts it; sparse encrypted callbacks go to status.artifact-cache.example. Omar's later nikto audit originates at the management workstation and lacks this accepted-upload/execution chain. This is a generic insecure upload design, not a claimed reproduction of a named CVE.

## Authored timeline

| Offset / time | Actor | System | Intended activity |
|---|---|---|---|
| +45m | www-data | LW-WEB-01 | An external client enumerates support-portal paths with a directory scanner. |
| +1h5m | www-data | LW-WEB-01 | An upload without the required filename extension is rejected. |
| +1h8m | www-data | LW-WEB-01 | A vulnerable attachment handler accepts a server-side script in the upload directory. |
| +1h9m | www-data | LW-WEB-01 | The PHP worker services the uploaded script. |
| +1h10m | www-data | LW-WEB-01 | The external client requests command execution through the uploaded script. |
| +1h10m2s | www-data | LW-WEB-01 | The web worker creates a command shell and queries its service identity. |
| +1h13m | www-data | LW-WEB-01 | The foothold checks the kernel and host identity. |
| +1h17m | www-data | LW-WEB-01 | A command-line client retrieves a secondary Linux helper from external infrastructure. |
| +1h19m | www-data | LW-WEB-01 | The helper is made executable and started under the compromised web service account. |
| +1h20m | www-data | LW-WEB-01 | The new helper makes sparse encrypted callbacks. |

## Benign comparisons

- approved-web-audit (+3h): An approved scanner produces conspicuous request patterns but lacks the accepted upload, command request and web-worker child chain.

## Capabilities demonstrated

gobuster and nikto scanner profiles; a directly addressed public web host; correlated curated IDS attachments; multipart upload/file analysis; web-worker child processes; sparse_poll encrypted callbacks.

## Modeling and interpretation limits

HTTP upload and command-request evidence are visible on port 80; the later TLS callback content is opaque. The upload represents script bytes by size and MIME, not an executable web-shell file distributed with the example. The secondary helper is fictional. Two canonical-path advisories are retained intentionally: Ubuntu PHP-FPM uses /usr/sbin/php-fpm8.3, and a newly staged helper belongs in /tmp rather than the generic /usr/bin fallback. Neither is an accidental path typo. An attached IDS SID asserts a configured match; the engine does not execute a Snort predicate or prove exploit success from that alert.

## Evidence acceptance

This guide describes authored intent, not a reviewed generated dataset. Input validation and publication do not prove that every intended observation appears. After generation, inspect the run-owned GROUND_TRUTH.md/JSON, collection/observation manifests, relevant artifacts and exact process/session/network relationships, then evaluate the bundle. Do not invent a missing source, relax an acceptance threshold or treat absent telemetry as proof of nonexecution.
