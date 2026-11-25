# Lantern Works Software - Web Server Compromise: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Identify successful server-side execution among noisy probes and scanner alerts.

## Learning questions

1. Which scan activity precedes the compromise, and how do the public and private address views identify the same portal?
2. Which web access records show the rejected upload, accepted upload, and follow-up request?
3. Which server-side process chain corroborates execution under the web service account?
4. What evidence shows the helper was downloaded and ran, and what do the repeated TLS connections establish?
5. Which scanner activity was authorized, and what additional evidence distinguishes successful execution from a scanner or IDS alert?

## Intended interpretation

The external scanner reaches the public HTTPS address, which the edge firewall maps to the private address of LW-WEB-01. Look for the 403 and 201 upload responses and the follow-up request in the web access log. Use Linux process ancestry to establish execution under www-data and corroborate the subsequent download and helper execution. Use the permitted outbound HTTP transfer and repeated TLS connections to the same destination to establish the network sequence. Omar’s later audit reaches the same server over its private HTTPS address from the management workstation and has no corresponding execution.

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

Scanner profiles and rate-based context, HTTPS through static NAT, firewall and Zeek correlation, web access and Linux process ancestry, a successful outbound HTTP transfer, and sparse encrypted callbacks.

## Modeling and interpretation limits

Public HTTPS request details and response codes are intended for web access collection. Passive Zeek sees connection and TLS metadata for HTTPS, and analysts should have no requirement to recover the uploaded file from that traffic. The separate outbound HTTP transfer remains eligible for HTTP and file observation. Callback contents stay encrypted. Any scanner IDS alert provides context for the scan.

## Evidence acceptance

The validator reports coverage warnings for the three HTTPS results. Its web-access check matches the destination address directly to a host, whereas the authored public destination is a static NAT address. Verify the 403, 201, and follow-up response in LW-WEB-01’s generated web access log before grading them. Also verify the firewall and Zeek address views, the Linux process lineage, the completed helper transfer, and the TLS callback cadence against the run’s ground truth and observation manifests.
