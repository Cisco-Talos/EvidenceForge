---
description: "Email, HTTP file, web access, and proxy evidence reference"
---

# Web, Proxy, Email, And File Evidence

Read this reference for email artifacts, SMTP, HTTP bodies/files, web access, proxy access, or
target-specific web/proxy rendering. Network sensor placement and IDS/firewall rules live in
`/eforge:references:evidence-network-ids`.

**Contents:** [Email and SMTP](#email-artifacts-and-smtp) · [HTTP files](#http-and-file-analysis) ·
[Web access](#web-access) · [Forward proxy](#forward-proxy-access)

## Email Artifacts And SMTP

With `environment.email`, storyline `email_message` and optional deterministic background mail use
the normal DNS, transport, and sensor-visibility layers.

- `ARTIFACTS_MANIFEST.json`: production-facing artifact metadata under `email.messages`.
- `artifacts/email/<artifact-id>.eml`: optional RFC 5322 message artifact.
- `<sensor>/smtp.json`: visible Zeek SMTP transactions.
- `<sensor>/files.json`: one row per visible plaintext MIME part, including body and attachments.

Manifest rows include message ID, sender/recipient metadata, subject/date, optional `eml_path`, and
blind-safe export status/reason. They exclude storyline IDs, verdict/classification labels, local
filesystem paths, expanded delivery recipients, and transport-route internals.

Plaintext SMTP rows share the connection UID and may include envelope/header data. A client or relay
hop that upgrades with STARTTLS before message transfer omits protected `subject`, `msg_id`, `from`,
`to`, `user_agent`, and attachment FUIDs. Client submission uses port 587 and may upgrade to
STARTTLS; server relay uses port 25. Materialized mail gets one `Received` header per server hop.

IMAPS 993 and OWA-style HTTPS 443 reads are opaque: Zeek sees DNS, connection, and TLS evidence,
not mailbox commands or content. Exchange is a behavioral flavor for SMTP and OWA; native Exchange
tracking and IIS/Exchange logs are not emitted.

## HTTP And File Analysis

Zeek `http.json` contains plaintext or proxy-inspected request/response fields. File-analyzed
requests expose `orig_fuids` and optional `orig_filenames`/`orig_mime_types`; responses use the
matching `resp_*` names. These FUIDs join `files.json` rows for the same connection UID.

Every successfully transmitted visible nonempty HTTP request body produces an `is_orig: true` file.
Every successfully transmitted visible nonempty response entity produces an `is_orig: false` file,
including tiny, redirect, authentication-failure, and other error bodies. HEAD, 1xx, 204, 205, 304,
successful CONNECT, zero-byte, failed-transport, and opaque HTTPS responses remain fileless.
Filename absence is normal; a URL never invents a response filename.

`files.json` uses Zeek-native `tx_hosts`, `rx_hosts`, and `conn_uids`, plus a FUID, optional filename
and MIME, observed byte counts, and hashes when analysis was complete. MIME requires leading
content; hashes require complete ordered observation. Observation loss may hide/truncate a file and
suppress the corresponding HTTP vector coherently.

A plaintext proxy MISS produces separate origin-to-proxy and proxy-to-client FUIDs with matching
content metadata/hashes. A HIT or proxy-generated error produces only the client-leg file. An
origin failure produces no egress response file. Successful CONNECT and opaque tunnel traffic are
not analyzed, while a failed CONNECT error body can be.

For multipart HTTP, outer request/response length includes boundaries, headers, separators, and
transfer encoding. Each nonempty decoded leaf produces a directional `files.log` row; containers
and envelope bytes do not. Leaf counts and hashes describe decoded content, and `total_bytes` is
absent unless that leaf has its own Content-Length. FUID arrays preserve discovery order and cap at
15 even though all leaf rows remain. Filename and MIME vectors are sparse present-value lists, not
positional projections of FUIDs. Missing-boundary input is one whole-body file. Ordinary
byteranges, chunked multipart, and top-level content-coded multipart are outside the model.

Plaintext SMB reads flow responder-to-originator and writes originator-to-responder. A visible
nonempty logical operation/content-version/direction gets a sensor-local FUID. Encrypted-share
operations remain opaque.

## Web Access

The file is `<web-host>/web_access.log` for systems with a web-server role.

- Default and SOF-ELK®: Apache/Nginx combined text.
- Splunk: NDJSON compatible with the Apache TA `apache:access:json` sourcetype.

Combined rows use:

```text
client-ip - username [dd/Mon/yyyy:HH:MM:SS zone] "METHOD path HTTP/version" status bytes "Referer" "User-Agent"
```

Browser traffic uses direct/search/same-origin/social referrer distributions; crawler referrers are
blank. Scanner presets follow tool-specific behavior rather than receiving browser referrers.

## Forward Proxy Access

The file is `<proxy-host>/proxy_access.log` for systems with the `forward_proxy` role.

- Default: extended combined text with an optional proxy metadata tail.
- SOF-ELK: plain combined text.
- Splunk: Apache TA-compatible NDJSON plus EvidenceForge proxy fields and CIM tagging.

Transparent mode may retain direct-looking client-to-origin sensor traffic. Explicit mode creates
client-to-proxy and proxy-to-origin legs; each sensor sees only its observable leg. A denial stops
at the proxy, so no origin-leg Zeek, IDS, or firewall evidence is emitted. HTTP/S beacons follow the
same route.

Combined proxy rows put an absolute URL or CONNECT authority in the request target. Default output
preserves full usernames. SOF-ELK strips a domain prefix and machine-account `$` for its parser;
Splunk JSON preserves the full username.

HTTPS creates one CONNECT row per client/host session and reuses a tunnel within the idle timeout.
The current model assumes interception, so inspected HTTPS requests can also appear as application
rows. CONNECT setup status is separate from the inspected request status. Non-intercepting,
tunnel-only HTTPS behavior is not yet modeled.

Browser and inbound visitor traffic can form multi-request page-load clusters. Persona depth uses
`browsing_intensity`; inbound visitor/tool/API profiles come from `web_session_profiles.yaml`.
Scenario traffic affinities traverse the same browser/proxy/Zeek/web-access paths and preserve
route-specific methods, status, sizes, and content types.
