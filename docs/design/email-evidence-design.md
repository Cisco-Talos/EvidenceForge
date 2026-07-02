# Email Evidence Design

Status: implemented V1

This document captures the working design for on-prem email evidence generation.
It intentionally avoids cloud email sources such as M365/Graph/Azure audit logs.

The implemented V1 surfaces are `environment.email`, typed `email_message`
storyline events, canonical `EmailContext`/`SmtpContext`, `zeek_smtp`, and
`artifacts/email/EMAIL_ARTIFACTS.json` plus optional `.eml` files.

## Scope

V1 models on-prem/local email behavior:

- SMTP delivery between internal users.
- SMTP delivery from internal users to internet recipients.
- SMTP delivery from internet senders to internal users.
- Lightweight TLS-only email read/access sessions.
- Optional `.eml` message artifacts for storyline or selected messages.
- Zeek SMTP metadata for visible SMTP transactions.

Email generation requires explicit `environment.email` configuration. If
`environment.email` is absent, baseline email generation is disabled and
storyline `email_message` events are validation errors. The generator must not
infer an authoritative mail topology from `roles: [mail_server]`.

Out of scope for V1:

- Cloud email platforms such as M365.
- Native Exchange logs such as message tracking, protocol logs, IIS/OWA/EWS logs,
  or Exchange-specific audit logs.
- Full semantic mailbox actions such as read/delete/forward of a specific message.
- Full local mail-client/cache modeling.

## Decisions

### Routing Is Explicit

Mail routing is controlled by explicit `environment.email` configuration. Existing
system roles such as `mail_server` may remain useful for world-model hints and
validation, but they are not authoritative for email routing.

When `environment.email` exists, the email subsystem owns SMTP delivery and mail
read/access behavior. Existing generic `mail_server` SMTP, OWA, and IMAPS
baseline traffic should be suppressed or skipped to avoid duplicate/conflicting
evidence. Non-email server background such as LDAP lookups and update checks can
remain.

### Platforms

V1 recognizes:

- `generic_smtp`
- `exchange`

Exchange is a behavioral flavor only in V1. It changes defaults for access and
server capabilities, but it does not produce native Exchange logs. SMTP-relevant
behavior still routes through the shared mail delivery model.

### Strict SMTP Relay

Internal users do not normally send SMTP directly to internet destinations.
Users submit mail to their home/submission mail server, and organizational mail
servers perform internet delivery.

Direct workstation-to-internet SMTP is suspicious and should require explicit
scenario authoring or future configuration.

### Mail Server Topology

V1 supports multiple organizational mail servers through explicit pools and
route chains. This allows:

- redundant SMTP/mailbox servers,
- departmental mailbox/submission servers,
- internal relay hops before internet delivery.

The implementation should avoid a full routing policy engine in V1.

### Mailbox Assignment

Each user resolves to a home mailbox SMTP server. V1 supports:

- a default mailbox server pool,
- optional group overrides.

Internal-to-internal mail follows:

1. sender client -> sender home mail server,
2. sender home mail server -> recipient home mail server,
3. if both users share the same home server, the second SMTP hop collapses into
   local delivery.

### Outbound Routes

V1 supports:

- one default outbound route,
- optional sender group route overrides.

This supports departmental SMTP routing without adding a full policy engine.

### Internet Delivery

V1 uses a global outbound internet delivery mode:

- `direct_mx` by default,
- optional `isp_relay`.

If `isp_relay` is configured, the relay step is appended after internal org
routing. Per-route ISP relay selection is future work.

### Inbound Routes

V1 uses one default inbound route for all accepted domains. The configuration
should leave room for per-domain inbound overrides later, but V1 does not need
domain-specific MX pools.

### SMTP Ports And TLS

Defaults:

- client submission: plaintext SMTP on port 587,
- server-to-server relay: SMTP on port 25,
- server-to-server TLS: STARTTLS only, controlled by SMTP endpoint settings,
- client STARTTLS: out of scope for V1.

SMTP endpoint TLS settings:

- `allow_inbound_starttls`
- `attempt_outbound_starttls`

If the sender attempts STARTTLS and the receiver allows it, the server-to-server
SMTP leg negotiates STARTTLS. Otherwise the leg remains plaintext.

### Zeek SMTP Visibility

Zeek `smtp.log` rendering is driven by canonical email metadata plus the SMTP
route-hop model.

Plaintext SMTP legs can render rich SMTP metadata such as:

- `helo`,
- `mailfrom`,
- `rcptto`,
- `date`,
- `from`,
- `to`,
- `msg_id`,
- `subject`,
- `user_agent`,
- `last_reply`,
- `path`,
- `fuids` when applicable.

If STARTTLS is negotiated before message transfer, Zeek should not magically see
message headers or body-derived fields. It may see pre-TLS handshake information
such as `helo` and `tls: true`, depending on how the Zeek SMTP emitter is
implemented.

V1 email routing emits DNS evidence for SMTP routing:

- MX lookup of destination mail domains where appropriate,
- A/AAAA lookup of the selected MX or relay hostname,
- A/AAAA lookup of client submission and mailbox access hostnames.

SPF/DKIM/DMARC TXT lookups are future or optional texture, not core V1.

`zeek_smtp` is an explicit output format and is also included in the `zeek`
format group. Sensors with `log_formats: [zeek]` can therefore emit `smtp.json`
when visible SMTP traffic exists, and scenarios may request `zeek_smtp`
directly.

### Canonical Contexts And Bundles

Email uses dedicated action bundles:

- `EmailDeliveryActionBundle` owns message metadata, route expansion, SMTP hops,
  outcomes, queue-aware timing, `Received` chains, artifact emission, and
  manifest/ground-truth references.
- `EmailAccessActionBundle` owns lightweight TLS mail read/access sessions.

Both bundles delegate concrete network evidence to the canonical network
connection path.

Canonical event data is split into two related contexts:

- `EmailContext` represents message-level identity and metadata used for
  artifacts, ground truth, and route planning.
- `SmtpContext` represents one SMTP hop/transaction and links back to the
  message identity. It owns hop-level fields such as HELO/EHLO, `MAIL FROM`,
  `RCPT TO`, transaction depth, TLS state, SMTP reply, path, visible header
  fields, and `fuids`.

This split prevents one authored message from being collapsed into one Zeek row
when delivery expands across multiple SMTP hops or recipient branches.

### Storyline Event Shape

Scenario authors use a single typed `email_message` event. Direction is inferred
from accepted domains. Optional purpose/preset fields guide scenario-skill
content generation and metadata defaults.

Example:

```yaml
- type: email_message
  sender: alice@corp.example.com
  recipients: [bob@corp.example.com]
  subject: "Updated invoice"
  purpose: phishing
  artifact: emails/updated-invoice.eml
  attachments:
    - filename: invoice.xlsm
      artifact: files/invoice.xlsm
```

### Outcomes And Security Decisions

V1 supports basic delivery outcomes:

- `delivered`,
- `rejected`,
- `deferred`,
- `bounced`.

Per-hop SMTP replies are derived from the outcome. Full retry queues, backoff,
and NDR chains are future work.

V1 supports simple mail security fields:

- `verdict: clean | spam | phishing | malware | suspicious`,
- `mail_action: deliver | reject | quarantine | strip_attachment`.

These fields affect delivery outcome, metadata, artifacts, and future gateway
integration, but V1 does not emit dedicated security gateway logs.

### Validation And Evaluation

V1 includes schema/semantic validation for email configuration and storyline
events. Validation should produce actionable messages for missing
`environment.email`, unknown mail servers, invalid accepted domains, impossible
routes, unresolved mailbox assignments, invalid distribution groups, unsupported
nested groups, and unsupported direct workstation-to-internet SMTP.

V1 includes parser/evaluation support for `zeek_smtp`, Zeek `files.log`, and
`EMAIL_ARTIFACTS.json`. Evaluation validates core field presence and basic
cross-source consistency: SMTP UIDs join to `conn.log`, visible SMTP FUIDs join
to `files.log`, plaintext SMTP metadata agrees with artifact manifests when a
message ID is visible, and STARTTLS-protected hops suppress protected SMTP
metadata. Deeper route/DNS/artifact causality scoring can be expanded later.

### Timing

V1 uses queue-aware timing without full retries:

- most SMTP hops occur seconds apart,
- a small fraction of messages can have minute-scale queue delays,
- deferred/rejected/quarantined outcomes can influence timing,
- full retry/backoff/NDR modeling is future work.

### Message Metadata And Artifacts

All modeled messages, including background noise, receive canonical metadata
rich enough for Zeek SMTP rendering:

- envelope sender and recipients,
- header sender/recipients,
- subject,
- `Date`,
- `Message-ID`,
- optional `In-Reply-To` and `References`,
- approximate body size,
- attachment metadata when applicable,
- SMTP status/result,
- route/hop identity.

Full message artifacts are selective:

- storyline and selected messages may produce `.eml` artifacts,
- background messages are metadata-only by default,
- `mode: all` or selected IDs can materialize background artifacts as well.

Message content is created before deterministic generation, typically during
scenario creation. `eforge generate` may stamp deterministic headers, dates,
message IDs, route-derived `Received` chains, and placeholders, but it must not
make LLM calls.

Every SMTP server that receives and relays a message must add a `Received`
header derived from the canonical SMTP hop. Each receiving server prepends its
own header, so rendered artifacts list the most recent hop first and earliest
submission hop last. The `Received` chain must agree with the SMTP route and
Zeek-visible hop evidence: sender HELO/EHLO, sender IP, receiver FQDN, protocol
flavor such as ESMTP/ESMTPS, TLS negotiation state, queue/message identifiers,
and the receiving server's timestamp all come from canonical route-hop data.

Metadata generation uses a hybrid model:

- built-in structured grammar and data-driven pools by default,
- optional scenario-created `email_corpus.yaml` overlays for richer contacts,
  subjects, bodies, headers, user agents, and MIME parts.

Corpus files are scenario-relative and contain a top-level `messages` list keyed
by stable IDs. `email_message.corpus_id` selects an entry for content while the
storyline event remains authoritative for sender and recipients. V1 rejects
inline `body` or `attachments` when `corpus_id` is set to avoid mixing explicit
and corpus-authored content.

### Recipients And Distribution Groups

V1 supports `to`, `cc`, and `bcc` recipients. `to` and `cc` appear in visible
message headers and artifacts. `bcc` recipients participate in SMTP envelope
delivery but are not rendered in visible message headers.

One authored email may contain multiple recipients and one visible `Message-ID`.
Delivery expansion may branch per recipient when recipients route to different
home mailbox servers or have different outcomes. Artifacts preserve the authored
visible headers while route evidence records the concrete SMTP delivery branches.

V1 supports distribution groups:

- distribution group addresses may appear in `to`, `cc`, or `bcc`,
- expansion happens at the organizational mail server, not at the sender client,
- the group address remains visible in headers when it was addressed in `to` or
  `cc`,
- expanded concrete recipients are used for envelope delivery,
- `EMAIL_ARTIFACTS.json` and storyline ground truth record both original
  addressed groups and expanded recipients.

V1 distribution groups are one-level only. Nested groups and recursive expansion
are future work. Validation must emit actionable errors for unsupported group
rules, including unknown group members, nested group references, duplicate group
addresses, invalid member addresses, and any detected expansion cycle.

### Attachments

V1 attachment handling is selective:

- storyline and selected artifact-backed messages may include real attachments
  or references to attachment files,
- background messages carry attachment metadata only by default,
- plaintext SMTP legs produce Zeek `files.log` metadata and SMTP `fuids` for
  every MIME part, including the body part and attachments,
- encrypted SMTP legs must not expose attachment/header/body details to Zeek
  after STARTTLS negotiation.

Full endpoint attachment handling, such as saving, opening, and child process
execution, is future work unless a storyline models it explicitly through the
existing process/browser/file bundles.

### Artifact Output Layout

Generated artifacts live under an `artifacts` directory that is a peer of
`data` in the generation output root:

```text
output/
  data/
  artifacts/
    email/
      EMAIL_ARTIFACTS.json
      <safe-message-token>-<storyline-or-event-id>.eml
```

`.eml` is the V1 per-message artifact format. Mbox-style mailbox/container
artifacts may be added later. `EMAIL_ARTIFACTS.json` is the canonical mapping
between message IDs, storyline/event IDs, artifact paths, sender/recipient
metadata, and route-hop metadata. Filenames are for human browsing and must not
be treated as the canonical identity source.

Storyline email artifacts are referenced in both `GROUND_TRUTH.json` and
`GROUND_TRUTH.md` in addition to `EMAIL_ARTIFACTS.json`. Non-storyline artifacts
are indexed only in `EMAIL_ARTIFACTS.json`.

Email artifact generation is controlled under `environment.email.artifacts`, not
through `output.logs`, because artifacts are not ingestable log sources and do
not live under `data`.

### Read/Access Sessions

V1 read/access behavior is TLS-only and content-opaque:

- generic SMTP platforms primarily use IMAPS on port 993,
- Exchange-flavored platforms primarily use HTTPS/OWA-style access on port 443,
- POP3S is absent or rare/future.

Read/access sessions create DNS, TLS, connection, proxy, firewall, and endpoint
flow evidence through the existing canonical network path. They do not claim
that a specific user opened a specific message.

### Client Process Attribution

V1 uses light client process attribution:

- source flows may be attributed to plausible mail clients such as Outlook,
  browser-based OWA, or generic mail clients where endpoint evidence is enabled,
- full local cache, mailbox file, attachment-open, and semantic read modeling is
  out of scope.

## Future Work

- Full local mail-client modeling: Outlook OST/PST, Thunderbird profiles,
  browser cache, local mailbox databases, and credential/session artifacts.
- Semantic mailbox actions: open/read/delete/reply/forward specific messages.
- Attachment handling and user interaction: attachment download/create/open,
  Office/PDF process launch, local file artifacts, browser download metadata,
  and AV/EDR side effects.
- Native Exchange evidence after careful source-backed research: message
  tracking logs, protocol logs, IIS/OWA/EWS logs, and Exchange audit logs.
- Client STARTTLS and implicit TLS submission.
- Per-domain inbound MX pools.
- Per-route ISP relay selection for multi-site or complex egress environments.
- Full mailbox corpus generation for background messages.
