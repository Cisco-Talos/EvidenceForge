# HTTP Multipart Zeek Research

## Purpose

This investigation establishes the source-native Zeek behavior that the future
HTTP multipart implementation must reproduce. It is research only: no external
PCAP, Zeek log, or Zeek fixture is added to EvidenceForge, and permanent tests
must use repository-owned model inputs with literal expected records.

Research was performed with Zeek 8.2.1 and a temporary filtered clone of Zeek at
commit `6089a766108e2d9d631cea86f2ed1758dc199435`. Temporary captures and generated
logs lived under `/private/tmp` and are not project dependencies.

## Sources and fixture policy

Primary sources:

- [Zeek HTTP entity policy](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/scripts/base/protocols/http/entities.zeek)
- [Zeek HTTP file identity policy](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/scripts/base/protocols/http/files.zeek)
- [Zeek HTTP analyzer](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/src/analyzer/protocol/http/HTTP.cc)
- [Zeek MIME analyzer](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/src/analyzer/protocol/mime/MIME.cc)
- [RFC 7578, multipart/form-data](https://www.rfc-editor.org/rfc/rfc7578.html)
- [RFC 2046, multipart MIME syntax](https://www.rfc-editor.org/rfc/rfc2046.html)
- [curl `--form` documentation](https://curl.se/docs/manpage.html#-F)

The Zeek repository is distributed under its three-clause BSD-style
[COPYING](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/COPYING),
but its trace index documents mixed provenance and does not give each relevant
capture an independent license statement. The Wireshark issue capture used for
one chunked-response probe also has no clear reusable license. Those captures
are suitable as ephemeral research inputs, but should not be copied, vendored,
downloaded during tests, or treated as redistributable EvidenceForge assets.
Only independently written findings and expected values derived from the
research belong in this repository.

## Empirical matrix

| Input | Zeek 8.2.1 result | Contract established |
|---|---|---|
| Zeek [`multipart-form-data.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/multipart-form-data.pcap) | POST body 767 bytes; one originator FUID, filename `test.txt`, MIME `text/plain`, `seen_bytes=584` | `request_body_len` is the complete top-level multipart entity, while the file is the decoded leaf. Boundaries, part headers, and separators are not file bytes. |
| Zeek [`multipart.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/multipart.pcap) | POST body 350 bytes; three anonymous originator files of 4, 5, and 5 bytes; ordinary JSON response body 465 bytes with one responder file | Every nonempty leaf form value is analyzed as a file, even without a filename or detected MIME. Request leaf files and the response file coexist on one transaction. |
| Zeek [`ctu-62604-80.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/ctu-62604-80.pcap) | POST body 440 bytes; four originator FUIDs of 38, 1, 6, and 22 bytes; only one filename (`file`) and one detected MIME (`text/plain`) | HTTP filename and MIME vectors are sparse lists, not arrays positionally aligned with FUIDs. |
| Zeek [`no_crlf.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/no_crlf.pcap) | Five multipart transactions share one connection UID; each transaction has a distinct originator FUID and responder FUID | Multipart vectors are transaction-local and reset for each `trans_depth` on a persistent connection. |
| Zeek [`deeply-nested-mime.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/deeply-nested-mime.pcap) | POST body 39,686 bytes; 50 originator file rows; only 15 FUID/MIME vector entries; `exceeded_mime_max_depth` at the default depth of 100 | Nested multipart/message entities recursively produce leaf files. File objects continue beyond the default HTTP vector limit of 15. MIME recursion has a separately configurable limit of 100. |
| Zeek [`byteranges.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/byteranges.pcap) | A 206 multipart/byteranges response has body length 56,493 but one responder FUID; its file reports sparse offsets against a 605,292,323-byte instance | `multipart/byteranges` is not ordinary multipart. Its children are ranges of one logical file and must share a file identity. |
| Zeek [`206_example_c.pcap`](https://github.com/zeek/zeek/blob/6089a766108e2d9d631cea86f2ed1758dc199435/testing/btest/Traces/http/206_example_c.pcap) | Many 206 transactions on two TCP connections reuse one PDF FUID; the final file has both connection UIDs, 498,668 observed bytes, and no missing bytes | Range identity can span HTTP transactions and TCP connections. Zeek keys responder range content by client and URL rather than by connection/MIME depth. |
| Wireshark issue [#18130](https://gitlab.com/wireshark/wireshark/-/work_items/18130) | Chunked multipart/mixed response: `response_body_len=56,348`; two responder files of 56,082 and 132 bytes; `HTTP_chunked_transfer_for_multipart_message` | Zeek explicitly regards chunked multipart as anomalous. Its analyzer processes raw chunk framing in the multipart path, so file/body sizes can depend on chunk layout rather than only semantic parts. |

The truncated `putty-upload.pcap` is useful only to confirm filename and content
sniffing: the declared part type is an MS executable type, while Zeek detects
`application/x-dosexec` and produces PE analysis. It is not suitable for exact
complete-body size expectations.

## Controlled edge probes

Temporary, repository-independent HTTP captures were generated locally to
isolate semantics that the public traces do not cover cleanly:

- A 409-byte multipart/form-data request produced three leaf files of 5, 6,
  and 7 bytes. `filename*=UTF-8''caf%C3%A9.txt` became `café.txt`; its base64
  leaf decoded to 6 bytes. A `Content-Type` `name="fallback.bin"` parameter
  supplied a fallback filename. Quoted-printable content was decoded before
  file accounting, including MIME line-ending semantics.
- A `multipart/form-data` Content-Type without a boundary produced one ordinary
  30-byte originator file for the entire 30-byte body. It did not disappear and
  did not create multipart children.
- A leaf with its own `Content-Length: 3` produced `seen_bytes=3` and
  `total_bytes=3`. Ordinary multipart leaves without a per-part Content-Length
  generally omit `total_bytes`, even when the outer HTTP body is complete.

These captures and their logs remain temporary. The permanent tests should
encode only the resulting model inputs and literal expected dictionaries.

## Required semantic contract

### Entity and byte accounting

1. A normal, non-chunked, non-content-encoded multipart HTTP body has one
   top-level analyzer body length and an ordered tree of MIME entities.
2. Only nonempty leaf entities become `files.log` objects. Multipart containers,
   boundaries, part headers, preambles, and epilogues do not.
3. For a leaf, `seen_bytes` and hashes describe decoded content after
   Content-Transfer-Encoding. The top-level body length includes the serialized
   boundaries, headers, separators, and transfer-encoded leaf octets.
4. Envelope overhead therefore cannot be assigned to any leaf file. It belongs
   to the originator or responder HTTP/TCP payload ledger.
5. A leaf's `total_bytes` is absent unless the leaf has its own declared length
   (or range instance size). The outer HTTP Content-Length must not be copied to
   every child.
6. Capture loss remains directional. It reduces observed top-level body bytes
   and child `seen_bytes` coherently, but the implementation must allocate the
   observed/missing bytes across ordered leaf spans and envelope spans rather
   than multiplying every child by one connection-wide ratio.

### MIME and filename metadata

1. Zeek `files.log.mime_type` and the HTTP MIME vectors are file-magic results,
   not the leaf's declared Content-Type. Canonical metadata therefore needs
   separate `declared_content_type` and `detected_mime_type` fields.
2. Zeek accepts a `filename` or `filename*` parameter from Content-Disposition,
   URI-decodes the extended value, and also accepts a `name` parameter on
   Content-Type as a fallback filename source. It does not infer filenames from
   the request URI.
3. Local source path, local source filename, form field name, and wire-visible
   filename are distinct values. Only the wire filename projects to Zeek.
4. RFC 7578 deprecates Content-Transfer-Encoding for HTTP form-data and forbids
   RFC 5987 `filename*`, but Zeek accepts both in observed traffic. They should
   be supported as analyzer-realism options, not emitted as the default browser
   profile.

### HTTP vectors and limits

1. `orig_fuids` and `resp_fuids` preserve leaf discovery order and default to a
   maximum of 15 entries per transaction/direction.
2. Filename and MIME vectors append only values that exist. They are sparse and
   cannot be indexed against FUID vectors. The current emitter behavior that
   duplicates a single filename/MIME to force equal lengths is incorrect and
   must be removed.
3. `files.log` may contain more file objects than the HTTP vectors reference.
   The evaluator must not require positional filename/MIME agreement or assume
   every connection-local file appears in a vector.

### Special cases

- Missing boundary parameter: analyze the entire body as one ordinary file.
- Missing closing boundary or interrupted transfer: retain any leaves actually
  opened/observed and represent incomplete timing/bytes; do not fabricate later
  parts.
- Nested MIME: recurse to leaf entities, enforce an authored/generator safety
  depth, and model the Zeek depth-limit weird if weird synthesis is in scope.
- `multipart/byteranges`: use a separate range-reassembly contract. Do not feed
  its children through the independent-part bundle.
- Chunked multipart: exclude from deterministic multipart authoring in the
  first implementation. Zeek emits a weird and its sizes are chunk-layout
  dependent; correct modeling requires an explicit chunk/framing plan.
- Top-level gzip/deflate multipart: likewise requires a content-coding layer
  because Zeek counts/analyzes decompressed entity data. It should not be
  silently approximated as ordinary multipart.

## Exact EvidenceForge change surface for planning

### Scenario and configuration models

- Add typed, ordered request/response multipart specs to `connection`, `beacon`,
  and beacon HTTP-sequence schemas. A part needs at least: form field name,
  decoded content size, optional local source path, optional wire filename,
  optional declared Content-Type, optional detected MIME override, transfer
  encoding, and stable content identity. Allow repeated field names.
- Support multiple curl `-F`/`--form` and `--form-string` arguments. For curl,
  `@file` is a file upload with a wire filename; `<file` is a text field read
  from a local file without a wire filename; literal values create no endpoint
  read. Honor supported `filename=`, `type=`, and `encoder=` modifiers.
- Define one data-driven serializer/profile section in
  `http_file_profiles.yaml`: boundary family/length, header ordering, default
  per-part headers, browser/curl disposition style, MIME detection mappings,
  and safe maximum parts/depth. Validate overlays in `config/schemas.py` and
  `validate_config.py`.
- For authored multipart, calculate `request_body_len`/`response_body_len` from
  the serialized entity. If an author also supplies a body length, require an
  exact match and fail validation; do not resize leaf content or invent padding.

### Canonical protocol ownership

- Replace the singular request-only entity assumption with a direction-neutral
  HTTP entity tree: a top-level entity owns analyzer body length/content type;
  ordered parts own declared headers, encoded size, decoded size, content
  identity, detected MIME, filenames, and local-source metadata.
- Preserve a compatibility construction path for existing raw request bodies,
  but do not represent a multipart envelope as one leaf whose size equals the
  HTTP body length.
- Generalize `HttpFileTransferActionBundle` to expand all observed leaves in
  order and return tuples of file transfers and PE analyses. Multiple executable
  parts require `ProtocolTransactionPlan` and the occurrence builder to own a
  tuple of `PeContext` values rather than the current singular `pe` field.
- Store explicit part-to-FUID associations internally. Project sparse native
  vectors only at the HTTP emitter boundary.

### Generation, transport, and proxies

- Update `_attach_http_file_transfers` to build every request and response leaf,
  retain ordinary one-entity behavior, and keep request and response parts on
  the same transaction.
- Allocate serialized envelope and encoded part bytes into the directional TCP
  ledger. Packet/duration floors use the top-level transmitted entity; file
  durations, hashes, MIME, PE, and missing bytes use each decoded leaf.
- Replace observation's per-transfer connection-wide ratio with span-aware loss
  allocation so a gap can affect an envelope, one part, or several ordered
  parts without making every file identically partial.
- Emit one endpoint FILE/READ for each resolved local source file. Literal form
  values and anonymous program-generated bodies do not create endpoint file
  activity. Preserve part/read order and process ownership.
- Generalize explicit-proxy HIT/MISS/error handling to a sequence of parts.
  A MISS creates leg-local FUIDs per part with matching content identity,
  decoded size, MIME, filename, and hashes; a HIT has client-leg response parts
  only; proxy-generated bodies remain proxy-owned entities.

### Rendering and evaluation

- Remove vector equalization from `zeek_http.py`; emit capped FUID vectors and
  sparse filename/MIME vectors in discovery order.
- Keep `zeek_files.py` leaf order stable within each direction and bound every
  file/PE observation by the owning connection. Update `zeek_pe.py` to emit all
  part-local PE analyses.
- Rewrite `_score_http_file_consistency`: join every exposed FUID to a file row,
  validate direction and connection UID, treat filename/MIME arrays as sparse
  multisets rather than positional arrays, and for multi-FUID transactions
  validate that observed leaf bytes fit within the top-level body rather than
  equaling it. Give 206 range responses their own rule.
- Add ground-truth multipart structure with ordered parts, local source details,
  wire metadata, encoded/decoded sizes, and FUIDs without exposing invented
  source paths.

### Documentation and regression gates

- Update `docs/ARCHITECTURE.md`, canonical scenario/evidence references, all
  matching copies under `commands/eforge/references`, and scenario/generate/
  evaluate/config skill material.
- Extend skill-installation and canonical/bundled reference-sync tests.
- Add fixture-free unit/integration matrices for request and response multipart,
  anonymous fields, several files, repeated field names, sparse vectors,
  15-entry limits, nested leaves, decoding, missing boundary, exact envelope
  sizing, local reads, proxy legs, observation loss, persistent connections,
  coexistence with ordinary opposite-direction bodies, multi-PE, and opaque
  HTTPS.
- The permanent suite must not run Zeek, fetch the network, or read a PCAP. It
  should assert repository-owned canonical inputs and literal Zeek-shaped output
  dictionaries derived from this worklog.

## Recommended scope boundary

The first implementation should cover deterministic Content-Length-based
`multipart/form-data` and `multipart/mixed` entities, including ordered and
nested parts in both directions. Treat `multipart/byteranges` as a named second
workstream because it needs cross-transaction/cross-connection file identity.
Keep chunked and top-level compressed multipart explicitly unsupported until the
model owns their framing/content-coding details. This avoids claiming source
fidelity where Zeek's own chunked-multipart behavior is anomalous and
packetization-sensitive.

## Implementation Record

Implemented on `codex/http-upload-files-log` as a fixture-free extension of the
bidirectional HTTP file-analysis work:

- Added ordered request/response multipart authoring to connection, beacon,
  beacon-sequence, and application/web-route profiles.
- Added a deterministic allocation-free serializer for form-data/mixed entities,
  nested boundaries, transfer encodings, per-part headers, exact outer sizes,
  decoded leaf spans, and one-unknown curl file-size solving.
- Added curl form parsing for repeated `-F`/`--form`, `--form-string`, `@path`,
  `<path`, and filename/type/encoder modifiers.
- Expanded each nonempty decoded leaf into a canonical directional file transfer,
  with sparse capped HTTP vectors, multiple PE analyses, span-aware observation
  loss, proxy leg-local FUIDs, endpoint reads, and additive ground truth.
- Fixed the full-suite DNS SRV failure at its ownership boundary: scenario setup
  no longer mutates the packaged process-global reverse-DNS registry, and DNS,
  proxy, workstation, and SRV hostname resolution consult the current
  generator's scenario-local system map first. Regressions prove both that
  system seeding leaves the global registry unchanged and that a stale mapping
  from an earlier scenario cannot override the current domain controller.
- Updated evaluator, architecture, evidence/scenario references, operational
  skills, configuration docs, and installed-skill/reference gates.
- Permanent tests use only repository-owned model inputs and literal expected
  Zeek-shaped values. They do not download or invoke Zeek and do not read PCAPs.

Verification:

- Fixture-free multipart, HTTP/files, proxy, evaluator, route-profile, skill,
  beacon, and compatibility acceptance set: `280 passed`.
- End-to-end raw and multipart 42 MiB RAR integration: `2 passed`.
- Repository-wide default suite: `5476 passed, 42 skipped` in 344.08 seconds.
- `uv run ruff check .`, `uv run ruff format --check .`, and
  `git diff --check`: passed.
- Version artifacts remain unchanged on the feature branch.
