# Loop 4 family contract

- **Family / classification:** non-empty process-produced file content erased to
  zero length on downstream transfer; recurring `sibling_defect` adjacent to the
  canonical empty-file identity issue from loop 2.
- **Owner:** process command-effect planning and canonical runtime artifact
  publication (`ProcessPreflightPlanner` / `RuntimeContentIdentityManager`),
  where file content length is first committed to the shared file identity.
- **Invariant:** successful commands whose semantics necessarily produce data
  publish a non-empty canonical file identity, and every later read, SCP/SMB
  transfer, file observation, and destination write preserves that same content
  identity and modeled length. Empty output remains valid only where the command
  or source artifact actually establishes emptiness.
- **Entry paths:** typed process effects (including SQL export redirection,
  gzip/tar/zip output), runtime file publication, SCP source resolution, and
  SMB copy to modeled shares. Inspect generic/ambient file effects as sibling
  paths before narrowing the change to command-owned outputs.
- **Consumers:** `FileContentIdentity`, eCAR file events, canonical file
  transfer bundles, Zeek `files.json`/`smb_files.json`, and server audit output.
- **Rationale:** the generated `SMB::FILE_WRITE` and Zeek file record report
  `size=0` and empty-payload digests for a successful staged `.sql.gz`; the
  DB process history and eCAR show successful `mysqldump`, `gzip`, SCP process
  creation and source-file read. The shared artifact identity is the earliest
  point that can keep sibling transfer formats consistent. Fixing only Zeek or
  Samba audit renderers would preserve the contradiction elsewhere.
- **Sibling risk:** avoid turning genuinely empty created files into non-empty
  files, preserve explicit source sizes, keep archive output and source reads
  correlated, retain deterministic scoped sizing, and avoid unrelated baseline
  storage-file sizing changes.
- **Fix type:** `family_level` if process-owned source output size is modeled
  canonically and preserved through transfer; otherwise defer and label the
  narrowing explicitly.
