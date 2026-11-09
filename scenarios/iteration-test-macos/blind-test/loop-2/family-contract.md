# Loop 2 family contract

- **Family / classification:** canonical empty-file digest contradiction; `sibling_defect` in file-content identity semantics.
- **Owner:** `FileContentIdentity` in `events/content_identity.py`.
- **Invariant:** a canonical file with zero bytes has the standard MD5, SHA-1, and SHA-256 digests of empty content wherever a source exposes hashes; identity IDs may remain object/version scoped.
- **Entry paths:** SMB file writes/reads, HTTP transfer metadata, file-transfer bundles, and any emitter consuming `FileContentIdentity.digests`.
- **Consumers:** Zeek `files.log`, SMB/file contexts, endpoint renderers, and canonical content-correlation checks.
- **Rationale:** size and content digest semantics are owned by the shared content identity model; emitters only project those facts.
- **Sibling risk:** non-empty files still use metadata-only deterministic digests; this change does not claim their digest bytes are reconstructible or alter size accounting.
- **Fix type:** `family_level`.

## Secondary family: mounted Mac SMB helper process starts

- **Owner:** persistent SMB action bundle delegated to the existing `ProcessExecutionService`.
- **Invariant:** a mounted Mac helper launched for SMB activity is a canonical process execution whose fork, exec, identity, executable facts, and later close are published by the same process lifecycle owner used by other Mac commands.
- **Entry paths:** persistent SMB reads/writes and the sibling ordinary SMB activity path; existing process reuse remains a reuse path.
- **Consumers:** StateManager process census, Mac ES occurrence ingress, eCAR endpoint evidence, and SMB transport/file projections.
- **Rationale:** SMB owns file and transport phases, while process execution owns process birth/exec/exit and native publication. Creating aggregate process state inside SMB bypasses the established process source contract.
- **Sibling risk:** retry after an operation owner has already started must reuse its exact lifecycle identity when still live; source-visible ordering must keep process evidence before transport.
- **Fix type:** `adapter_to_family_model`.
