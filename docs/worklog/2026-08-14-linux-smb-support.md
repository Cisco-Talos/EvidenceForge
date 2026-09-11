# Linux SMB client and server support

Date: 2026-08-14

## Objective

Extend the canonical SMB storage and activity model from Windows-only behavior to a cross-platform
matrix that includes modeled Linux clients and Samba servers without breaking existing Windows
scenarios, deterministic generation, or source-native evidence boundaries.

## Accepted scope

- Preserve Windows native clients and Windows file-server/domain-controller behavior.
- Add explicit Linux SMB client capability for kernel CIFS mounts and direct `smbclient`. Retain
  desktop/GVFS only as opaque background TCP/445/process texture. Linux hosts do not become SMB
  clients from OS identity alone.
- Add Samba server capability through explicit storage-server configuration or Samba service
  markers. A generic Linux `file_server` role alone does not imply Samba.
- Support POSIX client/server paths, ext4/XFS backing volumes, Linux mount mappings, per-user or
  fixed SMB principals, explicit Kerberos/NTLMSSP selection, and Samba audit tiers.
- Keep backing filesystem distinct from the SMB-native advertised filesystem.
- Upgrade `STORAGE_MANIFEST.json` to schema version 2 for platform, filesystem, mapping,
  credential-mode, and resolved-path metadata.
- Add overlay-aware `activity/smb_profiles.yaml` for client/server process morphology and transport
  ownership; scenario and organization schema continue to own topology and intent.
- Project existing canonical events into platform-eligible Windows Security, Samba syslog,
  OS-neutral Zeek, and eCAR evidence.

## Explicit boundaries

- Generic TCP/445 remains transport-only and does not imply authentication, a tree, or file I/O.
- Mounted CIFS transport is kernel-owned; `mount.cifs` is not attributed to every file operation.
- Direct `smbclient` is operation-scoped. GVFS is resident background texture and does not own typed
  SMB file/auth/session semantics. Samba separates its listener from per-transport `smbd` workers.
- Local application actor, SMB credential principal, and server effective UID/GID remain distinct.
- Routine successful Linux client syslog, kernel CIFS debug output, Linux Audit policy, KSMBD,
  protocol decryption, and SMB POSIX-extension fidelity are outside this initial slice.
- Industry-pack storage catalogs remain provider-neutral vocabulary. Concrete cross-platform
  topology may live in scenario or organization environments; packs do not embed internal
  `smb_profiles.yaml` policy.

## Completion status

The accepted Linux-client and Samba-server SMB2/3 disk-share slice is implemented. Windows native
behavior remains available, while Linux canonical activity resolves to a compatible mounted-CIFS
or direct-`smbclient` profile. Storage compilation and validation now cover POSIX server roots,
Linux mounts, mixed-platform mapping audiences, backing versus advertised filesystems, explicit
SMB principals/authentication, and Samba audit profiles. Generic Linux `file_server` roles and
generic TCP/445 still do not manufacture Samba or typed file activity.

The V1 boundary is enforced rather than silently approximated: KSMBD and Samba AD DC deployment
modes are rejected, and Samba does not receive Windows-reserved or administrative shares. Mapping
validation is per transfer leg, so every modeled client-side leg must have a compatible platform
presentation. Mounted transfers render directionally correct POSIX source/destination operands
instead of reusing a remote share presentation as a local path.

`STORAGE_MANIFEST.json` now uses numeric schema version 2. Share records preserve provider,
platform, network and server-native roots, backing and advertised filesystems, case policy, and
audit profile. Mapping records preserve their audience and explicit platform/type/root
presentations while retaining compatibility `drive`/`mount` fields. Resolved storyline targets
retain the applicable path views without storing credentials or file payloads.

The overlay-aware `activity/smb_profiles.yaml` remains profile schema version 1. Its top level now
contains advertised-filesystem defaults, canonical-to-Samba audit operation policy, client/server
defaults, and client/server profiles. The runtime keeps CIFS transport kernel-owned, renders direct
`smbclient` as an operation process with source-native authentication flags and operands, and
separates Samba's durable listener from its per-transport worker. Documentation and canonical
skill sources were updated together. Ignored `.agents`/`.claude` installer mirrors were regenerated
for smoke verification but remain untracked.

Evidence projection is platform-aware: Windows Security remains Windows-only, Samba lifecycle and
profile-gated VFS audit rows use the existing syslog family, eCAR preserves POSIX paths and
source-native process/session identity, and Zeek uses the advertised filesystem rather than the
Linux backing filesystem. The evaluator recognizes Samba/POSIX evidence and keeps the local actor
distinct from the server-side SMB credential identity.

## Verification

- The Linux SMB integration snapshot now passes 30 cases across the Windows/Linux client and
  Windows/Samba server matrix, including per-leg fixed credentials, denied delete-only moves,
  mounted-CIFS ownership, external clients, encryption, and generic transport-only TCP/445.
- `uv run pytest --no-cov -q tests/unit/test_install_skills.py`: 56 passed. The public scenario and
  evidence references remain byte-identical to their tracked command bundles.
- Resource forecasting advanced from schema v3 to v4 with all-platform Zeek SMB scope and Samba
  syslog fixed/per-operation costs. The retained v3 artifacts preserve history; the v4 artifacts
  record 4 measurements/0 limit violations for active, 3/0 for baseline, and 6/0 for long runs.
- The strict full-profile 31-day PID-chronology gate passed with 14,428 process creates, 14,035
  terminations, 3 safe PID reuses, 4 Linux wraps, and zero overlapping lifetimes, stale
  terminations, or unexplained reversals.
- Source-isolated 31-day Zeek/syslog calibration runs stayed within forecast memory bounds. The
  dedicated bounded-state slow tests, including the mixed Windows/Samba 31-day case, passed. Long
  calibration peak RSS was 224,002,048 bytes, within the 251,358,500-byte forecast upper bound.

`TODO.md` now records the Linux/Samba SMB2/3 slice as complete and retains higher-fidelity SMB
families as explicit deferred work.

## Primary technical references

- Linux CIFS client: <https://docs.kernel.org/admin-guide/cifs/introduction.html>
- Linux CIFS usage/debug interfaces: <https://docs.kernel.org/admin-guide/cifs/usage.html>
- Samba server configuration: <https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html>
- Samba full-audit VFS module:
  <https://www.samba.org/samba/docs/current/man-html/vfs_full_audit.8.html>
- Zeek SMB visibility: <https://docs.zeek.org/en/lts/logs/smb.html>

Exact CIFS, Samba audit, and Zeek field/default claims are version-sensitive. Tests and release
notes should pin the supported kernel/cifs-utils, Samba, and Zeek contract before claiming exact
source-native parity.
