# Root directory native identity — bounded adapter into filesystem ownership

Finding17Host: both Macs expose root/home as adjacent huge inode numbers, with
otherwise shared directory/file metadata. Native read-only public system-path stat
on this macOS27.2.1arm64 host demonstrates presented / inode2 and shared st_dev
across system/data paths. Apple File System Reference pp73/96documents reserved
root identifiers; this native presented-root scope must stay distinct from raw
on-disk system-volume flagged root IDs. Same st_dev is NOT a defect to erase.
Evidence is a single-host qualification, not a native population calibration.

Owning abstractions: optional frozen MacosExecutionMetadataProfile filesystem root
identity policy, canonical MacosExecutionMetadataProducer and installed-filesystem
allocation-conflict guard. Invariant: when apfs_presented_root is explicitly selected,
/ uses the reserved presented root inode2 in its host/volume namespace; home and
ordinary directories retain their allocated nonroot identities, cannot alias root
or installed files, and every process cwd/source view consumes the same directory
observation. Different hosts may validly share inode2. Preserve host/device/object
identity, immutable metadata, exact preparation/retry/recovery, filtering and legacy
profile absence. Do not move identity repair into ES rendering or randomize IDs.

Entry paths: all boot/root jobs, GUI/terminal/login/shell/Finder/SSH/Code and subsequent
exec inherited cwd through the shared metadata producer. Runtime files, special
terminals/devfs and externally explicit native observations retain their owners.
Consumers: canonical execution directories/descriptor context, native ES exec cwd,
State preparation, retained/exact recovery, native-only filter/checkpoints.

Classification adapter_to_family_model / bounded partial repair. The root directory
has a documented role-specific reserved identity that the generic directory allocator
currently ignores. Full installed-system snapshot allocation, sparse/background file
population, directory stat-history realism and process pidversion history need
larger contracts and are not claimed solved. These remain higher score-leverage
findings; this low-risk, source-qualified identity correction can be completed while
those architectural repairs are qualified. Preserve all four authored benchmarkSHA
and reviewer instructions. Source553frozen until actual18gen+postEXIT0; no19engine
changes while those jobs are active.

Primary source:
https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
Native engineering example retained in native-public-system-stat-example.json,
never supplied to blind experts. Do not copy native exact host identifiers into
engine defaults or claim one sample is a calibrated distribution.
