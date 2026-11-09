# Loop 16 root-cause probe

The shared Mac execution metadata producer previously assigned `directory_first_inode: 1099511627776` and `directory_age_seconds: 31536000` to every modeled root/home directory on every host. Loop 16 replaced these constants with bounded inode and age ranges; allocation is stable per host and path metadata time is stable per host/path.

Fresh Endpoint Security cwd observations:

| Host | Path | Inode | Birth time UTC | Age from window start |
|---|---|---:|---|---:|
| MAC-MROSS-01 | `/` | 2,061,341,048,677 | 2026-07-17 21:35:16 | ~107 days |
| MAC-MROSS-01 | `/Users/maya.ross` | 2,061,341,048,678 | 2026-01-22 08:16:17 | ~284 days |
| MAC-MROSS-02 | `/` | 2,176,108,086,486 | 2025-08-13 13:51:53 | ~446 days |
| MAC-MROSS-02 | `/Users/maya.ross` | 2,176,108,086,487 | 2025-03-25 18:13:26 | ~587 days |

The profile bounds are inode 1,099,511,627,776–2,199,023,255,552 and age 2,592,000–63,072,000 seconds. Tests instantiate two producers from identical frozen inputs and verify byte-stable metadata, distinct host inode bands, unique per-host directory inodes, and age bounds. `MacosInstalledFilesystem.directory_volume` still owns non-overlap with provisioned installed-file inodes. The 117-file blind copy is byte-identical to fresh output.
