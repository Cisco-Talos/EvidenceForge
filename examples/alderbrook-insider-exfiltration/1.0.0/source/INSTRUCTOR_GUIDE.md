# Alderbrook Lending - Insider Data Theft: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Evaluate intent and scope when an insider uses valid access and ordinary tools.

## Learning questions

1. What makes the late activity different from the employee's earlier single-document review?
2. Which quarterly files are selected, and where do local copies go?
3. What process creates the archive, and what later process reads it for transmission?
4. What does the destination and timing establish, and what cannot be inferred from encrypted traffic alone?
5. How does Tessa's approved export help constrain a detection?

## Intended interpretation

Jules Parker has legitimate Lending-group access. A normal review occurs at +2h; a later local logon at +11h5m is followed by enumeration and collection of all eight seeded quarterly review workbooks into a temporary Review directory. PowerShell archives the copied Reviews subtree as board-review.zip, and curl uploads it to a personal workspace at upload.workspace-sync.example. The instructor premise establishes the destination as personal and unauthorized; the logs alone do not establish organizational approval. Tessa's smaller daytime export goes to her ordinary Documents directory and supplies a comparison.

## Authored timeline

| Offset / time | Actor | System | Intended activity |
|---|---|---|---|
| +2h | jules.parker | ABL-WS-01 | The employee performs an ordinary single-document review during business hours. |
| +11h5m | jules.parker | ABL-WS-01 | The employee returns to the workstation well after the normal workday. |
| +11h10m | jules.parker | ABL-WS-01 | The employee enumerates the complete quarterly review directory. |
| +11h14m | jules.parker | ABL-WS-01 | Quarterly loan reviews are copied into a local temporary directory using the employee's normal permissions. |
| +11h20m | jules.parker | ABL-WS-01 | The collected review directory is compressed into one local archive. |
| +11h28m | jules.parker | ABL-WS-01 | The archive is uploaded to a personal workspace at an external file-transfer service. |

## Benign comparisons

- approved-portfolio-export (+3h): Approved daytime review copies provide a comparison for account, timing, volume, staging path and subsequent destination; bulk access alone is not proof of misuse.

## Capabilities demonstrated

Finance storage vocabulary; exact seeded files; mapped-drive SMB browsing and bounded collection; local archive command effects; file-backed multipart upload intent; a full day of business-hour context.

## Modeling and interpretation limits

There is no stolen account, exploit or malware in this storyline. Permission to read a share does not establish permission to export its data. The intended upload is file-backed multipart, but TLS keeps its form fields and archive contents out of network HTTP/file inspection. Use endpoint command/file evidence with connection bytes, destination and timing. The exact archive bytes and any generated transfer evidence are owned by generation, not a prewritten ZIP shipped here.

## Evidence acceptance

This guide describes authored intent, not a reviewed generated dataset. Input validation and publication do not prove that every intended observation appears. After generation, inspect the run-owned GROUND_TRUTH.md/JSON, collection/observation manifests, relevant artifacts and exact process/session/network relationships, then evaluate the bundle. Do not invent a missing source, relax an acceptance threshold or treat absent telemetry as proof of nonexecution.
