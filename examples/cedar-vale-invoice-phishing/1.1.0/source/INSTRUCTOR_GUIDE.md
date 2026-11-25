# Cedar Vale Advisory - Invoice Phishing: instructor guide

Instructor-only material. Give analysts ENVIRONMENT.md and the generated evidence; this guide and scenario.yaml reveal the intended sequence.

Reconstruct the path from an email lure to user execution, persistence and network tasking.

## Learning questions

1. Which message started the chain, and what differentiates it from the ordinary supplier receipt?
2. Which account and workstation acted on the lure, and what is the evidence for execution rather than delivery alone?
3. What persisted, and how can its command be linked to the downloaded script?
4. What network pattern follows execution, and which endpoint is involved?
5. Which scheduled-task activity is legitimate, and what makes it distinguishable?

## Intended interpretation

The invoice-review corpus entry is delivered to nina.torres on CVA-WS-01. The supplier-themed message directs her to documents.harbor-invoices.example. Browser access is followed by a PowerShell download and execution of statement-viewer.ps1. LedgerUpdateCheck is registered as an ONLOGON task, then a worker polls api.ledger-status.example using json_tasking. The ordinary receipt goes to Evan from harbor-supply.example; Caleb's DeviceInventory activity is on the separate IT workstation. The local logon is session context, not evidence of a second credential compromise.

## Authored timeline

| Offset / time | Actor | System | Intended activity |
|---|---|---|---|
| +1h | nina.torres | CVA-WS-01 | A supplier-themed message arrives in Nina's mailbox. |
| +1h12m | nina.torres | CVA-WS-01 | Nina opens her mailbox over encrypted IMAP. |
| +1h15m | nina.torres | CVA-WS-01 | A browser opens the supplier-themed document page. |
| +1h17m | nina.torres | CVA-WS-01 | A PowerShell download saves the offered reconciliation script. |
| +1h20m | nina.torres | CVA-WS-01 | Nina runs the offered script, establishing the user-context foothold. |
| +1h23m | nina.torres | CVA-WS-01 | The script registers a per-user logon task to rerun itself. |
| +1h25m | nina.torres | CVA-WS-01 | The bootstrap script starts its polling worker after task registration. |
| +1h26m | nina.torres | CVA-WS-01 | The foothold polls a JSON tasking endpoint with variable intervals. |
| +2h30m | nina.torres | CVA-WS-01 | The sender follows up on the earlier invoice message. |

## Benign comparisons

- inventory-task (+3h): Approved inventory work on the IT workstation; distinguish its host, operator and task name from the invoice chain.
- ordinary-supplier-mail (+45m): A legitimate supplier message has a similarly themed subject but different sender identity, recipient and receipt content.

## Capabilities demonstrated

Authored email corpus and attachments; materialized email; encrypted mailbox reads; HTTP download evidence; scheduled-task command effects; the json_tasking beacon profile.

## Modeling and interpretation limits

SMTP STARTTLS and IMAPS protect message contents on the wire. Use the generated email artifacts for message content; a mailbox-access session does not prove which message a person read. External web/mail systems have no defender endpoint logs. Scheduled-task creation is modeled; this exercise does not claim a later reboot or task-triggered re-execution. Cleartext HTTP is deliberate for the document-delivery and tasking portions of this introductory example.

## Evidence acceptance

This guide describes authored intent, not a reviewed generated dataset. Input validation and publication do not prove that every intended observation appears. After generation, inspect the run-owned GROUND_TRUTH.md/JSON, collection/observation manifests, relevant artifacts and exact process/session/network relationships, then evaluate the bundle. Do not invent a missing source, relax an acceptance threshold or treat absent telemetry as proof of nonexecution.
