# Invalid First Panel Note

The first attempt-60-d reviewer panel used a shared temporary review copy at:

```text
/private/tmp/research-data-6fGLJ1/dataset
```

That shared copy became contaminated during review. The Detection Engineer saw
source-search output inside
`WS-MCHEN-01.meridianhcs.local/windows_event_security.xml`, while the generated
source package under `scenarios/iteration-test-expanded/data/data/` still
contained clean XML beginning with `<?xml version="1.0" encoding="utf-8"?>`.

Those first-panel scores were discarded and are not included in `scores.json`.
The accepted loop-60 scores come from the clean rerun, which used four separate
read-only review copies:

```text
Threat Hunter: /private/tmp/research-data-th-OfGTeg/dataset
Detection Engineer: /private/tmp/research-data-de-sqEe4V/dataset
Network Forensics: /private/tmp/research-data-nf-apt5Xm/dataset
Host/EDR: /private/tmp/research-data-he-t1iawF/dataset
```
