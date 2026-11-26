# RC4 qualification

RC4 uses the existing release checks and release-mode installers with the
`qualify-only=true` dispatch option. Installers follow the test gates.
The publish job is skipped and no tag is created. Publication requires the
user's review and a separate release dispatch for the qualified source SHA.

- The first candidate at `d54afbf3` passed the Windows Python pack regressions.
  Its Windows Studio job exposed host-specific diagram export names. Windows
  treated `a:b` as a drive-relative path. Commit `01d9bb24` makes filename
  parsing consistent before applying the PNG filename rules.
  [Initial qualification](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/45827259810)
- The qualification at `01d9bb24` passed routine release CI, Linux coverage,
  native Studio/recovery and the evaluation-memory and portability jobs.
  Slow shard 1 exceeded its 30-second test-harness deadline for the late
  checkpoint marker. The individual case passed locally. Slow shard 3 reached
  the 120-minute runner limit while comparing complete iteration scenario
  output after a checkpoint resume. The other three shards passed.
  [Second qualification](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/45838517370)
- Costs from four JUnit reports and the partial third-shard log covered 1,884
  of the 2,272 collected slow cases. Updating 25 underestimated costs and
  using six shards brought the longest projected shard from about 145 to
  99 minutes. The existing 120-minute runner limit and all tests remain in
  the qualification gate. The late checkpoint test allows 60 seconds to
  reach its ready marker, then checks the original signal and byte contracts.
- An RC4 source startup with a fresh private profile enrolled all five 1.1.0
  examples and indexed Northstar Health 1.2.0, MetroLink Specialty Care 1.1.0
  and Talus Enterprises 1.0.0 from the bundled catalogs.
