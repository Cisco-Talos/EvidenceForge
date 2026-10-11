import type { CatalogItem, StudioJob, StudioSnapshot } from "./api";

/** Match retained runs without changing their immutable source paths. */
export function belongsToScenario(job: StudioJob, item: CatalogItem, snapshot: StudioSnapshot): boolean {
  return job.kind === "generation" && (snapshot.source_paths?.[item.id] || [item.path]).includes(job.scenario || "");
}
