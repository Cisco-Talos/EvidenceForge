/** Pack-specific facets kept in saved views; rendered through the shared `LibraryFilters`. */
export type PackFilterValues = { publisher: string; version: string; source: string };
export const emptyPackFilters: PackFilterValues = { publisher: "", version: "", source: "" };
