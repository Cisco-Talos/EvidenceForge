import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { SearchExcerpts } from "../src/SearchExcerpts";
import type { CatalogItem } from "../src/api";

afterEach(cleanup);

test("shows contextual highlighted matches and the number omitted", () => {
  const item = { search_matches: [
    { field: "environment.systems[0].hostname", file: "hosts.yaml", line: 9, kind: "value", excerpt: "workstation-17", highlights: [[0, 4]] },
    { field: "network_identities", file: "scenario.yaml", line: 24, kind: "key", excerpt: "network_identities", highlights: [[3, 7]] },
  ], search_match_count: 9 } as unknown as CatalogItem;
  const { container } = render(<SearchExcerpts item={item} />);
  expect(screen.getByText("hosts.yaml:9 · environment.systems[0].hostname")).toBeVisible();
  expect(screen.getByText("scenario.yaml:24 · network_identities · field name")).toBeVisible();
  expect(container.querySelectorAll("mark")).toHaveLength(2);
  expect(container.querySelector("mark")).toHaveTextContent("work");
  expect(screen.getByText("[and 7 more]")).toBeVisible();
});

test("hides empty excerpts and escapes authored markup", () => {
  const { container, rerender } = render(<SearchExcerpts item={{} as CatalogItem} />);
  expect(container).toBeEmptyDOMElement();
  rerender(<SearchExcerpts item={{ search_matches: [{ field: "description", file: "", line: 0, kind: "metadata", excerpt: "<script>work</script>", highlights: [[8, 12]] }], search_match_count: 1 } as unknown as CatalogItem} />);
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("code")).toHaveTextContent("<script>work</script>");
  expect(screen.queryByText(/and .* more/)).toBeNull();
});
