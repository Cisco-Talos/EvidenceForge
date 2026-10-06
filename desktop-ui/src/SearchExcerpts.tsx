import type { CatalogItem } from "./api";

function Highlight({ text, ranges }: { text: string; ranges: number[][] }) {
  const pieces: React.ReactNode[] = [];
  const characters = Array.from(text);
  let cursor = 0;
  for (const [start, end] of ranges) {
    pieces.push(characters.slice(cursor, start).join(""), <mark key={`${start}:${end}`}>{characters.slice(start, end).join("")}</mark>);
    cursor = end;
  }
  pieces.push(characters.slice(cursor).join(""));
  return <>{pieces}</>;
}

export function SearchExcerpts({ item }: { item: CatalogItem }) {
  const matches = item.search_matches || [];
  if (!matches.length) return item.search_excerpt ? <span className="scenario-search-excerpt"><span>{item.search_field} match</span><code>{item.search_excerpt}</code></span> : null;
  const remaining = Math.max(0, (item.search_match_count || 0) - matches.length);
  return <span className="search-excerpts" aria-label="Search matches">{matches.map((match, index) => <span className="scenario-search-excerpt" key={index} title={`${match.file ? `${match.file}:${match.line} · ` : ""}${match.field} (${match.kind})`}>
    <span className="search-match-origin">{match.file ? `${match.file}:${match.line}` : ""}{match.file && " · "}{match.field}{match.kind === "key" ? " · field name" : match.kind === "comment" ? " · comment" : ""}</span>
    <code><Highlight text={match.excerpt} ranges={match.highlights || []} /></code>
  </span>)}{remaining > 0 && <span className="search-more" title="Additional matching fields or source lines; repeated occurrences in one field count once">[and {remaining} more]</span>}</span>;
}
