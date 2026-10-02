import { useState } from "react";
import { ChevronRight, FileCode2, Search } from "lucide-react";
import type { CatalogItem, EnvironmentReport, StudioApi } from "./api";
import { BundleFileBrowser } from "./BundleFileBrowser";

type Declaration = EnvironmentReport["declarations"][number];
const PAGE_SIZE = 10;

function valueText(entry: Declaration, pretty = false): string {
  if (!entry.value_found) return "Value unavailable";
  if (typeof entry.value === "string") return entry.value || '""';
  return JSON.stringify(entry.value, null, pretty ? 2 : undefined);
}

export function SourceDeclarations({ item, report, api, onError }: {
  item: CatalogItem; report: EnvironmentReport; api: StudioApi; onError: (message: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [viewing, setViewing] = useState<Declaration | null>(null);
  const all = report.declarations || [];
  const matching = all.filter((entry) => `${entry.path} ${valueText(entry)} ${entry.layer} ${entry.source}`.toLowerCase().includes(query.trim().toLowerCase()));
  const lastPage = Math.max(0, Math.ceil(matching.length / PAGE_SIZE) - 1);
  const currentPage = Math.min(page, lastPage);
  const start = currentPage * PAGE_SIZE;
  const pageNumbers = [...new Set([0, lastPage, ...Array.from({ length: 5 }, (_, offset) => currentPage - 2 + offset)])]
    .filter((number) => number >= 0 && number <= lastPage).sort((left, right) => left - right);
  function view(entry: Declaration) {
    if (entry.source_key && report.compiled_sha256) setViewing(entry);
  }
  return <>
    <details className="surface source-declarations" open={expanded} onToggle={(event) => setExpanded(event.currentTarget.open)}>
      <summary><ChevronRight size={17} className="disclosure-chevron" /><h2>Source declarations</h2><span className="muted">{all.length} fields</span></summary>
      {expanded && <div className="declarations-content">
        <p className="muted">Find the value an input file declared and open its YAML. These are input values; later composition or configuration can change the effective value.</p>
        <div className="search-box"><Search size={15} /><input aria-label="Search environment origins" placeholder="Search fields, values, layers, or files…" value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }} /></div>
        <div className="environment-origins"><table><thead><tr><th>Field / layer</th><th>Declared value</th><th>Declaring YAML</th></tr></thead><tbody>{matching.slice(start, start + PAGE_SIZE).map((entry) => {
          const text = valueText(entry);
          const canView = !!entry.source_key && !!report.compiled_sha256;
          return <tr key={`${entry.layer}:${entry.path}`} className={canView ? "declaration-viewable" : ""} onClick={() => view(entry)}>
            <td><button className="declaration-field" disabled={!canView} title={entry.path} aria-label={`View declaring YAML for ${entry.path}`} onClick={(event) => { event.stopPropagation(); view(entry); }}><code>{entry.path}</code></button><span className="origin-layer">{entry.layer}</span></td>
            <td>{text.length > 120 || (entry.value !== null && typeof entry.value === "object") ? <details className="declaration-value" onClick={(event) => event.stopPropagation()}><summary title={text}>{text.length > 120 ? `${text.slice(0, 117)}…` : text}</summary><pre>{valueText(entry, true)}</pre></details> : <span className={entry.value_found ? "declaration-scalar" : "muted"}>{text}</span>}</td>
            <td><button className="declaration-source" disabled={!canView} title={entry.source} aria-label={`View ${entry.source} for ${entry.path}`} onClick={(event) => { event.stopPropagation(); view(entry); }}><FileCode2 size={14} /><span>{entry.source}{entry.line ? `:${entry.line}` : ""}</span></button></td>
          </tr>;
        })}</tbody></table>{!matching.length && <p className="muted">{all.length ? "No matching declarations." : "No source declarations are available for these inputs."}</p>}</div>
        {!!matching.length && <nav className="declarations-pagination" aria-label="Source declaration pages"><span className="muted">{start + 1}–{Math.min(start + PAGE_SIZE, matching.length)} of {matching.length} fields</span><div><button className="button-quiet" disabled={currentPage === 0} onClick={() => setPage(0)} aria-label="First declarations page">First</button><button className="button-quiet" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} aria-label="Previous declarations">Previous</button>{pageNumbers.map((number, index) => <span className="declaration-page-choice" key={number}>{index > 0 && number - pageNumbers[index - 1] > 1 && <span aria-hidden="true" className="pagination-gap">…</span>}<button className="button-quiet" aria-label={`Declarations page ${number + 1}`} aria-current={currentPage === number ? "page" : undefined} onClick={() => setPage(number)}>{number + 1}</button></span>)}<button className="button-quiet" disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)} aria-label="Next declarations">Next</button><button className="button-quiet" disabled={currentPage === lastPage} onClick={() => setPage(lastPage)} aria-label="Last declarations page">Last</button></div></nav>}
      </div>}
    </details>
    {viewing?.source_key && report.compiled_sha256 && <BundleFileBrowser initialLine={viewing.line} kind="declarations" jobId={item.id} files={{ root: `Read-only captured input · ${report.compiled_sha256.slice(0, 12)}`, files: [{ path: `${report.compiled_sha256}/${viewing.source_key}`, size: viewing.source_size || 0 }], truncated: false }} api={api} onClose={() => setViewing(null)} onError={onError} />}
  </>;
}
