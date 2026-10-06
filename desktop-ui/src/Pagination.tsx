export function Pagination({ page, pageSize, matching, unit, label, names, onPage }: {
  page: number; pageSize: number; matching: number; unit: string; label: string;
  names: { first: string; previous: string; next: string; last: string; page: (number: number) => string };
  onPage: (page: number) => void;
}) {
  const last = Math.max(0, Math.ceil(matching / pageSize) - 1);
  const current = Math.min(page, last);
  const start = current * pageSize;
  const numbers = [...new Set([0, last, ...Array.from({ length: 5 }, (_, offset) => current - 2 + offset)])]
    .filter((number) => number >= 0 && number <= last).sort((left, right) => left - right);
  return <nav className="declarations-pagination" aria-label={label}>
    <span className="muted">{matching ? start + 1 : 0}–{Math.min(start + pageSize, matching)} of {matching} {unit}</span>
    <div><button className="button-quiet" disabled={current === 0} onClick={() => onPage(0)} aria-label={names.first}>First</button>
      <button className="button-quiet" disabled={current === 0} onClick={() => onPage(current - 1)} aria-label={names.previous}>Previous</button>
      {numbers.map((number, index) => <span className="declaration-page-choice" key={number}>
        {index > 0 && number - numbers[index - 1] > 1 && <span aria-hidden="true" className="pagination-gap">…</span>}
        <button className="button-quiet" aria-label={names.page(number + 1)} aria-current={current === number ? "page" : undefined} onClick={() => onPage(number)}>{number + 1}</button>
      </span>)}
      <button className="button-quiet" disabled={current === last || !matching} onClick={() => onPage(current + 1)} aria-label={names.next}>Next</button>
      <button className="button-quiet" disabled={current === last || !matching} onClick={() => onPage(last)} aria-label={names.last}>Last</button>
    </div>
  </nav>;
}
