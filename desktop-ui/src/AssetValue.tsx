import { Fragment } from "react";
import { labelFor } from "./assetSchema";
import { includesPath, OverrideMark } from "./assetOverrides";

export function AssetValue({ value, path = "", overrides }: { value: unknown; path?: string; overrides?: string[] }) {
  if (value === undefined || value === null) return <span className="muted">Not set</span>;
  if (typeof value === "boolean") return <span>{value ? "Yes" : "No"}</span>;
  if (Array.isArray(value)) {
    if (!value.length) return <span className="muted">None</span>;
    if (value.every((entry) => typeof entry !== "object")) return <div className="asset-value-tags">{value.map((entry, index) => <span key={index} className="asset-value-tag">{String(entry)}</span>)}</div>;
    return <ol className="asset-value-list">{value.map((entry, index) => <li key={index}><AssetValue value={entry} path={`${path}.${index}`} overrides={overrides} /></li>)}</ol>;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) return <span className="muted">None</span>;
    return <dl className="asset-value-object">{entries.map(([name, entry]) => { const childPath = path ? `${path}.${name}` : name; const customized = includesPath(overrides, childPath); return <Fragment key={name}><dt className={customized ? "asset-customized-value" : ""}>{labelFor(name)} {customized && <OverrideMark />}</dt><dd className={customized ? "asset-customized-value" : ""}><AssetValue value={entry} path={childPath} overrides={overrides} /></dd></Fragment>; })}</dl>;
  }
  return <span className="asset-value-text">{String(value)}</span>;
}
