import { Empty, QueryLink, usePage } from "../common";
import type { HostTimeline as HostTimelineData, TimelineChange, TimelineEntry, TimelineState } from "../types";

type TimelineQuery = { page: number; showUnchanged: boolean };
type TimelineNavigation =
  | { type: "show-unchanged"; enabled: boolean }
  | { type: "newer" }
  | { type: "older" }
  | { type: "first-page" };

function transitionTimelineQuery(current: TimelineQuery, event: TimelineNavigation, pages: number): TimelineQuery {
  switch (event.type) {
    case "show-unchanged": return { page: 1, showUnchanged: event.enabled };
    case "first-page": return { ...current, page: 1 };
    case "newer": return { ...current, page: Math.max(1, Math.min(pages, current.page - 1)) };
    case "older": return { ...current, page: Math.min(pages, current.page + 1) };
  }
}

export function timelineUrl(page: number, showUnchanged: boolean) {
  const params = new URLSearchParams(location.search);
  params.set("timeline_page", String(Number.isSafeInteger(page) && page > 0 ? page : 1));
  params.set("timeline_unchanged", String(showUnchanged));
  return `?${params.toString()}#timeline`;
}

export function TimelineTime({ entry }: { entry: TimelineEntry }) {
  return <><span>{entry.source === "manual" ? "Action time" : entry.time_source === "scan" ? "Scan time" : "Import time"}: </span><time dateTime={entry.occurred_at}>{new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(entry.occurred_at))}</time></>;
}

export function timelineSummary(entry: TimelineEntry) {
  const added = entry.changes.filter((change) => change.kind === "added").length;
  const changed = entry.changes.filter((change) => change.kind === "changed").length;
  const removed = entry.changes.filter((change) => change.kind === "removed").length;
  const parts = [];
  if (entry.source === "manual") parts.push("Manual service change");
  if (entry.source === "scan" && entry.first_seen) parts.push("First seen · baseline");
  if (added) parts.push(`${added} added`);
  if (changed) parts.push(`${changed} changed`);
  if (removed) parts.push(`${removed} removed`);
  if (!entry.changes.length && !entry.first_seen && !entry.not_reported.length) parts.push("No observed changes");
  if (entry.not_reported.length) parts.push(`${entry.not_reported.length} not reported`);
  return parts.join(" · ");
}

const fields: { key: keyof TimelineState; label: string }[] = [
  { key: "state", label: "State" },
  { key: "service_name", label: "Service name" },
  { key: "product", label: "Product" },
  { key: "version", label: "Version" },
];

function ChangeDetail({ change, manual }: { change: TimelineChange; manual: boolean }) {
  return <details className="min-w-0 rounded border px-3 py-2">
    <summary className="cursor-pointer break-words text-sm">
      <span className="mono font-semibold">{change.port}/{change.proto}</span>{" · "}
      {change.kind === "added" ? "Added" : change.kind === "removed" ? "Removed" : "Changed"}{" · "}{change.after?.state ?? "Removed from inventory"}
      {change.after?.service_name ? ` · ${change.after.service_name}` : ""}
      <span className="muted"> — field differences</span>
    </summary>
    <div className="mt-3 space-y-3 text-xs">
      {fields.filter(({ key }) => !change.before || !change.after || change.before[key] !== change.after[key] || (manual && change.before_overrides?.[key] !== change.after_overrides?.[key])).map(({ key, label }) => (
        <div key={key} className="min-w-0">
          <h4 className="font-semibold">{label}</h4>
          <dl className="mt-1 grid grid-cols-2 gap-3">
            <div className="min-w-0"><dt className="muted">Before</dt><dd className="mono whitespace-pre-wrap break-all">{change.before ? (change.before[key] ?? "Not reported") : manual ? "Not in inventory" : "Not previously observed"}</dd></div>
            <div className="min-w-0"><dt className="muted">After</dt><dd className="mono whitespace-pre-wrap break-all">{change.after ? (change.after[key] ?? "Not reported") : "Removed from inventory"}</dd></div>
          </dl>
          {manual && (change.before_overrides || change.after_overrides) && <dl className="mt-2 grid grid-cols-2 gap-3">
            <div className="min-w-0"><dt className="muted">Before override</dt><dd className="mono whitespace-pre-wrap break-all">{change.before ? (change.before_overrides?.[key] ?? "Use scan value") : "Not in inventory"}</dd></div>
            <div className="min-w-0"><dt className="muted">After override</dt><dd className="mono whitespace-pre-wrap break-all">{change.after ? (change.after_overrides?.[key] ?? "Use scan value") : "Removed from inventory"}</dd></div>
          </dl>}
        </div>
      ))}
    </div>
  </details>;
}

type TimelineContent = "unavailable" | "events" | "empty-page" | "no-matching-events" | "no-history";

export function HostTimeline({ timeline }: { timeline?: HostTimelineData }) {
  const { updateQuery, queryPending } = usePage();
  const query: TimelineQuery = { page: timeline?.page ?? 1, showUnchanged: timeline?.show_unchanged ?? false };
  const { page, showUnchanged } = query;
  const pages = Math.max(1, timeline?.pages ?? 1);
  const content: TimelineContent = !timeline ? "unavailable"
    : timeline.entries.length ? "events"
    : page !== 1 || timeline.total > 0 || timeline.latest_change ? "empty-page"
    : !showUnchanged ? "no-matching-events"
    : "no-history";
  const firstPage = transitionTimelineQuery(query, { type: "first-page" }, pages);
  const newer = transitionTimelineQuery(query, { type: "newer" }, pages);
  const older = transitionTimelineQuery(query, { type: "older" }, pages);
  return <section aria-label="Host service history" aria-busy={queryPending} className="min-w-0 space-y-4 pe-3 pb-3" style={{ flex: "1 1 0%", minHeight: 0, overflowY: "auto", scrollbarGutter: "stable" }}>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 className="text-sm font-semibold">Host service history</h2>
      <label className="flex min-h-6 cursor-pointer items-center gap-2 text-sm">
        <input type="checkbox" name="timeline_unchanged" checked={showUnchanged} disabled={queryPending} onChange={(event) => {
          if (queryPending) return;
          const next = transitionTimelineQuery(query, { type: "show-unchanged", enabled: event.target.checked }, pages);
          updateQuery(timelineUrl(next.page, next.showUnchanged));
        }} />
        Show unchanged scans
      </label>
    </div>
    <p className="muted text-xs">Scan evidence and manual service changes, newest first. Missing ports in scans do not prove a service is closed.</p>
    {content !== "events" ? <Empty>
      {content === "unavailable" ? <><p>Service history is unavailable.</p><QueryLink className="underline underline-offset-4" href={timelineUrl(1, showUnchanged)}>Reload service history</QueryLink></>
        : content === "empty-page" ? <><p>No events on this timeline page.</p><QueryLink className="underline underline-offset-4" href={timelineUrl(firstPage.page, firstPage.showUnchanged)}>Return to the newest events</QueryLink></>
        : content === "no-matching-events" ? <><p>No change events to show.</p><QueryLink className="underline underline-offset-4" href={timelineUrl(1, true)}>Show unchanged scans</QueryLink></>
        : <><p>No service history for this host yet.</p><p>Ingest a scan containing this host or add, edit, or remove a service to record an event.</p></>}
    </Empty> : <ol className="space-y-4">
      {(timeline?.entries ?? []).map((entry) => <li key={entry.id} className="min-w-0 rounded border p-3">
        <article className="min-w-0 space-y-3">
          <header className="min-w-0 space-y-1">
            <h3 className="break-words text-sm font-semibold"><TimelineTime entry={entry} /></h3>
            {entry.source === "scan" && <p className="muted break-all text-xs">{entry.filename} · {entry.tool} · Scan #{entry.scan_id}</p>}
            {entry.time_source === "import" && <p className="muted text-xs">Scan time unavailable; ordered by import time.</p>}
            <p className="text-sm">{timelineSummary(entry)}</p>
            {entry.source === "scan" && entry.first_seen && <p className="muted text-xs">First scan evidence for this host; establishes the baseline.</p>}
            {entry.source === "scan" && !entry.coverage_known && <p className="muted text-xs">Coverage unknown: this scan cannot establish the state of unreported ports.</p>}
          </header>
          {!!entry.changes.length && <div className="space-y-2">{entry.changes.map((change) => <ChangeDetail key={`${change.port}/${change.proto}`} change={change} manual={entry.source === "manual"} />)}</div>}
          {entry.source === "scan" && !!entry.not_reported.length && <details className="min-w-0 text-xs">
            <summary className="cursor-pointer py-1">Not reported ({entry.not_reported.length}) — not closed</summary>
            <p className="muted mt-2">These previously observed ports were not reported. Their last known states are retained.</p>
            <ul className="mono mt-2 flex flex-wrap gap-x-4 gap-y-1">{entry.not_reported.map((port) => <li className="break-all" key={`${port.port}/${port.proto}`}>{port.port}/{port.proto}</li>)}</ul>
          </details>}
        </article>
      </li>)}
    </ol>}
    {(timeline?.total ?? 0) > 0 && <nav aria-label="Timeline pagination" className="flex flex-wrap items-center justify-between gap-3 text-xs">
      <span className="muted">{timeline?.total} events · Page {page} of {pages}</span>
      <div className="flex flex-wrap gap-4">
        {page > 1 && <QueryLink className="inline-flex min-h-6 items-center underline underline-offset-4" href={timelineUrl(newer.page, newer.showUnchanged)}>Newer events</QueryLink>}
        {page < pages && <QueryLink className="inline-flex min-h-6 items-center underline underline-offset-4" href={timelineUrl(older.page, older.showUnchanged)}>Older events</QueryLink>}
      </div>
    </nav>}
  </section>;
}
