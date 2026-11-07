import { ScopedLink, engagementUrl } from "./common";
import { Textarea } from "@/components/ui/textarea";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ListFilter,
  Pencil,
  Plus,
  Search,
  RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableHeader,
  TableRow,
  TableHead,
  TableBody,
  TableCell,
} from "@/components/ui/table";
import {
  PageContext,
  PageHeader,
  Field,
  SelectField,
  Modal,
  MutationForm,
  Filters,
  SortLink,
  Empty,
  Section,
} from "./common";
import type { HostRow, PageData } from "./types";
import { AppShell, navigation } from "./components/app-shell";

const HostPage = lazy(() =>
  import("./pages/host").then((module) => ({ default: module.HostPage })),
);
const CredentialsPage = lazy(() =>
  import("./pages/credentials").then((module) => ({
    default: module.CredentialsPage,
  })),
);
const ScansPage = lazy(() =>
  import("./pages/scans").then((module) => ({ default: module.ScansPage })),
);
const DiffPage = lazy(() =>
  import("./pages/scans").then((module) => ({ default: module.DiffPage })),
);
const OperationsPage = lazy(() =>
  import("./pages/operations").then((module) => ({
    default: module.OperationsPage,
  })),
);

function HostTable({
  rows,
  sortable = false,
}: {
  rows: HostRow[];
  sortable?: boolean;
}) {
  if (!rows.length)
    return (
      <Empty>
        No hosts match this view. Import a scan or add a host to start recon.
      </Empty>
    );
  const heading = (column: string, label: string) =>
    sortable ? <SortLink column={column}>{label}</SortLink> : label;
  return (
    <Table className={sortable ? "inventory-table" : undefined}>
      <TableHeader>
        <TableRow>
          <TableHead className="w-28">{heading("change", "Change")}</TableHead>
          <TableHead>{heading("ip", "Host / address")}</TableHead>
          <TableHead>{heading("ports", "Open services")}</TableHead>
          <TableHead>{heading("status", "Triage")}</TableHead>
          <TableHead>Tags</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.id}>
            <TableCell>
              {row.change ? (
                <Badge variant={row.change === "new" ? "default" : "secondary"}>
                  {row.change}
                </Badge>
              ) : (
                <span className="muted">—</span>
              )}
            </TableCell>
            <TableCell>
              <ScopedLink className="mono font-semibold text-primary hover:underline"
              href={"/hosts/" + row.id}
              title={[row.ip, ...row.hostnames].join(" · ")}>{row.ip}</ScopedLink>
              {!!row.hostnames.length && (
                <div className="mt-0.5 whitespace-normal break-words text-xs text-muted-foreground">
                  {row.hostnames.join(" · ")}
                </div>
              )}
            </TableCell>
            <TableCell>
              {sortable && row.open_count > 0 && (
                <ScopedLink href={`/hosts/${row.id}#services`} className="block text-xs">{row.open_count} open
                                </ScopedLink>
              )}
              <div
                className="flex max-w-xl flex-wrap gap-1"
                title={row.open_services
                  .map(([port, name]) => `${port} ${name}`)
                  .join(", ")}
              >
                {row.open_services.map(([port, name]) => (
                  <ScopedLink key={port}
                  href={"/hosts/" + row.id + "#services"}
                  className="rounded border bg-muted/40 px-1 text-xs"><span className="mono font-medium">{port}</span>
                  {name && (
                    <span className="ml-1 text-muted-foreground">{name}</span>
                  )}</ScopedLink>
                ))}
                {!row.open_count && (
                  <span className="muted">No open services</span>
                )}
              </div>
            </TableCell>
            <TableCell>
              {row.triaged && <Badge variant="outline">{row.status}</Badge>}
            </TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1" title={row.tags.join(", ")}>
                {row.tags.map((tag) => (
                  <Badge key={tag} variant="secondary">
                    {tag}
                  </Badge>
                ))}
              </div>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
function Inventory({ data }: { data: PageData }) {
  const viewport = useRef<HTMLDivElement>(null);
  const [capacity, setCapacity] = useState(0);
  const [result, setResult] = useState<{
    source: PageData;
    data: PageData;
    capacity: number;
  }>();
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const current = result?.source === data ? result.data : data;
  const ready = result?.source === data && result.capacity === capacity;
  const filtered = Boolean(
    data.q || data.port || data.tag || data.status || data.change,
  );

  useEffect(() => {
    const element = viewport.current;
    if (!element) return;
    const resize = () => {
      const rowHeight = Number.parseFloat(
        getComputedStyle(element).getPropertyValue("--inventory-row-height"),
      );
      const headerHeight =
        element.querySelector("thead")?.getBoundingClientRect().height ?? 32;
      setCapacity(
        Math.max(
          1,
          Math.min(
            50,
            Math.floor((element.clientHeight - headerHeight - 1) / rowHeight),
          ),
        ),
      );
    };
    const observer = new ResizeObserver(resize);
    observer.observe(element);
    resize();
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!capacity) return;
    const controller = new AbortController();
    const params = new URLSearchParams(location.search);
    const previousSize = Number(params.get("fit"));
    if (previousSize > 0 && previousSize !== capacity) {
      const firstRow =
        (Math.max(1, Number(params.get("page")) || 1) - 1) * previousSize;
      params.set("page", String(Math.floor(firstRow / capacity) + 1));
    }
    params.set("fit", String(capacity));
    params.delete("per");
    void fetch(engagementUrl(`/?${params}`), {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`Unable to load hosts (${response.status})`);
        const next = (await response.json()) as PageData;
        if (controller.signal.aborted) return;
        params.set("page", String(next.page ?? 1));
        history.replaceState(null, "", engagementUrl(`/?${params}`));
        setError("");
        setResult({ source: data, data: next, capacity });
      })
      .catch((cause: unknown) => {
        if (!controller.signal.aborted) {
          setError(
            cause instanceof Error ? cause.message : "Unable to load hosts",
          );
        }
      });
    return () => controller.abort();
  }, [capacity, data, retry]);

  function pageUrl(page: number): string {
    const params = new URLSearchParams(location.search);
    params.set("page", String(page));
    params.set("fit", String(capacity));
    params.delete("per");
    return `/?${params}`;
  }
  return (
    <div className="inventory-page">
      <div className="inventory-toolbar">
        <Modal
          title="Filter hosts"
          trigger={
            <Button variant="outline">
              <ListFilter />
              Filter hosts{filtered ? " · Active" : ""}
            </Button>
          }
        >
          <Filters>
            <Field
              label="Search inventory"
              name="q"
              type="search"
              defaultValue={data.q}
              placeholder="IP, hostname, service"
            />
            <Field
              label="Port"
              name="port"
              type="number"
              defaultValue={data.port}
              className="w-24"
            />
            <Field
              label="Tag"
              name="tag"
              defaultValue={data.tag}
              className="w-32"
            />
            <SelectField
              label="Status"
              name="status"
              defaultValue={data.status}
              empty="Any status"
              options={data.statuses ?? []}
            />
            <SelectField
              label="Change"
              name="change"
              defaultValue={data.change}
              empty="Any change"
              options={["new", "changed", "unchanged"]}
            />
            <input type="hidden" name="sort" value={data.sort ?? "change"} />
            <input type="hidden" name="dir" value={data.direction ?? ""} />
            <input type="hidden" name="fit" value={capacity || 1} />
            <Button type="submit" variant="outline">
              <ListFilter />
              Apply
            </Button>
          </Filters>
        </Modal>
        <Button variant="outline" render={<ScopedLink href="/" />}>
          <RotateCcw />
          Reset
        </Button>
        <PageHeader title="Hosts">
          <Button
            variant="outline"
            render={<ScopedLink href="/export/hosts.csv" download />}
          >
            <ArrowDownToLine />
            Export CSV
          </Button>
          <Modal
            title="New host"
            trigger={
              <Button>
                <Plus />
                New host
              </Button>
            }
          >
            <MutationForm action="/hosts">
              <Field
                label="IP address"
                name="ip"
                required
                placeholder="10.0.0.5"
                autoComplete="off"
              />
              <Button type="submit">Add host</Button>
            </MutationForm>
          </Modal>
        </PageHeader>
      </div>
      <div className="inventory-results rounded-lg border bg-card">
        <div
          className="shrink-0 border-b px-3 py-1.5 text-xs text-muted-foreground"
          role="status"
        >
          {ready
            ? `${current.matched ?? 0} of ${current.total ?? 0} hosts`
            : "Loading hosts…"}
        </div>
        <div
          className="inventory-viewport"
          ref={viewport}
          aria-busy={!ready && !error}
        >
          {error ? (
            <div className="p-3 text-sm" role="alert">
              {error}
              <Button
                variant="outline"
                className="ml-2"
                onClick={() => setRetry((value) => value + 1)}
              >
                Retry
              </Button>
            </div>
          ) : ready ? (
            <HostTable rows={current.rows ?? []} sortable />
          ) : null}
        </div>
      </div>
      <nav aria-label="Pagination" className="inventory-pagination">
        <span className="muted text-xs" aria-live="polite">
          Page {current.page ?? 1} of {current.pages ?? 1}
        </span>
        <div className="actions">
          <Button
            variant="outline"
            nativeButton={false}
            disabled={!ready || (current.page ?? 1) <= 1}
            render={
              <ScopedLink href={pageUrl((current.page ?? 1) - 1)}
              aria-label="Previous page" />
            }
          >
            Previous
          </Button>
          <Button
            variant="outline"
            nativeButton={false}
            disabled={!ready || (current.page ?? 1) >= (current.pages ?? 1)}
            render={
              <ScopedLink href={pageUrl((current.page ?? 1) + 1)}
              aria-label="Next page" />
            }
          >
            Next
          </Button>
        </div>
      </nav>
    </div>
  );
}
function SearchPage({ data }: { data: PageData }) {
  const results = data.results;
  const count =
    (results?.hosts.length ?? 0) +
    (results?.notes.length ?? 0) +
    (results?.credentials.length ?? 0);
  return (
    <>
      <PageHeader title="Search" />
      <Filters>
        <Field
          label="Search everything"
          name="q"
          type="search"
          defaultValue={data.q}
          placeholder="IP, note, tag, username…"
        />
        <Button type="submit">
          <Search />
          Search
        </Button>
      </Filters>
      {!data.q ? (
        <Empty>Enter a search term to explore your recon.</Empty>
      ) : (
        <>
          <p role="status" className="mb-2 text-xs text-muted-foreground">
            {count} results for “{data.q}”
          </p>
          {count === 0 && (
            <Empty>No matching hosts, notes, or credentials.</Empty>
          )}
          {!!results?.hosts.length && (
            <Section title={`Hosts (${results.hosts.length})`}>
              <HostTable rows={results.hosts} />
            </Section>
          )}
          {!!results?.notes.length && (
            <Section title={`Notes (${results.notes.length})`}>
              <div className="divide-y">
                {results.notes.map((note, index) => (
                  <article key={index} className="py-2 text-[13px]">
                    <ScopedLink className="font-medium text-primary hover:underline"
                    href={note.href}>{note.title}</ScopedLink>
                    <p className="mono mt-1 text-xs text-muted-foreground">
                      {note.where}
                    </p>
                    <p className="mt-1 whitespace-pre-wrap text-[13px]">
                      {note.preview}
                    </p>
                  </article>
                ))}
              </div>
            </Section>
          )}
          {!!results?.credentials.length && (
            <Section title={`Credentials (${results.credentials.length})`}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Kind</TableHead>
                    <TableHead>Username</TableHead>
                    <TableHead>Linked hosts</TableHead>
                    <TableHead>Manage</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {results.credentials.map((cred) => (
                    <TableRow key={cred.id}>
                      <TableCell>
                        <Badge variant="outline">{cred.kind}</Badge>
                      </TableCell>
                      <TableCell className="mono">
                        {cred.username || "—"}
                      </TableCell>
                      <TableCell>
                        {cred.hosts.map((host) => (
                          <ScopedLink key={host.host_id}
                          className="mono mr-3 text-primary"
                          href={"/hosts/" + host.host_id}>{host.ip}</ScopedLink>
                        ))}
                      </TableCell>
                      <TableCell>
                        <ScopedLink href={"/credentials#credential-" + cred.id}
                        className="text-primary hover:underline">
                          View credential
                        </ScopedLink>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>
          )}
        </>
      )}
    </>
  );
}
function EngagementsPage({ data }: { data: PageData }) {
  return (
    <div className="engagements-page">
      <PageHeader title="Engagements" description="Create or open an isolated recon workspace.">
        <Modal title="Create engagement" trigger={<Button><Plus />Create engagement</Button>}>
          <MutationForm action="/engagements">
            <Field label="Name" name="name" required />
            <Field label="Description"><Textarea name="description" rows={3} /></Field>
            <div className="flex justify-end"><Button type="submit">Create engagement</Button></div>
          </MutationForm>
        </Modal>
      </PageHeader>
      <Section title="Engagements" id="engagement-catalog">
        {data.engagements.length ? (
          <div className="engagement-table">
          <Table>
            <TableHeader><TableRow>
              <TableHead aria-sort={data.sort === "name" ? (data.direction === "desc" ? "descending" : "ascending") : "none"}><SortLink column="name">Name</SortLink></TableHead><TableHead>Description</TableHead>
              <TableHead aria-sort={data.sort === "created_at" ? (data.direction === "desc" ? "descending" : "ascending") : "none"}><SortLink column="created_at">Created</SortLink></TableHead>
              <TableHead className="w-12"><span className="sr-only">Actions</span></TableHead>
            </TableRow></TableHeader>
            <TableBody>{data.engagements.map((engagement) => (
              <TableRow key={engagement.id}>
                <TableCell className="min-w-40 max-w-64 whitespace-normal [overflow-wrap:anywhere] font-medium"><ScopedLink href={`/e/${engagement.id}/`}>{engagement.name}</ScopedLink></TableCell>
                <TableCell className="min-w-48 max-w-xl whitespace-pre-wrap [overflow-wrap:anywhere]">{engagement.description}</TableCell>
                <TableCell className="mono"><time dateTime={engagement.created_at}>{engagement.created_at.replace("T", " ").slice(0, 16)}</time></TableCell>
                <TableCell className="text-right">
                  <Modal title="Edit engagement" trigger={
                    <Button variant="ghost" size="icon" aria-label={`Edit ${engagement.name}`} title={`Edit ${engagement.name}`}>
                      <Pencil />
                    </Button>
                  }>
                    <MutationForm action={`/engagements/${engagement.id}/edit`}>
                      <Field label="Name" name="name" defaultValue={engagement.name} required />
                      <Field label="Description"><Textarea name="description" defaultValue={engagement.description} rows={3} /></Field>
                      <div className="flex justify-end"><Button type="submit">Save changes</Button></div>
                    </MutationForm>
                  </Modal>
                </TableCell>
              </TableRow>
            ))}</TableBody>
          </Table>
          </div>
        ) : <Empty>No engagements yet. Use Create engagement to start importing scans and recording recon.</Empty>}
      </Section>
    </div>
  );
}

export default function App() {
  const [data, setData] = useState<PageData>(
    () =>
      JSON.parse(
        document.getElementById("page-data")?.textContent ?? "{}",
      ) as PageData,
  );
  const path = location.pathname.replace(/^\/e\/[^/]+/, "") || "/";
  const refresh = async () => {
    const response = await fetch(location.pathname + location.search, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`Unable to refresh (${response.status})`);
    setData((await response.json()) as PageData);
  };
  const navigate = (url: string) => {
    location.assign(engagementUrl(url));
  };
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (
        !event.defaultPrevented &&
        !target.closest('[aria-modal="true"]') &&
        event.key === "/" &&
        !target.closest("input,textarea,select,[contenteditable]")
      ) {
        event.preventDefault();
        document
          .querySelector<HTMLInputElement>('input[type="search"]')
          ?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  useEffect(() => {
    const title = path === "/engagements" ? "Engagements" :
      data.host?.ip ?? (path === "/search" ? "Search" :
        (navigation.find((item) => item.href === path)?.label ?? "Hosts"));
    document.title = `${title}${data.engagement?.name ? ` — ${data.engagement.name}` : ""} — penrecon`;
  }, [data.host?.ip, data.engagement?.name, path]);
  return (
    <PageContext.Provider value={{ data, refresh, navigate }}>
      <AppShell data={data} path={path}
        className={
          path === "/"
            ? "workbench-shell inventory-shell"
            : path.startsWith("/hosts/") ||
                path === "/credentials" ||
                path === "/operations" ||
                path === "/scans" ||
                path === "/engagements"
              ? "workbench-shell"
              : undefined
        }
      >
        <main id="main" className="shell py-4" tabIndex={-1}>
          <Suspense fallback={<p role="status" className="muted">Loading page…</p>}>
          {path === "/engagements" ? (
            <EngagementsPage data={data} />
          ) : path.startsWith("/hosts/") ? (
            <HostPage data={data} />
          ) : path === "/credentials" ? (
            <CredentialsPage data={data} />
          ) : path === "/scans" ? (
            <ScansPage data={data} />
          ) : path === "/diff" ? (
            <DiffPage data={data} />
          ) : path === "/operations" ? (
            <OperationsPage data={data} />
          ) : path === "/search" ? (
            <SearchPage data={data} />
          ) : (
            <Inventory data={data} />
          )}
          </Suspense>
        </main>
      </AppShell>
    </PageContext.Provider>
  );
}
