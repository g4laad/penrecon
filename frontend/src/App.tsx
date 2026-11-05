import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  GitCompareArrows,
  KeyRound,
  ListFilter,
  Network,
  Plus,
  Radar,
  Search,
  RotateCcw,
  Terminal,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
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
import { HostPage } from "./pages/host";
import { CredentialsPage } from "./pages/credentials";
import { ScansPage, DiffPage } from "./pages/scans";
import { OperationsPage } from "./pages/operations";

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
              <a
                className="mono font-semibold text-primary hover:underline"
                href={"/hosts/" + row.id}
                title={[row.ip, ...row.hostnames].join(" · ")}
              >
                {row.ip}
              </a>
              {!!row.hostnames.length && (
                <div className="mt-0.5 whitespace-normal break-words text-xs text-muted-foreground">
                  {row.hostnames.join(" · ")}
                </div>
              )}
            </TableCell>
            <TableCell>
              {sortable && row.open_count > 0 && (
                <a href={`/hosts/${row.id}#services`} className="block text-xs">
                  {row.open_count} open
                </a>
              )}
              <div
                className="flex max-w-xl flex-wrap gap-1"
                title={row.open_services
                  .map(([port, name]) => `${port} ${name}`)
                  .join(", ")}
              >
                {row.open_services.map(([port, name]) => (
                  <a
                    key={port}
                    href={"/hosts/" + row.id + "#services"}
                    className="rounded border bg-muted/40 px-1 text-xs"
                  >
                    <span className="mono font-medium">{port}</span>
                    {name && (
                      <span className="ml-1 text-muted-foreground">{name}</span>
                    )}
                  </a>
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
    void fetch(`/?${params}`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok)
          throw new Error(`Unable to load hosts (${response.status})`);
        const next = (await response.json()) as PageData;
        if (controller.signal.aborted) return;
        params.set("page", String(next.page ?? 1));
        history.replaceState(null, "", `/?${params}`);
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
        <Button variant="outline" render={<a href="/" />}>
          <RotateCcw />
          Reset
        </Button>
        <PageHeader title="Hosts">
          <Button
            variant="outline"
            render={<a href="/export/hosts.csv" download />}
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
              <a
                href={pageUrl((current.page ?? 1) - 1)}
                aria-label="Previous page"
              />
            }
          >
            Previous
          </Button>
          <Button
            variant="outline"
            nativeButton={false}
            disabled={!ready || (current.page ?? 1) >= (current.pages ?? 1)}
            render={
              <a
                href={pageUrl((current.page ?? 1) + 1)}
                aria-label="Next page"
              />
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
                    <a
                      className="font-medium text-primary hover:underline"
                      href={note.href}
                    >
                      {note.title}
                    </a>
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
                          <a
                            key={host.host_id}
                            className="mono mr-3 text-primary"
                            href={"/hosts/" + host.host_id}
                          >
                            {host.ip}
                          </a>
                        ))}
                      </TableCell>
                      <TableCell>
                        <a
                          href={"/credentials#credential-" + cred.id}
                          className="text-primary hover:underline"
                        >
                          View credential
                        </a>
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
const navigation = [
  { href: "/", label: "Hosts", icon: Network },
  { href: "/credentials", label: "Credentials", icon: KeyRound },
  { href: "/operations", label: "Operations", icon: Terminal },
  { href: "/scans", label: "Scans", icon: Radar },
  { href: "/diff", label: "Scan diff", icon: GitCompareArrows },
];
export default function App() {
  const [data, setData] = useState<PageData>(
    () =>
      JSON.parse(
        document.getElementById("page-data")?.textContent ?? "{}",
      ) as PageData,
  );
  const path = location.pathname;
  const refresh = async () => {
    const response = await fetch(location.pathname + location.search, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(`Unable to refresh (${response.status})`);
    setData((await response.json()) as PageData);
  };
  const navigate = (url: string) => {
    location.assign(url);
  };
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      if (
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
    const title =
      data.host?.ip ??
      (path === "/search"
        ? "Search"
        : (navigation.find((item) => item.href === path)?.label ?? "Hosts"));
    document.title = `${title} — penrecon`;
  }, [data.host?.ip, path]);
  const active = path.startsWith("/hosts/") ? "/" : path;
  return (
    <PageContext.Provider value={{ data, refresh, navigate }}>
      <div
        className={
          path === "/"
            ? "workbench-shell inventory-shell"
            : path.startsWith("/hosts/") ||
                path === "/credentials" ||
                path === "/operations" ||
                path === "/scans"
              ? "workbench-shell"
              : undefined
        }
      >
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <header className="site-header">
          <div className="shell flex min-h-12 flex-wrap items-center gap-2 py-2">
            <a
              href="/"
              className="mr-4 flex items-center gap-2 text-base font-semibold tracking-tight"
            >
              <Activity className="size-5 text-primary" />
              penrecon
            </a>
            <nav
              aria-label="Primary"
              className="flex flex-wrap items-center gap-1"
            >
              {navigation.map((item) => (
                <a
                  key={item.href}
                  href={item.href}
                  aria-current={active === item.href ? "page" : undefined}
                  className={
                    "nav-link " + (active === item.href ? "active" : "")
                  }
                >
                  <item.icon className="size-4" />
                  {item.label}
                </a>
              ))}
            </nav>
            <form
              action="/search"
              method="get"
              className="ml-auto flex items-center gap-2"
              role="search"
              aria-label="Global search"
            >
              <div className="relative">
                <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
                <Input
                  type="search"
                  name="q"
                  aria-label="Global search"
                  placeholder="Search everything…"
                  defaultValue={path === "/search" ? data.q : ""}
                  className="w-52 pl-8"
                />
              </div>
              <Button type="submit" variant="outline">
                Find
              </Button>
            </form>
          </div>
        </header>
        <main id="main" className="shell py-4" tabIndex={-1}>
          {path.startsWith("/hosts/") ? (
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
        </main>
        <footer className="shell border-t py-2 text-xs text-muted-foreground">
          penrecon · Local recon workspace{" "}
          <span className="float-right">Press / to focus search</span>
        </footer>
      </div>
    </PageContext.Provider>
  );
}
