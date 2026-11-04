import { useEffect, useState } from "react";
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
  Pager,
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
    <Table>
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
              >
                {row.ip}
              </a>
              {row.hostnames.map((name) => (
                <div key={name} className="mt-1 text-xs text-muted-foreground">
                  {name}
                </div>
              ))}
            </TableCell>
            <TableCell>
              <div className="flex max-w-xl flex-wrap gap-1.5">
                {row.open_services.map(([port, name]) => (
                  <a
                    key={port}
                    href={"/hosts/" + row.id + "#services"}
                    className="rounded border bg-muted/40 px-1.5 py-0.5 text-xs"
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
              {row.triaged ? (
                <Badge variant="outline">{row.status}</Badge>
              ) : (
                <span className="muted text-xs">Not triaged</span>
              )}
            </TableCell>
            <TableCell>
              <div className="flex flex-wrap gap-1">
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
  return (
    <>
      <PageHeader
        title="Hosts"
        description="Current inventory · latest observations, with your triage intact."
      >
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
        <Button type="submit" variant="outline">
          <ListFilter />
          Apply
        </Button>
        <a href="/" className="text-sm text-muted-foreground hover:underline">
          Reset
        </a>
      </Filters>
      <div className="overflow-hidden rounded-lg border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-3 text-sm">
          <span className="font-medium">Host inventory</span>
          <span className="muted">
            {data.matched ?? 0} of {data.total ?? 0} hosts
          </span>
        </div>
        <HostTable rows={data.rows ?? []} sortable />
      </div>
      <Pager data={data} total={data.matched} />
    </>
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
      <PageHeader
        title="Search"
        description="Find hosts, notes, and credentials across your recon."
      />
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
          <p role="status" className="mb-4 text-sm text-muted-foreground">
            {count} results for “{data.q}”
          </p>
          <Section title={`Hosts (${results?.hosts.length ?? 0})`}>
            <HostTable rows={results?.hosts ?? []} />
          </Section>
          <Section title={`Notes (${results?.notes.length ?? 0})`}>
            {results?.notes.length ? (
              <div className="divide-y">
                {results.notes.map((note, index) => (
                  <article key={index} className="py-3">
                    <a
                      className="font-medium text-primary hover:underline"
                      href={note.href}
                    >
                      {note.title}
                    </a>
                    <p className="mono mt-1 text-xs text-muted-foreground">
                      {note.where}
                    </p>
                    <p className="mt-2 whitespace-pre-wrap text-sm">
                      {note.preview}
                    </p>
                  </article>
                ))}
              </div>
            ) : (
              <Empty>No matching notes.</Empty>
            )}
          </Section>
          <Section title={`Credentials (${results?.credentials.length ?? 0})`}>
            {results?.credentials.length ? (
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
            ) : (
              <Empty>No matching credentials.</Empty>
            )}
          </Section>
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
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="site-header">
        <div className="shell flex min-h-16 flex-wrap items-center gap-4 py-3">
          <a
            href="/"
            className="mr-4 flex items-center gap-2 text-base font-semibold tracking-tight"
          >
            <Activity className="size-5 text-primary" />
            penrecon
            <span className="ml-1 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-widest text-muted-foreground">
              local
            </span>
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
                className={"nav-link " + (active === item.href ? "active" : "")}
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
            <Button type="submit" variant="outline" size="sm">
              Find
            </Button>
          </form>
        </div>
      </header>
      <main id="main" className="shell py-7" tabIndex={-1}>
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
      <footer className="shell border-t py-4 text-xs text-muted-foreground">
        penrecon · Local recon workspace{" "}
        <span className="float-right">Press / to focus search</span>
      </footer>
    </PageContext.Provider>
  );
}
