import { ScopedLink } from "../common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Empty,
  Field,
  Filters,
  MutationForm,
  PageHeader,
  Section,
  SelectField,
} from "../common";
import type { PageData } from "../types";

export function ScansPage({ data }: { data: PageData }) {
  const scans = data.scans ?? [];
  const tools = data.tools ?? [];
  return (
    <div className="scans-page">
      <PageHeader
        title="Scans"
        description="Imports preserve notes, annotations, and credentials."
      />
      <Section title="Import scan" id="scan-import">
        <MutationForm
          action="/scans"
          className="flex flex-wrap items-end gap-3"
        >
          <SelectField
            label="Tool format"
            name="tool"
            defaultValue={tools.includes("nmap") ? "nmap" : tools[0]}
            options={tools}
          />
          <Field label="Scan result file" name="file">
            <Input type="file" name="file" required className="max-w-md" />
          </Field>
          <Button type="submit">Upload &amp; ingest</Button>
        </MutationForm>
      </Section>
      <Section title={`Import history (${scans.length})`} id="scan-history">
        {scans.length ? (
          <div className="scan-history-table rounded-lg border bg-card">
            <Table className="data-table">
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Tool</TableHead>
                  <TableHead className="text-right">Hosts</TableHead>
                  <TableHead>Imported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow key={scan.id}>
                    <TableCell className="mono">#{scan.id}</TableCell>
                    <TableCell className="min-w-48 max-w-lg break-all whitespace-normal font-medium">
                      {scan.filename}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{scan.tool}</Badge>
                    </TableCell>
                    <TableCell className="mono text-right">
                      {scan.host_count}
                    </TableCell>
                    <TableCell className="mono whitespace-nowrap">
                      <time dateTime={scan.imported_at}>
                        {scan.imported_at.replace("T", " ").slice(0, 16)}
                      </time>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <Empty>
            No scans yet. Upload a scan result to populate the inventory.
          </Empty>
        )}
      </Section>
    </div>
  );
}

export function DiffPage({ data }: { data: PageData }) {
  const scans = data.scans ?? [];
  const result = data.result;
  const options = scans.map((scan) => ({
    value: String(scan.id),
    label: `#${scan.id} ${scan.filename} (${scan.imported_at.replace("T", " ").slice(0, 16)})`,
  }));
  return (
    <div className="space-y-3">
      <PageHeader
        title="Diff scans"
        description="Compare immutable observations."
      />
      {scans.length ? (
        <Filters>
          <SelectField
            label="Scan A · before"
            name="a"
            defaultValue={data.a == null ? undefined : String(data.a)}
            options={options}
          />
          <SelectField
            label="Scan B · after"
            name="b"
            defaultValue={data.b == null ? undefined : String(data.b)}
            options={options}
          />
          <Button type="submit">Compare</Button>
        </Filters>
      ) : (
        <Empty>
          Import scans before comparing their observations.{" "}
          <ScopedLink href="/scans" className="underline underline-offset-4">
            Upload a scan
          </ScopedLink>
          .
        </Empty>
      )}
      {result ? (
        <Section
          title={`#${result.scan_a.id} → #${result.scan_b.id}`}
          action={
            <span className="muted text-xs">
              {result.entries.length} difference
              {result.entries.length === 1 ? "" : "s"}
            </span>
          }
        >
          <p className="muted mb-2 text-xs break-words">
            {result.scan_a.filename} → {result.scan_b.filename}
          </p>
          {result.entries.length ? (
            <div className="overflow-x-auto rounded-lg border bg-card">
              <Table className="data-table">
                <TableHeader>
                  <TableRow>
                    <TableHead>Change</TableHead>
                    <TableHead>Host</TableHead>
                    <TableHead>Port</TableHead>
                    <TableHead>Before</TableHead>
                    <TableHead>After</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.entries.map((entry, index) => (
                    <TableRow
                      key={`${entry.ip}-${entry.port}-${entry.proto}-${entry.kind}-${index}`}
                    >
                      <TableCell>
                        <Badge variant="outline">
                          {entry.kind}
                        </Badge>
                      </TableCell>
                      <TableCell className="mono whitespace-nowrap">
                        {entry.ip}
                      </TableCell>
                      <TableCell className="mono whitespace-nowrap">
                        {entry.port}/{entry.proto}
                      </TableCell>
                      <TableCell className="mono max-w-lg whitespace-pre-wrap break-words">
                        {entry.before || <span className="muted">—</span>}
                      </TableCell>
                      <TableCell className="mono max-w-lg whitespace-pre-wrap break-words">
                        {entry.after || <span className="muted">—</span>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <Empty>No differences between these scans.</Empty>
          )}
        </Section>
      ) : null}
    </div>
  );
}
