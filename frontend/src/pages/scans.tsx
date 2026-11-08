import { ScopedLink } from "../common";
import { useState } from "react";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
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
  Pager,
  Section,
} from "../common";
import type { PageData } from "../types";

type ScanUploadDraft = {
  tool: string;
  file: { kind: "empty" } | { kind: "selected"; file: File };
};

function initialUploadDraft(tools: string[]): ScanUploadDraft {
  return { tool: tools.includes("nmap") ? "nmap" : tools[0] ?? "", file: { kind: "empty" } };
}

function ScanUpload({ tools }: { tools: string[] }) {
  const [draft, setDraft] = useState(() => initialUploadDraft(tools));
  const toolAvailable = tools.includes(draft.tool);
  return (
    <div onReset={() => setDraft(initialUploadDraft(tools))}>
      <MutationForm
        action="/scans"
        className="flex flex-wrap items-end gap-3"
        canSubmit={draft.file.kind === "selected" && toolAvailable}
      >
        <Field label="Tool format">
          <NativeSelect
            name="tool"
            value={toolAvailable ? draft.tool : ""}
            required
            onChange={(event) => setDraft((current) => ({ ...current, tool: event.target.value }))}
          >
            {!toolAvailable && <NativeSelectOption value="">Select a tool format</NativeSelectOption>}
            {tools.map((tool) => <NativeSelectOption key={tool} value={tool}>{tool}</NativeSelectOption>)}
          </NativeSelect>
        </Field>
        <Field label="Scan result file" name="file">
          <Input
            type="file"
            name="file"
            required
            className="max-w-md"
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              setDraft((current) => ({ ...current, file: file ? { kind: "selected", file } : { kind: "empty" } }));
            }}
          />
        </Field>
        <Button type="submit">Upload &amp; ingest</Button>
        <p className="muted w-full text-xs" role="status">
          {!tools.length ? "No scan tool formats are available."
            : draft.file.kind === "selected" ? `${draft.file.file.name} selected.` : "Select a scan result file to import."}
        </p>
      </MutationForm>
    </div>
  );
}

type ScanDiffResult = NonNullable<PageData["result"]>;
type ScanDiffView =
  | { kind: "unavailable"; reason: string }
  | { kind: "selection" }
  | { kind: "no-result" }
  | { kind: "empty" | "differences"; result: ScanDiffResult };

function scanDiffView(data: PageData, a: string, b: string): ScanDiffView {
  const scans = data.scans ?? [];
  if (!scans.length) return { kind: "unavailable", reason: "Import scans before comparing their observations." };
  if (!scans.some((scan) => String(scan.id) === a) || !scans.some((scan) => String(scan.id) === b)) {
    return { kind: "unavailable", reason: "A selected scan is unavailable. Select two available scans to compare." };
  }
  if (!data.result) return { kind: "no-result" };
  if (String(data.result.scan_a.id) !== a || String(data.result.scan_b.id) !== b) return { kind: "selection" };
  return { kind: data.result.entries.length ? "differences" : "empty", result: data.result };
}
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
        <ScanUpload tools={tools} />
      </Section>
      <Section title={`Import history (${data.total ?? 0})`} id="scan-history">
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
      <Pager data={data} total={data.total} />
    </div>
  );
}

export function DiffPage({ data }: { data: PageData }) {
  return <ScanComparison key={`${data.a ?? ""}:${data.b ?? ""}`} data={data} />;
}

function ScanComparison({ data }: { data: PageData }) {
  const scans = data.scans ?? [];
  const [selection, setSelection] = useState(() => ({
    a: String(data.a ?? scans[0]?.id ?? ""),
    b: String(data.b ?? scans[0]?.id ?? ""),
  }));
  const view = scanDiffView(data, selection.a, selection.b);
  const result = view.kind === "empty" || view.kind === "differences" ? view.result : undefined;
  return (
    <div className="space-y-3">
      <PageHeader
        title="Diff scans"
        description="Compare immutable observations."
      />
      {scans.length ? (
        <Filters>
          <input type="hidden" name="per" value={data.per ?? "25"} />
          {(["a", "b"] as const).map((side) => {
            const available = scans.some((scan) => String(scan.id) === selection[side]);
            return (
              <Field key={side} label={side === "a" ? "Scan A · before" : "Scan B · after"}>
                <NativeSelect
                  name={side}
                  value={available ? selection[side] : ""}
                  required
                  onChange={(event) => setSelection((current) => ({ ...current, [side]: event.target.value }))}
                >
                  {!available && <NativeSelectOption value="">Select an available scan</NativeSelectOption>}
                  {scans.map((scan) => (
                    <NativeSelectOption key={scan.id} value={String(scan.id)}>
                      {`#${scan.id} ${scan.filename} (${scan.imported_at.replace("T", " ").slice(0, 16)})`}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </Field>
            );
          })}
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
      {scans.length > 0 && !result && (
        <p className="muted text-sm" role="status">
          {view.kind === "unavailable" ? view.reason
            : view.kind === "selection" ? "Selection changed. Compare to see differences for this pair."
              : "Select Compare to see differences. The same scan or either comparison order is allowed."}
        </p>
      )}
      {result ? (
        <Section
          title={`#${result.scan_a.id} → #${result.scan_b.id}`}
          action={
            <span className="muted text-xs">
              {data.total ?? 0} difference
              {data.total === 1 ? "" : "s"}
            </span>
          }
        >
          <p className="muted mb-2 text-xs break-words">
            {result.scan_a.filename} → {result.scan_b.filename}
          </p>
          {view.kind === "differences" ? (
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
          <Pager data={data} total={data.total} />
        </Section>
      ) : null}
    </div>
  );
}
