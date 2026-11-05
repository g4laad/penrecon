import { ScopedLink } from "../common";
import { useEffect, useId, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CalendarIcon, Copy, Paperclip } from "lucide-react";
import { format, parseISO } from "date-fns";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Empty,
  Field,
  Filters,
  Modal,
  MutationForm,
  PageHeader,
  Pager,
} from "../common";
import type { Operation, PageData } from "../types";

function OperationTimestamp({
  label,
  name,
  defaultValue,
}: {
  label: string;
  name: string;
  defaultValue?: string | null;
}) {
  const [date, setDate] = useState(defaultValue?.slice(0, 10) ?? "");
  const [time, setTime] = useState(defaultValue?.slice(11, 16) || "00:00");
  const [dateOpen, setDateOpen] = useState(false);
  const selectedDate = date ? parseISO(date) : undefined;
  return (
    <fieldset className="grid min-w-0 gap-1.5">
      <legend className="mb-1.5 text-sm font-medium">{label}</legend>
      <div className="grid grid-cols-[minmax(0,1fr)_9rem] gap-2">
        <Popover open={dateOpen} onOpenChange={setDateOpen}>
          <PopoverTrigger
            render={
              <Button
                type="button"
                variant="outline"
                className="mono w-full min-w-0 justify-between px-2"
                aria-label={`${label} date`}
              />
            }
          >
            {date || "Pick date"}
            <CalendarIcon className="size-3.5 shrink-0" />
          </PopoverTrigger>
          <PopoverContent className="w-auto p-0" align="start">
            <PopoverTitle className="sr-only">{label} date</PopoverTitle>
            <Calendar
              mode="single"
              selected={selectedDate}
              defaultMonth={selectedDate}
              autoFocus
              onSelect={(day) => {
                setDate(day ? format(day, "yyyy-MM-dd") : "");
                setDateOpen(false);
              }}
            />
            <Button
              type="button"
              variant="ghost"
              className="m-2 mt-0"
              onClick={() => {
                setDate("");
                setDateOpen(false);
              }}
            >
              Clear date
            </Button>
          </PopoverContent>
        </Popover>
        <Input
          type="time"
          aria-label={`${label} time`}
          value={time}
          required={Boolean(date)}
          onChange={(event) => setTime(event.target.value)}
        />
      </div>
      <p className="muted text-xs">Time defaults to midnight.</p>
      <input type="hidden" name={name} value={date ? `${date}T${time}` : ""} />
    </fieldset>
  );
}

function OperationFields({ operation }: { operation?: Operation }) {
  const attachmentId = useId();
  const removeId = useId();
  const attachmentInput = useRef<HTMLInputElement>(null);
  const [removeAttachment, setRemoveAttachment] = useState(false);
  return (
    <div className="form-grid">
      <OperationTimestamp
        label="Started"
        name="started_at"
        defaultValue={operation?.started_at}
      />
      <OperationTimestamp
        label="Ended"
        name="ended_at"
        defaultValue={operation?.ended_at}
      />
      <Field
        label="Source"
        name="source"
        defaultValue={operation?.source}
        placeholder="Operator host or IP"
      />
      <Field
        label="Destination"
        name="destination"
        defaultValue={operation?.destination}
        placeholder="Target host, IP, or range"
      />
      <Field
        label="Tool"
        name="tool"
        defaultValue={operation?.tool}
        placeholder="nmap"
      />
      <Field
        label="User context"
        name="user_context"
        defaultValue={operation?.user_context}
        placeholder="root, domain\\user, relay"
      />
      <div className="col-span-full">
        <Field label="Command" name="command" required>
          <Textarea
            name="command"
            defaultValue={operation?.command}
            required
            spellCheck={false}
            rows={3}
            className="mono"
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Output" name="output">
          <Textarea
            name="output"
            defaultValue={operation?.output}
            spellCheck={false}
            rows={7}
            className="mono"
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Description" name="description">
          <Textarea
            name="description"
            defaultValue={operation?.description}
            rows={3}
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field label="Comments" name="comments">
          <Textarea
            name="comments"
            defaultValue={operation?.comments}
            rows={3}
          />
        </Field>
      </div>
      <div className="col-span-full">
        <Field
          label="Tags"
          name="tags"
          defaultValue={operation?.tags.join(", ")}
          placeholder="comma, separated"
        />
      </div>
      {operation?.attachment_name && (
        <div className="stack col-span-full gap-2 rounded-md border bg-muted/30 p-3">
          <span className="text-sm font-medium">Current attachment</span>
          <ScopedLink href={`/operations/${operation.id}/attachment`}
          className="break-all text-sm underline underline-offset-4"
          download>{operation.attachment_name}</ScopedLink>
          <label htmlFor={removeId} className="flex items-center gap-2 text-sm">
            <input
              id={removeId}
              type="checkbox"
              name="remove_attachment"
              value="true"
              checked={removeAttachment}
              className="size-4 accent-primary"
              onChange={(event) => {
                const checked = event.target.checked;
                if (
                  checked &&
                  !window.confirm(
                    `Remove attachment ${operation.attachment_name}? The file will be deleted when you save.`,
                  )
                )
                  return;
                setRemoveAttachment(checked);
                if (checked && attachmentInput.current)
                  attachmentInput.current.value = "";
              }}
            />
            Remove attachment when saving
          </label>
        </div>
      )}
      <div className="stack col-span-full gap-2">
        <label htmlFor={attachmentId} className="text-sm font-medium">
          {operation?.attachment_name ? "Replacement attachment" : "Attachment"}
        </label>
        <Input
          id={attachmentId}
          ref={attachmentInput}
          type="file"
          name="attachment"
          disabled={removeAttachment}
          onChange={(event) => {
            if (
              event.currentTarget.files?.length &&
              operation?.attachment_name &&
              !window.confirm(
                `Replace attachment ${operation.attachment_name}? The current file will be deleted when you save.`,
              )
            ) {
              event.currentTarget.value = "";
            }
          }}
        />
        {operation?.attachment_name && (
          <p className="muted text-xs">
            {removeAttachment
              ? "Attachment removal selected. Uncheck removal to upload a replacement instead."
              : "Uploading a replacement deletes the current attachment when saved."}
          </p>
        )}
      </div>
    </div>
  );
}

function OperationEditor({ operation }: { operation: Operation }) {
  return (
    <div className="stack">
      <MutationForm action={`/operations/${operation.id}/edit`}>
        <OperationFields operation={operation} />
        <div className="actions mt-4 justify-end">
          <Button type="submit">Save operation</Button>
        </div>
      </MutationForm>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="muted text-xs">
          Created {operation.created_at.replace("T", " ").slice(0, 16)}
          <br />
          Updated {operation.updated_at.replace("T", " ").slice(0, 16)}
        </p>
        <MutationForm
          action={`/operations/${operation.id}/delete`}
          confirm={`Delete operation #${operation.id} and its attachment? This cannot be undone.`}
        >
          <Button type="submit" variant="destructive">
            Delete operation
          </Button>
        </MutationForm>
      </div>
    </div>
  );
}

function OperationDetails({ operation }: { operation: Operation }) {
  const [copyStatus, setCopyStatus] = useState("");
  const metadata = [
    ["Start", operation.started_at?.replace("T", " ").slice(0, 16)],
    ["End", operation.ended_at?.replace("T", " ").slice(0, 16)],
    ["From", operation.source],
    ["To", operation.destination],
    ["Tool", operation.tool],
    ["User context", operation.user_context],
  ];
  return (
    <section
      className="operation-detail"
      aria-label={`Operation ${operation.id} details`}
      tabIndex={0}
    >
      <header className="flex flex-wrap items-start justify-between gap-3 border-b pb-3">
        <div className="min-w-0">
          <p className="muted text-xs">Operation #{operation.id}</p>
          <h2 className="mt-1 whitespace-pre-wrap break-words text-sm font-semibold">
            {operation.description || operation.tool || "Recorded operation"}
          </h2>
        </div>
        <div className="actions">
          {operation.tags.map((tag, index) => (
            <Badge key={`${tag}-${index}`} variant="secondary">
              {tag}
            </Badge>
          ))}
          <Modal
            title={`Edit operation #${operation.id}`}
            trigger={
              <Button variant="outline" size="sm">
                Edit operation
              </Button>
            }
          >
            <OperationEditor operation={operation} />
          </Modal>
        </div>
      </header>
      {metadata.some(([, value]) => value) && (
        <dl className="operation-metadata">
          {metadata
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <div key={label}>
                <dt className="muted mb-1 text-xs">{label}</dt>
                <dd className="mono break-words">{value}</dd>
              </div>
            ))}
        </dl>
      )}
      <section>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="credential-label">Command</h3>
          <Button
            variant="ghost"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(operation.command);
                setCopyStatus("Command copied.");
              } catch {
                setCopyStatus(
                  "Unable to copy. Select the command and copy it manually.",
                );
              }
            }}
          >
            <Copy className="size-3.5" aria-hidden="true" />
            Copy command
          </Button>
        </div>
        <pre className="operation-code bg-muted">{operation.command}</pre>
        {copyStatus && (
          <p className="muted mt-1 text-xs" role="status">
            {copyStatus}
          </p>
        )}
      </section>
      {operation.output && (
        <section>
          <h3 className="credential-label mb-2">Output</h3>
          <pre className="operation-code">{operation.output}</pre>
        </section>
      )}
      {operation.comments && (
        <section className="border-l-2 pl-3">
          <h3 className="credential-label mb-1">Operator notes</h3>
          <p className="whitespace-pre-wrap break-words">
            {operation.comments}
          </p>
        </section>
      )}
      {operation.attachment_name && (
        <ScopedLink href={`/operations/${operation.id}/attachment`}
        className="flex items-center gap-2 break-all"
        download><Paperclip className="size-3.5 shrink-0" aria-hidden="true" />
        {operation.attachment_name}</ScopedLink>
      )}
      <p className="muted text-xs">
        Recorded {operation.created_at.replace("T", " ").slice(0, 16)}
        {" · "}Updated {operation.updated_at.replace("T", " ").slice(0, 16)}
      </p>
    </section>
  );
}

export function OperationsPage({ data }: { data: PageData }) {
  const operations = data.operations ?? [];
  const [hash, setHash] = useState(() => location.hash);
  useEffect(() => {
    const sync = () => setHash(location.hash);
    window.addEventListener("hashchange", sync);
    window.addEventListener("popstate", sync);
    return () => {
      window.removeEventListener("hashchange", sync);
      window.removeEventListener("popstate", sync);
    };
  }, []);
  const selected =
    operations.find((operation) => hash === `#operation-${operation.id}`) ??
    operations[0];
  return (
    <div className="operation-workbench-page">
      <div className="operation-toolbar">
        <Filters>
          <Field
            label="Search operations"
            name="q"
            type="search"
            defaultValue={data.q}
            placeholder="Command, endpoint, tool, tag, attachment"
          />
          <input type="hidden" name="page" value="1" />
          <input type="hidden" name="per" value={data.per ?? "25"} />
          <Button type="submit" variant="outline">
            Search
          </Button>
          {data.q && (
            <Button
              variant="ghost"
              render={<ScopedLink href={`/operations?per=${data.per ?? "25"}`} />}
            >
              Reset
            </Button>
          )}
        </Filters>
        <PageHeader title="Operation log">
          <Modal
            title="Add operation"
            trigger={<Button type="button">Add operation</Button>}
          >
            <MutationForm action="/operations">
              <OperationFields />
              <div className="actions mt-4 justify-end">
                <Button type="submit">Add operation</Button>
              </div>
            </MutationForm>
          </Modal>
        </PageHeader>
      </div>
      <p className="muted text-xs" role="status">
        {data.total ?? operations.length} matched operation
        {(data.total ?? operations.length) === 1 ? "" : "s"}
      </p>
      {selected ? (
        <div className="operation-workbench rounded-lg border bg-card">
          <nav
            className="operation-list"
            aria-label="Operations on this page"
            tabIndex={0}
          >
            {operations.map((operation) => (
              <button
                type="button"
                className="operation-choice"
                key={operation.id}
                aria-pressed={operation.id === selected.id}
                title={operation.command}
                onClick={() => {
                  const next = new URL(location.href);
                  next.hash = `operation-${operation.id}`;
                  history.pushState(null, "", next);
                  setHash(next.hash);
                }}
              >
                <span className="flex items-start justify-between gap-2">
                  <strong className="mono break-words">
                    {operation.destination || "No destination recorded"}
                  </strong>
                  <span className="muted shrink-0 text-xs">
                    #{operation.id}
                  </span>
                </span>
                <span className="mono line-clamp-2 break-all">
                  {operation.command}
                </span>
                <span className="muted flex flex-wrap gap-x-3 text-xs">
                  {operation.tool && <span>{operation.tool}</span>}
                  <span className="mono">
                    {operation.started_at?.replace("T", " ").slice(0, 16) ||
                      "Start not recorded"}
                  </span>
                </span>
              </button>
            ))}
          </nav>
          <OperationDetails
            key={`${selected.id}:${selected.updated_at}`}
            operation={selected}
          />
        </div>
      ) : (
        <Empty>
          {data.q ? (
            <>No operations match “{data.q}”.</>
          ) : (
            "No operations recorded yet. Add an operation to start your log."
          )}
        </Empty>
      )}
      <Pager
        data={{
          page: data.page ?? 1,
          pages: data.pages ?? 1,
          per: data.per ?? "25",
        }}
        total={data.total}
      />
    </div>
  );
}
