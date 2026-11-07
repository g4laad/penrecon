import { QueryLink, ScopedLink, engagementUrl } from "../common";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useClipboard } from "@/components/use-clipboard";
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
import {
  attachmentFile,
  resolveOperationSelection,
  timestampComplete,
  timestampDraft,
  timestampValue,
  transitionAttachment,
  transitionTimestamp,
  type AttachmentDraft,
  type TimestampDraft,
  type TimestampEvent,
} from "./operation-workflow";
import { SelectedDetail } from "./use-selected-detail";

function OperationTimestamp({
  label,
  name,
  draft,
  onChange,
}: {
  label: string;
  name: string;
  draft: TimestampDraft;
  onChange: (event: TimestampEvent) => void;
}) {
  const [calendar, setCalendar] = useState<"closed" | "open">("closed");
  const date = draft.kind === "dated" ? draft.date : "";
  const selectedDate = date ? parseISO(date) : undefined;
  return (
    <fieldset className="grid min-w-0 gap-1.5" data-draft-value={JSON.stringify(draft)}>
      <legend className="mb-1.5 text-sm font-medium">{label}</legend>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-[minmax(0,1fr)_9rem]">
        <Popover open={calendar === "open"} onOpenChange={(open) => setCalendar(open ? "open" : "closed")}>
          <PopoverTrigger
            render={
              <Button
                type="button"
                variant="outline"
                className="mono w-full min-w-0 justify-between px-2"
              />
            }
          >
            {date || "Pick date"}
            <CalendarIcon className="size-3.5 shrink-0" aria-hidden="true" />
          </PopoverTrigger>
          <PopoverContent className="w-auto p-0" align="start">
            <PopoverTitle className="sr-only">{label} date</PopoverTitle>
            <Calendar
              mode="single"
              selected={selectedDate}
              defaultMonth={selectedDate}
              autoFocus
              onSelect={(day) => {
                onChange(day ? { type: "select-date", date: format(day, "yyyy-MM-dd") } : { type: "clear-date" });
                setCalendar("closed");
              }}
            />
            <Button
              type="button"
              variant="ghost"
              className="m-2 mt-0"
              onClick={() => {
                onChange({ type: "clear-date" });
                setCalendar("closed");
              }}
            >
              Clear date
            </Button>
          </PopoverContent>
        </Popover>
        <Input
          type="time"
          aria-label={`${label} time`}
          value={draft.kind === "dated" ? draft.time : ""}
          disabled={draft.kind === "absent"}
          required={draft.kind === "dated"}
          onChange={(event) => onChange({ type: "edit-time", time: event.target.value })}
        />
      </div>
      <p className="muted text-xs">Time defaults to midnight after you pick a date.</p>
      <input type="hidden" name={name} value={timestampValue(draft)} />
    </fieldset>
  );
}

function OperationForm({ operation }: { operation?: Operation }) {
  const attachmentId = useId();
  const attachmentInput = useRef<HTMLInputElement>(null);
  const fields = useRef<HTMLDivElement>(null);
  const mounted = useRef(false);
  const [attachment, setAttachment] = useState<AttachmentDraft>({ intent: "keep" });
  const [started, setStarted] = useState(() => timestampDraft(operation?.started_at));
  const [ended, setEnded] = useState(() => timestampDraft(operation?.ended_at));
  const hasAttachment = Boolean(operation?.attachment_name);
  useEffect(() => {
    if (mounted.current) {
      // Calendar and intent buttons change submitted values without native input.
      fields.current?.dispatchEvent(new Event("input", { bubbles: true }));
    }
    mounted.current = true;
  }, [started, ended, attachment]);
  function setAttachmentDraft(next: AttachmentDraft) {
    const input = attachmentInput.current;
    if (input) {
      const files = new DataTransfer();
      const file = attachmentFile(next);
      if (file) files.items.add(file);
      input.files = files.files;
    }
    setAttachment(next);
  }
  return (
    <div onReset={() => {
      setStarted(timestampDraft(operation?.started_at));
      setEnded(timestampDraft(operation?.ended_at));
      setAttachment({ intent: "keep" });
    }}>
      <MutationForm
        action={operation ? `/operations/${operation.id}/edit` : "/operations"}
        canSubmit={timestampComplete(started) && timestampComplete(ended)}
      >
    <div ref={fields} className="form-grid">
      <OperationTimestamp
        label="Started"
        name="started_at"
        draft={started}
        onChange={(event) => setStarted((draft) => transitionTimestamp(draft, event))}
      />
      <OperationTimestamp
        label="Ended"
        name="ended_at"
        draft={ended}
        onChange={(event) => setEnded((draft) => transitionTimestamp(draft, event))}
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
          <input type="hidden" name="remove_attachment" value={attachment.intent === "remove" ? "true" : ""} />
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              if (attachment.intent === "remove") {
                setAttachmentDraft(transitionAttachment(attachment, { type: "undo-remove" }, hasAttachment));
              } else if (window.confirm(
                `Remove attachment ${operation.attachment_name}? The file will be deleted when you save. Any selected replacement will be retained if you cancel removal.`,
              )) {
                setAttachmentDraft(transitionAttachment(attachment, { type: "remove" }, hasAttachment));
              }
            }}
          >
            {attachment.intent === "remove" ? "Cancel attachment removal" : "Remove attachment when saving"}
          </Button>
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
          disabled={attachment.intent === "remove"}
          onChange={(event) => {
            const file = event.currentTarget.files?.[0];
            if (!file) {
              setAttachmentDraft(transitionAttachment(attachment, { type: "clear-file" }, hasAttachment));
              return;
            }
            if (hasAttachment && !window.confirm(
              `Replace attachment ${operation?.attachment_name} with ${file.name}? The current file will be deleted when you save.`,
            )) {
              // The browser already replaced FileList. Restore the accepted draft.
              setAttachmentDraft(attachment);
              return;
            }
            setAttachmentDraft(transitionAttachment(attachment, { type: "select-file", file }, hasAttachment));
          }}
        />
        {(attachment.intent === "new" || attachment.intent === "replace") && (
          <Button
            type="button"
            variant="ghost"
            className="self-start"
            onClick={() => setAttachmentDraft(transitionAttachment(attachment, { type: "clear-file" }, hasAttachment))}
          >
            Cancel {attachment.intent === "replace" ? "replacement" : "attachment"} upload
          </Button>
        )}
        <p className="muted text-xs" role="status">
          {attachment.intent === "remove"
            ? "Attachment removal selected. Cancel removal to restore your previous attachment choice."
            : attachment.intent === "new" || attachment.intent === "replace"
              ? `${attachment.file.name} selected. ${attachment.intent === "replace" ? "The current attachment will be replaced when saved." : "The file will be attached when saved."}`
              : hasAttachment ? "The current attachment will be kept unless you select a replacement or removal." : "No attachment selected."}
        </p>
      </div>
    </div>
        <div className="actions mt-4 justify-end">
          <Button type="submit">{operation ? "Save operation" : "Add operation"}</Button>
        </div>
      </MutationForm>
    </div>
  );
}

function OperationEditor({ operation }: { operation: Operation }) {
  return (
    <div className="stack">
      <OperationForm operation={operation} />
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
  const { status: copyStatus, copy } = useClipboard(operation.command);
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
            protectChanges="Discard unsaved operation changes?"
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
            onClick={() => void copy(operation.command)}
          >
            <Copy className="size-3.5" aria-hidden="true" />
            {copyStatus === "pending" ? "Copy again" : "Copy command"}
          </Button>
        </div>
        <pre className="operation-code bg-muted">{operation.command}</pre>
        <p className="muted mt-1 text-xs" role="status">
          {copyStatus === "pending" ? "Copying command…"
            : copyStatus === "copied" ? "Command copied."
              : copyStatus === "error" ? "Unable to copy. Select the command and copy it manually." : ""}
        </p>
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
  const operations = useMemo(() => data.operations ?? [], [data.operations]);
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
  useEffect(() => {
    if (hash || !operations.length) return;
    const next = new URL(location.href);
    const oldURL = location.href;
    next.hash = `operation-${operations[0].id}`;
    history.replaceState(null, "", next);
    window.dispatchEvent(new HashChangeEvent("hashchange", { oldURL, newURL: next.href }));
  }, [hash, operations]);
  const selection = resolveOperationSelection(operations, hash);
  const selected = selection.kind === "selected" ? selection.operation : undefined;
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
              render={<QueryLink href={engagementUrl(`/operations?per=${data.per ?? "25"}`)} />}
            >
              Reset
            </Button>
          )}
        </Filters>
        <PageHeader title="Operation log">
          <Modal
            title="Add operation"
            protectChanges="Discard unsaved operation changes?"
            trigger={<Button type="button">Add operation</Button>}
          >
            <OperationForm />
          </Modal>
        </PageHeader>
      </div>
      <p className="muted text-xs" role="status">
        {data.total ?? operations.length} matched operation
        {(data.total ?? operations.length) === 1 ? "" : "s"}
      </p>
      {operations.length || selection.kind === "unavailable" ? (
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
                aria-pressed={operation.id === selected?.id}
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
          {selected ? (
            <SelectedDetail<{ operation: Operation }>
              url={`/operations/${selected.id}`}
              revision={data}
              label="operation"
            >
              {({ operation }) => <OperationDetails key={operation.id} operation={operation} />}
            </SelectedDetail>
          ) : (
            <Empty>
              The selected operation is not available on this page. It may have been deleted or be outside the current search or page. Select an operation from the list or adjust the search and page.
            </Empty>
          )}
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
