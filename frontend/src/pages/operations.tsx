import { useId, useRef, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { CalendarIcon } from "lucide-react";
import { format, parseISO } from "date-fns";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover";
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
  Modal,
  MutationForm,
  PageHeader,
  Pager,
  SelectField,
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
          <a
            href={`/operations/${operation.id}/attachment`}
            className="break-all text-sm underline underline-offset-4"
            download
          >
            {operation.attachment_name}
          </a>
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

function OperationRow({ operation }: { operation: Operation }) {
  return (
    <TableRow>
      <TableCell className="mono whitespace-nowrap align-top">
        {operation.started_at && (
          <div>
            <span className="muted text-xs">Start </span>
            <time dateTime={operation.started_at}>
              {operation.started_at.replace("T", " ").slice(0, 16)}
            </time>
          </div>
        )}
        {operation.ended_at && (
          <div>
            <span className="muted text-xs">End </span>
            <time dateTime={operation.ended_at}>
              {operation.ended_at.replace("T", " ").slice(0, 16)}
            </time>
          </div>
        )}
      </TableCell>
      <TableCell className="mono max-w-56 align-top whitespace-normal break-words">
        {operation.source && (
          <div>
            <span className="muted text-xs">From </span>
            {operation.source}
          </div>
        )}
        {operation.destination && (
          <div>
            <span className="muted text-xs">To </span>
            {operation.destination}
          </div>
        )}
      </TableCell>
      <TableCell className="mono align-top">{operation.tool}</TableCell>
      <TableCell className="mono max-w-40 align-top whitespace-normal break-words">
        {operation.user_context}
      </TableCell>
      <TableCell className="min-w-56 max-w-md align-top">
        <pre
          className="mono line-clamp-4 whitespace-pre-wrap break-all text-[13px]"
          title={operation.command}
        >
          {operation.command}
        </pre>
        {operation.description && (
          <p className="muted mt-1 line-clamp-2 whitespace-pre-wrap">
            {operation.description}
          </p>
        )}
        {(operation.output || operation.comments) && (
          <div className="muted mt-1 flex flex-wrap gap-x-3 text-xs">
            {operation.output && <span>Output recorded</span>}
            {operation.comments && <span>Comments recorded</span>}
          </div>
        )}
      </TableCell>
      <TableCell className="max-w-48 align-top">
        {!!operation.tags.length && (
          <div className="flex flex-wrap gap-1">
            {operation.tags.map((tag, index) => (
              <Badge key={`${tag}-${index}`} variant="secondary">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </TableCell>
      <TableCell className="max-w-48 align-top whitespace-normal">
        {operation.attachment_name && (
          <a
            href={`/operations/${operation.id}/attachment`}
            className="break-all text-[13px] underline underline-offset-4"
            download
          >
            {operation.attachment_name}
          </a>
        )}
      </TableCell>
      <TableCell className="align-top">
        <Modal
          title={`Operation #${operation.id}`}
          trigger={
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="text-[13px]"
              aria-label={`View or edit operation ${operation.id}`}
            >
              View / edit
            </Button>
          }
        >
          <OperationEditor operation={operation} />
        </Modal>
      </TableCell>
    </TableRow>
  );
}

export function OperationsPage({ data }: { data: PageData }) {
  const operations = data.operations ?? [];
  return (
    <div className="stack gap-3">
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
      <Filters>
        <div className="min-w-64 flex-1">
          <Field
            label="Search operations"
            name="q"
            type="search"
            defaultValue={data.q}
            placeholder="Command, endpoint, tool, tag, attachment"
          />
        </div>
        <input type="hidden" name="page" value="1" />
        <SelectField
          label="Rows per page"
          name="per"
          defaultValue={data.per ?? "25"}
          options={(data.per_page_choices ?? ["10", "25", "50", "all"]).map(
            (value) => ({ value, label: value === "all" ? "All" : value }),
          )}
        />
        <Button type="submit">Search</Button>
        {data.q && (
          <a
            href="/operations"
            className="self-end pb-2 text-sm underline underline-offset-4"
          >
            Clear search
          </a>
        )}
      </Filters>
      <p className="muted text-xs" role="status">
        {data.total ?? operations.length} matched operation
        {(data.total ?? operations.length) === 1 ? "" : "s"}
      </p>
      {operations.length ? (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <Table className="data-table">
            <TableHeader>
              <TableRow>
                <TableHead>Start / end</TableHead>
                <TableHead>Source → destination</TableHead>
                <TableHead>Tool</TableHead>
                <TableHead>User context</TableHead>
                <TableHead>Command</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Attachment</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {operations.map((operation) => (
                <OperationRow key={operation.id} operation={operation} />
              ))}
            </TableBody>
          </Table>
        </div>
      ) : (
        <Empty>
          {data.q ? (
            <>No operations match “{data.q}”.</>
          ) : (
            "No operations recorded yet."
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
