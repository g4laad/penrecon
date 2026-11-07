import type { Operation } from "../types";

export type TimestampDraft =
  | { kind: "absent"; time: string }
  | { kind: "dated"; date: string; time: string };

export type TimestampEvent =
  | { type: "select-date"; date: string }
  | { type: "clear-date" }
  | { type: "edit-time"; time: string };

export function timestampDraft(value?: string | null): TimestampDraft {
  return value
    ? { kind: "dated", date: value.slice(0, 10), time: value.slice(11, 16) || "00:00" }
    : { kind: "absent", time: "00:00" };
}

export function transitionTimestamp(draft: TimestampDraft, event: TimestampEvent): TimestampDraft {
  switch (event.type) {
    case "select-date":
      return { kind: "dated", date: event.date, time: draft.time || "00:00" };
    case "clear-date":
      return { kind: "absent", time: draft.time || "00:00" };
    case "edit-time":
      return draft.kind === "dated" ? { ...draft, time: event.time } : draft;
  }
}

export function timestampComplete(draft: TimestampDraft): boolean {
  return draft.kind === "absent" || /^\d{2}:\d{2}$/.test(draft.time);
}

export function timestampValue(draft: TimestampDraft): string {
  return draft.kind === "dated" && timestampComplete(draft) ? `${draft.date}T${draft.time}` : "";
}

type RetainedAttachment = { intent: "keep" } | { intent: "replace"; file: File };
export type AttachmentDraft =
  | RetainedAttachment
  | { intent: "new"; file: File }
  | { intent: "remove"; previous: RetainedAttachment };

export type AttachmentEvent =
  | { type: "select-file"; file: File }
  | { type: "remove" }
  | { type: "undo-remove" }
  | { type: "clear-file" };

// Confirmation is the caller's responsibility; impossible intents remain unchanged.
export function transitionAttachment(
  draft: AttachmentDraft,
  event: AttachmentEvent,
  hasExisting: boolean,
): AttachmentDraft {
  switch (event.type) {
    case "select-file":
      return draft.intent === "remove" ? draft : { intent: hasExisting ? "replace" : "new", file: event.file };
    case "remove":
      return hasExisting && (draft.intent === "keep" || draft.intent === "replace")
        ? { intent: "remove", previous: draft }
        : draft;
    case "undo-remove":
      return draft.intent === "remove" ? draft.previous : draft;
    case "clear-file":
      return draft.intent === "new" || draft.intent === "replace" ? { intent: "keep" } : draft;
  }
}

export function attachmentFile(draft: AttachmentDraft): File | null {
  return draft.intent === "new" || draft.intent === "replace" ? draft.file : null;
}

export type OperationSelection =
  | { kind: "empty" }
  | { kind: "selected"; operation: Operation }
  | { kind: "unavailable"; hash: string };

export function resolveOperationSelection(operations: Operation[], hash: string): OperationSelection {
  if (hash) {
    const operation = operations.find((item) => hash === `#operation-${item.id}`);
    return operation ? { kind: "selected", operation } : { kind: "unavailable", hash };
  }
  return operations.length ? { kind: "selected", operation: operations[0] } : { kind: "empty" };
}
