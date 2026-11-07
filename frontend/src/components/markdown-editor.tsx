import { useEffect, useId, useReducer, useRef } from "react";
import { Compartment, EditorSelection, EditorState } from "@codemirror/state";
import { drawSelection, EditorView, keymap } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap } from "@codemirror/commands";
import { markdown, markdownKeymap, markdownLanguage } from "@codemirror/lang-markdown";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { Button } from "@/components/ui/button";
import { MarkdownView } from "@/components/markdown-view";

const editorTheme = EditorView.theme({
  "&": {
    height: "100%",
    backgroundColor: "var(--background)",
    color: "var(--foreground)",
    fontSize: "0.875rem",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": {
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    lineHeight: "1.65",
    overflow: "auto",
  },
  ".cm-content": {
    padding: "0.75rem",
    minHeight: "100%",
    caretColor: "var(--foreground)",
  },
  ".cm-line": { padding: "0" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--foreground)" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
    backgroundColor: "color-mix(in oklch, var(--primary) 22%, var(--background))",
  },
  ".cm-content ::selection": {
    backgroundColor: "color-mix(in oklch, var(--primary) 22%, var(--background))",
  },
});

const markdownHighlight = HighlightStyle.define([
  { tag: tags.heading, color: "var(--primary)", fontWeight: "700" },
  { tag: tags.strong, fontWeight: "700" },
  { tag: tags.emphasis, fontStyle: "italic" },
  { tag: tags.strikethrough, textDecoration: "line-through" },
  { tag: [tags.link, tags.url], color: "var(--primary)", textDecoration: "underline" },
  { tag: tags.monospace, color: "var(--accent-foreground)", backgroundColor: "var(--accent)" },
  { tag: [tags.processingInstruction, tags.meta, tags.punctuation], color: "var(--muted-foreground)" },
  { tag: tags.quote, color: "var(--muted-foreground)", fontStyle: "italic" },
]);

function wrapSelection(view: EditorView, before: string, after: string) {
  if (view.state.readOnly) return false;
  const { state } = view;
  const selection = state.selection.main;
  view.dispatch({
    changes: {
      from: selection.from,
      to: selection.to,
      insert: before + state.sliceDoc(selection.from, selection.to) + after,
    },
    selection: EditorSelection.range(
      selection.anchor + before.length,
      selection.head + before.length,
    ),
    scrollIntoView: true,
    userEvent: "input.format",
  });
  return true;
}

function prefixLines(view: EditorView, prefix: string) {
  if (view.state.readOnly) return false;
  const { state } = view;
  const selection = state.selection.main;
  const first = state.doc.lineAt(selection.from);
  // A selection ending at the start of a line does not include that line.
  const last = state.doc.lineAt(
    selection.to > selection.from && state.doc.lineAt(selection.to).from === selection.to
      ? selection.to - 1
      : selection.to,
  );
  const changes = [];
  for (let number = first.number; number <= last.number; number++) {
    changes.push({ from: state.doc.line(number).from, insert: prefix });
  }
  const changeSet = state.changes(changes);
  view.dispatch({
    changes: changeSet,
    selection: EditorSelection.range(
      changeSet.mapPos(selection.anchor, 1),
      changeSet.mapPos(selection.head, 1),
    ),
    scrollIntoView: true,
    userEvent: "input.format",
  });
  return true;
}

function insertCode(view: EditorView) {
  const { state } = view;
  const selection = state.selection.main;
  const text = state.sliceDoc(selection.from, selection.to);
  const longestRun = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  if (text.includes("\n")) {
    const fence = "`".repeat(Math.max(3, longestRun + 1));
    const before = (selection.from === state.doc.lineAt(selection.from).from ? "" : "\n") + fence + "\n";
    const after = "\n" + fence + (selection.to === state.doc.lineAt(selection.to).to ? "" : "\n");
    return wrapSelection(view, before, after);
  }
  const delimiter = "`".repeat(longestRun + 1);
  const padding = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return wrapSelection(view, delimiter + padding, padding + delimiter);
}

type EditorMode = "write" | "preview" | "split";
type EditorSize = "compact" | "expanded";
type EditorEditability = "editable" | "locked";
type MarkdownWorkspace = {
  source: string;
  mode: EditorMode;
  size: EditorSize;
  editability: EditorEditability;
};
type MarkdownWorkspaceEvent =
  | { type: "source-edited"; source: string }
  | { type: "mode-selected"; mode: EditorMode }
  | { type: "size-toggled" }
  | { type: "editability-changed"; editability: EditorEditability };
type EditorLifecycle = { phase: "detached" } | { phase: "ready"; view: EditorView };

function transitionMarkdownWorkspace(state: MarkdownWorkspace, event: MarkdownWorkspaceEvent): MarkdownWorkspace {
  switch (event.type) {
    // CodeMirror's transaction filter, not React's asynchronous render, guards edits.
    case "source-edited": return { ...state, source: event.source };
    case "editability-changed": return { ...state, editability: event.editability };
    case "mode-selected": return state.editability === "locked" ? state : { ...state, mode: event.mode };
    case "size-toggled": return state.editability === "locked" ? state : { ...state, size: state.size === "compact" ? "expanded" : "compact" };
  }
}

export function MarkdownEditor({
  defaultValue = "",
  name = "body_md",
}: {
  defaultValue?: string;
  name?: string;
}) {
  // A failed save or a parent rerender must not replace an in-progress draft.
  const draft = useRef(defaultValue);
  const [{ source, mode, size, editability: workspaceEditability }, dispatch] = useReducer(transitionMarkdownWorkspace, {
    source: defaultValue,
    mode: "write",
    size: "compact",
    editability: "editable",
  });
  const editorParent = useRef<HTMLDivElement>(null);
  const editor = useRef<EditorLifecycle>({ phase: "detached" });
  const hiddenInput = useRef<HTMLInputElement>(null);
  const labelId = useId();
  const helpId = useId();
  const editorId = useId();
  const previewId = useId();

  useEffect(() => {
    const parent = editorParent.current;
    const input = hiddenInput.current;
    if (!parent || !input) return;
    const editability = new Compartment();
    const editableExtensions = () => {
      const readOnly = input.matches(":disabled");
      return [
        EditorState.readOnly.of(readOnly),
        EditorView.editable.of(!readOnly),
        EditorView.contentAttributes.of({ "aria-readonly": String(readOnly) }),
      ];
    };
    const view = new EditorView({
      parent,
      state: EditorState.create({
        doc: draft.current,
        extensions: [
          // Keep CR characters in existing CRLF/mixed-line-ending notes rather
          // than silently normalizing the saved source when the editor mounts.
          EditorState.lineSeparator.of("\n"),
          history(),
          drawSelection(),
          markdown({ base: markdownLanguage, addKeymap: false }),
          syntaxHighlighting(markdownHighlight),
          editorTheme,
          EditorView.lineWrapping,
          EditorView.contentAttributes.of({
            "aria-labelledby": labelId,
            "aria-describedby": helpId,
            "aria-multiline": "true",
            role: "textbox",
            spellcheck: "false",
          }),
          editability.of(editableExtensions()),
          // This synchronous check closes the gap before MutationObserver runs
          // after a save disables the surrounding fieldset.
          EditorState.transactionFilter.of((transaction) =>
            transaction.docChanged && input.matches(":disabled") ? [] : transaction,
          ),
          keymap.of([
            { key: "Mod-b", run: (target) => wrapSelection(target, "**", "**") },
            { key: "Mod-i", run: (target) => wrapSelection(target, "*", "*") },
            ...markdownKeymap,
            ...defaultKeymap,
            ...historyKeymap,
          ]),
          // Deliberately do not bind Tab: it must leave the editor normally.
          EditorView.updateListener.of((update) => {
            if (!update.docChanged) return;
            const nextSource = update.state.doc.toString();
            // Update FormData before notifying the parent's draft guard. No
            // event is emitted for initial content or read-only reconfiguration.
            input.value = nextSource;
            draft.current = nextSource;
            dispatch({ type: "source-edited", source: nextSource });
            input.dispatchEvent(new Event("input", { bubbles: true }));
          }),
        ],
      }),
    });
    editor.current = { phase: "ready", view };
    let currentEditability: EditorEditability = input.matches(":disabled") ? "locked" : "editable";
    dispatch({ type: "editability-changed", editability: currentEditability });
    const observer = new MutationObserver(() => {
      const nextEditability = input.matches(":disabled") ? "locked" : "editable";
      if (nextEditability === currentEditability) return;
      currentEditability = nextEditability;
      view.dispatch({ effects: editability.reconfigure(editableExtensions()) });
      dispatch({ type: "editability-changed", editability: nextEditability });
    });
    for (let ancestor = input.parentElement; ancestor; ancestor = ancestor.parentElement) {
      if (ancestor instanceof HTMLFieldSetElement) {
        observer.observe(ancestor, { attributes: true, attributeFilter: ["disabled"] });
      }
    }
    return () => {
      observer.disconnect();
      editor.current = { phase: "detached" };
      view.destroy();
    };
  }, [helpId, labelId]);

  useEffect(() => {
    if (mode !== "preview" && editor.current.phase === "ready") editor.current.view.requestMeasure();
  }, [mode, size]);

  function format(command: (view: EditorView) => boolean) {
    const lifecycle = editor.current;
    if (lifecycle.phase !== "ready" || mode === "preview" || hiddenInput.current?.matches(":disabled")) return;
    command(lifecycle.view);
    lifecycle.view.focus();
  }

  const paneHeight = size === "expanded" ? "min(55dvh, 40rem)" : "18rem";
  const formattingDisabled = mode === "preview" || workspaceEditability === "locked";

  return (
    <div className="min-w-0 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span id={labelId} className="text-sm font-medium">Markdown source</span>
        <div role="group" aria-label="Markdown workspace view" className="flex flex-wrap gap-1">
          {(["write", "preview", "split"] as const).map((value) => (
            <Button
              key={value}
              type="button"
              size="sm"
              variant={mode === value ? "secondary" : "ghost"}
              aria-pressed={mode === value}
              aria-controls={value === "write" ? editorId : value === "preview" ? previewId : `${editorId} ${previewId}`}
              onClick={() => dispatch({ type: "mode-selected", mode: value })}
            >
              {value === "write" ? "Write" : value === "preview" ? "Preview" : "Split"}
            </Button>
          ))}
          <Button
            type="button"
            size="sm"
            variant="ghost"
            aria-pressed={size === "expanded"}
            onClick={() => dispatch({ type: "size-toggled" })}
          >
            {size === "expanded" ? "Compact editor" : "Expand editor"}
          </Button>
        </div>
      </div>
      <div role="group" aria-label="Markdown formatting" className="flex flex-wrap gap-1">
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} title="Bold (Ctrl/Cmd+B)" onClick={() => format((view) => wrapSelection(view, "**", "**"))}><strong>Bold</strong></Button>
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} title="Italic (Ctrl/Cmd+I)" onClick={() => format((view) => wrapSelection(view, "*", "*"))}><em>Italic</em></Button>
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} onClick={() => format((view) => prefixLines(view, "## "))}>Heading</Button>
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} onClick={() => format((view) => prefixLines(view, "- "))}>List</Button>
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} onClick={() => format((view) => wrapSelection(view, "[", "]()"))}>Link</Button>
        <Button type="button" size="sm" variant="outline" disabled={formattingDisabled} onClick={() => format(insertCode)}>Code</Button>
      </div>
      <div className={mode === "split" ? "grid min-w-0 gap-3 md:grid-cols-2" : "min-w-0"}>
        <div
          id={editorId}
          hidden={mode === "preview"}
          className="min-w-0 overflow-hidden rounded-lg border border-input focus-within:border-ring focus-within:ring-2 focus-within:ring-ring/40"
          style={{ height: paneHeight }}
        >
          <div ref={editorParent} className="h-full" />
        </div>
        <section
          id={previewId}
          hidden={mode === "write"}
          aria-label="Markdown preview"
          tabIndex={0}
          className="min-w-0 overflow-auto rounded-lg border border-border bg-background p-3"
          style={{ height: paneHeight }}
        >
          {source ? <MarkdownView source={source} /> : <p className="text-sm text-muted-foreground">Nothing to preview yet.</p>}
        </section>
      </div>
      <p id={helpId} className="text-xs text-muted-foreground">
        Markdown supported. Ctrl/Cmd+B for bold, Ctrl/Cmd+I for italic. Tab moves to the next control.
      </p>
      <input ref={hiddenInput} type="hidden" name={name} value={source} readOnly />
    </div>
  );
}
