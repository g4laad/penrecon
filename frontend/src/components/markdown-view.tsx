import { useRef, type ComponentPropsWithoutRef } from "react";
import { Copy } from "lucide-react";
import ReactMarkdown, { type Components, type ExtraProps } from "react-markdown";
import remarkGfm from "remark-gfm";
import { Button } from "@/components/ui/button";
import { useClipboard } from "./use-clipboard";
import "./markdown.css";

function MarkdownCodeBlock({ children, node }: ComponentPropsWithoutRef<"pre"> & ExtraProps) {
  const codeRef = useRef<HTMLPreElement>(null);
  const codeNode = node?.children[0];
  const codeText = codeNode?.type === "element" ? codeNode.children[0] : undefined;
  const clipboard = useClipboard(codeText?.type === "text" ? codeText.value : children);

  return (
    <div className="markdown-code-block">
      <div className="markdown-code-toolbar">
        <span>Code</span>
        <Button
          type="button"
          variant="ghost"
          size="xs"
          onClick={() => { void clipboard.copy(codeRef.current?.textContent ?? ""); }}
          aria-label="Copy code"
          aria-busy={clipboard.status === "pending"}
        >
          <Copy aria-hidden="true" />
          Copy
        </Button>
      </div>
      <pre ref={codeRef} tabIndex={0} aria-label="Code block">
        {children}
      </pre>
      <span className="markdown-copy-status" role="status">
        {clipboard.status === "pending" ? "Copying code…" : clipboard.status === "copied" ? "Code copied." : clipboard.status === "error" ? "Clipboard unavailable. Select the code to copy it." : ""}
      </span>
    </div>
  );
}

type MarkdownNode = {
  type: string;
  tagName?: string;
  children?: MarkdownNode[];
};

function containsImage(node: MarkdownNode | undefined): boolean {
  return node?.tagName === "img" || Boolean(node?.children?.some(containsImage));
}

const components: Components = {
  pre: MarkdownCodeBlock,
  a({ children, href, title, node }) {
    // Images become source links, including inside an existing Markdown link.
    // Unwrap that outer link rather than producing nested anchors.
    if (!href || containsImage(node)) {
      return <span title={title}>{children}</span>;
    }
    return (
      <a href={href} title={title} rel="noopener noreferrer">
        {children}
      </a>
    );
  },
  img({ src, alt, title }) {
    const description = alt ? `Image: ${alt}` : "Image";
    if (typeof src !== "string" || !src) {
      return <span className="markdown-image-source">{description} (source blocked)</span>;
    }
    return (
      <a className="markdown-image-source" href={src} title={title} rel="noopener noreferrer">
        {description} — {src}
      </a>
    );
  },
  table({ children }) {
    return (
      <div className="markdown-table-scroll" role="region" aria-label="Markdown table" tabIndex={0}>
        <table>{children}</table>
      </div>
    );
  },
};

export function MarkdownView({ source }: { source: string }) {
  if (!source) return <p className="muted text-sm">No note body.</p>;
  return (
    <div className="markdown-view">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {source}
      </ReactMarkdown>
    </div>
  );
}
