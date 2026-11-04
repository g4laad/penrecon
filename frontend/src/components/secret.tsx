import { useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";

export function Secret({ value }: { value: string }) {
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState("");
  if (!value)
    return <span className="muted flex min-h-7 items-center">No secret</span>;
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("Secret copied.");
    } catch {
      setVisible(true);
      setStatus(
        "Clipboard unavailable. Select the revealed secret to copy it.",
      );
    }
  }
  return (
    <div className="stack gap-1">
      <div className="flex min-h-7 items-start gap-2">
        <span className="mono block min-w-0 flex-1 select-text whitespace-pre-wrap break-all py-1">
          {visible ? value : "••••••••••••"}
        </span>
        <div className="flex shrink-0 items-center">
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={() => setVisible(!visible)}
            aria-label={visible ? "Hide secret" : "Reveal secret"}
            title={visible ? "Hide secret" : "Reveal secret"}
            aria-pressed={visible}
          >
            {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={copy}
            aria-label="Copy secret"
            title="Copy secret"
          >
            <Copy aria-hidden="true" />
          </Button>
        </div>
      </div>
      <span role="status" className="muted text-xs">
        {status}
      </span>
    </div>
  );
}
