import { useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useClipboard } from "./use-clipboard";

type SecretVisibility = "masked" | "revealed";

export function Secret({ value }: { value: string }) {
  // New content starts masked and cannot inherit an earlier copy request.
  return value ? <SecretValue key={value} value={value} /> : <span className="muted flex min-h-7 items-center">No secret</span>;
}

function SecretValue({ value }: { value: string }) {
  const [visibility, setVisibility] = useState<SecretVisibility>("masked");
  const clipboard = useClipboard(value);
  const visible = visibility === "revealed";

  async function copy() {
    if (await clipboard.copy(value) === "error") setVisibility("revealed");
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
            onClick={() => setVisibility((current) => current === "masked" ? "revealed" : "masked")}
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
            aria-busy={clipboard.status === "pending"}
          >
            <Copy aria-hidden="true" />
          </Button>
        </div>
      </div>
      <span role="status" className="muted text-xs">
        {clipboard.status === "pending" ? "Copying secret…" : clipboard.status === "copied" ? "Secret copied." : clipboard.status === "error" ? "Clipboard unavailable. Select the revealed secret to copy it." : ""}
      </span>
    </div>
  );
}
