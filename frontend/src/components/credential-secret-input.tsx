import { useId, useState, type CSSProperties } from "react";
import { Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";

type CredentialSecretInputProps = {
  kind: string;
  value: string;
  onChange: (value: string) => void;
};
type SecretVisibility = "masked" | "revealed";

export function CredentialSecretInput(props: CredentialSecretInputProps) {
  // The owner retains the draft value; a kind change resets only presentation.
  return <SecretInputForKind key={props.kind} {...props} />;
}

function SecretInputForKind({ kind, value, onChange }: CredentialSecretInputProps) {
  const [visibility, setVisibility] = useState<SecretVisibility>("masked");
  const reveal = visibility === "revealed";
  const id = useId();
  const hintId = useId();
  const label = kind === "key" ? "Private key" : kind === "hash" ? "Hash" : kind === "token" ? "Token" : "Secret";
  return <div className="grid min-w-0 gap-1.5">
    <div className="flex items-center justify-between gap-2">
      <label htmlFor={id} className="text-sm font-medium">{label}</label>
      <Button type="button" size="sm" variant="ghost" aria-pressed={reveal} onClick={() => setVisibility((current) => current === "masked" ? "revealed" : "masked")}>
        {reveal ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}{reveal ? "Hide" : "Reveal"}
      </Button>
    </div>
    {kind === "key" || kind === "other" ?
      <Textarea id={id} name="secret" className="mono" rows={kind === "key" ? 5 : 3} value={value} onChange={(event) => onChange(event.target.value)} autoComplete="off" spellCheck={false} aria-describedby={hintId} style={!reveal ? { WebkitTextSecurity: "disc" } as CSSProperties : undefined} placeholder={kind === "key" ? "Paste private key" : "Paste or enter secret"} /> :
      <Input id={id} name="secret" className="mono" type={reveal ? "text" : "password"} value={value} onChange={(event) => onChange(event.target.value)} autoComplete="new-password" spellCheck={false} aria-describedby={hintId} placeholder={kind === "hash" ? "Paste hash" : kind === "token" ? "Paste token" : "Paste or enter secret"} />}
    <p id={hintId} className="text-xs text-muted-foreground">Username or secret required; either can stand alone.</p>
  </div>;
}
