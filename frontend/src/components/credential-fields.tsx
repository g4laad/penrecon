import { useReducer } from "react";
import { CredentialSecretInput } from "./credential-secret-input";
import { NativeSelect } from "./ui/native-select";
import { Textarea } from "./ui/textarea";
import { Field } from "../common";
import type { Credential } from "../types";

type CredentialDraft = { kind: string; secret: string };
type CredentialDraftEvent =
  | { type: "kind-selected"; kind: string }
  | { type: "secret-edited"; secret: string };

function transitionCredentialDraft(state: CredentialDraft, event: CredentialDraftEvent): CredentialDraft {
  switch (event.type) {
    case "kind-selected": return { ...state, kind: event.kind };
    case "secret-edited": return { ...state, secret: event.secret };
  }
}

export function CredentialFields({
  credential,
  kinds,
}: {
  credential?: Credential;
  kinds: string[];
}) {
  const [{ kind, secret }, dispatch] = useReducer(transitionCredentialDraft, {
    kind: credential?.kind ?? "password",
    secret: credential?.secret ?? "",
  });
  return (
    <div className="form-grid">
      <Field label="Kind">
        <NativeSelect name="kind" value={kind} onChange={(event) => dispatch({ type: "kind-selected", kind: event.target.value })}>
          {kinds.map((value) => <option key={value}>{value}</option>)}
        </NativeSelect>
      </Field>
      <Field
        label="Username"
        name="username"
        defaultValue={credential?.username}
        placeholder="admin"
      />
      <div className="col-span-full">
        <CredentialSecretInput kind={kind} value={secret} onChange={(value) => dispatch({ type: "secret-edited", secret: value })} />
      </div>
      <div className="col-span-full">
        <Field label="Notes" name="notes">
          <Textarea
            name="notes"
            defaultValue={credential?.notes}
            rows={3}
            placeholder="Where and how this credential was found"
          />
        </Field>
      </div>
      <p className="muted col-span-full text-xs">
        Provide a username, a secret, or both. Credentials and their links are
        never changed by scan imports.
      </p>
    </div>
  );
}
