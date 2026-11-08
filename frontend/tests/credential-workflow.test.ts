import assert from "node:assert/strict";
import test from "node:test";
import { credentialListMatches, resolveCredentialSelection } from "../src/pages/credential-workflow.ts";
import type { CredentialSummary, PageData } from "../src/types.ts";

const first: CredentialSummary = {
  id: 10, kind: "password", username: "alice", notes_preview: "",
  host_count: 1, service_count: 0,
};
const second: CredentialSummary = { ...first, id: 20, username: "bob" };

function page(overrides: Partial<PageData> = {}): PageData {
  return {
    engagements: [], credentials: [first, second], q: "", kind: "", scope: "",
    page: 1, pages: 4, per: "25", total: 100, matched: 100, ...overrides,
  };
}

test("credential summaries must match the current page and row limit", () => {
  const data = page();
  assert.equal(credentialListMatches(data, new URLSearchParams()), true);
  assert.equal(credentialListMatches(data, new URLSearchParams("page=2")), false);
  assert.equal(credentialListMatches(data, new URLSearchParams("per=50")), false);
  assert.equal(credentialListMatches(page({ page: 2, per: "50", pages: 2 }), new URLSearchParams("page=2&per=50")), true);
});

test("credential summaries must match every search filter", () => {
  const params = new URLSearchParams({ filter: "ssh", kind: "token", scope: "linked", page: "2", per: "10" });
  const data = page({ q: "ssh", kind: "token", scope: "linked", page: 2, per: "10" });
  assert.equal(credentialListMatches(data, params), true);
  for (const key of ["filter", "kind", "scope"]) {
    const changed = new URLSearchParams(params);
    changed.set(key, "different");
    assert.equal(credentialListMatches(data, changed), false);
  }
});

test("credential pagination respects normalized limits and clamped pages", () => {
  assert.equal(credentialListMatches(page({ page: 4 }), new URLSearchParams("page=999")), true);
  assert.equal(credentialListMatches(page(), new URLSearchParams("page=-1")), true);
  assert.equal(credentialListMatches(page(), new URLSearchParams("per=unknown")), true);
  assert.equal(credentialListMatches(page(), new URLSearchParams("per=025")), true);
  assert.equal(credentialListMatches(page({ per: "all", pages: 1 }), new URLSearchParams("per=all&page=999")), true);
});

test("a credential list selects its first summary only without a deep link", () => {
  assert.deepEqual(resolveCredentialSelection("", [first, second]), { status: "selected", credential: first });
  assert.deepEqual(resolveCredentialSelection("", []), { status: "empty" });
  assert.deepEqual(resolveCredentialSelection("#credential-20", [first, second]), { status: "selected", credential: second });
});

test("deep links outside a page remain loadable even with no visible summaries", () => {
  assert.deepEqual(resolveCredentialSelection("#credential-30", [first, second]), { status: "outside-page", id: 30 });
  assert.deepEqual(resolveCredentialSelection("#credential-30", []), { status: "outside-page", id: 30 });
});

test("invalid credential links never become detail requests", () => {
  for (const hash of ["#other-20", "#credential-0", "#credential--1", "#credential-1.5", "#credential-9007199254740992"]) {
    assert.deepEqual(resolveCredentialSelection(hash, [first]), { status: "unavailable", reason: "invalid" });
  }
});
