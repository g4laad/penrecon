/** Translate document navigation into query-scoped API requests. */
export function apiUrl(url: string): string {
  const target = new URL(url, location.href);
  if (target.origin !== location.origin) throw new Error("API requests require the same origin");
  const scope = target.pathname.match(/^\/e\/([^/]+)(\/.*)?$/);
  let path = target.pathname;
  if (scope) {
    path = scope[2] && scope[2] !== "/" ? scope[2] : "/hosts";
    target.searchParams.set("engagement_id", decodeURIComponent(scope[1]));
  }
  if (!/^\/api(?:\/|$)/.test(path)) path = `/api${path}`;
  return path + (target.searchParams.size ? `?${target.searchParams}` : "");
}
