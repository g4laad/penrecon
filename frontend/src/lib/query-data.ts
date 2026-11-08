const serviceKeys = ["sort", "dir", "page", "per", "f_port", "f_state", "f_service", "f_status"];
const timelineKeys = ["timeline_page", "timeline_unchanged"];
const inventoryKeys = ["q", "port", "tag", "status", "change", "sort", "dir", "page", "fit"];

function resourceURL(path: string, source: URLSearchParams, keys: string[]): string {
  const params = new URLSearchParams();
  for (const key of keys) {
    for (const value of source.getAll(key)) params.append(key, value);
  }
  const query = params.toString();
  return path + (query ? `?${query}` : "");
}

/** Resource reads follow the document URL; history never contains data URLs. */
export function queryResources(target: URL, previous: URL): { urls: string[]; partial: boolean } {
  const scope = target.pathname.match(/^(\/[0-9a-f-]{36})(\/.*)$/);
  if (!scope) return { urls: [target.pathname + target.search], partial: false };
  const [, prefix, path] = scope;
  if (path === "/") {
    return { urls: [resourceURL(`${prefix}/hosts`, target.searchParams, inventoryKeys)], partial: true };
  }
  if (path === "/operations") {
    return { urls: [resourceURL(`${prefix}/operations`, target.searchParams, ["q", "page", "per"])], partial: true };
  }
  if (/^\/hosts\/\d+$/.test(path)) {
    const changed = new Set([...target.searchParams.keys(), ...previous.searchParams.keys()]
      .filter((key) => target.searchParams.getAll(key).join("\0") !== previous.searchParams.getAll(key).join("\0")));
    if ([...changed].some((key) => !serviceKeys.includes(key) && !timelineKeys.includes(key))) {
      return { urls: [target.pathname + target.search], partial: false };
    }
    const timelineChanged = timelineKeys.some((key) => changed.has(key));
    const servicesChanged = serviceKeys.some((key) => changed.has(key));
    const urls: string[] = [];
    if (servicesChanged || (!timelineChanged && target.hash !== "#timeline")) {
      urls.push(resourceURL(`${prefix}${path}/services`, target.searchParams, serviceKeys));
    }
    if (timelineChanged || (!servicesChanged && target.hash === "#timeline")) {
      urls.push(resourceURL(`${prefix}${path}/timeline`, target.searchParams, timelineKeys));
    }
    return { urls, partial: true };
  }
  return { urls: [target.pathname + target.search], partial: false };
}
