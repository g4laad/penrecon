import { useEffect, useRef, useState, type ReactNode } from "react";
import { Activity, ChevronsLeft, ChevronsRight, FolderOpen, GitCompareArrows, KeyRound, Network, Radar, Search, Terminal } from "lucide-react";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { NativeSelect, NativeSelectOption } from "./ui/native-select";
import { ScopedLink, engagementUrl } from "../common";
import type { PageData } from "../types";

export const navigation = [
  { href: "/", label: "Hosts", icon: Network },
  { href: "/credentials", label: "Credentials", icon: KeyRound },
  { href: "/operations", label: "Operations", icon: Terminal },
  { href: "/scans", label: "Scans", icon: Radar },
  { href: "/diff", label: "Scan diff", icon: GitCompareArrows },
];

export function AppShell({ data, path, className, children }: {
  data: PageData;
  path: string;
  className?: string;
  children: ReactNode;
}) {
  const [mobile, setMobile] = useState(() => matchMedia("(max-width: 700px)").matches);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [desktopCollapsed, setDesktopCollapsed] = useState(() => {
    try { return sessionStorage.getItem("penrecon.sidebar-collapsed") === "true"; }
    catch { return false; } // Storage can be disabled; navigation still works.
  });
  const sidebar = useRef<HTMLElement>(null);
  const toggleButton = useRef<HTMLButtonElement>(null);
  const modalOpen = Boolean(data.engagement) && mobile && mobileOpen;
  const collapsed = mobile ? !mobileOpen : desktopCollapsed;
  const active = path.startsWith("/hosts/") ? "/" : path;

  useEffect(() => {
    const media = matchMedia("(max-width: 700px)");
    const update = () => { setMobile(media.matches); setMobileOpen(false); };
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    if (!modalOpen) return;
    const restoreFocus = toggleButton.current;
    sidebar.current?.querySelector<HTMLAnchorElement>("a[href]")?.focus();
    return () => restoreFocus?.focus();
  }, [modalOpen]);

  function toggle() {
    if (mobile) { setMobileOpen(!mobileOpen); return; }
    const next = !desktopCollapsed;
    setDesktopCollapsed(next);
    try { sessionStorage.setItem("penrecon.sidebar-collapsed", String(next)); }
    catch { /* Keep the in-memory preference when browser storage is disabled. */ }
  }

  return (
    <div className="app-shell" data-scoped={Boolean(data.engagement)} data-collapsed={collapsed}>
      <ScopedLink className="skip-link" href="#main" inert={modalOpen}>Skip to content</ScopedLink>
      {data.engagement && (
        <aside ref={sidebar} className="app-sidebar" aria-label="Workspace navigation"
          role={modalOpen ? "dialog" : undefined} aria-modal={modalOpen || undefined}
          onKeyDown={(event) => {
            if (!modalOpen) return;
            if (event.key === "Escape") { event.preventDefault(); setMobileOpen(false); }
            if (event.key === "Tab") {
              const items = sidebar.current?.querySelectorAll<HTMLElement>("a[href],button:not(:disabled)");
              if (!items?.length) return;
              const first = items[0];
              const last = items[items.length - 1];
              if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
              else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
            }
          }}>
          <div className="sidebar-brand-row">
            <ScopedLink className="sidebar-brand" href="/engagements" aria-label="penrecon — all engagements" title="All engagements">
              <Activity aria-hidden="true" className="size-5 text-primary" /><span>penrecon</span>
            </ScopedLink>
          </div>
          <div className="sidebar-heading" aria-hidden="true">Navigate</div>
          <nav id="primary-navigation" aria-label="Primary" className="sidebar-navigation">
            {navigation.map((item) => (
              <ScopedLink key={item.href} href={item.href} aria-label={item.label} title={item.label}
                aria-current={active === item.href ? "page" : undefined}>
                <item.icon className="size-4" aria-hidden="true" /><span>{item.label}</span>
              </ScopedLink>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <ScopedLink className="sidebar-catalog" href="/engagements" aria-label="All engagements" title="All engagements">
              <FolderOpen className="size-4" aria-hidden="true" /><span>All engagements</span>
            </ScopedLink>
            <Button ref={toggleButton} variant="ghost" className="sidebar-toggle" onClick={toggle}
              aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
              title={collapsed ? "Expand navigation" : "Collapse navigation"}
              aria-expanded={!collapsed} aria-controls="primary-navigation">
              {collapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
              <span>Collapse sidebar</span>
            </Button>
          </div>
        </aside>
      )}
      {modalOpen && <button className="sidebar-backdrop" aria-label="Close expanded navigation" tabIndex={-1} onClick={() => setMobileOpen(false)} />}
      <div className={className} inert={modalOpen}>
        <header className="site-header">
          <div className="shell workspace-toolbar">
            {data.engagement ? <>
              <label className="workspace-selector"><span>Engagement</span>
                <NativeSelect value={data.engagement.id} onChange={(event) => location.assign(`/e/${event.target.value}/`)}>
                  {data.engagements.map((item) => <NativeSelectOption key={item.id} value={item.id}>{item.name}</NativeSelectOption>)}
                </NativeSelect>
              </label>
              <form role="search" aria-label="Global search" action={engagementUrl("/search")} className="workspace-search">
                <div className="workspace-search-field">
                  <Search className="size-4" aria-hidden="true" />
                  <Input type="search" name="q" aria-label={`Search ${data.engagement.name}`} placeholder="Search engagement…" defaultValue={path === "/search" ? data.q : ""} />
                  <kbd aria-hidden="true">/</kbd>
                </div>
                <Button type="submit" variant="outline">Find</Button>
              </form>
            </> : <ScopedLink className="sidebar-brand" href="/engagements"><Activity aria-hidden="true" className="size-5 text-primary" />penrecon</ScopedLink>}
          </div>
        </header>
        {children}
      </div>
    </div>
  );
}
