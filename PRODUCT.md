# Product

## Register

product

## Users

A single penetration tester running their own local instance during an
engagement. Context: mid-recon, scan files piling up, switching between the
terminal and this UI to make sense of what's been found. They are technical,
fast, and keyboard-driven; they want to scan a lot of hosts and services
quickly, spot what changed since the last scan, and jot triage notes without
friction. Not a team, not a client-facing deliverable — a personal operator
tool.

## Product Purpose

Ingest recon tool output (nmap XML today; masscan/httpx/nuclei/subfinder next),
merge it into a current-state view of hosts and services, diff any two scans to
show what changed, and let the operator annotate findings with markdown notes,
status, tags, and attachments that survive re-scans. Success = the operator
reaches for penrecon instead of grepping raw XML, and can answer "what's open
on this host, what changed since last week, and what did I note about it" in
seconds.

## Brand Personality

Modern, clean, dense, precise. Three words: **operator, legible, fast.** It
should feel like a well-made instrument — a light, information-dense surface with
monospace where the data lives (IPs, ports, versions) and a consistent icon set
for wayfinding, carried with quiet confidence and zero marketing gloss. Calm
under a lot of data. Reference points are clean modern operator tools (Linear,
Stripe, Raycast), rendered dense.

## Anti-references

Not a generic SaaS dashboard: no gradient hero-metric tiles, no pastel
card-grid-everything, no marketing-flavored admin chrome. Cards, soft elevation,
and icons are used only where they aid triage — never as filler; decoration that
doesn't carry information is noise. Also avoid the heavy enterprise-security
console look (cluttered toolbars, hierarchy-less tiny tables).

## Design Principles

- **Density serves triage.** Show many hosts and services at a glance; the
  operator scans, they don't scroll through padding.
- **Signal over chrome.** The data is the interface — IPs, ports, versions,
  diffs. Minimize anything that isn't information.
- **Notes are sacred.** User annotations are first-class and never lost to a
  re-scan; the tool protects the operator's own work above ingested data.
- **Change is the story.** "What's different since the last scan" must be
  immediately legible, not buried.
- **Fast and local.** Instant feedback, keyboard-friendly, no network detours.

## Accessibility & Inclusion

WCAG AA contrast on all text (including muted/monospace data and placeholders),
full keyboard navigation with visible focus states, and `prefers-reduced-motion`
honored on every animation. Status colors must stay distinguishable for
common color-vision deficiencies (pair color with text/shape, never color
alone).
