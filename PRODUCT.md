# Product

## Audience and purpose

penrecon is a single-user, local recon manager for a penetration tester working
between terminal commands and scan results. It should replace grepping raw output
with fast answers: what is open, what changed, what did I note, and which actions
led here?

One instance supports multiple engagements with isolated inventory, observations,
notes, credentials, and activity, even when target IPs overlap. Engagement selection
is explicit in page URLs, so separate tabs can work on different engagements.

The core workflow is to import **nmap XML and Amass hostname/IP exports**, browse
current hosts and services, compare any two scans, and maintain Markdown notes,
status, tags, attachments, and credentials. Amass adds host/name mappings, not
services. Import formats, setup, deployment, and operational contracts belong in
[README.md](README.md); committed UI behavior belongs in [DESIGN.md](DESIGN.md).

## Evidence and operator ownership

Two histories answer different questions:

- **Operation log:** manually recorded commands and actions, with up to one
  attachment per entry. It explains operator activity; it neither executes
  commands nor automatically captures terminal history.
- **Host service timeline:** timestamped scan evidence and manual service
  additions, edits, and removals, with explicit sources and before/after values.
  It explains how service state changed, independently of the operation log.

Re-scans preserve operator annotations and credentials. Manual service overrides
win over scan evidence until reset. Historical evidence remains available when a
service is removed from inventory; removal does not establish that a port closed.

Missing ports alone never imply closure, including in partial scans. Explicit
states or unambiguous nmap coverage/aggregate evidence can establish closed or
filtered states; ambiguous absence remains unknown. A scan diff's “removed” means
absent from that scan, not confirmed closed.

## Priorities and character

- **Density serves triage.** Let a technical, keyboard-driven operator scan many
  hosts and services without excessive padding or scrolling.
- **Signal over chrome.** IPs, ports, versions, and changes carry the interface.
  Use a modern, clean, light, precise surface; monospace for data and a consistent
  icon set for wayfinding. Cards, elevation, and icons must aid triage, not fill
  space. Avoid marketing dashboards and cluttered enterprise-security chrome.
- **Notes are sacred.** Protect the operator's work above ingested data.
- **Change is the story.** Make differences immediately legible.
- **Fast and local.** Favor immediate feedback, keyboard-friendly workflows,
  and no unnecessary network detours.
- **Legibility is essential.** Meet WCAG AA text contrast, including muted data
  and placeholders; provide full keyboard navigation and visible focus; honor
  reduced-motion preferences. Pair status colors with text or shape so meaning
  survives color-vision differences.

The result should feel like a calm, well-made instrument: **operator, legible,
fast**, without marketing gloss. Detailed interaction and accessibility contracts
live in [DESIGN.md](DESIGN.md).

## Non-goals

- Team collaboration or a client-facing deliverable.
- Running recon commands or automatically collecting terminal activity.
- Decorative dashboards that compete with evidence and triage.
