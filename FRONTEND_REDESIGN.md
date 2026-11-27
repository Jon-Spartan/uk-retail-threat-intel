# UK Retail CTI front-end redesign proposal

Design assessment and implementation proposal for review. Baseline release `dfd1c24`, assessed 27 November 2026.

## 1. Current UX assessment

The first visit opens CISA KEV. That is a useful analyst entry point, but makes the Executive overview, Retail Centre and stories look like secondary capabilities. The six top-level destinations organise navigation around implementation areas. Finding a source-backed lesson and returning to its underlying record requires moving between Retail, Stories and Executive. Search works within CISA KEV and the Retail archive. Stories has separate headline, watch and roundup sections with no shared search or reading pane. Pipeline groups exports, while feed health sits mainly in Executive and vulnerability collection controls.

Executive and Retail have the strongest visual hierarchy. Their panels use common tokens, expose source coverage and honour missing history. KEV uses two-column cards with the same fields repeated across each result, which makes it harder to compare severity, priority and exploitation. Dense controls, small metadata and different card treatments accumulate across older views. Editorial cards, findings, recommendations and individual articles would benefit from predictable reading and evidence patterns.

| Finding | Evidence | Impact |
|---|---|---|
| Sticky navigation uses much more vertical space on phones | 65 px at 1440 px, 155 px at 390 px and 221 px at 320 px | Less content stays visible during triage |
| Both overlays allow keyboard focus into the background and stay open after Escape | Live keyboard check of My Stack and daily briefing at 1440 px. Only My Stack initially moved focus inside. Neither overlay exposed dialog semantics. | Keyboard users can lose context and interact behind an overlay |
| Navigation scrolls to a fragment without explicitly placing focus in the opened view | Hash-change handler and live navigation review | Keyboard and screen-reader users may remain in the navigation after following a link |
| Initial requests cover several data types regardless of the active view | The homepage requested collection status, threats, flash, official and press JSON. The same fetch families are polled every minute. | Shared freshness works, but route-specific data can load on demand and reuse responses |
| Routing, state, rendering and policy helpers are tightly coupled | One HTML file holds six view containers. The main script combines polling, navigation, filters, overlays, local preferences, exports and renderers. Executive and Retail have their own renderers and local DOM helpers. | A layout or interaction change can affect otherwise unrelated views |

The live Chromium pass covered all six views at 1920 × 1080, 1440 × 900, 1280 × 800, 390 × 844 and 320 × 800. Each view opened without page overflow or uncaught JavaScript errors in that pass. Accessibility findings are scoped to the inspected flows, with contrast, screen-reader and zoom audits still to run. [Live platform](https://jon-spartan.github.io/uk-retail-threat-intel/)

**Retain** the immediate analyst shortlist, KEV evidence and filters, CISA references, official and press polling, attribution and disclosure links, Retail records and corrections, daily and weekly evidence, flash dismissal, MITRE technique citations, CSV and STIX/RSS exports, local My Stack matching and clearing, theme preference, and stale or partial data handling. Preserve the existing shareable fragments and match definitions.

## 2. Architecture decision

| Criterion | A. Refactor the existing DOM front end | B. Rebuild the UI with TypeScript, Vite and React |
|---|---|---|
| Complexity | Smaller initial change. Splitting coupled DOM handlers and state grows harder as selection, navigation and search cross more views. | Higher initial setup. Route state and rendering boundaries become explicit. |
| Security | Small dependency footprint and a proven staging path. | Adds the React runtime and build tooling. Requires lock, licence and artifact review, with the current content policy as the release gate. |
| Maintainability | Native modules improve separation. Shared components and state coordination still need project conventions. | Typed adapters, components and route state give the reader, table and detail views consistent behaviour. |
| Migration risk | Existing markup and behaviour are easier to preserve initially. Large changes remain interleaved with production code. | Requires feature-parity and link tests. An isolated prototype and a staged cutover limit production exposure. |
| Long-term fit | Strong option for a small collection of lightly interactive pages. | Better fit for a shared search index, list and detail state, cross-view navigation and independent feature development. |

**Recommendation** is option B. Rebuild the application shell and views on a dedicated branch and preserve the existing intelligence contracts. Use React with TypeScript, Vite as a build-only dependency, and CSS custom properties with native HTML and SVG. Carry forward the pure scoring, attribution and aggregation logic through typed adapters and parity tests. Keep React state local to views and use a small shared dataset cache. A full router, store or component framework can be revisited if a demonstrated need arises. [Vite static deployment guidance](https://vite.dev/guide/static-deploy#github-pages)

The first prototype should use native controls, semantic tables and SVG charts with equivalent data lists. Tailwind can support a measured migration step, with semantic tokens owning the design. Defer shadcn/ui, Recharts and TanStack Table until a prototype demonstrates a concrete interaction or accessibility gap. Consider a small set of bundled Lucide icons after licence review. Exact package versions, licence obligations, advisories, transitive footprint and browser bundle cost need verification before adoption.

## 3. Information architecture and shell

| Group | Destinations and shortcuts |
|---|---|
| **Overview** | Executive Overview as the default entry, Threat Trends as an analytical section, Intelligence Briefings as a reading view |
| **Explore** | Intelligence Feed for recent reporting, Vulnerability Radar for CVEs and exploitation evidence, Intelligence Archive for public historical records, MITRE ATT&CK for cited technique exploration |
| **Retail sector** | Retail Intelligence, Incident Tracker, and direct filtered links for Supply Chain, Payment Security and Regulatory Watch. Golden Quarter is a seasonal lens with a direct link. |
| **Workspace** | My Watchlist for local bookmarks and My Stack, Service Health for freshness and validation, Sources and Methodology for attribution and exports, Preferences for theme and local-data controls |

Use a persistent, collapsible desktop sidebar and a compact global header with search, current freshness and theme. On phones use a single menu button and a modal navigation drawer. A breadcrumb is useful for archive and incident detail, and page filters stay beside the content they affect. A visible skip link goes to main content. Changing views updates the document title and places focus on the destination heading. Changing an in-view filter preserves context.

Use fragment routes under `/uk-retail-threat-intel/`, such as `#/radar?severity=high` and `#/retail/incidents/retail-0003`. Map current anchors including `#executive`, `#kev`, `#stories`, `#retail`, `#retail-watch`, `#live-intelligence`, `#tabMitreContent` and `#tabAutomationContent`. Keep story-section links working as well. Validate direct navigation, refresh and back/forward at the Pages base path. Share actions include only allowlisted public filters and public identifiers. Personal queries and My Stack keywords stay in browser state and out of URLs and network requests.

## 4. Design system

| Token | Dark | Light or usage |
|---|---|---|
| Canvas / panel / border | `#0c111b` / `#151e2b` / `#334157` | `#eef3f8` / `#ffffff` / `#cbd5e1`. Interactive edges use a separately tested contrast token. |
| Primary / secondary text | `#f1f5f9` / `#aab8cb` | `#152133` / `#44556b` |
| Accent / focus | `#38bdf8` / `#7dd3fc` | `#075985` / `#075985`. Outline and shape reinforce focus. |
| Severity | Red, orange, amber and green | Theme-specific foregrounds with explicit Critical, High, Medium, Low and Unknown labels |
| Typography | Local Inter and JetBrains Mono | 14–16 px interface/body, 12–13 px supporting text, 24–28 px headings, 28–32 px analytic figures |
| Rhythm | 4 px base, 12–16 px gaps, 8–12 px radii | 24 px desktop content gutters, 16 px mobile gutters and a 44 px design target for key touch controls |
| Grid | 12 desktop columns, with 8/4 or 7/5 splits where useful | Single-column mobile reading order, with horizontal scrolling confined to an explicitly labelled table region where necessary |

Validate proposed tokens on their actual surfaces in both themes, including disabled, selected, hover and focus states. The design combines compact navigation, analytical panel hierarchy and evidence-first layouts. Use a consistent outline icon family and visible text labels for meaningful controls. Support reduced motion, and use chart captions and data alternatives. [WCAG 2.2](https://www.w3.org/TR/WCAG22/)

## 5. Page layouts

| View and primary task | Proposed layout |
|---|---|
| **Executive Overview · Decide what to review** | Compact freshness and coverage header, a KPI strip, an analytical grid and a short evidence-linked action queue. Empty trend periods have a compact explanation and a path to source coverage. |
| **Intelligence Feed · Read and verify a report** | Search and facets over a compact list with a detail pane on desktop. Mobile opens a full-width reading view with back navigation to the same list state. Show publisher, report date, supporting disclosure, and separate facts and assessments. |
| **Vulnerability Radar · Compare and research CVEs** | Native sortable table with severity, priority, exploitation, publish date and retail relevance in distinct columns. Expand evidence or open a linked detail view. Keep shortlist cues, My Stack matching and CSV near the results. |
| **Retail Intelligence · Understand sector impact** | Incident metrics and coverage, business-function and category breakdowns, then a compact archive. Supply Chain, Payments, Regulatory and Golden Quarter use the same evidence-backed views and filters. |
| **Incident Tracker · Follow developments** | Searchable results beside a structured incident profile, evidence timeline and corrections. Keep reported impact, data exposure, unknowns and analyst lessons separately labelled. |
| **Briefings · Read a validated report** | Daily and weekly picker, article-width body, section navigation and linked evidence. Show validation date and stale state in the heading. |
| **Service Health · Diagnose missing intelligence** | Collection timeline, per-source status table, last success, last validated briefing and retention status. Provide exports and methodology links without exposing private delivery or runner state. |

## 6. Component architecture

- **Shell and navigation** own persistent landmarks, fragment resolution, legacy aliases, viewport-aware navigation and focus restoration.
- **Data adapters and selectors** load only allowlisted same-origin paths, validate inputs, keep last verified responses with their original timestamps, and share one cache for collection, news, retail and briefings. Pure selectors provide consistent IDs, counts, facets and state labels. Use server-validated data contracts and retain client-side shape checks.
- **Discovery** indexes downloaded public records in memory. Offer scoped matches for CVEs, titles, organisations, categories and evidence. Native forms, sortable table headers, result announcements and same-origin related links provide progressive disclosure. Save bookmarks by public record ID and migrate existing My Stack and theme preferences through a bounded local storage adapter with clear controls.
- **Presentation** shares status labels, KPI cards, notices, evidence references and chart summaries. Tables, reading panes and drawers compose those primitives. Use native modal dialog behaviour where applicable, with an accessible name, initial focus, Escape and return to the opener. Full page details retain direct links.

## 7. Migration and publication

Build the prototype on `feature/platform-ux-redesign` with a separate local output directory excluded from staging. Reuse published data when suitable. Synthetic fixtures are labelled, isolated to tests or local previews, and absent from the publication manifest. The first screenshot review covers the shell, Executive, Retail, Radar and Feed at 1920 × 1080, 1440 × 900, 1280 × 800 and a mobile viewport.

After design approval, migrate in independently tested view slices behind the local preview. Compare selectors and durable link behaviour with the current site. Stage the replacement against validated current, stale, partial and unavailable snapshots. Preserve dataset and export URLs, storage keys or migrate them explicitly, and document any contract changes. For build output, extend the existing validator with a narrow asset manifest for the entry, local fonts and content-hashed JS/CSS. Reject symlinks, unexpected files, path traversal and test artifacts. Keep the existing pinned and least-privilege Pages job, deployment gate and independent production branch. Publish only after approval, with the previous approved commit as the rollback point.

## 8. Security and compatibility

Keep scripts, CSS, fonts, assets and data same-origin. Test the built artifact under the existing CSP without weakening it for runtime styling, dependencies or navigation. Render evidence and briefing text as text or separately approved structured blocks. Use validated URLs for external citations. Preserve Python validation and AI evidence restrictions, provider isolation, source approvals, public privacy rules and secret scanning. Avoid tracking scripts, browser-to-model requests, new credentials or public operational-state capture.

During migration, inspect the production bundle, audit and lock dependencies, check third-party licences, and run the existing data and security regressions. Test under the repository base path against a fresh served artifact. Use persistent on-screen refresh for the views that need it and measured request reuse for the rest. [Current remediation controls](SECURITY_REMEDIATION.md)

## 9. Acceptance criteria

- The four representative workflows locate an executive action, read and verify a story, compare and open a CVE, and find a retail incident with its original evidence.
- Old and new deep links work after a fresh load, reload and Back. Shared public filters restore accurately. Malformed fragments produce a useful fallback and never construct a fetch URL.
- WCAG 2.2 AA review covers contrast, keyboard order, skip link, focus visibility and restoration, labels, announcements, reflow at 320 CSS px, both themes and chart alternatives. Test at least one screen reader and supplement automated checks with manual review. [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- Current, stale, failed, partial, empty and unavailable evidence fixtures remain distinct. Shared retail counts match. Source links, export validation and existing alert dismissal pass regression tests.
- Network tests show no external calls during search, bookmarking, watchlist edits or theme changes. The staged site contains no fixture data, private files or unexpected assets. Measure initial requests and compressed JS against the observed baseline and approve any regression with a clear user-facing benefit.
- Capture all requested screenshot sizes before migration and compare key routes visually. Release requires passing build, accessibility, browser, data-integrity and publication checks and explicit approval.

## 10. Roadmap

1. **Assessment and proposal.** Record the architecture decision, information design and project instructions.
2. **Local visual prototype.** Build the shell and four representative views, inspect real data and missing coverage, and present the screenshots and interaction flows for approval.
3. **Discovery and analyst workflows.** Implement shared loading and search, Feed, Radar, incident detail and private bookmarks. Verify preserved filters, exports and direct links.
4. **Executive, Retail and operations.** Migrate analytical views and scoped filters, then briefings, MITRE, Service Health and preferences. Exercise alerts and storage migration.
5. **Release candidate.** Run parity, accessibility, visual, performance and publication checks on the full staged site. Request approval before switching production.
