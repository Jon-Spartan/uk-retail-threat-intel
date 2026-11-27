# UK Retail CTI local design prototype

This front end provides the application shell, Executive Overview, Retail Intelligence, Vulnerability Radar and Intelligence Feed. The hosted build is the default Pages view and uses the validated public datasets. The captured local design review uses the validated 27 November 2026 collection from 11:10 UK time and assesses freshness just after collection for a reproducible review.

## Build and review

Run the staging command from the repository root. Supply a fresh destination and either the checked-in empty snapshot or a complete downloaded public release dataset.

```sh
python -m scripts.publication stage-site data public-site
cd prototype
pnpm install --frozen-lockfile --ignore-scripts
node seed.mjs ../public-site
pnpm run build
pnpm run preview
```

The seed command copies only the input files the prototype consumes and the licensed fonts from the validated site. The review script expects a populated release dataset for its evidence tests. Supply the complete public dataset to the same Python staging command, then seed from that output.

```sh
pnpm exec playwright install chromium --only-shell
pnpm test
```

The review script serves the built bundle at the GitHub Pages repository base path and checks interactions, routes, same-origin requests, and automated accessibility. It writes 16 viewport screenshots under `review/`. The ignored build, snapshot and screenshot directories remain local.

## Decisions and limits

- The isolated lockfile uses React and React DOM for UI, Vite and TypeScript for building, Playwright and axe-core for tests. React and Vite use MIT, TypeScript uses Apache-2.0, Playwright uses Apache-2.0, and axe-core tooling uses MPL-2.0. The locally staged fonts retain their SIL Open Font Licence notices. Production adoption requires a release-specific dependency, licence and bundle review.
- The local prototype loads its staged snapshot once. The hosted build checks the canonical public assets every minute. Flash alerts and dismissal, validated daily and weekly briefings, public exports, the MITRE matrix and browser-local My Stack are part of the themed app. The new layout imports the older theme preference on first use and retains the existing My Stack and session-dismissal keys.
- Dates, editorial review, source attribution and collection states remain visible. There is no published daily trend series. Headlines use the approved title, date and links with primary disclosures shown where available.
- The fragment router demonstrates direct record links, legacy aliases for the representative views and one shareable severity filter. The full route inventory and legacy link migration are release work.
- Automated accessibility results cover the reviewed browser scenarios. Manual screen-reader, zoom and release-level WCAG review remain outstanding.
- The prototype bundle measures about 76 KB gzipped JavaScript, compared with about 27 KB for the four current production scripts compressed individually. Measure route splitting and selective data loading before approving production adoption.

## Hosted build

Use the same validated seed and locked install as above. Run `pnpm run build --mode hosted` and `node hosted.mjs copy`. Update the two content-hashed entries in the Python publication manifest and browser fixture allowlist when their names change. Include only the listed HTML, JS, CSS and licence artifacts from `redesign/`. Site staging reuses the allowlisted public fonts and stages a single canonical dataset. The historic `classic.html` URL resolves to the themed app for saved links. CI verifies the hosted build byte for byte.
