# UK Retail Threat Intelligence

This independent dashboard collects and presents public cyber threat intelligence relevant to UK retail, e-commerce, payments, loyalty and logistics. It helps readers prioritise which public reports to review and links back to the underlying evidence. It does not assess the security posture, technology estate or compliance of any organisation.

## Architecture

1. The Python collector reads the CISA KEV catalogue. It limits response size and redirect destinations, normalises article URLs, assigns stable IDs and tracks source health.
2. Classification adds evidence from the CVE List and FIRST EPSS when available. The pipeline writes JSON, RSS and a STIX 2.1 bundle of source reports and their URL references.
3. If configured, Gemini selects eligible evidence for daily and weekly briefings. The local verifier checks the selection and its citations. Local templates render the resulting Markdown and label AI-assisted analysis.
4. GitHub Actions serialises collection runs, scans the candidate for secrets, validates the dataset and assembles an allowlisted site artifact. A separate, gated job publishes the site to Pages. The browser uses local assets and fetches published data from the same origin.
5. Optional local notifications use a private SQLite delivery queue outside the checkout. The public data and notification state are separate.

## Install and preview

From the root of the independent checkout, use Python 3.11 and a virtual environment. Existing checked-in assets are sufficient for a preview. Node.js 24 and pnpm 11.25.0 are for asset builds and browser tests.

```sh
python -m venv .venv
# Activate with .venv\Scripts\Activate.ps1 on PowerShell or source .venv/bin/activate on POSIX.
python -m pip install --require-hashes --no-deps -r requirements.lock.txt
python -m pip check
python -m scripts.publication stage-site data public-site
python -m http.server --bind 127.0.0.1 --directory public-site 8000
```

Open [the local preview](http://127.0.0.1:8000/). The checked-in feed starts empty. The dashboard displays an uncollected snapshot until the first successful run. Use a fresh destination directory when staging again.

The collector command `python threat_intel_pipeline.py` fetches public sources and updates `data/`. Run it from the repository root. Add `--flash` for collection without a new briefing, `--briefing` to request a daily briefing outside its normal slot, or `--weekly` to request a weekly briefing. With no flags, daily briefing slots start at 07:15 on weekdays and weekly slots run from Friday at 16:00 through Sunday, London time. GitHub Actions attempts collection every 15 minutes. The first usable run in an active slot can catch up after a missed trigger.

### Configuration

No environment variables are required for the initial preview, tests or collection without briefings or notifications. Set optional values in the process environment. The collector does not load `.env` files. Use [the empty configuration template](.env.example) as a reference.

| Setting | Where to set it | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Local process environment or GitHub Actions repository secret | Enables AI-assisted selection. Briefings are unavailable without a key. |
| `DASHBOARD_URL` | Local process environment or GitHub Actions repository variable | Public dashboard URL for RSS and optional local notifications. RSS defaults to the project repository URL. |
| `WEBHOOK_URL` | Local process environment only | Optional endpoint for the local notification outbox. `GOOGLE_CHAT_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` are local fallbacks. |
| `GOOGLE_CHAT_WEBHOOK_URL` | GitHub Actions repository secret | The Google Chat incoming webhook for the hosted flash-alert job. |
| `ENABLE_GOOGLE_CHAT_FLASH_ALERTS` | GitHub Actions repository variable | Set to `true` to enable hosted delivery after configuring the webhook. |
| `NOTIFICATION_STATE_DIR` | Local process environment only | Optional persistent private directory outside the checkout and public output root. The default is `~/.uk-retail-threat-intel`. |
| `ENABLE_PAGES_PUBLICATION` | GitHub Actions repository variable | Set to `true` only after release approval. It gates Pages artifact packaging and deployment. |

## Intelligence methodology and sources

- The initial release collects CISA KEV automatically and includes reviewed NCSC and ICO guidance references. Retail watch adds dated notes with retail context, and Cyber watch covers major stories across other sectors. Both use original wording and link to the underlying sources. The collection and publication policy excludes commercial news feeds. [Sources and attribution](SOURCES.md)
- The [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) supports confirmed exploitation. A mention in reporting alone is insufficient. The [CVE List](https://github.com/CVEProject/cvelistV5) supplies published CVE records and available CVSS base scores. [FIRST EPSS](https://www.first.org/epss/) supplies dated probability estimates for verified CVEs.
- The dashboard keeps technical severity, sector priority, exploitation, and confidence separate. Retail relevance is assessed from public reporting cues. ATT&CK technique references require a source link. See [the scoring methodology](SCORING.md) for factor weights and interpretation.
- The dashboard labels stale, partial, failed and unavailable data. During a partial collection, recent reports from failed sources can be marked as retained. A total failure retains the prior snapshot. Reports in STIX and RSS link back to publishers. Source URLs are observables and must be treated as citations.

## Using the dashboard

Hosted collection is scheduled at minutes 07, 22, 37 and 52 of each hour. The dashboard’s sync button checks the latest published snapshot. If its timestamp is stale, a maintainer can start **Collect and publish UK retail intelligence** from GitHub Actions on the default branch and verify that Pages serves a newer collection timestamp.

Open **Vulnerability Radar** to filter and export catalogue results. Open a record to see its evidence, including declared products, CVSS, dated EPSS estimates, CISA KEV status, and affected versions and vendor advisories when available. **My Stack** manages browser-local preferences and labels declared product matches separately from topic matches. **Intelligence Feed** includes official headlines, reviewed press links and Cyber watch. **Intelligence Briefings** includes daily and weekly reports and the editorial roundup.

Save vulnerability, story and retail records to the **Review Queue** under Workspace. Use **To review**, **Reviewed** and **Watch for updates** to organise follow-up. The queue stays in the current browser profile and clears when you delete the site’s browser data. **Watch for updates** is a manual follow-up status. Saved entries retain a link to their source if they leave the published snapshot.

**Cyber Threat Intelligence** keeps the reviewed **Retail Sector** register and adds **Legal Sector**, **Finance Sector**, **Healthcare Sector**, and **AI Intelligence** headline views. These views match terms in the existing approved headline feeds, show feed coverage, and link to original sources. The Legal, Finance and Healthcare views also include manually reviewed links to sector guidance that stay visible during feed gaps. The executive metrics and retail priority scoring still cover UK retail.

Legal, Finance and Healthcare use the same dashboard structure as Retail, with coverage cards, publisher totals, a searchable intelligence register and reviewed resources. The cards count published reports and checked sources. The incident trend panel remains unavailable until there is enough reviewed incident history.

**Disclosure Watch** lists reviewed primary notices on the relevant sector dashboards and under Explore. The collection workflow checks the validated official-headline snapshot for potential disclosures and logs a count. An editor can run `python -m disclosure_watch path/to/official_updates.json` on a published snapshot to list candidate source links. Check the original statement, use a short factual summary, and add the approved entry to the reviewed list in `prototype/src/disclosures.tsx`. Append follow-ups to the existing incident ID. Rebuild and verify the hosted bundle before publication. Candidate screening uses headline wording, so it can miss disclosures outside the approved feeds or phrased differently.

Open **Executive** for the public sector briefing. It uses the same validated vulnerability and collection status files as CISA KEV, plus the reviewed Retail Watch notes. It uses no My Stack preferences and requires no AI key. The **Priority watch** label means a current, complete snapshot includes a documented retail-relevant record scoring at least 50. **Not assessed** is shown when that condition is unsupported. This is a project monitoring label based on the available evidence.

Open **Retail** for the reviewed retail intelligence register. Use the reporting period and category buttons to inspect public incidents, advisories, campaigns, supply chain and payments. Expand an entry to see unknown fields, dated evidence and defensive lessons. Search and filters run in the browser without storage or external requests. The Retail Watch highlights and Executive use the same register.

The incident count uses one stable editorial ID per event and the first report date in the register. Follow-ups and corrections belong to the original ID. The 30-day default counts UK calendar dates. The archive is a selection of public reports, and gaps leave other incidents outside coverage. A review older than 14 calendar days marks editorial metrics stale. Archived evidence keeps its original dates. For 90- and 365-day reporting, the interface requires dated records spanning the requested period.

- New priority threats count retail-relevant records scoring at least 50 and first observed within seven days of the collection. New retail KEVs count confirmed-exploited CVEs added by CISA within seven days with a documented sector cue. Active exploitation counts unique confirmed-exploited CVEs in the monitored snapshot.
- Incident Watch includes reviewed incidents and developments from the last 30 days. Its KPI counts only incident entries. The weekly action list combines citations from applicable vulnerability records and recently dated Retail Watch notes.
- Vulnerability counts are withheld when the collection is unavailable, failed or older than 90 minutes. Incomplete collections are marked and omit carried-forward records from the counts and rankings. The wider KEV context identifies entries with unestablished retail relevance.
- When two consecutive complete collections are available, the collector publishes an optional comparison containing the previous snapshot timestamp and public record IDs. The Executive view pairs it with the exact current snapshot and counts additions and removals from the monitored window. Retained, degraded and first-run data can leave comparison unavailable.
- The Executive distribution and category charts count validated records first seen in the 14 UTC dates ending at the snapshot timestamp. They use the published technical severity (including Unknown) and retail subsector, and exclude carried-forward records. The chart population covers the monitored sources, including records without established retail relevance. A stale snapshot can still supply explicitly dated descriptive counts. Current vulnerability KPIs, rankings and recommendations remain subject to the existing freshness checks.
- A historical trend needs versioned daily aggregates. A future collector could publish 14 days of UTC dates and counts for the four technical severity bands and Unknown, computed from complete validated snapshots. Missing or partial days should be published as gaps with coverage state. Apply the existing publication validator and allowlist, make each date a single replaceable entry, and publish no raw records, personal preferences or internal state in the trend file.

Leave **Latest from official sources** open on a screen to see new headlines appear automatically. GitHub Actions checks UK NCSC and US CISA, along with CERT-EU’s security advisories and monthly cyber briefs, on the existing 15-minute schedule. The open page checks for published updates once a minute. Actions and Pages delays can extend that interval. The panel shows up to eight headlines per feed from the past 30 days, newest first. If a source fails, the latest eligible headlines from that source stay visible with an availability notice. The browser marks the snapshot as potentially stale after one hour or when it cannot retrieve a fresh copy.

Open **Cyber news and research** for recent press links and automatically collected SANS Internet Storm Center diary headlines. The same schedule and browser refresh apply. Editors add press links to `editorial/press-links.json` with a dated primary disclosure and two independently written, fact-checked heading options. Gemini may choose an option for a new story. Publication accepts only the reviewed headings, and uses the first option if AI selection is unavailable. The press websites and their wording are outside the collector and AI input. The panel shows up to six press links and six research headlines from the past 30 days.

Run `python -m press_updates` to collect the SANS headline feed and stage the reviewed press links in `data/press_updates.json`. This command uses the existing locked dependencies and, optionally, the `GEMINI_API_KEY` GitHub Actions secret or local environment variable. For previously published fallback headings, collection retries AI selection on the first run of a new UTC day.

Run `python -m official_updates` from the repository root to collect headlines locally using the existing locked Python dependencies. The module writes optional `data/official_updates.json`, which passes through the same publication validation as the KEV dataset. Headline metadata stays separate from KEV results, alerts, exports and AI briefing inputs.

### Google Chat flash alerts

Create an incoming webhook in the chosen Google Chat space. Store the copied URL directly in the repository's Actions secret `GOOGLE_CHAT_WEBHOOK_URL`. Set the repository Actions variable `ENABLE_GOOGLE_CHAT_FLASH_ALERTS` to `true` and run the intelligence workflow on the default branch or wait for the next scheduled run. [Google Chat webhook setup](https://developers.google.com/workspace/chat/quickstart/webhooks)

The default-branch notification job runs after publication validation. It considers CISA KEV additions listed in the last two days and first observed by the collector in the last two hours. Critical severity or a sector priority of at least 50 makes a KEV a red alert. Other recent additions are labelled new KEVs. Old or retained entries are skipped. Messages link to the official source and do not require Gemini.

Before a KEV listing, editors can add a critical advisory to `editorial/urgent-vulnerabilities.json`. Verify the public CVE and the score of 9.0–10.0 in the primary advisory. Set the fields `cve`, `product`, `cvss`, `advisory_url`, `reviewed_at` (UTC), and `exploitation` (`confirmed` only when supported by the cited advisory, otherwise `unconfirmed`). The review qualifies for two hours after `reviewed_at`. A later KEV listing can produce a separate confirmation.

Hosted delivery uses a stable Google Chat message ID per CVE and alert type. Later eligible runs can retry a failed or unconfirmed send with the same ID. Chat handles message identity in the space. No delivery history belongs in the Pages artifact. Failed notification jobs appear in Actions and do not block Pages deployment. Verify receipt and duplicate handling in the intended space before relying on alerts for operational coverage. [Google Chat message IDs](https://developers.google.com/workspace/chat/api/reference/rest/v1/spaces.messages/create)

**Start here** shows up to three recent records with verified evidence and a source link. It puts structured My Stack matches first, then items first observed by the platform since this browser’s last successful visit, then the existing sector priority score. The shortlist is unavailable when collection data is stale or cannot be verified. Its visit timestamp stays in the browser.

**My Stack** checks vendor and product names declared by CISA KEV or the primary CVE record. Use a vertical bar to save aliases in a single preference. Existing terms can still match report text as topic matches. Verify affected versions and fixes in the vendor advisory.

**Weekly roundup** is a dated, manually maintained selection of key developments. Editorial updates cite the change or clarify when a disclosure was last checked. Neither requires Gemini or adds an entry to the automated feed.

## Privacy and security

- My Stack preferences stay in this browser's local storage. Filtering runs on the page, and application requests do not send the preferences. **Clear My Stack** deletes the stored preferences while preserving the theme. The flash dismissal is stored for the browser session.
- Public intake treats source text and links as untrusted. The browser renders dynamic text as text, validates external HTTP(S) links, and applies a same-origin content security policy. The CSV exporter protects formula-leading values.
- AI receives bounded public-source evidence under a separate data role. It selects from eligible IDs with tools disabled. The verifier rejects unsupported selections. The checked-in repository never needs API keys, webhook URLs, private inventories or notification state.
- The publication validator rejects unexpected files and inconsistent exports. GitHub Actions uses pinned actions, scoped permissions, secret scanning and locked dependencies. Frontend packages build or test locally and the Pages artifact includes only allowlisted files.

## Tests and development

Run tests from the repository root after installing the Python dependencies. Use a fresh `public-site` staging directory or an existing current staged build for the browser tests.

```sh
python -m unittest discover -s tests -v
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build:assets
python -m scripts.publication stage-site data public-site
pnpm exec playwright install --only-shell chromium
pnpm run test:browser
```

When deploying changes that require matching versions of the HTML, dashboard script and stylesheet, update the numeric asset revision in the two dashboard asset URLs in the HTML. This gives browsers and Pages caches a fresh URL for the updated assets.

The Python suite uses fixtures and mocked transport. The browser suite serves the staged site at a simulated Pages project path, intercepts requests and uses synthetic data. These tests make no Gemini requests or real webhook deliveries. The security workflow also audits dependency advisories, scans Git history and checks that the asset build reproduces the checked-in files. See [the remediation and verification record](SECURITY_REMEDIATION.md).

## GitHub Pages deployment

The Pages app contains Executive, Retail, Radar, Feed, MITRE ATT&CK, Briefings, My Stack and Service Health & Exports. Existing section links open their corresponding themed view. The hosted layout uses the validated public datasets. See [the front-end build instructions](prototype/README.md) for the locked build, local review and publication manifest.

- **What changed** compares complete, current views with a baseline saved in this browser. It tracks public KEV IDs, story IDs and retail timeline entries, including follow-ups. It retains up to 1,500 seen identifiers per group. An incomplete or stale group shows comparison unavailable. Mark as seen resets the comparison for available groups.
- **Daily history** keeps the latest complete vulnerability collection per UTC day for up to 90 days and displays the last 14 days. Counts reflect the monitored snapshot and confirmed catalogue matches. Missing days appear as gaps, and earlier dates are not inferred.
- **Service Health** separates the last successful collection, recent source checks, when the served Pages build was prepared and when the browser last checked. The build timestamp marks artifact preparation. A mismatch can indicate that the browser received files from different snapshots.
- **Briefings** can display a source-linked selection directly from validated public data when a validated AI-assisted briefing is unavailable. Dates and coverage limits stay visible.

After explicit publication approval, push only the clean release branch to the independent GitHub repository. Its history starts with the approved dataset. Use the latest source policy when approving additional sources.

1. Put the reviewed changes on the default branch and allow GitHub Actions to run. Keep `ENABLE_PAGES_PUBLICATION` unset for the first hosted collection and validation check.
2. Under **Settings → Pages**, choose **GitHub Actions** as the publishing source. Restrict the `github-pages` environment to the default branch and apply the repository's deployment protections.
3. Set `DASHBOARD_URL` to the approved Pages URL under **Settings → Secrets and variables → Actions → Variables**. Add `GEMINI_API_KEY` as an Actions secret only if enabling briefings.
4. Confirm a manually dispatched default-branch run produces the `validated-intelligence` artifact and inspect its collection status and contents. After release approval, set `ENABLE_PAGES_PUBLICATION` to `true` and use a subsequent scheduled or manual run to deploy the validated artifact. Verify that the Pages URL loads the dashboard and shows the expected collection state.

Unsetting the publication variable stops future workflow deployments. The previously deployed site can remain accessible until it is unpublished in Pages settings. [GitHub Pages custom workflow guide](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)

## Known limitations and appropriate use

- Sources can fail, omit information or change format. CVE and EPSS lookup budgets leave some evidence unassessed. Identical canonical URLs deduplicate, while separate URLs for syndicated copies can remain. GitHub can delay or drop scheduled triggers. The dashboard shows collection age and coverage separately.
- AI-assisted briefings can omit relevant items. Confirm consequential claims with primary sources and vendor guidance. An empty list or an unavailable feed provides no evidence of safety or regulatory compliance.
- Use this project for defensive awareness and triage. Do not use source URLs as automated blocking rules. The dashboard is not a source of legal, compliance or incident response advice.
- Redistribution rights vary by publisher. Review the terms and permitted use before adding a source. Shipped fonts and generated styling include their licence notices.
- Generic webhooks can leave delivery uncertain. Held delivery attempts require private reconciliation. Hosted deployment, live provider behaviour and licensing review need separate verification before release.
