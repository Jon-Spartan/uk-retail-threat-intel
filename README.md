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
| `WEBHOOK_URL` | Local process environment only | Optional notification endpoint. `GOOGLE_CHAT_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` are fallbacks. Webhook delivery is disabled in GitHub Actions. |
| `NOTIFICATION_STATE_DIR` | Local process environment only | Optional persistent private directory outside the checkout and public output root. The default is `~/.uk-retail-threat-intel`. |
| `ENABLE_PAGES_PUBLICATION` | GitHub Actions repository variable | Set to `true` only after release approval. It gates Pages artifact packaging and deployment. |

## Intelligence methodology and sources

- The initial release collects CISA KEV automatically and includes reviewed NCSC and ICO guidance references. The collection and publication policy excludes commercial news feeds. [Sources and attribution](SOURCES.md)
- The [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) supports confirmed exploitation. A mention in reporting alone is insufficient. The [CVE List](https://github.com/CVEProject/cvelistV5) supplies published CVE records and available CVSS base scores. [FIRST EPSS](https://www.first.org/epss/) supplies dated probability estimates for verified CVEs.
- The dashboard keeps technical severity, sector priority, exploitation, and confidence separate. Retail relevance is assessed from public reporting cues. ATT&CK technique references require a source link. See [the scoring methodology](SCORING.md) for factor weights and interpretation.
- The dashboard labels stale, partial, failed and unavailable data. During a partial collection, recent reports from failed sources can be marked as retained. A total failure retains the prior snapshot. Reports in STIX and RSS link back to publishers. Source URLs are observables and must be treated as citations.

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

The Python suite uses fixtures and mocked transport. The browser suite serves the staged site at a simulated Pages project path, intercepts requests and uses synthetic data. These tests make no Gemini requests or real webhook deliveries. The security workflow also audits dependency advisories, scans Git history and checks that the asset build reproduces the checked-in files. See [the remediation and verification record](SECURITY_REMEDIATION.md).

## GitHub Pages deployment

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
