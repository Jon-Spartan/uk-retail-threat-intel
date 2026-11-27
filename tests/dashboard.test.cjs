const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {after, before, test} = require('node:test');
const {chromium} = require('playwright');
const {buildModel} = require('../assets/executive.js');

const site = path.resolve(process.env.DASHBOARD_TEST_SITE || 'public-site');
const origin = 'https://pages.example.invalid';
const base = '/uk-retail-threat-intel/';
const allowedFiles = new Set(['index.html', 'assets/dashboard.css', 'assets/dashboard.js', 'assets/executive.js', 'assets/theme.js',
  'assets/inter.woff2', 'assets/jetbrains-mono.woff2', 'favicon.ico']);
const privateKeyword = 'private-keyword-fixture';
const sourceUrl = 'https://news.example.invalid/checkout';
const layoutMarker = '<img data-test-injected src="/unexpected-image">';
const report = {
  id: 'fixture-report', title: 'Checkout fixture', source: 'Test publisher', url: sourceUrl,
  summary: 'Test-only checkout summary', severity: 'UNKNOWN', subsector: 'ecom',
  date: 'Date unknown', tags: [], cves: [], reported_cves: [], attack_refs: []
};
const second = {...report, id: 'fixture-secondary', title: 'Logistics fixture',
  url: 'https://news.example.invalid/logistics', subsector: 'supply'};

let browser;
before(async () => {
  // Load a real staged site so missing assets or packaging regressions fail the suite.
  await fs.access(path.join(site, 'index.html'));
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
});

function hoursAgo(hours) {
  return new Date(Date.now() - hours * 3600000).toISOString();
}

function collection(state, hours = 0) {
  return {state, checked_at: hoursAgo(0), data_updated_at: hoursAgo(hours),
    last_success_at: hoursAgo(hours + 1), feeds: []};
}

async function dashboard(t, initialResponses, {checkCsp = false, clock = false, hash = ''} = {}) {
  const context = await browser.newContext({offline: true, serviceWorkers: 'block'});
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const requests = [];
  const unexpected = [];
  const errors = [];
  const responses = {'data/official_updates.json': 404, 'data/press_updates.json': 404,
    'data/executive_previous.json': 404, ...initialResponses};
  if (clock) await page.clock.install();
  if (checkCsp) {
    await page.addInitScript(() => {
      window.fixtureCspViolation = false;
      document.addEventListener('securitypolicyviolation', event => {
        if (event.blockedURI === 'inline') window.fixtureCspViolation = true;
      });
    });
  }
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    requests.push({url: request.url(), method: request.method(), body: request.postData(),
      headers: await request.allHeaders()});
    if (url.origin !== origin || !url.pathname.startsWith(base)) {
      unexpected.push(request.url());
      return route.abort();
    }
    const file = url.pathname.slice(base.length) || 'index.html';
    if (file.startsWith('data/') && Object.hasOwn(responses, file)) {
      const value = responses[file];
      if (typeof value === 'number') return route.fulfill({status: value});
      if (typeof value === 'string') return route.fulfill({body: value, contentType: 'text/plain'});
      return route.fulfill({json: value});
    }
    if (allowedFiles.has(file)) {
      if (file === 'favicon.ico') return route.fulfill({status: 404});
      const staged = path.join(site, file);
      if (file === 'index.html' && checkCsp) {
        const html = await fs.readFile(staged, 'utf8');
        return route.fulfill({contentType: 'text/html',
          body: html.replace('</body>', '<script>window.fixtureInlineRan = true</script></body>')});
      }
      return route.fulfill({path: staged});
    }
    unexpected.push(request.url());
    return route.fulfill({status: 404});
  });
  await page.goto(origin + base + hash, {waitUntil: 'domcontentloaded'});
  return {page, requests, responses, assertQuiet() {
    assert.deepEqual(unexpected, []);
    assert.deepEqual(errors, []);
  }};
}

function status(page, expected) {
  return page.waitForFunction(label => document.querySelector('#syncStatusText').textContent === label, expected);
}

function executiveKev(sequence, date, overrides = {}) {
  const id = 'CVE-2026-' + sequence;
  return {...report, id: 'cisa-kev-cve_2026_' + sequence, title: 'Public advisory fixture ' + sequence,
    source: 'CISA KEV Catalog', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + id,
    _timestamp: Date.parse(date) / 1000, first_seen_at: date,
    affected_products: [{vendor: 'Fixture vendor', product: 'Fixture gateway', source: 'cisa_kev'}],
    classification: {version: 1, components: {}, score: 70, exploitation: 'confirmed',
      relevance: 'uk_direct', confidence: 'catalogue', vulnerabilities: [{id, kev: true}]}, ...overrides};
}

test('executive model ranks verified retail evidence, deduplicates exploitation and limits editorial claims', () => {
  const now = Date.parse('2026-11-26T12:00:00Z');
  const collected = '2026-11-26T11:30:00Z';
  const metadata = {collection: {state: 'current', data_updated_at: collected, last_success_at: collected}};
  const eligible = executiveKev('10001', collected);
  const general = executiveKev('10002', collected, {classification: {...eligible.classification, relevance: 'unestablished',
    score: 95, vulnerabilities: [{id: 'CVE-2026-10002', kev: true}]}});
  const repeated = {...eligible, id: 'src-' + 'a'.repeat(64),
    classification: {...eligible.classification, relevance: 'sector', score: 53}};
  const retained = executiveKev('10003', collected, {carried_forward: true});
  const note = {title: 'Public notice fixture', summary: 'Summary from the source.', source: 'Disclosure',
    relevance: 'Payment services', action: 'Check the notification process.', date: '2026-11-25', kind: 'incident',
    url: 'https://issuer.example.invalid/notice'};
  const previous = {current_at: collected, previous_at: '2026-11-26T10:30:00Z',
    record_ids: [eligible.id, 'cisa-kev-cve_2026_10009']};
  const input = {now, metadata, previous, items: [general, retained, repeated, eligible],
    stories: [note, {...note, kind: 'development', url: note.url + '-update'},
      {...note, url: note.url + '-future', date: '2026-12-01'},
      {...note, url: 'javascript:alert(1)'}],
    evidenceFor: item => item.classification,
    safeUrl: value => value.startsWith('https://') ? value : null};
  const model = buildModel(input);
  assert.equal(model.level, 'Priority watch');
  assert.equal(model.topThreats[0].title, eligible.title);
  assert.ok(model.topThreats.every(item => item.related));
  assert.equal(model.metrics[1][1], '1');
  assert.equal(model.metrics[2][1], '1');
  assert.equal(model.metrics[3][1], '2');
  assert.equal(model.incidents.length, 2);
  assert.match(model.changes, /3 records added and 1 record left/);
  assert.equal(buildModel({...input, previous: {...previous, current_at: previous.previous_at}}).changes,
    'Change tracking not yet available.');
  const stale = buildModel({...input, now: now + 2 * 3600000});
  assert.equal(stale.metrics[0][1], 'Unavailable');
  assert.equal(stale.metrics[5][1], 'Stale');
  assert.equal(stale.level, 'Not assessed');
  assert.equal(stale.kev.length, 0);
  assert.equal(stale.actions.length, 1);
  const incomplete = buildModel({...input, metadata: {collection: {...metadata.collection, state: 'partial'}}});
  assert.equal(incomplete.level, 'Not assessed');
  assert.equal(incomplete.metrics[5][1], 'Incomplete');
  assert.match(incomplete.changes, /Comparison unavailable/);
  const generalOnly = buildModel({...input, items: [general]});
  assert.equal(generalOnly.metrics[1][1], '0');
  assert.equal(generalOnly.topThreats.length, 0);
  assert.match(generalOnly.kevNote, /Retail relevance is unestablished/);
});

test('executive charts count only validated records first seen in the 14-day UTC snapshot window', () => {
  const collected = '2026-11-26T11:30:00Z';
  const critical = executiveKev('10001', '2026-11-13T00:00:00Z', {severity: 'CRITICAL'});
  const unknown = executiveKev('10002', collected, {severity: 'UNKNOWN', subsector: 'enterprise'});
  const input = {now: Date.parse(collected), metadata: {collection: {state: 'current', data_updated_at: collected}},
    items: [critical, unknown, executiveKev('10003', '2026-11-12T23:59:59Z'), executiveKev('10004', '2026-11-27'),
      {...critical, id: 'carry', carried_forward: true}, {...unknown, id: 'invalid', url: 'javascript:alert(1)'}],
    stories: [], evidenceFor: item => item.classification, safeUrl: value => value.startsWith('https://') ? value : null};
  const model = buildModel(input);
  assert.equal(model.charts.total, 2);
  assert.match(model.charts.window, /13 Nov 2026.*26 Nov 2026.*UTC/);
  assert.deepEqual(model.charts.severity.map(entry => entry.value), [1, 0, 0, 0, 1]);
  assert.deepEqual(model.charts.categories, [{label: 'Enterprise technology', value: 1}, {label: 'Online retail', value: 1}]);
  assert.equal(buildModel({...input, items: []}).charts.total, 0);
  assert.equal(buildModel({...input, items: null}).charts, null);
  const stale = buildModel({...input, now: input.now + 91 * 60000});
  assert.equal(stale.healthStatus, 'Stale');
  assert.deepEqual(stale.charts, model.charts);
  assert.deepEqual(stale.recentThreats, []);
  assert.deepEqual(stale.actions, []);
});

test('executive view opens on mobile, compares published snapshots and withholds stale KEV actions', async t => {
  const current = collection('current');
  const item = executiveKev('10001', hoursAgo(4));
  const board = await dashboard(t, {
    'data/threats.json': [item], 'data/intelligence_status.json': {collection: current}, 'data/flash_alert.json': 404,
    'data/executive_previous.json': {current_at: current.data_updated_at, previous_at: hoursAgo(2), record_ids: []}
  });
  const {page, requests, responses} = board;
  await page.setViewportSize({width: 390, height: 845});
  await status(page, 'CURRENT');
  assert.equal(requests.some(request => request.url.includes('executive_previous.json')), false);
  await page.getByRole('link', {name: 'Executive', exact: true}).click();
  await page.getByText(/1 record added and 0 records left/).waitFor();
  assert.equal(await page.getByRole('heading', {name: 'Executive Intelligence', exact: true}).isVisible(), true);
  assert.equal(await page.locator('#searchInput').isVisible(), false);
  assert.equal(await page.locator('#executiveMetrics dd').count(), 12);
  assert.match(await page.locator('#executiveThreats').innerText(), /Priority 70\/100.*Online retail/s);
  assert.equal(await page.getByText('Historical trend unavailable').isVisible(), true);
  assert.equal(await page.locator('#executiveObservations').getByRole('link', {name: 'CISA KEV', exact: true})
    .getAttribute('href'), '#kev');
  assert.equal(await page.locator('#executiveSeverity [data-severity="unknown"] strong').innerText(), '1');
  assert.equal(await page.locator('#executiveCategories progress').getAttribute('value'), '1');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.setViewportSize({width: 1920, height: 1080});
  const cards = await page.locator('#executiveMetrics > div').evaluateAll(nodes =>
    nodes.map(node => node.getBoundingClientRect().top));
  assert.equal(new Set(cards).size, 1);
  const theme = page.getByRole('button', {name: 'Toggle Light / Dark Mode'});
  assert.equal(await page.locator('html').evaluate(node => node.classList.contains('dark')), true);
  await theme.click();
  assert.equal(await page.locator('html').evaluate(node => node.classList.contains('dark')), false);
  await theme.click();
  responses['data/intelligence_status.json'] = {collection: collection('current', 3)};
  await page.locator('#liveSyncBtn').click();
  await page.getByText(/The vulnerability snapshot is stale.*Snapshot dated/).waitFor();
  assert.match(await page.locator('#executiveChartWindow').innerText(), /Stale snapshot/);
  assert.equal(await page.locator('#executiveObservations').getByRole('link', {name: 'CISA KEV', exact: true}).count(), 0);
  assert.match(await page.locator('#executiveCategories').innerText(), /Stale snapshot/);
  assert.equal(await page.locator('#executiveThreats li').count(), 0);
  assert.equal(await page.locator('#executiveKev li').count(), 0);
  await page.getByRole('link', {name: 'CISA KEV', exact: true}).click();
  await page.locator('#searchInput').waitFor();
  board.assertQuiet();
});

test('official stories update in place and retain headlines on failure', async t => {
  const key = 'data/official_updates.json';
  const story = {source: 'ncsc', title: 'Earlier official headline', published_at: hoursAgo(2),
    url: 'https://www.ncsc.gov.uk/news/earlier-headline'};
  const snapshot = {checked_at: hoursAgo(0), sources: {ncsc: 'current', cisa: 'current',
    cert_eu_advisories: 'current', cert_eu_briefs: 'current'}, stories: [story]};
  const {page, responses, assertQuiet} = await dashboard(t, {
    'data/threats.json': [], 'data/intelligence_status.json': 404, 'data/flash_alert.json': 404, [key]: snapshot
  }, {clock: true, hash: '#official-updates'});
  const rows = page.locator('#officialUpdatesList li');
  const earlier = page.getByRole('link', {name: story.title});
  await earlier.waitFor();
  await earlier.focus();

  const latest = {...story, title: 'New official headline', url: 'https://www.ncsc.gov.uk/news/new-headline',
    published_at: hoursAgo(1)};
  const advisory = {source: 'cert_eu_advisories', title: 'CERT-EU advisory fixture', published_at: hoursAgo(3),
    url: 'https://cert.europa.eu/publications/security-advisories/2026-022'};
  responses[key] = {...snapshot, stories: [latest, story, advisory, {...story, url: 'https://www.ncsc.gov.uk.example.invalid/news/lookalike'},
    {...story, url: 'javascript:alert(1)'}]};
  await page.clock.fastForward(61000);
  await page.getByRole('link', {name: latest.title}).waitFor();
  assert.equal(await rows.count(), 3);
  assert.match(await rows.last().innerText(), /CERT-EU advisories/);
  assert.match(await rows.first().innerText(), /New official headline\s+UK NCSC/);
  assert.equal(await earlier.evaluate(link => document.activeElement === link), true);
  assert.equal(new URL(page.url()).hash, '#official-updates');

  responses[key] = {...snapshot, checked_at: hoursAgo(2),
    sources: {ncsc: 'current', cisa: 'unavailable'}, stories: [latest, story]};
  await page.clock.fastForward(61000);
  await page.getByText(/Headlines may be stale.*US CISA/).waitFor();
  responses[key] = 503;
  await Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/official_updates.json')
      && response.status() === 503),
    page.clock.fastForward(61000)
  ]);
  assert.equal(await rows.count(), 2);
  assertQuiet();
});

test('press links show their publisher, AI label and independent source', async t => {
  const headline = 'Verified press heading';
  const url = 'https://www.bleepingcomputer.com/news/security/verified-fixture/';
  const evidence = 'https://issuer.example.invalid/incident';
  const story = {source: 'bleeping', date: '2026-11-25', title: headline, url,
    evidence_url: evidence, heading_kind: 'ai-assisted'};
  const {page, assertQuiet} = await dashboard(t, {
    'data/threats.json': [], 'data/intelligence_status.json': 404, 'data/flash_alert.json': 404,
    'data/press_updates.json': {checked_at: hoursAgo(0), research: 'unavailable',
      stories: [story, {...story, title: 'Redirect fixture', url: 'https://other.example.invalid/'}]}
  }, {hash: '#press-updates'});
  const link = page.getByRole('link', {name: headline});
  await link.waitFor();
  assert.equal(await link.getAttribute('href'), url);
  assert.equal(await page.getByRole('link', {name: 'Primary source'}).getAttribute('href'), evidence);
  assert.match(await page.locator('#pressUpdatesList').innerText(), /Bleeping Computer.*AI-assisted heading/);
  assert.match(await page.locator('#pressUpdatesStatus').innerText(), /SANS feed unavailable/);
  assert.equal(await page.getByRole('link', {name: 'Redirect fixture'}).count(), 0);
  assertQuiet();
});

function titles(page) {
  return page.locator('#threatFeedContainer [data-field="title"]');
}

async function sync(page, expected) {
  await page.locator('#liveSyncBtn').click();
  await status(page, expected);
  // Rendering and any flash request complete before the next manual sync.
  await page.waitForFunction(() => document.getElementById('syncSpinner').classList.contains('hidden'));
}

test('dashboard renders source content as text, rejects unsafe links, and blocks inline scripts', {timeout: 30000}, async t => {
  const stamp = hoursAgo(1);
  const daily = {state: 'available', checked_at: stamp, generated_at: stamp, validated_at: stamp};
  const evidence = {schema_version: 1, period: 'daily', generated_at: stamp, validated_at: stamp,
    sources: [{id: 'S01', url: sourceUrl, publisher: layoutMarker}], selection: {facts: ['S01']}};
  const board = await dashboard(t, {
    'data/threats.json': [{...report, title: layoutMarker, summary: layoutMarker, url: 'javascript:void(0)'}],
    'data/intelligence_status.json': {collection: collection('current'), daily},
    'data/flash_alert.json': {...report, title: layoutMarker, url: 'javascript:void(0)'},
    'data/daily_briefing.json': evidence,
    'data/daily_summary.md': 'AI-assisted selection of public-source evidence.\n' + layoutMarker + '\nSources\n'
  }, {checkCsp: true});
  const {page} = board;
  await titles(page).first().waitFor();
  await page.locator('#flashAlertBanner').waitFor();
  assert.equal(await titles(page).first().textContent(), layoutMarker);
  assert.equal(await page.locator('#threatFeedContainer [data-field="link"][href]').count(), 0);
  assert.equal(await page.locator('#flashAlertLink').getAttribute('href'), null);
  assert.equal(await page.locator('#flashAlertTitle').textContent(), layoutMarker);
  await page.waitForFunction(() => window.fixtureCspViolation);
  assert.equal(await page.evaluate(() => window.fixtureInlineRan), undefined);

  await page.locator('#btnOpenBriefing').click();
  const briefing = page.locator('#aiBriefingContent');
  const citation = briefing.getByRole('link', {name: '[S01] ' + layoutMarker});
  await citation.waitFor();
  assert.equal(await citation.getAttribute('href'), sourceUrl);
  assert.match(await citation.getAttribute('rel'), /noopener/);
  assert.equal(await page.locator('[data-test-injected]').count(), 0);
  await page.getByRole('button', {name: 'Close', exact: true}).click();
  evidence.sources[0].url = 'javascript:void(0)';
  await page.locator('#btnOpenBriefing').click();
  await briefing.getByText('Daily briefing could not be loaded.', {exact: true}).waitFor();
  assert.equal(await briefing.locator('a').count(), 0);
  board.assertQuiet();
});

test('dashboard filters and exports locally, preserves preferences across reloads, and clears My Stack', {timeout: 30000}, async t => {
  const marked = {...report, title: '=Fixture ' + privateKeyword};
  const board = await dashboard(t, {
    'data/threats.json': [marked, second],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/flash_alert.json': marked
  });
  const {page, requests} = board;
  await titles(page).first().waitFor();
  assert.equal(await titles(page).count(), 2);
  await page.locator('#searchInput').fill('logistics');
  assert.deepEqual(await titles(page).allTextContents(), [second.title]);
  await page.locator('#searchInput').clear();
  await page.locator('#tabMitreBtn').click();
  await page.locator('#tabMitreContent').waitFor();
  await page.locator('#tabFeedBtn').click();
  await page.locator('#tabFeedContent').waitFor();
  await page.locator('#themeToggleBtn').click();
  const theme = await page.evaluate(() => localStorage.getItem('theme'));
  assert.ok(['dark', 'light'].includes(theme));

  await page.locator('[data-action="openTechStackModal"]').click();
  await page.locator('#techStackInput').fill(privateKeyword);
  await page.locator('#techStackInput').press('Enter');
  await page.locator('[data-action="closeTechStackModal"]').first().click();
  assert.equal(await page.locator('#myStackMatchCount').textContent(), '1');
  await page.locator('#myStackFilterBtn').click();
  assert.deepEqual(await titles(page).allTextContents(), [marked.title]);

  const [download] = await Promise.all([
    page.waitForEvent('download'), page.locator('[data-action="exportFilteredToCSV"]').click()
  ]);
  const csv = await fs.readFile(await download.path(), 'utf8');
  assert.ok(csv.includes("'=" + marked.title.slice(1)));
  assert.ok(!csv.includes(second.title));

  await page.locator('[data-action="dismissFlashAlert"]').click();
  await page.reload({waitUntil: 'domcontentloaded'});
  await titles(page).first().waitFor();
  assert.equal(await page.locator('#myStackMatchCount').textContent(), '1');
  assert.deepEqual(await page.evaluate(() => JSON.parse(localStorage.getItem('cti_my_tech_stack'))), [privateKeyword]);
  await sync(page, 'CURRENT');
  assert.equal(await page.locator('#flashAlertBanner').isVisible(), false);
  board.responses['data/flash_alert.json'] = second;
  await sync(page, 'CURRENT');
  await page.locator('#flashAlertBanner').waitFor();
  assert.equal(await page.locator('#flashAlertTitle').textContent(), second.title);

  await page.locator('[data-action="openTechStackModal"]').click();
  await page.locator('[data-action="clearTechStack"]').click();
  assert.equal(await page.evaluate(() => localStorage.getItem('cti_my_tech_stack')), null);
  assert.equal(await page.evaluate(() => localStorage.getItem('theme')), theme);
  assert.ok(requests.some(request => request.url.includes('/data/threats.json?')));
  for (const request of requests) {
    assert.equal(request.method, 'GET');
    assert.equal(request.body, null);
    const url = new URL(request.url);
    assert.ok(!request.url.includes(privateKeyword));
    assert.ok(!JSON.stringify(request.headers).includes(privateKeyword));
    assert.ok([...url.searchParams].every(([key, value]) => key === 't' && /^\d+$/.test(value)));
  }
  board.assertQuiet();
});

test('dashboard distinguishes retained, stale, failed, and unavailable intelligence', {timeout: 30000}, async t => {
  const partial = collection('partial');
  partial.feeds = [{name: 'Fixture feed', state: 'failed', checked_at: hoursAgo(0), last_success_at: hoursAgo(3)}];
  const stamp = hoursAgo(48);
  const daily = {state: 'failed', checked_at: hoursAgo(0), generated_at: stamp, validated_at: stamp};
  const board = await dashboard(t, {
    'data/threats.json': [{...report, carried_forward: true}],
    'data/intelligence_status.json': {collection: partial, daily},
    'data/flash_alert.json': 404,
    'data/daily_briefing.json': {schema_version: 1, period: 'daily', generated_at: stamp, validated_at: stamp,
      sources: [{id: 'S01', url: sourceUrl, publisher: report.source}], selection: {facts: ['S01']}},
    'data/daily_summary.md': 'AI-assisted selection of public-source evidence.\nRetained fixture.\nSources\n'
  });
  const {page, responses} = board;
  await status(page, 'INCOMPLETE');
  await page.getByText(/Retained from an earlier collection/).waitFor();
  await page.getByText('Collection and briefing history', {exact: true}).click();
  await page.locator('#feedHealth').getByText(/Fixture feed.*Check failed.*Last successful check/).waitFor();
  await page.locator('#collectionHistory').getByText(/Last complete collection/).waitFor();
  await page.locator('#collectionHistory').getByText(/Last weekly briefing validation.*unavailable/).waitFor();
  await page.locator('#btnOpenBriefing').click();
  await page.getByText(/earlier validated briefing \(stale\)/).waitFor();
  await page.getByRole('button', {name: 'Close', exact: true}).click();

  partial.data_updated_at = hoursAgo(3);
  await sync(page, 'STALE');
  assert.match(await page.locator('#collectionNotice').textContent(), /coverage was incomplete/);
  partial.state = 'failed';
  await sync(page, 'FAILED');
  assert.match(await page.locator('#collectionNotice').textContent(), /previous snapshot/);
  assert.deepEqual(await titles(page).allTextContents(), [report.title]);

  responses['data/threats.json'] = [];
  responses['data/intelligence_status.json'] = {collection: collection('current')};
  await sync(page, 'CURRENT');
  assert.equal(await titles(page).count(), 0);
  responses['data/threats.json'] = 404;
  await page.reload({waitUntil: 'domcontentloaded'});
  await status(page, 'UNAVAILABLE');
  assert.equal(await titles(page).count(), 0);
  board.assertQuiet();
});

test('editorial sections keep dated source links and stay separate from KEV filters on mobile', {timeout: 30000}, async t => {
  const board = await dashboard(t, {
    'data/threats.json': [report],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/flash_alert.json': 404
  });
  const {page} = board;
  await page.setViewportSize({width: 390, height: 844});
  const retail = page.getByRole('region', {name: 'Retail watch'});
  const cyber = page.getByRole('region', {name: 'Cyber watch'});
  const nav = page.getByRole('navigation', {name: 'Dashboard views'});
  const primaryLinks = await nav.getByRole('link').all();
  assert.deepEqual(await nav.getByRole('link').allTextContents(), ['Executive', 'CISA KEV', 'Stories']);
  const primaryBounds = await Promise.all(primaryLinks.map(link => link.boundingBox()));
  assert.ok(primaryBounds.every(box => box && box.height >= 44 && box.y === primaryBounds[0].y));
  const technicalNav = page.getByRole('navigation', {name: 'Technical views'});
  assert.ok((await technicalNav.boundingBox()).y >= primaryBounds[0].y + primaryBounds[0].height);
  await titles(page).first().waitFor();
  const filter = page.getByRole('region', {name: 'Filter vulnerabilities'});
  await filter.waitFor();
  assert.equal(await retail.isVisible(), false);
  await page.locator('#searchInput').fill('Checkout');
  await nav.getByRole('link', {name: 'Stories', exact: true}).click();
  await retail.waitFor();
  assert.equal(await filter.isVisible(), false);
  assert.equal(await page.locator('#threatFeedContainer').isVisible(), false);
  assert.equal(await nav.getByRole('link', {name: 'Stories', exact: true}).getAttribute('aria-current'), 'page');
  for (const section of [retail, cyber]) {
    await section.waitFor();
    const articles = await section.getByRole('article').all();
    assert.ok(articles.length > 0);
    for (const article of articles) {
      assert.ok((await article.getByRole('heading', {level: 4}).textContent()).trim());
      assert.match(await article.locator('time').first().getAttribute('datetime'), /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/);
      const links = await article.getByRole('link').all();
      assert.ok(links.length > 0);
      for (const link of links) {
        assert.ok((await link.textContent()).trim());
        const url = new URL(await link.getAttribute('href'));
        assert.equal(url.protocol, 'https:');
        assert.equal(url.username + url.password, '');
      }
    }
  }
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await page.getByRole('navigation', {name: 'Story sections'}).getByRole('link', {name: 'Cyber watch'}).click();
  assert.equal(new URL(page.url()).hash, '#cyber-watch');
  await page.reload({waitUntil: 'domcontentloaded'});
  await cyber.waitFor();
  assert.equal(await filter.isVisible(), false);

  await page.getByRole('navigation', {name: 'Story sections'}).getByRole('link', {name: 'Weekly roundup'}).click();
  assert.equal(new URL(page.url()).hash, '#weekly-roundup');
  await page.goBack();
  await cyber.waitFor();
  assert.equal(new URL(page.url()).hash, '#cyber-watch');
  await nav.getByRole('link', {name: 'CISA KEV', exact: true}).click();
  await filter.waitFor();
  assert.equal(await cyber.isVisible(), false);
  assert.equal(await nav.getByRole('link', {name: 'CISA KEV', exact: true}).getAttribute('aria-current'), 'page');
  assert.deepEqual(await titles(page).allTextContents(), [report.title]);

  await page.locator('#searchInput').fill('no matching report');
  await page.locator('#emptyFeedState').waitFor();
  await nav.getByRole('link', {name: 'Stories', exact: true}).click();
  await cyber.waitFor();
  await nav.getByRole('link', {name: 'CISA KEV', exact: true}).click();
  await filter.waitFor();
  assert.equal(await page.locator('#searchInput').inputValue(), 'no matching report');
  await page.locator('#emptyFeedState').waitFor();
  board.assertQuiet();
});

test('triage prefers declared product matches and newly observed records, withholds stale actions and keeps state local', {timeout: 30000}, async t => {
  const evidence = {version: 1, score: 75, components: {}, exploitation: 'confirmed',
    vulnerabilities: [{id: 'CVE-2024-12345', kev: true}]};
  const recent = {...report, id: 'recent-item', title: 'Recent supplier advisory', first_seen_at: hoursAgo(1),
    classification: evidence};
  const matched = {...second, id: 'matched-item', title: 'Gateway advisory',
    first_seen_at: hoursAgo(8), classification: {...evidence, score: 60},
    affected_products: [{vendor: 'Example Vendor', product: 'Edge Gateway', source: 'cisa_kev'}]};
  const priority = {...report, id: 'priority-item', title: 'High priority advisory',
    first_seen_at: hoursAgo(12), classification: {...evidence, score: 99}};
  const retained = {...report, id: 'retained-item', title: 'Retained advisory',
    first_seen_at: hoursAgo(1), carried_forward: true, classification: evidence};
  const board = await dashboard(t, {
    'data/threats.json': [priority, retained, recent, matched],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/flash_alert.json': 404
  });
  const {page, requests, responses} = board;
  await titles(page).first().waitFor();
  await page.evaluate(() => {
    localStorage.setItem('cti_last_collection_visit', String(Date.now() - 4 * 3600000));
    localStorage.setItem('cti_my_tech_stack', JSON.stringify(['private-fixture-alias | edge gateway']));
  });
  await page.reload({waitUntil: 'domcontentloaded'});
  const triage = page.getByRole('region', {name: 'Start here'});
  await triage.getByText('1 new since your last visit in this browser.', {exact: true}).waitFor();
  assert.deepEqual(await triage.getByRole('heading', {level: 4}).allTextContents(),
    [matched.title, recent.title, priority.title]);
  await triage.getByText('CISA KEV lists Example Vendor Edge Gateway. Check your version against the vendor advisory.',
    {exact: true}).waitFor();
  await page.getByText('PRODUCT MATCH (edge gateway)', {exact: true}).waitFor();
  assert.ok(requests.every(request => ![request.url, request.body, JSON.stringify(request.headers)]
    .some(value => value?.includes('private-fixture-alias'))));

  await page.locator('#tabStoriesBtn').click();
  await page.getByRole('region', {name: 'Weekly roundup'}).getByText(/19–25 November 2026/).waitFor();
  await page.getByRole('link', {name: 'Commission follow-up'}).waitFor();
  await page.locator('#tabFeedBtn').click();
  await triage.waitFor();
  responses['data/intelligence_status.json'] = {collection: collection('current', 4)};
  await sync(page, 'STALE');
  await triage.getByText(/shortlist is unavailable/).waitFor();
  assert.equal(await triage.getByRole('article').count(), 0);
  board.assertQuiet();
});
