const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {after, before, test} = require('node:test');
const {chromium} = require('playwright');

const site = path.resolve(process.env.DASHBOARD_TEST_SITE || 'public-site');
const origin = 'https://pages.example.invalid';
const base = '/uk-retail-threat-intel/';
const allowedFiles = new Set(['index.html', 'assets/dashboard.css', 'assets/dashboard.js', 'assets/theme.js',
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

async function dashboard(t, initialResponses, {checkCsp = false} = {}) {
  const context = await browser.newContext({offline: true, serviceWorkers: 'block'});
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const requests = [];
  const unexpected = [];
  const errors = [];
  const responses = {...initialResponses};
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
  await page.goto(origin + base, {waitUntil: 'domcontentloaded'});
  return {page, requests, responses, assertQuiet() {
    assert.deepEqual(unexpected, []);
    assert.deepEqual(errors, []);
  }};
}

function status(page, expected) {
  return page.waitForFunction(label => document.querySelector('#syncStatusText').textContent === label, expected);
}

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

test('retail watch presents dated source links and leaves the live feed accessible on mobile', {timeout: 30000}, async t => {
  const board = await dashboard(t, {
    'data/threats.json': [report],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/flash_alert.json': 404
  });
  const {page} = board;
  await page.setViewportSize({width: 390, height: 844});
  const watch = page.getByRole('region', {name: 'Retail watch'});
  await watch.waitFor();
  await titles(page).first().waitFor();
  const articles = await watch.getByRole('article').all();
  assert.ok(articles.length > 0);
  for (const article of articles) {
    assert.ok((await article.getByRole('heading', {level: 3}).textContent()).trim());
    assert.match(await article.locator('time').getAttribute('datetime'), /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/);
    const source = article.getByRole('link');
    assert.ok((await source.textContent()).trim());
    const url = new URL(await source.getAttribute('href'));
    assert.equal(url.protocol, 'https:');
    assert.equal(url.username + url.password, '');
  }
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await watch.getByRole('link', {name: 'Jump to the live feed'}).click();
  assert.equal(new URL(page.url()).hash, '#live-intelligence');
  assert.deepEqual(await titles(page).allTextContents(), [report.title]);
  board.assertQuiet();
});
