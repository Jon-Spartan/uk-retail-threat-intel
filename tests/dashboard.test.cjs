const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {after, before, test} = require('node:test');
const {chromium} = require('playwright');
const {buildModel} = require('../assets/executive.js');
const {aggregate, search, executiveStories} = require('../assets/retail.js');
const retailRegister = require('../assets/retail-intelligence.json');

const site = path.resolve(process.env.DASHBOARD_TEST_SITE || 'public-site');
const origin = 'https://pages.example.invalid';
const base = '/uk-retail-threat-intel/';
const allowedFiles = new Set(['index.html', 'classic.html', 'assets/dashboard.css', 'assets/dashboard.js', 'assets/executive.js', 'assets/theme.js',
  'assets/retail.js', 'assets/retail-intelligence.json',
  'assets/inter.woff2', 'assets/jetbrains-mono.woff2', 'favicon.ico',
  'assets/index-BXem3iOs.js', 'assets/index-Bm240rOB.css', 'fonts/inter.woff2', 'fonts/jetbrains-mono.woff2']);
const legacySource = new Map(['dashboard.css', 'dashboard.js', 'executive.js', 'theme.js', 'retail.js', 'inter.woff2',
  'jetbrains-mono.woff2'].map(name => ['assets/' + name, 'assets/' + name]));
legacySource.set('classic.html', 'index.html');
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

async function dashboard(t, initialResponses, {checkCsp = false, clock = false, hash = '', pathSuffix = 'classic.html', legacy = true} = {}) {
  const context = await browser.newContext({offline: true, serviceWorkers: 'block'});
  t.after(() => context.close());
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const requests = [];
  const unexpected = [];
  const errors = [];
  const responses = {'data/official_updates.json': 404, 'data/press_updates.json': 404, 'data/flash_alert.json': 404,
    'site_status.json': 404, 'data/intelligence_history.json': 404,
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
    if (Object.hasOwn(responses, file)) {
      const value = responses[file];
      if (typeof value === 'number') return route.fulfill({status: value});
      if (typeof value === 'string') return route.fulfill({body: value, contentType: 'text/plain'});
      return route.fulfill({json: value});
    }
    if (allowedFiles.has(file)) {
      if (file === 'favicon.ico') return route.fulfill({status: 404});
      const staged = legacy && legacySource.has(file) ? path.join(__dirname, '..', legacySource.get(file)) : path.join(site, file);
      if ((file === 'classic.html' || file === 'index.html') && checkCsp) {
        const html = await fs.readFile(staged, 'utf8');
        return route.fulfill({contentType: 'text/html',
          body: html.replace('</body>', '<script>window.fixtureInlineRan = true</script></body>')});
      }
      return route.fulfill({path: staged});
    }
    unexpected.push(request.url());
    return route.fulfill({status: 404});
  });
  await page.goto(origin + base + pathSuffix + hash, {waitUntil: 'domcontentloaded'});
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

test('retail windows count distinct report IDs and Executive uses the same 30-day total', () => {
  const now = Date.parse('2026-11-27T10:00:00Z');
  const register = retailRegister;
  const metrics = aggregate(register, 30, now);
  assert.equal(metrics.incidents.length, 4);
  assert.equal(metrics.reports.reduce((sum, [, count]) => sum + count, 0), 4);
  assert.equal(metrics.supplyReports.length, 2);
  assert.equal(search(metrics.records, {view: 'payments', sort: 'updated'})[0].id, 'retail-0003');
  assert.equal(aggregate(register, 7, now).incidents.length, 2);
  const executive = buildModel({now, stories: executiveStories(register), retailReviewedOn: register.reviewed_on,
    evidenceFor: () => null, safeUrl: url => url});
  assert.equal(executive.metrics[2][1], String(metrics.incidents.length));
  assert.equal(aggregate(register, 30, now + 16 * 86400000).stale, true);
});

test('Retail Centre searches locally, preserves unknowns and safely links reviewed evidence on mobile', async t => {
  const board = await dashboard(t, {'data/threats.json': [], 'data/intelligence_status.json': 404}, {hash: '#retail'});
  const {page, requests} = board;
  await page.clock.setFixedTime(new Date('2026-11-27T10:00:00Z'));
  await page.setViewportSize({width: 390, height: 844});
  await page.getByText('4 distinct incident records', {exact: false}).waitFor();
  assert.equal(await page.locator('#retailMetrics dd').count(), 12);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  const before = requests.filter(request => request.url.includes('retail-intelligence.json')).length;
  await page.getByRole('button', {name: 'Supply chain', exact: true}).click();
  await page.locator('#retailResults summary').filter({hasText: 'Next'}).click();
  assert.match(await page.locator('#retailResults').innerText(), /Initial access\s+Unknown/);
  assert.equal(await page.locator('#retailResults').getByRole('link', {name: 'The Register'}).count(), 1);
  await page.getByLabel('Search records').fill('nonmatching search');
  await page.getByText('No reviewed records match these filters.').waitFor();
  assert.equal(requests.filter(request => request.url.includes('retail-intelligence.json')).length, before);
  assert.equal(requests.some(request => request.url.includes('nonmatching')), false);
  board.assertQuiet();
});

test('themed tools and legacy links use canonical datasets without leaving the app', async t => {
  const current = collection('current');
  const item = executiveKev('10001', hoursAgo(4), {attack_refs: ['T1566', 'T1566'], is_flash: true});
  const board = await dashboard(t, {
    'data/threats.json': [item],
    'data/intelligence_status.json': {collection: current},
    'data/flash_alert.json': item
  }, {pathSuffix: '', hash: '#/radar', legacy: false});
  const {page, requests} = board;
  await page.getByRole('heading', {name: 'Vulnerability Radar', exact: true}).waitFor();
  await page.getByText('1 matching records').waitFor();
  assert.ok(requests.some(request => new URL(request.url).pathname === base + 'data/threats.json'));
  assert.ok(requests.some(request => new URL(request.url).pathname === base + 'assets/retail-intelligence.json'));
  const search = page.getByRole('button', {name: 'Search intelligence', exact: true});
  await search.click();
  await page.getByRole('dialog').getByRole('searchbox').fill('CVE-2026-10001');
  await page.getByRole('dialog').getByRole('link', {name: /10001/}).waitFor();
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({state: 'hidden'});
  assert.ok(await search.evaluate(node => node === document.activeElement));
  assert.equal(await page.getByRole('link', {name: /More tools|Extra tools/i}).count(), 0);
  const flash = page.getByRole('region', {name: 'Flash alert'});
  await flash.getByRole('button', {name: 'Dismiss alert'}).click();
  await page.reload();
  await page.getByText('1 matching records').waitFor();
  assert.equal(await flash.count(), 0);
  await page.goto(origin + base + 'classic.html#tabAutomationContent');
  await page.getByRole('heading', {name: 'Service Health & Exports', exact: true}).waitFor();
  assert.equal(new URL(page.url()).pathname, base + 'classic.html');
  assert.equal(await page.getByRole('link', {name: 'STIX 2.1 report bundle'}).getAttribute('href'), './data/threats.stix.json');
  assert.equal(await page.getByRole('link', {name: 'RSS intelligence feed'}).getAttribute('href'), './data/feed.xml');
  await page.getByRole('link', {name: 'MITRE ATT&CK', exact: true}).click();
  const technique = page.getByRole('link', {name: /T1566/});
  assert.match(await technique.locator('..').innerText(), /T1566 Phishing\s+1$/);
  await technique.click();
  await page.getByText('1 matching records').waitFor();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', {name: 'Export CSV'}).click();
  const download = await downloadEvent;
  const stream = await download.createReadStream();
  let csv = '';
  for await (const chunk of stream) csv += chunk;
  assert.match(csv, /T1566/);
  assert.match(csv, /CVE-2026-10001/);
  board.assertQuiet();
});

test('CVE detail shows dated evidence and the review queue keeps records and status private', async t => {
  const date = hoursAgo(1);
  const item = executiveKev('10001', date);
  const advisory = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-10001';
  Object.assign(item.classification.vulnerabilities[0], {evidence: 'cve_list', cvss: {score: 9.8, version: '3.1'},
    epss: {probability: 0.42, date: date.slice(0, 10)}, remediation: {
      affected_versions: [{vendor: 'Fixture vendor', product: 'Fixture gateway', from: '1.2', before: '1.5'}],
      vendor_advisories: [advisory]
    }});
  const board = await dashboard(t, {
    'data/threats.json': [item],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/official_updates.json': {stories: [{id: 'review-story', title: 'Queue story fixture',
      source: 'ncsc', published_at: date, url: sourceUrl}]}
  }, {pathSuffix: '', hash: '#/radar/' + item.id, legacy: false});
  const {page, requests, responses} = board;
  await page.getByText('Listed · confirmed exploitation', {exact: true}).waitFor();
  await page.getByText(/42% · /).waitFor();
  await page.getByText('9.8 / 10 · v3.1', {exact: true}).waitFor();
  await page.getByText('1.2 up to but excluding 1.5', {exact: true}).waitFor();
  assert.equal(await page.getByRole('link', {name: /Vendor advisory/}).getAttribute('href'), advisory);
  const before = requests.length;
  const navigate = hash => page.evaluate(next => {location.hash = next;}, hash);
  const save = page.getByRole('button', {name: 'Save to review queue', exact: true});
  await save.click();
  await navigate('#/feed/review-story');
  await page.getByRole('heading', {name: 'Queue story fixture', exact: true}).waitFor();
  await save.click();
  await navigate('#/retail/retail-0003');
  await page.getByRole('heading', {name: 'Evidence timeline'}).waitFor();
  await save.click();
  await navigate('#/review');
  const queue = page.getByRole('list').filter({has: page.getByRole('link', {name: 'Queue story fixture', exact: true})});
  await queue.waitFor();
  assert.equal(await queue.locator(':scope > li').count(), 3);
  const status = title => queue.getByLabel('Review status for ' + title, {exact: true});
  await status(item.title).selectOption('Reviewed');
  await status('Queue story fixture').selectOption('Watch for updates');
  const filter = page.getByLabel('Status filter');
  await filter.selectOption('Reviewed');
  assert.equal(await page.getByRole('link', {name: 'Queue story fixture', exact: true}).count(), 0);
  await filter.selectOption('All statuses');
  assert.equal(requests.length, before);
  assert.equal(new URL(page.url()).hash, '#/review');

  responses['data/threats.json'] = [];
  await page.setViewportSize({width: 390, height: 844});
  await page.reload();
  const retained = queue.getByRole('listitem').filter({hasText: item.title});
  await retained.getByText('Outside the available snapshot', {exact: true}).waitFor();
  assert.equal(await retained.getByRole('link', {name: 'Original source'}).getAttribute('href'), item.url);
  assert.equal(await status(item.title).inputValue(), 'Reviewed');
  assert.equal(await status('Queue story fixture').inputValue(), 'Watch for updates');
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await retained.getByRole('button', {name: 'Remove ' + item.title}).click();
  await retained.waitFor({state: 'detached'});
  board.assertQuiet();
});

test('sector and AI views match headlines locally and show coverage gaps', async t => {
  const titles = ['Law firm reports cyber incident', 'Banking security advisory', 'Hospital reports an outage',
    'Guidance on prompt injection', 'Retail bulletin'];
  const board = await dashboard(t, {
    'data/threats.json': [],
    'data/intelligence_status.json': {collection: collection('current')},
    'data/official_updates.json': {stories: titles.map((title, index) => ({id: 'sector-' + index,
      title, source: 'ncsc', url: sourceUrl, published_at: hoursAgo(index)}))}
  }, {pathSuffix: '', hash: '#/legal', legacy: false});
  const {page} = board;
  const pages = ['Legal Sector', 'Finance Sector', 'Healthcare Sector', 'AI Intelligence'];
  for (const [index, label] of pages.entries()) {
    await page.getByRole('link', {name: label, exact: true}).click();
    await page.getByRole('heading', {name: label, exact: true}).waitFor();
    const matches = page.getByRole('link', {name: titles[index], exact: true});
    await matches.waitFor();
    assert.equal(await matches.getAttribute('href'), '#/feed/sector-' + index);
    assert.equal(await page.getByRole('link', {name: 'Retail bulletin', exact: true}).count(), 0);
  }
  assert.match(await page.title(), /Cyber Threat Intelligence$/);
  await page.getByRole('link', {name: 'Retail Sector', exact: true}).click();
  await page.getByRole('heading', {name: 'Retail Intelligence', exact: true}).waitFor();
  board.responses['data/official_updates.json'] = 404;
  await page.getByRole('link', {name: 'AI Intelligence', exact: true}).click();
  await page.reload();
  await page.getByText('Headline coverage is unavailable.', {exact: true}).waitFor();
  for (const [label, publisher, url] of [
    ['Legal Sector', 'Cybercrime guidance for solicitors', 'https://www.sra.org.uk/solicitors/guidance/cybercrime/'],
    ['Finance Sector', 'Operational resilience resources', 'https://www.fca.org.uk/firms/operational-resilience'],
    ['Healthcare Sector', 'Cyber alerts and incident support', 'https://digital.nhs.uk/cyber-and-data-security/incidents-and-alerts']
  ]) {
    await page.getByRole('link', {name: label, exact: true}).click();
    await page.getByText('Headline coverage is unavailable.', {exact: true}).waitFor();
    assert.equal(await page.getByRole('link', {name: publisher, exact: true}).getAttribute('href'), url);
  }
  board.assertQuiet();
});

test('themed My Stack migrates browser preferences and sends no query over the network', async t => {
  const board = await dashboard(t, {
    'data/threats.json': [executiveKev('10001', hoursAgo(4))],
    'data/intelligence_status.json': {collection: collection('current')}
  }, {pathSuffix: '', hash: '#/stack', legacy: false});
  const {page, requests} = board;
  await page.evaluate(() => localStorage.setItem('cti_my_tech_stack', JSON.stringify(['Fixture gateway'])));
  await page.reload();
  await page.getByText('Declared product match', {exact: true}).waitFor();
  const before = requests.length;
  await page.getByLabel('Product or topic').fill(privateKeyword);
  await page.getByRole('button', {name: 'Add to My Stack'}).click();
  await page.getByText(privateKeyword, {exact: true}).waitFor();
  await page.getByRole('button', {name: 'Clear My Stack'}).click();
  assert.equal(await page.evaluate(() => localStorage.getItem('cti_my_tech_stack')), null);
  assert.equal(requests.length, before);
  assert.equal(requests.some(request => request.url.includes(privateKeyword) || request.body?.includes(privateKeyword)), false);
  board.assertQuiet();
});

test('themed briefings render the validated pair and reject mismatched citations', async t => {
  const stamp = hoursAgo(1);
  const evidence = {schema_version: 1, period: 'weekly', generated_at: stamp, validated_at: stamp, coverage: 'current',
    sources: [{id: 'S01', publisher: 'Public disclosure', url: sourceUrl}],
    selection: {facts: ['S01'], assessments: [], recommendations: []}};
  const summary = 'AI-assisted selection of public-source evidence.\nGenerated ' + stamp + ' · Validated ' + stamp +
    '\n\nFacts and attributed reporting\n- Reviewed disclosure. [S01]\n\nSources\n- [S01] Public disclosure <' + sourceUrl + '>\n';
  const board = await dashboard(t, {
    'data/threats.json': [],
    'data/intelligence_status.json': {collection: collection('current'), weekly: {state: 'available', generated_at: stamp, validated_at: stamp}},
    'data/weekly_briefing.json': evidence, 'data/weekly_summary.md': summary
  }, {pathSuffix: '', hash: '#/briefings/weekly', legacy: false});
  const {page, responses} = board;
  await page.getByText('Reviewed disclosure.', {exact: false}).waitFor();
  assert.equal(await page.getByRole('link', {name: '[S01] Public disclosure'}).getAttribute('href'), sourceUrl);
  responses['data/weekly_summary.md'] = summary.replace('[S01]', '[S02]');
  await page.reload();
  await page.getByText('Briefing validation or loading failed').waitFor();
  assert.equal(await page.getByRole('link', {name: '[S01] Public disclosure'}).count(), 0);
  board.assertQuiet();
});

test('Executive compares new records while open, marks them seen and shows real history gaps', async t => {
  const now = Date.parse('2026-11-27T13:00:00+00:00');
  const stamp = '2026-11-27T12:55:00+00:00';
  const officialName = 'data/official_updates.json';
  const pressName = 'data/press_updates.json';
  const retailName = 'assets/retail-intelligence.json';
  const story = {id: 'quote-1', source: 'ncsc', title: 'Published source fixture', url: 'https://www.ncsc.gov.uk/news/example',
    published_at: '2026-11-27T12:00:00+00:00'};
  const official = {checked_at: stamp, sources: {ncsc: 'current'}, stories: []};
  const dataset = structuredClone(retailRegister);
  const board = await dashboard(t, {
    'data/intelligence_status.json': {collection: {state: 'current', checked_at: stamp, data_updated_at: stamp, last_success_at: stamp}},
    'data/threats.json': [], [officialName]: official, [pressName]: {checked_at: stamp, research: 'current', stories: []},
    [retailName]: dataset,
    'data/intelligence_history.json': {version: 1, days: [
      {collected_at: '2026-11-25T13:00:00+00:00', severity: {CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0}, kev: 1},
      {collected_at: '2026-11-27T12:00:00+00:00', severity: {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0}, kev: 0}
    ]},
    'site_status.json': {prepared_at: stamp, data_updated_at: '2026-11-20T11:30:00+00:00'}
  }, {pathSuffix: '', legacy: false, clock: true});
  const {page, responses} = board;
  await page.clock.setFixedTime(new Date(now));
  await page.getByText('What changed since your last visit?').waitFor();
  await page.getByText(/No additions in the available window/).first().waitFor();
  await page.getByText('View daily counts').click();
  assert.match(await page.getByRole('row', {name: /2026-11-26/}).innerText(), /No complete collection/);
  assert.deepEqual(await page.getByRole('row', {name: /2026-11-27/}).locator('td').allTextContents(), ['0','0','0','0','0','0']);
  responses[officialName] = {...official, stories: [story]};
  responses['data/threats.json'] = [executiveKev('10021', '2026-11-27T12:50:00+00:00')];
  dataset.records[2].timeline.push({date: '2026-11-27', kind: 'update', publisher: 'Cleverbridge',
    url: 'https://grow.cleverbridge.com/incident-update', summary: 'Follow-up fixture.'});
  await page.getByRole('link', {name: 'Service Health & Exports'}).click();
  await page.getByText('Served Pages build prepared', {exact: true}).waitFor();
  await page.getByText(/different snapshots/).waitFor();
  await page.getByRole('button', {name: 'Refresh intelligence'}).click();
  await page.getByRole('link', {name: 'Executive Overview'}).click();
  await page.getByRole('link', {name: /10021/}).first().waitFor();
  await page.getByRole('link', {name: /Published source fixture/}).waitFor();
  await page.getByText(/Follow-up · 27 Nov 2026/).waitFor();
  await page.getByRole('button', {name: 'Mark as seen'}).click();
  assert.equal(await page.getByText(/No additions in the available window/).count(), 3);
  await page.getByRole('link', {name: 'Intelligence Briefings'}).click();
  await page.getByText(/Source-linked briefing/).waitFor();
  await page.getByRole('link', {name: /10021/}).waitFor();
  board.assertQuiet();
});

test('redesigned Feed separates evidence actions and retains filters on mobile navigation', async t => {
  const source = 'https://www.theregister.com/security/example';
  const primary = 'https://example.invalid/public-notice';
  const board = await dashboard(t, {
    'data/threats.json': [], 'data/intelligence_status.json': {collection: collection('current')},
    'data/official_updates.json': {checked_at: hoursAgo(0), sources: {ncsc: 'current'}, stories: [
      {id: 'official-fixture', source: 'ncsc', title: 'Official guidance fixture', url: 'https://www.ncsc.gov.uk/news/example',
        published_at: hoursAgo(1)}
    ]},
    'data/press_updates.json': {checked_at: hoursAgo(0), research: 'current', stories: [
      {id: 'press-fixture', source: 'register', title: 'Supplier disclosure fixture', url: source, evidence_url: primary,
        date: new Date().toISOString().slice(0, 10)}
    ]}
  }, {pathSuffix: '', hash: '#/feed', legacy: false});
  const {page, requests} = board;
  await page.setViewportSize({width: 1440, height: 900});
  await page.getByRole('link', {name: /Official guidance fixture/}).waitFor();
  const listing = await page.getByRole('region', {name: 'Latest reports'}).boundingBox();
  const reader = await page.getByRole('article', {name: 'Selected report'}).boundingBox();
  assert.ok(listing && reader);
  assert.ok(Math.abs(listing.width - reader.width) <= 1 && Math.abs(listing.height - reader.height) <= 1);
  assert.equal(await page.getByRole('region', {name: 'Report details'}).evaluate(element => getComputedStyle(element).overflowY), 'auto');
  await page.setViewportSize({width: 390, height: 844});
  const sources = page.getByRole('navigation', {name: 'Report sources'});
  await page.getByRole('link', {name: /Official guidance fixture/}).waitFor();
  const before = requests.length;
  await sources.getByRole('link', {name: 'Press', exact: true}).click();
  await page.getByRole('link', {name: /Official guidance fixture/}).waitFor({state: 'hidden'});
  await page.getByRole('searchbox', {name: 'Search reports'}).fill('Supplier disclosure');
  const results = page.getByRole('region', {name: 'Reports by publication date'});
  assert.equal(await results.getByRole('link').count(), 1);
  await results.getByRole('link').click();
  await page.getByRole('heading', {name: 'Supplier disclosure fixture'}).waitFor();
  assert.equal(await page.getByRole('link', {name: /Open primary disclosure/}).getAttribute('href'), primary);
  assert.equal(await page.getByRole('link', {name: /Read on The Register/}).getAttribute('href'), source);
  assert.equal(await results.isVisible(), false);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.getByRole('link', {name: 'Back to reports'}).click();
  await page.getByRole('searchbox', {name: 'Search reports'}).waitFor();
  assert.equal(await page.getByRole('searchbox', {name: 'Search reports'}).inputValue(), 'Supplier disclosure');
  assert.equal(await sources.getByRole('link', {name: 'Press', exact: true}).getAttribute('aria-current'), 'page');
  assert.equal(new URL(page.url()).hash, '#/feed?source=Press');
  assert.equal(requests.length, before);
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
  assert.deepEqual(await nav.getByRole('link').allTextContents(), ['Executive', 'CISA KEV', 'Retail', 'Stories']);
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
  await retail.getByRole('article').first().waitFor();
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
