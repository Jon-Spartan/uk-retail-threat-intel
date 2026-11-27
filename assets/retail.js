'use strict';

const retailCentre = (() => {
  const day = 86400000;
  const names = {
    incident: 'Incident', advisory: 'Advisory', campaign: 'Campaign', development: 'Development',
    uk_direct: 'Direct UK retail', sector: 'Sector relevance', first_party: 'First-party disclosure',
    attributed: 'Attributed reporting', investigating: 'Investigating', resolved: 'Resolved', reported: 'Reported',
    guidance: 'Guidance', unknown: 'Unknown', ecommerce: 'E-commerce', ecommerce_fraud: 'E-commerce fraud',
    payments: 'Payments', payment: 'Payment provider', payment_card: 'Payment card compromise', phishing: 'Phishing and social engineering',
    physical_stores: 'Physical stores', logistics: 'Warehousing and logistics', supply_chain: 'Supply chain', customer_data: 'Customer data',
    contact_centres: 'Contact centres', enterprise: 'Enterprise technology', loyalty: 'Loyalty programmes',
    ransomware: 'Ransomware and extortion', credential_theft: 'Credential theft', exploitation: 'Vulnerability exploitation',
    data_breach: 'Data breach', disruption: 'DDoS and operational disruption', insider: 'Insider threats',
    ai_enabled: 'AI-enabled attacks', unclassified: 'Unclassified', saas: 'SaaS provider', managed_service: 'Managed service provider',
    marketing: 'Marketing provider', customer_service: 'Customer service provider', cloud: 'Cloud provider',
    report: 'Initial report', update: 'Update', correction: 'Correction', evidence_review: 'Evidence reviewed'
  };
  const ukDay = new Intl.DateTimeFormat('sv-SE', {timeZone: 'Europe/London', year: 'numeric', month: '2-digit', day: '2-digit'});
  const displayDay = new Intl.DateTimeFormat('en-GB', {dateStyle: 'medium', timeZone: 'UTC'});
  const todayFor = now => Date.parse(ukDay.format(now));
  const windowContains = (date, today, days) => date <= today && date >= today - (days - 1) * day;
  const payments = record => record.functions.includes('payments');
  const supply = record => record.categories.includes('supply_chain');
  const dateOf = record => record.timeline[0].date;
  const latestOf = record => record.timeline.at(-1).date;

  function aggregate(register, days, now = Date.now()) {
    if (!register) return null;
    const today = todayFor(now);
    const reviewed = Date.parse(register.reviewed_on);
    const records = register.records.filter(record => windowContains(Date.parse(dateOf(record)), today, days));
    const incidents = records.filter(record => record.kind === 'incident');
    const counts = values => [...values.reduce((result, value) => result.set(value, (result.get(value) || 0) + 1), new Map())]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const first = register.records.map(dateOf).sort()[0];
    return {
      records, incidents, first, stale: !windowContains(reviewed, today, 15),
      span: first ? (today - Date.parse(first)) / day + 1 : 0,
      sources: new Set(records.flatMap(record => record.timeline.map(entry => entry.publisher))).size,
      categories: counts(incidents.flatMap(record => record.categories)),
      functions: counts(incidents.flatMap(record => record.functions)),
      geography: counts(incidents.map(record => record.geography || 'Unknown')),
      reports: counts(incidents.map(dateOf)),
      supplyReports: counts(incidents.filter(supply).map(dateOf)),
      paymentReports: counts(records.filter(payments).map(dateOf))
    };
  }

  function search(records, filters = {}) {
    const term = (filters.search || '').trim().toLowerCase();
    return records.filter(record =>
      (!term || [record.title, record.organisation, ...record.timeline.map(entry => entry.summary)].some(text => text.toLowerCase().includes(term))) &&
      (!filters.kind || record.kind === filters.kind) &&
      (!filters.category || record.categories.includes(filters.category)) &&
      (!filters.function || record.functions.includes(filters.function)) &&
      (!filters.geography || (record.geography || 'Unknown') === filters.geography) &&
      (!filters.organisation || record.organisation === filters.organisation) &&
      (!filters.status || record.status === filters.status) &&
      (!filters.relevance || record.relevance === filters.relevance) &&
      (!filters.confidence || record.confidence === filters.confidence) &&
      (!filters.source || record.timeline.some(entry => entry.publisher === filters.source)) &&
      (!filters.view || ({incidents: record.kind === 'incident', campaigns: record.kind === 'campaign',
        supply: supply(record), payments: payments(record)})[filters.view]))
      .sort((a, b) => (filters.sort === 'updated' ? latestOf(b).localeCompare(latestOf(a)) : dateOf(b).localeCompare(dateOf(a))) ||
        a.id.localeCompare(b.id));
  }

  let pending;
  function load() {
    pending ||= fetch('./assets/retail-intelligence.json?t=2026112704', {signal: AbortSignal.timeout(5000)})
      .then(response => {
        if (!response.ok) throw Error('Retail register unavailable.');
        return response.json();
      })
      .then(register => {
        if (register.version !== 1 || !Number.isFinite(Date.parse(register.reviewed_on)) || !Array.isArray(register.records)) {
          throw Error('Retail register unavailable.');
        }
        return register;
      })
      .catch(() => { pending = null; return null; });
    return pending;
  }

  function executiveStories(register) {
    return (register?.records || []).filter(record => ['incident', 'advisory', 'development'].includes(record.kind)).map(record => {
      const evidence = record.timeline[0];
      return {id: record.id, kind: record.kind === 'advisory' ? 'development' : record.kind,
        relevance: names[record.relevance], title: record.title, date: dateOf(record),
        summary: evidence.summary, source: evidence.publisher, url: evidence.url, action: record.lesson};
    });
  }

  async function renderWatch(safeUrl) {
    const container = byId('retailWatchCards');
    if (container.childElementCount && container.firstElementChild.tagName === 'ARTICLE') return;
    const register = await load();
    const highlights = search(register?.records || []).slice(0, 3);
    const cards = highlights.map(record => {
      const report = record.timeline[0];
      const card = element('article', '', 'executive-panel retail-watch-card');
      const date = element('time', prettyDate(report.date));
      date.dateTime = report.date;
      card.append(date, element('h4', record.title), element('p', report.summary), sourceLink(report, safeUrl));
      return card;
    });
    container.replaceChildren(...(cards.length ? cards : [element('p', 'Reviewed retail highlights are unavailable.')]));
  }

  const element = (tag, text = '', classes = '') => {
    const node = document.createElement(tag);
    node.textContent = text;
    if (classes) node.className = classes;
    return node;
  };
  const byId = id => document.getElementById(id);
  const label = value => names[value] || value;
  const prettyDate = date => displayDay.format(Date.parse(date));
  const listNames = values => values.map(label).join(' · ') || 'Unknown';
  function sourceLink(entry, safeUrl) {
    const url = safeUrl(entry.url);
    if (!url || new URL(url).protocol !== 'https:') return element('span', 'Source unavailable');
    const anchor = element('a', entry.publisher, 'executive-link');
    anchor.href = url;
    anchor.rel = 'noopener noreferrer';
    return anchor;
  }

  function renderBars(target, entries, max, format = label, empty = 'No reviewed records in this window.') {
    const rows = element('ul', '', 'executive-categories');
    for (const [key, value] of entries) {
      const row = element('li', '', 'executive-category');
      const bar = element('progress');
      bar.max = max;
      bar.value = value;
      bar.setAttribute('aria-hidden', 'true');
      row.append(element('span', format(key)), element('strong', String(value)), bar);
      rows.append(row);
    }
    target.replaceChildren(entries.length ? rows : element('p', empty, 'executive-meta'));
  }

  function renderRecord(record, safeUrl) {
    const details = element('details', '', 'retail-record');
    const summary = element('summary');
    summary.append(element('span', label(record.kind), 'retail-record-kind'),
      element('strong', record.title), element('span', prettyDate(dateOf(record)) + ' · ' + label(record.confidence), 'executive-meta'));
    const facts = element('dl', '', 'executive-health');
    const fields = [
      ['Organisation', record.organisation + ' · ' + record.organisation_type],
      ['Geography', record.geography], ['Status', label(record.status)], ['Retail relevance', label(record.relevance)],
      ['Threat categories', listNames(record.categories)], ['Retail functions', listNames(record.functions)],
      ['Latest evidence', prettyDate(latestOf(record))], ['Validation', 'Editorially reviewed'],
      ...(record.supplier_type ? [['Supplier category', label(record.supplier_type)]] : []),
      ...(record.kind === 'incident' ? [['Initial access', record.initial_access], ['Publicly reported impact', record.impact],
        ['Data exposure', record.exposure]] : [])
    ];
    for (const [name, value] of fields) {
      const pair = element('div');
      pair.append(element('dt', name), element('dd', value || 'Unknown'));
      facts.append(pair);
    }
    const evidence = element('ol', '', 'executive-list');
    for (const entry of record.timeline) {
      const row = element('li');
      row.append(element('strong', prettyDate(entry.date) + ' · ' + label(entry.kind)),
        element('p', entry.summary), sourceLink(entry, safeUrl));
      evidence.append(row);
    }
    details.append(summary, facts, element('h4', 'Evidence timeline'), evidence,
      element('p', 'Defensive lesson · ' + record.lesson));
    return details;
  }

  let activeView = '';
  let connected;
  async function open(safeUrl) {
    if (connected) return;
    const register = await load();
    if (connected) return;
    if (!register) {
      byId('retailFreshness').textContent = 'Unavailable';
      byId('retailCoverage').textContent = 'The reviewed register could not be loaded.';
      return;
    }
    connected = true;
    const controls = byId('retailFilters');
    const period = byId('retailPeriod');
    const topics = byId('retailViews');
    const all = aggregate(register, 365);
    for (const option of period.options) {
      if (Number(option.value) > 30 && all.span < Number(option.value)) option.disabled = true;
    }
    const facets = {
      category: record => record.categories, function: record => record.functions,
      geography: record => [record.geography || 'Unknown'], organisation: record => [record.organisation],
      status: record => [record.status], kind: record => [record.kind], relevance: record => [record.relevance],
      confidence: record => [record.confidence], source: record => record.timeline.map(entry => entry.publisher)
    };
    for (const [key, select] of Object.entries(facets)) {
      for (const value of [...new Set(register.records.flatMap(select))].sort((a, b) => label(a).localeCompare(label(b)))) {
        const option = element('option', label(value));
        option.value = value;
        controls.elements.namedItem(key).append(option);
      }
    }

    function render() {
      const days = Number(period.value);
      const model = aggregate(register, days);
      const {records, incidents, stale} = model;
      const windowText = 'Last ' + days + ' days · reviewed register';
      byId('retailFreshness').textContent = (stale ? 'Stale · ' : 'Reviewed · ') + prettyDate(register.reviewed_on);
      byId('retailCoverage').textContent = (model.first ? 'Earliest reviewed report: ' + prettyDate(model.first) + '. ' : '') +
        'Selected public disclosures only. Missing periods and unreported incidents are outside coverage.';
      const metrics = [
        ['Reported incidents', incidents.length, '▲', 'priority'], ['Supply chain incidents', incidents.filter(supply).length, '◆', 'exploitation'],
        ['Retail advisories', records.filter(record => record.kind === 'advisory').length, '▤', 'actions'],
        ['Payment developments', records.filter(payments).length, '▣', 'incidents'],
        ['High-priority retail intelligence', 'Unassessed', '!', 'kev'], ['Source coverage', model.sources, '▥', 'coverage']
      ];
      byId('retailMetrics').replaceChildren(...metrics.map(([name, count, icon, tone]) => {
        const card = element('div', '', 'executive-kpi');
        card.dataset.icon = tone;
        const title = element('dt', name);
        const marker = element('span', icon, 'executive-kpi-icon');
        marker.setAttribute('aria-hidden', 'true');
        title.prepend(marker);
        const value = stale && typeof count === 'number' ? 'Stale' : String(count);
        card.append(title, element('dd', value, typeof count === 'number' && !stale ? 'executive-value executive-number' : 'executive-value'),
          element('dd', count === 'Unassessed' ? 'Evidence-based priority criteria pending' : windowText, 'executive-meta'));
        return card;
      }));
      const brief = byId('retailBrief');
      brief.textContent = stale ? 'Editorial review is stale. Archive entries remain available with their original dates.' :
        incidents.length ? incidents.length + ' distinct incident records in this window. Reported functions include ' +
          model.functions.map(([key]) => label(key).toLowerCase()).join(', ') + '.' : 'No incidents in the reviewed register for this window.';
      const links = byId('retailBriefSources');
      links.replaceChildren(...incidents.map(record => sourceLink(record.timeline[0], safeUrl)));
      const trend = model.span >= days && !stale;
      for (const [id, entries] of [['retailTrend', model.reports], ['retailSupplyTrend', model.supplyReports],
        ['retailPaymentTrend', model.paymentReports]]) {
        renderBars(byId(id), trend ? entries.slice().sort(([a], [b]) => a.localeCompare(b)) : [], Math.max(1, records.length),
          prettyDate, trend ? 'No reviewed records in this window.' : 'Insufficient current dated coverage for this trend.');
      }
      renderBars(byId('retailFunctions'), model.functions, Math.max(1, incidents.length));
      renderBars(byId('retailCategories'), model.categories, Math.max(1, incidents.length));
      renderBars(byId('retailGeography'), model.geography, Math.max(1, incidents.length));
      byId('retailChartStatus').textContent = stale ? 'Charts show counts from a stale editorial archive.' :
        'Counts are from reviewed incident records. A record can contribute to multiple categories.';
      const lessons = byId('retailLessons');
      lessons.replaceChildren(...records.slice().sort((a, b) => dateOf(b).localeCompare(dateOf(a))).slice(0, 3).map(record => {
        const row = element('li', record.lesson + ' ');
        row.append(sourceLink(record.timeline[0], safeUrl));
        return row;
      }));
      byId('retailSeasonal').replaceChildren(...register.records.filter(record => record.seasonal)
        .map(record => sourceLink(record.timeline[0], safeUrl)));
      const month = ukDay.format(Date.now()).slice(5, 7);
      byId('retailSeason').classList.toggle('retail-season-active', ['10', '11', '12', '01'].includes(month));
      renderArchive(records);
    }

    function renderArchive(records) {
      const filters = Object.fromEntries(new FormData(controls));
      filters.view = activeView;
      const results = search(records, filters);
      byId('retailResultsCount').textContent = results.length + (results.length === 1 ? ' reviewed record' : ' reviewed records');
      byId('retailResults').replaceChildren(...(results.length ? results.map(record => renderRecord(record, safeUrl)) :
        [element('p', 'No reviewed records match these filters.', 'executive-meta')]));
    }
    controls.addEventListener('submit', event => event.preventDefault());
    controls.addEventListener('input', () => renderArchive(aggregate(register, Number(period.value)).records));
    period.addEventListener('change', render);
    topics.addEventListener('click', event => {
      const selected = event.target.closest('button[data-retail-view]');
      if (!selected) return;
      activeView = selected.dataset.retailView;
      topics.querySelectorAll('button').forEach(button => button.setAttribute('aria-pressed', String(button === selected)));
      renderArchive(aggregate(register, Number(period.value)).records);
    });
    render();
  }

  return {aggregate, search, load, open, renderWatch, executiveStories, todayFor, windowContains};
})();

if (typeof module !== 'undefined') module.exports = retailCentre;
