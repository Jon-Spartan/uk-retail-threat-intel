'use strict';

const executiveDashboard = (() => {
  const day = 86400000;
  const categories = {
    ecom: 'Online retail', pos: 'Point of sale', loyalty: 'Customer accounts',
    supply: 'Supply chain', enterprise: 'Enterprise technology'
  };
  const severityLabels = {critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown'};
  const metricIcons = {priority: '▲', kev: '⚡', incidents: '◎', exploitation: '◈', actions: '✓', coverage: '▥'};
  const timeFormat = new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/London'
  });
  const dayFormat = new Intl.DateTimeFormat('en-GB', {dateStyle: 'medium', timeZone: 'UTC'});
  const time = value => Number.isFinite(Date.parse(value)) ? timeFormat.format(Date.parse(value)) + ' UK time' : 'Unavailable';
  const within = (date, reference, limit) => Number.isFinite(date) && date <= reference && reference - date <= limit;
  const count = (number, singular, plural = singular + 's') => number + ' ' + (number === 1 ? singular : plural);
  const cvePattern = /^CVE-[0-9]{4}-[0-9]{4,15}$/;
  const recordIdPattern = /^(?:cisa-kev-cve_[0-9]{4}_[0-9]{4,15}|src-[0-9a-f]{64})$/;
  const validId = id => typeof id === 'string' && recordIdPattern.test(id);

  function compareSnapshots(items, previous, collection, coverage) {
    if (coverage !== 'current') return 'Comparison unavailable until a complete, current collection can be verified.';
    if (previous?.current_at !== collection.data_updated_at ||
        !Number.isFinite(Date.parse(previous?.previous_at)) ||
        Date.parse(previous.previous_at) >= Date.parse(previous.current_at) ||
        !Array.isArray(previous.record_ids) || previous.record_ids.length > 1000 ||
        !previous.record_ids.every(validId) || !items.every(item => validId(item.id))) {
      return 'Change tracking not yet available.';
    }
    const before = new Set(previous.record_ids);
    const after = new Set(items.map(item => item.id));
    const added = [...after].filter(id => !before.has(id)).length;
    const removed = [...before].filter(id => !after.has(id)).length;
    const since = time(previous.previous_at);
    return added || removed
      ? count(added, 'record') + ' added and ' + count(removed, 'record') + ' left the collection window since ' + since + '.'
      : 'No records were added to or removed from the collection window since ' + since + '.';
  }

  function buildModel({items, metadata, previous, stories, retailReviewedOn, now = Date.now(), evidenceFor, safeUrl}) {
    const retail = typeof module !== 'undefined' ? require('./retail.js') : retailCentre;
    const collection = metadata?.collection || {};
    const updated = Date.parse(collection.data_updated_at);
    const age = now - updated;
    const complete = collection.state === 'current';
    const partial = collection.state === 'partial';
    const hasVerifiedTime = Number.isFinite(age) && age >= -5 * 60000;
    let coverage = 'Unavailable';
    if (collection.state === 'failed') coverage = 'Failed';
    else if (hasVerifiedTime && age > 90 * 60000) coverage = 'Stale';
    else if (Array.isArray(items) && hasVerifiedTime && (complete || partial)) coverage = collection.state;
    const fresh = coverage === 'current' || coverage === 'partial';
    const healthStatus = {current: 'Current', partial: 'Incomplete'}[coverage] || coverage;
    const linked = value => {
      const url = safeUrl(value);
      return url && new URL(url).protocol === 'https:' ? url : null;
    };

    const hasSnapshot = Array.isArray(items) && hasVerifiedTime && (complete || partial);
    const snapshotRecords = (hasSnapshot ? items : []).flatMap(item => {
      const evidence = evidenceFor(item);
      const url = linked(item.url);
      if (!evidence || !url || item.carried_forward) return [];
      const cves = evidence.vulnerabilities.filter(cve => cvePattern.test(cve?.id));
      if (!cves.length) return [];
      const relevance = evidence.relevance;
      const related = ['uk_direct', 'sector'].includes(relevance);
      const products = Array.isArray(item.affected_products) ? item.affected_products.filter(Boolean) : [];
      const product = products.find(value => value.source === 'cisa_kev') || products[0];
      const productName = product ? [...new Set([product.vendor, product.product])]
        .filter(value => typeof value === 'string' && value.trim()).join(' ') : '';
      const severity = typeof item.severity === 'string' ? item.severity.toLowerCase() : 'unknown';
      return [{
        title: item.title, category: categories[item.subsector] || 'Other technology',
        severity: Object.hasOwn(severityLabels, severity) ? severity : 'unknown',
        score: evidence.score, relevance, related, confidence: evidence.confidence, url, source: item.source || 'Public reference',
        firstSeen: Date.parse(item.first_seen_at),
        added: typeof item._timestamp === 'number' && item._timestamp > 0 ? item._timestamp * 1000 : NaN,
        product: productName,
        action: productName
          ? 'Check whether ' + productName + ' is in use. Verify affected versions and fixes with the vendor.'
          : 'Verify the affected product, versions and fixes with the vendor.',
        confirmed: evidence.exploitation === 'confirmed',
        kev: cves.filter(cve => cve.kev === true).map(cve => cve.id)
      }];
    }).sort((a, b) => Number(b.related) - Number(a.related) || b.score - a.score ||
      (b.added || 0) - (a.added || 0) || a.title.localeCompare(b.title));

    const records = fresh ? snapshotRecords : [];
    const windowStart = Math.floor(updated / day) * day - 13 * day;
    const windowRecords = snapshotRecords.filter(record => record.firstSeen >= windowStart && record.firstSeen <= updated);
    const charts = hasSnapshot ? {
      total: windowRecords.length,
      window: dayFormat.format(windowStart) + ' – ' + dayFormat.format(updated) + ' (UTC)',
      severity: Object.entries(severityLabels).map(([key, label]) =>
        ({key, label, value: windowRecords.filter(record => record.severity === key).length})),
      categories: [...Object.values(categories), 'Other technology']
        .map(label => ({label, value: windowRecords.filter(record => record.category === label).length}))
        .filter(category => category.value > 0)
        .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
    } : null;
    const topThreats = records.filter(record => record.related);
    const recentThreats = fresh ? windowRecords.slice(0, 3) : [];
    const recentPriority = topThreats.filter(record => record.score >= 50 && within(record.firstSeen, updated, 7 * day));
    const exploited = new Map();
    for (const record of records) {
      if (record.confirmed) {
        for (const cve of record.kev) {
          if (!exploited.has(cve)) exploited.set(cve, {...record, cve});
        }
      }
    }
    const kev = [...exploited.values()];
    const relatedKev = kev.filter(record => record.related);
    const newRelatedKev = relatedKev.filter(record => within(record.added, updated, 7 * day));
    const hasRecentPriority = topThreats.some(record => record.score >= 50);

    const today = retail.todayFor(now);
    const retailStale = retailReviewedOn != null && !retail.windowContains(Date.parse(retailReviewedOn), today, 15);
    const reviewed = [...new Map(stories.flatMap(story => {
      const url = linked(story.url);
      const date = Date.parse(story.date);
      if (!url || !story.title || !story.summary || !story.source || !story.relevance ||
          !['incident', 'development'].includes(story.kind) || !/^\d{4}-\d{2}-\d{2}$/.test(story.date) ||
          !Number.isFinite(date) || new Date(date).toISOString().slice(0, 10) !== story.date) return [];
      return [[story.id || url, {...story, url, date}]];
    })).values()].sort((a, b) => b.date - a.date);
    const incidents = reviewed.filter(story => retail.windowContains(story.date, today, 30));
    const incidentCount = incidents.filter(story => story.kind === 'incident').length;

    const actions = [];
    const usedActions = new Set();
    const timelyRetail = retailStale ? [] : incidents.filter(story => retail.windowContains(story.date, today, 7));
    for (const item of [...recentPriority, ...timelyRetail]) {
      if (!item.action || usedActions.has(item.action)) continue;
      usedActions.add(item.action);
      actions.push({text: item.action, url: item.url, source: item.source});
      if (actions.length === 5) break;
    }
    if (actions.length < 5 && kev.length && !recentPriority.length) {
      actions.push({
        text: 'Review whether any products in the latest CISA KEV snapshot are in use. Check vendor fixes where applicable.',
        url: '#live-intelligence', source: 'CISA KEV collection'
      });
    }

    const confidence = fresh
      ? (partial ? 'Limited · incomplete feed coverage'
        : kev.length ? 'Catalogue-backed · limited sector coverage' : 'Limited · no verified exploitation evidence in this snapshot')
      : 'Unavailable';
    const level = coverage === 'current' && hasRecentPriority ? 'Priority watch' : 'Not assessed';
    const observations = [];
    if (fresh) {
      const exploitationSummary = kev.length
        ? count(kev.length, 'CVE') + ' in this collection ' + (kev.length === 1 ? 'has' : 'have') + ' confirmed exploitation. ' +
          (relatedKev.length ? count(relatedKev.length, 'CVE') + (relatedKev.length === 1 ? ' has' : ' have') +
            ' documented retail relevance.' : 'Retail relevance is unestablished in the collected evidence.')
        : 'This snapshot has no confirmed-exploitation records with usable evidence.';
      observations.push({text: exploitationSummary, source: 'CISA KEV', url: '#kev'});
      if (partial) observations.push({text: 'Source coverage is incomplete. Counts reflect records verified in this collection.'});
    } else {
      observations.push({text: 'Current vulnerability observations are unavailable.'});
    }
    if (incidents.length && !retailStale) {
      const topics = [...new Set(incidents.map(story => story.relevance.toLowerCase()))];
      observations.push({text: 'Recent Retail Watch coverage includes ' + new Intl.ListFormat('en-GB').format(topics) + '.',
        source: 'Retail Watch', url: '#retail-watch'});
    }

    const availableRecords = fresh ? count(topThreats.length, 'verified record') + ' with retail relevance and ' +
      count(kev.length, 'confirmed-exploited CVE') + ' in the monitored collection.' : '';
    const summary = fresh
      ? (partial ? 'Vulnerability coverage is incomplete. ' : '') + availableRecords
      : (coverage === 'Stale' ? 'The vulnerability snapshot is stale. Current threat counts are withheld. ' +
          'Snapshot dated ' + time(collection.data_updated_at) + '.'
        : coverage === 'Failed' ? 'The latest collection failed. Current threat counts are unavailable.'
          : 'A current vulnerability collection could not be verified.');
    const feeds = Array.isArray(collection.feeds) ? collection.feeds.filter(feed => typeof feed?.name === 'string') : [];
    const briefings = [
      {name: 'Daily', report: metadata?.daily, limit: 36 * 3600000},
      {name: 'Weekly', report: metadata?.weekly, limit: 8 * day}
    ].filter(item => Number.isFinite(Date.parse(item.report?.validated_at)))
      .sort((a, b) => Date.parse(b.report.validated_at) - Date.parse(a.report.validated_at));
    const lastBriefing = briefings[0];
    const briefingText = lastBriefing
      ? lastBriefing.name + ' · ' + time(lastBriefing.report.validated_at) +
        (lastBriefing.report.state !== 'available' ||
          !within(Date.parse(lastBriefing.report.generated_at), now, lastBriefing.limit) ? ' · stale' : '')
      : 'Unavailable';
    const health = [
      ['Confidence', confidence],
      ['Vulnerability source coverage', feeds.length ? feeds.map(feed => feed.name).join(', ') : 'Unavailable'],
      ['Retail incident coverage', 'Reviewed Retail Watch entries from the last 30 days'],
      ...feeds.map(feed => [feed.name + ' last check',
        (feed.state === 'success' ? 'Succeeded' : feed.state === 'failed' ? 'Failed' : 'Unavailable') + ' · ' + time(feed.checked_at)]),
      ['Last successful collection', time(collection.last_success_at)],
      ['Last validated briefing', briefingText],
      ['AI validation', lastBriefing ? 'Last published briefing passed validation. See its freshness above.' : 'No validated briefing available'],
      ['Data freshness', healthStatus + ' · ' + time(collection.data_updated_at)],
      ['Collection limits', 'Vulnerability coverage is limited to monitored sources. Daily severity history is not published.']
    ];
    const total = value => fresh ? String(value) : 'Unavailable';
    const metrics = [
      ['New priority threats', total(recentPriority.length), 'Retail-relevant, first seen in 7 days', 'priority'],
      ['New KEVs relevant to retail', total(newRelatedKev.length), 'CISA additions in 7 days', 'kev'],
      ['Reported retail incidents', retailStale ? 'Stale' : (retailReviewedOn || reviewed.length) ? String(incidentCount) : 'Unavailable',
        'Reviewed public incidents in 30 days', 'incidents'],
      ['Confirmed active exploitation', total(kev.length), 'Unique CVEs in the collection', 'exploitation'],
      ['Recommended actions', actions.length ? String(actions.length) : 'Unavailable', 'Evidence-linked reviews for this week', 'actions'],
      ['Feed health', healthStatus, 'Vulnerability collection', 'coverage']
    ];
    return {summary, level, confidence, healthStatus, charts, metrics, actions, health, observations, recentThreats,
      success: time(collection.last_success_at),
      collectionStatus: {current: 'Complete', partial: 'Incomplete', failed: 'Failed'}[collection.state] || 'Unavailable',
      topThreats: topThreats.slice(0, 3), kev: (relatedKev.length ? relatedKev : kev).slice(0, 3),
      incidents: incidents.slice(0, 3), changes: compareSnapshots(items, previous, collection, coverage),
      threatNote: !fresh ? 'Current threat ranking is unavailable.' : recentThreats.length ?
        'First seen in 14 days, ranked by retail relevance and priority.' : 'No records first seen in this snapshot window.',
      kevNote: !fresh ? 'Current KEV coverage is unavailable.' : relatedKev.length ? 'Confirmed exploitation with documented retail relevance.' :
        kev.length ? 'Wider catalogue watch. Retail relevance is unestablished for these entries.' : 'No verified KEVs in this snapshot.',
      incidentNote: retailStale ? 'The editorial review is stale. Dated records are from the reviewed archive.' :
        incidents.length ? 'Selected public incidents and developments from the past 30 days.'
        : 'No recent reviewed entries are available from Retail Watch.'};
  }

  let lastRendered;
  function render(model, relevanceLabels, confidenceLabels) {
    const signature = JSON.stringify(model);
    if (signature === lastRendered) return;
    lastRendered = signature;
    const byId = id => document.getElementById('executive' + id);
    const set = (id, text) => { if (byId(id).textContent !== text) byId(id).textContent = text; };
    const renderList = (id, values, row) => {
      const list = byId(id);
      const focused = list.contains(document.activeElement) ? document.activeElement : null;
      list.replaceChildren(...values.map(row));
      if (focused?.href) {
        [...list.querySelectorAll('a')].find(link => link.href === focused.href &&
          link.textContent === focused.textContent)?.focus({preventScroll: true});
      }
    };
    const el = (tag, text, classes) => {
      const node = document.createElement(tag);
      node.textContent = text;
      if (classes) node.className = classes;
      return node;
    };
    const label = 'executive-meta';
    const sourceLink = (text, url) => {
      const link = el('a', text, 'executive-link');
      link.href = url;
      if (url.startsWith('https://')) {
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
      }
      return link;
    };
    const svg = (tag, attributes) => {
      const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
      return node;
    };

    set('Summary', model.summary);
    byId('Summary').dataset.state = model.healthStatus;
    set('Level', model.level);
    set('Confidence', model.confidence);
    set('Freshness', model.healthStatus);
    set('Collection', model.collectionStatus);
    set('Success', model.success);
    set('ThreatsNote', model.threatNote);
    set('KevNote', model.kevNote);
    set('IncidentsNote', model.incidentNote);
    set('ActionsNote', model.actions.length ? '' : 'No current, evidence-linked actions are available.');
    set('Changes', model.changes);
    renderList('Metrics', model.metrics, ([name, value, context, icon]) => {
      const card = el('div', '', 'executive-kpi');
      card.dataset.icon = icon;
      const title = el('dt', name);
      const symbol = el('span', metricIcons[icon], 'executive-kpi-icon');
      symbol.setAttribute('aria-hidden', 'true');
      title.prepend(symbol);
      card.append(title, el('dd', value, /^\d+$/.test(value) ? 'executive-value executive-number' : 'executive-value'),
        el('dd', context, label));
      return card;
    });
    renderList('Threats', model.recentThreats, item => {
      const row = el('li', '');
      const badge = el('span', severityLabels[item.severity], 'executive-badge');
      badge.dataset.severity = item.severity;
      const metadata = el('p', '', label);
      metadata.append(sourceLink(item.source, item.url), ' · ' + dayFormat.format(item.firstSeen) + ' (first seen)');
      row.append(badge, el('h4', item.title), metadata,
        el('p', ['Priority ' + item.score + '/100', item.category, relevanceLabels[item.relevance], confidenceLabels[item.confidence]]
          .filter(Boolean).join(' · '), label));
      return row;
    });
    renderList('Kev', model.kev, item => {
      const row = el('li', '');
      row.append(el('h4', item.cve + ' · ' + (item.product || 'Product details unavailable')),
        el('p', 'Confirmed exploitation · ' + (relevanceLabels[item.relevance] || relevanceLabels.unestablished), label),
        sourceLink(item.source, item.url));
      return row;
    });
    renderList('Incidents', model.incidents, item => {
      const row = el('li', '');
      row.append(el('h4', item.title), el('p', dayFormat.format(item.date) + ' · ' + item.relevance, label),
        sourceLink(item.source, item.url));
      return row;
    });
    renderList('Actions', model.actions, item => {
      const row = el('li', '');
      row.append(el('p', item.text), sourceLink(item.source, item.url));
      return row;
    });
    const observationRows = [...model.observations, ...model.actions.slice(0, 1)];
    renderList('Observations', observationRows, ({text, source, url}) => {
      const row = el('li', text);
      if (url) row.append(' ', sourceLink(source, url));
      return row;
    });
    renderList('Health', model.health, ([name, value]) => {
      const row = el('div', '');
      row.append(el('dt', name), el('dd', value));
      return row;
    });
    const charts = model.charts;
    const suffix = model.healthStatus === 'Current' ? '' : ' · ' + model.healthStatus + ' snapshot';
    set('ChartWindow', charts ? charts.window + suffix : '14-day snapshot window');
    const chartNote = !charts ? 'No validated snapshot available.' : 'No verified records first seen in this window' +
      (suffix ? ' (' + suffix.slice(3).toLowerCase() + ').' : '.');
    const severity = byId('Severity');
    const categoriesPanel = byId('Categories');
    if (!charts?.total) {
      severity.replaceChildren(el('p', chartNote, label));
      categoriesPanel.replaceChildren(el('p', chartNote, label));
      return;
    }
    const donut = svg('svg', {viewBox: '0 0 80 80', 'aria-hidden': 'true'});
    const circle = {'class': 'executive-ring', cx: 40, cy: 40, r: 33};
    donut.append(svg('circle', circle));
    const legend = el('ul', '', 'executive-legend');
    legend.setAttribute('aria-label', 'Record counts by technical severity');
    let offset = 0;
    for (const {key, label: severityLabel, value} of charts.severity) {
      const share = value * 100 / charts.total;
      if (value) {
        donut.append(svg('circle', {...circle, 'data-severity': key, pathLength: 100,
          'stroke-dasharray': share + ' ' + (100 - share), 'stroke-dashoffset': -offset,
          transform: 'rotate(-90 40 40)'}));
        offset += share;
      }
      const row = el('li', '');
      row.dataset.severity = key;
      row.append(el('span', '', 'executive-dot'), el('span', severityLabel), el('strong', String(value)));
      legend.append(row);
    }
    const donutTotal = svg('text', {x: 40, y: 45, 'font-size': 15});
    donutTotal.textContent = charts.total;
    donut.append(donutTotal);
    severity.replaceChildren(donut, legend);
    const bars = el('ul', '', 'executive-categories');
    for (const {label: category, value} of charts.categories) {
      const row = el('li', '', 'executive-category');
      const bar = el('progress', '');
      bar.max = charts.total;
      bar.value = value;
      bar.setAttribute('aria-hidden', 'true');
      row.append(el('span', category), el('strong', String(value)), bar);
      bars.append(row);
    }
    categoriesPanel.replaceChildren(...(suffix ? [el('p', suffix.slice(3), label), bars] : [bars]));
  }

  return {buildModel, render};
})();

if (typeof module !== 'undefined') module.exports = executiveDashboard;
