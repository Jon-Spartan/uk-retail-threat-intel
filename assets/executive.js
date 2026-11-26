'use strict';

const executiveDashboard = (() => {
  const day = 86400000;
  const categories = {
    ecom: 'Online retail', pos: 'Point of sale', loyalty: 'Customer accounts',
    supply: 'Supply chain', enterprise: 'Enterprise technology'
  };
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

  function newsFromRetailWatch() {
    return Array.from(document.querySelectorAll('#retail-watch [data-retail-development]'), card => {
      const source = card.querySelector('a[href]');
      return {
        kind: card.dataset.retailDevelopment, relevance: card.dataset.retailRelevance,
        title: card.querySelector('h4')?.textContent.trim(),
        date: card.querySelector('time[datetime]')?.dateTime,
        summary: card.querySelector('[data-retail-summary]')?.textContent.trim(),
        action: card.querySelector('[data-retail-action]')?.textContent.trim(),
        source: source?.textContent.trim(), url: source?.getAttribute('href')
      };
    });
  }

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

  function buildModel({items, metadata, previous, stories, now = Date.now(), evidenceFor, safeUrl}) {
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

    const records = (fresh ? items : []).flatMap(item => {
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
      return [{
        title: item.title, category: categories[item.subsector] || 'Other technology',
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

    const topThreats = records.filter(record => record.related);
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

    const today = Math.floor(now / day) * day;
    const reviewed = [...new Map(stories.flatMap(story => {
      const url = linked(story.url);
      const date = Date.parse(story.date);
      if (!url || !story.title || !story.summary || !story.source || !story.relevance ||
          !['incident', 'development'].includes(story.kind) || !/^\d{4}-\d{2}-\d{2}$/.test(story.date) ||
          !Number.isFinite(date) || new Date(date).toISOString().slice(0, 10) !== story.date) return [];
      return [[url, {...story, url, date}]];
    })).values()].sort((a, b) => b.date - a.date);
    const incidents = reviewed.filter(story => within(story.date, today, 30 * day));
    const incidentCount = incidents.filter(story => story.kind === 'incident').length;

    const actions = [];
    const usedActions = new Set();
    for (const item of [...recentPriority, ...incidents.filter(story => within(story.date, today, 7 * day))]) {
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
      observations.push(kev.length
        ? count(kev.length, 'CVE') + ' in this collection ' + (kev.length === 1 ? 'has' : 'have') + ' confirmed exploitation. ' +
          (relatedKev.length ? count(relatedKev.length, 'CVE') + (relatedKev.length === 1 ? ' has' : ' have') +
            ' documented retail relevance.' : 'Retail relevance is unestablished in the collected evidence.')
        : 'This snapshot has no confirmed-exploitation records with usable evidence.');
      if (partial) observations.push('Source coverage is incomplete. Counts reflect records verified in this collection.');
    } else {
      observations.push('Current vulnerability observations are unavailable.');
    }
    if (incidents.length) {
      const topics = [...new Set(incidents.map(story => story.relevance.toLowerCase()))];
      observations.push('Recent Retail Watch coverage includes ' + new Intl.ListFormat('en-GB').format(topics) + '.');
    }

    const availableRecords = fresh ? count(topThreats.length, 'verified record') + ' with retail relevance and ' +
      count(kev.length, 'confirmed-exploited CVE') + ' in the monitored collection.' : '';
    const summary = fresh
      ? (partial ? 'Vulnerability coverage is incomplete. ' : '') + availableRecords
      : (coverage === 'Stale' ? 'The vulnerability snapshot is stale. Current threat counts are withheld.'
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
      ['Last validated briefing', briefingText]
    ];
    const total = value => fresh ? String(value) : 'Unavailable';
    const metrics = [
      ['New priority threats', total(recentPriority.length), 'Retail-relevant, first seen in 7 days'],
      ['New KEVs relevant to retail', total(newRelatedKev.length), 'CISA additions in 7 days'],
      ['Active exploitation cases', total(kev.length), 'Unique confirmed-exploited CVEs in the collection'],
      ['Retail incidents tracked', reviewed.length ? String(incidentCount) : 'Unavailable', 'Reviewed public incidents in 30 days'],
      ['Actions to review this week', actions.length ? String(actions.length) : 'Unavailable', 'Reviews based on cited evidence'],
      ['Feed health', healthStatus, 'Vulnerability collection']
    ];
    return {summary, level, confidence, updated: time(collection.data_updated_at), metrics, actions, health, observations,
      topThreats: topThreats.slice(0, 3), kev: (relatedKev.length ? relatedKev : kev).slice(0, 3),
      incidents: incidents.slice(0, 3), changes: compareSnapshots(items, previous, collection, coverage),
      threatNote: !fresh ? 'Current threat ranking is unavailable.' : topThreats.length ? '' :
        'No items with documented retail relevance in this collection.',
      kevNote: !fresh ? 'Current KEV coverage is unavailable.' : relatedKev.length ? 'Confirmed exploitation with documented retail relevance.' :
        kev.length ? 'Wider catalogue watch. Retail relevance is unestablished for these entries.' : 'No verified KEVs in this snapshot.',
      incidentNote: incidents.length ? 'Selected public incidents and developments from the past 30 days.'
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
    const label = 'text-xs text-slate-600 dark:text-slate-300';
    const copy = 'text-sm leading-relaxed text-slate-700 dark:text-slate-200';
    const rowStyle = 'space-y-1.5 py-3 first:pt-1';
    const sourceLink = (text, url) => {
      const link = el('a', text, 'text-xs font-medium text-sky-700 underline underline-offset-4 dark:text-sky-300');
      link.href = url;
      if (url.startsWith('https://')) {
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
      }
      return link;
    };

    set('Summary', model.summary);
    set('Level', model.level);
    set('Confidence', model.confidence);
    set('Updated', model.updated);
    set('ThreatsNote', model.threatNote);
    set('KevNote', model.kevNote);
    set('IncidentsNote', model.incidentNote);
    set('ActionsNote', model.actions.length ? '' : 'No current, evidence-linked actions are available.');
    set('Changes', model.changes);
    renderList('Metrics', model.metrics, ([name, value, context]) => {
      const card = el('div', '', 'min-w-0 rounded-xl border border-slate-200 bg-white p-3 shadow-sm dark:border-slate-800 dark:bg-slate-900/80');
      card.append(el('dt', name, 'text-xs font-semibold'), el('dd', value,
        /^\d+$/.test(value) ? 'my-1 font-mono text-2xl font-bold' : 'my-1 text-sm font-bold'),
      el('dd', context, label));
      return card;
    });
    renderList('Threats', model.topThreats, item => {
      const row = el('li', '', rowStyle);
      const badge = el('span', 'Priority ' + item.score + '/100', item.score >= 50
        ? 'rounded-full bg-amber-100 px-2 py-1 text-xs font-semibold text-amber-950 dark:bg-amber-950 dark:text-amber-200'
        : 'rounded-full bg-sky-100 px-2 py-1 text-xs font-semibold text-sky-950 dark:bg-sky-950 dark:text-sky-200');
      row.append(el('h4', item.title, 'font-semibold'), badge,
        el('p', [item.category, relevanceLabels[item.relevance], confidenceLabels[item.confidence]].filter(Boolean).join(' · '), label),
        el('p', item.action, copy), sourceLink('Source: ' + item.source, item.url));
      return row;
    });
    renderList('Kev', model.kev, item => {
      const row = el('li', '', rowStyle);
      row.append(el('h4', item.cve + ' · ' + (item.product || 'Product details unavailable'), 'font-semibold'),
        el('p', 'Confirmed exploitation · ' + (relevanceLabels[item.relevance] || relevanceLabels.unestablished), label),
        el('p', item.action, copy), sourceLink('Source: ' + item.source, item.url));
      return row;
    });
    renderList('Incidents', model.incidents, item => {
      const row = el('li', '', rowStyle);
      row.append(el('p', dayFormat.format(item.date) + ' · ' + item.relevance, label),
        el('h4', item.title, 'font-semibold'), el('p', item.summary, copy), sourceLink(item.source, item.url));
      return row;
    });
    renderList('Actions', model.actions, item => {
      const row = el('li', '', 'space-y-0.5');
      row.append(el('p', item.text, copy), sourceLink(item.source, item.url));
      return row;
    });
    renderList('Observations', model.observations, text => el('li', text));
    renderList('Health', model.health, ([name, value]) => {
      const row = el('li', '', 'flex flex-col gap-0.5');
      row.append(el('strong', name, 'font-semibold text-slate-900 dark:text-slate-100'), el('span', value));
      return row;
    });
  }

  return {buildModel, newsFromRetailWatch, render};
})();

if (typeof module !== 'undefined') module.exports = executiveDashboard;
