// State management
let activeThreats = [];
let currentFilteredThreats = [];
let currentSubsector = 'all';
let filterKevOnly = false;
let activeTechnique = null;
let filterPciIcoOnly = false;
let filterPeakModeOnly = false;
let filterMyStackOnly = false;
let hasCollection = false;
let syncInProgress = false;
let activeFlashKey = null;
let dismissedFlashKeys = [];
try {
  const saved = JSON.parse(sessionStorage.getItem('dismissedFlashKeys'));
  if (Array.isArray(saved)) dismissedFlashKeys = saved.filter(key => typeof key === 'string');
} catch {}
let pollIntervalTimer = null;

const techStackStorageKey = 'cti_my_tech_stack';
let userTechStack = [];
try {
  const stored = JSON.parse(localStorage.getItem(techStackStorageKey));
  if (Array.isArray(stored)) {
    userTechStack = stored.filter(keyword => typeof keyword === 'string' && keyword.trim());
  }
} catch (e) {}

const visitStorageKey = 'cti_last_collection_visit';
let lastCollectionVisit = null;
try {
  const saved = Number(localStorage.getItem(visitStorageKey));
  if (saved > 0 && saved <= Date.now()) lastCollectionVisit = saved;
} catch {}
let triageCoverage = null;

function textElement(tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function safeHttpUrl(value) {
  if (typeof value !== 'string' || !/^https?:\/\/[^/]/i.test(value) || /[\s\u0000-\u001f\u007f\\<>"|]/u.test(value)) {
    return null;
  }
  try {
    const url = new URL(value);
    const authority = value.split('/')[2].split(/[?#]/)[0];
    return url.hostname && !authority.includes('@') && url.port !== '0' ? url.href : null;
  } catch {
    return null;
  }
}

// =========================================================================
// 2. HELPER CLASSIFIERS (KEV, PCI-DSS, UK ICO, PEAK TRADING)
// =========================================================================
const priorityFactors = [
  ['technical', 'Technical severity', 20], ['exploitation', 'Confirmed exploitation', 20],
  ['kev', 'CISA KEV membership', 10], ['epss', 'FIRST EPSS', 15], ['retail', 'Retail relevance', 20],
  ['source', 'Source credibility', 5], ['confidence', 'Evidence confidence', 5],
  ['freshness', 'Source-date freshness', 5]
];
const relevanceLabels = {uk_direct: 'Direct UK retail', sector: 'Sector-related', unestablished: 'Relevance unestablished'};
const confidenceLabels = {catalogue: 'Catalogue evidence', reference: 'CVE reference verified', unassessed: 'Unassessed'};
const sourceLabels = {authority: 'Official source', reporting: 'Specialist reporting', unassessed: 'Source unassessed'};

function priorityEvidence(item) {
  const evidence = item?.classification;
  if (evidence?.version !== 1 || !Number.isInteger(evidence.score) || evidence.score < 0 || evidence.score > 100 ||
      !Array.isArray(evidence.vulnerabilities) || !evidence.components) return null;
  return evidence;
}

function isKevItem(item) {
  return priorityEvidence(item)?.vulnerabilities.some(cve => cve?.kev === true) || false;
}

function citedTechniques(item) {
  return Array.isArray(item.attack_refs)
    ? item.attack_refs.filter(id => typeof id === 'string' && /^T[0-9]{4}(?:\.[0-9]{3})?$/.test(id)) : [];
}

function appendPriorityEvidence(field, item, evidence) {
  if (!evidence) {
    field('priority-details').remove();
    return;
  }
  const details = field('priority-points');
  details.append(textElement('li', (relevanceLabels[evidence.relevance] || 'Relevance unestablished') +
    ' · ' + (sourceLabels[evidence.source_tier] || 'Source unassessed')));
  if (evidence.exploitation !== 'confirmed') {
    details.append(textElement('li', evidence.kev_catalog_available
      ? 'Exploitation unconfirmed by the collected evidence' : 'CISA catalogue coverage unavailable'));
  }
  for (const [key, label, limit] of priorityFactors) {
    details.append(textElement('li', label + ' ' + (evidence.components[key] ?? 0) + '/' + limit));
  }
  if (evidence.vulnerabilities.length && !evidence.vulnerabilities.some(cve => cve?.epss)) {
    details.append(textElement('li', 'EPSS unavailable'));
  }
  for (const cve of evidence.vulnerabilities) {
    if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(cve?.id)) continue;
    const line = document.createElement('li');
    const link = textElement('a', cve.id, 'text-sky-600 dark:text-sky-400 hover:underline');
    link.href = cve.evidence === 'kev_catalogue'
      ? 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + cve.id
      : 'https://www.cve.org/CVERecord?id=' + cve.id;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    const signals = [];
    if (cve.cvss) signals.push('CVSS ' + cve.cvss.version + ' ' + cve.cvss.score);
    if (cve.epss) signals.push('EPSS ' + (100 * cve.epss.probability).toFixed(1) + '% on ' + cve.epss.date);
    if (cve.kev === true) signals.push('CISA KEV listed');
    line.append(link, document.createTextNode(signals.length ? ' · ' + signals.join(' · ') : ''));
    details.append(line);
  }
  const verified = new Set(item.cves || []);
  const unverified = (item.reported_cves || []).filter(cve => !verified.has(cve));
  if (unverified.length) details.append(textElement('li', 'Unverified CVE mentions ' + unverified.join(', ')));
}

function isPciOrIcoItem(item) {
  if (!item) return false;
  const combined = `${item.title || ''} ${item.summary || ''} ${(item.tags || []).join(' ')}`.toLowerCase();
  return (
    combined.includes("magecart") ||
    combined.includes("skimm") ||
    combined.includes("formjacking") ||
    combined.includes("pci") ||
    combined.includes("cvv") ||
    combined.includes("checkout injection") ||
    combined.includes("ico") ||
    combined.includes("information commissioner") ||
    combined.includes("gdpr") ||
    combined.includes("credential stuffing") ||
    combined.includes("account takeover") ||
    combined.includes("ato") ||
    item.subsector === 'loyalty'
  );
}

function isPeakTradingItem(item) {
  if (!item) return false;
  if (item.is_peak_trading) return true;
  const combined = `${item.title || ''} ${item.summary || ''} ${(item.tags || []).join(' ')}`.toLowerCase();
  return (
    combined.includes("bot") ||
    combined.includes("scalper") ||
    combined.includes("courier") ||
    combined.includes("evri") ||
    combined.includes("dpd") ||
    combined.includes("royal mail") ||
    combined.includes("smishing") ||
    combined.includes("ddos") ||
    combined.includes("gift card") ||
    combined.includes("voucher")
  );
}

function matchWords(value) {
  return (String(value ?? '').normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) || []).join(' ');
}

function getTechStackMatches(item) {
  if (!item || !userTechStack.length) return [];
  const products = Array.isArray(item.affected_products) ? item.affected_products : [];
  const context = ' ' + matchWords([item.title, item.summary, ...(item.tags || []), ...(item.cves || [])].join(' ')) + ' ';
  return userTechStack.flatMap(entry => {
    const terms = entry.split('|').map(value => ({keyword: value.trim(), words: matchWords(value)}))
      .filter(term => term.words);
    for (const term of terms) {
      const phrase = ' ' + term.words + ' ';
      const product = products.find(product => product && ['cisa_kev', 'cve_list'].includes(product.source)
        && typeof product.vendor === 'string' && typeof product.product === 'string'
        && (' ' + matchWords(product.vendor + ' ' + product.product) + ' ').includes(phrase));
      if (product) return [{keyword: term.keyword, product}];
    }
    // Keep older topic and CVE preferences useful with an explicitly weaker label.
    const topic = terms.find(term => context.includes(' ' + term.words + ' '));
    return topic ? [{keyword: topic.keyword}] : [];
  });
}

function newSinceVisit(item) {
  if (!triageCoverage || !lastCollectionVisit || item.carried_forward) return false;
  const observed = Date.parse(item.first_seen_at);
  return Number.isFinite(observed) && observed > lastCollectionVisit && observed <= Date.now();
}

function describeProductMatch(match) {
  const product = match.product;
  const source = product.source === 'cisa_kev' ? 'CISA KEV' : 'the CVE record';
  const name = matchWords(product.product).startsWith(matchWords(product.vendor) + ' ')
    ? product.product : product.vendor + ' ' + product.product;
  return source + ' lists ' + name + '. Check your version against the vendor advisory.';
}

function renderTriage() {
  const list = document.getElementById('triageItems');
  const note = document.getElementById('triageStatus');
  if (!list || !note) return;
  list.replaceChildren();
  if (!triageCoverage) {
    note.textContent = 'The shortlist is unavailable until a recent collection can be verified.';
    return;
  }
  const count = activeThreats.filter(newSinceVisit).length;
  const freshness = lastCollectionVisit ? count + ' new since your last visit in this browser.'
    : 'New items will be marked after this browser saves a previous visit.';
  const ranked = activeThreats.flatMap(item => {
    const url = safeHttpUrl(item.url);
    const evidence = priorityEvidence(item);
    if (!url || !evidence || item.carried_forward || !evidence.vulnerabilities.length) return [];
    return [{item, url, evidence, product: getTechStackMatches(item).find(match => match.product),
      recent: newSinceVisit(item)}];
  }).sort((left, right) =>
    Number(Boolean(right.product)) - Number(Boolean(left.product)) ||
    Number(right.recent) - Number(left.recent) ||
    right.evidence.score - left.evidence.score);
  const coverage = triageCoverage === 'partial' ? 'Coverage is incomplete. ' : '';
  note.textContent = coverage + (ranked.length ? freshness : 'No verified items to review in this collection. ' + freshness);

  for (const {item, url, evidence, product, recent} of ranked.slice(0, 3)) {
    const card = document.createElement('article');
    card.className = 'flex flex-col gap-2 rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900/80';
    const reasons = [];
    if (product) reasons.push('My Stack product match');
    if (recent) reasons.push('New since your last visit');
    if (evidence.exploitation === 'confirmed') reasons.push('Exploitation confirmed');
    if (!reasons.length) reasons.push('Verified CVE evidence');
    const link = textElement('a', 'Verify with ' + item.source, 'mt-auto text-sm font-medium text-sky-700 underline underline-offset-4 dark:text-sky-300');
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    const action = product ? describeProductMatch(product)
      : 'Check whether you use the affected product, then verify versions and fixes in the vendor advisory.';
    card.append(
      textElement('p', reasons.join(' · '), 'text-xs font-medium text-sky-700 dark:text-sky-300'),
      textElement('h4', item.title, 'font-semibold leading-tight'),
      textElement('p', action, 'text-sm text-slate-600 dark:text-slate-300'),
      link
    );
    list.append(card);
  }
}

// =========================================================================
// 3. CARD RENDERING ENGINE (BALANCED 2-COLUMN, ISOLATED DOM ELEMENTS)
// =========================================================================
function renderFeedItems(items) {
  const container = document.getElementById('threatFeedContainer');
  const emptyState = document.getElementById('emptyFeedState');
  if (!container) return;
  const template = document.getElementById('threatCardTemplate');
  emptyState?.classList.toggle('hidden', items.length > 0);

  const cards = items.map(item => {
    const card = template.content.firstElementChild.cloneNode(true);
    const field = name => card.querySelector('[data-field="' + name + '"]');
    const badges = field('badges');
    const evidence = priorityEvidence(item);
    const severity = evidence ? item.severity : 'UNKNOWN';
    const matches = getTechStackMatches(item);
    const critical = severity === 'CRITICAL';
    const border = matches.length
      ? 'border-indigo-400/80 dark:border-indigo-600/80 ring-1 ring-indigo-400/30 dark:ring-indigo-500/20'
      : critical ? 'border-rose-300 dark:border-rose-900/60' : 'border-slate-200 dark:border-slate-800';
    card.classList.add(...border.split(' '));
    const badge = (label, colors) => badges.append(
      textElement('span', label, 'px-2 py-0.5 rounded text-[10px] font-semibold border ' + colors)
    );

    const product = matches.find(match => match.product);
    if (matches.length) {
      const labels = matches.filter(match => Boolean(match.product) === Boolean(product));
      badge((product ? 'PRODUCT MATCH (' : 'TOPIC MATCH (') + labels.slice(0, 2).map(match => match.keyword).join(', ') + ')',
        'bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border-indigo-300 dark:border-indigo-800');
    }
    badge(severity && severity !== 'UNKNOWN' ? 'CVSS ' + severity : 'CVSS unassessed', critical
      ? 'bg-rose-100 dark:bg-rose-950/80 text-rose-600 dark:text-rose-400 border-rose-200 dark:border-rose-900'
      : 'bg-amber-100 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400 border-amber-200 dark:border-amber-900');
    const stackNote = field('stack-match');
    if (product) stackNote.textContent = describeProductMatch(product);
    else if (matches.length) stackNote.textContent = 'Matched terms in the report. Check product applicability at the source.';
    else stackNote.remove();
    if (newSinceVisit(item)) badge('NEW SINCE YOUR VISIT', 'bg-sky-500 text-white border-transparent');
    else if (item.is_new) badge('NEW', 'bg-sky-500 text-white border-transparent');
    if (isKevItem(item)) {
      badge('CISA KEV · exploitation confirmed', 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-800');
    }
    if (isPciOrIcoItem(item)) {
      badge('PCI / ICO TOPIC', 'bg-teal-100 dark:bg-teal-950 text-teal-700 dark:text-teal-300 border-teal-300 dark:border-teal-800');
    }
    if (isPeakTradingItem(item)) {
      badge('🛍️ PEAK TRADE', 'bg-pink-100 dark:bg-pink-950 text-pink-700 dark:text-pink-300 border-pink-300 dark:border-pink-800');
    }

    const title = item.title;
    const url = safeHttpUrl(item.url);
    if (url) {
      const link = textElement('a', title, 'hover:text-sky-600 dark:hover:text-sky-400 hover:underline transition');
      link.href = url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      field('title').append(link);
      field('link').href = url;
    } else {
      field('title').textContent = title;
      field('link').remove();
    }
    field('date').textContent = (item.date || 'Date unknown') + (item.carried_forward === true ? ' · Retained from an earlier collection' : '');
    field('summary').textContent = item.summary || 'Summary unavailable.';
    field('source').textContent = item.source || 'Source unavailable';
    const techniques = citedTechniques(item);
    field('mitre').textContent = techniques.length ? 'Cited techniques ' + techniques.join(', ') : '';
    field('confidence').textContent = 'Confidence · ' + (confidenceLabels[evidence?.confidence] || 'Unassessed');
    field('priority').textContent = Number.isInteger(evidence?.score)
      ? 'UK retail priority ' + evidence.score + '/100' : 'UK retail priority unassessed';
    appendPriorityEvidence(field, item, evidence);
    if (item.advisory) {
      field('advisory').textContent = item.advisory;
    } else {
      field('advisory-box').remove();
    }
    const tags = (item.tags || []).slice(0, 3);
    if (tags.length) {
      field('tags').append(...tags.map(tag => textElement('span', tag,
        'px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700')));
    } else {
      field('tags').remove();
    }
    return card;
  });
  container.replaceChildren(...cards);
}

// =========================================================================
// 4. STATS & METRICS CALCULATOR
// =========================================================================
function updateMetricsCounters() {
  // 1. Critical Count
  const critCount = activeThreats.filter(t => priorityEvidence(t) && t.severity === 'CRITICAL').length;
  const statCrit = document.getElementById('statCriticalCount');
  if (statCrit) statCrit.textContent = activeThreats.some(t => priorityEvidence(t) && t.severity !== 'UNKNOWN') ? critCount : '—';

  // 2. CISA KEV Count
  const kevCount = activeThreats.filter(isKevItem).length;
  const statKev = document.getElementById('statKevCount');
  if (statKev) statKev.textContent = activeThreats.some(t => priorityEvidence(t)?.kev_catalog_available) ? kevCount : '—';

  // 3. PCI & ICO Impact Count
  const compCount = activeThreats.filter(isPciOrIcoItem).length;
  const statComp = document.getElementById('statComplianceCount');
  if (statComp) {
    statComp.textContent = hasCollection ? compCount : '—';
  }

  // 4. My Stack Count
  const myStackMatchesCount = activeThreats.filter(t => getTechStackMatches(t).length > 0).length;
  const matchBadge = document.getElementById('myStackMatchCount');
  if (matchBadge) matchBadge.textContent = myStackMatchesCount;
}

// =========================================================================
// 5. FILTERING & SEARCH CONTROLLER
// =========================================================================
function applyFilters() {
  renderTriage();
  const searchVal = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();
  const severityVal = document.getElementById('severitySelect')?.value || 'ALL';

  let results = activeThreats.filter(item => {
    // Subsector filter
    if (currentSubsector !== 'all' && item.subsector !== currentSubsector) {
      return false;
    }

    // My Stack Only filter
    if (filterMyStackOnly && getTechStackMatches(item).length === 0) {
      return false;
    }

    // CISA KEV filter
    if (filterKevOnly && !isKevItem(item)) {
      return false;
    }

    // PCI & ICO filter
    if (filterPciIcoOnly && !isPciOrIcoItem(item)) {
      return false;
    }

    // Peak Trading filter
    if (filterPeakModeOnly && !isPeakTradingItem(item)) {
      return false;
    }

    const severity = priorityEvidence(item) ? item.severity : 'UNKNOWN';
    if (severityVal === 'HIGH' && !['CRITICAL', 'HIGH'].includes(severity)) return false;
    if (!['ALL', 'HIGH'].includes(severityVal) && severityVal !== severity) return false;
    if (activeTechnique && !citedTechniques(item).includes(activeTechnique)) return false;

    // Keyword search
    if (searchVal && !activeTechnique) {
      const haystack = `${item.title || ''} ${item.summary || ''} ${item.source || ''} ${(item.tags || []).join(' ')} ${(item.reported_cves || []).join(' ')} ${citedTechniques(item).join(' ')}`.toLowerCase();
      if (!haystack.includes(searchVal)) {
        return false;
      }
    }

    return true;
  });

  currentFilteredThreats = results;
  renderFeedItems(results);
  updateFilterBanner();
}

function toggleMyStackFilter() {
  filterMyStackOnly = !filterMyStackOnly;
  const btn = document.getElementById('myStackFilterBtn');

  if (filterMyStackOnly) {
    btn?.classList.add('bg-indigo-600', 'text-white');
    btn?.classList.remove('text-slate-700', 'dark:text-slate-300');
  } else {
    btn?.classList.remove('bg-indigo-600', 'text-white');
    btn?.classList.add('text-slate-700', 'dark:text-slate-300');
  }
  applyFilters();
}

function openTechStackModal() {
  const modal = document.getElementById('techStackModal');
  renderTechStackTags();
  modal?.classList.remove('hidden');
  setTimeout(() => document.getElementById('techStackInput')?.focus(), 50);
}

function closeTechStackModal() {
  const modal = document.getElementById('techStackModal');
  modal?.classList.add('hidden');
  updateMetricsCounters();
  applyFilters();
}

function renderTechStackTags() {
  const container = document.getElementById('techStackTagsContainer');
  if (!container) return;
  if (!userTechStack.length) {
    container.replaceChildren(textElement('span', 'No technology keywords configured yet.', 'text-xs text-slate-400 italic'));
    return;
  }
  const tags = userTechStack.map((tag, index) => {
    const label = textElement('span', '',
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 shadow-sm');
    const remove = textElement('button', '✕', 'text-slate-400 hover:text-rose-500 font-bold ml-0.5 text-xs');
    remove.type = 'button';
    remove.setAttribute('aria-label', 'Remove ' + tag);
    remove.addEventListener('click', () => removeTechStackTag(index));
    label.append(textElement('span', tag), remove);
    return label;
  });
  container.replaceChildren(...tags);
}

function addTechStackTag() {
  const input = document.getElementById('techStackInput');
  if (!input) return;
  const raw = input.value.trim().toLowerCase();
  if (!raw) return;

  if (!userTechStack.includes(raw)) {
    userTechStack.push(raw);
    saveTechStack();
    renderTechStackTags();
    showToast(`Added "${raw}" to your private stack`);
  }
  input.value = '';
}

function quickAddTech(keyword) {
  const kw = keyword.toLowerCase().trim();
  if (!userTechStack.includes(kw)) {
    userTechStack.push(kw);
    saveTechStack();
    renderTechStackTags();
    showToast(`Added "${keyword}"`);
  }
}

function removeTechStackTag(index) {
  if (index >= 0 && index < userTechStack.length) {
    const removed = userTechStack.splice(index, 1);
    saveTechStack();
    renderTechStackTags();
    showToast(`Removed "${removed[0]}"`);
  }
}

function clearTechStack() {
  userTechStack = [];
  let message = "Cleared My Stack keywords";
  try {
    localStorage.removeItem(techStackStorageKey);
  } catch (e) {
    message = "Cleared this view. Use browser settings to clear saved keywords.";
  }
  renderTechStackTags();
  updateMetricsCounters();
  applyFilters();
  showToast(message);
}

function saveTechStack() {
  try {
    localStorage.setItem(techStackStorageKey, JSON.stringify(userTechStack));
  } catch (e) {}
}

function setSubsector(subsectorKey) {
  currentSubsector = subsectorKey;
  document.querySelectorAll('.subsector-btn').forEach(btn => {
    if (btn.getAttribute('data-subsector') === subsectorKey) {
      btn.className = "subsector-btn px-2.5 py-1 rounded-md bg-sky-600 text-white font-medium transition cursor-pointer";
    } else {
      btn.className = "subsector-btn px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 font-medium transition cursor-pointer";
    }
  });
  applyFilters();
}

function toggleKevFilter() {
  filterKevOnly = !filterKevOnly;
  const kevBtn = document.getElementById('kevFilterBtn');
  const kevCard = document.getElementById('statKevCard');
  const kevIndicator = document.getElementById('kevCardIndicator');

  if (filterKevOnly) {
    kevBtn?.classList.add('bg-amber-500', 'text-white', 'border-amber-600');
    kevBtn?.classList.remove('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
    kevCard?.classList.add('ring-2', 'ring-amber-500', 'border-amber-500');
    if (kevIndicator) kevIndicator.textContent = 'Active ✓';
  } else {
    kevBtn?.classList.remove('bg-amber-500', 'text-white', 'border-amber-600');
    kevBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
    kevCard?.classList.remove('ring-2', 'ring-amber-500', 'border-amber-500');
    if (kevIndicator) kevIndicator.textContent = 'Filter ↗';
  }
  applyFilters();
}

function togglePciIcoFilter() {
  filterPciIcoOnly = !filterPciIcoOnly;
  const pciBtn = document.getElementById('pciFilterBtn');
  const compCard = document.getElementById('statComplianceCard');
  const compIndicator = document.getElementById('complianceCardIndicator');

  if (filterPciIcoOnly) {
    pciBtn?.classList.add('bg-emerald-600', 'text-white', 'border-emerald-700');
    pciBtn?.classList.remove('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
    compCard?.classList.add('ring-2', 'ring-emerald-500', 'border-emerald-500');
    if (compIndicator) compIndicator.textContent = 'Active ✓';
  } else {
    pciBtn?.classList.remove('bg-emerald-600', 'text-white', 'border-emerald-700');
    pciBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
    compCard?.classList.remove('ring-2', 'ring-emerald-500', 'border-emerald-500');
    if (compIndicator) compIndicator.textContent = 'Filter ↗';
  }
  applyFilters();
}

function togglePeakTradingFilter() {
  filterPeakModeOnly = !filterPeakModeOnly;
  const peakBtn = document.getElementById('peakModeBtn');

  if (filterPeakModeOnly) {
    peakBtn?.classList.add('bg-pink-600', 'text-white', 'border-pink-700');
    peakBtn?.classList.remove('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
  } else {
    peakBtn?.classList.remove('bg-pink-600', 'text-white', 'border-pink-700');
    peakBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
  }
  applyFilters();
}

function clearAllFilters() {
  activeTechnique = null;
  currentSubsector = 'all';
  filterKevOnly = false;
  filterPciIcoOnly = false;
  filterPeakModeOnly = false;
  filterMyStackOnly = false;

  const searchInput = document.getElementById('searchInput');
  if (searchInput) searchInput.value = '';

  const sevSelect = document.getElementById('severitySelect');
  if (sevSelect) sevSelect.value = 'ALL';

  setSubsector('all');

  // Reset My Stack styles
  const stackBtn = document.getElementById('myStackFilterBtn');
  stackBtn?.classList.remove('bg-indigo-600', 'text-white');
  stackBtn?.classList.add('text-slate-700', 'dark:text-slate-300');

  // Reset KEV styles
  const kevBtn = document.getElementById('kevFilterBtn');
  const kevCard = document.getElementById('statKevCard');
  const kevIndicator = document.getElementById('kevCardIndicator');
  kevBtn?.classList.remove('bg-amber-500', 'text-white', 'border-amber-600');
  kevBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
  kevCard?.classList.remove('ring-2', 'ring-amber-500', 'border-amber-500');
  if (kevIndicator) kevIndicator.textContent = 'Filter ↗';

  // Reset PCI styles
  const pciBtn = document.getElementById('pciFilterBtn');
  const compCard = document.getElementById('statComplianceCard');
  const compIndicator = document.getElementById('complianceCardIndicator');
  pciBtn?.classList.remove('bg-emerald-600', 'text-white', 'border-emerald-700');
  pciBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');
  compCard?.classList.remove('ring-2', 'ring-emerald-500', 'border-emerald-500');
  if (compIndicator) compIndicator.textContent = 'Filter ↗';

  // Reset Peak styles
  const peakBtn = document.getElementById('peakModeBtn');
  peakBtn?.classList.remove('bg-pink-600', 'text-white', 'border-pink-700');
  peakBtn?.classList.add('bg-slate-100', 'dark:bg-slate-800', 'text-slate-600', 'dark:text-slate-300');

  applyFilters();
}

function updateFilterBanner() {
  const banner = document.getElementById('filterBanner');
  const bannerText = document.getElementById('filterBannerText');
  if (!banner || !bannerText) return;

  const activeTags = [];
  if (filterMyStackOnly) activeTags.push(`🎯 My Stack Only (${userTechStack.length} keywords)`);
  if (currentSubsector !== 'all') activeTags.push(`Sector: ${currentSubsector.toUpperCase()}`);
  if (filterKevOnly) activeTags.push('⚡ CISA KEV only');
  if (filterPciIcoOnly) activeTags.push('⚖️ PCI & ICO Threats');
  if (filterPeakModeOnly) activeTags.push('🛍️ Peak Trading Vectors');
  const searchVal = document.getElementById('searchInput')?.value.trim();
  if (searchVal) activeTags.push(`Search: "${searchVal}"`);

  if (activeTags.length > 0) {
    bannerText.textContent = `Showing ${currentFilteredThreats.length} filtered alerts (${activeTags.join(' • ')})`;
    banner.classList.remove('hidden');
    banner.classList.add('flex');
  } else {
    banner.classList.add('hidden');
    banner.classList.remove('flex');
  }
}

// =========================================================================
// 6. MITRE ATT&CK MATRIX RENDERER
// =========================================================================
function renderMitreMatrix() {
  const grid = document.getElementById('mitreMatrixGrid');
  if (!grid) return;
  const tactics = {
    'Initial Access': [['T1190', 'Exploit Public-Facing Application'], ['T1195', 'Supply Chain Compromise'],
      ['T1566', 'Phishing']],
    'Credential Access': [['T1110', 'Brute Force'], ['T1078', 'Valid Accounts']],
    'Collection': [['T1056.004', 'Credential API Hooking'], ['T1005', 'Data from Local System']],
    'Impact': [['T1486', 'Data Encrypted for Impact'], ['T1499', 'Endpoint Denial of Service']]
  };
  const counts = new Map();
  for (const article of activeThreats) {
    for (const id of new Set(citedTechniques(article))) counts.set(id, (counts.get(id) || 0) + 1);
  }
  const displayed = new Set(Object.values(tactics).flat().map(([id]) => id));
  const other = [...counts.keys()].filter(id => !displayed.has(id)).sort();
  if (other.length) tactics['Other cited techniques'] = other.map(id => [id, 'Source reference']);
  const columns = Object.entries(tactics).map(([name, techniques]) => {
    const column = textElement('div', '',
      'border border-slate-200 dark:border-slate-800 rounded-xl p-3 bg-slate-50/50 dark:bg-slate-950/40 space-y-2');
    column.append(textElement('h4', name,
      'font-bold text-slate-800 dark:text-slate-200 text-xs border-b border-slate-200 dark:border-slate-800 pb-1.5'));
    for (const [id, label] of techniques) {
      const button = textElement('button', '',
        'w-full text-left p-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-sky-400 dark:hover:border-sky-500 transition group flex items-center justify-between');
      button.dataset.action = 'filterByMitreTechnique';
      button.dataset.value = id;
      const technique = document.createElement('div');
      technique.append(textElement('span', id, 'font-mono text-[10px] text-sky-600 dark:text-sky-400 block'),
        textElement('span', label, 'text-[11px] font-medium text-slate-700 dark:text-slate-300'));
      button.append(technique,
        textElement('span', String(counts.get(id) || 0), 'px-1.5 py-0.5 rounded text-[10px] font-mono font-bold'));
      column.append(button);
    }
    return column;
  });
  grid.replaceChildren(...columns);
}

function filterByMitreTechnique(techId) {
  activeTechnique = techId;
  window.location.hash = 'live-intelligence';
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.value = techId;
    applyFilters();
  }
}

// =========================================================================
// 7. FLASH ALERT LOADER
// =========================================================================
async function fetchJson(name, options) {
  const response = await fetch('data/' + name + '?t=' + Date.now(), options);
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('Data request failed.');
  return response.json();
}

function dateAge(value) {
  const elapsed = Date.now() - Date.parse(value);
  return Number.isFinite(elapsed) && elapsed >= -5 * 60 * 1000 ? elapsed : Infinity;
}

const officialPublishers = new Map([
  ['ncsc', {label: 'UK NCSC', host: 'www.ncsc.gov.uk'}],
  ['cisa', {label: 'US CISA', host: 'www.cisa.gov'}]
]);
const pressPublishers = new Map([
  ['bleeping', {label: 'Bleeping Computer', host: 'www.bleepingcomputer.com'}],
  ['neowin', {label: 'Neowin', host: 'www.neowin.net'}],
  ['securityweek', {label: 'SecurityWeek', host: 'www.securityweek.com'}],
  ['sans', {label: 'SANS Internet Storm Center', host: 'isc.sans.edu'}]
]);
const officialDate = new Intl.DateTimeFormat('en-GB', {dateStyle: 'medium', timeZone: 'Europe/London'});
const officialCheckTime = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/London'
});
let officialSnapshot = null;
let pressSnapshot = null;
const renderedStories = new WeakMap();

function renderStoryRows(list, stories, publishers) {
  const identity = JSON.stringify(stories);
  if (identity === renderedStories.get(list)) return;
  renderedStories.set(list, identity);
  const rows = [];
  for (const story of stories.slice(0, 16)) {
    const publisher = publishers.get(story?.source);
    const url = safeHttpUrl(story?.url);
    const publishedAt = story?.published_at ?? story?.date;
    const published = Date.parse(publishedAt);
    if (!publisher || !url || !Number.isFinite(published) ||
        typeof story.title !== 'string' || !story.title.trim() || story.title.length > 240) continue;
    if (new URL(url).origin !== 'https://' + publisher.host) continue;

    const row = textElement('li', '', 'border-t border-slate-200 py-2 dark:border-slate-800');
    const link = textElement('a', story.title, 'text-sm font-semibold text-sky-700 hover:underline dark:text-sky-300');
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    const byline = textElement('div', publisher.label + ' · ', 'text-xs text-slate-600 dark:text-slate-400');
    const time = textElement('time', officialDate.format(published));
    time.dateTime = publishedAt;
    byline.append(time);
    const evidence = safeHttpUrl(story.evidence_url);
    if (evidence && new URL(evidence).protocol === 'https:') {
      const reference = textElement('a', 'Primary source', 'underline underline-offset-4');
      reference.href = evidence;
      reference.target = '_blank';
      reference.rel = 'noopener noreferrer';
      byline.append(story.heading_kind === 'ai-assisted' ? ' · AI-assisted heading · ' : ' · Original heading · ', reference);
    }
    row.append(link, byline);
    rows.push(row);
  }
  const focusedLink = list.contains(document.activeElement) ? document.activeElement.href : null;
  list.replaceChildren(...rows);
  if (focusedLink) {
    [...list.querySelectorAll('a')].find(link => link.href === focusedLink)?.focus({preventScroll: true});
  }
}

async function loadOfficialUpdates() {
  let reachable = false;
  try {
    const snapshot = await fetchJson('official_updates.json', {signal: AbortSignal.timeout(10000)});
    if (Array.isArray(snapshot?.stories) && Number.isFinite(Date.parse(snapshot.checked_at))) {
      officialSnapshot = snapshot;
      reachable = true;
    }
  } catch {
    // Keep the last rendered headlines if the network or publication fails.
  }
  const status = document.getElementById('officialUpdatesStatus');
  let message = 'Official headlines are currently unavailable.';
  if (officialSnapshot) {
    const {checked_at: checkedAt, stories, sources} = officialSnapshot;
    renderStoryRows(document.getElementById('officialUpdatesList'), stories, officialPublishers);
    const unavailable = [...officialPublishers].filter(([id]) => sources?.[id] !== 'current')
      .map(([, publisher]) => publisher.label);
    const details = [];
    if (!reachable || dateAge(checkedAt) > 60 * 60 * 1000) details.push('Headlines may be stale.');
    if (unavailable.length) {
      details.push('Source unavailable: ' + unavailable.join(', ') + '. Showing retained headlines where available.');
    }
    if (!document.getElementById('officialUpdatesList').childElementCount) details.push('No recent headlines in this snapshot.');
    details.push('Sources last checked ' + officialCheckTime.format(Date.parse(checkedAt)) + ' (UK time).');
    message = details.join(' ');
  }
  if (status.textContent !== message) status.textContent = message;
}

async function loadPressUpdates() {
  let reachable = false;
  try {
    const snapshot = await fetchJson('press_updates.json', {signal: AbortSignal.timeout(10000)});
    if (Array.isArray(snapshot?.stories) && Number.isFinite(Date.parse(snapshot.checked_at))) {
      pressSnapshot = snapshot;
      reachable = true;
    }
  } catch {
    // Keep the last validated headlines visible while the refresh is unavailable.
  }
  const status = document.getElementById('pressUpdatesStatus');
  let message = 'Cyber news and research are currently unavailable.';
  if (pressSnapshot) {
    const list = document.getElementById('pressUpdatesList');
    renderStoryRows(list, pressSnapshot.stories, pressPublishers);
    const details = [];
    if (!reachable || dateAge(pressSnapshot.checked_at) > 60 * 60 * 1000) details.push('Headlines may be stale.');
    if (pressSnapshot.research !== 'current') details.push('SANS feed unavailable. Earlier research may still be shown.');
    if (!list.childElementCount) details.push('No recent items in this snapshot.');
    details.push('Research last checked ' + officialCheckTime.format(Date.parse(pressSnapshot.checked_at)) + ' (UK time).');
    message = details.join(' ');
  }
  if (status.textContent !== message) status.textContent = message;
}

function setCollectionStatus(label, message, timestamp) {
  const status = document.getElementById('syncStatusText');
  const notice = document.getElementById('collectionNotice');
  const time = document.getElementById('syncTimeAgo');
  if (status) status.textContent = label;
  if (notice) notice.textContent = message;
  if (time) time.textContent = Number.isFinite(dateAge(timestamp))
    ? '(' + new Date(timestamp).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) + ')' : '';
}

function renderCollectionHistory(metadata) {
  const collection = metadata?.collection;
  const time = value => Number.isFinite(dateAge(value))
    ? new Date(value).toLocaleString('en-GB', {timeZone: 'Europe/London', timeZoneName: 'short'})
    : 'unavailable';
  const show = (id, lines) => {
    const target = document.getElementById(id);
    if (!target) return;
    target.replaceChildren(...lines.map(line => {
      const entry = document.createElement('li');
      entry.textContent = line;
      return entry;
    }));
  };
  show('collectionHistory', [
    'Last complete collection · ' + time(collection?.last_success_at),
    'Last daily briefing validation · ' + time(metadata?.daily?.validated_at),
    'Last weekly briefing validation · ' + time(metadata?.weekly?.validated_at)
  ]);
  const feeds = Array.isArray(collection?.feeds) ? collection.feeds : [];
  show('feedHealth', feeds.length
    ? feeds.filter(feed => typeof feed?.name === 'string').map(feed =>
        feed.name + ' · ' + (feed.state === 'success' ? 'Checked' : 'Check failed') +
        ' ' + time(feed.checked_at) + ' · Last successful check ' + time(feed.last_success_at))
    : ['Source check history unavailable']);
}

function showFlashAlert(record) {
  const banner = document.getElementById('flashAlertBanner');
  const title = document.getElementById('flashAlertTitle');
  const advisory = document.getElementById('flashAlertAdvisory');
  const link = document.getElementById('flashAlertLink');
  const url = safeHttpUrl(record?.url);
  activeFlashKey = record && typeof record.title === 'string' && record.title.trim()
    ? url || (typeof record.id === 'string' && record.id) : null;
  banner?.classList.toggle('hidden', !activeFlashKey || dismissedFlashKeys.includes(activeFlashKey));
  if (title) title.textContent = activeFlashKey ? record.title : '';
  if (advisory) advisory.textContent = activeFlashKey && typeof record.advisory === 'string' ? record.advisory : '';
  if (link) {
    link.classList.toggle('hidden', !url);
    if (url) link.href = url;
    else link.removeAttribute('href');
  }
}

async function loadFlashAlert() {
  try {
    showFlashAlert(await fetchJson('flash_alert.json'));
  } catch {
    showFlashAlert(null);
  }
}

function dismissFlashAlert() {
  if (!activeFlashKey) return;
  dismissedFlashKeys = [...dismissedFlashKeys, activeFlashKey].slice(-30);
  document.getElementById('flashAlertBanner')?.classList.add('hidden');
  try {
    sessionStorage.setItem('dismissedFlashKeys', JSON.stringify(dismissedFlashKeys));
  } catch {}
}

function isThreatRecord(record) {
  if (!record || typeof record.title !== 'string' || !record.title.trim()) return false;
  for (const key of ['severity', 'subsector', 'source', 'summary', 'advisory', 'date']) {
    if (record[key] != null && typeof record[key] !== 'string') return false;
  }
  return ['tags', 'cves', 'reported_cves', 'attack_refs'].every(key => record[key] == null ||
    (Array.isArray(record[key]) && record[key].every(value => typeof value === 'string')));
}

let executiveInputs;
let executiveRequest;

async function refreshExecutiveView() {
  const panel = document.querySelector('[data-dashboard-view="executive"]');
  const inputs = executiveInputs;
  if (!inputs || !panel || panel.classList.contains('hidden') || executiveRequest === inputs) return;
  executiveRequest = inputs;
  const previous = inputs.items && inputs.metadata?.collection?.state === 'current'
    ? await fetchJson('executive_previous.json', {signal: AbortSignal.timeout(5000)}).catch(() => null) : null;
  if (executiveInputs !== inputs) return;
  const model = executiveDashboard.buildModel({
    ...inputs, previous, stories: executiveDashboard.newsFromRetailWatch(),
    evidenceFor: priorityEvidence, safeUrl: safeHttpUrl
  });
  executiveDashboard.render(model, relevanceLabels, confidenceLabels);
}

async function fetchThreatTelemetry(isManual = false) {
  if (syncInProgress) return;
  syncInProgress = true;
  const spinner = document.getElementById('syncSpinner');
  const pulseDot = document.getElementById('syncPulseDot');
  let fresh = false;
  if (isManual) {
    spinner?.classList.remove('hidden');
    setCollectionStatus('SYNCING', 'Checking for updated intelligence.');
  }
  pulseDot?.classList.add('hidden');

  try {
    const [items, metadata] = await Promise.all([
      fetchJson('threats.json'),
      fetchJson('intelligence_status.json').catch(() => null)
    ]);
    renderCollectionHistory(metadata);
    const briefingStatus = document.getElementById('briefingLastRun');
    const daily = metadata?.daily;
    if (briefingStatus) {
      if (Number.isFinite(dateAge(daily?.validated_at))) {
        const when = new Date(daily.validated_at).toLocaleString();
        const stale = daily.state !== 'available' || dateAge(daily.generated_at) > 36 * 60 * 60 * 1000;
        briefingStatus.textContent = (stale ? 'Stale · validated ' : 'Validated ') + when;
      } else {
        briefingStatus.textContent = daily?.state === 'failed' ? 'Briefing check failed' : 'Briefing unavailable';
      }
    }
    if (items !== null && (!Array.isArray(items) || !items.every(isThreatRecord))) {
      throw new Error('Invalid threat data.');
    }
    executiveInputs = {items, metadata};
    if (items !== null) {
      activeThreats = items;
      hasCollection = true;
    }
    const collection = metadata?.collection;
    const updatedAt = collection?.data_updated_at;
    const age = dateAge(updatedAt);
    triageCoverage = items !== null && age <= 90 * 60 * 1000 &&
      ['current', 'partial'].includes(collection?.state) ? collection.state : null;
    if (triageCoverage) {
      try { localStorage.setItem(visitStorageKey, String(Date.now())); } catch {}
    }
    if (collection?.state === 'failed') {
      setCollectionStatus('FAILED', hasCollection
        ? 'Collection failed. Showing the previous snapshot, which may be stale.'
        : 'Collection failed. Threat intelligence is unavailable.', updatedAt);
    } else if (items === null) {
      setCollectionStatus(hasCollection ? 'STALE' : 'UNAVAILABLE', hasCollection
        ? 'The dataset is unavailable. Showing the previously loaded snapshot.'
        : 'Threat intelligence is unavailable.');
    } else if (!Number.isFinite(age) || !['current', 'partial'].includes(collection?.state)) {
      setCollectionStatus('AGE UNKNOWN', 'Showing a snapshot with no verified collection time.');
    } else if (age > 90 * 60 * 1000) {
      setCollectionStatus('STALE', collection.state === 'partial'
        ? 'The last collection is more than 90 minutes old and coverage was incomplete.'
        : 'The last collection is more than 90 minutes old.', updatedAt);
    } else if (collection.state === 'partial') {
      setCollectionStatus('INCOMPLETE', 'Some sources could not be collected. Recent reports from earlier collections may be shown.', updatedAt);
    } else {
      fresh = true;
      pulseDot?.classList.remove('hidden');
      setCollectionStatus('CURRENT', 'Showing the latest collected public-source intelligence.', updatedAt);
    }
    if (items !== null && Number.isFinite(age) && age <= 90 * 60 * 1000 &&
        ['current', 'partial'].includes(collection?.state)) {
      await loadFlashAlert();
    } else {
      showFlashAlert(null);
    }
  } catch {
    triageCoverage = null;
    executiveInputs = {items: null, metadata: executiveInputs?.metadata};
    const briefingStatus = document.getElementById('briefingLastRun');
    if (briefingStatus) briefingStatus.textContent = 'Briefing status could not be loaded';
    setCollectionStatus('LOAD FAILED', hasCollection
      ? 'The dataset could not be loaded. Showing the previously loaded snapshot.'
      : 'The dataset could not be loaded.');
    showFlashAlert(null);
  } finally {
    refreshExecutiveView();
    updateMetricsCounters();
    applyFilters();
    renderMitreMatrix();
    spinner?.classList.add('hidden');
    syncInProgress = false;
  }
  if (isManual && fresh) showToast('Intelligence refreshed');
}

function manualSync() {
  fetchThreatTelemetry(true);
}

async function viewAiBriefing() {
  const modal = document.getElementById('aiBriefingModal');
  const content = document.getElementById('aiBriefingContent');
  if (!modal || !content) return;

  modal.classList.remove('hidden');
  content.textContent = 'Loading daily briefing.';
  try {
    const metadata = await fetchJson('intelligence_status.json');
    const daily = metadata?.daily;
    if (!daily?.generated_at || !daily?.validated_at) {
      content.textContent = daily?.state === 'failed'
        ? 'Daily briefing generation or validation failed.' : 'Daily briefing unavailable.';
      return;
    }
    const [evidence, response] = await Promise.all([
      fetchJson('daily_briefing.json'),
      fetch('data/daily_summary.md?t=' + Date.now())
    ]);
    if (!evidence || response.status === 404) {
      content.textContent = 'Daily briefing unavailable.';
      return;
    }
    if (!response.ok) throw new Error('Briefing request failed.');
    if (evidence.schema_version !== 1 || evidence.period !== 'daily' ||
        evidence.generated_at !== daily.generated_at || evidence.validated_at !== daily.validated_at ||
        !Array.isArray(evidence.sources) || !Array.isArray(evidence.selection?.facts)) {
      throw new Error('Briefing evidence does not match its status.');
    }
    const summary = (await response.text()).replace(/\r\n/g, '\n');
    const sourceHeading = summary.indexOf('\nSources\n');
    if (!summary.startsWith('AI-assisted selection of public-source evidence.') || sourceHeading < 0) {
      throw new Error('Briefing format is invalid.');
    }
    const sourceList = document.createElement('ul');
    const sources = new Map(evidence.sources.map(source => [source.id, source]));
    for (const id of evidence.selection.facts) {
      const source = sources.get(id);
      const url = safeHttpUrl(source?.url);
      if (!url || typeof source.publisher !== 'string') throw new Error('Briefing source is invalid.');
      const link = textElement('a', '[' + id + '] ' + source.publisher, 'text-sky-600 dark:text-sky-400 hover:underline');
      link.href = url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      const item = document.createElement('li');
      item.append(link);
      sourceList.append(item);
    }
    const evidenceLink = textElement('a', 'Briefing evidence and selection (JSON)', 'text-sky-600 dark:text-sky-400 hover:underline');
    evidenceLink.href = 'data/daily_briefing.json';
    const stale = daily.state !== 'available' || dateAge(daily.generated_at) > 36 * 60 * 60 * 1000;
    const failure = daily.state === 'failed' ? 'Latest briefing generation or validation failed. ' : '';
    const notice = stale ? failure + 'Showing an earlier validated briefing (stale).\n\n' : '';
    content.textContent = notice + summary.slice(0, sourceHeading);
    content.append(textElement('p', 'Sources', 'font-semibold'), sourceList, evidenceLink);
  } catch {
    content.textContent = 'Daily briefing could not be loaded.';
  }
}

function closeAiBriefing() {
  document.getElementById('aiBriefingModal')?.classList.add('hidden');
}

// =========================================================================
// 10. TAB NAVIGATION & CSV EXPORTER
// =========================================================================
function showDashboardView() {
  const target = document.getElementById(window.location.hash.slice(1));
  const view = target?.closest('[data-dashboard-view]')?.dataset.dashboardView || 'kev';
  document.querySelectorAll('[data-dashboard-view]').forEach(panel => {
    panel.classList.toggle('hidden', panel.dataset.dashboardView !== view);
  });
  document.querySelectorAll('[data-dashboard-link]').forEach(link => {
    if (link.dataset.dashboardLink === view) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  if (view === 'executive') refreshExecutiveView();
  // The target may have been hidden when the browser tried to scroll to it.
  if (target) requestAnimationFrame(() => target.scrollIntoView({block: 'start'}));
}

function csvCell(value) {
  const text = String(value ?? '');
  const safe = /^[\t\r\n]|^\s*[=+\-@＝＋－＠]/u.test(text) ? "'" + text : text;
  return '"' + safe.replace(/"/g, '""') + '"';
}

function exportFilteredToCSV() {
  if (!currentFilteredThreats.length) {
    showToast('No data to export');
    return;
  }
  const headers = ['Technical severity', 'Sector priority', 'Retail relevance', 'Evidence confidence', 'Exploitation',
    'Title', 'Subsector', 'Source', 'Date', 'Verified CVEs', 'CVEs mentioned', 'EPSS by CVE',
    'Cited techniques', 'Recommendation', 'Source URL'];
  const rows = currentFilteredThreats.map(item => {
    const evidence = priorityEvidence(item);
    const epss = evidence?.vulnerabilities.filter(cve => cve?.epss)
      .map(cve => cve.id + ' ' + cve.epss.probability + ' (' + cve.epss.date + ')').join(', ');
    return [
      evidence ? item.severity : 'UNKNOWN', evidence?.score, relevanceLabels[evidence?.relevance],
      confidenceLabels[evidence?.confidence] || 'Unassessed', evidence?.exploitation || 'unknown',
      item.title, item.subsector, item.source, item.date, (item.cves || []).join(', '),
      (item.reported_cves || []).join(', '), epss, citedTechniques(item).join(', '), item.advisory, safeHttpUrl(item.url)
    ];
  });
  const content = [headers, ...rows].map(row => row.map(csvCell).join(',')).join('\r\n');
  const url = URL.createObjectURL(new Blob([content], {type: 'text/csv;charset=utf-8'}));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'uk_retail_threat_intel_' + new Date().toISOString().slice(0, 10) + '.csv';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  showToast('CSV export downloaded');
}

function showToast(message) {
  const toast = document.getElementById('toastNotification');
  const msg = document.getElementById('toastMsg');
  if (!toast || !msg) return;
  msg.textContent = message;
  toast.classList.remove('translate-y-20', 'opacity-0');
  setTimeout(() => {
    toast.classList.add('translate-y-20', 'opacity-0');
  }, 2500);
}

function toggleTheme() {
  if (document.documentElement.classList.contains('dark')) {
    document.documentElement.classList.remove('dark');
    localStorage.theme = 'light';
  } else {
    document.documentElement.classList.add('dark');
    localStorage.theme = 'dark';
  }
}

// =========================================================================
// 11. INITIALIZATION ON PAGE LOAD
// =========================================================================
function bindDashboardControls() {
  const actions = {
    dismissFlashAlert,
    manualSync,
    exportFilteredToCSV,
    toggleTheme,
    toggleKevFilter,
    togglePciIcoFilter,
    viewAiBriefing,
    toggleMyStackFilter,
    openTechStackModal,
    togglePeakTradingFilter,
    setSubsector,
    clearAllFilters,
    closeAiBriefing,
    closeTechStackModal,
    addTechStackTag,
    quickAddTech,
    clearTechStack,
    filterByMitreTechnique,
  };
  document.addEventListener('click', event => {
    const control = event.target.closest('[data-action]');
    const action = control?.dataset.action;
    if (action && Object.hasOwn(actions, action)) actions[action](control.dataset.value);
  });
  document.getElementById('searchInput').addEventListener('input', () => {
    activeTechnique = null;
    applyFilters();
  });
  document.getElementById('severitySelect').addEventListener('change', applyFilters);
  document.getElementById('techStackInput').addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      addTechStackTag();
    }
  });
}

window.addEventListener('DOMContentLoaded', () => {
  bindDashboardControls();
  showDashboardView();
  window.addEventListener('hashchange', showDashboardView);
  // 1. Initial Load
  fetchThreatTelemetry();
  loadOfficialUpdates();
  loadPressUpdates();

  // 2. Automated background poller every 60 seconds
  if (pollIntervalTimer) clearInterval(pollIntervalTimer);
  pollIntervalTimer = setInterval(() => {
    fetchThreatTelemetry(false);
    loadOfficialUpdates();
    loadPressUpdates();
  }, 60000);
});
