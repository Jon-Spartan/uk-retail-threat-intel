export type Collection = {
  state: string
  checked_at?: string | null
  data_updated_at: string | null
  last_success_at: string | null
  feeds?: { name: string; state: string }[]
}

export type Threat = {
  id: string
  title: string
  url: string
  severity: string
  date: string
  source: string
  first_seen_at?: string
  summary?: string
  subsector?: string
  advisory?: string
  tags?: string[]
  cves?: string[]
  reported_cves?: string[]
  attack_refs?: string[]
  carried_forward?: boolean
  affected_products?: {vendor: string; product: string; source: string}[]
  classification?: {
    version: number
    score: number
    relevance: string
    confidence: string
    exploitation: string
    vulnerabilities: { id: string; kev: boolean; cvss?: {score: number; version: string}; epss?: {probability: number; date: string} }[]
  }
}

export type Evidence = {date: string; kind: string; publisher: string; url: string; summary: string}

export type RetailRecord = {
  id: string; title: string; kind: string; organisation: string; geography: string | null; status: string
  confidence: string; relevance: string; functions: string[]; initial_access: string | null; impact: string | null
  exposure: string | null; lesson: string; timeline: Evidence[]; seasonal?: boolean
}

export type RetailRegister = {version: number; reviewed_on: string; records: RetailRecord[]}
export type Story = {id: string; source: string; title: string; url: string; date: string; evidence?: string;
  kind: 'Official' | 'Press' | 'Research' | 'Cyber watch'; summary?: string; lesson?: string}
export type Period = 'daily' | 'weekly'
export type BriefingStatus = {state: string; generated_at: string | null; validated_at: string | null}
export type HistoryDay = {collected_at: string; severity: Record<string, number>; kev: number}
export type Snapshot = {
  threats: Threat[] | null
  collection: Collection | null
  briefing: string
  briefings: Record<Period, BriefingStatus | null>
  flash: {id: string; title: string; url: string; advisory: string | null} | null
  stories: Story[]
  storyCoverage: string
  history: HistoryDay[] | null
  browserCheckedAt: string
  siteStatus: {prepared_at: string; data_updated_at: string | null} | null
  headlineChecks: {name: string; checkedAt: string | null; coverage: string}[]
  retail: RetailRegister | null
}

export const hostedPreview = import.meta.env.MODE === 'hosted'
const official = {ncsc: 'UK NCSC', cisa: 'US CISA', cert_eu_advisories: 'CERT-EU advisories', cert_eu_briefs: 'CERT-EU cyber briefs'}
const press = {register: 'The Register', record: 'The Record', bleeping: 'BleepingComputer', neowin: 'Neowin',
  securityweek: 'SecurityWeek', sans: 'SANS Internet Storm Center'}
const publishers: Record<string, string> = {...official, ...press}
export const publicLabels: Record<string, string> = {uk_direct: 'Direct UK retail', sector: 'Sector-related',
  unestablished: 'Relevance unestablished', catalogue: 'Catalogue evidence', first_party: 'First-party disclosure',
  attributed: 'Attributed reporting', ecommerce: 'E-commerce', customer_data: 'Customer data', supply_chain: 'Supply chain'}

const paths = {
  threats: 'data/threats.json', status: 'data/intelligence_status.json', official: 'data/official_updates.json',
  press: 'data/press_updates.json', retail: 'assets/retail-intelligence.json', flash: 'data/flash_alert.json',
  history: 'data/intelligence_history.json', publication: 'site_status.json'
} as const

export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function textFields<T extends object>(value: unknown, fields: (keyof T)[]): value is T {
  return object(value) && fields.every(key => typeof value[String(key)] === 'string')
}

export function safeUrl(value: unknown) {
  if (typeof value !== 'string' || !/^https:\/\/[^/]/i.test(value) || /[\s\u0000-\u001f\u007f\\<>"|]/u.test(value)) return null
  try {
    const url = new URL(value)
    return url.hostname && !url.username && !url.password && (!url.port || url.port === '443') ? url.href : null
  } catch { return null }
}

function validateThreat(value: unknown): value is Threat {
  if (!textFields<Threat>(value, ['id', 'title', 'url', 'severity', 'date', 'source']) || !safeUrl(value.url)) return false
  const finding = value.classification
  return finding === undefined || (object(finding) && finding.version === 1 && Number.isInteger(finding.score) &&
    typeof finding.relevance === 'string' && typeof finding.confidence === 'string' &&
    typeof finding.exploitation === 'string' && Array.isArray(finding.vulnerabilities) &&
    finding.vulnerabilities.every((entry: unknown) => textFields<{id: string}>(entry, ['id']) && /^CVE-\d{4}-\d{4,15}$/.test(entry.id)))
}

function validateRetail(value: unknown): value is RetailRegister {
  return object(value) && value.version === 1 && typeof value.reviewed_on === 'string' && Array.isArray(value.records) &&
    value.records.every(record => textFields<RetailRecord>(record, ['id', 'title', 'kind', 'organisation', 'status', 'confidence', 'relevance', 'lesson']) &&
      Array.isArray(record.functions) && record.functions.every(key => typeof key === 'string') && Array.isArray(record.timeline) &&
      record.timeline.length > 0 && record.timeline.every(entry => textFields<Evidence>(entry, ['date', 'publisher', 'summary', 'kind', 'url']) && safeUrl(entry.url)))
}

function readStories(value: unknown, kind: 'Official' | 'Press'): Story[] {
  if (!object(value) || !Array.isArray(value.stories)) return []
  return value.stories.flatMap((row: unknown) => {
    if (!object(row) || typeof row.id !== 'string' || typeof row.title !== 'string' ||
      typeof row.source !== 'string' || !Object.hasOwn(kind === 'Official' ? official : press, row.source)) return []
    const date = kind === 'Official' ? row.published_at : row.date
    const url = safeUrl(row.url)
    if (typeof date !== 'string' || !Number.isFinite(Date.parse(date)) || !url) return []
    return [{id: row.id, title: row.title, source: publishers[row.source], url, date,
      evidence: safeUrl(row.evidence_url) ?? undefined, kind: row.source === 'sans' ? 'Research' : kind}]
  })
}

async function read(name: keyof typeof paths): Promise<unknown> {
  try {
    const url = new URL(paths[name], document.baseURI)
    if (hostedPreview && name !== 'retail') url.searchParams.set('check', String(Date.now()))
    const response = await fetch(url, {signal: AbortSignal.timeout(6000)})
    return response.ok ? await response.json() : null
  } catch { return null }
}

function briefingStatus(value: unknown): BriefingStatus | null {
  if (!object(value) || typeof value.state !== 'string') return null
  const date = (entry: unknown) => typeof entry === 'string' && Number.isFinite(Date.parse(entry)) ? entry : null
  return {state: value.state, generated_at: date(value.generated_at), validated_at: date(value.validated_at)}
}

export const citedTechniques = (record: Threat) => (Array.isArray(record.attack_refs) ? record.attack_refs : [])
  .filter(id => typeof id === 'string' && /^T\d{4}(?:\.\d{3})?$/.test(id))
export const recordHref = (view: string, id: string) => '#/' + view + '/' + encodeURIComponent(id)

function timestamp(value: unknown) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null
}

function readHistory(value: unknown): HistoryDay[] | null {
  if (!object(value) || value.version !== 1 || !Array.isArray(value.days) || value.days.length > 90) return null
  const days = value.days as unknown[]
  if (!days.every(row => object(row) && timestamp(row.collected_at) && Number.isInteger(row.kev) &&
    Number(row.kev) >= 0 && Number(row.kev) <= 1000 && object(row.severity) && bandOrder.every(band =>
      object(row.severity) && Number.isInteger(row.severity[band]) && Number(row.severity[band]) >= 0 &&
      Number(row.severity[band]) <= 1000))) return null
  return days as HistoryDay[]
}

export async function loadSnapshot(): Promise<Snapshot> {
  const [threats, status, official, press, retail, alert, history, publication] = await Promise.all(
    [read('threats'), read('status'), read('official'), read('press'), read('retail'), read('flash'), read('history'), read('publication')])
  const collection = object(status) && object(status.collection) && typeof status.collection.state === 'string' &&
    (status.collection.data_updated_at === null || typeof status.collection.data_updated_at === 'string') ? status.collection as Collection : null
  const headlineCoverage = [official, press].filter(object)
  const outdated = headlineCoverage.some(item => typeof item.checked_at !== 'string' ||
    !Number.isFinite(Date.parse(item.checked_at)) || Date.now() - Date.parse(item.checked_at) > 90 * 60_000)
  const incomplete = headlineCoverage.length === 1 ||
    (object(official) && object(official.sources) && Object.values(official.sources).some(state => state !== 'current')) ||
    (object(press) && press.research === 'unavailable')
  const records = Array.isArray(threats) && threats.every(validateThreat) ? threats : null
  const flagged = object(alert) && alert.is_flash === true
    ? records?.find(record => record.id === alert.id && record.url === alert.url && record.classification?.exploitation === 'confirmed') : null
  const flashUrl = safeUrl(flagged?.url)
  const preparedAt = object(publication) && timestamp(publication.prepared_at)
  const headlineChecks = [
    ...Object.entries(publishers).filter(([key]) => ['ncsc', 'cisa', 'cert_eu_advisories', 'cert_eu_briefs'].includes(key)).map(([key, name]) =>
      ({name, checkedAt: object(official) ? timestamp(official.checked_at) : null,
        coverage: object(official) && object(official.sources) && official.sources[key] === 'current' ? 'Checked' : 'Unavailable'})),
    {name: 'Cyber news and research', checkedAt: object(press) ? timestamp(press.checked_at) : null,
      coverage: !object(press) ? 'Unavailable' : press.research === 'unavailable' ? 'Research incomplete' : 'Checked'}
  ]
  return {
    threats: records,
    collection,
    history: readHistory(history),
    browserCheckedAt: new Date().toISOString(),
    siteStatus: preparedAt ? {prepared_at: preparedAt, data_updated_at: object(publication) ? timestamp(publication.data_updated_at) : null} : null,
    headlineChecks,
    briefings: {daily: briefingStatus(object(status) ? status.daily : null), weekly: briefingStatus(object(status) ? status.weekly : null)},
    flash: flagged && flashUrl ? {id: flagged.id, title: flagged.title, url: flashUrl,
      advisory: typeof flagged.advisory === 'string' ? flagged.advisory : null} : null,
    briefing: object(status) && object(status.daily) && typeof status.daily.validated_at === 'string'
      ? 'Last validated ' + showDate(status.daily.validated_at, true) : 'No validated daily briefing available',
    stories: [...readStories(official, 'Official'), ...readStories(press, 'Press')]
      .sort((left, right) => Date.parse(right.date) - Date.parse(left.date) || left.id.localeCompare(right.id)),
    storyCoverage: headlineCoverage.length === 0 ? 'Unavailable' : outdated ? 'Stale' :
      incomplete ? 'Incomplete' : 'Snapshot available',
    retail: validateRetail(retail) ? retail : null
  }
}

export function collectionState(snapshot: Snapshot | null) {
  if (!snapshot) return 'Loading'
  const collection = snapshot.collection
  if (collection?.state === 'failed') return 'Failed'
  const age = collection?.data_updated_at ? Date.now() - Date.parse(collection.data_updated_at) : NaN
  if (!snapshot.threats || !Number.isFinite(age) || age < -5 * 60_000) return 'Unavailable'
  if (age > 90 * 60_000) return 'Stale'
  return collection?.state === 'current' ? 'Current' : collection?.state === 'partial' ? 'Incomplete' : 'Unavailable'
}

export function showDate(value: string | null | undefined, withTime = false) {
  const timestamp = value ? Date.parse(value) : NaN
  if (!Number.isFinite(timestamp)) return 'Unavailable'
  return new Intl.DateTimeFormat('en-GB', withTime ? {
    dateStyle: 'medium', timeStyle: 'short', timeZone: 'Europe/London'
  } : {day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Europe/London'}).format(timestamp)
}

const ukToday = () => Date.parse(new Intl.DateTimeFormat('sv-SE', {timeZone: 'Europe/London', dateStyle: 'short'}).format(Date.now()))
export function lastThirty(record: RetailRecord) {
  const now = ukToday()
  const first = Date.parse(record.timeline[0].date)
  return first <= now && first >= now - 29 * 86400000
}

export function retailStale(register: RetailRegister) {
  const age = ukToday() - Date.parse(register.reviewed_on)
  return !Number.isFinite(age) || age < 0 || age > 14 * 86400000
}

export const bandOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
export const severity = (record: Threat) => bandOrder.includes(record.severity) ? record.severity : 'UNKNOWN'
