export type Collection = {
  state: string
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
  classification?: {
    version: number
    score: number
    relevance: string
    confidence: string
    exploitation: string
    vulnerabilities: { id: string; kev: boolean; cvss?: {score: number; version: string} }[]
  }
}

export type Evidence = {date: string; kind: string; publisher: string; url: string; summary: string}

export type RetailRecord = {
  id: string; title: string; kind: string; organisation: string; geography: string | null; status: string
  confidence: string; relevance: string; functions: string[]; initial_access: string | null; impact: string | null
  exposure: string | null; lesson: string; timeline: Evidence[]
}

export type RetailRegister = {version: number; reviewed_on: string; records: RetailRecord[]}
export type Story = {id: string; source: string; title: string; url: string; date: string; evidence?: string; kind: 'Official' | 'Press' | 'Research'}
export type Snapshot = {
  threats: Threat[] | null
  collection: Collection | null
  briefing: string
  stories: Story[]
  storyCoverage: string
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
  press: 'data/press_updates.json', retail: 'assets/retail-intelligence.json'
} as const

function object(value: unknown): value is Record<string, unknown> {
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
    const response = await fetch(new URL(paths[name], document.baseURI), {signal: AbortSignal.timeout(6000)})
    return response.ok ? await response.json() : null
  } catch { return null }
}

export async function loadSnapshot(): Promise<Snapshot> {
  const [threats, status, official, press, retail] = await Promise.all(
    [read('threats'), read('status'), read('official'), read('press'), read('retail')])
  const collection = object(status) && object(status.collection) && typeof status.collection.state === 'string' &&
    (status.collection.data_updated_at === null || typeof status.collection.data_updated_at === 'string') ? status.collection as Collection : null
  const headlineCoverage = [official, press].filter(object)
  const outdated = headlineCoverage.some(item => typeof item.checked_at !== 'string' ||
    !Number.isFinite(Date.parse(item.checked_at)) || Date.now() - Date.parse(item.checked_at) > 90 * 60_000)
  const incomplete = headlineCoverage.length === 1 ||
    (object(official) && object(official.sources) && Object.values(official.sources).some(state => state !== 'current'))
  return {
    threats: Array.isArray(threats) && threats.every(validateThreat) ? threats : null,
    collection,
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
