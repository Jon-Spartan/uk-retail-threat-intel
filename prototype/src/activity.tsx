import {useEffect, useRef, useState} from 'react'
import {bandOrder, collectionState, lastThirty, object, recordHref, retailStale, showDate} from './data'
import type {Period, Snapshot} from './data'
import {Empty, External, Panel} from './ui'

const groups = ['KEVs', 'Stories', 'Retail incidents'] as const
type Group = typeof groups[number]
type Entry = {key: string; title: string; detail: string; href: string}
type Tracker = Partial<Record<Group, {at: string; keys: string[]}>>
const storageKey = 'cti_activity_seen_v1'
const day = 86400000

function entries(snapshot: Snapshot | null): Partial<Record<Group, Entry[]>> {
  const available: Partial<Record<Group, Entry[]>> = {}
  if (!snapshot) return available
  if (collectionState(snapshot) === 'Current') {
    const byCve = new Map<string, Entry>()
    for (const row of snapshot.threats || []) {
      if (row.carried_forward) continue
      for (const cve of row.classification?.vulnerabilities || []) {
        if (cve.kev && !byCve.has(cve.id)) byCve.set(cve.id, {key: cve.id, title: row.title,
          detail: 'CISA KEV · ' + row.date, href: recordHref('radar', row.id)})
      }
    }
    available.KEVs = [...byCve.values()]
  }
  if (snapshot.storyCoverage === 'Snapshot available') {
    available.Stories = snapshot.stories.map(story => ({key: story.id, title: story.title,
      detail: story.source + ' · ' + showDate(story.date), href: recordHref('feed', story.id)}))
  }
  if (snapshot.retail && !retailStale(snapshot.retail)) {
    available['Retail incidents'] = snapshot.retail.records.filter(row => row.kind === 'incident').flatMap(row =>
      row.timeline.map(item => ({
        key: [row.id, item.date, item.kind, item.url].join('|'),
        title: row.title, detail: (item.kind === 'report' ? 'Initial report' :
          item.kind === 'evidence_review' ? 'Evidence review' : item.kind === 'correction' ? 'Correction' : 'Follow-up') +
          ' · ' + showDate(item.date),
        href: recordHref('retail', row.id)
      })))
  }
  return available
}

function loadTracker(): Tracker {
  const tracker: Tracker = {}
  try {
    const value: unknown = JSON.parse(localStorage.getItem(storageKey) || '{}')
    if (object(value)) for (const group of groups) {
      const source = value[group]
      if (object(source) && typeof source.at === 'string' && Number.isFinite(Date.parse(source.at)) &&
        Array.isArray(source.keys) && source.keys.length <= 1500 &&
        source.keys.every(key => typeof key === 'string' && key.length <= 500)) {
        tracker[group] = {at: source.at, keys: source.keys}
      }
    }
  } catch { /* The view still works in memory when storage is disabled. */ }
  return tracker
}

function capture(current: Entry[], prior?: Tracker[Group]) {
  const priorKeys = prior?.keys || []
  return {at: new Date().toISOString(), keys: [...new Set([...current.map(item => item.key), ...priorKeys])].slice(0, 1500)}
}

function save(tracker: Tracker) {
  try {localStorage.setItem(storageKey, JSON.stringify(tracker))} catch { /* In-memory comparison remains available. */ }
}

export function Activity({snapshot}: {snapshot: Snapshot | null}) {
  const [baseline, setBaseline] = useState(loadTracker)
  const saved = useRef(baseline)
  const captured = useRef(new Set<Group>())
  const [marked, setMarked] = useState(false)
  const current = entries(snapshot)
  useEffect(() => {
    const received = entries(snapshot)
    for (const group of groups) {
      const items = received[group]
      if (!items || captured.current.has(group)) continue
      captured.current.add(group)
      const first = !saved.current[group]
      const next = capture(items, saved.current[group])
      saved.current = {...saved.current, [group]: next}
      if (first) setBaseline(previous => ({...previous, [group]: next}))
      save(saved.current)
    }
  }, [snapshot])
  return <Panel title="What changed since your last visit?"
    detail="Compare records in the published windows with the last baseline saved in this browser."
    trailing={<button className="button" disabled={!groups.some(group => current[group])} onClick={() => {
      const updated = {...saved.current}
      for (const group of groups) if (current[group]) updated[group] = capture(current[group]!, updated[group])
      saved.current = updated
      save(updated)
      setBaseline(updated)
      setMarked(true)
    }}>Mark as seen</button>}>
    <p className="sr-only" role="status">{marked ? 'Available records marked as seen.' : ''}</p>
    <div className="activity-groups">{groups.map(group => {
      const items = current[group]
      const comparison = baseline[group]
      const seen = new Set(comparison?.keys)
      const changes = items?.filter(entry => !seen.has(entry.key)) || []
      return <section key={group}><h3>{group}</h3>
        <p className="muted">{!items ? 'Comparison unavailable for this source.' :
          !comparison ? 'Setting a baseline for this browser.' : changes.length ?
            changes.length + ' new since ' + showDate(comparison.at, true) + ' UK time' :
            'No additions in the available window since ' + showDate(comparison.at, true) + ' UK time.'}</p>
        {items && comparison && changes.length > 0 && <ul className="record-list">{changes.slice(0, 8).map(item =>
          <li key={item.key}><a href={item.href}><strong>{item.title}</strong><span className="muted">{item.detail}</span></a></li>)}</ul>}
      </section>
    })}</div>
  </Panel>
}

const series = ['Confirmed KEVs', ...bandOrder]
export function Trend({snapshot}: {snapshot: Snapshot | null}) {
  const end = Math.floor(Date.now() / day) * day
  const available = new Map(snapshot?.history?.map(row => [row.collected_at.slice(0, 10), row]))
  const rows = Array.from({length: 14}, (_, index) => {
    const date = new Date(end - (13 - index) * day).toISOString().slice(0, 10)
    return {date, row: available.get(date)}
  })
  const maximum = Math.max(1, ...rows.flatMap(({row}) => row ? [row.kev, ...bandOrder.map(band => row.severity[band])] : []))
  const hasHistory = rows.some(entry => entry.row)
  if (!hasHistory) return <Empty title="Daily history is not available yet">The chart will populate after complete vulnerability collections are published.</Empty>
  const values = rows.map(({row}) => row ? [row.kev, ...bandOrder.map(band => row.severity[band])] : null)
  const points = (index: number) => values.map((value, offset) => value ?
    {x: 24 + offset * 36, y: 126 - value[index] * 100 / maximum} : null)
  return <>
    <svg className="trend-chart" viewBox="0 0 520 150" aria-hidden="true">
      {[26, 51, 76, 101, 126].map(y => <line key={y} className="chart-rule" x1="24" x2="492" y1={y} y2={y}/>)}
      {series.map((label, index) => {
        const values = points(index)
        return <g key={label} className="chart-series" data-series={index}>
          {values.map((point, offset) => {
            const previous = values[offset - 1]
            return point ? <g key={offset}>
              {previous && <line x1={previous.x} x2={point.x} y1={previous.y} y2={point.y}/>}
              <circle cx={point.x} cy={point.y} r="3"/>
            </g> : null
          })}
        </g>
      })}
    </svg>
    <div className="trend-legend">{series.map((label, index) => <span key={label} data-series={index}>{label}</span>)}</div>
    <p className="muted">{showDate(rows[0].date)} to {showDate(rows.at(-1)?.date)} · UTC collection days. Missing days are gaps.</p>
    <details className="history-details"><summary>View daily counts</summary>
      <div className="table-scroll" role="region" aria-label="Daily vulnerability counts" tabIndex={0}><table>
        <caption className="sr-only">Counts from the latest complete collection on each UTC day</caption>
        <thead><tr><th scope="col">UTC date</th>{series.map(label => <th key={label} scope="col">{label}</th>)}</tr></thead><tbody>
          {rows.map(({date, row}) => <tr key={date}><th scope="row">{date}</th>{row ?
            [row.kev, ...bandOrder.map(band => row.severity[band])].map((value, index) => <td key={index}>{value}</td>) :
            <td colSpan={series.length}>No complete collection</td>}</tr>)}
        </tbody>
      </table></div>
    </details>
  </>
}

export function BriefingFallback({snapshot, period}: {snapshot: Snapshot; period: Period}) {
  const limit = (period === 'daily' ? 1 : 7) * day
  const recent = (value: string | undefined) => {
    const age = Date.now() - Date.parse(value || '')
    return Number.isFinite(age) && age >= 0 && age <= limit
  }
  const recentReport = (value: string) => {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return recent(value)
    const today = new Intl.DateTimeFormat('sv-SE', {timeZone: 'Europe/London', dateStyle: 'short'}).format(Date.now())
    const age = (Date.parse(today) - Date.parse(value)) / day
    return age >= 0 && age <= (period === 'daily' ? 1 : 6)
  }
  const current = entries(snapshot)
  const kevs = current.KEVs ? (snapshot.threats || []).filter(row =>
    !row.carried_forward && recent(row.first_seen_at) && row.classification?.vulnerabilities.some(cve => cve.kev)).slice(0, 4) : []
  const stories = current.Stories ? snapshot.stories.filter(story => recentReport(story.date)).slice(0, 4) : []
  const retail = current['Retail incidents'] ? snapshot.retail?.records.filter(row => row.kind === 'incident' && lastThirty(row) &&
    row.timeline.some(evidence => recentReport(evidence.date))).slice(0, 4) || [] : []
  return <div className="briefing-body">
    <p className="notice">Source-linked briefing · {period === 'daily' ? 'Last 24 hours for timed records. Today and yesterday for date-only reports.' :
      'Seven-day window.'} Created from the published records.</p>
    <section><h3>Newly observed CISA KEVs</h3>
      {!kevs.length && <p className="muted">{current.KEVs ? 'No new items in the available window.' : 'Current vulnerability coverage unavailable.'}</p>}
      <ul>{kevs.map(row => <li key={row.id}><a href={recordHref('radar', row.id)}>{row.title}</a> · <External url={row.url}>{row.source}</External></li>)}</ul>
    </section><section><h3>Recent headlines</h3>
      {!stories.length && <p className="muted">{current.Stories ? 'No dated headlines in the available window.' : 'Headline coverage unavailable or incomplete.'}</p>}
      <ul>{stories.map(story => <li key={story.id}><a href={recordHref('feed', story.id)}>{story.title}</a> · <External url={story.url}>{story.source}</External></li>)}</ul>
    </section><section><h3>Retail incident reports and updates</h3>
      {!retail.length && <p className="muted">{current['Retail incidents'] ? 'No dated entries in the reviewed archive for this window.' : 'Current retail review unavailable.'}</p>}
      <ul>{retail.map(row => {
        const evidence = row.timeline.filter(entry => recentReport(entry.date)).at(-1)!
        return <li key={row.id}><a href={recordHref('retail', row.id)}>{row.title}</a> · <External url={evidence.url}>{evidence.publisher}</External></li>
      })}</ul>
    </section>
  </div>
}
