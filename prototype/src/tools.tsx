import {useEffect, useState} from 'react'
import {citedTechniques, collectionState, object, recordHref, safeUrl, severity, showDate} from './data'
import type {BriefingStatus, Period, Snapshot, Threat} from './data'
import {Empty, External, Panel, State} from './ui'
import {BriefingFallback} from './activity'

const stackKey = 'cti_my_tech_stack'
const dismissKey = 'dismissedFlashKeys'
const words = (value: string) => value.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu)?.join(' ') || ''

function readList(storage: 'localStorage' | 'sessionStorage', key: string, limit: number) {
  try {
    const entries: unknown = JSON.parse(window[storage].getItem(key) || '[]')
    return Array.isArray(entries) ? entries.filter((entry): entry is string =>
      typeof entry === 'string' && entry.trim().length > 0 && entry.length <= 500).slice(0, limit) : []
  } catch { return [] }
}

export function useMyStack() {
  const [stack, setStack] = useState(() => readList('localStorage', stackKey, 50))
  function update(entries: string[]) {
    setStack(entries)
    try {
      if (entries.length) localStorage.setItem(stackKey, JSON.stringify(entries))
      else localStorage.removeItem(stackKey)
    } catch { /* Preferences remain in memory when storage is disabled. */ }
  }
  return {stack, update}
}

export function stackMatch(record: Threat, entries: string[]) {
  const terms = entries.flatMap(entry => entry.split('|').map(words)).filter(Boolean)
  const phrase = (text: string, term: string) => (' ' + words(text) + ' ').includes(' ' + term + ' ')
  const products = Array.isArray(record.affected_products) ? record.affected_products : []
  if (terms.some(term => products.some(product => product && ['cisa_kev', 'cve_list'].includes(product.source)
      && typeof product.vendor === 'string' && typeof product.product === 'string' && phrase(product.vendor + ' ' + product.product, term)))) {
    return 'Declared product match'
  }
  const context = [record.title, record.summary, ...(Array.isArray(record.tags) ? record.tags : []),
    ...(Array.isArray(record.cves) ? record.cves : [])].join(' ')
  return terms.some(term => phrase(context, term)) ? 'Topic match' : ''
}

export function MyStack({snapshot, stack, update}: {snapshot: Snapshot | null; stack: string[]; update: (entries: string[]) => void}) {
  const [input, setInput] = useState('')
  const [status, setStatus] = useState('')
  const records = (snapshot?.threats || []).map(row => ({row, match: stackMatch(row, stack)})).filter(result => result.match)
  function add() {
    const entry = input.trim()
    if (!words(entry)) return
    if (stack.some(value => value.toLowerCase() === entry.toLowerCase())) {
      setStatus('That entry is already saved.')
      return
    }
    if (stack.length >= 50) {
      setStatus('Remove an entry before adding another.')
      return
    }
    update([...stack, entry])
    setInput('')
    setStatus('Entry saved.')
  }
  return <>
    <Panel title="Technology preferences" detail="Saved only in this browser. A match is a lead for reviewing public evidence.">
      <form className="filterbar" onSubmit={event => {event.preventDefault(); add()}}>
        <label>Product or topic<input value={input} maxLength={120} placeholder="Product, topic or CVE"
          onChange={event => setInput(event.target.value)}/></label>
        <button className="button" type="submit">Add to My Stack</button>
        <button className="button" type="button" disabled={!stack.length} onClick={() => {update([]); setStatus('My Stack cleared.')}}>Clear My Stack</button>
      </form>
      <p className="count" role="status">{status}</p>
      <ul className="tool-list">{stack.map(entry => <li key={entry}><span>{entry}</span>
        <button className="button" type="button" aria-label={'Remove ' + entry}
          onClick={() => {update(stack.filter(value => value !== entry)); setStatus('Entry removed.')}}>Remove</button></li>)}</ul>
      {!stack.length && <Empty title="My Stack is empty"/>}
    </Panel>
    <Panel title="Matching vulnerability records" detail="Declared product matches and broader topic matches are labelled separately.">
      <ul className="tool-list">{records.map(({row, match}) => <li key={row.id}><a href={recordHref('radar', row.id)}>{row.title}</a><span>{match}</span></li>)}</ul>
      {!records.length && <Empty title={snapshot?.threats ? 'No records match My Stack' : 'Vulnerability snapshot unavailable'}/>}
    </Panel>
  </>
}

export function Flash({snapshot}: {snapshot: Snapshot | null}) {
  const [dismissed, setDismissed] = useState(() => readList('sessionStorage', dismissKey, 30))
  const alert = snapshot?.flash
  const state = collectionState(snapshot)
  if (!alert || !['Current', 'Incomplete'].includes(state) || dismissed.includes(alert.url) || dismissed.includes(alert.id)) return null
  return <section className="notice flash" aria-label="Flash alert">
    <div><strong>Flash alert · {alert.title}</strong>{alert.advisory && <p>{alert.advisory}</p>}
      <a href={recordHref('radar', alert.id)}>Open vulnerability evidence</a></div>
    <button type="button" className="button" onClick={() => {
      const next = [...dismissed, alert.url].slice(-30)
      setDismissed(next)
      try {sessionStorage.setItem(dismissKey, JSON.stringify(next))} catch { /* Session controls still work in memory. */ }
    }}>Dismiss alert</button>
  </section>
}

const tactics = {
  'Initial access': [['T1190', 'Exploit Public-Facing Application'], ['T1195', 'Supply Chain Compromise'], ['T1566', 'Phishing']],
  'Credential access': [['T1110', 'Brute Force'], ['T1078', 'Valid Accounts']],
  'Collection': [['T1056.004', 'Credential API Hooking'], ['T1005', 'Data from Local System']],
  'Impact': [['T1486', 'Data Encrypted for Impact'], ['T1499', 'Endpoint Denial of Service']]
}

export function Mitre({snapshot}: {snapshot: Snapshot | null}) {
  if (!snapshot?.threats) return <Empty title="Technique evidence unavailable"/>
  const totals = new Map<string, number>()
  for (const row of snapshot.threats) {
    for (const id of new Set(citedTechniques(row))) totals.set(id, (totals.get(id) || 0) + 1)
  }
  const listed = new Set(Object.values(tactics).flat().map(([id]) => id))
  const extra = [...totals.keys()].filter(id => !listed.has(id)).sort().map(id => [id, 'Additional cited technique'])
  return <>
    <div className="notice"><State>{collectionState(snapshot)}</State><span>Counts reflect source citations. Select a technique to open its records in Radar.</span></div>
    <div className="tools-grid">{Object.entries({...tactics, ...(extra.length ? {'Other cited techniques': extra} : {})}).map(([group, items]) =>
      <Panel key={group} title={group}><ul className="tool-list">{items.map(([id, name]) => <li key={id}>
        <a href={'#/radar?technique=' + id}><strong>{id}</strong> {name}</a><span>{totals.get(id) || 0}</span>
      </li>)}</ul></Panel>)}</div>
  </>
}

const titles = ['Facts and attributed reporting', 'Assessments', 'Recommendations']
type Briefing = {sections: {title: string; rows: {text: string; id: string}[]}[]; sources: {id: string; publisher: string; url: string}[]; stale: boolean}

async function readBriefing(period: Period, status: BriefingStatus): Promise<Briefing> {
  const fetchFile = (suffix: string) => fetch('./data/' + period + suffix, {signal: AbortSignal.timeout(6000)})
  const [evidence, summary] = await Promise.all([fetchFile('_briefing.json'), fetchFile('_summary.md')])
  if (!evidence.ok || !summary.ok) throw Error('Published briefing files are unavailable.')
  const json: unknown = await evidence.json()
  const markdown = (await summary.text()).replace(/\r\n/g, '\n')
  if (!object(json) || json.schema_version !== 1 || json.period !== period || json.generated_at !== status.generated_at ||
    json.validated_at !== status.validated_at || !Array.isArray(json.sources) || !object(json.selection) ||
    !markdown.startsWith('AI-assisted selection of public-source evidence.\n') || !markdown.includes('\nSources\n')) {
    throw Error('Briefing files do not match the validated publication.')
  }
  const sourceMap = new Map<string, Briefing['sources'][number]>()
  for (const source of json.sources) {
    const url = object(source) ? safeUrl(source.url) : null
    if (!object(source) || typeof source.id !== 'string' || typeof source.publisher !== 'string' || !url || sourceMap.has(source.id)) {
      throw Error('Invalid briefing source.')
    }
    sourceMap.set(source.id, {id: source.id, url, publisher: source.publisher})
  }
  const keys = ['facts', 'assessments', 'recommendations']
  const body = markdown.split('\nSources\n')[0]
  const collected = new Map(titles.map(title => [title, [] as {text: string; id: string}[]]))
  let heading = ''
  for (const line of body.split('\n')) {
    if (titles.includes(line)) heading = line
    else if (line.startsWith('- ')) {
      const match = line.match(/^- (.+) \[([^\]]+)\]$/)
      if (!match || !collected.has(heading)) throw Error('Invalid briefing entry.')
      collected.get(heading)!.push({text: match[1], id: match[2]})
    }
  }
  const sections = titles.map((title, index) => {
    const rows = collected.get(title)!
    const expected = json.selection as Record<string, unknown>
    if (!Array.isArray(expected[keys[index]]) || JSON.stringify(rows.map(row => row.id)) !== JSON.stringify(expected[keys[index]]) ||
      rows.some(row => !sourceMap.has(row.id) || !collected.get(titles[0])?.some(fact => fact.id === row.id))) {
      throw Error('Invalid briefing evidence references.')
    }
    return {title, rows}
  })
  if (!sections[0].rows.length) throw Error('Briefing contains no verified facts.')
  const maxAge = (period === 'daily' ? 36 : 8 * 24) * 3600000
  const sources = sections[0].rows.map(row => sourceMap.get(row.id)!)
  return {sections, sources, stale: status.state !== 'available' || Date.now() - Date.parse(status.generated_at || '') > maxAge}
}

export function Briefings({snapshot, period, compact = false}: {snapshot: Snapshot | null; period: Period; compact?: boolean}) {
  const status = snapshot?.briefings[period]
  const [result, setResult] = useState<{value: Briefing | null; key: string} | null>(null)
  const key = period + '|' + status?.generated_at + '|' + status?.validated_at + '|' + status?.state
  const generated = status?.generated_at
  const validated = status?.validated_at
  const state = status?.state
  useEffect(() => {
    if (!generated || !validated || !state) return
    let active = true
    void readBriefing(period, {generated_at: generated, validated_at: validated, state})
      .then(value => {if (active) setResult({value, key})})
      .catch(() => {if (active) setResult({value: null, key})})
    return () => {active = false}
  }, [period, generated, validated, state, key])
  const briefing = result?.key === key ? result.value : undefined
  return <Panel title={period === 'daily' ? 'Daily intelligence briefing' : 'Weekly intelligence briefing'}
    detail={briefing ? 'AI-assisted selection of public-source evidence' : undefined}>
    {compact ? <a href="#/briefings/daily">Read the full briefing</a> : <nav aria-label="Briefing editions" className="inline-links">
      <a href="#/briefings/daily" aria-current={period === 'daily' ? 'page' : undefined}>Daily</a>
      <a href="#/briefings/weekly" aria-current={period === 'weekly' ? 'page' : undefined}>Weekly</a>
      <a href="#/roundup">Editorial roundup</a>
    </nav>}
    {briefing ? <div className="briefing-body">
      <div className="notice"><State>{briefing.stale ? 'Stale' : 'Validated'}</State><span>Validated {showDate(validated, true)} UK time</span></div>
      {briefing.sections.filter(section => section.rows.length).map(section => <section key={section.title}>
        <h3>{section.title}</h3><ul>{(compact ? section.rows.slice(0, 2) : section.rows).map(row => <li key={row.id}>{row.text} <a href={'#' + period + '-source-' + row.id}
          onClick={event => {event.preventDefault(); document.getElementById(period + '-source-' + row.id)?.focus()}}>[{row.id}]</a></li>)}</ul>
      </section>)}
      <section><h3>Sources</h3><ul>{briefing.sources.map(source => <li key={source.id} id={period + '-source-' + source.id} tabIndex={-1}>
        <External url={source.url}>{'[' + source.id + '] ' + source.publisher}</External>
      </li>)}</ul></section>
      <a href={'./data/' + period + '_briefing.json'}>Download evidence and selection JSON</a>
    </div> : <>
      <Empty title={briefing === null ? 'Briefing validation or loading failed' : !snapshot || generated && validated ?
        'Loading briefing evidence' : state === 'failed' ? 'Latest briefing generation or validation failed' : 'No validated AI-assisted briefing available'}/>
      {snapshot && (briefing === null || !generated || !validated) && <BriefingFallback snapshot={snapshot} period={period}/>}
    </>}
  </Panel>
}

export function Health({snapshot, refresh}: {snapshot: Snapshot | null; refresh: () => void}) {
  const collection = snapshot?.collection
  const prepared = snapshot?.siteStatus
  const mismatched = Boolean(prepared?.data_updated_at && collection?.data_updated_at && prepared.data_updated_at !== collection.data_updated_at)
  return <>
    <Panel title="Collection and validation" trailing={<button className="button" onClick={refresh}>Refresh intelligence</button>}>
      <div className="notice"><State>{collectionState(snapshot)}</State><span>Last successful collection · {showDate(collection?.last_success_at, true)} UK time</span></div>
      {mismatched && <p className="notice">The build and collection timestamps refer to different snapshots. A refresh can check for a matching pair.</p>}
      <dl className="assurance"><div><dt>Last collection attempt</dt><dd>{showDate(collection?.checked_at, true)}</dd></div>
        <div><dt>Served Pages build prepared</dt><dd>{showDate(prepared?.prepared_at, true)}</dd></div>
        <div><dt>Last browser check completed</dt><dd>{showDate(snapshot?.browserCheckedAt, true)}</dd></div>
        <div><dt>Daily briefing validated</dt><dd>{showDate(snapshot?.briefings.daily?.validated_at, true)}</dd></div>
        <div><dt>Weekly briefing validated</dt><dd>{showDate(snapshot?.briefings.weekly?.validated_at, true)}</dd></div>
        <div><dt>Headline coverage</dt><dd>{snapshot?.storyCoverage || 'Unavailable'}</dd></div>
        <div><dt>Retail editorial review</dt><dd>{showDate(snapshot?.retail?.reviewed_on)}</dd></div></dl>
      <ul className="tool-list">{(Array.isArray(collection?.feeds) ? collection.feeds : [])
        .filter(feed => typeof feed?.name === 'string').map(feed => <li key={feed.name}><span>{feed.name}</span>
          <span>{feed.state === 'success' ? 'Last check succeeded' : 'Last check unavailable or failed'}</span></li>)}</ul>
    </Panel>
    <Panel title="Headline source checks" detail="Feed check times can advance while the newest published headline stays the same. Times are UK local.">
      <ul className="tool-list">{snapshot?.headlineChecks.map(feed => <li key={feed.name}>
        <span>{feed.name}</span><span>{feed.coverage} · {showDate(feed.checkedAt, true)}</span>
      </li>)}</ul>
    </Panel>
    <Panel title="Exports and methodology" detail="Public-source report exports and evidence standards.">
      <ul className="tool-list"><li><a href="./data/threats.stix.json">STIX 2.1 report bundle</a></li><li><a href="./data/feed.xml">RSS intelligence feed</a></li>
        <li><a href="./SOURCES.md">Approved sources and attribution</a></li><li><a href="./SCORING.md">Scoring methodology</a></li>
        <li><a href="#/radar">Filter and export vulnerability CSV</a></li></ul>
    </Panel>
  </>
}

function csvCell(input: unknown) {
  const value = String(input ?? '')
  const escaped = /^[\t\r\n]|^\s*[=+\-@＝＋－＠]/u.test(value) ? "'" + value : value
  return '"' + escaped.replaceAll('"', '""') + '"'
}

export function downloadRadar(rows: Threat[]) {
  const headers = ['Technical severity', 'Sector priority', 'Retail relevance', 'Evidence confidence', 'Exploitation',
    'Title', 'Subsector', 'Source', 'Date', 'Verified CVEs', 'CVEs mentioned', 'EPSS by CVE', 'Cited techniques', 'Recommendation', 'Source URL']
  const values = rows.map(row => {
    const evidence = row.classification
    return [severity(row), evidence?.score, evidence?.relevance, evidence?.confidence, evidence?.exploitation,
      row.title, row.subsector, row.source, row.date, evidence?.vulnerabilities.map(entry => entry.id).join(', '),
      Array.isArray(row.reported_cves) ? row.reported_cves.join(', ') : '', evidence?.vulnerabilities.filter(entry => entry.epss)
        .map(entry => entry.id + ' ' + entry.epss?.probability + ' (' + entry.epss?.date + ')').join(', '),
      citedTechniques(row).join(', '), row.advisory, safeUrl(row.url)]
  })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([[headers, ...values].map(row => row.map(csvCell).join(',')).join('\r\n')],
    {type: 'text/csv;charset=utf-8'}))
  link.download = 'uk_retail_threat_intel_' + new Date().toISOString().slice(0, 10) + '.csv'
  link.click()
  setTimeout(() => URL.revokeObjectURL(link.href), 1000)
}
