import {useState} from 'react'
import {bandOrder, citedTechniques, collectionState, lastThirty, publicLabels, recordHref, retailStale, severity, showDate} from './data'
import type {Snapshot, Story, Threat} from './data'
import {Bars, Empty, External, Icon, Metric, Panel, State} from './ui'
import {downloadRadar, stackMatch} from './tools'
import {cyberWatch} from './editorial'
import {Activity, Trend} from './activity'
const titleCase = (value: string) => Object.hasOwn(publicLabels, value)
  ? publicLabels[value] : value.replaceAll('_', ' ').replace(/^./, first => first.toUpperCase())
const matches = (text: string, query: string) => text.toLowerCase().includes(query.toLowerCase().trim())
const cves = (row: Threat) => row.classification?.vulnerabilities.map(cve => cve.id).join(', ') || 'Unavailable'

export function Executive({snapshot}: {snapshot: Snapshot | null}) {
  const state = collectionState(snapshot)
  const threats = snapshot?.threats || []
  const retail = snapshot?.retail?.records.filter(record => record.kind === 'incident' && lastThirty(record))
  const editorialStale = snapshot?.retail && retailStale(snapshot.retail)
  const current = state === 'Current' || state === 'Incomplete'
  const exploited = new Set(threats.flatMap(row => row.classification?.exploitation === 'confirmed'
    ? row.classification.vulnerabilities.filter(cve => cve.kev).map(cve => cve.id) : [])).size
  const related = threats.filter(row => ['uk_direct', 'sector'].includes(row.classification?.relevance || '')).length
  const priority = threats.filter(row => row.classification?.exploitation === 'confirmed')
    .sort((a, b) => (b.classification?.score ?? 0) - (a.classification?.score ?? 0)).slice(0, 3)
  return <>
    <div className="notice"><State>{state}</State><span>Vulnerability snapshot · {showDate(snapshot?.collection?.data_updated_at, true)} UK time</span></div>
    <dl className="metrics">
      <Metric label="Vulnerability records" value={current ? threats.length : state} detail="Validated collection" icon="radar"/>
      <Metric label="Confirmed exploitation" value={current ? exploited : state} detail="Unique CISA-listed CVEs" icon="shield" tone="red"/>
      <Metric label="Documented retail relevance" value={current ? related : state} detail="Direct UK or sector relevance" icon="retail" tone="green"/>
      <Metric label="Reported retail incidents" value={editorialStale ? 'Stale' : retail?.length ?? 'Unavailable'} detail={'30 days · Review ' + showDate(snapshot?.retail?.reviewed_on)} icon="feed" tone="violet"/>
    </dl>
    <Activity snapshot={snapshot}/>
    <div className="main-grid">
      <Panel title="Threat intelligence trend" detail="Latest complete snapshot per UTC day · 14-day view">
        <Trend snapshot={snapshot}/>
      </Panel>
      <Panel title="Severity distribution" detail={snapshot?.threats ? 'Dated vulnerability snapshot · technical severity' : 'Vulnerability snapshot unavailable'}>
        {snapshot?.threats ? <Bars rows={bandOrder.map(band => ({label: titleCase(band.toLowerCase()), tone: band.toLowerCase(),
          count: threats.filter(threat => severity(threat) === band).length}))} total={threats.length}/>
          : <Empty title="No verified snapshot available"/>}
      </Panel>
    </div>
    <div className="main-grid">
      <Panel title="Priority review" detail="Catalogue-confirmed exploitation · ranked by documented priority"
        trailing={<a className="text-link" href="#/radar">Open radar <Icon name="arrow" size={15}/></a>}>
        {current && priority.length ? <ul className="record-list">{priority.map(row => <li key={row.id}><a href={recordHref('radar', row.id)}>
          <span className="severity" data-tone={severity(row).toLowerCase()}>{titleCase(severity(row).toLowerCase())}</span>
          <strong>{row.title.replace(/^CISA KEV addition: /i, '')}</strong>
          <span className="muted">{titleCase(row.classification?.relevance || 'unestablished')}</span></a></li>)}</ul>
          : <Empty title={current ? 'No priority records match this view' : 'Current priority review unavailable'}/>}
      </Panel>
      <Panel title="Intelligence assurance" detail="Collection and evidence status">
        <dl className="assurance">
          <div><dt>Last successful collection</dt><dd>{showDate(snapshot?.collection?.last_success_at, true)}</dd></div>
          <div><dt>Briefing validation</dt><dd>{snapshot?.briefing || 'Checking'}</dd></div>
          <div><dt>Editorial review</dt><dd>{showDate(snapshot?.retail?.reviewed_on)}</dd></div>
        </dl>
      </Panel>
    </div>
  </>
}

export function Radar({snapshot, selected, initialSeverity, technique, stack}: {
  snapshot: Snapshot | null; selected?: string; initialSeverity: string; technique: string; stack: string[]
}) {
  const [query, setQuery] = useState('')
  const [ascending, setAscending] = useState(false)
  const [matchOnly, setMatchOnly] = useState(false)
  const [kevOnly, setKevOnly] = useState(false)
  const [topic, setTopic] = useState('')
  const state = collectionState(snapshot)
  const coverage = state === 'Current' || state === 'Incomplete'
  const rows = (snapshot?.threats || []).filter(row =>
    (!initialSeverity || severity(row) === initialSeverity) && (!technique || citedTechniques(row).includes(technique)) &&
    (!kevOnly || row.classification?.vulnerabilities.some(cve => cve.kev)) && (!matchOnly || stackMatch(row, stack)) &&
    (!topic || (topic === 'retail' ? ['uk_direct', 'sector'].includes(row.classification?.relevance || '') :
      topic === 'regulatory' ? /\b(?:ico|pci(?:\s+dss)?|gdpr|data protection|payment card)\b/i.test([row.title, row.summary, row.advisory].join(' ')) :
        /\b(?:black friday|cyber monday|christmas|fraud|phishing|delivery scam|returns|checkout)\b/i.test([row.title, row.summary, row.advisory].join(' ')))) &&
    matches(row.title + ' ' + cves(row) + ' ' + citedTechniques(row).join(' '), query))
    .sort((a, b) => (ascending ? 1 : -1) * ((a.classification?.score ?? -1) - (b.classification?.score ?? -1)) || a.id.localeCompare(b.id))
  const hit = snapshot?.threats?.find(row => row.id === selected)
  return <>
    <div className="notice"><State>{state}</State><span>Collection date · {showDate(snapshot?.collection?.data_updated_at, true)} UK time</span></div>
    {hit && <Panel title={hit.title} detail="Public vulnerability evidence" trailing={<a href="#/radar" className="text-link">Close detail</a>}>
      <dl className="assurance"><div><dt>Verified CVEs</dt><dd>{cves(hit)}</dd></div>
      <div><dt>Evidence confidence</dt><dd>{titleCase(hit.classification?.confidence || 'unassessed')}</dd></div>
      <div><dt>Technical severity</dt><dd>{titleCase(severity(hit).toLowerCase())}</dd></div></dl>
      {stackMatch(hit, stack) && <p className="muted">{stackMatch(hit, stack)} · Check published applicability before acting.</p>}
      <External url={hit.url}>Open CISA catalogue entry</External>
    </Panel>}
    {selected && !hit && <div className="notice"><span>Vulnerability record is unavailable in this snapshot.</span> <a href="#/radar">Return to the radar</a></div>}
    <Panel title="Vulnerability catalogue" detail="Compare technical severity, exploitation evidence and sector relevance."
      trailing={<button className="button" type="button" disabled={!rows.length} onClick={() => downloadRadar(rows)}>Export CSV</button>}>
      <div className="filterbar">
        <label>Search CVEs and products<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Enter a CVE or product"/></label>
        <label>Severity<select aria-label="Severity" value={initialSeverity} onChange={event => {
          const filters = new URLSearchParams()
          if (event.target.value) filters.set('severity', event.target.value.toLowerCase())
          if (technique) filters.set('technique', technique)
          const query = filters.toString()
          location.hash = '/radar' + (query ? '?' + query : '')
        }}><option value="">All severities</option>{bandOrder.map(band => <option key={band} value={band}>{titleCase(band.toLowerCase())}</option>)}</select></label>
        <label>Topic<select aria-label="Topic" value={topic} onChange={event => setTopic(event.target.value)}>
          <option value="">All topics</option><option value="retail">Retail relevance</option>
          <option value="regulatory">Regulatory topics</option><option value="seasonal">Seasonal retail topics</option>
        </select></label>
      </div>
      <div className="inline-links filter-toggles">
        <label><input type="checkbox" checked={kevOnly} onChange={event => setKevOnly(event.target.checked)}/> CISA KEV only</label>
        <label><input type="checkbox" checked={matchOnly} onChange={event => setMatchOnly(event.target.checked)}/> My Stack matches</label>
        {technique && <a href={initialSeverity ? '#/radar?severity=' + initialSeverity.toLowerCase() : '#/radar'}>Clear technique {technique}</a>}
      </div>
      <p role="status" className="count">{snapshot?.threats ? rows.length + ' matching records' : 'Catalogue unavailable'}</p>
      {rows.length ? <div className="table-scroll" role="region" aria-label="Vulnerability results" tabIndex={0}><table>
        <caption className="sr-only">Vulnerability results sorted by documented priority</caption>
        <thead><tr><th scope="col">Vulnerability</th><th scope="col">Severity</th><th scope="col" aria-sort={ascending ? 'ascending' : 'descending'}>
          <button className="sort-button" type="button" onClick={() => setAscending(value => !value)}>Priority {ascending ? '↑' : '↓'}</button>
        </th><th scope="col">Exploitation</th><th scope="col">Retail relevance</th><th scope="col">Source date</th></tr></thead>
        <tbody>{rows.map(row => <tr key={row.id}>
          <th scope="row"><a href={recordHref('radar', row.id)}>{row.title.replace(/^CISA KEV addition: /i, '')}</a>
            {stackMatch(row, stack) && <small className="row-note">{stackMatch(row, stack)}</small>}
            {!coverage && row.carried_forward && <small className="row-note">Carried forward</small>}</th>
          <td><span className="severity" data-tone={severity(row).toLowerCase()}>{titleCase(severity(row).toLowerCase())}</span></td>
          <td className="mono">{row.classification?.score ?? '—'}</td><td>{titleCase(row.classification?.exploitation || 'unknown')}</td>
          <td>{titleCase(row.classification?.relevance || 'unestablished')}</td><td>{row.date}</td>
        </tr>)}</tbody>
      </table></div> : <Empty title={snapshot?.threats ? 'No vulnerabilities match these filters' : 'Vulnerability records unavailable'}/>}
    </Panel>
  </>
}

export function Feed({snapshot, selected, initialSource}: {snapshot: Snapshot | null; selected?: string; initialSource: string}) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState(initialSource)
  const all = (snapshot?.stories || []).concat(cyberWatch).sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
  const stories = all.filter(story => (kind === 'All sources' || story.kind === kind) && matches(story.title + ' ' + story.source, query))
  const story = selected ? all.find(item => item.id === selected) : stories[0]
  return <>
    <div className="notice"><State>{snapshot?.storyCoverage || 'Loading'}</State><span>Official publications, reviewed press links and security research</span></div>
    <div className="reader-grid">
      <Panel title="Reports" detail="Published source dates">
        <div className="filterbar reader-filters"><label>Search reports<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Title or publisher"/></label>
          <label>Source type<select value={kind} onChange={event => setKind(event.target.value)}>{['All sources', 'Official', 'Press', 'Research', 'Cyber watch'].map(value => <option key={value}>{value}</option>)}</select></label>
        </div>
        <p className="count" role="status">{stories.length} {stories.length === 1 ? 'report' : 'reports'}</p>
        <ol className="report-list">{stories.map(item => <li key={item.id}><a href={recordHref('feed', item.id)} aria-current={story?.id === item.id ? 'true' : undefined}>
          <span>{item.source} · {showDate(item.date)}</span><strong>{item.title}</strong></a></li>)}</ol>
        {!stories.length && <Empty title="No matching reports"/>}
      </Panel>
      <article className={'panel reader' + (selected ? ' reader-selected' : '')}>
        {story ? <ReadingPane story={story}/> : <Empty title="Report unavailable">Choose a report from the list.</Empty>}
      </article>
    </div>
  </>
}

function ReadingPane({story}: {story: Story}) {
  return <>
    <a className="text-link reader-back" href="#/feed">Back to reports</a>
    <p className="reader-label">{story.kind} · {story.source}</p>
    <h2>{story.title}</h2><p className="muted">{showDate(story.date)}</p>
    <div className="evidence-block"><h3>Source evidence</h3>
      {story.summary ? <p>{story.summary}</p> :
        <p className="muted">The reviewed record contains a title, date and source link. Read the publication for the full account.</p>}
      {story.lesson && <p><strong>Defensive lesson · </strong>{story.lesson}</p>}
      <External url={story.url}>Read on {story.source}</External>
      {story.evidence && <External url={story.evidence}>Open primary disclosure</External>}
    </div>
  </>
}

export function Retail({snapshot, selected}: {snapshot: Snapshot | null; selected?: string}) {
  const [mode, setMode] = useState('All records')
  const [query, setQuery] = useState('')
  const [period, setPeriod] = useState('recent')
  const register = snapshot?.retail
  const reports = register?.records.filter(lastThirty) || []
  const incidents = reports.filter(record => record.kind === 'incident')
  const functions = [...new Set(incidents.flatMap(record => record.functions))].map(key => ({label: titleCase(key),
    count: incidents.filter(record => record.functions.includes(key)).length})).sort((a, b) => b.count - a.count)
  const focus = register?.records.find(record => record.id === selected)
  const rows = (period === 'archive' ? register?.records || [] : reports).filter(record => matches(record.title + ' ' + record.organisation, query) &&
    (mode === 'All records' || (mode === 'Incidents' ? record.kind === 'incident' : mode === 'Threat campaigns' ?
      record.kind === 'campaign' : mode === 'Golden Quarter' ? record.seasonal :
        record.functions.includes(mode === 'Payments' ? 'payments' : 'supply_chain'))))
  const stale = register && retailStale(register)
  const value = (number: number) => register ? stale ? 'Stale' : number : 'Unavailable'
  return <>
    <div className="notice"><State>{register ? stale ? 'Stale' : 'Reviewed' : snapshot ? 'Unavailable' : 'Loading'}</State>
      <span>Editorial review · {showDate(register?.reviewed_on)} · Selected public disclosures</span></div>
    <dl className="metrics">
      <Metric icon="retail" label="Reported incidents" value={value(incidents.length)} detail="Unique events in 30 days" tone="red"/>
      <Metric icon="feed" label="Retail advisories" value={value(reports.filter(row => row.kind === 'advisory').length)} detail="Reviewed guidance in 30 days"/>
      <Metric icon="shield" label="Supply chain incidents" value={value(incidents.filter(row => row.functions.includes('supply_chain')).length)} detail="Evidenced business function" tone="green"/>
      <Metric icon="dot" label="Payment developments" value={value(reports.filter(row => row.functions.includes('payments')).length)} detail="Evidenced payment relevance" tone="violet"/>
    </dl>
    <div className="main-grid">
      <Panel title="Affected retail functions" detail="Observed in reviewed incidents · records may cover multiple functions">
        {functions.length ? <Bars rows={functions} total={incidents.length}/> : <Empty title="No reviewed incidents in the window"/>}
      </Panel>
      <Panel title="Incident trend" detail="Historical reporting coverage">
        <Empty title="Insufficient history for a trend">The archive holds selected reports. Counts describe public reporting coverage.</Empty>
      </Panel>
    </div>
    {focus && <Panel title={focus.title} detail={titleCase(focus.confidence) + ' · ' + titleCase(focus.relevance)}
      trailing={<a className="text-link" href="#/retail">Close detail</a>}>
      <dl className="assurance">
        <div><dt>Organisation</dt><dd>{focus.organisation}</dd></div><div><dt>Geography</dt><dd>{focus.geography || 'Unknown'}</dd></div>
        <div><dt>Initial access</dt><dd>{focus.initial_access || 'Unknown'}</dd></div>
        <div><dt>Publicly reported impact</dt><dd>{focus.impact || 'Unknown'}</dd></div>
        <div><dt>Data exposure</dt><dd>{focus.exposure || 'Unknown'}</dd></div>
      </dl>
      <h3>Evidence timeline</h3><ul className="evidence-timeline">{focus.timeline.map((entry, index) => <li key={entry.date + index}>
        <strong>{showDate(entry.date)} · {titleCase(entry.kind)}</strong><p>{entry.summary}</p><External url={entry.url}>{entry.publisher}</External>
      </li>)}</ul>
      <h3>Defensive lesson</h3><p>{focus.lesson}</p>
    </Panel>}
    {selected && !focus && <div className="notice">Retail record unavailable in this snapshot. <a href="#/retail">Return to Retail</a></div>}
    <Panel title="Retail intelligence register" detail={period === 'archive' ? 'All reviewed records, including historical incidents' :
      'Reports first entered in the past 30 days'}>
      <div className="filterbar"><label>Search retail records<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Title or organisation"/></label>
        <label>Date range<select aria-label="Date range" value={period} onChange={event => setPeriod(event.target.value)}>
          <option value="recent">Last 30 days</option><option value="archive">All reviewed records</option></select></label>
        <label>View<select value={mode} onChange={event => setMode(event.target.value)}>{['All records', 'Incidents', 'Threat campaigns', 'Supply chain', 'Payments', 'Golden Quarter'].map(value => <option key={value}>{value}</option>)}</select></label></div>
      <p className="count" role="status">{rows.length} matching records</p>
      <ul className="record-list">{rows.map(record => <li key={record.id}><a href={recordHref('retail', record.id)}>
        <span className="label">{titleCase(record.kind)}</span><strong>{record.title}</strong><span className="muted">{showDate(record.timeline[0].date)}</span>
      </a></li>)}</ul>
      {!rows.length && <Empty title={register ? 'No matching retail records' : 'Retail register unavailable'}/>}
    </Panel>
    <div className="main-grid">
      <Panel title="Lessons for retailers" detail="Editorial recommendations linked to reviewed evidence.">
        <ul className="tool-list">{reports.filter(record => record.lesson).slice(0, 4).map(record =>
          <li key={record.id}><span>{record.lesson}</span><External url={record.timeline[0].url}>{record.timeline[0].publisher}</External></li>)}</ul>
        {!reports.length && <Empty title="No reviewed lessons in this window"/>}
      </Panel>
      <Panel title="Golden Quarter Watch" detail="Black Friday and Cyber Monday through Christmas trading and January returns.">
        <ul className="record-list">{register?.records.filter(record => record.seasonal).map(record =>
          <li key={record.id}><a href={recordHref('retail', record.id)}>{record.title}</a></li>)}</ul>
        {!register?.records.some(record => record.seasonal) && <Empty title="No reviewed seasonal entries"/>}
      </Panel>
    </div>
  </>
}
