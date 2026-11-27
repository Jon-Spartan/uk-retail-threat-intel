import {useState} from 'react'
import {recordHref, showDate} from './data'
import type {Snapshot} from './data'
import {Bars, Empty, External, Metric, Panel, State} from './ui'

export const watchTopics = {
  legal: /\b(?:law firms?|legal services|law practices?|solicitors?|legal aid|courts? service)\b/i,
  finance: /\b(?:banks?|banking|credit unions?|insurers?|financial services|financial institutions?|fintech|payment processors?)\b/i,
  healthcare: /\b(?:healthcare|health care|hospitals?|NHS|medical clinics?|health systems?)\b/i,
  ai: /\b(?:AI|artificial intelligence|generative AI|LLMs?|large language models?|agentic AI|prompt injection|deepfakes?)\b/i
}

const sectorResources = {
  legal: [
    ['Cybercrime guidance for solicitors', 'Solicitors Regulation Authority', 'Review examples of payment diversion and malware, and practical measures for protecting client information.', 'https://www.sra.org.uk/solicitors/guidance/cybercrime/'],
    ['Legal Aid Agency incident update', 'Legal Aid Agency · 14 October 2026', 'The agency revised its account of the personal data affected by the April 2025 cyber incident.', 'https://www.gov.uk/government/news/legal-aid-agency-cyber-security-incident-data-update-october-2026'],
    ['Cyber security thematic review', 'Solicitors Regulation Authority', 'Read the regulator’s 2020 study of how law firms managed threats such as email fraud and ransomware.', 'https://www.sra.org.uk/sra/research-publications/cyber-security/']
  ],
  finance: [
    ['Operational resilience resources', 'Financial Conduct Authority', 'Find resources for identifying important business services, mapping dependencies and testing disruption scenarios.', 'https://www.fca.org.uk/firms/operational-resilience'],
    ['Consultation on cyber risk and resilience', 'Financial Conduct Authority · 19 November 2026', 'The FCA, PRA and Bank of England published proposed guidance on cyber risk management and recovery.', 'https://www.fca.org.uk/publications/guidance-consultations/gc26-9-cyber-risk-resilience-management'],
    ['Operational incident reporting', 'Financial Conduct Authority', 'Check which incidents may need to be reported and find the reporting routes.', 'https://www.fca.org.uk/firms/operational-resilience/reporting-operational-incidents']
  ],
  healthcare: [
    ['Cyber alerts and incident support', 'NHS England', 'Find published cyber alerts and incident response resources for health and care organisations.', 'https://digital.nhs.uk/cyber-and-data-security/incidents-and-alerts'],
    ['Reporting a healthcare cyber incident', 'NHS England', 'Find the reporting routes for incidents that affect health and care services, systems or data in England.', 'https://digital.nhs.uk/cyber-and-data-security/incidents-and-alerts/report-an-incident']
  ],
  ai: []
}

const sectorSources = {legal: 'moj_cyber', finance: 'treasury_cyber', healthcare: 'nhs_cyber', ai: undefined}

export function TopicWatch({topic, snapshot}: {topic: keyof typeof watchTopics; snapshot: Snapshot | null}) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('All sources')
  const source = sectorSources[topic]
  const check = source ? snapshot?.headlineChecks.find(item => item.key === source) : undefined
  const matches = (snapshot?.stories || []).filter(story =>
    (source !== undefined && story.sourceKey === source) || watchTopics[topic].test(story.title))
    .sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
  const resources = sectorResources[topic]
  const dedicatedCount = matches.filter(story => story.sourceKey === source).length
  const publishers = [...new Set(matches.map(story => story.source))].map(label =>
    ({label, count: matches.filter(story => story.source === label).length})).sort((a, b) => b.count - a.count)
  const coverage = snapshot?.storyCoverage || 'Loading'
  const count = (value: number) => coverage === 'Unavailable' || coverage === 'Loading' || (coverage === 'Stale' && !matches.length)
    ? coverage : value
  const reports = matches.filter(story =>
    (!source || filter === 'All sources' || (filter === 'Sector feed') === (story.sourceKey === source)) &&
    (story.title + ' ' + story.source).toLowerCase().includes(query.trim().toLowerCase()))
  const resourcePanel = <Panel title="Sector guidance and resources" detail="Reviewed references and public disclosures from sector authorities.">
    <ul className="review-queue-list">{resources.map(([title, publisher, summary, url]) =>
      <li key={url}><div className="review-entry">
        <p className="muted">{publisher}</p>
        <h3><External url={url}>{title}</External></h3>
        <p>{summary}</p>
      </div></li>)}</ul>
  </Panel>
  return <>
    {source && <>
      <div className="notice"><State>{coverage}</State><span>Public-source coverage · {check?.name || 'Sector feed'} · {check?.coverage || 'Unavailable'}
        {check?.checkedAt && ' · Last checked ' + showDate(check.checkedAt, true)}</span></div>
      <dl className="metrics">
        <Metric icon="feed" label="Public reports" value={count(matches.length)} detail="Matches in this snapshot"/>
        <Metric icon="shield" label="Sector feed items" value={dedicatedCount || (check?.coverage === 'Checked' ? count(0) : 'Unavailable')}
          detail="Published by the sector source" tone="green"/>
        <Metric icon="dot" label="General feed matches" value={count(matches.length - dedicatedCount)} detail="Matched by headline wording" tone="violet"/>
        <Metric icon="retail" label="Reviewed resources" value={resources.length} detail="Guidance and public disclosures"/>
      </dl>
      <div className="main-grid">
        <Panel title="Reporting by publisher" detail="Headline counts in this snapshot">
          {publishers.length ? <Bars rows={publishers} total={matches.length}/> : <Empty title="No publisher totals available"/>}
        </Panel>
        <Panel title="Incident trend" detail="Historical reporting coverage">
          <Empty title="Insufficient history for a trend">A reviewed incident series is needed to measure changes over time.</Empty>
        </Panel>
      </div>
    </>}
    <Panel title={source ? 'Sector intelligence register' : 'Public reporting'} detail={source ?
      'Sector feed updates and matches from general cyber headlines.' : 'Matches from headline wording.'}
    trailing={<State>{snapshot?.storyCoverage || 'Loading'}</State>}>
    {source && <div className="filterbar">
      <label>Search sector reports<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Title or publisher"/></label>
      <label>Source<select aria-label="Source" value={filter} onChange={event => setFilter(event.target.value)}>
        {['All sources', 'Sector feed', 'General feeds'].map(option => <option key={option}>{option}</option>)}
      </select></label>
    </div>}
    {topic === 'healthcare' && <p className="muted">Information from NHS England, licenced under the current version of the Open Government Licence.</p>}
    {(topic === 'legal' || topic === 'finance') && <p className="muted">GOV.UK headlines contain Crown copyright information licensed under the Open Government Licence v3.0.</p>}
    {reports.length ? <ul className="review-queue-list">{reports.map(story =>
      <li key={story.kind + ':' + story.id}><div className="review-entry">
        <p className="muted">{story.source} · {showDate(story.date)}</p>
        <h3><a href={recordHref('feed', story.id)}>{story.title}</a></h3>
        <External url={story.url}>Original source</External>
      </div></li>)}</ul> : <Empty title={matches.length ? 'No reports match these filters' : snapshot ?
      'No matching headlines in this snapshot' : 'Waiting for the headline snapshot'}>
      {matches.length ? 'Try a different search or source.' : snapshot?.storyCoverage === 'Unavailable' ?
        'Headline coverage is unavailable.' : 'Matches will appear when the available feeds carry relevant headlines.'}
    </Empty>}
  </Panel>
  {source && <div className="main-grid">{resourcePanel}
    <Panel title="Evidence and coverage" detail="How the sector view is populated">
      <p>Sector feed items come from the designated publisher. General feed matches use headline wording and can miss relevant reports.</p>
      <p>Use the original source to confirm relevance. Headline counts describe reporting coverage.</p>
    </Panel>
  </div>}
  </>
}
