import {recordHref, showDate} from './data'
import type {Snapshot} from './data'
import {Empty, External, Panel, State} from './ui'

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
  const source = sectorSources[topic]
  const check = source && snapshot?.headlineChecks.find(item => item.key === source)
  const matches = (snapshot?.stories || []).filter(story =>
    (source !== undefined && story.sourceKey === source) || watchTopics[topic].test(story.title))
    .sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
  const resources = sectorResources[topic]
  return <>
    {resources.length > 0 && <Panel title="Sector guidance and resources" detail="Reference material from sector authorities.">
      <ul className="review-queue-list">{resources.map(([title, publisher, summary, url]) =>
        <li key={url}><div className="review-entry">
          <p className="muted">{publisher}</p>
          <h3><External url={url}>{title}</External></h3>
          <p>{summary}</p>
        </div></li>)}</ul>
    </Panel>}
    <Panel title="Public reporting" detail={source ? 'Sector feed updates and matches from general cyber headlines.' : 'Matches from headline wording.'}
    trailing={<State>{snapshot?.storyCoverage || 'Loading'}</State>}>
    {check && <p className="notice">{check.name} · {check.coverage}{check.checkedAt && ' · Last checked ' + showDate(check.checkedAt, true)}</p>}
    {topic === 'healthcare' && <p className="muted">Information from NHS England, licenced under the current version of the Open Government Licence.</p>}
    {(topic === 'legal' || topic === 'finance') && <p className="muted">GOV.UK headlines contain Crown copyright information licensed under the Open Government Licence v3.0.</p>}
    {matches.length ? <ul className="review-queue-list">{matches.map(story =>
      <li key={story.kind + ':' + story.id}><div className="review-entry">
        <p className="muted">{story.source} · {showDate(story.date)}</p>
        <h3><a href={recordHref('feed', story.id)}>{story.title}</a></h3>
        <External url={story.url}>Original source</External>
      </div></li>)}</ul> : <Empty title={snapshot ? 'No matching headlines in this snapshot' : 'Waiting for the headline snapshot'}>
      {snapshot?.storyCoverage === 'Unavailable' ? 'Headline coverage is unavailable.' : 'Matches will appear when the available feeds carry relevant headlines.'}
    </Empty>}
  </Panel>
  </>
}
