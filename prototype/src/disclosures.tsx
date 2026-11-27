import {showDate} from './data'
import {Empty, External, Panel} from './ui'

type Sector = 'retail' | 'legal' | 'finance' | 'healthcare'
type Disclosure = {id: string; title: string; sectors: Sector[];
  timeline: {date: string; publisher: string; summary: string; url: string}[]}

// Editors add an incident only after checking the linked primary statements.
const reviewed: Disclosure[] = [
  {id: 'cleverbridge-2026', title: 'Cleverbridge data incident', sectors: ['retail', 'finance'], timeline: [
    {date: '2026-11-20', publisher: 'Cleverbridge', summary: 'The payments provider reported that some personal data was copied and said customer notifications began on 20 November.', url: 'https://grow.cleverbridge.com/incident-update'}
  ]},
  {id: 'legal-aid-agency-2025', title: 'Legal Aid Agency cyber incident', sectors: ['legal'], timeline: [
    {date: '2026-10-14', publisher: 'Legal Aid Agency', summary: 'The agency revised its public account of which types of personal data were affected by the April 2025 incident.', url: 'https://www.gov.uk/government/news/legal-aid-agency-cyber-security-incident-data-update-october-2026'}
  ]},
  {id: 'synnovis-2024', title: 'Synnovis pathology services incident', sectors: ['healthcare'], timeline: [
    {date: '2024-06-14', publisher: 'NHS England', summary: 'NHS England reported that the disruption to pathology services led to postponed appointments and procedures in South East London.', url: 'https://www.england.nhs.uk/london/2024/06/14/update-on-cyber-incident-clinical-impact-in-south-east-london-friday-14-june-2024/'},
    {date: '2025-11-10', publisher: 'NHS England', summary: 'NHS England reported that services had been restored by December 2024. It said Synnovis was contacting affected healthcare organisations about stolen data.', url: 'https://www.england.nhs.uk/synnovis-cyber-incident/questions-and-answers/'}
  ]}
]

export function DisclosureWatch({sector, preview = false}: {sector?: Sector; preview?: boolean}) {
  const records = reviewed.filter(record => !sector || record.sectors.includes(sector))
    .sort((a, b) => b.timeline.at(-1)!.date.localeCompare(a.timeline.at(-1)!.date)).slice(0, preview ? 3 : undefined)
  return <Panel title={sector ? 'Disclosure Watch' : 'Reviewed disclosures'} detail="Selected original notices and follow-ups, including historical incidents.">
    {records.length ? <ul className="review-queue-list">{records.map(record => <li key={record.id}>
      <div className="review-entry"><h3>{record.title}</h3>
        <ul className="evidence-timeline">{(preview ? record.timeline.slice(-1) : record.timeline).map(entry => <li key={entry.date + entry.url}>
          <strong>{showDate(entry.date)}</strong><p>{entry.summary}</p><External url={entry.url}>{entry.publisher}</External>
        </li>)}</ul>
      </div>
    </li>)}</ul> : <Empty title="No reviewed disclosures for this sector"/>}
    {(sector || preview) && <a className="text-link" href="#/disclosures">View all reviewed disclosures</a>}
  </Panel>
}
