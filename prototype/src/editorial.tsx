import type {Story} from './data'
import {External, Panel} from './ui'

export const cyberWatch: Story[] = [
  {
    id: 'cyber-watch-fincen', kind: 'Cyber watch', source: 'The Register', date: '2026-11-25',
    title: 'FinCEN extends some filing deadlines after disruption',
    summary: 'The US Treasury’s financial crimes bureau took some systems offline while it investigated unauthorised access. FinCEN gave eligible filers extra time to submit certain reports.',
    lesson: 'Know where to check for deadline changes if a regulator’s filing portal goes down.',
    url: 'https://www.theregister.com/security/2026/11/25/us-treasury-financial-crimes-unit-becomes-latest-fed-breach-victim/5312165',
    evidence: 'https://www.fincen.gov/sites/default/files/100/ORDER-FIN-2026-R002.pdf'
  },
  {
    id: 'cyber-watch-eu-academy', kind: 'Cyber watch', source: 'European Commission', date: '2026-11-23',
    title: 'EU Academy goes offline after a data leak',
    summary: 'The European Commission confirmed that a wider cyber incident exposed personal data from its learning platform. It suspended public access while it assessed how many users were affected. On 25 November the Commission said its investigation was still open.',
    lesson: 'Plan how to reach users through a separate channel when the service they normally sign in to is unavailable.',
    url: 'https://audiovisual.ec.europa.eu/en/media/video/I-298395',
    evidence: 'https://audiovisual.ec.europa.eu/en/media/video/I-298552'
  },
  {
    id: 'cyber-watch-oyster', kind: 'Cyber watch', source: 'The Register', date: '2026-11-19',
    title: 'Oyster cards kept working as TfL investigated a breach',
    summary: 'Transport for London told The Register it took the Oyster photocard website offline after an incident affecting customer accounts. Existing photocards could still be used for travel.',
    lesson: 'In an incident update, spell out which services customers can still use and where to get help.',
    url: 'https://www.theregister.com/cyber-crime/2026/11/19/tfl-takes-oyster-photocard-website-offline-after-attackers-compromise-customer-accounts/5310985'
  }
]

export function Roundup() {
  return <Panel title="Weekly roundup" detail="Reviewed editorial edition · 19–25 November 2026">
    <div className="briefing-body">
      <section><h3>Check internet-facing services</h3>
        <p>The NCSC reported an increase in AI-assisted attacks and urged defenders to revisit basic controls such as account permissions and access to public-facing services.</p>
        <External url="https://www.ncsc.gov.uk/blogs/familiar-weaknesses-exploited-faster-defending-against-agentic-cyber-attacks">NCSC guidance, 24 November</External></section>
      <section><h3>Plan for customer notifications</h3>
        <p>Cleverbridge’s update explains what it confirmed about payment data. The ICO’s guide covers assessment, recording and reporting when personal data is involved.</p>
        <div className="inline-links"><External url="https://grow.cleverbridge.com/incident-update">Cleverbridge disclosure</External>
          <External url="https://ico.org.uk/for-organisations/report-a-breach/personal-data-breach/personal-data-breaches-a-guide/">ICO breach guide</External></div></section>
      <section><h3>Keep an alternative route open</h3>
        <p>Disruption at FinCEN affected some filings, while people could still travel on existing Oyster photocards during the portal outage.</p>
        <div className="inline-links"><a href="#/feed/cyber-watch-fincen">FinCEN story</a><a href="#/feed/cyber-watch-oyster">Oyster story</a></div></section>
    </div>
  </Panel>
}
