import {recordHref, showDate} from './data'
import type {Snapshot} from './data'
import {Empty, External, Panel, State} from './ui'

export const watchTopics = {
  legal: /\b(?:law firms?|legal services|law practices?|solicitors?|legal aid|courts? service)\b/i,
  finance: /\b(?:banks?|banking|credit unions?|insurers?|financial services|financial institutions?|fintech|payment processors?)\b/i,
  healthcare: /\b(?:healthcare|health care|hospitals?|NHS|medical clinics?|health systems?)\b/i,
  ai: /\b(?:AI|artificial intelligence|generative AI|LLMs?|large language models?|agentic AI|prompt injection|deepfakes?)\b/i
}

export function TopicWatch({topic, snapshot}: {topic: RegExp; snapshot: Snapshot | null}) {
  const matches = (snapshot?.stories || []).filter(story => topic.test(story.title))
    .sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
  return <Panel title="Public reporting" detail="Matches from headline wording. Read the original source to confirm relevance."
    trailing={<State>{snapshot?.storyCoverage || 'Loading'}</State>}>
    <p className="notice">Coverage is limited to the existing headline feeds. This view does not measure sector risk.</p>
    {matches.length ? <ul className="review-queue-list">{matches.map(story =>
      <li key={story.kind + ':' + story.id}><div className="review-entry">
        <p className="muted">{story.source} · {showDate(story.date)}</p>
        <h3><a href={recordHref('feed', story.id)}>{story.title}</a></h3>
        <External url={story.url}>Original source</External>
      </div></li>)}</ul> : <Empty title={snapshot ? 'No matching headlines in this snapshot' : 'Waiting for the headline snapshot'}>
      {snapshot?.storyCoverage === 'Unavailable' ? 'Headline coverage is unavailable.' : 'Matches will appear when the available feeds carry relevant headlines.'}
    </Empty>}
  </Panel>
}
