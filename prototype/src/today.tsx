import {collectionState, recordHref, safeUrl, showDate} from './data'
import type {Snapshot, Story} from './data'
import {DisclosureWatch} from './disclosures'
import {Briefings} from './tools'
import {Empty, External, Panel, State} from './ui'

function latestReporting(stories: Story[], now: number) {
  const groups: {lead: Story; sources: Story[]}[] = []
  const keys = new Map<string, typeof groups[number]>()
  for (const story of stories) {
    const age = now - Date.parse(story.date)
    const evidence = safeUrl(story.evidence)
    const url = safeUrl(story.url)
    if (!url || !Number.isFinite(age) || age < 0 || age > 48 * 3600000) continue
    const headline = story.title.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim()
    const matches = [evidence, url, headline].filter((key): key is string => Boolean(key))
    const existing = matches.map(key => keys.get(key)).find(Boolean)
    const group = existing || {lead: story, sources: []}
    if (!existing) groups.push(group)
    if (!group.sources.some(entry => entry.url === url)) group.sources.push(story)
    if (story.kind === 'Official' && group.lead.kind !== 'Official') group.lead = story
    matches.forEach(key => keys.set(key, group))
  }
  return groups
}

export function Today({snapshot}: {snapshot: Snapshot | null}) {
  const state = collectionState(snapshot)
  const current = state === 'Current' || state === 'Incomplete'
  const seen = new Set<string>()
  const priority = current ? (snapshot?.threats || []).filter(item => !item.carried_forward &&
    item.classification?.exploitation === 'confirmed').sort((a, b) =>
      (b.classification?.score ?? 0) - (a.classification?.score ?? 0)).flatMap(item => {
    const cve = item.classification?.vulnerabilities.find(entry => entry.kev && !seen.has(entry.id))
    if (!cve) return []
    item.classification?.vulnerabilities.filter(entry => entry.kev).forEach(entry => seen.add(entry.id))
    return [{item, cve}]
  }).slice(0, 3) : []
  const reporting = latestReporting(snapshot?.stories || [], Date.now()).slice(0, 5)
  return <>
    <div className="notice"><State>{snapshot?.storyCoverage || 'Loading'}</State>
      <span>Headline coverage · Vulnerabilities {state.toLowerCase()}</span>
      <a href="#/health">Check source health</a>
    </div>
    <div className="main-grid">
      <Panel title="Priority vulnerabilities" detail="CISA-listed exploitation · ranked by project priority"
        trailing={<a href="#/radar">Open Vulnerability Radar</a>}>
        {priority.length ? <ul className="review-queue-list">{priority.map(({item, cve}) =>
          <li key={cve.id}><div className="review-entry">
            <h3><a href={recordHref('radar', item.id)}>{item.title}</a></h3>
            <p>{cve.id} has confirmed exploitation. Check whether the affected product and versions apply to you.</p>
            <External url={item.url}>CISA catalogue entry</External>
          </div></li>)}</ul> : <Empty title={current ? 'No confirmed items in this snapshot' : 'Current vulnerability priorities unavailable'}/>}
      </Panel>
      <Panel title="Latest reporting" detail="Past 48 hours · matching source links and headlines are grouped"
        trailing={<a href="#/feed">Open Intelligence Feed</a>}>
        {reporting.length ? <ul className="review-queue-list">{reporting.map(({lead, sources}) =>
          <li key={lead.id}><div className="review-entry">
            <p className="muted">{lead.kind === 'Official' ? 'Official reporting' : lead.kind} · {showDate(lead.date, true)}</p>
            <h3><a href={recordHref('feed', lead.id)}>{lead.title}</a></h3>
            <div className="inline-links">{sources.slice(0, 3).map(source =>
              <External key={source.url} url={source.url}>{source.source}</External>)}</div>
          </div></li>)}</ul> : <Empty title={snapshot ? 'No recent headlines available in this snapshot' : 'Waiting for headline coverage'}/>}
      </Panel>
    </div>
    <Briefings snapshot={snapshot} period="daily" compact/>
    <DisclosureWatch preview/>
  </>
}
