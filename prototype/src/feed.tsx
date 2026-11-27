import {useState} from 'react'
import {recordHref, safeUrl, showDate} from './data'
import type {Snapshot, Story} from './data'
import {cyberWatch} from './editorial'
import {Empty, Icon, State} from './ui'

export const feedSources = ['All sources', 'Official', 'Press', 'Research', 'Cyber watch'] as const
type FeedSource = typeof feedSources[number]
const sourceLabels: Record<FeedSource, string> = {
  'All sources': 'All reports', Official: 'Official', Press: 'Press', Research: 'Research', 'Cyber watch': 'Cyber watch'
}

function feedHref(source: FeedSource, id?: string) {
  const path = id ? recordHref('feed', id) : '#/feed'
  return source === 'All sources' ? path : path + '?' + new URLSearchParams({source}).toString()
}

function SourceTag({kind}: {kind: Story['kind']}) {
  return <span className="feed-source-tag" data-kind={kind}>{kind}</span>
}

function SourceAction({url, label, prominent = false}: {url: unknown; label: string; prominent?: boolean}) {
  const href = safeUrl(url)
  if (!href) return null
  const host = new URL(href).hostname.replace(/^www\./, '')
  return <a className={'feed-source-action' + (prominent ? ' feed-source-primary' : '')}
    href={href} target="_blank" rel="noopener noreferrer">
    <span><strong>{label}</strong><small>{host}</small></span><Icon name="external" size={16}/>
  </a>
}

function ReadingPane({story, reports, source}: {story: Story; reports: Story[]; source: FeedSource}) {
  const index = reports.findIndex(item => item.id === story.id)
  const previous = index > 0 ? reports[index - 1] : null
  const next = index >= 0 && index < reports.length - 1 ? reports[index + 1] : null
  const related = reports.filter(item => item.source === story.source && item.id !== story.id).slice(0, 2)
  return <>
    <header className="feed-reader-header">
      <SourceTag kind={story.kind}/>
      <h2 id="feed-reader-title">{story.title}</h2>
      <p className="feed-reader-byline"><span>{story.source}</span><span aria-hidden="true">·</span>
        <time dateTime={story.date}>{showDate(story.date)}</time></p>
    </header>
    {(story.summary || story.lesson) && <section className="feed-context" aria-label="Editorial context">
      {story.summary && <div><h3>Summary</h3><p>{story.summary}</p></div>}
      {story.lesson && <div className="feed-lesson"><h3>Defensive lesson</h3><p>{story.lesson}</p></div>}
    </section>}
    <section className="feed-evidence" aria-label="Sources">
      <h3>Sources</h3>
      <div className="feed-evidence-actions">
        {story.evidence && <SourceAction url={story.evidence} label="Open primary disclosure" prominent/>}
        <SourceAction url={story.url} label={'Read on ' + story.source} prominent={!story.evidence}/>
      </div>
    </section>
    {related.length > 0 && <section className="feed-related" aria-label="More from this publisher">
      <h3>More from {story.source}</h3>
      <ul>{related.map(item => <li key={item.id}><a href={feedHref(source, item.id)}>
        <span>{item.title}</span><Icon name="arrow" size={15}/>
      </a></li>)}</ul>
    </section>}
    {(previous || next) && <nav className="feed-reader-nav" aria-label="Adjacent reports">
      {previous && <a className="feed-newer" href={feedHref(source, previous.id)}><Icon name="arrow" size={16}/>Newer report</a>}
      {next && <a href={feedHref(source, next.id)}>Older report<Icon name="arrow" size={16}/></a>}
    </nav>}
  </>
}

export function Feed({snapshot, selected, source}: {snapshot: Snapshot | null; selected?: string; source: FeedSource}) {
  const [query, setQuery] = useState('')
  const all = (snapshot?.stories || []).concat(cyberWatch).sort((a, b) => Date.parse(b.date) - Date.parse(a.date))
  const term = query.trim().toLowerCase()
  const reports = all.filter(item => (source === 'All sources' || source === item.kind) &&
    (item.title + ' ' + item.source).toLowerCase().includes(term))
  const story = selected ? all.find(item => item.id === selected) : reports[0]
  const groups = new Map<string, Story[]>()
  for (const report of reports) {
    const label = showDate(report.date)
    const group = groups.get(label) || []
    group.push(report)
    groups.set(label, group)
  }
  const latestCheck = snapshot?.headlineChecks.map(check => check.checkedAt)
    .filter((date): date is string => Boolean(date)).sort((a, b) => Date.parse(b) - Date.parse(a))[0]
  const count = reports.length + (reports.length === 1 ? ' report' : ' reports')
  return <div className="feed-workspace">
    <div className="feed-toolbar panel">
      <div className="feed-toolbar-top">
        <label className="feed-search"><span>Search reports</span><span className="feed-search-field">
          <Icon name="search" size={17}/><input type="search" placeholder="Search by title or publisher" value={query}
            onChange={event => setQuery(event.target.value)}/>
        </span></label>
        <div className="feed-coverage"><State>{snapshot?.storyCoverage || 'Loading'}</State>
          {latestCheck && <span>Latest source check · {showDate(latestCheck, true)} UK time</span>}</div>
      </div>
      <nav className="feed-filters" aria-label="Report sources">
        {feedSources.map(kind => <a key={kind} href={feedHref(kind)}
          aria-current={source === kind ? 'page' : undefined}>{sourceLabels[kind]}</a>)}
      </nav>
    </div>
    <div className="feed-layout" data-report-open={Boolean(selected)}>
      <section className="panel feed-results" aria-labelledby="feed-results-title">
        <div className="feed-pane-heading"><h2 id="feed-results-title">Latest reports</h2><span role="status">{count}</span></div>
        {groups.size ? <div className="feed-list" role="region" aria-label="Reports by publication date" tabIndex={0}>
          {[...groups].map(([date, reportsOnDate]) => <section key={date}><h3>{date}</h3>
            <ol>{reportsOnDate.map(item => <li key={item.id}><a className="feed-row" href={feedHref(source, item.id)}
              aria-current={item.id === story?.id ? 'true' : undefined}>
              <span className="feed-row-meta"><SourceTag kind={item.kind}/><span>{item.source}</span></span>
              <strong>{item.title}</strong><Icon name="arrow" size={16}/>
            </a></li>)}</ol>
          </section>)}
        </div> : <div className="feed-empty"><Empty title="No matching reports">
          {query ? 'Try a different title or publisher.' : 'Try another source filter.'}
        </Empty></div>}
      </section>
      <article className="panel feed-reader" aria-label={story ? 'Selected report' : 'Report reader'}>
        <div className="feed-pane-heading">
          <a href={feedHref(source)} className="feed-back"><Icon name="arrow" size={16}/>Back to reports</a>
          <span className="feed-reader-caption">Selected report</span>
          {story && reports.includes(story) && <span>{reports.indexOf(story) + 1} of {reports.length}</span>}
        </div>
        <div className="feed-reader-content" key={story?.id ?? 'empty'} role="region" aria-label="Report details" tabIndex={0}>
          {story ? <ReadingPane story={story} reports={reports} source={source}/> :
            <Empty title={selected ? 'Report unavailable in this snapshot' : 'No report selected'}>
              {selected ? <a href={feedHref(source)}>Return to reports</a> : 'Choose a report to see its sources.'}
            </Empty>}
        </div>
      </article>
    </div>
  </div>
}
