import {useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {bandOrder, collectionState, hostedPreview, loadSnapshot, recordHref} from './data'
import type {Snapshot} from './data'
import {Executive, Radar, Retail} from './views'
import {Feed, feedSources} from './feed'
import {Briefings, Flash, Health, Mitre, MyStack, useMyStack} from './tools'
import {cyberWatch, Roundup} from './editorial'
import {ReviewQueueProvider, ReviewQueueView} from './reviewQueue'
import {TopicWatch} from './topicWatch'
import {DisclosureWatch} from './disclosures'
import {Icon, State} from './ui'
import './style.css'

const views = {
  overview: {title: 'Executive Overview', description: 'Monitor the public UK retail cyber threat landscape.', icon: 'overview', group: 'Overview'},
  feed: {title: 'Intelligence Feed', description: 'Find security reporting and verify it against the original sources.', icon: 'feed', group: 'Explore'},
  disclosures: {title: 'Disclosure Watch', description: 'Read reviewed public notices and follow-up statements.', icon: 'feed', group: 'Explore'},
  radar: {title: 'Vulnerability Radar', description: 'Investigate public CVEs and compare documented evidence.', icon: 'radar', group: 'Explore'},
  retail: {title: 'Retail Intelligence', description: 'Explore reviewed incidents and guidance relevant to retail.', icon: 'retail', group: 'Sectors'},
  legal: {title: 'Legal Sector', description: 'Explore public cyber reporting about law firms and legal services.', icon: 'feed', group: 'Sectors'},
  finance: {title: 'Finance Sector', description: 'Explore public cyber reporting about banking, insurance and financial services.', icon: 'feed', group: 'Sectors'},
  healthcare: {title: 'Healthcare Sector', description: 'Explore public cyber reporting about healthcare providers and services.', icon: 'feed', group: 'Sectors'},
  ai: {title: 'AI Intelligence', description: 'Follow public reporting about AI security, misuse and defensive guidance.', icon: 'radar', group: 'Explore'},
  mitre: {title: 'MITRE ATT&CK', description: 'Explore techniques explicitly cited in public records.', icon: 'radar', group: 'Explore'},
  briefings: {title: 'Intelligence Briefings', description: 'Read published analysis with traceable evidence.', icon: 'feed', group: 'Overview'},
  stack: {title: 'My Stack', description: 'Match public evidence against technology preferences saved in this browser.', icon: 'retail', group: 'Workspace'},
  review: {title: 'Review Queue', description: 'Organise saved vulnerabilities, stories and retail records.', icon: 'bookmark', group: 'Workspace'},
  health: {title: 'Service Health & Exports', description: 'Check source coverage, validation and public data exports.', icon: 'clock', group: 'Workspace'},
  roundup: {title: 'Editorial Roundup', description: 'Reviewed public reporting and defensive lessons.', icon: 'feed', group: 'Overview'}
} as const
type View = keyof typeof views
const aliases: Record<string, string> = {
  executive: '/overview', kev: '/radar', 'live-intelligence': '/radar', 'start-here': '/radar',
  stories: '/feed', 'press-updates': '/feed?source=Press', 'official-updates': '/feed?source=Official',
  'cyber-watch': '/feed?source=Cyber+watch', 'weekly-roundup': '/roundup',
  retail: '/retail', 'retail-watch': '/retail', tabMitreContent: '/mitre', tabAutomationContent: '/health'
}

function route() {
  const fragment = location.hash.slice(1)
  const legacyStory = cyberWatch.find(story => story.id === fragment)
  const normalized = !fragment ? '/overview' : legacyStory ? '/feed/' + legacyStory.id :
    Object.hasOwn(aliases, fragment) ? aliases[fragment] : fragment
  const [raw, query] = normalized.split('?')
  const path = raw.match(/^\/([a-z]+)(?:\/([a-z0-9_-]{1,90}))?$/)
  const valid = Boolean(path && Object.hasOwn(views, path[1]))
  const params = new URLSearchParams(query)
  const band = params.get('severity')?.toUpperCase() || ''
  const technique = params.get('technique') || ''
  const source = params.get('source') || ''
  return {view: (valid ? path![1] : 'overview') as View, id: path?.[2], severity: bandOrder.includes(band) ? band : '',
    technique: /^T\d{4}(?:\.\d{3})?$/.test(technique) ? technique : '',
    source: feedSources.find(kind => kind === source) ?? 'All sources', valid}
}

function Navigation({view, onNavigate}: {view: View; onNavigate?: () => void}) {
  return <nav className="navigation" aria-label="Intelligence views">
    {(['Overview', 'Explore', 'Sectors', 'Workspace'] as const).map(group => <div key={group} className="nav-group">
      <p>{group}</p>{(Object.keys(views) as View[]).filter(key => key !== 'roundup' && views[key].group === group).map(key =>
        <a key={key} href={'#/' + key} aria-current={key === view ? 'page' : undefined} onClick={onNavigate}>
          <Icon name={views[key].icon}/><span>{key === 'retail' ? 'Retail Sector' : views[key].title}</span>
        </a>)}</div>)}
  </nav>
}

function Brand() {
  return <a className="brand" href="#/overview"><span className="brand-mark"><Icon name="shield" size={20}/></span>
    <span><strong>Cyber Threat Intelligence</strong></span></a>
}

function SearchDialog({dialog, snapshot}: {dialog: React.RefObject<HTMLDialogElement | null>; snapshot: Snapshot | null}) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const entries = [
    ...(snapshot?.threats || []).map(row => ({id: row.id, title: row.title, view: 'radar',
      keywords: row.classification?.vulnerabilities.map(cve => cve.id).join(' ') || ''})),
    ...(snapshot?.retail?.records || []).map(row => ({id: row.id, title: row.title, view: 'retail', keywords: row.organisation})),
    ...(snapshot?.stories || []).concat(cyberWatch).map(row => ({id: row.id, title: row.title, view: 'feed', keywords: row.source}))
  ]
  const results = needle.length >= 2 ? entries.filter(row => (row.title + ' ' + row.keywords).toLowerCase().includes(needle)).slice(0, 12) : []
  return <dialog ref={dialog} className="surface-dialog" aria-labelledby="global-search-title" onKeyDown={event => {
    if (event.key === 'Escape') {
      event.preventDefault()
      dialog.current?.close()
    }
  }}>
    <div className="dialog-heading"><h2 id="global-search-title">Search intelligence</h2>
      <button type="button" className="button" onClick={() => dialog.current?.close()}>Close</button></div>
    <label>Search titles, CVEs, organisations and publishers
      <input autoFocus type="search" placeholder="Search public intelligence" value={query} onChange={event => setQuery(event.target.value)}/></label>
    <p className="count" role="status">{needle.length < 2 ? 'Enter at least two characters.' : results.length + ' matching results shown'}</p>
    <ul className="search-results">{results.map(row => <li key={row.view + row.id}>
      <a href={recordHref(row.view, row.id)} onClick={() => dialog.current?.close()}><span>{views[row.view as View].title}</span>{row.title}</a>
    </li>)}</ul>
  </dialog>
}

function App() {
  const [current, setCurrent] = useState(route)
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [refreshVersion, setRefreshVersion] = useState(0)
  const {stack, update: updateStack} = useMyStack()
  const [collapsed, setCollapsed] = useState(false)
  const [theme, setTheme] = useState(() => {
    try { return (localStorage.getItem('cti_prototype_theme') ?? localStorage.getItem('theme')) === 'light' ? 'light' : 'dark' }
    catch { return 'dark' }
  })
  const main = useRef<HTMLElement>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const search = useRef<HTMLDialogElement>(null)
  const navigation = useRef<HTMLDialogElement>(null)
  const shouldFocus = useRef(false)

  useEffect(() => {
    let active = true
    let loading = false
    async function refresh() {
      if (loading) return
      loading = true
      try {
        const next = await loadSnapshot()
        if (active) setSnapshot(next)
      } finally {
        loading = false
      }
    }
    void refresh()
    const timer = hostedPreview ? window.setInterval(refresh, 60_000) : undefined
    return () => {active = false; window.clearInterval(timer)}
  }, [refreshVersion])
  useEffect(() => {
    const update = () => {
      setCurrent(previous => {
        const next = route()
        shouldFocus.current = previous.view !== next.view || previous.id !== next.id
        return next
      })
    }
    window.addEventListener('hashchange', update)
    return () => window.removeEventListener('hashchange', update)
  }, [])
  useEffect(() => {
    document.title = views[current.view].title + ' · Cyber Threat Intelligence'
    if (shouldFocus.current) {
      window.scrollTo(0, 0)
      heading.current?.focus({preventScroll: true})
    }
  }, [current])
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { localStorage.setItem('cti_prototype_theme', theme) } catch {}
  }, [theme])
  const view = views[current.view]
  return <div className={'app' + (collapsed ? ' is-collapsed' : '')}>
    <a className="skip-link" href="#main-content" onClick={event => {event.preventDefault(); main.current?.focus()}}>Skip to main content</a>
    <aside className="sidebar">
      <Brand/><Navigation view={current.view}/>
      <div className="sidebar-bottom"><span>Public-source intelligence</span>
        <button className="icon-button" type="button" aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed} onClick={() => setCollapsed(value => !value)}><Icon name="collapse"/></button></div>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <button className="mobile-menu icon-button" type="button" onClick={() => navigation.current?.showModal()} aria-label="Open navigation"><Icon name="menu"/></button>
        <div className="breadcrumbs"><span>{view.group}</span><span aria-hidden="true">/</span><strong>{view.title}</strong></div>
        <div className="top-actions">
          <button className="search-trigger" type="button" onClick={() => {
            search.current?.showModal()
            search.current?.querySelector('input')?.focus()
          }} aria-label="Search intelligence"><Icon name="search"/><span>Search intelligence</span></button>
          <div className="top-status"><State>{collectionState(snapshot)}</State></div>
          <button className="icon-button" type="button" aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
            onClick={() => setTheme(value => value === 'dark' ? 'light' : 'dark')}><Icon name="moon"/></button>
        </div>
      </header>
      <main id="main-content" tabIndex={-1} ref={main} className="page">
        <div className="page-heading"><div><h1 tabIndex={-1} ref={heading}>{view.title}</h1><p>{view.description}</p></div>
          {!hostedPreview && <span className="prototype-label">Local prototype</span>}</div>
        <Flash snapshot={snapshot}/>
        {!current.valid && <div className="notice">This route is unavailable in the prototype. Choose a view in the navigation.</div>}
        <div className="overview-surface" hidden={current.view !== 'overview'}><Executive snapshot={snapshot}/></div>
        {current.view === 'retail' && <><Retail snapshot={snapshot} selected={current.id}/><DisclosureWatch sector="retail"/></>}
        {current.view === 'disclosures' && <DisclosureWatch/>}
        {(current.view === 'legal' || current.view === 'finance' || current.view === 'healthcare' || current.view === 'ai') &&
          <TopicWatch key={current.view} topic={current.view} snapshot={snapshot}/>}
        {current.view === 'radar' && <Radar snapshot={snapshot} selected={current.id} initialSeverity={current.severity} technique={current.technique} stack={stack}/>}
        {current.view === 'feed' && <Feed snapshot={snapshot} selected={current.id} source={current.source}/>}
        {current.view === 'mitre' && <Mitre snapshot={snapshot}/>}
        {current.view === 'briefings' && <Briefings snapshot={snapshot} period={current.id === 'weekly' ? 'weekly' : 'daily'}/>}
        {current.view === 'roundup' && <Roundup/>}
        {current.view === 'stack' && <MyStack snapshot={snapshot} stack={stack} update={updateStack}/>}
        {current.view === 'review' && <ReviewQueueView snapshot={snapshot}/>}
        {current.view === 'health' && <Health snapshot={snapshot} refresh={() => setRefreshVersion(value => value + 1)}/>}
      </main>
    </div>
    <SearchDialog dialog={search} snapshot={snapshot}/>
    <dialog className="surface-dialog mobile-drawer" ref={navigation} aria-labelledby="mobile-nav-title">
      <div className="dialog-heading"><h2 id="mobile-nav-title">Navigate</h2>
        <button className="button" type="button" onClick={() => navigation.current?.close()}>Close</button></div>
      <Navigation view={current.view} onNavigate={() => navigation.current?.close()}/>
    </dialog>
  </div>
}

createRoot(document.getElementById('root')!).render(<ReviewQueueProvider><App/></ReviewQueueProvider>)
