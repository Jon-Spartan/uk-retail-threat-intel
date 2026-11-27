import {useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {bandOrder, collectionState, hostedPreview, loadSnapshot} from './data'
import type {Snapshot} from './data'
import {Executive, Feed, Radar, Retail, recordHref} from './views'
import {Icon, State} from './ui'
import './style.css'

const views = {
  overview: {title: 'Executive Overview', description: 'Monitor the public UK retail cyber threat landscape.', icon: 'overview', group: 'Overview'},
  feed: {title: 'Intelligence Feed', description: 'Find security reporting and verify it against the original sources.', icon: 'feed', group: 'Explore'},
  radar: {title: 'Vulnerability Radar', description: 'Investigate public CVEs and compare documented evidence.', icon: 'radar', group: 'Explore'},
  retail: {title: 'Retail Intelligence', description: 'Explore reviewed incidents and guidance relevant to retail.', icon: 'retail', group: 'Retail sector'}
} as const
type View = keyof typeof views
const aliases: Record<string, View> = {
  executive: 'overview', kev: 'radar', 'live-intelligence': 'radar', 'start-here': 'radar',
  stories: 'feed', 'press-updates': 'feed', 'official-updates': 'feed', 'cyber-watch': 'feed', 'weekly-roundup': 'feed',
  retail: 'retail', 'retail-watch': 'retail'
}
const classicAnchors = new Set(['tabMitreContent', 'tabAutomationContent', 'start-here', 'live-intelligence',
  'press-updates', 'official-updates', 'retail-watch', 'cyber-watch', 'weekly-roundup'])

function route() {
  const fragment = location.hash.slice(1)
  if (Object.hasOwn(aliases, fragment)) return {view: aliases[fragment], severity: '', valid: true}
  if (!fragment) return {view: 'overview' as View, severity: '', valid: true}
  const [raw, query] = fragment.split('?')
  const path = raw.match(/^\/(overview|feed|radar|retail)(?:\/([a-z0-9_-]{1,90}))?$/)
  const band = new URLSearchParams(query).get('severity')?.toUpperCase() || ''
  return {view: (path?.[1] || 'overview') as View, id: path?.[2], severity: bandOrder.includes(band) ? band : '', valid: Boolean(path)}
}

function Navigation({view, onNavigate}: {view: View; onNavigate?: () => void}) {
  return <nav className="navigation" aria-label="Intelligence views">
    {(['Overview', 'Explore', 'Retail sector'] as const).map(group => <div key={group} className="nav-group">
      <p>{group}</p>{(Object.keys(views) as View[]).filter(key => views[key].group === group).map(key =>
        <a key={key} href={'#/' + key} aria-current={key === view ? 'page' : undefined} onClick={onNavigate}>
          <Icon name={views[key].icon}/><span>{views[key].title}</span>
        </a>)}</div>)}
  </nav>
}

function Brand() {
  return <a className="brand" href="#/overview"><span className="brand-mark"><Icon name="shield" size={20}/></span>
    <span><strong>UK Retail CTI</strong><small>Threat intelligence</small></span></a>
}

function SearchDialog({dialog, snapshot}: {dialog: React.RefObject<HTMLDialogElement | null>; snapshot: Snapshot | null}) {
  const [query, setQuery] = useState('')
  const needle = query.trim().toLowerCase()
  const entries = [
    ...(snapshot?.threats || []).map(row => ({id: row.id, title: row.title, view: 'radar',
      keywords: row.classification?.vulnerabilities.map(cve => cve.id).join(' ') || ''})),
    ...(snapshot?.retail?.records || []).map(row => ({id: row.id, title: row.title, view: 'retail', keywords: row.organisation})),
    ...(snapshot?.stories || []).map(row => ({id: row.id, title: row.title, view: 'feed', keywords: row.source}))
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
  const [collapsed, setCollapsed] = useState(false)
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('cti_prototype_theme') === 'light' ? 'light' : 'dark' }
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
    const update = () => {
      if (hostedPreview && classicAnchors.has(location.hash.slice(1))) {
        location.replace('./classic.html' + location.hash)
        return
      }
      setCurrent(previous => {
        const next = route()
        shouldFocus.current = previous.view !== next.view || previous.id !== next.id
        return next
      })
    }
    if (hostedPreview && classicAnchors.has(location.hash.slice(1))) update()
    window.addEventListener('hashchange', update)
    return () => {
      active = false
      window.clearInterval(timer)
      window.removeEventListener('hashchange', update)
    }
  }, [])
  useEffect(() => {
    document.title = views[current.view].title + ' · UK Retail CTI'
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
          {hostedPreview ? <a className="text-link" href="./classic.html">More tools <Icon name="arrow" size={15}/></a> :
            <span className="prototype-label">Local prototype</span>}</div>
        {hostedPreview && <p className="notice">Find alerts, briefings, exports and My Stack under More tools.</p>}
        {!current.valid && <div className="notice">This route is unavailable in the prototype. Choose a view in the navigation.</div>}
        {current.view === 'overview' && <Executive snapshot={snapshot}/>}
        {current.view === 'retail' && <Retail snapshot={snapshot} selected={current.id}/>}
        {current.view === 'radar' && <Radar snapshot={snapshot} selected={current.id} initialSeverity={current.severity}/>}
        {current.view === 'feed' && <Feed snapshot={snapshot} selected={current.id}/>}
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

createRoot(document.getElementById('root')!).render(<App/>)
