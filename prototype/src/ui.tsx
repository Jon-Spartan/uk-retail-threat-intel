import type {ReactNode} from 'react'
import {safeUrl} from './data'

const icons: Record<string, string> = {
  shield: 'M12 22s7-4 7-11V5l-7-3-7 3v6c0 7 7 11 7 11Z M9 12l2 2 4-4',
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  feed: 'M6 3h12v18H6z M9 8h6 M9 12h6 M9 16h4',
  radar: 'M12 22a10 10 0 1 1 10-10 M8 18a7 7 0 0 1 10-10 M12 16a4 4 0 0 1 4-4 M12 12l9-9',
  retail: 'M4 9h16v12H4z M3 9l2-6h14l2 6 M9 21v-7h6v7',
  search: 'M16 16l5 5 M18 11a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z',
  menu: 'M4 6h16 M4 12h16 M4 18h16',
  collapse: 'M4 4h16v16H4z M9 4v16 M16 9l-3 3 3 3',
  moon: 'M21 13a9 9 0 1 1-10-10 7 7 0 0 0 10 10Z',
  external: 'M13 4h7v7 M20 4l-9 9 M19 13v7H4V5h7',
  arrow: 'M5 12h14 M13 6l6 6-6 6',
  dot: 'M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8Z',
  clock: 'M12 22a10 10 0 1 1 0-20 10 10 0 0 1 0 20Z M12 7v6l4 2',
}

export function Icon({name, size = 18}: {name: string; size?: number}) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
    strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d={icons[name] || icons.dot}/></svg>
}

export function Panel({title, detail, children, trailing}: {title: string; detail?: string; children: ReactNode; trailing?: ReactNode}) {
  return <section className="panel"><div className="panel-title"><div><h2>{title}</h2>{detail && <p>{detail}</p>}</div>{trailing}</div>{children}</section>
}

export function State({children}: {children: string}) {
  return <span className="state" data-state={children}><span aria-hidden="true" />{children}</span>
}

export function Empty({title, children}: {title: string; children?: ReactNode}) {
  return <div className="empty"><strong>{title}</strong>{children && <p>{children}</p>}</div>
}

export function External({url, children}: {url: unknown; children: ReactNode}) {
  const href = safeUrl(url)
  return href ? <a className="external" href={href} target="_blank" rel="noopener noreferrer">{children}<Icon name="external" size={14}/></a>
    : <span className="muted">Source unavailable</span>
}

export function Bars({rows, total}: {rows: {label: string; count: number; tone?: string}[]; total: number}) {
  return <ul className="bars">{rows.map(row => <li key={row.label}>
    <span>{row.label}</span><strong>{row.count}</strong><progress aria-hidden="true" data-tone={row.tone} value={row.count} max={Math.max(1, total)}/>
  </li>)}</ul>
}

export function Metric({label, value, detail, icon, tone}: {label: string; value: number | string; detail: string; icon: string; tone?: string}) {
  return <div className="metric" data-tone={tone}><dt><span className="metric-icon"><Icon name={icon}/></span>{label}</dt>
    <dd className={typeof value === 'number' ? 'metric-value mono' : 'metric-value word'}>{value}</dd><dd className="metric-detail muted">{detail}</dd></div>
}
