import {createContext, useContext, useEffect, useState} from 'react'
import type {ReactNode} from 'react'
import {object, recordHref, safeUrl, showDate} from './data'
import type {Snapshot} from './data'
import {cyberWatch} from './editorial'
import {Empty, External, Icon, Panel} from './ui'

const storageKey = 'cti_review_queue_v1'
const limit = 200
const kinds = ['radar', 'feed', 'retail'] as const
const statuses = ['To review', 'Reviewed', 'Watch for updates'] as const
type Kind = typeof kinds[number]
type ReviewStatus = typeof statuses[number]
type ReviewTarget = {kind: Kind; id: string; title: string; url: string}
type ReviewItem = ReviewTarget & {status: ReviewStatus; updatedAt: string}
const kindNames: Record<Kind, string> = {radar: 'Vulnerability', feed: 'Story', retail: 'Retail record'}
const identity = ({kind, id}: Pick<ReviewTarget, 'kind' | 'id'>) => kind + ':' + id
const eligibleId = (id: unknown) => typeof id === 'string' && /^[a-z0-9_-]{1,90}$/.test(id)

function readQueue(): ReviewItem[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(storageKey) || '[]')
    if (!Array.isArray(value)) return []
    const items = new Map<string, ReviewItem>()
    for (const entry of value.slice(0, limit)) {
      if (!object(entry) || !kinds.includes(entry.kind as Kind) || !eligibleId(entry.id) ||
          typeof entry.title !== 'string' || !entry.title.trim() || entry.title.length > 300 ||
          !safeUrl(entry.url) || !statuses.includes(entry.status as ReviewStatus) ||
          typeof entry.updatedAt !== 'string' || !Number.isFinite(Date.parse(entry.updatedAt))) continue
      const item = entry as ReviewItem
      items.set(identity(item), item)
    }
    return [...items.values()]
  } catch { return [] }
}

type ReviewQueue = {
  records: ReviewItem[]
  notice: string
  save: (target: ReviewTarget, status: ReviewStatus) => void
  remove: (target: ReviewTarget) => void
}
const QueueContext = createContext<ReviewQueue | null>(null)

export function ReviewQueueProvider({children}: {children: ReactNode}) {
  const [records, setRecords] = useState(readQueue)
  const [notice, setNotice] = useState('')
  useEffect(() => {
    const sync = (event: StorageEvent) => {if (event.key === storageKey || event.key === null) setRecords(readQueue())}
    window.addEventListener('storage', sync)
    return () => window.removeEventListener('storage', sync)
  }, [])
  function write(next: ReviewItem[], message: string) {
    setRecords(next)
    try {
      localStorage.setItem(storageKey, JSON.stringify(next))
      setNotice(message)
    } catch { setNotice('Browser storage is unavailable. Changes are held for this visit.') }
  }
  function save(target: ReviewTarget, status: ReviewStatus) {
    const url = safeUrl(target.url)
    if (!url || !eligibleId(target.id) || !target.title.trim()) return
    const others = records.filter(item => identity(item) !== identity(target))
    if (others.length >= limit) {
      setNotice('Review queue is full. Remove an item before saving another.')
      return
    }
    const title = target.title.slice(0, 300)
    write([{kind: target.kind, id: target.id, title, url, status, updatedAt: new Date().toISOString()}, ...others],
      status === 'To review' ? 'Saved to the review queue.' : 'Review status updated.')
  }
  function remove(target: ReviewTarget) {
    write(records.filter(item => identity(item) !== identity(target)), 'Removed from the review queue.')
  }
  return <QueueContext.Provider value={{records, notice, save, remove}}>
    {children}<p className="sr-only" role="status">{notice}</p>
  </QueueContext.Provider>
}

function useQueue() {
  const queue = useContext(QueueContext)
  if (!queue) throw Error('Review queue context missing.')
  return queue
}

function ReviewStatusSelect({item}: {item: ReviewItem}) {
  const {save} = useQueue()
  return <label>Review status<select aria-label={'Review status for ' + item.title}
    value={item.status} onChange={event => save(item, event.target.value as ReviewStatus)}>
    {statuses.map(status => <option key={status}>{status}</option>)}
  </select></label>
}

export function SaveForReview({item}: {item: ReviewTarget}) {
  const {records, save} = useQueue()
  const saved = records.find(record => identity(record) === identity(item))
  if (!eligibleId(item.id) || !safeUrl(item.url)) return null
  return <div className="review-control">
    {saved ? <ReviewStatusSelect item={saved}/> :
      <button className="button" type="button" onClick={() => save(item, 'To review')}>
        <Icon name="bookmark" size={16}/>Save to review queue
      </button>}
  </div>
}

export function ReviewQueueView({snapshot}: {snapshot: Snapshot | null}) {
  const {records, notice, remove} = useQueue()
  const [filter, setFilter] = useState('All statuses')
  const saved = records.filter(item => filter === 'All statuses' || item.status === filter)
  function inSnapshot(item: ReviewItem) {
    if (item.kind === 'radar') return snapshot?.threats?.some(row => row.id === item.id)
    if (item.kind === 'retail') return snapshot?.retail?.records.some(row => row.id === item.id)
    return (snapshot?.stories || []).concat(cyberWatch).some(row => row.id === item.id)
  }
  return <Panel title="Saved for review" detail="This queue stays in this browser. Watch for updates marks an item for follow-up.">
    <div className="filterbar">
      <label>Status filter<select aria-label="Status filter" value={filter} onChange={event => setFilter(event.target.value)}>
        {['All statuses', ...statuses].map(status => <option key={status}>{status}</option>)}
      </select></label>
    </div>
    {notice && <p className="count">{notice}</p>}
    {!saved.length ? <Empty title={records.length ? 'No records match this status' : 'Review queue is empty'}>
      Save a record from Vulnerability Radar, Intelligence Feed or Retail Intelligence.
    </Empty> : <ul className="review-queue-list">{saved.map(item => <li key={identity(item)}>
      <div className="review-entry">
        <p className="muted">{kindNames[item.kind]} · Updated {showDate(item.updatedAt)}</p>
        <h3>{inSnapshot(item) || !snapshot ? <a href={recordHref(item.kind, item.id)}>{item.title}</a> : item.title}</h3>
        {snapshot && !inSnapshot(item) && <p className="muted">Outside the available snapshot</p>}
        <External url={item.url}>Original source</External>
      </div>
      <div className="review-entry-actions"><ReviewStatusSelect item={item}/>
        <button className="button" type="button" aria-label={'Remove ' + item.title}
          onClick={() => remove(item)}>Remove</button></div>
    </li>)}</ul>}
  </Panel>
}
