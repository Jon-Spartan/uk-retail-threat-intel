import {object, safeUrl, severity, showDate} from './data'
import type {AffectedVersion, Threat, Vulnerability} from './data'
import {SaveForReview} from './reviewQueue'
import {External, Panel, State} from './ui'

const token = (value: unknown) => typeof value === 'string' && /^[a-z0-9][a-z0-9._+~:-]{0,63}$/i.test(value)

function versionLabel(range: AffectedVersion) {
  if (range.before) return range.from + ' up to but excluding ' + range.before
  if (range.through) return range.from + ' through ' + range.through + ' (inclusive)'
  return range.from
}

function CveMetrics({cve}: {cve: Vulnerability}) {
  const cvss = cve.cvss
  const epss = cve.epss
  const epDate = epss ? Date.parse(epss.date) : NaN
  const epAge = Date.now() - epDate
  const probability = epss && Number.isFinite(epss.probability) && epss.probability >= 0 && epss.probability <= 1 && Number.isFinite(epDate)
    ? new Intl.NumberFormat('en-GB', {style: 'percent', maximumFractionDigits: 2}).format(epss.probability) +
      ' · ' + showDate(epss.date) + (epAge > 8 * 86400000 ? ' · Older estimate' : '') : 'Unavailable'
  return <dl className="cve-signal-grid">
    <div><dt>CVSS base score</dt><dd>{cvss && Number.isFinite(cvss.score) && cvss.score >= 0 && cvss.score <= 10 &&
      ['3.0', '3.1', '4.0'].includes(cvss.version) ? cvss.score + ' / 10 · v' + cvss.version : 'Unavailable'}</dd></div>
    <div><dt>FIRST EPSS estimate</dt><dd>{probability}</dd></div>
    <div><dt>CISA KEV status</dt><dd>{cve.kev === true ? 'Listed · confirmed exploitation' :
      cve.kev === false ? 'No listing in this snapshot' : 'Catalogue status unavailable'}</dd></div>
  </dl>
}

export function CveEvidence({record, closeHref, collection, match, relevance, confidence}: {
  record: Threat; closeHref: string; collection: string; match: string; relevance: string; confidence: string
}) {
  const vulnerabilities = record.classification?.vulnerabilities
  const findings = Array.isArray(vulnerabilities) ? vulnerabilities.filter(cve =>
    object(cve) && typeof cve.id === 'string' && /^CVE-[0-9]{4}-[0-9]{4,}$/.test(cve.id)) : []
  const products = (Array.isArray(record.affected_products) ? record.affected_products : [])
    .filter(product => object(product) && (product.source === 'cve_list' || product.source === 'cisa_kev') &&
      typeof product.vendor === 'string' && typeof product.product === 'string')
  return <Panel title={record.title} detail="Public vulnerability and remediation evidence"
    trailing={<a href={closeHref} className="text-link">Close detail</a>}>
    <div className="cve-evidence">
      <div className="inline-links">
        <State>{collection}</State>
        {record.carried_forward && <span className="label">Carried forward</span>}
        <SaveForReview item={{kind: 'radar', id: record.id, title: record.title, url: record.url}}/>
      </div>
      <dl className="cve-signal-grid">
        <div><dt>Technical severity</dt><dd><span className="severity" data-tone={severity(record).toLowerCase()}>
          {severity(record)}</span></dd></div>
        <div><dt>Sector priority</dt><dd>{record.classification ? record.classification.score + ' / 100' : 'Unassessed'}</dd></div>
        <div><dt>Evidence confidence</dt><dd>{confidence}</dd></div>
        <div><dt>Retail relevance</dt><dd>{relevance}</dd></div>
      </dl>
      {match && <p className="notice">{match} · Check published applicability before acting.</p>}
      <section className="cve-section"><h3>Declared affected products</h3>
        {products.length ? <ul className="tool-list">{products.map((product, index) =>
          <li key={index}><strong>{product.vendor} · {product.product}</strong><span>{product.source === 'cisa_kev' ? 'CISA KEV' : 'Primary CVE record'}</span></li>)}</ul>
          : <p className="muted">Product evidence unavailable in this snapshot.</p>}
      </section>
      {!findings.length && <p className="muted">Per-CVE evidence unavailable in this snapshot.</p>}
      {findings.map(cve => {
        const ranges = (Array.isArray(cve.remediation?.affected_versions) ? cve.remediation.affected_versions : [])
          .filter(range => object(range) && typeof range.vendor === 'string' && typeof range.product === 'string' &&
            token(range.from) && (range.before === undefined || token(range.before)) &&
            (range.through === undefined || token(range.through)) && !(range.before && range.through))
        const advisories = (Array.isArray(cve.remediation?.vendor_advisories) ? cve.remediation.vendor_advisories : [])
          .map(safeUrl).filter((url): url is string => Boolean(url))
        return <section className="cve-section" key={cve.id}><h3>{cve.id}</h3>
          <CveMetrics cve={cve}/>
          <h4>Reported affected versions</h4>
          {ranges.length ? <ul className="tool-list">{ranges.map((range, index) => <li key={index}>
            <strong>{range.vendor} · {range.product}</strong><span>{versionLabel(range)}</span>
          </li>)}</ul> : <p className="muted">Version information unavailable in this snapshot.</p>}
          <div className="inline-links">
            {cve.evidence === 'cve_list' && <External url={'https://www.cve.org/CVERecord?id=' + encodeURIComponent(cve.id)}>Primary CVE record</External>}
            {advisories.map(url => <External key={url} url={url}>Vendor advisory · {new URL(url).hostname}</External>)}
          </div>
        </section>
      })}
      <section className="cve-section"><h3>Remediation guidance</h3>
        <p className="muted">Check affected versions, exceptions and available fixes in the original guidance.</p>
        <External url={record.url}>Open CISA catalogue entry</External>
        {findings.some(cve => cve.epss) && <p><External url="https://www.first.org/epss/">FIRST EPSS methodology</External></p>}
      </section>
    </div>
  </Panel>
}
