import assert from 'node:assert/strict'
import {createServer} from 'node:http'
import {readFile, mkdir, readdir} from 'node:fs/promises'
import {extname, join} from 'node:path'
import {gzipSync} from 'node:zlib'
import {chromium} from 'playwright'
import AxeBuilder from '@axe-core/playwright'

const base = '/uk-retail-threat-intel/'
const types = {'.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.woff2': 'font/woff2'}
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname
  const file = pathname.startsWith(base) ? pathname.slice(base.length) || 'index.html' : ''
  if (!/^(?:index\.html|site_status\.json|(?:assets|data|fonts)\/[A-Za-z0-9_.-]+)$/.test(file)) return response.writeHead(404).end()
  try {
    const body = await readFile(join('dist', file))
    response.writeHead(200, {'Content-Type': types[extname(file)] || 'text/plain'}).end(body)
  } catch {
    response.writeHead(404).end()
  }
})

await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const url = 'http://127.0.0.1:' + server.address().port + base
const assets = await readdir('dist/assets')
const javascript = await Promise.all(assets.filter(name => name.endsWith('.js')).map(name => readFile(join('dist/assets', name))))
console.log('Built JavaScript gzip size:', javascript.reduce((size, file) => size + gzipSync(file).length, 0), 'bytes')
const status = JSON.parse(await readFile('dist/data/intelligence_status.json'))
const asOf = status.collection?.data_updated_at ? new Date(Date.parse(status.collection.data_updated_at) + 60_000) : new Date()
const browser = await chromium.launch()
const errors = []
const requests = []
async function pageAt(width, height) {
  const context = await browser.newContext({viewport: {width, height}})
  const page = await context.newPage()
  page.setDefaultTimeout(5000)
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => requests.push(request.url()))
  await page.clock.setFixedTime(asOf)
  return page
}

async function audit(page, description) {
  const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze()
  assert.deepEqual(result.violations.map(entry => [entry.id, entry.nodes.map(node => node.target)]), [], description)
}

try {
  await mkdir('review', {recursive: true})
  for (const [width, height] of [[1920, 1080], [1440, 900], [1280, 800], [390, 844]]) {
    const page = await pageAt(width, height)
    for (const [view, title] of [['overview', 'Executive Overview'], ['retail', 'Retail Intelligence'],
      ['radar', 'Vulnerability Radar'], ['feed', 'Intelligence Feed'], ['review', 'Review Queue']]) {
      await page.goto(url + '?review=' + view + '#/' + view, {waitUntil: 'networkidle'})
      await page.getByRole('heading', {name: title, exact: true}).waitFor()
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, view + ' has page overflow')
      await page.evaluate(() => document.fonts.ready)
      if (width === 390 && view === 'feed' && await page.locator('.feed-row').count()) {
        await page.screenshot({path: 'review/feed-index-390x844.png', animations: 'disabled'})
        await page.locator('.feed-row').first().click()
        await page.getByRole('link', {name: 'Back to reports'}).waitFor()
      }
      await page.screenshot({path: 'review/' + view + '-' + width + 'x' + height + '.png', animations: 'disabled'})
      if (width === 1440) await audit(page, view + ' dark')
    }
    await page.close()
    console.log('Captured five views at', width + 'x' + height)
  }

  const desktop = await pageAt(1440, 900)
  await desktop.goto(url + '#kev', {waitUntil: 'networkidle'})
  await desktop.getByRole('heading', {name: 'Vulnerability Radar', exact: true}).waitFor()
  await desktop.evaluate(() => document.fonts.ready)
  assert.equal(await desktop.locator('.sidebar .brand strong').evaluate(title => {
    const text = document.createRange()
    text.selectNodeContents(title)
    const sidebar = title.closest('.sidebar').getBoundingClientRect()
    return [...text.getClientRects()].every(rect => rect.left >= sidebar.left && rect.right <= sidebar.right)
  }), true, 'The sidebar title should fit within the rail')
  const sort = desktop.getByRole('button', {name: /^Priority/})
  if (await sort.count()) {
    await sort.click()
    assert.equal(await sort.locator('..').getAttribute('aria-sort'), 'ascending')
    const first = desktop.locator('tbody a').first()
    const detail = await first.getAttribute('href')
    await first.click()
    await desktop.getByRole('link', {name: 'Open CISA catalogue entry'}).waitFor()
    await desktop.reload({waitUntil: 'networkidle'})
    await desktop.getByRole('link', {name: 'Open CISA catalogue entry'}).waitFor()
    assert.equal(new URL(desktop.url()).hash, detail)
    await audit(desktop, 'CVE evidence dark')
    await desktop.screenshot({path: 'review/cve-evidence-1440x900.png', animations: 'disabled'})
    await desktop.getByRole('button', {name: 'Save to review queue'}).click()
    await desktop.getByRole('combobox', {name: /Review status for/}).waitFor()
    await desktop.getByRole('link', {name: 'Close detail'}).click()
    await desktop.waitForURL(address => address.hash === '#/radar')
    await desktop.waitForFunction(() => document.activeElement?.tagName === 'H1')
    const severity = desktop.getByLabel('Severity', {exact: true})
    await severity.focus()
    await severity.selectOption('CRITICAL')
    await desktop.waitForURL(address => address.hash === '#/radar?severity=critical')
    assert.equal(await desktop.locator('tbody .severity').evaluateAll(nodes =>
      nodes.length > 0 && nodes.every(node => node.textContent === 'Critical')), true)
    assert.equal(await severity.evaluate(node => node === document.activeElement), true)
  }
  await desktop.getByRole('button', {name: 'Collapse sidebar'}).click()
  assert.equal(await desktop.getByRole('button', {name: 'Expand sidebar'}).getAttribute('aria-expanded'), 'false')
  const opener = desktop.getByRole('button', {name: 'Search intelligence'})
  const before = requests.length
  await opener.click()
  const dialog = desktop.getByRole('dialog')
  const field = dialog.getByRole('searchbox')
  assert.equal(await field.evaluate(node => node === document.activeElement), true)
  await field.fill('Cleverbridge')
  assert.ok(await dialog.getByRole('link', {name: /Cleverbridge/}).count() > 0)
  await desktop.keyboard.press('Escape')
  await dialog.waitFor({state: 'hidden'})
  assert.equal(await opener.evaluate(node => node === document.activeElement), true)
  assert.equal(requests.length, before)
  assert.equal(desktop.url().includes('Cleverbridge'), false)
  await desktop.getByRole('button', {name: 'Switch to light theme'}).click()
  await audit(desktop, 'radar light')
  for (const [route, title] of [['mitre', 'MITRE ATT&CK'], ['briefings', 'Intelligence Briefings'], ['stack', 'My Stack'],
    ['health', 'Service Health & Exports'], ['review', 'Review Queue']]) {
    await desktop.goto(url + '#/' + route)
    await desktop.getByRole('heading', {name: title, exact: true}).waitFor()
    assert.equal(await desktop.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await audit(desktop, route + ' light')
    await desktop.screenshot({path: 'review/' + route + '-1440x900.png', animations: 'disabled'})
  }
  await desktop.goto(url + '#/retail/retail-0003')
  await desktop.getByRole('heading', {name: 'Evidence timeline'}).waitFor()
  assert.match(await desktop.getByText('Initial access', {exact: true}).locator('..').innerText(), /Unknown/)
  await audit(desktop, 'retail details light')
  await desktop.close()

  const phone = await pageAt(320, 800)
  await phone.goto(url + '#/overview', {waitUntil: 'networkidle'})
  const nav = phone.getByRole('button', {name: 'Open navigation'})
  await nav.click()
  await phone.getByRole('dialog').getByRole('link', {name: 'Intelligence Feed'}).click()
  await phone.getByRole('heading', {name: 'Intelligence Feed', exact: true}).waitFor()
  assert.equal(await phone.getByRole('dialog').count(), 0)
  assert.equal(await phone.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
  await nav.click()
  await phone.getByRole('dialog').getByRole('link', {name: 'My Stack', exact: true}).click()
  await phone.getByRole('heading', {name: 'My Stack', exact: true}).waitFor()
  assert.equal(await phone.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
  await audit(phone, 'stack mobile dark')
  await phone.screenshot({path: 'review/stack-320x800.png', animations: 'disabled'})
  await phone.close()

  const unavailable = await pageAt(1440, 900)
  await unavailable.route(address => /\/data\/[^/]+\.json$/.test(address.pathname), route => route.fulfill({status: 404}))
  await unavailable.goto(url, {waitUntil: 'networkidle'})
  await unavailable.getByText('No verified snapshot available').waitFor()
  await unavailable.close()

  assert.deepEqual(errors, [])
  assert.ok(requests.every(request => request.startsWith(url)), 'Unexpected external browser request')
  console.log('Interaction, accessibility, failure state and same-origin checks passed.')
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
