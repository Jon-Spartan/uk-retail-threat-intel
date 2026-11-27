import {copyFile, mkdir, rm} from 'node:fs/promises'
import {dirname, join, resolve} from 'node:path'
import {fileURLToPath} from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
if (!process.argv[2]) throw Error('Pass a site directory created by scripts.publication stage-site.')
const staged = resolve(process.argv[2])
const files = [
  ['site_status.json', 'site_status.json', true],
  ['data/threats.json', 'data/threats.json'],
  ['data/intelligence_status.json', 'data/intelligence_status.json'],
  ['data/press_updates.json', 'data/press_updates.json', true],
  ['data/official_updates.json', 'data/official_updates.json', true],
  ['data/intelligence_history.json', 'data/intelligence_history.json', true],
  ['data/flash_alert.json', 'data/flash_alert.json', true],
  ['data/daily_briefing.json', 'data/daily_briefing.json', true],
  ['data/daily_summary.md', 'data/daily_summary.md', true],
  ['data/weekly_briefing.json', 'data/weekly_briefing.json', true],
  ['data/weekly_summary.md', 'data/weekly_summary.md', true],
  ['assets/retail-intelligence.json', 'assets/retail-intelligence.json'],
  ['fonts/inter.woff2', 'fonts/inter.woff2'], ['fonts/inter-OFL.txt', 'fonts/inter-OFL.txt'],
  ['fonts/jetbrains-mono.woff2', 'fonts/jetbrains-mono.woff2'], ['fonts/jetbrains-mono-OFL.txt', 'fonts/jetbrains-mono-OFL.txt']
]
for (const [source, name, optional] of files) {
  const output = join(root, 'public', name)
  await mkdir(dirname(output), {recursive: true})
  try {
    await copyFile(join(staged, source), output)
  } catch (error) {
    if (!optional || error.code !== 'ENOENT') throw error
    await rm(output, {force: true})
  }
}
