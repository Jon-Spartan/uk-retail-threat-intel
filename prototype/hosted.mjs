import assert from 'node:assert/strict'
import {copyFile, mkdir, readFile, readdir} from 'node:fs/promises'
import {dirname, join} from 'node:path'

const mode = process.argv[2]
if (!['copy', 'verify'].includes(mode)) throw Error('Use copy or verify after the hosted build.')
const compiled = (await readdir('dist/assets')).filter(name => /^index-[A-Za-z0-9_-]+\.(css|js)$/.test(name))
assert.equal(compiled.filter(name => name.endsWith('.css')).length, 1)
assert.equal(compiled.filter(name => name.endsWith('.js')).length, 1)
const files = [
  ['dist/index.html', 'index.html'],
  ...compiled.map(name => ['dist/assets/' + name, 'assets/' + name]),
  ['node_modules/react/LICENSE', 'licenses/react.txt'],
  ['node_modules/react-dom/LICENSE', 'licenses/react-dom.txt'],
  ['node_modules/.pnpm/node_modules/scheduler/LICENSE', 'licenses/scheduler.txt'],
]
for (const [input, path] of files) {
  const output = join('..', 'redesign', path)
  if (mode === 'copy') {
    await mkdir(dirname(output), {recursive: true})
    await copyFile(input, output)
  } else {
    assert.ok((await readFile(input)).equals(await readFile(output)), path + ' differs from the locked hosted build')
  }
}
