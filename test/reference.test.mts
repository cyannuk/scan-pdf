// Differential test: the native implementation finds everything the reference/pdf-scanner.ts finds.
import assert from 'node:assert/strict'
import { it } from 'node:test'
import { deflateSync } from 'node:zlib'

import { scanPdf } from '../index.js'
import { scanPdf as referenceScan } from '../reference/pdf-scanner.ts'
import { concat, objStm, pdf, stream } from './pdf.mts'

// reference: 'Exceed unpack limit', native: 'Unpack limit exceeded'
const ERRORS: Record<string, string> = {
  'Exceed unpack limit': 'Unpack limit exceeded',
  'Too many object': 'Too many objects',
  'Nesting of objects is too deep': 'Nesting of objects is too deep'
}

const CORPUS: Buffer[] = [
  pdf('1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj'),
  pdf('1 0 obj << /OpenAction [3 0 R /Fit] /AcroForm << /Fields [] /XFA 7 0 R >> >> endobj'),
  pdf('1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> /AA << /O 4 0 R >> >> endobj'),
  pdf('1 0 obj << /Names << /EmbeddedFiles << /Names [(a.exe) 2 0 R] >> /JavaScript 3 0 R >> >> endobj\n',
    '2 0 obj << /Type /Filespec /EF << /F 5 0 R >> >> endobj\n',
    stream(5, '/Type /EmbeddedFile /Filter /FlateDecode', deflateSync('MZ payload'))),
  pdf('1 0 obj << /S /Launch /Win << /F (cmd.exe) >> >> endobj 2 0 obj << /S /GoToR /F (x.pdf) >> endobj'),
  pdf('1 0 obj << /S /SubmitForm /F << /FS /URL /F (http://x) >> >> endobj << /S /ImportData >> << /S /GoToE >>'),
  pdf('1 0 obj << /Subtype /RichMedia /Filter /JBIG2Decode >> endobj 2 0 obj << /S /URI /URI (http://a) >> endobj'),
  pdf('1 0 obj << /OpenAction 5 0 R >> endobj\n', objStm(4, [[5, '<< /S /JavaScript /JS (x) >>'], [6, '[1 0 R /Fit]']])),
  pdf('1 0 obj << /OpenAction 6 0 R >> endobj\n', objStm(4, [[5, '<< /S /JavaScript /JS (x) >>'], [6, '[1 0 R /Fit]']])),
  pdf(objStm(4, [[5, '<< /S /Launch >>']], '/DecodeParms << /Predictor 1 >>')),
  pdf(stream(4, '/Type /ObjStm /N 1 /First 4 /Filter /DCTDecode', '5 0 << /JS (x) >>')),
  pdf(stream(4, '/Type /ObjStm /N 1 /First 4 /Filter [/AHx]', Buffer.from('5 0 << /JS (x) >>').toString('hex') + '>')),
  pdf('trailer << /Encrypt 9 0 R >>'),
  pdf('1 0 obj ' + '[ '.repeat(100) + ' endobj'),
  pdf(stream(4, '/Type /ObjStm /N 1 /First 0 /Filter /FlateDecode', deflateSync(Buffer.alloc(300 << 20)))),
  Buffer.from('garbage only')
]

function mulberry32(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const TOKENS = ['<<', '>>', '[', ']', '(', ')', '/', '#4A', ' obj ', ' R ', 'endstream', '/JS ', '/AA ', '%']

function mutate(src: Buffer, rnd: () => number): Buffer {
  let d: Buffer = Buffer.from(src)
  const n = 1 + Math.floor(rnd() * 6)
  for (let i = 0; i < n; i++) {
    const pos = Math.floor(rnd() * (d.length + 1))
    const op = Math.floor(rnd() * 3)
    if (op === 0 && pos < d.length)
      d[pos] = Math.floor(rnd() * 256)
    else if (op === 1)
      d = concat([d.subarray(0, pos), TOKENS[Math.floor(rnd() * TOKENS.length)], d.subarray(pos)])
    else
      d = concat([d.subarray(0, pos), d.subarray(pos + Math.floor(rnd() * 8))])
  }
  return d
}

async function compare(doc: Buffer, exact: boolean) {
  const ref = referenceScan(doc)
  const nat = await scanPdf(doc)
  const ctx = () => JSON.stringify({ ref, nat, doc: doc.length < 2000 ? doc.toString('latin1') : `${doc.length} bytes` })
  if (ref.error) {
    assert.equal(nat.error, ERRORS[ref.error] ?? ref.error, ctx())
    return
  }
  assert.ok(!ref.suspicious || nat.suspicious, ctx())
  assert.equal(nat.encrypted, ref.encrypted, ctx())
  // native decodes more filters (LZW, RunLength, damaged Flate), so findings inside streams
  // that are undecodable for the reference may be added
  const lenient = ref.findings.some((f) => f.name === 'UndecodableObjStm')
  for (const f of ref.findings) {
    // OpenAction depends on whether the reference to an object inside the ObjStm could be resolved
    if (lenient && f.name === 'OpenAction')
      continue
    // native partially decodes a damaged stream and flags it as DamagedObjStm
    const alias = f.name === 'UndecodableObjStm' ? ['UndecodableObjStm', 'DamagedObjStm'] : [f.name]
    const n = nat.findings.find((x) => alias.includes(x.name))
    assert.ok(n, `missing ${f.name}: ${ctx()}`)
    assert.equal(n.severity, f.severity, ctx())
    if (exact && !lenient)
      assert.equal(n.count, f.count, ctx())
    else
      assert.ok(n.count >= f.count, ctx())
  }
}

it('matches reference on the corpus', async () => {
  for (const doc of CORPUS)
    await compare(doc, true)
})

it('finds at least what the reference finds on mutated inputs', async () => {
  const rnd = mulberry32(42)
  const seeds = CORPUS.filter((d) => d.length < 1 << 20)
  for (let i = 0; i < 3000; i++)
    await compare(mutate(seeds[i % seeds.length], rnd), false)
})
