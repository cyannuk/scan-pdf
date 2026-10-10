import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { deflateSync } from 'node:zlib'

import { scanPdf, type ScanResult } from '../index.js'
import { objStm, pdf, stream } from './pdf.mts'

const names = (r: ScanResult) => Object.fromEntries(r.findings.map((f) => [f.name, f.count]))

describe('scanPdf', () => {
  it('clean document', async () => {
    const r = await scanPdf(pdf('1 0 obj << /Type /Catalog /OpenAction [3 0 R /Fit] >> endobj'))
    assert.deepEqual(r, { suspicious: false, encrypted: false, findings: [] })
    assert.ok(!('error' in r))
  })

  it('javascript open action', async () => {
    const r = await scanPdf(pdf('1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >> endobj'))
    assert.equal(r.suspicious, true)
    assert.deepEqual(r.findings, [
      { name: 'JavaScript', severity: 'high', count: 1 },
      { name: 'JS', severity: 'high', count: 1 },
      { name: 'OpenAction', severity: 'medium', count: 1 }
    ])
  })

  it('findings hidden in object stream, obfuscated names, suspicious JS', async () => {
    const r = await scanPdf(pdf(
      '1 0 obj << /OpenAction 5 0 R >> endobj\n',
      objStm(4, [[5, '<< /S /J#61vaScript /JS 6 0 R >>'], [6, '(this.exportDataObject\\({nLaunch: 2}\\))']])
    ))
    assert.deepEqual(names(r), { JavaScript: 1, ObfuscatedName: 1, JS: 1, SuspiciousJS: 1, OpenAction: 1 })
  })

  it('accepts Buffer, Uint8Array and subarray views', async () => {
    const doc = pdf('1 0 obj << /S /Launch >> endobj')
    const padded = new Uint8Array(doc.length + 20)
    padded.set(doc, 10)
    for (const input of [doc, new Uint8Array(doc), padded.subarray(10, 10 + doc.length)])
      assert.deepEqual(names(await scanPdf(input)), { Launch: 1 })
  })

  it('reads the input in place and leaves it unchanged', async () => {
    const doc = pdf('1 0 obj << /S /Launch >> endobj')
    const before = Buffer.from(doc)
    const results = await Promise.all(Array.from({ length: 8 }, () => scanPdf(doc)))
    for (const r of results)
      assert.deepEqual(names(r), { Launch: 1 })
    assert.deepEqual(doc, before)
  })

  it('keeps the buffer alive while scanning even if the caller drops it', async () => {
    const pending = Array.from({ length: 8 }, () => scanPdf(pdf('1 0 obj << /S /Launch >> endobj')))
    globalThis.gc?.()
    for (const r of await Promise.all(pending))
      assert.deepEqual(names(r), { Launch: 1 })
  })

  it('encrypted', async () => {
    const r = await scanPdf(pdf('trailer << /Encrypt 5 0 R >>'))
    assert.equal(r.encrypted, true)
    assert.equal(r.suspicious, true)
  })

  it('limits: decompression bomb and object count', async () => {
    const bomb = deflateSync(Buffer.alloc(64 << 20))
    const doc = pdf(stream(4, '/Type /ObjStm /N 1 /First 0 /Filter /FlateDecode', bomb))
    const r = await scanPdf(doc, { maxStreamBytes: 1 << 20 })
    assert.equal(r.error, 'Unpack limit exceeded')
    assert.equal(r.suspicious, true)
    assert.equal((await scanPdf(doc, { maxTotalBytes: 1000 })).error, 'Unpack limit exceeded')

    const many = pdf(...Array.from({ length: 20 }, (_, i) => `${i + 1} 0 obj << >> endobj\n`))
    assert.equal((await scanPdf(many, { maxObjects: 10 })).error, 'Too many objects')
    assert.equal((await scanPdf(many, { maxObjects: 100 })).error, undefined)
  })

  it('garbage input does not throw', async () => {
    const r = await scanPdf(Buffer.from('definitely not a pdf'))
    assert.deepEqual(names(r), { NoHeader: 1 })
    assert.deepEqual(names(await scanPdf(new Uint8Array(0))), { NoHeader: 1 })
  })

  it('rejects (does not throw synchronously) on invalid arguments', async () => {
    const bad: [unknown, unknown][] = [
      ['string', undefined],
      [null, undefined],
      [Buffer.from('%PDF'), { maxObjects: -1 }],
      [Buffer.from('%PDF'), { maxStreamBytes: 1.5 }],
      [Buffer.from('%PDF'), { maxTotalBytes: Number.NaN }],
      [Buffer.from('%PDF'), { maxTotalBytes: '10' }]
    ]
    for (const [bytes, opts] of bad) {
      const p = (scanPdf as (...a: unknown[]) => Promise<ScanResult>)(bytes, opts)
      assert.ok(p instanceof Promise)
      await assert.rejects(p, `${String(bytes)} ${JSON.stringify(opts)}`)
    }
  })

  it('runs off the main thread and in parallel', async () => {
    // ~40 MB: many objects so that the scan takes noticeable time
    const obj = '1 0 obj << /Type /Page /Annots [<< /S /URI /URI (https://example.com) >>] >> endobj\n'
    const big = pdf(obj.repeat((40 << 20) / obj.length))
    let ticks = 0
    const timer = setInterval(() => ticks++, 1)
    const t0 = performance.now()
    const results = await Promise.all(Array.from({ length: 4 }, () => scanPdf(big)))
    clearInterval(timer)
    const elapsed = performance.now() - t0
    for (const r of results)
      assert.equal(r.findings.find((f) => f.name === 'URI')?.severity, 'low')
    // the event loop kept running during the scan
    assert.ok(ticks > elapsed / 20, `ticks=${ticks}, elapsed=${elapsed.toFixed(0)}ms`)
  })
})
