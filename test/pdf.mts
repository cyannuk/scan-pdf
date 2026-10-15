// Generator of synthetic PDFs for tests (no real malware samples are used).
import { readFile } from 'node:fs/promises'
import { deflateSync } from 'node:zlib'

export type Part = string | Uint8Array

export function concat(parts: Part[]): Buffer {
  return Buffer.concat(parts.map((p) => (typeof p === 'string' ? Buffer.from(p, 'latin1') : p)))
}

export function pdf(...body: Part[]): Buffer {
  return concat(['%PDF-1.7\n', ...body, '\ntrailer << /Root 1 0 R >>\n%%EOF\n'])
}

export function stream(num: number, dict: string, data: Part): Buffer {
  const d = concat([data])
  return concat([`${num} 0 obj << ${dict} /Length ${d.length} >> stream\n`, d, '\nendstream endobj\n'])
}

/** Object stream (ObjStm) compressed with Flate */
export function objStm(num: number, objs: [number, string][], extraDict = ''): Buffer {
  let header = ''
  let body = ''
  for (const [n, o] of objs) {
    header += `${n} ${body.length} `
    body += o + ' '
  }
  const data = deflateSync(Buffer.from(header + body, 'latin1'))
  return stream(num, `/Type /ObjStm /N ${objs.length} /First ${header.length} /Filter /FlateDecode ${extraDict}`, data)
}

/** Encrypted fixture made by qpdf (scripts/make-fixtures.py) */
export function fixture(name: string): Promise<Buffer> {
  return readFile(new URL(`fixtures/${name}.pdf`, import.meta.url))
}

export const FIXTURES = ['r2', 'r3', 'r4-rc4-nometa', 'r4-aes-objstm', 'r5', 'r6', 'r6-objstm', 'r6-objstm-clean', 'r6-password']
