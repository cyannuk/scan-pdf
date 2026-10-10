import { inflateSync, inflateRawSync } from 'node:zlib'

export type Severity = 'high' | 'medium' | 'low'

const RULES = new Map<string, Severity>([
  ['JavaScript', 'high'], ['JS', 'high'],                // JS code and JS actions
  ['Launch', 'high'],                                    // launching an external program
  ['EmbeddedFile', 'high'], ['EmbeddedFiles', 'high'],   // embedded files
  ['RichMedia', 'high'],                                 // Flash/multimedia
  ['XFA', 'medium'],                                     // XML forms
  ['AA', 'medium'],                                      // actions on page/field events
  ['SubmitForm', 'medium'], ['ImportData', 'medium'],
  ['GoToR', 'medium'], ['GoToE', 'medium'],              // jump to another document
  ['JBIG2Decode', 'low'], ['AcroForm', 'low'], ['URI', 'low']
])

// OpenAction (medium) is handled separately: [page /Fit] is a plain destination

type Finding = {
  name: string
  severity: Severity
  count: number
}

type Result = {
  suspicious: boolean
  encrypted: boolean
  findings: Finding[]
  error?: string
}

type Options = {
  maxStreamBytes?: number // decompression limit per stream
  maxTotalBytes?: number  // total decompression limit per file
  maxObjects?: number
}

class ScanError extends Error {
  constructor(message: string, cause?: Error) {
    super(message, { cause })
    this.name = 'ScanError'
  }
}

const WS = new Uint8Array(256)
const DELIM = new Uint8Array(256)
for (const c of [0, 9, 10, 12, 13, 32])
  WS[c] = 1
for (const c of '()<>[]{}/%')
  DELIM[c.charCodeAt(0)] = 1
const isRegular = (c: number) => !WS[c] && !DELIM[c]
const hexVal = (c: number): number => c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1

type Tok =
  | { k: 'name'; v: string }
  | { k: 'num'; v: number; int: boolean }
  | { k: 'kw'; v: string }
  | { k: 'str' | '<<' | '>>' | '[' | ']' | 'junk' }

class Lexer {
  public pos: number

  constructor(readonly b: Uint8Array) {
    this.pos = 0
  }

  next(): Tok | null {
    const b = this.b
    // whitespace and comments
    while (this.pos < b.length) {
      const c = b[this.pos]
      if (WS[c]) {
        this.pos++
      } else if (c === 0x25) {
        while (this.pos < b.length && b[this.pos] !== 10 && b[this.pos] !== 13)
          this.pos++
      } else {
        break
      }
    }
    if (this.pos >= b.length)
      return null
    const c = b[this.pos]
    switch (c) {
      case 0x2f:
        return { k: 'name', v: this.readName() }
      case 0x28:
        this.skipLiteralString()
        return { k: 'str' }
      case 0x5b:
        this.pos++
        return { k: '[' }
      case 0x5d:
        this.pos++
        return { k: ']' }
      case 0x3c:
        if (b[this.pos + 1] === 0x3c) {
          this.pos += 2
          return { k: '<<' }
        }
        const end = b.indexOf(0x3e, this.pos)
        this.pos = end < 0 ? b.length : end + 1
        return { k: 'str' }
      case 0x3e:
        if (b[this.pos + 1] === 0x3e) {
          this.pos += 2
          return { k: '>>' }
        }
        this.pos++
        return { k: 'junk' }
    }
    if (DELIM[c]) {
      this.pos++
      return { k: 'junk' }
    }
    const start = this.pos
    while (this.pos < b.length && isRegular(b[this.pos]))
      this.pos++
    if (this.pos - start > 64)
      return { k: 'junk' }
    const s = String.fromCharCode(...b.subarray(start, this.pos))
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(s))
      return { k: 'num', v: Number(s), int: /^[+-]?\d+$/.test(s) }
    return { k: 'kw', v: s }
  }

  private readName(): string {
    const b = this.b
    let s = ''
    this.pos++
    while (this.pos < b.length && isRegular(b[this.pos])) {
      let c = b[this.pos++]
      if (c === 0x23 && this.pos + 1 < b.length) {
        const h = hexVal(b[this.pos]), l = hexVal(b[this.pos + 1])
        if (h >= 0 && l >= 0) {
          c = h * 16 + l
          this.pos += 2
        }
      }
      if (s.length < 128)
        s += String.fromCharCode(c)
    }
    return s
  }

  private skipLiteralString(): void {
    const b = this.b
    let depth = 0
    while (this.pos < b.length) {
      const c = b[this.pos++]
      if (c === 0x5c)
        this.pos++
      else if (c === 0x28)
        depth++
      else if (c === 0x29 && --depth === 0)
        return
    }
  }
}

type Obj =
  | { t: 'name'; v: string }
  | { t: 'num'; v: number }
  | { t: 'ref'; n: number }
  | { t: 'arr'; v: Obj[] }
  | { t: 'dict'; v: Map<string, Obj> }
  | { t: 'other' }

const STRUCTURAL = new Set(['obj', 'endobj', 'stream', 'endstream', 'trailer', 'xref', 'startxref'])
const MAX_DEPTH = 64

function parseValue(lx: Lexer, tok: Tok, depth = 0): Obj | Tok {
  switch (tok.k) {
    case 'name':
      return { t: 'name', v: tok.v }
    case 'str':
      return { t: 'other' }
    case 'num': {
      if (tok.int) { // "N G R" → reference
        const save = lx.pos
        const t2 = lx.next()
        if (t2?.k === 'num' && t2.int) {
          const t3 = lx.next()
          if (t3?.k === 'kw' && t3.v === 'R') return { t: 'ref', n: tok.v }
        }
        lx.pos = save
      }
      return { t: 'num', v: tok.v }
    }
    case 'kw':
      return tok.v === 'true' || tok.v === 'false' || tok.v === 'null' ? { t: 'other' } : tok
    case '[':
    case '<<':
      if (depth >= MAX_DEPTH)
        throw new ScanError('Nesting of objects is too deep')
      const isDict = tok.k === '<<'
      const close = isDict ? '>>' : ']'
      const items: Obj[] = []
      const map = new Map<string, Obj>()
      let key: string | null = null
      while (true) {
        const save = lx.pos
        const t = lx.next()
        if (!t || t.k === close)
          break
        if (t.k === 'kw' && STRUCTURAL.has(t.v)) {
          lx.pos = save
          break
        }
        const v = parseValue(lx, t, depth + 1)
        if (!('t' in v))
          continue
        if (!isDict) {
          items.push(v)
        } else if (key === null) {
          if (v.t === 'name')
            key = v.v
        } else {
          map.set(key, v)
          key = null
        }
      }
      if (key !== null)
        map.set(key, { t: 'other' })
      return isDict ? { t: 'dict', v: map } : { t: 'arr', v: items }
    default:
      return tok
  }
}

function unpredict(data: Uint8Array, parms: Obj | undefined): Uint8Array | null {
  const d = parms?.t === 'dict' ? parms.v : undefined
  const num = (k: string, def: number) => {
    const v = d?.get(k)
    return v?.t === 'num' ? v.v : def
  }
  const pred = num('Predictor', 1)
  if (pred <= 1)
    return data
  if (pred < 10)
    return null
  const colors = num('Colors', 1), bpc = num('BitsPerComponent', 8), cols = num('Columns', 1)
  const bpp = Math.max(1, Math.ceil((colors * bpc) / 8))
  const rowLen = Math.ceil((colors * bpc * cols) / 8)
  if (!(rowLen > 0 && rowLen < 1e6))
    return null
  const rows = Math.floor(data.length / (rowLen + 1))
  const out = new Uint8Array(rows * rowLen)
  for (let r = 0; r < rows; r++) {
    const type = data[r * (rowLen + 1)], src = r * (rowLen + 1) + 1, dst = r * rowLen
    for (let i = 0; i < rowLen; i++) {
      const a = i >= bpp ? out[dst + i - bpp] : 0
      const up = r > 0 ? out[dst + i - rowLen] : 0
      const ul = r > 0 && i >= bpp ? out[dst + i - rowLen - bpp] : 0
      let v = data[src + i]
      switch (type) {
        case 0:
          break
        case 1:
          v += a
          break
        case 2:
          v += up
          break
        case 3:
          v += (a + up) >> 1
          break
        case 4:
          const p = a + up - ul, pa = Math.abs(p - a), pb = Math.abs(p - up), pc = Math.abs(p - ul)
          v += pa <= pb && pa <= pc ? a : pb <= pc ? up : ul
          break
        default:
          return null
      }
      out[dst + i] = v
    }
  }
  return out
}

function asciiHex(b: Uint8Array): Uint8Array {
  const out = new Uint8Array((b.length >> 1) + 1)
  let o = 0, hi = -1
  for (const c of b) {
    if (c === 0x3e)
      break
    const v = hexVal(c)
    if (v < 0)
      continue
    if (hi < 0) {
      hi = v
    } else {
      out[o++] = hi * 16 + v
      hi = -1
    }
  }
  if (hi >= 0)
    out[o++] = hi * 16
  return out.subarray(0, o)
}

function ascii85(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length * 4 + 4)
  let o = 0, n = 0, cnt = 0
  for (const c of b) {
    if (c === 0x7e)
      break
    if (c === 0x7a && cnt === 0) {
      o += 4
      continue
    }
    if (c < 0x21 || c > 0x75)
      continue
    n = n * 85 + (c - 33)
    if (++cnt === 5) {
      out[o++] = n >>> 24
      out[o++] = n >>> 16
      out[o++] = n >>> 8
      out[o++] = n
      n = 0
      cnt = 0
    }
  }
  if (cnt > 1) {
    for (let k = cnt; k < 5; k++)
      n = n * 85 + 84
    for (let k = 0; k < cnt - 1; k++)
      out[o++] = n >>> (24 - 8 * k)
  }
  return out.subarray(0, o)
}

const ENDSTREAM = [...'endstream'].map((c) => c.charCodeAt(0))
const matchAt = (b: Uint8Array, p: number, pat: number[]) => pat.every((c, i) => b[p + i] === c)

function findSeq(b: Uint8Array, pat: number[], from: number): number {
  for (let i = b.indexOf(pat[0], from); i >= 0; i = b.indexOf(pat[0], i + 1)) {
    if (matchAt(b, i, pat))
      return i
  }
  return -1
}

const tooLarge = (err: any) => err?.code === 'ERR_BUFFER_TOO_LARGE'

export function scanPdf(bytes: Uint8Array, opts: Options = {}): Result {
  const maxStream = opts.maxStreamBytes ?? 50 * 2 ** 20
  const maxTotal = opts.maxTotalBytes ?? 200 * 2 ** 20
  const maxObjects = opts.maxObjects ?? 500_000

  const found = new Map<string, Finding>()
  const add = (name: string, severity: Severity) => {
    const f = found.get(name)
    if (f)
      f.count++
    else
      found.set(name, { name, severity, count: 1 })
  }
  const objects = new Map<number, Obj>()
  const openActions: Obj[] = []
  let encrypted = false
  let inflated = 0

  const resolve = (o: Obj | undefined) => (o?.t === 'ref' ? objects.get(o.n) : o)
  const remember = (n: number, o: Obj) => {
    if (objects.size >= maxObjects)
      throw new ScanError('Too many object')
    objects.set(n, o)
  }

  const visit = (o: Obj): void => {
    if (o.t === 'name') {
      const sev = RULES.get(o.v)
      if (sev)
        add(o.v, sev)
    } else if (o.t === 'arr') {
      o.v.forEach(visit)
    } else if (o.t === 'dict') {
      for (const [k, v] of o.v) {
        if (k === 'OpenAction') {
          openActions.push(v)
        } else {
          const sev = RULES.get(k)
          if (sev)
            add(k, sev)
        }
        if (k === 'Encrypt')
          encrypted = true
        visit(v)
      }
    }
  }

  const inflate = (data: Uint8Array): Uint8Array => {
    const limit = Math.min(maxStream, maxTotal - inflated)
    if (limit <= 0)
      throw new ScanError('Exceed unpack limit')
    const options = { finishFlush: 2, maxOutputLength: limit }
    let out: Uint8Array
    try {
      out = inflateSync(data, options)
    } catch (err: any) {
      if (tooLarge(err))
        throw new ScanError('Exceed unpack limit')
      try {
        out = inflateRawSync(data, options)
      } catch (err: any) {
        if (tooLarge(err))
          throw new ScanError('Exceed unpack limit')
        throw err
      }
    }
    inflated += out.length
    return out
  }

  const decode = (data: Uint8Array, dict: Map<string, Obj>): Uint8Array | null => {
    const f = resolve(dict.get('Filter'))
    const filters = !f ? [] : f.t === 'name' ? [f] : f.t === 'arr' ? f.v : null
    const p = resolve(dict.get('DecodeParms'))
    if (!filters)
      return null
    try {
      for (let i = 0; i < filters.length; i++) {
        const fi = resolve(filters[i])
        const parms = resolve(p?.t === 'arr' ? p.v[i] : p)
        if (fi?.t !== 'name')
          return null
        if (fi.v === 'FlateDecode' || fi.v === 'Fl') {
          const r = unpredict(inflate(data), parms)
          if (!r)
            return null
          data = r
        } else if (fi.v === 'ASCIIHexDecode' || fi.v === 'AHx') {
          data = asciiHex(data)
        } else if (fi.v === 'ASCII85Decode' || fi.v === 'A85') {
          data = ascii85(data)
        } else {
          return null
        }
      }
      return data
    } catch (err: any) {
      if (err.name === 'ScanError')
        throw err
      return null
    }
  }

  const readStream = (lx: Lexer, dict: Map<string, Obj>): Uint8Array => {
    const b = lx.b
    let p = lx.pos
    if (b[p] === 13)
      p++
    if (b[p] === 10)
      p++
    const len = resolve(dict.get('Length'))
    if (len?.t === 'num' && len.v >= 0 && p + len.v <= b.length) {
      let q = p + len.v
      while (q < b.length && WS[b[q]])
        q++
      if (matchAt(b, q, ENDSTREAM)) {
        lx.pos = q + ENDSTREAM.length
        return b.subarray(p, p + len.v)
      }
    }
    const q = findSeq(b, ENDSTREAM, p)
    if (q < 0) {
      lx.pos = b.length
      return b.subarray(p)
    }
    let end = q
    if (end > p && b[end - 1] === 10)
      end--
    if (end > p && b[end - 1] === 13)
      end--
    lx.pos = q + ENDSTREAM.length
    return b.subarray(p, end)
  }

  const scanObjStm = (data: Uint8Array, dict: Map<string, Obj>) => {
    const lx = new Lexer(data)
    const n = resolve(dict.get('N')), first = resolve(dict.get('First'))
    if (n?.t === 'num' && first?.t === 'num' && first.v <= data.length) {
      const pairs: number[] = []
      while (pairs.length < n.v * 2 && lx.pos < first.v) {
        const t = lx.next()
        if (t?.k !== 'num')
          break
        pairs.push(t.v)
      }
      for (let i = 0; i + 1 < pairs.length; i += 2) {
        lx.pos = first.v + pairs[i + 1]
        const t = lx.next()
        const v = t && parseValue(lx, t)
        if (v && 't' in v)
          remember(pairs[i], v)
      }
    }
    lx.pos = 0
    for (let t = lx.next(); t; t = lx.next()) {
      const v = parseValue(lx, t)
      if ('t' in v)
        visit(v)
    }
  }

  const handleStream = (dict: Map<string, Obj>, data: Uint8Array) => {
    const type = resolve(dict.get('Type'))
    const isObjStm = (type?.t === 'name' && type.v === 'ObjStm') || (dict.has('N') && dict.has('First'))
    if (!isObjStm) // images, fonts, content: skip
      return
    const dec = decode(data, dict)
    if (dec)
      scanObjStm(dec, dict)
    else
      add('UndecodableObjStm', 'high')
  }

  try {
    const lx = new Lexer(bytes)
    let prevNum: number | null = null, lastNum: number | null = null
    let lastDict: Map<string, Obj> | null = null

    for (let t = lx.next(); t; t = lx.next()) {
      if (t.k === 'num') {
        prevNum = lastNum
        lastNum = t.v
        continue
      }

      if (t.k === 'kw' && t.v === 'obj') {
        const objNum = prevNum
        prevNum = lastNum = null
        lastDict = null
        const save = lx.pos
        const vt = lx.next()
        const v = vt && parseValue(lx, vt)
        if (v && 't' in v) {
          if (objNum !== null)
            remember(objNum, v)
          visit(v)
          if (v.t === 'dict')
            lastDict = v.v
        } else {
          lx.pos = save
        }
        continue
      }

      if (t.k === 'kw' && t.v === 'stream') {
        const data = readStream(lx, lastDict ?? new Map())
        if (lastDict)
          handleStream(lastDict, data)
        lastDict = null
        continue
      }

      prevNum = lastNum = null
      const v = parseValue(lx, t)
      if ('t' in v) {
        visit(v)
        lastDict = v.t === 'dict' ? v.v : null
      }
    }

    for (const oa of openActions) {
      if (resolve(oa)?.t !== 'arr')
        add('OpenAction', 'medium')
    }
  } catch (err: any) {
    return { suspicious: true, encrypted, findings: [...found.values()], error: err.message }
  }

  const findings = [...found.values()]
  return {
    suspicious: encrypted || findings.some((f) => f.severity === 'high'),
    encrypted,
    findings
  }
}
