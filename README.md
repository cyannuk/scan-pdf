# scan-pdf

Native Node.js addon (Rust + N-API) for heuristic detection of potentially malicious content in PDF files: JavaScript, program launch actions, embedded files, automatic actions, constructs hidden in object streams, and more.

- Platforms: Linux x64 (glibc ≥ 2.36, Debian 12+), Windows x64.
- Node.js ≥ 22. Prebuilt binaries are included in the package; no compiler is needed at install time.
- Scanning runs on the libuv thread pool and does not block the event loop.

## Usage

```ts
import { readFile } from 'node:fs/promises'
import { scanPdf } from 'scan-pdf'

const result = await scanPdf(await readFile('file.pdf'), { maxStreamBytes: 20 << 20 })
if (result.suspicious)
  console.log(result.findings) // [{ name: 'JavaScript', severity: 'high', count: 1 }, …]
```

```ts
scanPdf(bytes: Uint8Array, opts?: Options): Promise<ScanResult>

interface Options {
  maxStreamBytes?: number // decompression limit per stream, default 50 MiB
  maxTotalBytes?: number  // total decompression limit per file, default 200 MiB
  maxObjects?: number     // default 500,000
}

interface ScanResult {
  suspicious: boolean     // a high-severity finding, an encrypted file, or an aborted scan
  encrypted: boolean
  findings: { name: string; severity: 'high' | 'medium' | 'low'; count: number }[]
  error?: string          // why the scan was aborted (limits, nesting depth); findings are partial
}
```

The input buffer is not copied: it is read in place on a worker thread, so it must not be modified until the Promise settles. Invalid arguments result in a rejected Promise; for any input data (including corrupted files) the function returns a result rather than throwing.

## Rules

| Finding | Severity | Meaning |
|---|---|---|
| `JavaScript`, `JS` | high | JavaScript code and actions |
| `Launch` | high | launching an external program |
| `EmbeddedFile(s)` | high | embedded files |
| `RichMedia` | high | Flash/multimedia |
| `ObfuscatedName` | high | a sensitive name written with `#xx` escapes (`/J#61vaScript`) |
| `SuspiciousJS` | high | exploit indicators in a JS/XFA script: `eval`, `unescape`, `util.printf`, `Collab.getIcon`, heap spray… |
| `ScriptURI` | high | a `javascript:` / `vbscript:` link |
| `UndecodableObjStm` | high | an object stream cannot be decoded (unknown filter) |
| `DamagedObjStm` | high | an object stream is corrupted/truncated (its content is still scanned) |
| `OpenAction` | medium | an action on document open (except a plain `[page /Fit]` destination) |
| `AA`, `XFA`, `SubmitForm`, `ImportData`, `GoToR`, `GoToE`, `Rendition` | medium | automatic actions, forms, jumps to other documents |
| `XFAScript` | medium | an XFA form with scripts |
| `FileURI` | medium | a `file:`/UNC/`smb:` link (NTLM hash leak) |
| `NoHeader` | medium | no `%PDF-` within the first 1024 bytes |
| `JBIG2Decode`, `AcroForm`, `URI`, `Sound`, `Movie`, `GoTo3DView`, `Collection` | low | |
| `HeaderOffset`, `TrailingData` | low | data before the header / after the last `%%EOF` (polyglots) |

The whole file is tokenized without relying on the xref table, so objects outside the cross-reference table are found too. Object streams (ObjStm) are decompressed: FlateDecode (tolerant to truncation and bad checksums), LZWDecode, RunLengthDecode, ASCIIHex, ASCII85, PNG and TIFF predictors. Decompression limits apply to all filters.

This is a heuristic, not an antivirus: `suspicious: false` does not guarantee that a file is safe.

## Development

Requires Rust (stable) and Node.js ≥ 22; cross-compiling for Windows on Linux additionally requires [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) and the `x86_64-pc-windows-msvc` target.

```sh
npm install
npm run build        # prebuilds/linux-x64 and prebuilds/win32-x64
npm test             # cargo test + tsc + node:test
```

- `crates/scanner` is the pure-Rust core (`pdf-scan-core`); `crates/node` is the N-API wrapper.
- The Linux build verifies that the binary does not require glibc newer than 2.36. Build on a system with glibc ≤ 2.36 or rely on the check in `scripts/build.mjs`.
- Windows: the CRT is linked statically; only system DLLs are required.
- `reference/pdf-scanner.ts` is the original TypeScript implementation; `test/reference.test.mts` compares results against it on a corpus and on mutated files.
- The npm package contains only `index.js`, `index.d.ts`, `prebuilds/`, `README.md`, and `LICENSE`.

## License

MIT
