# scan-pdf

## Task

A native Node.js addon that scans PDF files for malicious content.
- Usable from TypeScript (types in `index.d.ts`).
- Supported OS: Linux x64 glibc (Debian 12 / glibc 2.36 or newer), Windows x64.
- Node.js ≥ 22.
- MIT license; dependencies must have permissive licenses only (MIT, Apache-2.0, ISC, Zlib, BSD, Unicode).
- Pre-built binaries with minimal system dependencies.
- The original functionality example is `reference/pdf-scanner.ts` (the reference; do not change its logic:
  it is used as an oracle in tests).

## Decisions (agreed with the customer)

- Language: Rust + napi-rs (`napi` 3, N-API 8), without `@napi-rs/cli`; built with plain cargo.
- Async-only API: `scanPdf(bytes: Uint8Array, opts?: Options): Promise<ScanResult>`.
  The scan runs on the libuv thread pool (`AsyncTask`), the input buffer is read in place without
  copying (the file is only read, never modified), a panic becomes a result
  with `error`, invalid arguments produce a rejected Promise (`async` wrapper in `index.js`).
- Detection is extended beyond the reference (1:1 compatibility is not required, but native must find
  at least what the reference finds; the differential test checks this).
- Distribution: a single npm package with all `.node` files in `prebuilds/<platform>-<arch>/scan-pdf.node`.
  The package contains only `index.js`, `index.d.ts`, `prebuilds/`, `README.md`, `LICENSE` (`files` field).
  No install scripts and no build scripts in the package.
- No GitHub Actions/CI.
- Branch `main`. Committer: `cyannuk <cyannuk@gmail.com>` (git config is not set:
  `git -c user.name=cyannuk -c user.email=cyannuk@gmail.com commit …`). Commit only when asked.
- Version 1.0.0 (kept in sync in `Cargo.toml` [workspace.package] and `package.json`).
- All code comments and documentation are in English.

## Layout

```
Cargo.toml                 workspace, shared version, release profile (lto, strip)
.cargo/config.toml         Windows: +crt-static, /ignore:4099
crates/scanner/            pdf-scan-core: pure-Rust core (no napi, tested with cargo test)
  src/lexer.rs             tokenizer, string decoding
  src/parser.rs            Obj/Dict (Dict = Vec<Entry>, duplicate keys are kept; lookup returns the last)
  src/filters.rs           Flate (miniz_oxide, lenient), LZW, RunLength, AHx, A85, predictors; Budget = limits
  src/lib.rs               Scanner: rules, file walk, ObjStm, JS/XFA/URI analysis, structure checks
  src/tests.rs             unit tests on synthetic PDFs + mutation fuzzing
  examples/scan.rs         CLI for timing: cargo run --release -p pdf-scan-core --example scan -- f.pdf
crates/node/               scan-pdf-node: cdylib, napi wrapper (AsyncTask, option validation)
index.js / index.d.ts      prebuilds loader (CJS, named export) and types
scripts/build.mjs          builds prebuilds + checks that the Linux binary needs no GLIBC > 2.36
test/pdf.mts               synthetic PDF generator
test/scan.test.mts         API tests
test/reference.test.mts    differential test against reference/pdf-scanner.ts (corpus + mutations)
reference/pdf-scanner.ts   the reference
```

## Commands

```sh
npm install                # dev dependencies: typescript, @types/node
npm run build              # both platforms → prebuilds/ (build:linux, build:win separately)
npm test                   # cargo test + tsc + node --test
npm pack                   # run npm run build first (prebuilds/ is in .gitignore)
```

- Windows is built on Linux via `cargo xwin` (target `x86_64-pc-windows-msvc`); on Windows with plain cargo.
- Node tests need `--experimental-transform-types` (the reference uses parameter properties); already in `npm run test:node`.
- Tests are `.mts`: the package is CommonJS, while the tests need ESM/top-level await.
- clippy is not installed in the toolchain.

## Result semantics

- `suspicious` = a `high` finding || `encrypted` || the scan was aborted (`error`).
- `findings` are sorted by severity, then in order of discovery.
- Errors: `Unpack limit exceeded`, `Too many objects`, `Nesting of objects is too deep`
  (the reference uses `Exceed unpack limit`, `Too many object`; the mapping is in `test/reference.test.mts`).
- Default limits: 50 MiB per stream (per filter), 200 MiB in total, 500,000 objects, nesting depth 64.

The reference rules are kept; added: `ObfuscatedName`, `SuspiciousJS`, `ScriptURI`, `DamagedObjStm` (high);
`Rendition`, `XFAScript`, `FileURI`, `NoHeader` (medium); `Sound`, `Movie`, `GoTo3DView`, `Collection`,
`HeaderOffset`, `TrailingData` (low). The full table is in `README.md`; when changing rules, update
`rule()`/`static_name()` in `crates/scanner/src/lib.rs`, the README and the tests.

## Invariants that are easy to break

- The scanner must never panic on any input; every index must be bounds-checked.
- Every expanding filter must stay within `Budget` (protection against decompression bombs).
- A damaged/truncated ObjStm is scanned partially but must be flagged `DamagedObjStm`
  (otherwise a deliberately damaged stream passes as clean; found by the differential test).
- miniz_oxide `decompress_to_vec*` returns a buffer with a garbage tail on error, hence the custom
  loop over `inflate::core::decompress` in `inflate_lenient`.
- Linux binary: dependencies are only `libc`, `libgcc_s`, `ld-linux`; symbols ≤ GLIBC_2.36
  (checked by `scripts/build.mjs`). Windows: system DLLs only (check: `objdump -p … | grep "DLL Name"`).
- Binaries are stripped (`strip = true`) and must not contain build machine paths: `scripts/build.mjs`
  passes `--remap-path-prefix` (CARGO_HOME → `/cargo`, repo → `/scan-pdf`) via `cargo --config`, which
  merges with `.cargo/config.toml` (do not use `RUSTFLAGS`: it would drop `+crt-static`), and fails if a path remains.

## Status (v1.0.0)

Done and committed: core, wrapper, loader, types, tests (30 Rust + 13 Node, all passing),
README, LICENSE. Performance ≈ 2.5× faster than the reference.
GitHub release `v1.0.0` exists with assets: npm tarball, both `.node` binaries, `SHA256SUMS`.
