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
  at least what the reference finds; the differential test checks this). The reference may have bugs
  too: decide every divergence on its merits, and document the exceptions in `test/reference.test.mts`.
- Encrypted files that open without a password must be accepted if clean: they are decrypted with the
  empty user password and scanned in full (the reference flags every encrypted file as suspicious).
  Anything that cannot be opened gets the `Undecryptable` finding (high).
- Distribution: a single npm package with all `.node` files in `prebuilds/<platform>-<arch>/scan-pdf.node`.
  The package contains only `index.js`, `index.d.ts`, `prebuilds/`, `README.md`, `LICENSE` (`files` field).
  No install scripts and no build scripts in the package.
- No GitHub Actions/CI.
- Branch `main`. Committer: `cyannuk <cyannuk@gmail.com>` (git config is not set:
  `git -c user.name=cyannuk -c user.email=cyannuk@gmail.com commit …`). Commit only when asked.
- Version 1.1.0 (kept in sync in `Cargo.toml` [workspace.package], `package.json`, `package-lock.json`).
- All code comments and documentation are in English.

## Layout

```
Cargo.toml                 workspace, shared version, release profile (lto, strip)
.cargo/config.toml         Windows: +crt-static, /ignore:4099
crates/scanner/            pdf-scan-core: pure-Rust core (no napi, tested with cargo test)
  src/lexer.rs             tokenizer, string decoding
  src/parser.rs            Obj/Dict (Dict = Vec<Entry>, duplicate keys are kept; lookup returns the last)
  src/filters.rs           Flate (miniz_oxide, lenient), LZW, RunLength, AHx, A85, predictors; Budget = limits
  src/crypt.rs             standard security handler: empty-password check, keys, RC4/AES-128/AES-256
  src/lib.rs               Scanner: rules, file walk, ObjStm, JS/XFA/URI analysis, structure checks,
                           choice of the encryption dictionary (decryptor())
  src/tests.rs             unit tests on synthetic PDFs + mutation fuzzing
  examples/scan.rs         CLI for timing: cargo run --release -p pdf-scan-core --example scan -- f.pdf
crates/node/               scan-pdf-node: cdylib, napi wrapper (AsyncTask, option validation)
index.js / index.d.ts      prebuilds loader (CJS, named export) and types
scripts/build.mjs          builds prebuilds + checks that the Linux binary needs no GLIBC > 2.36
scripts/make-fixtures.py   generates test/fixtures/*.pdf with qpdf (pikepdf); not needed for building
test/fixtures/             encrypted PDFs (RC4 40/128, AES-128, AES-256 R5/R6, with/without ObjStm,
                           a clean one, a password-protected one); used by Rust and Node tests
test/pdf.mts               synthetic PDF generator, fixture loader
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
- Fixtures: `python3 -m venv .venv && .venv/bin/pip install pikepdf && .venv/bin/python scripts/make-fixtures.py`
  (salts are random: the bytes change, the expected results do not).
- Crypto dependencies: `aes`, `md-5`, `sha2` (RustCrypto, MIT OR Apache-2.0). `[profile.dev.package."*"]`
  is optimized because the R6 key derivation is slow in debug builds.
- clippy is not installed in the toolchain.

## Result semantics

- `suspicious` = a `high` finding || the scan was aborted (`error`). `encrypted` alone does not make
  a file suspicious: an encrypted file is either decrypted and scanned, or gets `Undecryptable` (high).
- `findings` are sorted by severity, then in order of discovery.
- Errors: `Unpack limit exceeded`, `Too many objects`, `Nesting of objects is too deep`
  (the reference uses `Exceed unpack limit`, `Too many object`; the mapping is in `test/reference.test.mts`).
- Default limits: 50 MiB per stream (per filter), 200 MiB in total, 500,000 objects, nesting depth 64.

The reference rules are kept; added: `ObfuscatedName`, `SuspiciousJS`, `ScriptURI`, `DamagedObjStm`, `Undecryptable` (high);
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
- Encryption (`scan()`): pass 1 is a plain scan; if `/Encrypt` was seen, `decryptor()` picks the handler
  and pass 2 rescans with decryption. Every document trailer (`trailer` dicts and XRef stream dicts with
  `/Root`) must refer to encryption, and every definition of the encryption dictionary (and `/ID[0]`) must
  give the same key; otherwise `Undecryptable` (a viewer could use another one). At most `MAX_HANDLERS`
  key derivations per file.
- In pass 2, `/JS` and `/URI` strings, JS/XFA streams and object streams are analyzed both decrypted and as
  stored: an object stream is fully scanned in its main reading (decrypted first, undamaged preferred),
  the other reading only contributes names (its objects must not replace the main ones).
- The `/Crypt` filter is a no-op only during decryption; elsewhere it is an unknown filter.
- Strings of the encryption dictionary and `/ID` are decoded by the parser (`wants_string`), and arrays
  inherit the choice; `true`/`false` are `Obj::Bool` (`/EncryptMetadata false` changes the R4 key).
- Binaries are stripped (`strip = true`) and must not contain build machine paths: `scripts/build.mjs`
  passes `--remap-path-prefix` (CARGO_HOME → `/cargo`, repo → `/scan-pdf`) via `cargo --config`, which
  merges with `.cargo/config.toml` (do not use `RUSTFLAGS`: it would drop `+crt-static`), and fails if a path remains.

## Status (v1.1.0)

Done and committed (a single commit on `main`): core, wrapper, loader, types, tests (35 Rust + 15 Node,
all passing), README, LICENSE. Performance ≈ 2.5× faster than the reference.
1.1.0 added decryption of encrypted files that open without a password (`crypt.rs`, `Undecryptable`,
qpdf fixtures); `encrypted` alone no longer makes a file suspicious; an object stream whose `/Filter`
has no value (or is `null`) is undecodable.
GitHub release `v1.1.0` exists with assets: npm tarball, both `.node` binaries, `SHA256SUMS`.
