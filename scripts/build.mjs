// Builds prebuilds/<platform>-<arch>/scan-pdf.node.
// Linux: cargo (host glibc; checks that no symbol is newer than GLIBC_2.36, i.e. Debian 12).
// Windows: cargo on Windows, cross-compilation via cargo-xwin on Linux. The CRT is linked statically.
// Absolute build paths (embedded in panic locations) are remapped so that binaries do not leak
// the build machine layout; the build fails if any of them remain.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const MAX_GLIBC = [2, 36]

const TARGETS = {
  linux: { triple: 'x86_64-unknown-linux-gnu', file: 'libscan_pdf_node.so', dir: 'linux-x64' },
  win32: { triple: 'x86_64-pc-windows-msvc', file: 'scan_pdf_node.dll', dir: 'win32-x64' }
}

const cargoHome = resolve(process.env.CARGO_HOME ?? join(homedir(), '.cargo'))
const REMAP = [[cargoHome, '/cargo'], [root, '/scan-pdf']]

const run = (cmd, args) => execFileSync(cmd, args, { cwd: root, stdio: 'inherit' })

function build(name) {
  const t = TARGETS[name]
  const cargo = name === 'win32' && process.platform !== 'win32' ? ['xwin', 'build'] : ['build']
  // arrays from --config are merged with .cargo/config.toml, so +crt-static is kept
  const flags = REMAP.map(([from, to]) => `--remap-path-prefix=${from}=${to}`)
  const config = `target.${t.triple}.rustflags=${JSON.stringify(flags)}`
  run('cargo', [...cargo, '--release', '-p', 'scan-pdf-node', '--target', t.triple, '--config', config])
  const src = join(root, 'target', t.triple, 'release', t.file)
  if (name === 'linux')
    checkGlibc(src)
  checkPaths(src)
  const dst = join(root, 'prebuilds', t.dir, 'scan-pdf.node')
  mkdirSync(dirname(dst), { recursive: true })
  copyFileSync(src, dst)
  console.log(`built ${dst}`)
}

function checkGlibc(file) {
  const syms = execFileSync('objdump', ['-T', file], { encoding: 'utf8' })
  for (const [, v] of syms.matchAll(/GLIBC_(\d+\.\d+(?:\.\d+)?)/g)) {
    const [maj, min] = v.split('.').map(Number)
    if (maj > MAX_GLIBC[0] || (maj === MAX_GLIBC[0] && min > MAX_GLIBC[1]))
      throw new Error(`${file} requires GLIBC_${v}, max allowed is ${MAX_GLIBC.join('.')}`)
  }
}

function checkPaths(file) {
  const bin = readFileSync(file)
  for (const [from] of REMAP) {
    if (bin.includes(from))
      throw new Error(`${file} contains the build path ${from}`)
  }
}

const which = process.argv[2]
for (const name of which ? [which] : Object.keys(TARGETS)) {
  if (!TARGETS[name])
    throw new Error(`unknown target ${name}`)
  build(name)
}
