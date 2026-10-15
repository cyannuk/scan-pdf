'use strict'

const SUPPORTED = ['linux-x64', 'win32-x64']

function load() {
  const target = `${process.platform}-${process.arch}`
  if (!SUPPORTED.includes(target))
    throw new Error(`scan-pdf: unsupported platform ${target} (supported: ${SUPPORTED.join(', ')})`)
  try {
    return require(`./prebuilds/${target}/scan-pdf.node`)
  } catch (err) {
    if (process.platform === 'linux' && !process.report?.getReport().header.glibcVersionRuntime)
      throw new Error('scan-pdf: only glibc-based Linux is supported (Debian 12 / glibc 2.36 or newer)', { cause: err })
    throw err
  }
}

const native = load()

/**
 * Scans a PDF for potentially malicious content.
 * Scanning runs on the libuv thread pool; argument errors are reported as a rejected Promise.
 */
async function scanPdf(bytes, opts) {
  if (!(bytes instanceof Uint8Array))
    throw new TypeError('scanPdf: bytes must be a Uint8Array or Buffer')
  return native.scanPdf(bytes, opts ?? undefined)
}

exports.scanPdf = scanPdf
