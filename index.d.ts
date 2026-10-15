export type Severity = 'high' | 'medium' | 'low'

export interface Finding {
  /** Rule name: a PDF key (`JavaScript`, `Launch`, …) or a heuristic (`SuspiciousJS`, `ObfuscatedName`, …) */
  name: string
  severity: Severity
  /** Number of occurrences */
  count: number
}

export interface ScanResult {
  /** A high-severity finding (including `Undecryptable`) or an aborted scan */
  suspicious: boolean
  /** The file is encrypted. If it opens without a password, it is decrypted and scanned in full;
   * otherwise the `Undecryptable` finding is reported. */
  encrypted: boolean
  /** By descending severity, then in order of discovery */
  findings: Finding[]
  /** Why the scan was aborted (limit exceeded, etc.); findings are partial in that case */
  error?: string
}

export interface Options {
  /** Decompression limit per stream, in bytes. Default 50 MiB */
  maxStreamBytes?: number
  /** Total decompression limit per file, in bytes. Default 200 MiB */
  maxTotalBytes?: number
  /** Maximum number of objects. Default 500,000 */
  maxObjects?: number
}

/**
 * Scans a PDF for potentially malicious content.
 * Runs off the main thread and reads the buffer in place (no copy);
 * the buffer must not be modified until the Promise settles.
 */
export declare function scanPdf(bytes: Uint8Array, opts?: Options): Promise<ScanResult>
