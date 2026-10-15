//! PDF stream filters. All filters that expand data stay within the shared [`Budget`].

use miniz_oxide::inflate::{self, TINFLStatus};

use crate::lexer::hex_val;
use crate::ScanError;

/// Decompression limits: per filter and in total per file.
pub struct Budget {
    pub max_stream: usize,
    pub remaining: usize,
    /// The stream was only partially decoded (truncated, corrupted, bad checksum).
    pub damaged: bool,
}

impl Budget {
    /// How many bytes the next filter may produce.
    fn limit(&self) -> Result<usize, ScanError> {
        let l = self.max_stream.min(self.remaining);
        if l == 0 {
            return Err(ScanError::UnpackLimit);
        }
        Ok(l)
    }

    fn consume(&mut self, out: &[u8], limit: usize) -> Result<(), ScanError> {
        if out.len() > limit {
            return Err(ScanError::UnpackLimit);
        }
        self.remaining -= out.len();
        Ok(())
    }
}

/// Filter result: `Ok(None)` means the data cannot be decoded.
type FilterResult = Result<Option<Vec<u8>>, ScanError>;

pub fn flate(data: &[u8], budget: &mut Budget) -> FilterResult {
    let limit = budget.limit()?;
    let out = match inflate_lenient(data, limit, true, &mut budget.damaged)? {
        Some(out) => Some(out),
        None => inflate_lenient(data, limit, false, &mut budget.damaged)?,
    };
    if let Some(out) = &out {
        budget.consume(out, limit)?;
    }
    Ok(out)
}

/// Decompression tolerant to truncated streams and bad checksums:
/// malicious files often break streams on purpose, and Acrobat still reads them.
fn inflate_lenient(data: &[u8], limit: usize, zlib: bool, damaged: &mut bool) -> FilterResult {
    use inflate::core::inflate_flags::*;
    use inflate::core::{decompress, DecompressorOxide};

    let mut flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    if zlib {
        flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
    }
    let mut d = Box::<DecompressorOxide>::default();
    let mut out = vec![0u8; data.len().saturating_mul(2).max(64).min(limit)];
    let (mut in_pos, mut out_pos) = (0, 0);
    loop {
        let (status, consumed, written) = decompress(&mut d, &data[in_pos..], &mut out, out_pos, flags);
        in_pos += consumed;
        out_pos += written;
        match status {
            TINFLStatus::Done => break,
            TINFLStatus::Adler32Mismatch => {
                *damaged = true;
                break;
            }
            TINFLStatus::HasMoreOutput => {
                if out.len() >= limit {
                    return Err(ScanError::UnpackLimit);
                }
                let n = out.len().saturating_mul(2).min(limit);
                out.resize(n, 0);
            }
            // truncated stream: keep what has been decompressed so far
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress if out_pos > 0 => {
                *damaged = true;
                break;
            }
            _ => return Ok(None),
        }
    }
    out.truncate(out_pos);
    Ok(Some(out))
}

pub fn ascii_hex(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len() / 2 + 1);
    let mut hi: Option<u8> = None;
    for &c in b {
        if c == b'>' {
            break;
        }
        let Some(v) = hex_val(c) else { continue };
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push(h * 16 + v),
        }
    }
    if let Some(h) = hi {
        out.push(h * 16);
    }
    out
}

pub fn ascii85(b: &[u8]) -> Vec<u8> {
    let b = b.strip_prefix(b"<~").unwrap_or(b);
    let mut out = Vec::with_capacity(b.len() / 5 * 4 + 4);
    let (mut n, mut cnt) = (0u32, 0);
    for &c in b {
        if c == b'~' {
            break;
        }
        if c == b'z' && cnt == 0 {
            out.extend_from_slice(&[0; 4]);
            continue;
        }
        if !(0x21..=0x75).contains(&c) {
            continue;
        }
        n = n.wrapping_mul(85).wrapping_add((c - 33) as u32);
        cnt += 1;
        if cnt == 5 {
            out.extend_from_slice(&n.to_be_bytes());
            n = 0;
            cnt = 0;
        }
    }
    if cnt > 1 {
        for _ in cnt..5 {
            n = n.wrapping_mul(85).wrapping_add(84);
        }
        out.extend_from_slice(&n.to_be_bytes()[..cnt - 1]);
    }
    out
}

pub fn run_length(data: &[u8], budget: &mut Budget) -> FilterResult {
    let limit = budget.limit()?;
    let mut out = Vec::with_capacity(data.len().min(limit));
    let mut i = 0;
    while i < data.len() {
        let l = data[i] as usize;
        i += 1;
        if l < 128 {
            let chunk = &data[i..(i + l + 1).min(data.len())];
            out.extend_from_slice(chunk);
            i += l + 1;
        } else if l > 128 {
            let Some(&c) = data.get(i) else { break };
            out.resize(out.len() + 257 - l, c);
            i += 1;
        } else {
            break;
        }
        if out.len() > limit {
            return Err(ScanError::UnpackLimit);
        }
    }
    budget.consume(&out, limit)?;
    Ok(Some(out))
}

pub fn lzw(data: &[u8], early_change: bool, budget: &mut Budget) -> FilterResult {
    const CLEAR: usize = 256;
    const EOD: usize = 257;
    let limit = budget.limit()?;
    let early = early_change as usize;

    let mut prefix = vec![0u16; 4096];
    let mut suffix = vec![0u8; 4096];
    let mut first = vec![0u8; 4096];
    let mut len = vec![0u32; 4096];
    for i in 0..256 {
        suffix[i] = i as u8;
        first[i] = i as u8;
        len[i] = 1;
    }
    let mut next = 258usize;
    let mut width = 9u32;
    let mut prev: Option<usize> = None;
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out: Vec<u8> = Vec::with_capacity(data.len().saturating_mul(2).min(limit));

    let emit = |out: &mut Vec<u8>, code: usize, len: &[u32], prefix: &[u16], suffix: &[u8]| -> Result<(), ScanError> {
        let n = len[code] as usize;
        if out.len() + n > limit {
            return Err(ScanError::UnpackLimit);
        }
        let start = out.len();
        out.resize(start + n, 0);
        let mut c = code;
        for k in (start..start + n).rev() {
            out[k] = suffix[c];
            c = prefix[c] as usize;
        }
        Ok(())
    };

    let mut iter = data.iter();
    loop {
        while bits < width {
            let Some(&byte) = iter.next() else {
                budget.consume(&out, limit)?;
                return Ok(Some(out));
            };
            acc = (acc << 8) | byte as u32;
            bits += 8;
        }
        bits -= width;
        let code = ((acc >> bits) & ((1 << width) - 1)) as usize;
        acc &= (1 << bits) - 1;

        if code == CLEAR {
            next = 258;
            width = 9;
            prev = None;
            continue;
        }
        if code == EOD {
            break;
        }
        let Some(p) = prev else {
            if code > 255 {
                budget.damaged = true; // the first code after Clear must be a literal
                break;
            }
            emit(&mut out, code, &len, &prefix, &suffix)?;
            prev = Some(code);
            continue;
        };
        let head = if code < next {
            emit(&mut out, code, &len, &prefix, &suffix)?;
            first[code]
        } else if code == next && next < 4096 {
            emit(&mut out, p, &len, &prefix, &suffix)?;
            if out.len() + 1 > limit {
                return Err(ScanError::UnpackLimit);
            }
            out.push(first[p]);
            first[p]
        } else {
            budget.damaged = true;
            break;
        };
        if next < 4096 {
            prefix[next] = p as u16;
            suffix[next] = head;
            first[next] = first[p];
            len[next] = len[p] + 1;
            next += 1;
        }
        width = match next + early {
            n if n >= 2048 => 12,
            n if n >= 1024 => 11,
            n if n >= 512 => 10,
            _ => 9,
        };
        prev = Some(code);
    }
    budget.consume(&out, limit)?;
    Ok(Some(out))
}

/// Predictor parameters from /DecodeParms.
pub struct Predictor {
    pub predictor: f64,
    pub colors: f64,
    pub bpc: f64,
    pub columns: f64,
}

/// Reverses the predictor (TIFF 2 and PNG 10–15). `None` means unsupported parameters.
pub fn unpredict(data: Vec<u8>, p: &Predictor) -> Option<Vec<u8>> {
    if p.predictor <= 1.0 {
        return Some(data);
    }
    let bits_px = p.colors * p.bpc;
    let row_bits = bits_px * p.columns;
    if !(bits_px > 0.0 && row_bits > 0.0 && row_bits < 8e6) {
        return None;
    }
    let bpp = ((bits_px / 8.0).ceil() as usize).max(1);
    let row_len = (row_bits / 8.0).ceil() as usize;

    if p.predictor == 2.0 {
        if p.bpc != 8.0 {
            return None;
        }
        let mut out = data;
        for row in out.chunks_mut(row_len) {
            for i in bpp..row.len() {
                row[i] = row[i].wrapping_add(row[i - bpp]);
            }
        }
        return Some(out);
    }
    if p.predictor < 10.0 {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut prev_row: Option<usize> = None;
    for src in data.chunks(row_len + 1) {
        let (&ty, src) = src.split_first()?;
        let dst = out.len();
        for (i, &v) in src.iter().enumerate() {
            let a = if i >= bpp { out[dst + i - bpp] } else { 0 };
            let up = prev_row.map_or(0, |r| out[r + i]);
            let ul = match prev_row {
                Some(r) if i >= bpp => out[r + i - bpp],
                _ => 0,
            };
            let x = match ty {
                0 => v,
                1 => v.wrapping_add(a),
                2 => v.wrapping_add(up),
                3 => v.wrapping_add(((a as u16 + up as u16) >> 1) as u8),
                4 => {
                    let (ia, iu, il) = (a as i16, up as i16, ul as i16);
                    let pp = ia + iu - il;
                    let (pa, pb, pc) = ((pp - ia).abs(), (pp - iu).abs(), (pp - il).abs());
                    v.wrapping_add(if pa <= pb && pa <= pc { a } else if pb <= pc { up } else { ul })
                }
                _ => return None,
            };
            out.push(x);
        }
        // incomplete last row: its "up" row is still full length
        prev_row = Some(dst);
        if src.len() < row_len {
            break;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> Budget {
        Budget { max_stream: 1 << 20, remaining: 1 << 22, damaged: false }
    }

    #[test]
    fn hex_and_85() {
        assert_eq!(ascii_hex(b"41 42 4>zz"), b"AB@");
        assert_eq!(ascii85(b"<~87cURD]i,\"Ebo80~>"), b"Hello World!");
        assert_eq!(ascii85(b"z!!~>"), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn flate_roundtrip_and_limits() {
        let raw = vec![b'a'; 100_000];
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6);
        assert_eq!(flate(&z, &mut budget()).unwrap().unwrap(), raw);
        // raw deflate without a zlib header
        let d = miniz_oxide::deflate::compress_to_vec(&raw, 6);
        assert_eq!(flate(&d, &mut budget()).unwrap().unwrap(), raw);
        // truncated stream → partial result
        let mut b = budget();
        let part = flate(&z[..z.len() / 2], &mut b).unwrap().unwrap();
        assert!(!part.is_empty() && raw.starts_with(&part) && b.damaged);
        let mut small = Budget { max_stream: 1000, remaining: 1 << 20, damaged: false };
        assert!(matches!(flate(&z, &mut small), Err(ScanError::UnpackLimit)));
        assert_eq!(flate(b"garbage!", &mut budget()).unwrap(), None);
    }

    #[test]
    fn total_budget() {
        let z = miniz_oxide::deflate::compress_to_vec_zlib(&[0u8; 600], 6);
        let mut b = Budget { max_stream: 1000, remaining: 1000, damaged: false };
        flate(&z, &mut b).unwrap();
        assert!(matches!(flate(&z, &mut b), Err(ScanError::UnpackLimit)));
    }

    #[test]
    fn run_length_decode() {
        assert_eq!(run_length(&[2, b'a', b'b', b'c', 254, b'x', 128, 9], &mut budget()).unwrap().unwrap(), b"abcxxx");
        let bomb: Vec<u8> = [129u8, 0].repeat(100_000);
        let mut small = Budget { max_stream: 1000, remaining: 1 << 20, damaged: false };
        assert!(matches!(run_length(&bomb, &mut small), Err(ScanError::UnpackLimit)));
    }

    /// Simple LZW encoder (EarlyChange=1) to test the decoder.
    fn lzw_encode(data: &[u8]) -> Vec<u8> {
        use std::collections::HashMap;
        let mut dict: HashMap<Vec<u8>, usize> = (0..256).map(|i| (vec![i as u8], i)).collect();
        let mut next = 258;
        let mut width = 9;
        let (mut acc, mut bits, mut out) = (0u64, 0, Vec::new());
        let put = |code: usize, width: u32, acc: &mut u64, bits: &mut u32, out: &mut Vec<u8>| {
            *acc = (*acc << width) | code as u64;
            *bits += width;
            while *bits >= 8 {
                *bits -= 8;
                out.push((*acc >> *bits) as u8);
            }
        };
        put(256, width, &mut acc, &mut bits, &mut out);
        let mut w: Vec<u8> = Vec::new();
        for &c in data {
            let mut wc = w.clone();
            wc.push(c);
            if dict.contains_key(&wc) {
                w = wc;
            } else {
                put(dict[&w], width, &mut acc, &mut bits, &mut out);
                dict.insert(wc, next);
                next += 1;
                // the decoder lags one entry behind, so EarlyChange is already accounted for here
                width = match next {
                    n if n >= 2048 => 12,
                    n if n >= 1024 => 11,
                    n if n >= 512 => 10,
                    _ => 9,
                };
                if next >= 4095 {
                    put(256, width, &mut acc, &mut bits, &mut out);
                    dict = (0..256).map(|i| (vec![i as u8], i)).collect();
                    next = 258;
                    width = 9;
                }
                w = vec![c];
            }
        }
        if !w.is_empty() {
            put(dict[&w], width, &mut acc, &mut bits, &mut out);
        }
        put(257, width, &mut acc, &mut bits, &mut out);
        if bits > 0 {
            out.push((acc << (8 - bits)) as u8);
        }
        out
    }

    #[test]
    fn lzw_decode() {
        // example from the PDF 1.7 specification, 7.4.4.2
        let spec = [0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01];
        assert_eq!(lzw(&spec, true, &mut budget()).unwrap().unwrap(), b"-----A---B");
        let mut data = Vec::new();
        for i in 0..20_000u32 {
            data.extend_from_slice(format!("{} obj << /K {} >> ", i % 97, i * 7 % 13).as_bytes());
        }
        assert_eq!(lzw(&lzw_encode(&data), true, &mut budget()).unwrap().unwrap(), data);
    }

    #[test]
    fn png_predictor() {
        // 2 rows of 3 bytes: Sub and Up
        let data = vec![1, 1, 1, 1, 2, 1, 1, 1];
        let p = Predictor { predictor: 12.0, colors: 1.0, bpc: 8.0, columns: 3.0 };
        assert_eq!(unpredict(data, &p).unwrap(), [1, 2, 3, 2, 3, 4]);
        let p = Predictor { predictor: 12.0, colors: 1.0, bpc: 8.0, columns: 0.0 };
        assert_eq!(unpredict(vec![0, 1], &p), None);
        let p = Predictor { predictor: 2.0, colors: 1.0, bpc: 8.0, columns: 3.0 };
        assert_eq!(unpredict(vec![1, 1, 1, 5, 1, 1], &p).unwrap(), [1, 2, 3, 5, 6, 7]);
    }
}
