//! PDF tokenizer. Tolerant to garbage: never fails, yields `Tok::Junk` for unrecognized bytes.

const fn class_table(chars: &[u8]) -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < chars.len() {
        t[chars[i] as usize] = true;
        i += 1;
    }
    t
}

pub(crate) static WS: [bool; 256] = class_table(&[0, 9, 10, 12, 13, 32]);
static DELIM: [bool; 256] = class_table(b"()<>[]{}/%");

#[inline]
fn is_regular(c: u8) -> bool {
    !WS[c as usize] && !DELIM[c as usize]
}

#[inline]
pub(crate) fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Maximum length of a name (the rest is dropped) and of a regular token.
const MAX_NAME: usize = 128;
const MAX_REGULAR: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrKind {
    Literal,
    Hex,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tok<'a> {
    /// `escaped`: the name contained a `#xx` escape sequence.
    Name { v: Box<[u8]>, escaped: bool },
    Num { v: f64, int: bool },
    Kw(&'a [u8]),
    /// String; `start..end` is the content without delimiters (not yet decoded).
    Str { kind: StrKind, start: usize, end: usize },
    DictOpen,
    DictClose,
    ArrOpen,
    ArrClose,
    Junk,
}

pub struct Lexer<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Lexer { b, pos: 0 }
    }

    pub fn next_tok(&mut self) -> Option<Tok<'a>> {
        let b = self.b;
        // whitespace and comments
        while self.pos < b.len() {
            let c = b[self.pos];
            if WS[c as usize] {
                self.pos += 1;
            } else if c == b'%' {
                while self.pos < b.len() && b[self.pos] != b'\n' && b[self.pos] != b'\r' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
        if self.pos >= b.len() {
            return None;
        }
        let c = b[self.pos];
        match c {
            b'/' => return Some(self.read_name()),
            b'(' => {
                let start = self.pos + 1;
                let end = self.skip_literal_string();
                return Some(Tok::Str { kind: StrKind::Literal, start, end });
            }
            b'[' => {
                self.pos += 1;
                return Some(Tok::ArrOpen);
            }
            b']' => {
                self.pos += 1;
                return Some(Tok::ArrClose);
            }
            b'<' => {
                if b.get(self.pos + 1) == Some(&b'<') {
                    self.pos += 2;
                    return Some(Tok::DictOpen);
                }
                let start = self.pos + 1;
                return Some(match memchr::memchr(b'>', &b[start..]) {
                    Some(i) => {
                        self.pos = start + i + 1;
                        Tok::Str { kind: StrKind::Hex, start, end: start + i }
                    }
                    None => {
                        self.pos = b.len();
                        Tok::Str { kind: StrKind::Hex, start, end: b.len() }
                    }
                });
            }
            b'>' => {
                if b.get(self.pos + 1) == Some(&b'>') {
                    self.pos += 2;
                    return Some(Tok::DictClose);
                }
                self.pos += 1;
                return Some(Tok::Junk);
            }
            _ => {}
        }
        if DELIM[c as usize] {
            self.pos += 1;
            return Some(Tok::Junk);
        }
        let start = self.pos;
        while self.pos < b.len() && is_regular(b[self.pos]) {
            self.pos += 1;
        }
        let s = &b[start..self.pos];
        if s.len() > MAX_REGULAR {
            return Some(Tok::Junk);
        }
        if let Some(int) = number_kind(s) {
            // number_kind guarantees ASCII syntax that f64::from_str understands
            let v = std::str::from_utf8(s).ok().and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            return Some(Tok::Num { v, int });
        }
        Some(Tok::Kw(s))
    }

    fn read_name(&mut self) -> Tok<'a> {
        let b = self.b;
        let mut v = Vec::new();
        let mut escaped = false;
        self.pos += 1;
        while self.pos < b.len() && is_regular(b[self.pos]) {
            let mut c = b[self.pos];
            self.pos += 1;
            if c == b'#' && self.pos + 1 < b.len() {
                if let (Some(h), Some(l)) = (hex_val(b[self.pos]), hex_val(b[self.pos + 1])) {
                    c = h * 16 + l;
                    self.pos += 2;
                    escaped = true;
                }
            }
            if v.len() < MAX_NAME {
                v.push(c);
            }
        }
        Tok::Name { v: v.into_boxed_slice(), escaped }
    }

    /// Skips a literal string and returns the position of the closing parenthesis (or the end of the buffer).
    fn skip_literal_string(&mut self) -> usize {
        let b = self.b;
        let mut depth = 0u32;
        while self.pos < b.len() {
            let c = b[self.pos];
            self.pos += 1;
            match c {
                b'\\' => self.pos += 1,
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return self.pos - 1;
                    }
                }
                _ => {}
            }
        }
        self.pos = b.len();
        b.len()
    }
}

/// `^[+-]?(\d+\.?\d*|\.\d+)$` → Some(is integer), otherwise None.
fn number_kind(s: &[u8]) -> Option<bool> {
    let digits = match s.first() {
        Some(b'+' | b'-') => &s[1..],
        _ => s,
    };
    if digits.is_empty() {
        return None;
    }
    let mut dots = 0;
    let mut nd = 0;
    for &c in digits {
        match c {
            b'0'..=b'9' => nd += 1,
            b'.' => dots += 1,
            _ => return None,
        }
    }
    if nd == 0 || dots > 1 {
        return None;
    }
    Some(dots == 0)
}

/// Decodes string content (without delimiters).
pub fn decode_string(raw: &[u8], kind: StrKind) -> Vec<u8> {
    match kind {
        StrKind::Hex => crate::filters::ascii_hex(raw),
        StrKind::Literal => decode_literal(raw),
    }
}

fn decode_literal(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        i += 1;
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let Some(&e) = raw.get(i) else { break };
        i += 1;
        match e {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'\r' => {
                if raw.get(i) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut v = (e - b'0') as u32;
                for _ in 0..2 {
                    match raw.get(i) {
                        Some(&d @ b'0'..=b'7') => {
                            v = v * 8 + (d - b'0') as u32;
                            i += 1;
                        }
                        _ => break,
                    }
                }
                out.push(v as u8);
            }
            _ => out.push(e),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &[u8]) -> Vec<Tok<'_>> {
        let mut lx = Lexer::new(s);
        std::iter::from_fn(|| lx.next_tok()).collect()
    }

    #[test]
    fn basic_tokens() {
        let t = toks(b"<< /Type /J#61vaScript 12 0 R -.5 [ (a(b)c) <4142> ] >> % comment\n obj");
        assert_eq!(t[0], Tok::DictOpen);
        assert_eq!(t[1], Tok::Name { v: (*b"Type").into(), escaped: false });
        assert_eq!(t[2], Tok::Name { v: (*b"JavaScript").into(), escaped: true });
        assert_eq!(t[3], Tok::Num { v: 12.0, int: true });
        assert_eq!(t[5], Tok::Kw(b"R"));
        assert_eq!(t[6], Tok::Num { v: -0.5, int: false });
        assert!(matches!(t[8], Tok::Str { kind: StrKind::Literal, .. }));
        assert!(matches!(t[9], Tok::Str { kind: StrKind::Hex, .. }));
        assert_eq!(t[11], Tok::DictClose);
        assert_eq!(t[12], Tok::Kw(b"obj"));
    }

    #[test]
    fn numbers() {
        assert_eq!(number_kind(b"12"), Some(true));
        assert_eq!(number_kind(b"+1."), Some(false));
        assert_eq!(number_kind(b".5"), Some(false));
        assert_eq!(number_kind(b"."), None);
        assert_eq!(number_kind(b"1.2.3"), None);
        assert_eq!(number_kind(b"-"), None);
    }

    #[test]
    fn literal_strings() {
        assert_eq!(decode_literal(b"a\\(b\\)\\n\\101\\\nz"), b"a(b)\nAz");
        assert_eq!(decode_literal(b"x\\"), b"x");
    }

    #[test]
    fn unterminated() {
        let t = toks(b"(abc");
        assert_eq!(t, vec![Tok::Str { kind: StrKind::Literal, start: 1, end: 4 }]);
        let t = toks(b"<41");
        assert_eq!(t, vec![Tok::Str { kind: StrKind::Hex, start: 1, end: 3 }]);
    }
}
