//! Parsing of PDF objects on top of the lexer.

use std::rc::Rc;

use crate::lexer::{decode_string, Lexer, Tok};
use crate::ScanError;

pub const MAX_DEPTH: usize = 64;

/// Object table key: the object number as f64 (like Map<number> in the reference).
pub type ObjKey = u64;

pub fn obj_key(n: f64) -> ObjKey {
    // -0 and 0 are the same object
    (if n == 0.0 { 0.0 } else { n }).to_bits()
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub k: Box<[u8]>,
    pub v: Obj,
    pub key_escaped: bool,
}

/// Dictionary in source order. Duplicate keys are all kept: every value is analyzed
/// (viewers disagree on which one to use), while lookup returns the last one.
pub type Dict = Vec<Entry>;

#[derive(Debug, Clone)]
pub enum Obj {
    Name { v: Box<[u8]>, escaped: bool },
    Num(f64),
    Ref(ObjKey),
    /// Decoded content; filled in only where the analysis needs it.
    Str(Rc<[u8]>),
    Arr(Vec<Obj>),
    Dict(Rc<Dict>),
    Other,
}

impl Obj {
    pub fn as_name(&self) -> Option<&[u8]> {
        match self {
            Obj::Name { v, .. } => Some(v),
            _ => None,
        }
    }
}

pub fn dict_get<'d>(d: &'d Dict, k: &[u8]) -> Option<&'d Obj> {
    d.iter().rev().find(|e| &*e.k == k).map(|e| &e.v)
}

/// Values of these dictionary keys are kept as decoded strings.
fn wants_string(key: &[u8]) -> bool {
    matches!(key, b"JS" | b"URI")
}

fn is_structural(kw: &[u8]) -> bool {
    matches!(kw, b"obj" | b"endobj" | b"stream" | b"endstream" | b"trailer" | b"xref" | b"startxref")
}

pub enum Parsed {
    Obj(Obj),
    /// A token that is not a value (`>>`, `]`, a keyword…).
    NotObj,
}

/// Parses a value starting with the token `tok`.
/// `want_str`: whether to decode the value if it turns out to be a string.
pub fn parse_value<'a>(
    lx: &mut Lexer<'a>,
    tok: Tok<'a>,
    depth: usize,
    want_str: bool,
) -> Result<Parsed, ScanError> {
    Ok(match tok {
        Tok::Name { v, escaped } => Parsed::Obj(Obj::Name { v, escaped }),
        Tok::Str { kind, start, end } => Parsed::Obj(if want_str {
            Obj::Str(decode_string(&lx.b[start..end], kind).into())
        } else {
            Obj::Str(Rc::from(&[][..]))
        }),
        Tok::Num { v, int } => {
            if int {
                // "N G R" → reference
                let save = lx.pos;
                if let Some(Tok::Num { int: true, .. }) = lx.next_tok() {
                    if let Some(Tok::Kw(b"R")) = lx.next_tok() {
                        return Ok(Parsed::Obj(Obj::Ref(obj_key(v))));
                    }
                }
                lx.pos = save;
            }
            Parsed::Obj(Obj::Num(v))
        }
        Tok::Kw(b"true" | b"false" | b"null") => Parsed::Obj(Obj::Other),
        Tok::ArrOpen | Tok::DictOpen => {
            if depth >= MAX_DEPTH {
                return Err(ScanError::TooDeep);
            }
            let is_dict = matches!(tok, Tok::DictOpen);
            let mut items = Vec::new();
            let mut map = Dict::new();
            let mut key: Option<(Box<[u8]>, bool)> = None;
            loop {
                let save = lx.pos;
                let Some(t) = lx.next_tok() else { break };
                match (&t, is_dict) {
                    (Tok::DictClose, true) | (Tok::ArrClose, false) => break,
                    (Tok::Kw(kw), _) if is_structural(kw) => {
                        lx.pos = save;
                        break;
                    }
                    _ => {}
                }
                let want = matches!(&key, Some((k, _)) if wants_string(k));
                let Parsed::Obj(v) = parse_value(lx, t, depth + 1, want)? else { continue };
                if !is_dict {
                    items.push(v);
                } else if let Some((k, key_escaped)) = key.take() {
                    map.push(Entry { k, v, key_escaped });
                } else if let Obj::Name { v, escaped } = v {
                    key = Some((v, escaped));
                }
            }
            if let Some((k, key_escaped)) = key {
                map.push(Entry { k, v: Obj::Other, key_escaped });
            }
            Parsed::Obj(if is_dict { Obj::Dict(Rc::new(map)) } else { Obj::Arr(items) })
        }
        _ => Parsed::NotObj,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &[u8]) -> Obj {
        let mut lx = Lexer::new(s);
        let t = lx.next_tok().unwrap();
        match parse_value(&mut lx, t, 0, true).unwrap() {
            Parsed::Obj(o) => o,
            Parsed::NotObj => panic!("not an object"),
        }
    }

    #[test]
    fn dict_with_refs_and_strings() {
        let Obj::Dict(d) = parse(b"<< /A 1 0 R /JS (app.alert\\(1\\)) /K [1 2 /N] /Z >>") else { panic!() };
        assert!(matches!(dict_get(&d, b"A"), Some(Obj::Ref(_))));
        match dict_get(&d, b"JS") {
            Some(Obj::Str(s)) => assert_eq!(&**s, b"app.alert(1)"),
            o => panic!("{o:?}"),
        }
        assert!(matches!(dict_get(&d, b"K"), Some(Obj::Arr(a)) if a.len() == 3));
        assert!(matches!(dict_get(&d, b"Z"), Some(Obj::Other)));
        let Obj::Dict(d) = parse(b"<< /A 1 /A 2 >>") else { panic!() };
        assert!(matches!(dict_get(&d, b"A"), Some(Obj::Num(v)) if *v == 2.0));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn stops_at_structural_keyword() {
        let mut lx = Lexer::new(b"<< /A 1 endobj");
        let t = lx.next_tok().unwrap();
        assert!(matches!(parse_value(&mut lx, t, 0, false).unwrap(), Parsed::Obj(Obj::Dict(_))));
        assert_eq!(lx.next_tok(), Some(Tok::Kw(b"endobj")));
    }

    #[test]
    fn too_deep() {
        let s = "[".repeat(100);
        let mut lx = Lexer::new(s.as_bytes());
        let t = lx.next_tok().unwrap();
        assert!(matches!(parse_value(&mut lx, t, 0, false), Err(ScanError::TooDeep)));
    }
}
