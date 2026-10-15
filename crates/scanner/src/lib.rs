//! Heuristic detection of potentially malicious content in PDF files.
//!
//! The file is not parsed "by the book" (via xref): the lexer walks through all of it,
//! so objects hidden outside the cross-reference table or in damaged files are found too.

mod crypt;
mod filters;
mod lexer;
mod parser;

use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use memchr::memmem;

use crypt::{Decryptor, Method, ObjId, Params};
use filters::{Budget, Predictor};
use lexer::{Lexer, Tok, WS};
use parser::{dict_get, obj_key, parse_value, Dict, Obj, ObjKey, Parsed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub name: String,
    pub severity: Severity,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub suspicious: bool,
    pub encrypted: bool,
    /// Sorted by descending severity, then in order of discovery.
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Decompression limit for a single stream (per filter).
    pub max_stream_bytes: usize,
    /// Total decompression limit per file.
    pub max_total_bytes: usize,
    pub max_objects: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { max_stream_bytes: 50 << 20, max_total_bytes: 200 << 20, max_objects: 500_000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanError {
    TooDeep,
    TooManyObjects,
    UnpackLimit,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ScanError::TooDeep => "Nesting of objects is too deep",
            ScanError::TooManyObjects => "Too many objects",
            ScanError::UnpackLimit => "Unpack limit exceeded",
        })
    }
}

impl std::error::Error for ScanError {}

/// Rules: name (dictionary key or value) → severity.
/// OpenAction is handled separately: `[page /Fit]` is a plain destination.
fn rule(name: &[u8]) -> Option<Severity> {
    use Severity::*;
    Some(match name {
        b"JavaScript" | b"JS" => High,                // JS code and JS actions
        b"Launch" => High,                            // launching an external program
        b"EmbeddedFile" | b"EmbeddedFiles" => High,   // embedded files
        b"RichMedia" => High,                         // Flash/multimedia
        b"XFA" => Medium,                             // XML forms
        b"AA" => Medium,                              // actions on page/field events
        b"SubmitForm" | b"ImportData" => Medium,
        b"GoToR" | b"GoToE" => Medium,                // jump to another document
        b"Rendition" => Medium,                       // may contain JS
        b"JBIG2Decode" | b"AcroForm" | b"URI" => Low,
        b"Sound" | b"Movie" | b"GoTo3DView" => Low,   // multimedia/3D
        b"Collection" => Low,                         // PDF portfolio
        _ => return None,
    })
}

/// Names whose `#xx`-escaped spelling indicates obfuscation.
fn is_sensitive(name: &[u8]) -> bool {
    rule(name).is_some()
        || matches!(
            name,
            b"OpenAction"
                | b"ObjStm"
                | b"Encrypt"
                | b"FlateDecode"
                | b"Fl"
                | b"ASCIIHexDecode"
                | b"AHx"
                | b"ASCII85Decode"
                | b"A85"
                | b"LZWDecode"
                | b"LZW"
                | b"RunLengthDecode"
                | b"RL"
        )
}

/// Exploit indicators in JavaScript (Acrobat/Reader CVEs, heap spray, obfuscation).
const JS_PATTERNS: &[&[u8]] = &[
    b"eval(",
    b"eval (",
    b"unescape(",
    b"String.fromCharCode",
    b"util.printf",
    b"util.printd",
    b"Collab.getIcon",
    b"Collab.collectEmailInfo",
    b"getAnnots",
    b"spell.customDictionaryOpen",
    b"media.newPlayer",
    b"app.setTimeOut",
    b"app.launchURL",
    b"exportDataObject",
    b"getURL(",
    b"syncAnnotScan",
    b"ActiveXObject",
    b"WScript",
];

/// Search window for the `%PDF-` header (Acrobat looks for it within the first 1024 bytes).
const HEADER_WINDOW: usize = 1024;

/// How many distinct encryption dictionaries/IDs are tried (each costs a key derivation).
const MAX_HANDLERS: usize = 8;

#[derive(Clone)]
struct StreamRef {
    dict: Rc<Dict>,
    start: usize,
    end: usize,
    id: Option<ObjId>,
}

struct Scanner<'a> {
    bytes: &'a [u8],
    opts: Options,
    /// Findings in order of discovery (there are few names, so a linear search beats hashing).
    found: Vec<Finding>,
    objects: HashMap<ObjKey, Obj>,
    /// Top-level streams by object number (for JS and XFA stored in streams).
    streams: HashMap<ObjKey, StreamRef>,
    open_actions: Vec<Obj>,
    /// `/JS` and `/URI` values with the top-level object they belong to (its key encrypts strings).
    js: Vec<(Obj, Option<ObjId>)>,
    xfa: Vec<Obj>,
    uris: Vec<(Obj, Option<ObjId>)>,
    encrypted: bool,
    budget: Budget,
    /// Set for the second pass over an encrypted file that opens without a password.
    crypt: Option<Decryptor>,
    /// The top-level object being visited.
    owner: Option<ObjId>,
    /// Top-level string objects (strings referenced by `/JS` and `/URI` are decrypted with their id).
    str_ids: HashMap<ObjKey, ObjId>,
    /// `trailer` dictionaries and XRef stream dictionaries.
    trailers: Vec<Rc<Dict>>,
    /// Top-level dictionaries that look like an encryption dictionary.
    security: Vec<(ObjKey, Rc<Dict>)>,
}

/// Scans an in-memory PDF. Never panics on arbitrary input.
pub fn scan(bytes: &[u8], opts: &Options) -> ScanResult {
    let mut s = Scanner::new(bytes, opts, None);
    let mut error = s.run().err();
    if error.is_none() && s.encrypted {
        match s.decryptor() {
            // opens without a password, as in a viewer: scan again with strings and streams decrypted
            Some(d) => {
                s = Scanner::new(bytes, opts, Some(d));
                error = s.run().err();
            }
            None => s.add("Undecryptable", Severity::High),
        }
    }
    let error = error.map(|e| e.to_string());
    let mut findings = std::mem::take(&mut s.found);
    findings.sort_by_key(|f| f.severity); // stable sort preserves the order of discovery
    ScanResult {
        suspicious: error.is_some() || findings.iter().any(|f| f.severity == Severity::High),
        encrypted: s.encrypted,
        findings,
        error,
    }
}

/// Finding name as `&'static str` (rule names come from a fixed set).
fn static_name(name: &[u8]) -> &'static str {
    const NAMES: &[&str] = &[
        "JavaScript", "JS", "Launch", "EmbeddedFile", "EmbeddedFiles", "RichMedia", "XFA", "AA",
        "SubmitForm", "ImportData", "GoToR", "GoToE", "Rendition", "JBIG2Decode", "AcroForm", "URI",
        "Sound", "Movie", "GoTo3DView", "Collection",
    ];
    NAMES.iter().copied().find(|n| n.as_bytes() == name).unwrap_or("Unknown")
}

/// Object id from `num gen obj`.
fn obj_id(num: f64, gen: f64) -> Option<ObjId> {
    let valid = |v: f64, max: f64| v.fract() == 0.0 && (0.0..=max).contains(&v);
    (valid(num, u32::MAX as f64) && valid(gen, u16::MAX as f64)).then(|| (num as u32, gen as u16))
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8], opts: &Options, crypt: Option<Decryptor>) -> Self {
        Scanner {
            bytes,
            opts: *opts,
            found: Vec::new(),
            objects: HashMap::new(),
            streams: HashMap::new(),
            open_actions: Vec::new(),
            js: Vec::new(),
            xfa: Vec::new(),
            uris: Vec::new(),
            encrypted: false,
            budget: Budget { max_stream: opts.max_stream_bytes, remaining: opts.max_total_bytes, damaged: false },
            crypt,
            owner: None,
            str_ids: HashMap::new(),
            trailers: Vec::new(),
            security: Vec::new(),
        }
    }

    fn add(&mut self, name: &'static str, severity: Severity) {
        match self.found.iter_mut().find(|f| f.name == name) {
            Some(f) => f.count += 1,
            None => self.found.push(Finding { name: name.to_owned(), severity, count: 1 }),
        }
    }

    fn resolve<'o>(&'o self, o: Option<&'o Obj>) -> Option<&'o Obj> {
        match o {
            Some(Obj::Ref(n)) => self.objects.get(n),
            o => o,
        }
    }

    fn remember(&mut self, n: ObjKey, o: Obj) -> Result<(), ScanError> {
        if self.objects.len() >= self.opts.max_objects {
            return Err(ScanError::TooManyObjects);
        }
        self.objects.insert(n, o);
        Ok(())
    }

    fn check_name(&mut self, name: &[u8], escaped: bool) {
        if let Some(sev) = rule(name) {
            self.add(static_name(name), sev);
        }
        if escaped && is_sensitive(name) {
            self.add("ObfuscatedName", Severity::High);
        }
    }

    fn visit(&mut self, o: &Obj) {
        match o {
            Obj::Name { v, escaped } => self.check_name(v, *escaped),
            Obj::Arr(items) => items.iter().for_each(|v| self.visit(v)),
            Obj::Dict(d) => {
                for e in d.iter() {
                    let k = &e.k;
                    match &**k {
                        b"OpenAction" => {
                            self.open_actions.push(e.v.clone());
                            if e.key_escaped {
                                self.add("ObfuscatedName", Severity::High);
                            }
                        }
                        k => self.check_name(k, e.key_escaped),
                    }
                    match &**k {
                        b"Encrypt" => self.encrypted = true,
                        b"JS" => self.js.push((e.v.clone(), self.owner)),
                        b"XFA" => self.xfa.push(e.v.clone()),
                        b"URI" => self.uris.push((e.v.clone(), self.owner)),
                        _ => {}
                    }
                    self.visit(&e.v);
                }
            }
            _ => {}
        }
    }

    fn run(&mut self) -> Result<(), ScanError> {
        self.check_structure();
        let bytes = self.bytes;
        let mut lx = Lexer::new(bytes);
        let (mut prev_num, mut last_num): (Option<f64>, Option<f64>) = (None, None);
        let mut last_dict: Option<(Option<ObjKey>, Option<ObjId>, Rc<Dict>)> = None;
        let mut after_trailer = false;

        while let Some(t) = lx.next_tok() {
            let trailer = std::mem::take(&mut after_trailer);
            match t {
                Tok::Num { v, .. } => {
                    prev_num = last_num;
                    last_num = Some(v);
                }
                Tok::Kw(b"obj") => {
                    let num = prev_num.map(obj_key);
                    let id = prev_num.zip(last_num).and_then(|(n, g)| obj_id(n, g));
                    prev_num = None;
                    last_num = None;
                    last_dict = None;
                    let save = lx.pos;
                    let parsed = match lx.next_tok() {
                        Some(vt) => parse_value(&mut lx, vt, 0, true)?,
                        None => continue,
                    };
                    match parsed {
                        Parsed::Obj(v) => {
                            self.owner = id;
                            self.visit(&v);
                            self.owner = None;
                            if let Obj::Dict(d) = &v {
                                last_dict = Some((num, id, d.clone()));
                                if self.name_of(d, b"Type") == Some(b"XRef") {
                                    self.trailers.push(d.clone());
                                }
                                let has = |k: &[u8]| dict_get(d, k).is_some();
                                if let (Some(n), true) = (num, has(b"Filter") && has(b"O") && has(b"U")) {
                                    self.security.push((n, d.clone()));
                                }
                            }
                            if let Some(n) = num {
                                if let (Obj::Str(_), Some(id), Some(_)) = (&v, id, &self.crypt) {
                                    self.str_ids.insert(n, id);
                                }
                                self.remember(n, v)?;
                            }
                        }
                        Parsed::NotObj => lx.pos = save,
                    }
                }
                Tok::Kw(b"stream") => {
                    let empty = Rc::new(Dict::new());
                    let dict = last_dict.as_ref().map_or(&empty, |(_, _, d)| d);
                    let (start, end) = self.read_stream(&mut lx, dict);
                    if let Some((num, id, dict)) = last_dict.take() {
                        if let Some(n) = num {
                            self.streams.insert(n, StreamRef { dict: dict.clone(), start, end, id });
                        }
                        self.handle_stream(&dict, &bytes[start..end], id)?;
                    }
                }
                Tok::Kw(b"trailer") => {
                    prev_num = None;
                    last_num = None;
                    after_trailer = true;
                }
                t => {
                    prev_num = None;
                    last_num = None;
                    if let Parsed::Obj(v) = parse_value(&mut lx, t, 0, false)? {
                        self.visit(&v);
                        last_dict = match v {
                            Obj::Dict(d) => {
                                if trailer {
                                    self.trailers.push(d.clone());
                                }
                                Some((None, None, d))
                            }
                            _ => None,
                        };
                    }
                }
            }
        }

        let open_actions = std::mem::take(&mut self.open_actions);
        for oa in &open_actions {
            if !matches!(self.resolve(Some(oa)), Some(Obj::Arr(_))) {
                self.add("OpenAction", Severity::Medium);
            }
        }
        self.analyze_js()?;
        self.analyze_xfa()?;
        self.analyze_uris();
        Ok(())
    }

    /// Header not at the start of the file (polyglots) and data after the last `%%EOF`.
    fn check_structure(&mut self) {
        let b = self.bytes;
        match memmem::find(&b[..b.len().min(HEADER_WINDOW)], b"%PDF-") {
            Some(0) => {}
            Some(_) => self.add("HeaderOffset", Severity::Low),
            None => self.add("NoHeader", Severity::Medium),
        }
        if let Some(i) = memmem::rfind(b, b"%%EOF") {
            if b[i + 5..].iter().any(|&c| !WS[c as usize]) {
                self.add("TrailingData", Severity::Low);
            }
        }
    }

    /// Returns the stream data range and moves the lexer past `endstream`.
    fn read_stream(&self, lx: &mut Lexer, dict: &Dict) -> (usize, usize) {
        const ENDSTREAM: &[u8] = b"endstream";
        let b = lx.b;
        let mut p = lx.pos;
        if b.get(p) == Some(&b'\r') {
            p += 1;
        }
        if b.get(p) == Some(&b'\n') {
            p += 1;
        }
        let p = p.min(b.len());
        if let Some(Obj::Num(len)) = self.resolve(dict_get(dict, b"Length")) {
            let len = *len;
            if len >= 0.0 && len.fract() == 0.0 && (p as f64 + len) <= b.len() as f64 {
                let end = p + len as usize;
                let mut q = end;
                while q < b.len() && WS[b[q] as usize] {
                    q += 1;
                }
                if b[q..].starts_with(ENDSTREAM) {
                    lx.pos = q + ENDSTREAM.len();
                    return (p, end);
                }
            }
        }
        let Some(i) = memmem::find(&b[p..], ENDSTREAM) else {
            lx.pos = b.len();
            return (p, b.len());
        };
        let q = p + i;
        let mut end = q;
        if end > p && b[end - 1] == b'\n' {
            end -= 1;
        }
        if end > p && b[end - 1] == b'\r' {
            end -= 1;
        }
        lx.pos = q + ENDSTREAM.len();
        (p, end)
    }

    fn name_of<'o>(&'o self, d: &'o Dict, k: &[u8]) -> Option<&'o [u8]> {
        self.resolve(dict_get(d, k)).and_then(Obj::as_name)
    }

    fn handle_stream(&mut self, dict: &Dict, data: &[u8], id: Option<ObjId>) -> Result<(), ScanError> {
        let is_objstm = self.name_of(dict, b"Type") == Some(b"ObjStm")
            || (dict_get(dict, b"N").is_some() && dict_get(dict, b"First").is_some());
        if !is_objstm {
            return Ok(()); // images, fonts, content: skip
        }
        // in an encrypted file: decrypted and as stored (a viewer that disagrees on encryption)
        let decrypted = self.decrypt_stream(dict, data, id);
        let mut decoded = Vec::new(); // (data, damaged)
        for data in decrypted.as_deref().into_iter().chain([data]) {
            self.budget.damaged = false;
            if let Some(dec) = self.decode(data, dict)? {
                decoded.push((dec, self.budget.damaged));
            }
        }
        // the main reading: the first undamaged one, else the first one
        let Some(main) = decoded.iter().position(|(_, damaged)| !damaged).or((!decoded.is_empty()).then_some(0)) else {
            self.add("UndecodableObjStm", Severity::High);
            return Ok(());
        };
        let (dec, damaged) = decoded.remove(main);
        // scan a damaged stream anyway: Acrobat also reads whatever could be decompressed
        if damaged {
            self.add("DamagedObjStm", Severity::High);
        }
        self.scan_objstm(&dec, dict)?;
        // names in the other reading count too, its objects do not replace the main ones
        for (other, _) in decoded {
            self.visit_all(&other)?;
        }
        Ok(())
    }

    /// Stream data decrypted with the key of its object; `None` if the stream is not encrypted.
    fn decrypt_stream(&self, dict: &Dict, data: &[u8], id: Option<ObjId>) -> Option<Vec<u8>> {
        let (c, id) = (self.crypt.as_ref()?, id?);
        if self.name_of(dict, b"Type") == Some(b"XRef") {
            return None; // cross-reference streams are never encrypted
        }
        // a /Crypt filter (always the first one) overrides the default method
        let first = match self.resolve(dict_get(dict, b"Filter")) {
            Some(Obj::Arr(a)) => self.resolve(a.first()),
            f => f,
        };
        let method = if first.and_then(Obj::as_name) == Some(b"Crypt") {
            let parms = match self.resolve(dict_get(dict, b"DecodeParms")) {
                Some(Obj::Arr(a)) => self.resolve(a.first()),
                p => p,
            };
            match parms {
                Some(Obj::Dict(p)) => c.named(self.name_of(p, b"Name").unwrap_or(b"Identity")),
                _ => Method::Identity,
            }
        } else {
            c.stm
        };
        c.decrypt(method, id, data)
    }

    fn num_param(&self, d: Option<&Dict>, k: &[u8], def: f64) -> f64 {
        match self.resolve(d.and_then(|d| dict_get(d, k))) {
            Some(Obj::Num(v)) => *v,
            _ => def,
        }
    }

    /// Applies the /Filter chain. `Ok(None)` means an unsupported filter or corrupted data.
    fn decode(&mut self, data: &[u8], dict: &Dict) -> Result<Option<Vec<u8>>, ScanError> {
        let filters: Vec<Obj> = match self.resolve(dict_get(dict, b"Filter")) {
            None => vec![],
            Some(f @ Obj::Name { .. }) => vec![f.clone()],
            Some(Obj::Arr(a)) => a.clone(),
            // anything else, `null` and a key without a value included, is malformed (as in the reference)
            Some(_) => return Ok(None),
        };
        let parms = self.resolve(dict_get(dict, b"DecodeParms")).cloned();
        let mut data = data.to_vec();
        for (i, f) in filters.iter().enumerate() {
            let Some(name) = self.resolve(Some(f)).and_then(Obj::as_name) else { return Ok(None) };
            let name = name.to_vec();
            let p = match &parms {
                Some(Obj::Arr(a)) => self.resolve(a.get(i)),
                p => self.resolve(p.as_ref()),
            };
            let pd = match p {
                Some(Obj::Dict(d)) => Some(d.clone()),
                _ => None,
            };
            let predictor = |s: &Self| Predictor {
                predictor: s.num_param(pd.as_deref(), b"Predictor", 1.0),
                colors: s.num_param(pd.as_deref(), b"Colors", 1.0),
                bpc: s.num_param(pd.as_deref(), b"BitsPerComponent", 8.0),
                columns: s.num_param(pd.as_deref(), b"Columns", 1.0),
            };
            let out = match &name[..] {
                b"FlateDecode" | b"Fl" => filters::flate(&data, &mut self.budget)?
                    .and_then(|d| filters::unpredict(d, &predictor(self))),
                b"LZWDecode" | b"LZW" => {
                    let early = self.num_param(pd.as_deref(), b"EarlyChange", 1.0) != 0.0;
                    filters::lzw(&data, early, &mut self.budget)?.and_then(|d| filters::unpredict(d, &predictor(self)))
                }
                b"ASCIIHexDecode" | b"AHx" => Some(filters::ascii_hex(&data)),
                b"ASCII85Decode" | b"A85" => Some(filters::ascii85(&data)),
                b"RunLengthDecode" | b"RL" => filters::run_length(&data, &mut self.budget)?,
                // decryption is applied before decoding (see decrypt_stream)
                b"Crypt" if self.crypt.is_some() => Some(std::mem::take(&mut data)),
                _ => None,
            };
            match out {
                Some(o) => data = o,
                None => return Ok(None),
            }
        }
        Ok(Some(data))
    }

    fn scan_objstm(&mut self, data: &[u8], dict: &Dict) -> Result<(), ScanError> {
        let mut lx = Lexer::new(data);
        let n = self.resolve(dict_get(dict, b"N")).cloned();
        let first = self.resolve(dict_get(dict, b"First")).cloned();
        if let (Some(Obj::Num(n)), Some(Obj::Num(first))) = (n, first) {
            if first >= 0.0 && first <= data.len() as f64 {
                let first = first as usize;
                let mut pairs: Vec<f64> = Vec::new();
                while (pairs.len() as f64) < n * 2.0 && lx.pos < first {
                    match lx.next_tok() {
                        Some(Tok::Num { v, .. }) => pairs.push(v),
                        _ => break,
                    }
                }
                for pair in pairs.chunks_exact(2) {
                    let off = pair[1];
                    if !(off >= 0.0 && first as f64 + off < data.len() as f64) {
                        continue;
                    }
                    lx.pos = first + off as usize;
                    let Some(t) = lx.next_tok() else { continue };
                    if let Parsed::Obj(v) = parse_value(&mut lx, t, 0, true)? {
                        // strings inside an object stream are not encrypted separately
                        self.str_ids.remove(&obj_key(pair[0]));
                        self.remember(obj_key(pair[0]), v)?;
                    }
                }
            }
        }
        self.visit_all(data)
    }

    /// Visits every value in the data: names anywhere count, as in the file itself.
    fn visit_all(&mut self, data: &[u8]) -> Result<(), ScanError> {
        let mut lx = Lexer::new(data);
        while let Some(t) = lx.next_tok() {
            if let Parsed::Obj(v) = parse_value(&mut lx, t, 0, false)? {
                self.visit(&v);
            }
        }
        Ok(())
    }

    /// The string the value is or refers to: as stored and, in an encrypted file, decrypted
    /// (a viewer that disagrees on encryption would see the stored one).
    fn load_strings(&self, o: &Obj, owner: Option<ObjId>) -> Vec<Rc<[u8]>> {
        let (s, id) = match o {
            Obj::Str(s) => (s, owner),
            Obj::Ref(n) => match self.objects.get(n) {
                Some(Obj::Str(s)) => (s, self.str_ids.get(n).copied()),
                _ => return vec![],
            },
            _ => return vec![],
        };
        let decrypted = self.crypt.as_ref().zip(id).and_then(|(c, id)| c.string(id, s));
        [s.clone()].into_iter().chain(decrypted.map(Rc::from)).collect()
    }

    /// Content of the string or stream the value points to (directly or by reference),
    /// in every variant a viewer could see.
    fn load_texts(&mut self, o: &Obj, owner: Option<ObjId>) -> Result<Vec<Vec<u8>>, ScanError> {
        let Some(st) = (match o {
            Obj::Ref(n) => self.streams.get(n).cloned(),
            _ => None,
        }) else {
            return Ok(self.load_strings(o, owner).iter().map(|s| s.to_vec()).collect());
        };
        let raw = &self.bytes[st.start..st.end];
        let mut texts = Vec::new();
        if let Some(dec) = self.decrypt_stream(&st.dict, raw, st.id) {
            texts.extend(self.decode(&dec, &st.dict)?);
        }
        texts.extend(self.decode(raw, &st.dict)?);
        Ok(texts)
    }

    fn analyze_js(&mut self) -> Result<(), ScanError> {
        for (o, owner) in std::mem::take(&mut self.js) {
            if self.load_texts(&o, owner)?.iter().any(|code| is_suspicious_js(code)) {
                self.add("SuspiciousJS", Severity::High);
            }
        }
        Ok(())
    }

    /// XFA: a stream or an array `[(part) stream …]`; look for embedded scripts.
    fn analyze_xfa(&mut self) -> Result<(), ScanError> {
        for o in std::mem::take(&mut self.xfa) {
            let parts: Vec<Obj> = match self.resolve(Some(&o)) {
                Some(Obj::Arr(a)) => a.clone(),
                _ => vec![o],
            };
            for part in &parts {
                let (mut script, mut suspicious) = (false, false);
                for xml in self.load_texts(part, None)? {
                    let xml = to_single_byte(&xml);
                    if memmem::find(&xml.to_ascii_lowercase(), b"<script").is_some() {
                        script = true;
                        suspicious |= is_suspicious_js(&xml);
                    }
                }
                if script {
                    self.add("XFAScript", Severity::Medium);
                }
                if suspicious {
                    self.add("SuspiciousJS", Severity::High);
                }
            }
        }
        Ok(())
    }

    fn analyze_uris(&mut self) {
        for (o, owner) in std::mem::take(&mut self.uris) {
            // the most dangerous reading wins
            let kind = self.load_strings(&o, owner).iter().map(|s| uri_kind(s)).min();
            match kind {
                Some(UriKind::Script) => self.add("ScriptURI", Severity::High),
                // NTLM hash leak / launching local files
                Some(UriKind::File) => self.add("FileURI", Severity::Medium),
                _ => {}
            }
        }
    }

    /// The decryptor for a file that opens without a password. `None` if a password is required,
    /// the handler is not supported, or the trailers disagree (a viewer could use another one).
    fn decryptor(&self) -> Option<Decryptor> {
        let mut seen: Vec<(Rc<Dict>, Rc<[u8]>)> = Vec::new();
        let mut found: Option<Decryptor> = None;
        for t in &self.trailers {
            let id0 = match self.resolve(dict_get(t, b"ID")) {
                Some(Obj::Arr(a)) => match self.resolve(a.first()) {
                    Some(Obj::Str(s)) => s.clone(),
                    _ => Rc::from(&[][..]),
                },
                _ => Rc::from(&[][..]),
            };
            // a document trailer without /Encrypt: a viewer could read the file as unencrypted;
            // others (the /XRefStm stream of a hybrid file) need not repeat it
            let Some(enc) = dict_get(t, b"Encrypt") else {
                if dict_get(t, b"Root").is_some() {
                    return None;
                }
                continue;
            };
            // every definition of the encryption dictionary must give the same key
            let dicts: Vec<Rc<Dict>> = match enc {
                Obj::Ref(k) => self.security.iter().filter(|(n, _)| n == k).map(|(_, d)| d.clone()).collect(),
                Obj::Dict(d) => vec![d.clone()],
                _ => vec![],
            };
            if dicts.is_empty() {
                return None;
            }
            for d in dicts {
                if seen.iter().any(|(sd, sid)| Rc::ptr_eq(sd, &d) && *sid == id0) {
                    continue;
                }
                if seen.len() == MAX_HANDLERS {
                    return None;
                }
                let dec = self.open(&d, &id0)?;
                if found.as_ref().is_some_and(|f| *f != dec) {
                    return None;
                }
                found = Some(dec);
                seen.push((d, id0.clone()));
            }
        }
        found
    }

    /// Opens a standard security handler with the empty password.
    fn open(&self, d: &Dict, id0: &[u8]) -> Option<Decryptor> {
        let num = |k: &[u8]| match self.resolve(dict_get(d, k)) {
            Some(Obj::Num(v)) => Some(*v),
            _ => None,
        };
        let string = |k: &[u8]| match self.resolve(dict_get(d, k)) {
            Some(Obj::Str(s)) => &s[..],
            _ => &[][..],
        };
        if self.name_of(d, b"Filter") != Some(b"Standard") {
            return None;
        }
        let cf = match self.resolve(dict_get(d, b"CF")) {
            Some(Obj::Dict(cf)) => cf.clone(),
            _ => Rc::new(Dict::new()),
        };
        let filter = |f: &Obj| match self.resolve(Some(f)) {
            Some(Obj::Dict(f)) => match self.name_of(f, b"CFM") {
                None | Some(b"None") => Method::Identity,
                Some(b"V2") => Method::Rc4,
                Some(b"AESV2") => Method::Aes128,
                Some(b"AESV3") => Method::Aes256,
                _ => Method::Unsupported,
            },
            _ => Method::Unsupported,
        };
        let named: Vec<(Box<[u8]>, Method)> = cf.iter().map(|e| (e.k.clone(), filter(&e.v))).collect();
        let default = |k: &[u8]| match self.name_of(d, k) {
            None | Some(b"Identity") => Method::Identity,
            Some(n) => dict_get(&cf, n).map_or(Method::Unsupported, filter),
        };
        let stm_name = self.name_of(d, b"StmF").unwrap_or(b"Identity");
        let cf_length = match self.resolve(dict_get(&cf, stm_name)) {
            Some(Obj::Dict(f)) => match self.resolve(dict_get(f, b"Length")) {
                Some(Obj::Num(l)) => Some(*l),
                _ => None,
            },
            _ => None,
        };
        let v = num(b"V").unwrap_or(0.0);
        Decryptor::open(&Params {
            v,
            r: num(b"R").unwrap_or(0.0),
            length: if v == 4.0 { cf_length } else { num(b"Length") },
            o: string(b"O"),
            u: string(b"U"),
            ue: string(b"UE"),
            p: num(b"P").unwrap_or(0.0),
            encrypt_metadata: !matches!(self.resolve(dict_get(d, b"EncryptMetadata")), Some(Obj::Bool(false))),
            id0,
            stm: default(b"StmF"),
            strf: default(b"StrF"),
            named,
        })
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum UriKind {
    Script,
    File,
    Other,
}

fn uri_kind(s: &[u8]) -> UriKind {
    let s = to_single_byte(s);
    let start = s.iter().position(|c| !c.is_ascii_whitespace() && *c != 0).unwrap_or(s.len());
    let uri = &s[start..];
    let starts = |p: &[u8]| uri.get(..p.len()).is_some_and(|u| u.eq_ignore_ascii_case(p));
    if starts(b"javascript:") || starts(b"vbscript:") {
        UriKind::Script
    } else if starts(b"file:") || starts(b"\\\\") || starts(b"smb:") {
        UriKind::File
    } else {
        UriKind::Other
    }
}

/// PDF text strings may be UTF-16 with a BOM; reduce them to single-byte characters.
fn to_single_byte(s: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    match s {
        [0xFE, 0xFF, rest @ ..] => rest.chunks(2).filter_map(|c| c.get(1).copied()).collect(),
        [0xFF, 0xFE, rest @ ..] => rest.chunks(2).map(|c| c[0]).collect(),
        _ => s.into(),
    }
}

fn is_suspicious_js(code: &[u8]) -> bool {
    let code = to_single_byte(code);
    if JS_PATTERNS.iter().any(|p| memmem::find(&code, p).is_some()) {
        return true;
    }
    // shellcode/heap spray: long runs of %uXXXX or \xXX
    memmem::find_iter(&code, b"%u").count() >= 16 || memmem::find_iter(&code, b"\\x").count() >= 64
}

#[cfg(test)]
mod tests;
