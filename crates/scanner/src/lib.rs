//! Heuristic detection of potentially malicious content in PDF files.
//!
//! The file is not parsed "by the book" (via xref): the lexer walks through all of it,
//! so objects hidden outside the cross-reference table or in damaged files are found too.

mod filters;
mod lexer;
mod parser;

use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

use memchr::memmem;

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

#[derive(Clone)]
struct StreamRef {
    dict: Rc<Dict>,
    start: usize,
    end: usize,
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
    js: Vec<Obj>,
    xfa: Vec<Obj>,
    uris: Vec<Obj>,
    encrypted: bool,
    budget: Budget,
}

/// Scans an in-memory PDF. Never panics on arbitrary input.
pub fn scan(bytes: &[u8], opts: &Options) -> ScanResult {
    let mut s = Scanner {
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
    };
    let error = s.run().err().map(|e| e.to_string());
    let mut findings = std::mem::take(&mut s.found);
    findings.sort_by_key(|f| f.severity); // stable sort preserves the order of discovery
    ScanResult {
        suspicious: error.is_some() || s.encrypted || findings.iter().any(|f| f.severity == Severity::High),
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

impl<'a> Scanner<'a> {
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
                        b"JS" => self.js.push(e.v.clone()),
                        b"XFA" => self.xfa.push(e.v.clone()),
                        b"URI" => self.uris.push(e.v.clone()),
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
        let mut last_dict: Option<(Option<ObjKey>, Rc<Dict>)> = None;

        while let Some(t) = lx.next_tok() {
            match t {
                Tok::Num { v, .. } => {
                    prev_num = last_num;
                    last_num = Some(v);
                }
                Tok::Kw(b"obj") => {
                    let num = prev_num.map(obj_key);
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
                            self.visit(&v);
                            if let Obj::Dict(d) = &v {
                                last_dict = Some((num, d.clone()));
                            }
                            if let Some(n) = num {
                                self.remember(n, v)?;
                            }
                        }
                        Parsed::NotObj => lx.pos = save,
                    }
                }
                Tok::Kw(b"stream") => {
                    let empty = Rc::new(Dict::new());
                    let dict = last_dict.as_ref().map_or(&empty, |(_, d)| d);
                    let (start, end) = self.read_stream(&mut lx, dict);
                    if let Some((num, dict)) = last_dict.take() {
                        if let Some(n) = num {
                            self.streams.insert(n, StreamRef { dict: dict.clone(), start, end });
                        }
                        self.handle_stream(&dict, &bytes[start..end])?;
                    }
                }
                t => {
                    prev_num = None;
                    last_num = None;
                    if let Parsed::Obj(v) = parse_value(&mut lx, t, 0, false)? {
                        self.visit(&v);
                        last_dict = match v {
                            Obj::Dict(d) => Some((None, d)),
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

    fn handle_stream(&mut self, dict: &Dict, data: &[u8]) -> Result<(), ScanError> {
        let is_objstm = self.resolve(dict_get(dict, b"Type")).and_then(Obj::as_name) == Some(b"ObjStm")
            || (dict_get(dict, b"N").is_some() && dict_get(dict, b"First").is_some());
        if !is_objstm {
            return Ok(()); // images, fonts, content: skip
        }
        self.budget.damaged = false;
        match self.decode(data, dict)? {
            Some(dec) => {
                // scan a damaged stream anyway: Acrobat also reads whatever could be decompressed
                if self.budget.damaged {
                    self.add("DamagedObjStm", Severity::High);
                }
                self.scan_objstm(&dec, dict)
            }
            None => {
                self.add("UndecodableObjStm", Severity::High);
                Ok(())
            }
        }
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
            None | Some(Obj::Other) => vec![],
            Some(f @ Obj::Name { .. }) => vec![f.clone()],
            Some(Obj::Arr(a)) => a.clone(),
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
                        self.remember(obj_key(pair[0]), v)?;
                    }
                }
            }
        }
        lx.pos = 0;
        while let Some(t) = lx.next_tok() {
            if let Parsed::Obj(v) = parse_value(&mut lx, t, 0, false)? {
                self.visit(&v);
            }
        }
        Ok(())
    }

    /// Content of the string or stream the value points to (directly or by reference).
    fn load_text(&mut self, o: &Obj) -> Result<Option<Vec<u8>>, ScanError> {
        match o {
            Obj::Str(s) => Ok(Some(s.to_vec())),
            Obj::Ref(n) => {
                if let Some(st) = self.streams.get(n).cloned() {
                    return self.decode(&self.bytes[st.start..st.end], &st.dict);
                }
                match self.objects.get(n) {
                    Some(Obj::Str(s)) => Ok(Some(s.to_vec())),
                    _ => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    fn analyze_js(&mut self) -> Result<(), ScanError> {
        for o in std::mem::take(&mut self.js) {
            if let Some(code) = self.load_text(&o)? {
                if is_suspicious_js(&code) {
                    self.add("SuspiciousJS", Severity::High);
                }
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
                let Some(xml) = self.load_text(part)? else { continue };
                let xml = to_single_byte(&xml);
                if memmem::find(&xml.to_ascii_lowercase(), b"<script").is_some() {
                    self.add("XFAScript", Severity::Medium);
                    if is_suspicious_js(&xml) {
                        self.add("SuspiciousJS", Severity::High);
                    }
                }
            }
        }
        Ok(())
    }

    fn analyze_uris(&mut self) {
        for o in std::mem::take(&mut self.uris) {
            let Some(Obj::Str(s)) = self.resolve(Some(&o)) else { continue };
            let s = to_single_byte(s);
            let start = s.iter().position(|c| !c.is_ascii_whitespace() && *c != 0).unwrap_or(s.len());
            let uri = s[start..].to_ascii_lowercase();
            if uri.starts_with(b"javascript:") || uri.starts_with(b"vbscript:") {
                self.add("ScriptURI", Severity::High);
            } else if uri.starts_with(b"file:") || uri.starts_with(b"\\\\") || uri.starts_with(b"smb:") {
                // NTLM hash leak / launching local files
                self.add("FileURI", Severity::Medium);
            }
        }
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
