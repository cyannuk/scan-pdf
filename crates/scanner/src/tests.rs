use super::*;

fn pdf(body: &str) -> Vec<u8> {
    format!("%PDF-1.7\n{body}\ntrailer << /Root 1 0 R >>\n%%EOF\n").into_bytes()
}

fn names(r: &ScanResult) -> Vec<(&str, u32)> {
    r.findings.iter().map(|f| (f.name.as_str(), f.count)).collect()
}

fn has(r: &ScanResult, name: &str) -> bool {
    r.findings.iter().any(|f| f.name == name)
}

fn zlib(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

fn stream_obj(num: u32, dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("{num} 0 obj << {dict} /Length {} >> stream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream endobj\n");
    v
}

fn wrap(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = b"%PDF-1.7\n".to_vec();
    for p in parts {
        v.extend_from_slice(p);
    }
    v.extend_from_slice(b"trailer << /Root 1 0 R >>\n%%EOF\n");
    v
}

fn objstm(objs: &[(u32, &str)]) -> Vec<u8> {
    let mut header = String::new();
    let mut body = String::new();
    for (n, o) in objs {
        header += &format!("{n} {} ", body.len());
        body += o;
        body += " ";
    }
    (header + &body).into_bytes()
}

fn first_of(objs: &[(u32, &str)]) -> usize {
    let mut header = String::new();
    let mut len = 0;
    for (n, o) in objs {
        header += &format!("{n} {len} ");
        len += o.len() + 1;
    }
    header.len()
}

#[test]
fn clean_document() {
    let r = scan(&pdf("1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction [3 0 R /Fit] >> endobj"), &Options::default());
    assert_eq!(r, ScanResult { suspicious: false, encrypted: false, findings: vec![], error: None });
}

#[test]
fn javascript_action() {
    let r = scan(
        &pdf("1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >> endobj"),
        &Options::default(),
    );
    assert!(r.suspicious);
    assert_eq!(names(&r), [("JavaScript", 1), ("JS", 1), ("OpenAction", 1)]);
}

#[test]
fn obfuscated_names() {
    let r = scan(&pdf("1 0 obj << /S /J#61vaScript /J#53 (x) >> endobj"), &Options::default());
    assert_eq!(names(&r), [("JavaScript", 1), ("ObfuscatedName", 2), ("JS", 1)]);
    // harmless escaping is not counted
    let r = scan(&pdf("1 0 obj << /BaseFont /Arial#20Bold >> endobj"), &Options::default());
    assert!(r.findings.is_empty());
}

#[test]
fn suspicious_js_in_string_and_stream() {
    let r = scan(&pdf("1 0 obj << /S /JavaScript /JS (var s = unescape\\('%u0c0c'\\);) >> endobj"), &Options::default());
    assert!(has(&r, "SuspiciousJS"));

    let js = zlib(b"this.exportDataObject({cName: 'a', nLaunch: 2});");
    let doc = wrap(&[
        b"1 0 obj << /OpenAction 2 0 R >> endobj\n",
        b"2 0 obj << /S /JavaScript /JS 3 0 R >> endobj\n",
        &stream_obj(3, "/Filter /FlateDecode", &js),
    ]);
    let r = scan(&doc, &Options::default());
    assert!(has(&r, "SuspiciousJS"), "{r:?}");
    assert!(has(&r, "OpenAction"));

    // UTF-16BE with BOM
    let r = scan(&pdf("1 0 obj << /JS <FEFF006500760061006C0028> >> endobj"), &Options::default());
    assert!(has(&r, "SuspiciousJS"));
}

#[test]
fn objstm_with_predictor() {
    let objs = [(5, "<< /Type /Action /S /Launch /F (cmd.exe) >>"), (6, "<< /AA << /O 5 0 R >> >>")];
    let raw = objstm(&objs);
    // PNG Up predictor, 4 columns
    let mut predicted = Vec::new();
    let mut prev = [0u8; 4];
    for row in raw.chunks(4) {
        let mut r = [0u8; 4];
        r[..row.len()].copy_from_slice(row);
        predicted.push(2);
        for i in 0..4 {
            predicted.push(r[i].wrapping_sub(prev[i]));
        }
        prev = r;
    }
    let dict = format!(
        "/Type /ObjStm /N 2 /First {} /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>",
        first_of(&objs)
    );
    let r = scan(&wrap(&[&stream_obj(4, &dict, &zlib(&predicted))]), &Options::default());
    assert_eq!(names(&r), [("Launch", 1), ("AA", 1)], "{r:?}");
}

#[test]
fn objstm_lzw_and_runlength_and_chain() {
    let objs = [(5, "<< /S /JavaScript /JS (1) >>")];
    let raw = objstm(&objs);
    let first = first_of(&objs);
    // ASCIIHex on top of Flate
    let hex: String = zlib(&raw).iter().map(|b| format!("{b:02x}")).collect::<String>() + ">";
    let dict = format!("/Type /ObjStm /N 1 /First {first} /Filter [/AHx /Fl]");
    let r = scan(&wrap(&[&stream_obj(4, &dict, hex.as_bytes())]), &Options::default());
    assert!(has(&r, "JavaScript") && !has(&r, "UndecodableObjStm"), "{r:?}");

    // RunLength: literal runs of 128 bytes
    let mut rl = Vec::new();
    for c in raw.chunks(128) {
        rl.push((c.len() - 1) as u8);
        rl.extend_from_slice(c);
    }
    rl.push(128);
    let dict = format!("/Type /ObjStm /N 1 /First {first} /Filter /RunLengthDecode");
    let r = scan(&wrap(&[&stream_obj(4, &dict, &rl)]), &Options::default());
    assert!(has(&r, "JavaScript") && !has(&r, "UndecodableObjStm"), "{r:?}");

    let dict = format!("/Type /ObjStm /N 1 /First {first} /Filter /DCTDecode");
    let r = scan(&wrap(&[&stream_obj(4, &dict, &raw)]), &Options::default());
    assert!(has(&r, "UndecodableObjStm") && r.suspicious);
}

#[test]
fn objstm_object_resolves_open_action() {
    // OpenAction refers to an array inside an ObjStm → a destination, not an action
    let objs = [(7, "[3 0 R /Fit]")];
    let dict = format!("/Type /ObjStm /N 1 /First {} /Filter /FlateDecode", first_of(&objs));
    let doc = wrap(&[b"1 0 obj << /OpenAction 7 0 R >> endobj\n", &stream_obj(4, &dict, &zlib(&objstm(&objs)))]);
    let r = scan(&doc, &Options::default());
    assert!(r.findings.is_empty(), "{r:?}");
}

#[test]
fn xfa_scripts() {
    let xml = b"<xdp:xdp><template><script contentType='application/x-javascript'>util.printf('%45000f', 1)</script></template></xdp:xdp>";
    let doc = wrap(&[b"1 0 obj << /AcroForm << /XFA [(template) 2 0 R] >> >> endobj\n", &stream_obj(2, "", xml)]);
    let r = scan(&doc, &Options::default());
    assert_eq!(names(&r), [("SuspiciousJS", 1), ("XFA", 1), ("XFAScript", 1), ("AcroForm", 1)], "{r:?}");
}

#[test]
fn uris() {
    let r = scan(&pdf("1 0 obj << /S /URI /URI (  JavaScript:alert\\(1\\)) >> endobj"), &Options::default());
    assert!(has(&r, "ScriptURI") && r.suspicious);
    let r = scan(&pdf("1 0 obj << /S /URI /URI (\\\\\\\\evil\\\\share) >> endobj"), &Options::default());
    assert!(has(&r, "FileURI"), "{r:?}");
    let r = scan(&pdf("1 0 obj << /S /URI /URI (https://example.com) >> endobj"), &Options::default());
    assert_eq!(names(&r), [("URI", 2)]);
}

#[test]
fn structure() {
    let mut doc = b"MZ\x90\x00garbage".to_vec();
    doc.extend_from_slice(&pdf("1 0 obj << >> endobj"));
    doc.extend_from_slice(b"PK\x03\x04 trailing zip");
    let r = scan(&doc, &Options::default());
    assert_eq!(names(&r), [("HeaderOffset", 1), ("TrailingData", 1)]);
    let r = scan(b"not a pdf", &Options::default());
    assert_eq!(names(&r), [("NoHeader", 1)]);
}

#[test]
fn encrypted() {
    let r = scan(&pdf("trailer << /Encrypt 5 0 R >>"), &Options::default());
    assert!(r.encrypted && r.suspicious);
}

#[test]
fn limits() {
    let bomb = zlib(&vec![0u8; 10 << 20]);
    let dict = "/Type /ObjStm /N 1 /First 0 /Filter /FlateDecode";
    let opts = Options { max_stream_bytes: 1 << 20, ..Options::default() };
    let r = scan(&wrap(&[&stream_obj(4, dict, &bomb)]), &opts);
    assert_eq!(r.error.as_deref(), Some("Unpack limit exceeded"));
    assert!(r.suspicious);

    let opts = Options { max_objects: 10, ..Options::default() };
    let body: String = (1..=20).map(|i| format!("{i} 0 obj << >> endobj\n")).collect();
    assert_eq!(scan(&pdf(&body), &opts).error.as_deref(), Some("Too many objects"));

    let deep = format!("1 0 obj {} endobj", "<< /A ".repeat(200));
    assert_eq!(scan(&pdf(&deep), &Options::default()).error.as_deref(), Some("Nesting of objects is too deep"));
}

#[test]
fn stream_length_by_ref_and_wrong_length() {
    // wrong /Length: the stream is located by endstream; JS inside a non-ObjStm stream is not counted
    let doc = wrap(&[b"4 0 obj << /Length 9999 >> stream\n/JS /JavaScript\nendstream endobj\n"]);
    let r = scan(&doc, &Options::default());
    assert!(r.findings.is_empty(), "{r:?}");
    let doc = wrap(&[b"4 0 obj << /Length 5 0 R >> stream\nabc\nendstream endobj\n5 0 obj 3 endobj\n"]);
    assert!(scan(&doc, &Options::default()).findings.is_empty());
}

/// Mutation fuzzing: no panics and reasonable time on any input.
#[test]
fn fuzz_no_panics() {
    let mut seed = 0x9E3779B97F4A7C15u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let objs = [(5, "<< /S /JavaScript /JS (eval\\(x\\)) /K [1 2 R <41> (a\\)b)] >>"), (6, "[1 0 R /Fit]")];
    let dict = format!("/Type /ObjStm /N 2 /First {} /Filter [/Fl /AHx]", first_of(&objs));
    let hex: String = objstm(&objs).iter().map(|b| format!("{b:02x}")).collect();
    let seeds = [
        pdf("1 0 obj << /OpenAction 6 0 R /AA << /O << /S /Launch >> >> /URI (file://x) >> endobj"),
        wrap(&[&stream_obj(4, &dict, &zlib(hex.as_bytes())), b"1 0 obj << /XFA 4 0 R /JS 4 0 R >> endobj\n"]),
    ];
    const TOKENS: &[&[u8]] = &[b"<<", b">>", b"[", b"]", b"(", b")", b"<", b">", b"/", b"#", b"\\", b" obj ", b" stream\n", b"endstream", b" R ", b"0 0", b"%"];
    let small = Options { max_stream_bytes: 1 << 16, max_total_bytes: 1 << 18, max_objects: 1000 };
    for iter in 0..20_000 {
        let mut d = seeds[iter % seeds.len()].clone();
        for _ in 0..1 + rnd() % 8 {
            let pos = (rnd() as usize) % (d.len() + 1);
            match rnd() % 4 {
                0 if pos < d.len() => d[pos] = rnd() as u8,
                1 => d.splice(pos..pos, TOKENS[(rnd() as usize) % TOKENS.len()].iter().copied()).for_each(drop),
                2 if pos < d.len() => {
                    let n = ((rnd() as usize) % 16).min(d.len() - pos);
                    d.drain(pos..pos + n);
                }
                _ => d.truncate(pos),
            }
        }
        scan(&d, &small);
    }
    // degenerate inputs
    for d in [&b""[..], b"(", b"<", b"/", b"<<<<<<", b"stream", b"1 0 obj", b"%PDF-1.7\n1 0 obj << /Length -1 >> stream"] {
        scan(d, &Options::default());
    }
}

#[test]
fn tiny_limits() {
    let objs = [(5, "<< /JS (1) >>")];
    let dict = format!("/Type /ObjStm /N 1 /First {} /Filter /FlateDecode", first_of(&objs));
    let doc = wrap(&[&stream_obj(4, &dict, &zlib(&objstm(&objs)))]);
    for max in 0..40 {
        let r = scan(&doc, &Options { max_stream_bytes: max, max_total_bytes: max, max_objects: 0 });
        assert!(r.error.is_some() && r.suspicious);
    }
}

#[test]
fn damaged_objstm() {
    let objs = [(5, "<< /S /Launch >>")];
    let dict = format!("/Type /ObjStm /N 1 /First {} /Filter /FlateDecode", first_of(&objs));
    let z = zlib(&objstm(&objs));
    // truncated stream: Launch is still found, but the stream is flagged as damaged
    let r = scan(&wrap(&[&stream_obj(4, &dict, &z[..z.len() - 4])]), &Options::default());
    assert_eq!(names(&r), [("DamagedObjStm", 1), ("Launch", 1)], "{r:?}");
    let mut bad = z.clone();
    *bad.last_mut().unwrap() ^= 0xff; // bad Adler-32
    let r = scan(&wrap(&[&stream_obj(4, &dict, &bad)]), &Options::default());
    assert_eq!(names(&r), [("DamagedObjStm", 1), ("Launch", 1)], "{r:?}");
}

#[test]
fn duplicate_keys_are_all_analyzed() {
    let r = scan(&pdf("1 0 obj << /JS (eval\\(x\\)) /JS (1) >> endobj"), &Options::default());
    assert_eq!(names(&r), [("JS", 2), ("SuspiciousJS", 1)]);
}
