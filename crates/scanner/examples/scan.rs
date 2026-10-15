//! Scans files and prints the result and timing: `cargo run --release --example scan -- file.pdf…`
fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).expect("read");
        let t = std::time::Instant::now();
        let r = pdf_scan_core::scan(&data, &Default::default());
        println!("{path}: {:?} ({:.1} ms)", r, t.elapsed().as_secs_f64() * 1e3);
    }
}
